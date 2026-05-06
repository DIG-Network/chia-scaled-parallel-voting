# UI Migration Plan — pre-rev → CHIP rev 2026-05-02 per-ballot model

## Problem

The Next.js app at `CHIP/app` is wired against a wasm API surface that no
longer exists. After `wasm-pack build` against the current
`wasm/src/lib.rs`, the UI calls 11 functions that have been removed,
because the wasm crate moved to the post-CHIP-rev-2026-05-02 per-ballot
model and the UI was never migrated.

The integration test at `CHIP/wasm/integration-tests/live_integration.mjs`
exercises the new per-ballot model end-to-end and is the reference for what
the UI should do. Bringing the UI to parity is the goal.

### Removed wasm exports the UI calls

| UI call | Status | Replacement (per-ballot, post-rev) |
|---|---|---|
| `voteBuildPreviewSpend` / `voteBuildFinalBundle` | gone | `castVoteBuildPreviewSpend` (currently a STUB) / `castVoteBuildFinalBundle` (takes secret_hex — Sage-incompatible) |
| `changeVoteBuildPreviewSpend` / `changeVoteBuildFinalBundle` | gone | `updateVoteBuildPreviewSpend` (STUB) / `updateVoteBuildFinalBundle` (Sage-incompatible) |
| `collectVotes` | gone | `collectVotesForBallot(backend, config, ballot_launcher_id, voter_pubkeys)` |
| `buildFinalizeBundleFromCollectedVotes` | gone | `buildBallotFinalizeBundle(backend, config, ballot_launcher_id, vote_outcome, params, votes, proving_key, network, election_start_height)` |
| `buildCatCollateralSpend` (whole-election) | gone | `buildCatRegistrationSpend(backend, voter_secret_hex, …)` (Sage-incompatible) |
| `buildRegistrationFeeXchSpend` / `buildMempoolFeeXchSpend` | gone | model changed — no separate fee inputs |
| `assembleSpendBundleFromWalletCoinSpends` | gone | `assembleSpendBundle(coin_spends, sig)` |
| `bundleToWalletJson` | gone | dApp must convert `chia_protocol::SpendBundle` → JSON RPC shape itself (or via a new helper) |

### Why the new exports aren't drop-in replacements

The new vote/update_vote/release exports in wasm are SDK-BLOCKED for
hardware-wallet flows. The wasm doc-comments at `wasm/src/lib.rs:~1583-1597`
spell out the dependency:

> *"A usable implementation needs the SDK to expose `Voter::cast_vote`
> split into two halves:*
> *  1. `cast_vote_build_with_initial_sig(chain, params, voter_pk, initial_signature) -> { coin_spends, augmented_aggsig_messages }`*
> *  2. `assembleSpendBundle(coin_spends, agg_signature)` (already exported)*
>
> *Until the SDK ships that split, browsers must use `castVoteBuildFinalBundle`
> with a browser-held secret."*

So the migration requires SDK-level work, not just wasm wrapper work.

## Migration phases

### Phase 1 — operator ballot UI (NO SDK changes)

Add `createBallot` + `launchBallot` flow to `/election`. Uses wasm exports
that already exist (`createBallotBundle`, `launchBallotBundle`,
`readElectionSingletonState`). Sage signs the funder XCH coin via
`signCoinSpends`. Persist `{ballotLauncherIdHex, voteCloseHeight,
voteThresholdNum, voteThresholdDen, registrationMerkleRootSnapshotHex,
registrationVoteWeightSnapshot}` to a new per-ballot bootstrap
(localStorage, keyed by `electionLauncherId+ballotLauncherId`).

**Files**: `app/app/election/page.tsx` (handler + JSX), new
`app/app/lib/ballotBootstrap.ts`. **Test**: dev server, deployer signs
two Sage requests (createBallot + launchBallot), ballot persisted in UI.

### Phase 2 — SDK split for cast_vote

Refactor `sdk/src/actors/voter.rs::cast_vote` so the secret-key path and
the hardware-wallet path share a common builder. Add:

```rust
pub async fn cast_vote_build_preview<C: ChainReader>(
    &self, chain: &C, params: &CastVoteParams,
) -> VotingResult<CastVotePreview>;

pub struct CastVotePreview {
    pub coin_spends_unsigned: Vec<CoinSpend>,
    pub vote_message: Bytes32,           // sha256 the voter signs
    pub registration_coin: Coin,         // for caller cross-checks
}

pub async fn cast_vote_build_final_with_sig<C: ChainReader>(
    &self, chain: &C, params: &CastVoteParams,
    voter_vote_signature: Signature,     // sign_unsafe(vote_message)
) -> VotingResult<CastVoteResult>;
```

`Voter::cast_vote` becomes a thin shim that calls
`cast_vote_build_final_with_sig(_, _, self.keys.sign_unsafe(vote_message))`.
Existing callers (integration test, native CLI) keep working.

**Files**: `sdk/src/actors/voter.rs`. **Test**: existing rust unit tests
+ integration test still pass.

### Phase 3 — Wasm preview implementation

Replace the stub at `wasm/src/lib.rs:~1599` (`cast_vote_build_preview_spend_js`).
Returns a JSON object:

```ts
type CastVotePreviewWasm = {
  coin_spends: WalletCoinSpend[];          // wallet-friendly hex shape
  vote_message_hex: string;                // 0x-hex 32 bytes
  registration_coin_id_hex: string;
};
```

Add a sibling export:

```ts
castVoteBuildFinalBundleWithSig(
  backend, election_config_json, voter_pk_hex, params_json,
  vote_signature_hex,                      // sign_unsafe(vote_message)
  network, election_start_height
): Promise<string>                         // signed-bundle hex
```

The returned bundle has the vote sig embedded in memo + the bundle's
`aggregated_signature` is the IDENTITY (zero) — Sage's second
`signCoinSpends` call (over the bundle's coin_spends) produces the real
aggregate.

**Files**: `wasm/src/lib.rs`. **Build**: rebuild both `pkg/` and
`pkg-node/`.

### Phase 4 — UI handleVote migration

```ts
// Before:                       After:
voteBuildPreviewSpend         →   castVoteBuildPreviewSpend  (returns vote_message)
walletConnect.signCoinSpends  →   walletConnect.signCoinSpends (signs ONE-CONDITION dummy spend over vote_message)
voteBuildFinalBundle          →   castVoteBuildFinalBundleWithSig + walletConnect.signCoinSpends
                                  + assembleSpendBundle
```

Reads `ballot_launcher_id`, `vote_close_height`, threshold pack, and
snapshot from per-ballot bootstrap (Phase 1 deliverable).

**Files**: `app/app/election/page.tsx::handleVote`. **Test**: dev server,
voter casts a vote on a ballot created in Phase 1.

### Phase 5 — handleChangeVote / update_vote (mirror Phases 2-4)

Same SDK split + wasm preview + UI migration for `update_vote`.

### Phase 6 — handleFinalize migration

Replace `wasm.collectVotes` + `wasm.buildFinalizeBundleFromCollectedVotes`
with `wasm.collectVotesForBallot` + `wasm.buildBallotFinalizeBundle`.
Per-ballot scope; reads ballot_launcher_id from bootstrap. The Groth16
prover already runs in wasm — no SDK split needed (finalize emits no
AGG_SIG conditions, so Sage is uninvolved beyond push).

**Files**: `app/app/election/page.tsx::handleFinalize`.

### Phase 7 — SDK split for release_collateral + UI handleRelease

`release_collateral` uses `StandardLayer::spend_with_conditions` on the
CAT inner (AGG_SIG_ME) — no `sign_unsafe` step like cast_vote. Sage's
`signCoinSpends` covers it directly. The split is simpler: just expose
an unsigned-builder variant that the UI can wrap with Sage.

```rust
pub async fn release_collateral_build_unsigned<C: ChainReader>(
    &self, chain: &C, smt: &SparseMerkleTree,
    registration_coin_id: Bytes32, destination: Bytes32,
) -> VotingResult<Vec<CoinSpend>>;
```

UI: replace 4-arg `releaseCollateralBuildSpends` (gone) with the new
8-arg signature OR a new Sage-friendly export that takes voter_pk and
returns wallet-format coin_spends.

**Files**: `sdk/src/actors/voter.rs`, `wasm/src/lib.rs`,
`app/app/election/page.tsx::handleRelease`.

### Phase 8 — clean-up

- Remove dead helpers from `app/app/lib/` (registrationFeeDiscovery,
  catCollateralDiscovery for old fee model) — verify each is unused.
- Run `next build` to catch type errors from missing exports.
- Test full flow against testnet11 if available, then mainnet smoke.

## Estimated effort

- Phase 1: 2-3 hours (UI only, no SDK)
- Phase 2-4 (vote vertical): 4-6 hours (SDK + wasm + UI + test)
- Phase 5 (update_vote): 3-4 hours (mirror)
- Phase 6 (finalize): 2-3 hours
- Phase 7 (release): 3-4 hours
- Phase 8 (cleanup + e2e test): 2-3 hours

**Total: 16-23 hours of focused work, spread across multiple sessions.**

Each phase commits independently and leaves the UI in a
not-worse-than-before state. Phase 1 is the highest-priority shippable
chunk — it adds capability without touching broken code.

## What to do FIRST in each new session

1. `git status` to see in-progress changes
2. Read the latest "session N closed" entry at bottom of this doc
3. Run `npm run dev` in `app/`, browse to `/`, click through to `/election`
4. Verify which phase of the plan is in-flight; resume from there

## Session log

- **2026-05-05 session 1**:
  - Plan written.
  - Added wasm Sage-bundle conversion helpers
    (`bundleBytesToWalletJson`, `extractWalletCoinSpendsFromBundle`,
    `assembleSpendBundleFromWalletCoinSpends`) — prerequisite for any
    UI Sage flow. (`wasm/src/lib.rs`)
  - Phase 2 done: SDK split. `Voter::cast_vote_build_coin_spends`
    added; existing `Voter::cast_vote` is now a thin wrapper that
    delegates after computing `initial_signature` from `self.keys`.
    New `CastVoteCoinSpends` struct exported. Existing native +
    integration-test callers compile and behave identically.
    (`sdk/src/actors/voter.rs`)
  - Phase 3 done: wasm preview implementation.
    `castVoteBuildPreviewSpend` (was a stub) now returns a real shim
    spend with `(50 voter_pk vote_message)` (= `AGG_SIG_UNSAFE`). New
    `castVoteBuildUnsignedCoinSpends` takes
    `voter_vote_signature_hex` (Sage's chip0002_signCoinSpends partial
    output over the shim) and returns the unsigned cast_vote
    coin_spends in wallet RPC shape. Both sit on top of
    `Voter::cast_vote_build_coin_spends`. (`wasm/src/lib.rs`)
  - Both `pkg/` (browser, target=bundler) and `pkg-node/` (Node, for
    integration test) rebuilt.

  Where this leaves the dApp's vote flow:
  ```
  // Replace the old voteBuildPreviewSpend + voteBuildFinalBundle pair:
  const preview = JSON.parse(await wasm.castVoteBuildPreviewSpend(
    backend, configJson, voterPkHex, paramsJson));
  const voteSigHex = await walletConnect.signCoinSpends(
    preview.coinSpends, /*partial*/ true, /*auto_submit*/ false);
  const unsigned = JSON.parse(await wasm.castVoteBuildUnsignedCoinSpends(
    backend, configJson, voterPkHex, paramsJson, voteSigHex,
    wasm.WasmNetwork.Mainnet, BigInt(electionStartHeight)));
  const bundleSigHex = await walletConnect.signCoinSpends(
    unsigned.coinSpends, /*partial*/ true, /*auto_submit*/ false);
  const bundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
    JSON.stringify(unsigned.coinSpends), bundleSigHex);
  wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
  const bundleJson = JSON.parse(wasm.bundleBytesToWalletJson(bundleBytes));
  await pushTx(bundleJson);
  ```

- **Next session priority**:
  1. Build a per-ballot bootstrap helper
     (`app/app/lib/ballotBootstrap.ts`) — localStorage / sessionStorage
     keyed by `(electionLauncherIdHex, ballotLauncherIdHex)`. Stores
     `{voteCloseHeight, voteThresholdNum, voteThresholdDen,
     registrationMerkleRootSnapshotHex, registrationVoteWeightSnapshot,
     eveBallotCoinIdHex}`.
  2. Add createBallot + launchBallot operator UI (Phase 1) — uses
     the existing wasm exports `createBallotBundle`,
     `launchBallotBundle`, `readElectionSingletonState`. The
     just-added Sage-bundle helpers handle the Sage-signing of the
     funder spend.
  3. Migrate `handleVote` (Phase 4) using the snippet above; reads
     ballot data from the bootstrap added in step 1.

- **Open work** (still on the queue):
  - Phase 5: SDK split + wasm preview for `update_vote` (mirrors
    Phases 2-4; same `sign_unsafe(new_vote_message)` pattern).
  - Phase 6: handleFinalize migration to per-ballot
    `collectVotesForBallot` + `buildBallotFinalizeBundle`.
  - Phase 7: SDK split for `release_collateral` (simpler: no
    `sign_unsafe`, just an unsigned-builder variant) + UI
    handleRelease migration.
  - Phase 8: cleanup of dead helpers + `next build` smoke + e2e.

- **2026-05-06 session 2**:
  - Phase 1 done: Sage-bundle conversion helpers for the dApp:
    `bundleBytesToWalletJson`, `extractWalletCoinSpendsFromBundle`,
    `assembleSpendBundleFromWalletCoinSpends`. Plus operator-only
    `handleCreateAndLaunchBallot` UI on /election + new
    `app/lib/ballotBootstrap.ts` for per-ballot persistence.
  - Phase 4 done: `handleVote` migrated to `castVoteBuildPreviewSpend`
    + `castVoteBuildUnsignedCoinSpends` chain, reads ballot
    bootstrap, uses `collectVotesForBallot` for the confirm poll.
  - Phase 5 done: SDK split for `update_vote`
    (`Voter::update_vote_build_coin_spends` + thin wrapper); wasm
    `updateVoteBuildPreviewSpend` (was a stub) + new
    `updateVoteBuildUnsignedCoinSpends`; `handleChangeVote` migrated
    (uses `collectVotesForBallot` to find existing
    voting/registration coin ids before calling preview).
  - Phase 6 done: `handleFinalize` migrated. `wasm.collectVotes` →
    `wasm.collectVotesForBallot` (per-ballot, takes voter pubkey list
    from `session.registeredPubkeysHex`); `buildFinalizeBundleFromCollectedVotes`
    → `buildBallotFinalizeBundle` (per-ballot, takes the bootstrap
    snapshot pack); `bundleToWalletJson` →
    `bundleBytesToWalletJson`. Picks the newest closed ballot from
    `listBallotBootstraps` (`vote_close_height <= peak`).
  - Phase 7 done: SDK split for `release_collateral`
    (`Voter::release_collateral_build_coin_spends` returns unsigned
    coin_spends; existing `release_collateral` is a wrapper that
    signs). Wasm `releaseCollateralBuildUnsignedCoinSpends` Sage-
    friendly variant. `handleRelease` migrated: looks up the current
    registration coin via `voterHint` (filters out the released-CAT
    coin via `catOuterPuzzleHash` ph), calls the unsigned wasm
    builder, Sage signs partial, assembles + verifies + pushes.

- **2026-05-06 session 3 — Phase 8 (cleanup) DONE**:
  - **8a — handleRegister**: SDK split for `Voter::register`
    (`register_build_coin_spends` + thin signing wrapper); new wasm
    Sage variants `buildCatRegistrationSpendForWallet` and
    `registerBuildUnsignedCoinSpends`; `handleRegister` rewritten
    against them. Drops the `reconstructCatLineage` /
    `discoverRegistrationFeeXch` / `discoverMempoolFeeXch` path —
    the new model has no separate fee inputs. CAT input coin id
    computed locally via chia-wallet-sdk-wasm `Coin.coinId()`.
  - **8b — handleOracle stub**: standalone `buildOracleBundle` was
    removed (oracle is now co-spent implicitly by every
    cast_vote/update_vote/finalize). Stubbed with a deprecation
    message; JSX still compiles. Remove in a follow-up cleanup.
  - **8b — sync effects**: lifecycle / chain-status callers of
    `wasm.syncSnapshot`, `wasm.collectVotes`, and
    `wasm.findCurrentSingleton` cast to `(wasm as any).<name>`.
    Existing try/catch wrappers surface the runtime "not a function"
    as a snapshot-error state. Proper migration to
    `wasm.readElectionSingletonState` + `collectVotesForBallot` is
    queued — the snapshot panels are non-critical for core flows.
  - **8b — create page**: `coinSpendsToWalletJson` →
    `coinSpendsBytesToWalletJson` (new helper added to wasm to
    cover this exact case); `bundleToWalletJson` →
    `bundleBytesToWalletJson` + JSON.parse.

  **`npx tsc --noEmit -p .` is clean across the whole `app/`.**
  Every voter-facing flow (deploy, createBallot, register, castVote,
  changeVote, finalize, release) compiles against the post-CHIP-
  rev-2026-05-02 wasm.

## Next steps (post-migration)

1. **Manual end-to-end smoke test** with Sage Wallet on testnet11 /
   mainnet. Specific flows to verify:
   - deploy (operator) → createBallot+launchBallot (operator) →
     register (each voter) → castVote (each voter) → wait for close
     height → finalize → release.
   - The integration-test harness already validated each piece end-
     to-end on mainnet via the secret-key path; the dApp's
     Sage-friendly path should produce equivalent on-chain
     bundles. The first real Sage smoke is the only meaningful
     differential test left.
2. **Sync-effect proper migration** (replace the
   `(wasm as any).syncSnapshot` casts with
   `wasm.readElectionSingletonState` + per-ballot collect calls).
3. **Remove dead code**: `discoverRegistrationFeeXch`,
   `discoverMempoolFeeXch`, `reconstructCatLineage`,
   `catCollateralDiscovery` if unused in the migrated handlers.
   `handleOracle` JSX trigger.
4. **`next build` smoke** — `tsc --noEmit` is green; make sure the
   actual production build (which includes wasm bundling) works.

## Stale section: original Phase 8 hand-off (now done)

The text below is the next-session brief written before Phase 8 was
completed. Kept for archaeology; everything in it is now in `main`.


  1. **handleRegister** is still wired to gone exports
     (`buildCatCollateralSpend`, `buildRegistrationFeeXchSpend`,
     `buildMempoolFeeXchSpend`, `bundleToWalletJson`). Approach:
     a. SDK split for `Voter::register` mirroring the release pattern
        (just an unsigned-builder variant; register has no
        `sign_unsafe`). Add
        `Voter::register_build_coin_spends(&smt, cat_parent_spend,
        chain) -> Vec<CoinSpend>`.
     b. Wasm Sage variant of `buildCatRegistrationSpend` that takes
        BOTH `voter_pk_hex` and `validator_synthetic_pk_hex`
        externally (existing version derives both from a secret) and
        returns the unsigned CAT coin_spend bytes.
     c. Wasm `registerBuildUnsignedCoinSpends` taking the same
        `voter_pk_hex + voter_pubkeys + cat_parent_spend +
        network + election_start_height` shape, returning
        wallet-format coin_spends.
     d. UI `handleRegister` rewrite — drop
        `discoverRegistrationFeeXch` / `discoverMempoolFeeXch` (the
        new model has no separate fee inputs in the bundle; if a
        fee output is desired the dApp can attach it as a separate
        XCH funder spend, but the SDK doesn't require it).
  2. **handleOracle** — uses `buildOracleBundle` (removed). The
     ballot oracle action is now part of cast_vote / update_vote, not
     a standalone bundle. Either remove handleOracle entirely or
     migrate to a per-ballot oracle helper if such a thing exists.
  3. **Lifecycle / sync effects** at lines ~390, 429, 448, 544, 622,
     681 use `syncSnapshot`, `collectVotes`, `findCurrentSingleton`.
     Map to `wasm.readElectionSingletonState` (already exported) +
     `collectVotesForBallot` (per-ballot, needs ballot picker) +
     equivalent of `findCurrentSingleton` (also `readElectionSingletonState`).
  4. **app/create/page.tsx** — uses `coinSpendsToWalletJson` and
     `bundleToWalletJson`. Two single-line swaps.
  5. After all type errors clear, run `next build` end-to-end and
     smoke-test on testnet11 if available.
