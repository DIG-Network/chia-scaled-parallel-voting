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
