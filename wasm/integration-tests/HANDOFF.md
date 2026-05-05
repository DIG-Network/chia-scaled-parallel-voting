# Handoff — complete phases 8-11 of the wasm e2e integration test

You're picking up a Node.js test harness that drives the chip-voting-wasm
bindings end-to-end against live Chia mainnet, mirroring `cli/src/bin/live_integration_test.rs`.
Three phases (deploy, createBallot, launchBallot) are confirmed on chain.
Four phases remain. **Phase 8 (register) has a hard on-chain bug that
must be diagnosed and fixed first**; phases 9-11 follow the same
template once register works.

---

## Run command

```bash
cd CHIP/wasm/integration-tests
node live_integration.mjs --credentials ../../.test-credentials \
  --run-create-ballot --run-register --push
```

Flags:
- `--credentials <path>`: required for any write phase
- `--push`: actually broadcast (otherwise dry-run only)
- `--force-redeploy`: deploy a fresh Election Singleton (~10 mojos, creates a stranded singleton)
- `--run-create-ballot`: run phases 6+7 (creates and launches a Ballot Coin)
- `--run-register`: run phase 8

**Cached state lives in `wasm/integration-tests/.artifacts/`** (gitignored).
`deploy.json` carries the active launcher; `ballots.json` tracks created ballots.
Re-runs reuse cached unless `--force-redeploy` / `--force-recreate-ballot` flags.

---

## What works — three phases live on mainnet

| Phase | Status | Mainnet block (last verified) |
|---|---|---|
| 0: env smoke | ✅ | — |
| 1: pure helpers | ✅ | — |
| 2: ballot reads (`listBallots` / `getBallot`) | ✅ | — |
| 3: BIP39→BLS ceremony (matches `.test-credentials` addresses) | ✅ | — |
| **4: deploy Election Singleton** | ✅ ON CHAIN | 8684717 |
| 5: voter readiness (XCH + DIG balances) | ✅ | — |
| **6: createBallot** | ✅ ON CHAIN | confirmed |
| **7: launchBallot (eve coin)** | ✅ ON CHAIN | 8684722 |
| 8: **register** | 🟥 **bundle pushes but consensus rejects** | — |
| 9: castVote / updateVote | ⏸ scaffold not wired | — |
| 10: finalize | ⏸ scaffold not wired | — |
| 11: release | ⏸ scaffold not wired | — |

---

## Phase 8: register — the hard problem

### What's working
- `wasm.buildCatRegistrationSpend(backend, voter_secret_hex, cat_input_coin_id_hex,
  election_launcher_id_hex, cat_tail_hash_hex, collateral_amount)` → 2549 streamable bytes
- `wasm.registerBuildSpends(...)` → 7996-byte bundle
- `wasm.verifyBundleLocally(bundle, network)` → passes (CLVM dry-run, balance check)
- `coinset.org /push_tx` → returns `SUCCESS` (or `ALREADY_INCLUDING_TRANSACTION` on retries)

### What's broken
- `coinset.org /get_mempool_item_by_tx_id` for the register tx: `TX_NOT_IN_MEMPOOL`
- The predicted Registration Coin puzzle hash (computed by
  `wasm.freshRegistrationCoinPuzzleHash(config, voter_pk)`) never yields a coin record
- The validator's CAT input coin ID isn't visibly spent on chain

**Diagnosis: bundle is admitted to mempool, then rejected at full
consensus validation, then dropped silently.** Local dry-run (CLVM
`run_program`) doesn't catch the mismatch — meaning the divergence is
in something CLVM can't validate locally without full chain context
(e.g., AGG_SIG signature mismatch, announcement mismatch, or coin
puzzle-hash declared-vs-actual divergence that only fails when the
parent is read from the actual chain).

### Three concrete suspects

1. **CAT lineage proof reconstruction divergence.** My wasm port of
   `cli/src/bin/live_integration_test.rs::build_cat_collateral_spend`
   reconstructs the CAT lineage proof via `chia_sdk_driver::Cat::parse_children`.
   The parent's puzzle/solution come from the `JsChainBackend.puzzleAndSolution`
   callback, which returns `JsPuzzleSolution { puzzleHex, solutionHex }`.
   `coinset.mjs::puzzleAndSolution()` returns hex with `0x` prefix; the
   wasm decoder (in `wasm/src/lib.rs::record_from_js`'s sibling
   `parse_program_hex`) trims the prefix. **But the on-chain bytes
   themselves may be reconstructed differently** if the SDK's Bytes32
   serde behaves differently when crossing the JS↔wasm boundary vs
   reading directly from the rust `chia_query::ChiaQuery`.

2. **`create_reg_msg` byte-equality.** The on-chain register action
   asserts a specific announcement message:
   ```
   sha256("create_reg" || election_launcher_id || pk_bytes || reg_outer_ph || amount_be8)
   ```
   My wasm impl in `buildCatRegistrationSpend` (lines ~720-740 of
   `wasm/src/lib.rs`) computes this byte-for-byte. But subtle
   issues — e.g., `pk_bytes` being the synthetic vs the raw BLS pubkey,
   `amount_be8` truncating `u64` → 7 bytes, etc. — would silently break
   it. **Worth byte-level verification against the rust test's
   `compute_create_reg_msg` (line ~883 of `live_integration_test.rs`).**

3. **AGG_SIG_ME augmentation mismatch.** My
   `sign_bundle_signature` wasm impl uses `chia_sdk_signer::RequiredSignature::from_coin_spends`
   + chia mainnet's hardcoded `agg_sig_me_additional_data`. If that
   constant or the augmentation rule diverges from what `dig_l1_wallet::transaction::sign_coin_spends`
   does on native, the sig fails consensus AggSig verification.
   Smaller bundles (deploy, launchBallot) work, suggesting the
   constant is right — but register is the first bundle with TWO
   AGG_SIG_ME conditions (validator's CAT spend + voter's BLS sig
   on the registration message). One of those sigs may be over the
   wrong message.

### Diagnostic plan (do this FIRST in the next session)

Run the rust `live_integration_test.rs` against the **same** mainnet
funder + the **same** validators, capture the rust-built register
bundle's bytes, and diff against the wasm-built bundle's bytes.

```bash
# Build the rust live test
cd CHIP
cargo build --release --bin chip-voting-live-test

# Run it against mainnet, dump bundles to disk
CHIP_VOTING_DUMP_DIR=/tmp/rust-bundles ./target/release/chip-voting-live-test \
  --credentials .test-credentials --network mainnet 2>&1 | tee /tmp/rust-run.log

# Then run the wasm test, dumping the equivalent bundle
cd wasm/integration-tests
# (dump-bundle hook needs to be added — see below)
node live_integration.mjs --credentials ../../.test-credentials --run-register
```

The wasm test doesn't yet dump the register bundle to disk. Add a
`--dump-bundles <dir>` flag that writes:
- `register_validator1.bundle.bytes` (raw streamable bytes of the assembled bundle)
- `register_validator1.cat_parent_spend.bytes` (just the CAT spend)
- `register_validator1.params.json` (the inputs the test used)

Then byte-diff:
```bash
diff <(xxd /tmp/rust-bundles/register-*.bundle.bytes) \
     <(xxd /tmp/wasm-bundles/register_validator1.bundle.bytes)
```

The first byte that differs identifies which field — typically:
- **First ~32 bytes** = parent_coin_info → JsCoinRecord round-trip issue
- **~bytes 32-64** = puzzle_hash → wrong synthetic pubkey or curry mismatch
- **bytes 72-200** = puzzle_reveal → CAT outer or inner puzzle currying off
- **mid-bundle** = solution → conditions list / announcement message wrong
- **Last 96 bytes** = aggregated_signature → AggSig augmentation

### Files to inspect when fixing

- `wasm/src/lib.rs::build_cat_registration_spend_js` (lines ~681-810) — the wasm export
- `cli/src/bin/live_integration_test.rs::build_cat_collateral_spend` (lines ~784-876) — the rust reference
- `cli/src/bin/live_integration_test.rs::compute_create_reg_msg` (line ~883) — the announcement formula
- `sdk/src/actors/voter.rs::reconstruct_cat_lineage` (line ~1876) — the lineage path the SDK uses internally
- `wasm/integration-tests/live_integration.mjs::phaseRegisterVoter` (line ~870ish) — the JS test driver

---

## Phases 9-11 — pattern (once register works)

All three follow `phaseCreateBallot`'s template:

```
1. Read deploy + ballot artifacts from .artifacts/
2. Find the inputs needed (Voting Coin, registered voter coin, etc.)
3. Call wasm.<actor>BuildXxxBundle → bundle hex
4. Decode bundle, extract coin_spends via wasm.extractCoinSpendsFromBundle
5. Sign with wasm.signCoinSpends + appropriate secret
6. Re-assemble via wasm.assembleSpendBundle
7. wasm.verifyBundleLocally
8. pushSpendBundleBytes (uses manual /push_tx fallback in push.mjs)
9. pollUntilConfirmed against the predicted output coin id
10. Persist artifacts
```

### Phase 9: cast vote

**Wasm export already wired:** `wasm.castVoteBuildFinalBundle(backend,
configJson, voterSecretHex, paramsJson, network, electionStartHeight)`.

**Inputs:**
- voter's account-path BLS secret (the validator's mnemonic-derived `m/12381'/8444'/2'/0`)
- A `WasmCastVoteParams` JSON: `{ ballotLauncherIdHex, voteDataHex,
  voteCloseHeight, voteThresholdNum, voteThresholdDen,
  registrationMerkleRootSnapshotHex, registrationVoteWeightSnapshot,
  votingCoinAmount }`. The thresholds + close_height + outcome_domain
  must match the values you used at `launchBallotBundle` time
  (persist them in `ballots.json` already — done by phaseLaunchBallot).
- The `vote_data` is `sha256("vote:" + choice_label)` per the
  app's `lib/elections.ts::deriveVoteData` convention. Use a known
  label like "Yes" so the outcome is identifiable.

**Pre-conditions:** the voter must be **already registered** — i.e.,
their unspent Registration Coin must exist at the predicted ph. The
SDK's cast_vote walks the chain to find it.

**Output:** JSON-stringified `WasmVoteResult { votingCoinIdHex,
spendBundleHex, voteSignatureHex }`. Push the bundle, poll for the
voting coin confirmation.

### Phase 10: finalize

**Wasm export already wired:** `wasm.buildBallotFinalizeBundle(...)`.

**Inputs:**
- `votes_json`: a JSON array of `VoteRecordWire` objects. Get this
  by calling `wasm.collectVotesForBallot(backend, configJson,
  ballotLauncherIdHex, voterPubkeysHexJson)` first — that walks
  the chain to find every Voting Coin under this ballot.
- `proving_key_bytes`: arkworks-compressed proving key.
  **Already cached in `.artifacts/deploy.json::provingKeyBytesB64`** —
  decode from base64. The Groth16 prover runs in wasm.
- `vote_outcome_hex`: the canonical 32-byte outcome (whatever
  message most signers signed; for a yes/no ballot with majority
  Yes, this is `sha256("vote:Yes")`).
- `WasmFinalizeParams`: same per-ballot snapshots used at
  launch_ballot time.

**Pre-conditions:** vote_close_height must have passed. If you set
close_height = peak + 50 at create_ballot time, ~25 minutes of real
time on mainnet. The harness's `vote_close_height` lives in
`ballots.json::voteCloseHeight`. Add a `phaseWaitForCloseHeight()`
that polls `peakHeight()` until it exceeds the close height (mirrors
`live_integration_test.rs::phase_wait_window`).

**Output:** Streamable-encoded SpendBundle hex. Sign with empty
keys (finalize emits no AggSig conditions of its own — the off-chain
aggregate Groth16 proof is what authenticates), push, poll for the
recreated ballot coin's puzzle hash to surface (the new state has
`finalized=true`).

### Phase 11: release

**Wasm export already wired:** `wasm.releaseCollateralBuildSpends(...)`.

**Inputs:** voter secret, registered_voter_pubkey_list_json (for SMT —
includes the voter being released), `registrationCoinIdHex` (must
match the on-chain reg coin), `destinationPuzzleHashHex` (where the
returned CAT collateral lands — typically the validator's own
synthetic p2 ph).

**Pre-conditions:** the voter's Registration Coin must be in
fresh state (no votes cast OR votes cast but not finalised — see
SDK source for the exact state contract). After
`phase_release` the validator's CAT balance returns to its pre-
register total.

---

## Files / utilities you have to work with

```
wasm/integration-tests/
├── live_integration.mjs    — phase runner (phaseDeploy ... phaseRegisterVoter)
├── walletKeys.mjs          — chia BIP39 → synthetic key (verified)
├── coinset.mjs             — coinset.org HTTP client w/ retry
├── chainBackend.mjs        — JsChainBackend (6 methods, all working)
├── push.mjs                — pushSpendBundleBytes + pollUntilConfirmed
├── credentials.mjs         — .test-credentials parser
├── encoding.mjs            — JS Streamable encoders (mostly superseded
│                              by wasm.extractCoinSpendsFromBundle)
├── artifacts.mjs           — .artifacts/{deploy,ballots}.json persistence
└── HANDOFF.md              — this file
```

## Wasm exports relevant to remaining phases

```ts
// Already wired & tested in phase 4-7:
runSingleParticipantCeremony(): { verificationKeyHex, provingKeyBytes }
buildXchFunderSpend(parent, synthPk, amount, change): Uint8Array
buildDeployBundle(params, parentCoin, funderPk): { coinSpendsBytes, ... }
buildCatRegistrationSpend(backend, secret, catCoinId, launcherId, tail, collateral): Uint8Array
extractCoinSpendsFromBundle(bundleBytes): Uint8Array  // length-prefixed coin_spends list
signCoinSpends(coinSpends, secrets, network): Uint8Array  // 96-byte BLS aggregate
assembleSpendBundle(coinSpends, sig): Uint8Array
verifyBundleLocally(bundle, network): void

// Wired but not yet driven by an integration phase:
castVoteBuildFinalBundle(backend, config, voterSecret, params, network, startHeight): string
updateVoteBuildFinalBundle(backend, config, voterSecret, params, network, startHeight): string
buildBallotFinalizeBundle(backend, config, ballotId, voteOutcome, params, votes, pk, network, startHeight): string
collectVotesForBallot(backend, config, ballotId, voterPubkeysJson): string
releaseCollateralBuildSpends(backend, config, voterSecret, voterPubkeysJson, regCoinId, destination, network, startHeight): string
announceBallotFinalization(backend, config, params, network): string
```

All phase-9+ exports return JSON-stringified bundles that you'll
decode + extract coin_spends + sign + assemble + push the same way
phase 6 / 8 do.

---

## Session-budget guidance

- **Diagnose register: 60-90 min.** Run rust live test, byte-diff
  bundle, identify divergence. Most likely fix is in
  `wasm/src/lib.rs::build_cat_registration_spend_js` or its
  pubkey/announcement byte handling.
- **Phases 9-11: 1-2 hours each** once register works. Each is
  mechanically following the phase-6 pattern with different inputs.
- **Total: realistically a 5-8 hour session** to get phases 8-11
  all live on mainnet end-to-end.

If the rust live test ALSO fails on register against the cached
mainnet election (which is possible — this election was deployed via
wasm + may have subtly different state than what rust expects), the
fastest path is to deploy a fresh test election via rust, run the
full rust pipeline through register on it, and then point the wasm
test at THAT election (override `.artifacts/deploy.json` with the
rust deployment's launcher id + config).

Good luck.
