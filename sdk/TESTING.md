# Testing the CHIP voting SDK

This document describes the SDK's test architecture, what each layer
covers, and how to run / extend the suite.

---

## Layers

```
┌────────────────────────────────────────────────────────────────────┐
│  Layer 4: tests/integration.rs (consensus-runner)                   │
│  Submits real spend bundles to chia-sdk-test::Simulator. Validates  │
│  that our compiled puzzles execute on the SAME consensus runner    │
│  Chia mainnet uses, not just our test harness. Includes adapter     │
│  wrapper that lets us spend a coin whose puzzle IS one of our       │
│  action puzzles directly (for puzzles that work standalone).        │
├────────────────────────────────────────────────────────────────────┤
│  Layer 3: src/clvm_runner.rs (direct CLVM execution)                │
│  Loads each compiled .rue.hex constant, allocates structured        │
│  solutions from typed Rust data, runs the puzzle via                │
│  chia_sdk_types::run_puzzle, parses the output. Tests action        │
│  puzzles' business logic in isolation: announce_finalization,       │
│  release, vote — all success paths AND assertion-violating          │
│  failure paths.                                                     │
├────────────────────────────────────────────────────────────────────┤
│  Layer 2: cargo test --lib (per-module)                             │
│  Pure-Rust unit tests inline in each src/* file. Covers arithmetic, │
│  serde round-trips, error paths, ceremony orchestration, SPT ops,   │
│  all puzzle-hash predictors, Aggregator pre-checks + witness prep.  │
├────────────────────────────────────────────────────────────────────┤
│  Layer 1: build.rs                                                  │
│  Embeds compiled Rue artefacts at compile time. A stale or missing  │
│  `puzzles/compiled/*.hex|.hash` causes immediate compile error.     │
└────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — compile-time embedding

`build.rs` re-runs whenever `puzzles/compiled/**` changes. The
`puzzles.rs` module references each artefact via `include_str!`. If
the build script fails or a `.hex`/`.hash` file is malformed, the
crate won't compile — there is no runtime path that can encounter a
missing puzzle.

**To regenerate after a Rue change**:

```powershell
cd CHIP
./build.ps1            # or ./build.sh on bash
cd sdk
cargo build            # picks up the new .hex / .hash
```

---

## Layer 2 — unit tests (`cargo test --lib`)

Run with:

```powershell
cd CHIP\sdk
cargo test --lib
```

Each module under `src/` carries a `#[cfg(test)] mod tests { ... }`
block. The convention:

* **`puzzles.rs`** — every `curry_tree_hash` / `hash_atom` / `hash_pair`
  helper is tested against `clvm_utils`'s own arithmetic (so any
  upstream change immediately surfaces here). `voter_hint`,
  `fresh_registration_coin_puzzle_hash`,
  `election_singleton_puzzle_hash`, and the two Merkle-root helpers
  are tested for determinism, per-voter / per-election uniqueness,
  and order-independence (where applicable).

* **`merkle.rs`** — round-trips for empty trees, populated trees, and
  boundary slots (`u32::MAX`); proof verification against both the
  active leaf and the empty leaf for a populated tree; root
  determinism under permutations of insert order.

* **`config.rs`** — `validate()` rejects every invalid combination
  (wrong tree_depth, wrong max_signers, bad hex, short hex, wrong VK
  length); JSON round-trip preserves all fields; typed accessors
  return the exact bytes the hex encodes; `EMPTY_LEAF_HASH` is
  cross-checked against a `python -c sha256(b"\x00"*48)` golden value.

* **`state.rs`** — `RegistrationStateWire` and `VoteRecordWire`
  round-trip through `serde_json::to_string + from_str`; `into_state`
  rejects malformed pubkey hex and short pubkey hex; `ElectionState::genesis`
  and `RegistrationState::fresh` set every field to its documented
  initial value.

* **`ceremony/`** — coordinator rejects a contribution with a wrong
  chain link, with a wrong attestation count, or zero contributions;
  participant + coordinator round-trip on a happy-path 2-participant
  ceremony; transcript hash is deterministic and independent of the
  attestation vector.

* **`prover/proof.rs`** — 9 tests: `Scalars::compute` is deterministic
  and changes when ANY public input changes (one assertion per input);
  the count input is verified to use big-endian 8-byte encoding (the
  same encoding the on-chain Rue side uses); the agg_signers scalar
  is verified to be `sha256(pk.to_bytes())` (G1 compressed — what
  Groth16 consumes); `Scalars::as_array` preserves order; `Groth16Proof`
  serde round-trip; **`Groth16Proof::from_arkworks → to_arkworks`
  round-trip** (bridges typed `ark_groth16::Proof<Bls12_381>` to the
  hex-encoded wire form); `to_arkworks` rejects malformed hex AND
  off-curve points with TYPED errors.

* **`prover/conversions.rs`** — 10 tests pin the cryptographic
  compatibility between `chia_bls` and `arkworks::bls12_381`:
  byte-identical G1/G2 compressed encodings; PK and Signature
  round-trip losslessly through arkworks types; G1 scalar conversion
  preserves big-endian semantics; G1 aggregation is identity for
  empty input, commutative, and 3 copies of x equal 3*x. This
  module is what makes the on-chain `bls_pairing_identity` opcode
  accept proofs our off-chain arkworks prover generates.

* **`prover/circuit.rs`** — 9 tests for the actual Groth16 circuit
  + prover pipeline:
  * `generate_test_setup` produces a valid (PK, VK).
  * `prove → verify_offchain` round-trips for valid majority votes.
  * Tampered public inputs fail `verify_offchain` (Groth16
    soundness).
  * `prove` rejects `BelowThreshold` (2k ≤ n) before running the
    prover.
  * Boundary majority (2k = n+1) succeeds.
  * VK `chia_chunked_bytes` is exactly 576 bytes (the layout the
    on-chain `finalize.rue` expects: alpha_g1 + beta_g2 + gamma_g2
    + delta_g2 + 5 IC).
  * VK serialise/deserialise round-trips.
  * `public_inputs_as_fr` is deterministic.
  * **`public_inputs_as_fr_match_scalars_compute`** — the cross-
    layer consistency contract: the circuit's Fr public-input
    commitment EQUALS `bytes32_to_fr(Scalars::compute(...).s_i)`
    for all 4 inputs. This is what guarantees the off-chain Groth16
    prover and the on-chain `finalize.rue` IC linear combination
    speak the same scalars byte-for-byte.

* **`actors/deployer.rs`** — `derive_launcher_id` is deterministic and
  changes per amount; `config_for_launcher` produces a config that
  passes `.validate()`; `genesis_inner_puzzle_hash` is deterministic
  and per-launcher; `election_actions_merkle_root` changes when any
  curried parameter (VK, fee, etc.) changes; `uint_atom_hash` is
  tested against CLVM canonical encodings (zero → empty atom,
  high-bit pad, no-pad, multi-byte).

* **`actors/voter.rs`** — `vote_message` and `release_message` are
  deterministic and domain-separated by their `b"vote"` / `b"release"`
  prefixes; `convert_coin` accepts both `0x`-prefixed and bare hex,
  and rejects bad hex / short hex.

* **`chain.rs`** — `ChainReader` trait + adapters for `chia_query::ChiaQuery`
  (production) and `chia_sdk_test::Simulator` (tests, via the
  `SharedSimulator` shim). Tests pin the simulator-backed adapter's
  read paths: unspent coin lookup by puzzle hash, `puzzle_and_solution`
  returns `None` for unspent coins.

* **`actors/aggregator.rs`** — generic over `C: ChainReader` (defaults
  to `chia_query::ChiaQuery`). The full `WHAT/HOW/WHY` covered tests:
  * `sync_after_deploy_recovers_genesis_state` — eve-singleton sync
    populates state, voter_set, smt to their genesis values.
  * `sync_against_empty_chain_returns_not_deployed` — typed error
    surface on a chain with no deploy.
  * `eve_puzzle_hash_matches_deployer_prediction` — the
    aggregator's eve puzzle hash predictor agrees byte-for-byte with
    the deployer's path; if they ever drifted, sync would miss every
    singleton.
  * `accessors_before_sync_return_not_deployed` — pin the lifecycle
    contract (must sync first).
  * `collect_votes_empty_voter_set_returns_empty_vec` — the common
    pre-vote state short-circuits cleanly.
  * `collect_votes_before_sync_returns_not_deployed` — lifecycle.
  * `build_finalize_before_sync_returns_not_deployed` — lifecycle.
  * `build_finalize_rejects_unregistered_voter` — off-chain pre-check
    for the on-chain Merkle-membership constraint.
  * `build_finalize_rejects_duplicate_voter` — duplicate detection
    in the pre-aggregation gate.
  * `build_finalize_rejects_below_threshold` — strict-majority
    pre-check before the prover boundary.
  * `build_finalize_reaches_prover_boundary` — with valid majority,
    real signatures, and a populated SPT, build_finalize fails ONLY
    at the prover boundary (returns `ProvingError(_)`), proving every
    pre-check passed.
  * `prepare_finalize_witness_returns_consistent_witness` — every
    field of the off-chain witness is internally consistent
    (signer_pubkeys ↔ merkle_proofs cardinality, agg_signers equals
    G1 sum, scalars match the prover's deterministic computation).
  * `prepare_finalize_witness_aggregated_signature_verifies` — the
    aggregated G2 signature passes Chia's per-pair augmented BLS
    `aggregate_verify` (the equation the on-chain Groth16 circuit
    asserts in zk).
  * `prepare_finalize_witness_merkle_proofs_verify` — every per-
    signer Merkle inclusion proof verifies against the witness's
    `registration_merkle_root` with the signer's `active_leaf_hash`.
  * `prepare_finalize_witness_rejects_signatures_over_wrong_message`
    — the off-chain aggregate-verify pre-check catches signers who
    signed a stale or wrong vote_outcome.
  * `prepare_finalize_witness_rejects_malformed_signature` /
    `_rejects_bad_hex_signature` — typed `InvalidSignature` errors
    for the two parse-failure modes.
  * `aggregate_pubkeys_*` and
    `canonical_vote_message_is_sha256_of_outcome_and_election_id` —
    pin the BLS arithmetic and the canonical message formula
    against hand-computed values.
  * `threshold_inequality_is_strict_majority` — the off-by-one
    boundary (k=5 of 10 fails, k=6 passes).

---

## Layer 3 — direct CLVM execution (`cargo test --lib clvm_runner::`)

`src/clvm_runner.rs` is a `#[cfg(test)]`-only module that exposes a
`PuzzleRunner` harness. It:

1. Loads a compiled `.rue.hex` constant via `Program::from(bytes)`.
2. Allocates a structured solution from typed Rust data via
   `clvm_traits::ToClvm`.
3. Runs the puzzle via `chia_sdk_types::run_puzzle` (the canonical
   chia consensus dialect, with the standard cost limit).
4. Parses the output via `clvm_traits::FromClvm` — typically as a
   `(Truth, Vec<Condition<NodePtr>>)` tuple.
5. Asserts on the output's structural shape and condition contents.

Coverage:

* **`announce_finalization`** — emits exactly ONE
  `CreateCoinAnnouncement` whose message equals
  `sha256("finalized" || vote_outcome || count_be8 || root)`;
  state-unchanged invariant; rejects `finalized=false`.
* **`release`** — emits two conditions (`AssertCoinAnnouncement`
  with the finalization message id + `AggSigMe` for the voter's
  release authorisation); transitions `release_destination` to the
  supplied destination; rejects when already released.
* **`vote`** — emits the per-voter `AggSigUnsafe` over
  `sha256("vote" || election_id || pubkey || vote_data)`;
  transitions `has_voted` false → true and commits `vote_data`;
  rejects double-voting; rejects voting after release.
* **embedded artefact smoke test** — every embedded `.rue.hex` is
  loadable (catches build-script regressions immediately).
* **basic CLVM machinery roundtrip** — `clvm_quote!(42)` runs and
  parses to `42`; baseline check that the underlying allocator +
  dialect + cost limit are wired correctly.

NOTE on what's NOT covered at this layer:
The election finalizer, registration_coin finalizer, and action
layer dispatcher are double-curried wrappers whose only business
logic is a CreateCoin construction (and, for registration_coin,
choosing between two branches). They are validated end-to-end by the
deploy integration test (Layer 4 below); driving them in isolation
would require reconstructing the action layer's `last_action_output`
shape, which has subtle CLVM-shape dependencies on the upstream Rue
compiler. The bug-density of these wrappers is low; the bug-density
of our hand-rolled solution shape would be HIGH. They live behind
the integration tests by design.

## Layer 4 — integration tests (`cargo test --test integration`)

Run with:

```powershell
cd CHIP\sdk
cargo test --test integration
```

Each integration test:

1. Spins up a fresh `Simulator` (ChaCha8-seeded for determinism).
2. Pre-funds a standard p2 coin via `sim.bls(amount)` OR inserts a
   coin at a custom puzzle hash via `sim.insert_coin(coin)`.
3. Drives the SDK (or a hand-built spend bundle) through some
   scenario.
4. Asserts the simulator's chain state matches what we predicted
   off-chain.

Current coverage:

### Deploy + state-prediction

* **`deploy_creates_eve_singleton_at_predicted_puzzle_hash`** — the
  master invariant: an `ElectionDeployer::build_deploy_bundle` ⨯
  `Simulator::spend_coins` cycle produces an eve singleton at the
  exact puzzle hash predicted by `election_singleton_puzzle_hash`.
* **`deploy_then_redeploy_with_different_funder_yields_different_election_id`**
  — replay safety across funder coins.
* **`config_emitted_by_deploy_self_validates`** — every shipped
  config passes `.validate()`.
* **`predicted_inner_puzzle_hash_uses_action_layer_constants`** —
  guards against a stale `puzzles/compiled/action.rue.hash`.
* **`tree_depth_constant_is_32`** — pins the SPT depth that every
  other component depends on.

### Consensus-level CLVM execution

* **`announce_finalization_executes_on_simulator`** — wraps the
  `announce_finalization` action puzzle in a tiny adapter
  (`(r (a 2 (c 5 ())))` — strip the `(state_truth . conds)`
  wrapping the action returns), insert at a puzzle hash, build a
  CoinSpend, submit via `Simulator::new_transaction`. Proves our
  compiled puzzle bytecode is BYTE-CORRECT and accepted by the
  consensus runner — not just our test harness.
* **`announce_finalization_on_simulator_rejects_non_finalized`** —
  same setup with `finalized=false` state. Bundle MUST be rejected
  by consensus on CLVM trap. Pins the safety guard at the consensus
  layer.
* **`bls_aggregate_verify_roundtrips_for_two_signers`** — sanity
  check that `chia_bls::aggregate` + `chia_bls::aggregate_verify`
  (Chia's augmented BLS) round-trip correctly for our use case
  (two signers, distinct messages).

### End-to-end Groth16 + CLVM (the master compatibility test)

* **`groth16_proof_accepted_by_clvm_pairing_identity_opcode`** —
  the master cross-language compatibility test. Generates a
  trusted setup via arkworks, builds a real Groth16 proof for our
  `VotingCircuit`, computes the `vk_input` linear combination
  off-chain, and submits a spend bundle whose CLVM puzzle is just
  `(58 2 5 11 23 47 95 191 383)` — opcode 58 is
  `bls_pairing_identity`, the same opcode that
  `puzzles/election/finalize.rue` uses for on-chain Groth16
  verification. The simulator runs the CLVM dialect against
  consensus rules; acceptance proves our prover and the on-chain
  verifier agree on EVERY byte (curve point encoding, scalar
  derivation, pairing equation, negation convention).
* **`tampered_groth16_proof_rejected_by_clvm_pairing_identity`** —
  the dual case: flip ONE byte of `proof.A` and assert the
  consensus runner rejects the spend. Confirms the on-chain
  verifier is a real cryptographic check, not a no-op.

### Pending integration tests (paired with their pending SDK methods)

These tests can only be added once the corresponding SDK methods are
implemented (see roadmaps in each method's doc comments). Their
test outlines below define the ACCEPTANCE CRITERIA that those
implementations must hit.

* **`Voter::register` ↔ `voter_register_creates_registration_coin_at_predicted_hash`**
  - Funder coin pre-funded with CAT collateral and XCH for fee + bundle fee.
  - Build via `Voter::register`; submit via `Simulator::spend_coins`.
  - Assert: a CAT-wrapped coin lands at
    `Voter::registration_coin_puzzle_hash`, hinted by `Voter::voter_hint`.
  - Assert: Election Singleton spent + recreated with
    `registration_count = N+1` and updated SPT root.

* **`Voter::vote` ↔ `voter_vote_records_vote_data_in_state_and_memos`**
  - After `register`, spend the registration coin via `Voter::vote(vote_data)`.
  - Assert: new registration coin's puzzle hash reflects the
    `has_voted=true, vote_data=X` state via the inner-puzzle predictor.
  - Assert: the new coin's parent `CreateCoin` memo carries
    `[hint, vote_data, vote_signature]` (matches Rue finalizer layout).

* **`Voter::release_collateral` ↔ `voter_release_unlocks_cat_to_destination`**
  - Drive the election to finalized state.
  - `Voter::release_collateral(destination)`.
  - Assert: the `Election Singleton` emits the finalization
    announcement; the registration coin's CAT is sent to `destination`.

* **`Aggregator::sync` (post-spend recovery)** — paired with
  `Voter::register` so we have actual chain-walks to test. The
  current `sync()` handles only the eve case (no voters yet); the
  full implementation walks the singleton's spend history to rebuild
  the voter set. Test: deploy + 3 registers → sync → assert
  `voter_set.voters.len() == 3` and locally-computed root matches
  `state.registration_merkle_root`.

* **`Aggregator::collect_votes` (memo extraction)** — paired with
  `Voter::vote`. Current `collect_votes()` short-circuits cleanly
  for the empty voter set; full impl walks per-voter hints, parses
  parent-spend memos. Test: 3 registrations + 2 votes →
  `collect_votes` returns 2 records with valid BLS signatures over
  the canonical vote message.

* **`Aggregator::build_finalize` (Groth16 prove + spend assembly)** —
  the off-chain witness preparation
  (`prepare_finalize_witness`) is fully implemented and
  comprehensively tested. The remaining work is:
    1. Run `crate::prover::VotingCircuit::prove` (itself a separate
       milestone — implementing the R1CS constraint system).
    2. Build the action-layer solution + spend bundle.
  Test target: deploy + 3 registers + 2 votes (majority) + time-lock
  satisfied → `build_finalize` returns Ok(SpendBundle) → submit via
  simulator → assert state transitions to `finalized=true,
  vote_outcome=...`, finalization announcement asserted,
  accumulated_fees paid to the reward address.

* **`Aggregator::build_finalize_too_early_fails`** —
  majority of votes but the height-relative time lock not yet
  elapsed. Submitting the bundle should fail with the
  `ASSERT_HEIGHT_RELATIVE` error. (Pre-check pending — currently
  callers find out at submit time.)

---

## Counts

```
Layer 2 (cargo test --lib, non-clvm_runner)  ── 131 tests
                                                  (includes 28 prover tests:
                                                   10 conversions + 9 circuit
                                                   + 9 proof)
Layer 3 (cargo test --lib clvm_runner::)     ──  12 tests
Layer 4 (cargo test --test integration)      ──  10 tests (foundational deploy +
                                                  Groth16 + announce_finalization
                                                  on simulator)
Layer 4 (cargo test --test voter_actions_e2e)──   5 tests (vote multi-arg adapter
                                                  + release paired-bundle, all
                                                  passing after the release.rue
                                                  AssertCoinAnnouncement fix)
Layer 4 (cargo test --test register_action_e2e)── 3 tests (announcer scaffolding +
                                                  register puzzle slot/SPT proof
                                                  validation + canonical-slot
                                                  rejection)
                                             ──────────────
                                               161 active, 0 ignored
```

## Coverage matrix per actor / action

| Actor / Action            | CLVM execution test | Status |
|---------------------------|---------------------|--------|
| Deployer::build_deploy_bundle | `integration::deploy_creates_eve_singleton_at_predicted_puzzle_hash` | passing |
| Voter::register (puzzle)  | `register_action_e2e::register_with_valid_inputs_traps_only_at_announcement_assertion` + `register_rejects_wrong_slot_index` | passing |
| Voter::register (actor)   | not yet exposed via `Voter::register` actor method — pending implementation | pending |
| Voter::vote               | `voter_actions_e2e::vote_action_executes_on_simulator_with_valid_signature` + `vote_action_rejects_wrong_signature` | passing |
| Voter::release_collateral | `voter_actions_e2e::release_paired_with_announce_finalization_executes_on_simulator` + 2 rejection tests | passing |
| Aggregator::sync (eve)    | `aggregator::sync_after_deploy_recovers_genesis_state` | passing |
| Aggregator::sync (post)   | walking spent-singleton history — pending implementation | pending |
| Aggregator::collect_votes | memo-extraction from voter hints — pending implementation | pending |
| Aggregator::build_finalize | Groth16-prove + finalize.rue full path — pending implementation | pending |
| Indexer::sync             | mirrors `Aggregator::sync` — pending implementation | pending |
| Indexer::vote_records     | mirrors `Aggregator::collect_votes` — pending implementation | pending |
| announce_finalization (action) | `integration::announce_finalization_executes_on_simulator` + `_rejects_non_finalized` | passing |
| Groth16 pairing identity (on-chain) | `integration::groth16_proof_accepted_by_clvm_pairing_identity_opcode` + `tampered_..._rejected` | passing |
| BLS aggregate verify roundtrip | `integration::bls_aggregate_verify_roundtrips_for_two_signers` | passing |

## Real bugs found by end-to-end TDD

* **`puzzles/registration_coin/release.rue` AssertCoinAnnouncement
  bug** (FIXED): the puzzle was asserting `id = sha256("finalized"
  || ...)` (just the message hash), but consensus expects `id =
  sha256(announcer_coin_id || message)` (the full announcement_id).
  Fixed by adding a `singleton_coin_id` solution param so the puzzle
  computes the correct `sha256(singleton_coin_id || message)` id.
  Verified by `release_paired_with_announce_finalization_executes_on_simulator`.

* **`puzzles/election/register.rue` curry-arg convention drift**
  (FIXED): the puzzle was double-wrapping `finalizer_full_hash` with
  `tree_hash_atom(...)` even though the value is already a tree hash
  (the result of `curry_tree_hash(...)`). Aligned with yakuhito's
  slot-machine convention (atom values → wrap with `tree_hash_atom`,
  tree-hashed values → pass directly). The same fix was mirrored in
  the SDK's `puzzles::fresh_registration_inner_hash` so off-chain
  hash predictions match the on-chain calculation.

Run everything:

```powershell
cd CHIP\sdk
cargo test
```
