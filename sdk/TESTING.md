# Testing the CHIP voting SDK

Test architecture for the SDK at CHIP rev 2026-05-02. The phased plan
that drove this rev lives in
[`../app/docs/superpowers/plans/2026-05-02-chip-migration.md`](../app/docs/superpowers/plans/2026-05-02-chip-migration.md);
the per-ballot lane is stubbed pending Phase 6.

---

## Layers

```
Layer 4: tests/integration*.rs        — consensus runner via chia-sdk-test::Simulator
Layer 3: src/clvm_runner.rs           — direct CLVM execution of compiled puzzles
Layer 2: cargo test --lib             — pure-Rust unit tests (per src/* module)
Layer 1: build.rs                     — compile-time embedding of puzzles/compiled/*
```

### Layer 1 — compile-time embedding

`build.rs` re-runs whenever `puzzles/compiled/**` changes; `puzzles.rs`
references each artefact via `include_str!`. A stale or missing
`.hex`/`.hash` file is a compile error — there's no runtime path that
can encounter a missing puzzle.

To regenerate after a Rue change:

```powershell
cd CHIP
./build.ps1            # or ./build.sh on bash
cd sdk
cargo build
```

### Layer 2 — unit tests (`cargo test --lib`)

Each module under `src/` carries a `#[cfg(test)] mod tests` block:

* **`puzzles.rs`** — every `curry_tree_hash` / `hash_atom` / `hash_pair`
  helper checked against `clvm_utils`'s own arithmetic; `voter_hint`,
  registration / singleton / ballot puzzle-hash predictors, and Merkle
  helpers tested for determinism, per-voter / per-election uniqueness,
  and order-independence.
* **`merkle.rs`** — round-trips for empty / populated / boundary
  (`u32::MAX`) trees; proof verification against active and empty
  leaves; root determinism under permuted insert order.
* **`config.rs`** — `validate()` rejects every invalid combination;
  JSON round-trip preserves all fields; typed accessors return the
  exact bytes the hex encodes; `EMPTY_LEAF_HASH` cross-checked against
  a SHA-256 golden value.
* **`state.rs`** — wire types round-trip through serde; `into_state`
  rejects malformed pubkey hex; `ElectionState::genesis` and
  `RegistrationState::fresh` set every field to its documented initial
  value.
* **`ceremony/`** — coordinator rejects wrong-chain / wrong-attestation /
  zero-contribution transcripts; happy-path 2-participant round-trip;
  transcript hash determinism.
* **`prover/proof.rs`** — `Scalars::compute` deterministic and changes
  per public input (one assertion per input); count uses big-endian
  8-byte encoding; `agg_signers` scalar is `sha256(pk.to_bytes())`;
  arkworks-Proof ↔ wire form round-trip; rejects malformed hex /
  off-curve points with typed errors.
* **`prover/conversions.rs`** — pins `chia_bls` ↔ `arkworks::bls12_381`
  byte-identical G1/G2 compressed encodings; PK/Signature lossless
  round-trip; G1 aggregation identity / commutativity / scalar.
* **`prover/circuit.rs`** — Groth16 circuit + prover pipeline:
  `generate_test_setup`, prove → verify_offchain on valid majority,
  tampered inputs fail, below-threshold rejected, boundary majority
  succeeds, VK serialises to exactly **672 bytes** (alpha_g1 + beta_g2
  + gamma_g2 + delta_g2 + 7 IC for the 6-public-input circuit), and
  the master cross-layer test
  `public_inputs_as_fr_match_scalars_compute` — Fr commitment EQUALS
  `bytes32_to_fr(Scalars::compute(...).s_i)` for all 6 inputs.
* **`actors/deployer.rs`** — `derive_launcher_id` deterministic and
  per-amount; `config_for_launcher` produces a config that passes
  `.validate()`; `genesis_inner_puzzle_hash` per-launcher;
  `election_actions_merkle_root` changes per curried parameter;
  `uint_atom_hash` matches CLVM canonical encodings.
* **`actors/voter.rs`** — `cast_vote` / `update_vote` / `release_message`
  bytes are domain-separated and deterministic; `convert_coin` accepts
  prefixed / bare hex and rejects malformed input.
* **`actors/aggregator.rs`** — eve-genesis sync, lifecycle errors
  before-sync, off-chain pre-checks for finalize witness preparation
  (Merkle membership, duplicate detection, strict-majority threshold,
  signature aggregation, signed-message canonical form). The full
  per-ballot finalize / vote-collection paths are stubbed pending
  Phase 6 (their tests are `#[ignore]`d in this rev).
* **`chain.rs`** — `ChainReader` trait + adapters for
  `chia_query::ChiaQuery` (production) and `chia_sdk_test::Simulator`
  (tests).

### Layer 3 — direct CLVM (`cargo test --lib clvm_runner::`)

`src/clvm_runner.rs` loads a compiled `.rue.hex`, allocates structured
solutions from typed Rust data via `clvm_traits::ToClvm`, runs the
puzzle via `chia_sdk_types::run_puzzle`, and parses the output. Action
puzzles tested in isolation include `cast_vote` / `update_vote` (vote
binding + outcome-domain assertions), `mint_voting_coin` (per-ballot
SPT uniqueness), `release` (deregister gating), and the Ballot Coin
oracle / `announce_finalization`. Every embedded `.rue.hex` is also
load-checked.

### Layer 4 — integration tests (`cargo test --test '*'`)

Each test spins up a fresh `Simulator` (ChaCha8-seeded), pre-funds via
`sim.bls(amount)` or `sim.insert_coin(...)`, drives the SDK through a
scenario, and asserts the chain state matches the off-chain prediction.

Foundational coverage today:

* **Deploy + state-prediction** — the master invariant: deploy bundle
  ⨯ simulator produces an eve singleton at the exact puzzle hash
  predicted by `election_singleton_puzzle_hash`; replay-safety across
  funder coins; emitted config self-validates; pinned tree-depth = 32.
* **Consensus-level CLVM** — `announce_finalization` on the simulator
  (success + non-finalized rejection); BLS aggregate-verify round-trip.
* **End-to-end Groth16 + CLVM** — `groth16_proof_accepted_by_clvm_pairing_identity_opcode`
  and its `tampered_..._rejected` dual case. The simulator runs CLVM
  opcode 58 (`bls_pairing_identity`) — the same opcode the on-chain
  Ballot Coin's `finalize.rue` uses — proving prover and verifier
  agree on every byte (curve point encoding, scalar derivation,
  pairing equation, negation convention).

---

## Coverage matrix

Status legend:
* **passing** — implemented and exercised by an active test.
* **stubbed pending Phase 6** — public API stubbed; tests scaffolded
  with `#[ignore]` markers and acceptance criteria documented inline.
  See `../app/docs/superpowers/plans/2026-05-02-chip-migration.md`.

| Actor / Action                            | Status |
|-------------------------------------------|--------|
| `ElectionDeployer::build_deploy_bundle`   | passing |
| `Voter::register`                         | puzzle: passing (`register_action_e2e`); actor stubbed pending Phase 6 |
| `Voter::cast_vote`                        | stubbed pending Phase 6 |
| `Voter::update_vote`                      | stubbed pending Phase 6 |
| `Voter::release_collateral`               | stubbed pending Phase 6 |
| `BallotIssuer::create_ballot`             | stubbed pending Phase 6 |
| `BallotReader::list_ballots`              | stubbed pending Phase 6 |
| `BallotReader::get_ballot`                | stubbed pending Phase 6 |
| `Aggregator::sync` (eve genesis)          | passing |
| `Aggregator::sync` (post-spend lineage)   | stubbed pending Phase 6 |
| `Aggregator::collect_votes_for_ballot`    | stubbed pending Phase 6 |
| `Aggregator::build_finalize_for_ballot`   | stubbed pending Phase 6 |
| `Indexer::sync`                           | mirrors `Aggregator::sync` — eve passing, post stubbed |
| `Indexer::ballots`                        | stubbed pending Phase 6 |
| `Indexer::ballot_state`                   | stubbed pending Phase 6 |
| `Indexer::votes_for_ballot`               | stubbed pending Phase 6 |
| `Indexer::is_finalized_for` / `vote_outcome_for` | stubbed pending Phase 6 |
| `prepare_finalize_witness` (off-chain)    | passing (witness shape pinned at 6 scalars; one duplicate-witness assertion ignored pending Phase 6 review) |
| `announce_finalization` (action)          | passing |
| Ballot Coin oracle (action)               | passing (Layer 3) |
| `mint_voting_coin` (action)               | passing (Layer 3) |
| `release` deregister gate (action)        | passing (Layer 3) |
| Groth16 pairing identity (on-chain)       | passing |
| BLS aggregate-verify round-trip            | passing |

### Acceptance criteria for stubbed methods

These tests will land alongside the Phase 6 implementations:

* **`Voter::cast_vote`** — given a Ballot Coin and a Registration Coin
  for the voter, `cast_vote(ballot_launcher_id, payload)` returns a
  bundle that mints exactly one Voting Coin hinted by
  `voter_hint(election_id, cat_tail, voter_pk) ⨯ ballot_launcher_id`,
  with the parent `CreateCoin` memo carrying the canonical
  vote-message signature.
* **`Voter::update_vote`** — same shape as `cast_vote` but consumes
  the prior Voting Coin. Bundle MUST be rejected by consensus when
  height > Ballot Coin's `vote_close_height` (oracle gate).
* **`Voter::release_collateral`** — once every Ballot Coin the voter
  cast on has finalized, `release_collateral(dest)` produces a bundle
  that asserts each finalize announcement and sends the locked CAT to
  `dest`. Rejected by consensus while any pending ballot is unfinalized.
* **`BallotIssuer::create_ballot`** — singleton `createBallot` action
  spend mints a fresh launcher coin + eve Ballot Coin curried with
  `(election_launcher_id, ballot_launcher_id, vote_close_height,
  outcome_domain_hash, vk)`; emits the `createBallot` announcement.
* **`BallotReader::list_ballots` / `get_ballot`** — chain-walk by
  hint returns one entry per launched ballot; `get_ballot` short-
  circuits cleanly on unknown launcher_id.
* **`Aggregator::collect_votes_for_ballot`** — walks per-voter Voting
  Coin hints scoped to `ballot_launcher_id`, parses memos, returns
  `Vec<VoteRecord>` with valid BLS signatures over the canonical
  vote message.
* **`Aggregator::build_finalize_for_ballot`** — given a majority of
  votes for `ballot_launcher_id`, runs `VotingCircuit::prove`, builds
  the Ballot Coin's `finalize` action solution + bundle, and returns
  Ok. Submission transitions the Ballot Coin to its finalized lineage
  with the `announce_finalization` message asserted; rejected before
  the ballot's `vote_close_height` (`ASSERT_HEIGHT_RELATIVE`).
* **`Indexer::ballots` / `ballot_state` / `votes_for_ballot` /
  `is_finalized_for` / `vote_outcome_for`** — mirror the aggregator's
  walks but return read-only snapshots. Each returns `None` (or empty)
  for unknown launcher_id rather than erroring.

## Real bugs found by end-to-end TDD

* **`puzzles/registration_coin/release.rue` AssertCoinAnnouncement
  bug** (FIXED): the puzzle was asserting `id = sha256(message)`, but
  consensus expects `id = sha256(announcer_coin_id || message)`. Fixed
  by adding a `singleton_coin_id` solution param so the puzzle computes
  the correct id.
* **`puzzles/election/register.rue` curry-arg convention drift** (FIXED):
  the puzzle was double-wrapping `finalizer_full_hash` with
  `tree_hash_atom`. Aligned with the slot-machine convention (atom →
  wrap, tree-hash → pass). Mirrored in
  `puzzles::fresh_registration_inner_hash` so off-chain predictions
  match on-chain.

---

## Running everything

```powershell
cd CHIP\sdk
cargo test
```

Stubbed-method tests carry `#[ignore]` markers; they show up under
"ignored" rather than failing. To run a stubbed test once its
implementation lands:

```powershell
cargo test --test integration -- --ignored
```
