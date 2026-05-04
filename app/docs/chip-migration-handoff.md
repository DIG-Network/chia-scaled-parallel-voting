# CHIP Migration — Final Handoff

**Date:** 2026-05-03 (final)
**Branch:** `main`
**Latest commit:** `a05bd1c phase c: align finalize Scalars::compute s2 with curried snapshot weight`
**Workspace status:** Builds clean. **220 SDK tests passing, 0 ignored, 0 failed.**

The CHIP rev 2026-05-02 migration is **complete**. Every actor method that was a stub at the start of this work has a full implementation, every `#[ignore]` test marker has been resolved, and every actor flow has end-to-end coverage against the simulator.

## What was done in this rev

| Tier | Commit | Implementation |
|------|--------|----------------|
| 0 | `903ded6` | Fixed `BallotIssuer::create_ballot` CLVM raise (singleton-outer multi-odd-CreateCoin invariant); launcher amount 1 → 2; added `funder_spend` param. |
| 1 | `63b343e` | `BallotReader::list_ballots` / `get_ballot` walk the Election Singleton lineage; Indexer per-ballot accessors delegate. |
| 1.5 | `ff839e8` | `BallotIssuer::launch_ballot` — full launcher second-spend driver with per-ballot finalize/oracle/announce_finalization curries + singleton outer wrap. e2e `launch_ballot_e2e`. |
| 2.1 | `fc374bc` + `c2ef8fa` | `Voter::release_collateral` (singleton deregister + CAT-wrapped registration release co-spend). e2e `voter_release_collateral_e2e`. Also fixed `apply_singleton_spend`'s vote_weight tracking. |
| 2.2 | `b8b8bed` + `a8438d9` + `bfd8b3b` | `Voter::cast_vote` end-to-end. Pre-requisite fixes: moved `update_vote.rue`'s 3 curry args to its solution, fixed `registration_actions_merkle_root` to use the curried `mint_voting_coin` hash, fixed `mint_voting_coin.rue` to emit a non-CAT-wrapped CreateCoin (CAT outer wraps once), fixed `empty_ballot_root` to use plain sha256. e2e `voter_cast_vote_e2e` (also covers `Aggregator::collect_votes_for_ballot`). |
| 2.3 | `7d915b1` | `Voter::update_vote` end-to-end. New `find_current_ballot_singleton` helper walks Eve / Lineage proofs through the singleton lineage. e2e `voter_revote_e2e`. |
| 3.1 | `44942dd` | `Aggregator::collect_votes_for_ballot` + free-function `collect_votes_for_ballot_via_chain` so `Indexer::votes_for_ballot` can re-use it. |
| 3.2 | `c1d5c50` + `593a74d` | `Aggregator::build_finalize_for_ballot` + `_with_proof_for_ballot` variants. Introduces `BuildFinalizeForBallotParams`, `find_current_ballot_singleton_via_chain`, `prepare_finalize_witness_with_threshold`. |
| Phase A | `1f7f96e` | SPT leaf format aligned to `sha256(pk \|\| locked_cat_mojos_be8)` per CHIP.md (was previously `sha256(pk)`). Threaded `collateral_amount` through SDK + CLI. |
| Phase B | `725206f` | Real weighted-quorum circuit gadget: `Σ signer_weights * den - num * registration_vote_weight - slack == 0` (R1CS-shape stable; per-signer weight is private witness). Replaces the prior permissive non-empty-signers placeholder. |
| Phase C | `a05bd1c` | **Finalize on-chain CLVM raise resolved.** Root cause: `Scalars::compute` was using `voter_set.registration_count` for the s2 input, but the on-chain `ballot_coin/finalize.rue` recomputes s2 from the curried `REGISTRATION_VOTE_WEIGHT_SNAPSHOT`. Coincided when `COLLATERAL_AMOUNT == 1`; mismatched once `COLLATERAL_AMOUNT > 1`. Fix: thread `registration_vote_weight_snapshot` through `prepare_finalize_witness_with_threshold`. `finalize_per_ballot_e2e` now runs unignored end-to-end. |
| Cleanup | `6ec0477` + `15b0ddd` | Deleted 24 obsolete `#[ignore]` tests targeting pre-CHIP-rev singleton-finalize / `vote` / `release` actions. |

## Tests now in place (all passing, none ignored)

| Test file | Coverage |
|-----------|----------|
| `tests/voter_register_full_flow.rs` | `Voter::register` against simulator (announcement-only `cat_parent_spend` pattern). |
| `tests/voter_release_collateral_e2e.rs` | Full deploy → real CAT issuance → register → release_collateral. |
| `tests/create_ballot_e2e.rs` | `BallotIssuer::create_ballot` lands launcher eve coin at predicted ph. |
| `tests/launch_ballot_e2e.rs` | `BallotIssuer::launch_ballot` mints eve Ballot Coin singleton at predicted singleton-wrapped ph. |
| `tests/ballot_reader_e2e.rs` | `BallotReader::list_ballots` walks the Election Singleton lineage. |
| `tests/voter_cast_vote_e2e.rs` | Full pipeline through cast_vote, plus `Aggregator::collect_votes_for_ballot` recovers the vote. |
| `tests/voter_revote_e2e.rs` | cast_vote → update_vote, asserting recreated Voting Coin lands at SDK-predicted ph. |
| `tests/finalize_per_ballot_e2e.rs` | **Full pipeline through finalize.** Real VK + matching ProvingKey, deploy → CAT issue → register → create_ballot → launch_ballot → cast_vote → advance height past `vote_close_height` → `Aggregator::build_finalize_for_ballot` → submit. Asserts the eve Ballot Coin singleton was consumed and a recreated singleton at a new puzzle hash (state.finalized = true) is present. |

Plus per-actor unit tests in `sdk/src/actors/*.rs` and `sdk/src/prover/*.rs` (≈ 161 unit tests).

## Debug aids

`Aggregator::build_finalize_with_proof_for_ballot_inner` honours the `CHIP_VOTING_DUMP_DIR` environment variable: on dry-run failure it writes a JSON file with the full coin_spend hex (puzzle_reveal + solution), all curried snapshot values, all 6 scalars, agg_signers, agg_sig, and the underlying error. Useful for any future on-chain assertion debug.

```
CHIP_VOTING_DUMP_DIR=/tmp/chip-dump cargo test --test finalize_per_ballot_e2e -p chip-voting-sdk -- --nocapture
```

## Architectural references (still current)

1. **`CHIP.md`** — canonical spec.
2. **`puzzles/`** — every action puzzle's `.rue` source pins the curry / solution shapes the SDK must mirror.
3. **`sdk/src/action_spends.rs`** — `build_action_layer_puzzle`, `build_action_layer_solution`, `build_singleton_spend`, `build_cat_spend`, `build_election_finalizer_full`, `build_ballot_finalizer_full`, `build_voting_coin_finalizer_full`, `build_registration_finalizer_full`, `load_action_puzzle`. Read the docstrings.
4. **`sdk/src/puzzles.rs`** — every puzzle hash, action root, predicted ph, message preimage helper. Single source of truth for tree-hash compositions.
5. **`sdk/src/actors/voter.rs::find_current_ballot_singleton`** + **`sdk/src/actors/aggregator.rs::find_current_ballot_singleton_via_chain`** — chain-walking template for any Ballot Coin lineage operation.
6. **`sdk/src/prover/circuit.rs`** — Groth16 circuit with the weighted-quorum gadget. Public inputs and IC ordering MUST match `puzzles/ballot_coin/finalize.rue`.
