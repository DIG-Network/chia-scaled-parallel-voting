# CHIP Migration — Final Handoff

**Date:** 2026-05-03 (migration); superseded 2026-05-04 by spec-compliance pass.
**Branch:** `main`
**Workspace status:** Builds clean. **254 SDK tests passing, 0 ignored, 0 failed.**

The CHIP rev 2026-05-02 migration is **complete**. Every actor method that was a stub at the start of this work has a full implementation, every `#[ignore]` test marker has been resolved, and every actor flow has end-to-end coverage against the simulator.

**Note (2026-05-04 update):** Phase A's leaf-format change was reverted by the
spec-compliance pass — see [Spec Compliance addendum](#spec-compliance-addendum-2026-05-04)
at the bottom of this document. CHIP.md §88-91 says the occupied leaf is
`sha256(pubkey)` for this revision; the appended-weight form is forward-compatible
but explicitly "not yet implemented". The Phase A row below describes the original
2026-05-03 change; the live implementation matches the spec leaf form.

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

---

## Spec compliance addendum (2026-05-04)

Following the 2026-05-03 handoff, a dedicated spec-compliance pass aligned the
implementation to CHIP.md as the source of truth and pinned every normative
claim with a CLVM- or simulator-executing test.

### Divergence fixed

| Area | Pre-2026-05-04 | After spec-compliance pass |
|------|----------------|------------------------------|
| SPT occupied leaf | `sha256(pubkey \|\| locked_cat_mojos_be8)` (Phase A change in `1f7f96e`) | `sha256(pubkey)` per CHIP.md §88-91 (uniform per-registration weight tracked on Election Singleton state, not in the leaf) |

The phase-A leaf-format change was reverted because CHIP.md §88-89 and §143-146
explicitly mark the appended-weight form as forward-compatible but "not yet
implemented" for this revision. The puzzle source (`register.rue`,
`deregister.rue`), recompiled hex artifacts, the SDK's `active_leaf_hash`
helper, and every e2e test's siblings reconstruction were aligned to the spec
form. `SparseMerkleTree::with_collateral_amount` was removed; callers use
`::new()`.

### Compliance infrastructure

| Artifact | Path | Purpose |
|----------|------|---------|
| Compliance matrix | `app/docs/chip-compliance.md` | 58 rows, one per normative claim. Every `claim` field is a verbatim CHIP.md substring. |
| Compliance worklist | `app/docs/chip-compliance-worklist.md` | Divergence + test-gap worklists (now both empty). |
| Compliance test suite | `sdk/tests/chip_spec_compliance.rs` | 40 tests pinning the matrix; 6 run real CLVM via simulator or `clvmr::run_program`. |
| CI gate | `chip_md_compliance_matrix_complete` (in same file) | Parses matrix at runtime; panics if any row is `divergent`, any `claim` is not a verbatim CHIP.md substring, or any aligned MUST row lacks a negative test. |
| Design doc | `app/docs/superpowers/specs/2026-05-04-chip-spec-compliance-design.md` | The approach. |
| Implementation plan | `app/docs/superpowers/plans/2026-05-04-chip-spec-compliance.md` | Phase-by-phase plan executed by this pass. |

### Spec edit (CHIP.md)

`CHIP.md` §335-343 ("Implementation alignment (this revision)") was a dated
status snapshot that contradicted the current implementation (it claimed two
gaps that the 2026-05-03 phase-b/c commits had already closed). It was deleted
and replaced with a `## Compliance` section pointing at
`app/docs/chip-compliance.md` and the CI gate. CHIP.md is now exclusively
normative + historical migration narrative — no live status snapshots that
can rot.

### CLVM-executing tests added in this pass

| Test | CHIP.md row pinned | Harness |
|------|--------------------|---------|
| `chip_spt_leaf_format_register_puzzle_executes_cleanly_with_spec_leaf` | SPT-LEAF-FORMAT | Simulator + `register.rue` |
| `chip_ballot_announce_finalization_curry_shape_is_single_arg` | BALLOT-ANNOUNCE-CURRY | `clvmr::run_program` |
| `chip_ballot_announce_finalization_clvm_succeeds_when_finalized` | BALLOT-ANNOUNCE-ROLE positive | Simulator + `announce_finalization.rue` |
| `chip_ballot_announce_finalization_clvm_traps_when_not_finalized` | BALLOT-ANNOUNCE-ROLE finalized-only guard | Simulator + `announce_finalization.rue` |
| `chip_ballot_announce_finalization_clvm_message_is_bound_to_state` | BALLOT-ANNOUNCE-ROLE state binding | Simulator + `announce_finalization.rue` (3 sub-cases) |
| `chip_sec_timing_oracle_curry_binds_vote_close_height` | SEC-TIMING | `clvmr::run_program` against `oracle.rue` |
| `voter_double_vote_e2e::chip_single_vote_per_ballot_double_mint_simulator_rejects` | SEC-SINGLE-VOTE-PER-BALLOT | Simulator + `mint_voting_coin.rue` |
| `voter_revote_oracle_required_e2e::chip_voting_update_vote_without_oracle_assertion_traps` | VOTING-UPDATE-VOTE-ORACLE | Simulator + `update_vote.rue` |
| `chip_finalize_rejects_threshold_pack_mismatch_run_program` | SEC-THRESHOLD-PRESERVED | `clvmr::run_program` against `finalize.rue` |

### Final state

- 254 tests passing across 17 binaries, 0 ignored, 0 failed.
- Matrix: 57/57 rows aligned (1 header marker), 0 untested, 0 divergent.
- CI gate `chip_md_compliance_matrix_complete` green.
- Spec drift detection: any future edit that renames a quoted CHIP.md sentence
  fails CI until the matrix is realigned.
- Implementation drift detection: every aligned MUST row's negative test would
  fail if the underlying constraint were relaxed.

### Commits (2026-05-04 spec-compliance pass)

```
0408cb5 test(compliance): CLVM-executing SEC-THRESHOLD-PRESERVED via clvmr::run_program
f2077f6 test(compliance): CLVM-executing VOTING-UPDATE-VOTE-ORACLE via simulator strip-oracle
8b645b6 test(compliance): CLVM-executing SEC-SINGLE-VOTE-PER-BALLOT via simulator double-mint guard
05b23eb test(compliance): CLVM-executing announce_finalization tests for BALLOT-ANNOUNCE-ROLE
6c04bd6 test(chip-compliance): drive final 8 rows untested -> aligned (matrix 100%)
b51b370 compliance(batch2): pin per-action coin-state rows via structural tests
6d750b5 compliance: pin 12 data-layout + circuit-input rows via negative tests
0f49ed9 compliance: add 8 negative/structural tests + CI gate (chip_md_compliance_matrix_complete)
aa877ab compliance: honest cross-walk of positive tests from existing e2e
a139f06 spec: delete stale 'Implementation alignment' status section; cite compliance matrix
578b7c5 compliance: design + implementation plan for CHIP.md alignment
1cf2627 compliance(SPT-LEAF-FORMAT): green positive + negative tests; matrix row aligned
190bc98 compliance(SPT-LEAF-FORMAT): align SDK Merkle helpers + e2e tests to sha256(pubkey)
b7d4d5d compliance(SPT-LEAF-FORMAT): align register/deregister leaf to sha256(pubkey)
ab00785 compliance(SPT-LEAF-FORMAT): pin negative test (red)
c406a15 compliance: link impl_locus, cross-walk tests, produce worklists
d8936fd compliance: enumerate normative claims from CHIP.md
57ce4a9 compliance: scaffold normative-claim registry
```
