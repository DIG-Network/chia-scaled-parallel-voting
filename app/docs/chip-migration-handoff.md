# CHIP Migration — Phase 6+ Handoff

**Date:** 2026-05-03
**Branch:** `main`
**Latest commit:** `a698390 test: ignore create_ballot_e2e pending CLVM-raise debug`
**Workspace status:** Builds clean, all tests green or `#[ignore]`-d.

This document is the entry-point prompt for a fresh session that picks up where the structural CHIP-rev-2026-05-02 migration ended. Phases 0-8 of `app/docs/superpowers/plans/2026-05-02-chip-migration.md` are committed; this work covers the residual Phase 6 implementation stubs and remaining ignored tests.

---

## Use as a session-start prompt

Copy everything between the `===` markers below into a new Claude Code session.

```
===
You are continuing a multi-session CHIP migration project. The structural migration (Phases 0-8 of app/docs/superpowers/plans/2026-05-02-chip-migration.md) is complete and committed on `main`. The remaining work is filling in stubbed actor methods + un-ignoring or deleting tests, all per the user's directive: "all stubbed methods need to be implemented and fully tested; all ignored tests must pass or be removed."

Working directory: `C:\Users\micha\workspace\dig-network\CHIP` (Windows; use bash for git, ctx_execute_file for analysis).

Branch: `main`. Latest commit before this session: `a698390`.

Read the full handoff at `app/docs/chip-migration-handoff.md` for inventory + recommended order. Then start executing.

The session before this finished:
- Phases 0-8 of the plan (puzzles + SDK + CLI + docs all migrated)
- Replaced 13 obsolete clvm_runner ignored tests with 5 new working puzzle tests (commit a345872)
- Began BallotIssuer::create_ballot real implementation (commit 2924fc1) — but the e2e test traps with a CLVM raise; currently #[ignore]-d (a698390). Debug this FIRST.

Recommended priority order is in the handoff doc. Begin with the create_ballot debug since it unblocks several downstream stubs.
===
```

---

## Current ignored / stubbed inventory (as of `a698390`)

### Stubbed actor methods (12)

Source-of-truth grep: `grep -rn "stubbed pending Phase 6" sdk/src/actors/`

| Method | File | Line | Blocking reason | Estimated effort |
|---|---|---|---|---|
| `BallotIssuer::create_ballot` | `sdk/src/actors/ballot.rs` | 153 | **Implementation present, e2e test traps with CLVM raise. Debug first.** | 1-3 hrs (debug only) |
| `BallotReader::list_ballots` | `sdk/src/actors/ballot.rs` | 401 | Needs chain-walk for ballot lineage by hint | 2-4 hrs |
| `BallotReader::get_ballot` | `sdk/src/actors/ballot.rs` | 416 | Same (single ballot variant) | 1 hr (same code as list_ballots, single match) |
| `Aggregator::collect_votes_for_ballot` | `sdk/src/actors/aggregator.rs` | 234 | Needs Voting Coin lineage walker by `ballot_launcher_id` | 3-5 hrs |
| `Aggregator::build_finalize_for_ballot` | (search for stub) | — | Needs real 6-input Groth16 prover wiring + Ballot Coin spend assembly | 5-10 hrs |
| `Voter::cast_vote` | `sdk/src/actors/voter.rs` | 432 | Needs Registration Coin spend (mint_voting_coin action) + Voting Coin curry composition + Ballot Coin oracle co-spend | 5-8 hrs |
| `Voter::update_vote` | `sdk/src/actors/voter.rs` | 462 | Voting Coin spend + Ballot Coin oracle co-spend + AGG_SIG over new vote_message | 3-5 hrs |
| `Voter::release_collateral` | `sdk/src/actors/voter.rs` | 491 | Singleton deregister co-spend + Registration Coin release.rue spend in same bundle | 3-5 hrs |
| `Indexer::ballots` | `sdk/src/actors/indexer.rs` | 200 | Delegates to BallotReader::list_ballots | <30 min once BallotReader works |
| `Indexer::ballot_state` | `sdk/src/actors/indexer.rs` | 215 | Delegates to BallotReader::get_ballot | <30 min |
| `Indexer::votes_for_ballot` | `sdk/src/actors/indexer.rs` | 232 | Delegates to Aggregator::collect_votes_for_ballot | <30 min |
| `Indexer::is_finalized_for` | `sdk/src/actors/indexer.rs` | 246 | Pulls `BallotState.finalized` from `BallotReader::get_ballot` | <30 min |
| `Indexer::vote_outcome_for` | `sdk/src/actors/indexer.rs` | 261 | Pulls `BallotState.vote_outcome` from `BallotReader::get_ballot` | <30 min |

**Total stub effort:** 24-44 hours focused work.

### Ignored tests (34, by category)

```bash
grep -rn "#\[ignore" sdk/ cli/ 2>&1 | grep -v target | wc -l   # 34
```

| Category | Count | Disposition |
|---|---|---|
| **Aggregator finalize-stub-dependent** (`build_finalize_for_ballot` returns Err) | 3 | Un-ignore after `Aggregator::build_finalize_for_ballot` lands |
| **`actor_functions_e2e.rs`** stub-dependent | 4 | Un-ignore after corresponding actor stub lands |
| **`integration.rs`** Groth16 / VK / proof tests | varies | Mostly stub-dependent; some need fresh fixtures |
| **`register_action_e2e.rs`** (3) | 3 | Stub-dependent on Voter::register flow integration |
| **`register_action_layer_isolated.rs`** (2) | 2 | Stub-dependent |
| **`voter_actions_e2e.rs`** (5) | 5 | Stub-dependent on cast_vote / update_vote |
| **`action_layer_e2e.rs`** (4) | 4 | Stub-dependent |
| **`actor_functions_e2e.rs`** (4) | 4 | Stub-dependent |
| **`create_ballot_e2e.rs`** (1) | 1 | Debug create_ballot CLVM raise (priority #1) |
| **Inline lib `#[ignore]`-d** (e.g. `inner_hash_regression_tests`) | varies | Need fixture updates for new state shapes |

---

## Priority order (recommended)

### Tier 0: unblock everything else

**0.1 — Debug `BallotIssuer::create_ballot` CLVM raise**

The implementation in `sdk/src/actors/ballot.rs` is structurally complete: walks lineage, builds curried action puzzle, wraps with action layer + singleton outer, computes eve coin id, signs. The runtime curry hash check at `ballot.rs:240` PASSES (the action-leaf hash matches the predicted leaves). Yet the dry-run traps with `EvalErr(NodePtr(SmallAtom, 0), "clvm raise")` from inside the spend at `puzzle_hash d52eb3ce858ee73b43f03ded01036a03471393548b33091f26882225a9e6ba39`.

**Most likely root causes:**

1. **State cons encoding mismatch.** The `state_node_for` helper at `sdk/src/actors/ballot.rs:343` builds `(root . (count . (vote_weight . start_height)))` — a 3-level cons with start_height as the trailing rest. The deployer's `state::ElectionState::clvm_tree_hash()` (in `sdk/src/state.rs`) bakes its own encoding into the singleton's puzzle hash. If the two encodings differ (e.g. tree_hash uses `(a . (b . (c . (d . NIL))))` 4-level vs `state_node_for` uses 3-level), the action layer's state-truth check in `puzzles/finalizer.rue` traps.
   - **Verify:** print `tree_hash(&ctx, state_node_for(&mut ctx, &state)?)` and compare to `state.clvm_tree_hash()`. They MUST be byte-identical.

2. **Action-layer merkle-proof shape.** `build_action_layer_solution` may compute a proof against the wrong leaf order or use a different `MerkleTree::list_to_binary_tree` than `puzzles::election_actions_merkle_root` does. Test path: print both and assert equality.

3. **Singleton lineage proof shape mismatch.** `wait_for_current_singleton` returns a `LineageProof` with `parent_parent_coin_info`, `parent_inner_puzzle_hash`, `parent_amount`. If the deployer used a different convention, the singleton outer traps.

**Debug recipe:**

```rust
// In sdk/src/actors/ballot.rs::create_ballot, BEFORE the dry_run_coin_spends call:
{
    let predicted = state.clvm_tree_hash();
    let runtime_node = state_node_for(&mut ctx, &on_chain_state)?;
    let runtime_hash = Bytes32::new(clvm_utils::tree_hash(&ctx, runtime_node).to_bytes());
    eprintln!("STATE HASH predicted={} runtime={}", hex::encode(predicted), hex::encode(runtime_hash));
    assert_eq!(predicted, runtime_hash, "state encoding drift between SDK helpers");
}
```

If they match, repeat the check for the action-layer's inner-puzzle hash and the singleton's full puzzle hash. Compare to `chain.coin_record(launcher_id).await?.coin.puzzle_hash`.

If both match and the raise persists, run the full `dry_run_coin_spends` with `RUST_LOG=trace` and inspect the EvalErr's inner CLVM stack.

Time estimate: 1-3 hours.

### Tier 1: foundation (unblocks ballot/voting coin tests)

**1.1 — Implement `BallotReader::list_ballots` and `get_ballot`** (ballot.rs:401, 416)

Strategy: query the chain by hint. Each Ballot Coin's launcher eve coin is created with `hint = ballot_launcher_id`. Use `chain.coin_records_by_hint(hint)` if available; otherwise enumerate spends of the Election Singleton lineage and look at each spend's `CREATE_COIN` outputs for `puzzle_hash == SINGLETON_LAUNCHER_HASH`. For each launcher coin found, look at its child spend (the launcher → Ballot Coin singleton transition) to extract the curried `(vote_close_height, outcome_domain_hash)` and the current `BallotState`.

For now, the launcher second-spend may not exist on chain (per the migration plan, it's caller responsibility). In that case `list_ballots` returns just the eve-coin records as `BallotCoinSnapshot { state: BallotState::fresh(), ... }`.

E2E test target: depends on `BallotIssuer::create_ballot` working. After the debug at Tier 0 completes, write `tests/list_ballots_e2e.rs` that creates 2-3 ballots, then asserts `BallotReader::list_ballots` returns all of them with stable `ballot_launcher_id`s.

**1.2 — Wire `Indexer` per-ballot accessors** (indexer.rs:200, 215, 232, 246, 261)

Trivial after 1.1. Replace each `Err(...)` body with a delegated call:

```rust
pub async fn ballots(&self) -> VotingResult<Vec<BallotCoinSnapshot>> {
    BallotReader::new(self.config.clone(), self.chain.clone())
        .list_ballots()
        .await
}

pub async fn ballot_state(&self, ballot_launcher_id: Bytes32) -> VotingResult<Option<BallotState>> {
    let snapshot = BallotReader::new(self.config.clone(), self.chain.clone())
        .get_ballot(ballot_launcher_id)
        .await?;
    Ok(snapshot.map(|s| s.state))
}

pub async fn is_finalized_for(&self, ballot_launcher_id: Bytes32) -> VotingResult<bool> {
    self.ballot_state(ballot_launcher_id)
        .await
        .map(|st| st.map_or(false, |s| s.finalized))
}

pub async fn vote_outcome_for(&self, ballot_launcher_id: Bytes32) -> VotingResult<Option<Bytes32>> {
    self.ballot_state(ballot_launcher_id)
        .await
        .map(|st| st.and_then(|s| if s.finalized { Some(s.vote_outcome) } else { None }))
}

pub async fn votes_for_ballot(&self, ballot_launcher_id: Bytes32) -> VotingResult<Vec<VoteRecord>> {
    // delegate to Aggregator::collect_votes_for_ballot once that lands (Tier 2)
    self.aggregator.collect_votes_for_ballot(ballot_launcher_id).await
}
```

Caveat: `BallotReader` may not be `Clone` today; either add a derive or share via `Arc`. Match what `Indexer` already does for `Aggregator`.

### Tier 2: voting flows

**2.1 — `Voter::release_collateral`** (voter.rs:491)

Mirrors `Voter::register` closely. Delta: instead of mint_registration_coin + register-action, this builds:
- Election Singleton spend: `deregister` action with solution `(voter_pubkey, leaf_index, occupied_siblings)`. SPT membership proof + remove leaf.
- Registration Coin spend: `release.rue` action with solution `(collateral_destination, singleton_coin_id)`. Asserts the singleton's deregister announcement.

Both bundled together. Sign with the voter's BLS key (the `release` action emits `AggSigMe`).

E2E test: register voter → release_collateral → assert collateral coin appears at destination, voter's SPT slot is empty.

**2.2 — `Voter::cast_vote`** (voter.rs:432)

Hardest of the voter methods. Builds:
- Registration Coin spend invoking `mint_voting_coin` action with solution `(ballot_launcher_id, vote_close_height, vote_data, ballot_coin_id, registration_coin_id, initial_signature, ballot_membership_witness, voting_coin_amount)`. The `ballot_membership_witness` proves non-membership of `ballot_launcher_id` in the per-registration ballot SPT.
- Ballot Coin spend running its `oracle` action (open variant) — `mint_voting_coin` asserts the announcement.

Computing `ballot_membership_witness`: same SPT machinery as `register` for the registration SPT, but applied to the per-registration ballot SPT carried in `RegistrationState.voted_ballots_root`. The voter's local state must track which ballots they've already minted Voting Coins for, OR the SDK can read the latest `voted_ballots_root` from chain and recompute siblings off-chain (deterministic).

The Voting Coin's puzzle hash is computed via `puzzles::voting_coin_puzzle_hash(...)`.

E2E test: register voter → create_ballot → cast_vote → assert Voting Coin lands on chain at predicted puzzle hash + emits the BLS sig in memos.

**2.3 — `Voter::update_vote`** (voter.rs:462)

Voting Coin spend running its `update_vote` action. Co-spends Ballot Coin oracle. Recreates Voting Coin with new `vote_data`.

E2E test: cast_vote → update_vote → assert new Voting Coin's `vote_data` matches; old Voting Coin spent.

### Tier 3: finalize (heaviest)

**3.1 — `Aggregator::collect_votes_for_ballot`** (aggregator.rs:234)

Walks Voting Coin lineage by `ballot_launcher_id`. Each Voting Coin's tip is the latest spend; extract the `(voter_pubkey, ballot_launcher_id, vote_data, registration_coin_id)` from its curried state and the BLS signature from its memo. Cross-reference `voter_pubkey` against the registration SPT for `vote_weight`. Return `Vec<VoteRecord>`.

**3.2 — `Aggregator::build_finalize_for_ballot`**

The crown jewel. Requires:
- Real 6-input Groth16 proof (not the stubbed witness). Uses `prover::Scalars::compute(vote_outcome, registration_merkle_root, registration_vote_weight, agg_signers, vote_threshold_num, vote_threshold_den, ballot_launcher_id)`.
- Aggregated BLS signature over `vote_message = sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`.
- Ballot Coin spend running its `finalize` action with solution `(proof, vote_outcome_data, agg_signers, agg_sig, scalars)`.

E2E tests at this tier are the migration plan's `tests/finalize_per_ballot_e2e.rs` and `tests/cross_ballot_replay_rejected.rs`.

---

## Test triage (which #[ignore] does what)

To find each ignored test's reason and decide its disposition:

```bash
grep -rn "#\[ignore" sdk/ cli/ | grep -v target
```

The ignore-message strings are precise enough to triage from output alone. Tests fall into:

- **"stubbed pending Phase 6 — XYZ stub"** → un-ignore when XYZ stub lands.
- **"depends on aggregator finalize"** → un-ignore after Tier 3.
- **"fixture / setup needs Phase 6 update"** → rewrite the test fixture for the new state shape (RegistrationState, BallotState, etc.).
- **"CLVM raise from inside action layer"** → debug Tier 0 first, then un-ignore.

Tests with no clear path back to passing should be DELETED. Bias toward keeping rather than deleting; the original concept usually has a per-ballot analogue.

---

## Architectural references (read before implementing)

1. **`CHIP.md`** (worktree root) — canonical spec. Especially "Ballot Coin", "Voting Coin", "Vote message preimage", "Inner actions" tables.

2. **`puzzles/`** — every action puzzle's `.rue` source pins the exact solution shape. The SDK code MUST match the rest-arg convention (last field after `...` is the cdr of the last cons, no nil terminator).

3. **`sdk/src/actors/voter.rs::register_for_election`** — the working template for singleton-spend assembly. Every other singleton-spending actor method should follow the same structure: locate via `wait_for_current_singleton`, build action-layer puzzle, build action solution, wrap with `build_singleton_spend`, dry-run, sign.

4. **`sdk/tests/voter_register_full_flow.rs`** — the working template for simulator e2e tests.

5. **`sdk/src/action_spends.rs`** — the action-layer machinery. `build_action_layer_puzzle`, `build_action_layer_solution`, `build_singleton_spend`, `build_election_finalizer_full`. Read the docstrings; they explain CHIP-0050.

6. **`sdk/src/puzzles.rs`** — every puzzle hash, action root, helper function. Single source of truth for tree-hash compositions.

7. **`app/docs/superpowers/plans/2026-05-02-chip-migration.md`** — the migration plan that produced everything up to commit `db779b7`. Phase 6 in the plan is the work this handoff covers.

8. **`app/docs/chip-migration-gap-analysis.md`** — the original gap analysis from before the migration started; useful for understanding why each piece was migrated.

---

## Verification at the end of each Tier

```bash
cd /c/Users/micha/workspace/dig-network/CHIP
cargo build --workspace                                       # must succeed
cargo test --workspace 2>&1 | grep -E "^test result"           # all rows "ok"
cargo test --workspace 2>&1 | grep "^FAILED" | wc -l           # must be 0
grep -rn "#\[ignore" sdk/ cli/ | grep -v target | wc -l        # decreasing each tier
```

When the count of ignored tests reaches 0 and every stubbed actor method has a passing e2e test, the migration is complete.

---

## Commit hygiene

Each Tier should land as a single commit (or 2-3 if the implementation + test are large enough to separate). Suggested message format:

```
sdk(<actor>): implement <Method>; e2e <test name>

Replaces the Phase 4 stub with <one-line summary>.

Test <test name> covers <what>: <how>.

Removes <N> #[ignore] markers (now passing).
```

Do not amend earlier migration commits; build forward.
