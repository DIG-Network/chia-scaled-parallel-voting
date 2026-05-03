# CHIP Migration — Phase 6+ Handoff (continued)

**Date:** 2026-05-03 (updated)
**Branch:** `main`
**Latest commit:** `fc374bc sdk(actors): implement Voter::release_collateral; CLI plumbed for SMT sync`
**Workspace status:** Builds clean. 210 tests passing, 24 ignored, 0 failed.

This document is the entry-point prompt for a fresh session continuing the CHIP-rev-2026-05-02 migration. Tiers 0, 1, and 2.1 are complete and committed on `main`; remaining work is Tiers 2.2 (cast_vote), 2.3 (update_vote), and 3 (Aggregator finalize), plus the missing Ballot Coin launcher second-spend driver that gates testing for Tier 2.2+.

---

## Use as a session-start prompt

Copy everything between the `===` markers below into a new Claude Code session.

```
===
You are continuing a multi-session CHIP migration project. Tiers 0, 1, and
2.1 are complete and committed on `main`. The remaining work is filling in
stubbed actor methods + un-ignoring or deleting tests, per the user's
directive: "all stubbed methods need to be implemented and fully tested;
all ignored tests must pass or be removed."

Working directory: `C:\Users\micha\workspace\dig-network\CHIP` (Windows;
use bash for git, ctx_execute_file for analysis).

Branch: `main`. Latest commit before this session: `fc374bc`.

Read the full handoff at `app/docs/chip-migration-handoff.md` for the
remaining work + recommended order. Then start executing.

Pre-session state:
- Tier 0 (commit 903ded6): fixed BallotIssuer::create_ballot CLVM raise.
  Root cause was the standard singleton outer's
  `(assert (not has_odd_output_been_found))` rejecting two odd-amount
  CreateCoins (the finalizer's recreation + the launcher mint). Fix:
  changed launcher mint to amount 2 + added a `funder_spend` parameter.
- Tier 1 (commit 63b343e): implemented BallotReader.list_ballots/get_ballot
  + Indexer per-ballot accessors via Election Singleton lineage walk.
- Tier 2.1 (commit fc374bc): implemented Voter::release_collateral
  (singleton deregister + CAT-wrapped registration release co-spend). No
  e2e yet — see "Tier 2.1 follow-up" below.

The first thing the next session should do is build the Ballot Coin
launcher second-spend driver — it unblocks testing for Tier 2.2 onward.
```

---

## Done so far (this session)

| Tier | Commit | What landed |
|---|---|---|
| 0 | `903ded6` | Fixed `BallotIssuer::create_ballot` CLVM raise (singleton-outer multi-odd-CreateCoin invariant); launcher amount 1 → 2; added `funder_spend` param. e2e `create_ballot_e2e` un-ignored, passes. New regression test `create_ballot_action_isolated`. |
| 1.1 | `63b343e` | `BallotReader::list_ballots` / `get_ballot` walk the Election Singleton lineage and pick out launcher children at `SINGLETON_LAUNCHER_HASH` + amount 2. New e2e `ballot_reader_e2e`. |
| 1.2 | `63b343e` | Wired `Indexer::ballots`, `ballot_state`, `is_finalized_for`, `vote_outcome_for` to delegate to shared free functions `list_ballots_via_chain` / `get_ballot_via_chain`. Same e2e. |
| 2.1 | `fc374bc` | `Voter::release_collateral` builds singleton-deregister + CAT-wrapped Registration Coin release co-spend. New `registration_state_node` helper. CLI both call sites updated. **No e2e yet** — see follow-up below. |

**Workspace baseline at end of session:** 210 passed, 24 ignored, 0 failed.

---

## Critical gotcha discovered (already fixed)

**Singleton outer enforces single-odd-CreateCoin invariant.** The standard `singleton_top_layer_v1_1.clsp`'s `check_and_morph_conditions_for_singleton` raises if it sees more than one odd-amount CreateCoin in the inner conditions. ANY action that mints a child coin from inside the singleton MUST use an even amount or accept the singleton outer's recreation slot semantics.

Implication for any future action: **child coins minted via singleton actions must be even-amount**, and the SDK + caller must provide a co-spent funder when the child requires a positive amount the singleton can't fund out of its own (1-mojo) recreation budget.

---

## Tier 2.1 follow-up: e2e for `Voter::release_collateral`

Implementation landed in `fc374bc` but no e2e covers the full path. The blockers:

1. **Need a real on-chain Registration Coin** (CAT-wrapped at the predicted `fresh_registration_coin_puzzle_hash`).
2. **Need the Registration Coin's parent to be a parseable CAT spend** (so `reconstruct_cat_lineage` can derive the lineage proof).

The existing `voter_register_full_flow.rs` test ALSO doesn't actually mint a Registration Coin — its `cat_parent_spend` is a quoted-conditions p2 puzzle that emits only `CreateCoinAnnouncement`, not `CreateCoin`. The test only validates the singleton accepts the announcement assertion.

**Practical path for the e2e:** build a CAT issuance fixture in `tests/common/mod.rs` (a single-use TAIL spend that issues `COLLATERAL_AMOUNT` to the predicted fresh registration ph), then deploy → run register → run release. Sub-task estimate: 2-3 hours.

---

## Remaining work

### Prerequisite: Ballot Coin launcher second-spend driver (NEW, ~3-4 hrs)

Tier 2.2+ all need a Ballot Coin singleton on chain — the `BallotIssuer::create_ballot` from Tier 0 only mints the launcher EVE coin. Adding the launcher second-spend driver is a small focused task that unblocks every downstream Tier:

* **API:** new `BallotIssuer::launch_ballot(launcher_coin_id, vote_close_height, outcome_domain_hash) -> SpendBundle` (and matching helper for the predicted Ballot Coin singleton puzzle hash).
* **Curries:** the Ballot Coin's action layer is curried with the Ballot finalizer + ballot actions merkle root + `BallotState::fresh()`. The Ballot finalizer is itself curried with `(VK, IC, threshold_pack, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID, MAX_SIGNERS, ACTION_LAYER_MOD_HASH)` — see `puzzles/ballot_coin/finalizer.rue` for the exact list.
* **Funder:** the launcher coin is amount 2; the eve Ballot Coin singleton needs amount ≥ 1 (odd). Caller provides a funder coin to balance amounts (or the launcher's 2 mojos can cover a 1-mojo eve singleton with 1 mojo as fee).
* **Test:** `tests/launch_ballot_e2e.rs` — `create_ballot` → `launch_ballot` → assert eve Ballot Coin lands at predicted puzzle hash.

### Tier 2.2: `Voter::cast_vote` (~5-8 hrs)

`sdk/src/actors/voter.rs:432` — current stub.

Builds:
* **Registration Coin spend** running `mint_voting_coin` action. Solution: 8 fields including a BLS signature over `vote_message`, an SPT non-membership proof for the per-registration ballot SPT, the ballot coin id (looked up via `BallotReader::get_ballot`), and the voting coin amount.
* **Ballot Coin spend** running `oracle` action (open variant). The mint_voting_coin action `AssertCoinAnnouncement`s its message.

**Curry order** (per `puzzles/registration_coin/mint_voting_coin.rue`):
`(CAT_MOD_HASH, CAT_TAIL_HASH, ACTION_LAYER_MOD_HASH, VOTING_COIN_FINALIZER_MOD_HASH, VOTING_COIN_ACTIONS_MERKLE_ROOT)`

**Solution shape:**
`(ballot_launcher_id, vote_close_height, vote_data, ballot_coin_id, registration_coin_id, initial_signature, ballot_membership_witness, ...voting_coin_amount)`

**SDK helpers needed (none exist yet):**
* `voting_coin_full_puzzle_hash(...)` — CAT-wraps the action layer hash with `(CAT_MOD_HASH, CAT_TAIL_HASH, vc_action_layer_hash)`.
* `voting_coin_inner_puzzle_hash(state, election_id, voter_pubkey, ballot_launcher_id, ...)` — composes the action layer hash from the VC finalizer + VC actions root + initial state.
* `voting_coin_hint(election_id, cat_tail_hash, voter_pubkey, ballot_launcher_id)` — `sha256("CHIP/onchain/voting_coin_hint/v1/" || ...)`.

**Per-registration ballot SPT:** the registration coin's `voted_ballots_root` is a separate small SPT (typed `BallotMembership` in shared.rue, depth ≠ TREE_DEPTH per CHIP — needs verification against the puzzle). Voter must maintain it locally OR derive from the on-chain Registration Coin's spend history.

**E2E test (depends on launcher second-spend):** deploy → register → create_ballot → launch_ballot → cast_vote → assert Voting Coin lands at predicted PH.

### Tier 2.3: `Voter::update_vote` (~3-5 hrs)

`sdk/src/actors/voter.rs:462` — current stub.

Smaller delta from cast_vote: spends an existing Voting Coin via its `update_vote` action; co-spends Ballot Coin oracle. Recreates Voting Coin with new `vote_data`. AGG_SIG over the new vote_message.

**E2E (depends on cast_vote):** cast_vote → update_vote → assert new Voting Coin's vote_data matches; old VC spent.

### Tier 3: Aggregator finalize (~8-15 hrs)

#### 3.1 — `Aggregator::collect_votes_for_ballot` (`aggregator.rs:234`)

Walks Voting Coin lineage by `ballot_launcher_id`. For each Voting Coin tip: extract `(voter_pubkey, ballot_launcher_id, vote_data, registration_coin_id)` from the curried state and the BLS signature from memos / spend solution. Cross-reference `voter_pubkey` against the registration SPT for `vote_weight`. Returns `Vec<VoteRecord>`.

Once landed, `Indexer::votes_for_ballot` (currently still stubbed) wires up via:
```rust
self.aggregator.collect_votes_for_ballot(ballot_launcher_id).await
```

#### 3.2 — `Aggregator::build_finalize_for_ballot`

Heaviest piece. Requires:
* **Real 6-input Groth16 proof** (not the current stub). Uses `prover::Scalars::compute(vote_outcome, registration_merkle_root, registration_vote_weight, agg_signers, vote_threshold_num, vote_threshold_den, ballot_launcher_id)`.
* **Aggregated BLS signature** over `vote_message = sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`.
* **Ballot Coin spend** running `finalize` action with solution `(proof, vote_outcome_data, agg_signers, agg_sig, scalars)`.

**E2E:** the migration plan's `tests/finalize_per_ballot_e2e.rs` and `tests/cross_ballot_replay_rejected.rs`.

---

## Architectural references

1. **`CHIP.md`** — canonical spec; sections "Ballot Coin", "Voting Coin", "Vote message preimage", "Inner actions" tables.
2. **`puzzles/`** — every action puzzle's `.rue` source pins the exact solution shape. SDK code MUST match the rest-arg convention (last field after `...` is the cdr of the last cons, no nil terminator).
3. **`sdk/src/actors/voter.rs::register_for_election` (`Voter::register`)** — working template for singleton-spend assembly. Tier 2.1's `release_collateral` follows the same shape.
4. **`sdk/tests/voter_register_full_flow.rs`** — working template for simulator e2e tests.
5. **`sdk/src/action_spends.rs`** — the action-layer machinery. `build_action_layer_puzzle`, `build_action_layer_solution`, `build_singleton_spend`, `build_cat_spend`, `build_election_finalizer_full`, `build_registration_finalizer_full`. Read the docstrings; they explain CHIP-0050.
6. **`sdk/src/puzzles.rs`** — every puzzle hash, action root, helper function. Single source of truth for tree-hash compositions.
7. **`sdk/src/actors/ballot.rs::list_ballots_via_chain`** — pattern for chain-walking the singleton lineage; reusable shape for any post-singleton coin-discovery method.
8. **`puzzles/election/create_ballot.rue` + commit `903ded6`** — record of the singleton-outer multi-odd-CreateCoin lesson.

---

## Minor cleanup

**Dead helper in `puzzles/ballot_coin/shared.rue`:** `ballot_oracle_open_msg` uses prefix `"ballot_open"` but `oracle.rue` actually emits `"ballot_oracle_open"`. The helper isn't called from any action so functionality isn't affected, but the helper is misleading — either delete it or update its prefix to match. (Discovered during Tier 2.2 prep.)

---

## Verification at the end of each Tier

```bash
cd /c/Users/micha/workspace/dig-network/CHIP
cargo build --workspace                                       # must succeed
cargo test --workspace 2>&1 | grep -E "^test result"           # all rows "ok"
cargo test --workspace 2>&1 | grep "^FAILED" | wc -l           # must be 0
grep -rn "#\[ignore" sdk/ cli/ | grep -v target | wc -l        # decreasing each tier (currently 24)
```

When the count of ignored tests reaches 0 and every stubbed actor method has a passing e2e test, the migration is complete.

---

## Commit hygiene

Each Tier should land as a single commit (or 2-3 if implementation + test are large enough to separate). Format:

```
sdk(<actor>): implement <Method>; e2e <test name>

Replaces the Phase 6 stub with <one-line summary>.

Test <test name> covers <what>: <how>.

Removes <N> #[ignore] markers (now passing).
```

Do not amend earlier migration commits; build forward.
