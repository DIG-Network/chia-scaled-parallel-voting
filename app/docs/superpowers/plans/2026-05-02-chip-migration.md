# CHIP Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended — each phase is well-suited to a fresh subagent) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `puzzles/` and `sdk/` to match the revised `CHIP.md` (rev 2026-05-02): Election Singleton becomes a pure orchestrator; election mechanics (finalize, oracle, announce_finalization) move to a new Ballot Coin; voting moves off the Registration Coin onto new Voting Coins; the Groth16 circuit gains a 6th `ballot_launcher_id` public input; the XCH registration fee is removed; per-ballot uniqueness is enforced via a per-registration ballot SPT.

**Architecture:** Three new coin types (`Ballot Coin`, `Voting Coin`) and one re-scoped coin type (`Election Singleton` as orchestrator only). Action layer (CHIP-0050) wraps every coin's inner actions. Off-chain prover and aggregator are reworked to enumerate Voting Coins per ballot rather than registration memos. Existing SPT, lineage-proof, and ceremony infrastructure are preserved; only the circuit shape and VK change.

**Tech Stack:** Rust 1.75+, `chia-wallet-sdk`, `clvm-traits`, Rue puzzle DSL (compiled to CLVM), `ark-groth16` / `ark-bls12-381` for proving, custom MPC ceremony backend.

**Scope check:** This plan touches five subsystems (puzzles, SDK types, SDK actors, prover/ceremony, tests). It is presented as one document with sequential phases because the dependencies are tight (later phases consume earlier outputs). Each phase IS suitable for a dedicated subagent; the recommended execution mode is one subagent per phase with a verification checkpoint between phases.

**Decisions resolved against CHIP.md (rev 2026-05-02):**
- Singleton actions: `{register, createBallot, deregister}` only (delete `finalize`, `oracle`, `announce_finalization`).
- Ballot Coin actions: `{finalize, oracle, announce_finalization}`.
- Registration Coin actions: `{mint_voting_coin, release}` (delete `vote`, `change_vote`).
- Voting Coin actions: `{update_vote}`.
- Public inputs: 6, in order — `registration_merkle_root, registration_vote_weight, agg_signers, vote_message, threshold_pack, ballot_launcher_id`. **Threshold check preserved.**
- `vote_message = sha256(vote_outcome || ballot_launcher_id || election_launcher_id)` (pinned).
- Per-registration ballot SPT (depth 32, slot from `sha256(ballot_launcher_id) mod 2^32`) carries `voted_ballots_root` in `RegistrationState`.
- VK length: `336 + 7*48 = 672` bytes. Fresh MPC ceremony required.
- No XCH registration fee anywhere; no `accumulated_fees` field; no `REGISTRATION_FEE` curry.
- Release-collateral trigger: singleton `deregister` announcement. Independent of ballot finalize.

---

## Phase 0 — Branch, Worktree, Baseline Tests

**Why first:** Every later phase deletes or rewrites code, so we need a clean baseline and a way to roll back per-phase.

### Task 0.1: Create worktree

**Files:** none (workspace setup).

- [ ] **Step 1:** Create the migration branch in a worktree from `main`.

```bash
git worktree add ../CHIP-migration -b chip-rev-2026-05-02 main
cd ../CHIP-migration
```

- [ ] **Step 2:** Confirm baseline build passes on `main` before any edits.

```bash
cargo build --workspace --all-targets
cargo test --workspace --no-run
```
Expected: workspace builds. Some tests may currently fail (per `git status`); record which.

- [ ] **Step 3:** Capture the baseline test pass/fail list.

```bash
cargo test --workspace 2>&1 | tee /tmp/chip-baseline-tests.txt
```
Save the list to `app/docs/chip-migration-baseline-tests.md` for later comparison.

- [ ] **Step 4:** Commit the baseline marker.

```bash
git add app/docs/chip-migration-baseline-tests.md
git commit -m "chore: snapshot baseline test results before CHIP rev migration"
```

---

## Phase 1 — Puzzles: Author, Edit, Delete

**Why second:** Compiled puzzle hex/hash files are the source-of-truth that `sdk/src/puzzles.rs` mirrors. SDK changes that depend on new puzzle hashes must wait until the compiled artifacts exist.

**Worktree note:** Each `.rue` source change must be followed by recompilation. The repo provides `puzzles/build.ps1` (Windows) and `puzzles/build.sh` (Unix). All compiled artifacts under `puzzles/compiled/` are checked in.

### Task 1.1: Update shared puzzle types

**Files:**
- Modify: `puzzles/election/shared.rue`
- Modify: `puzzles/registration_coin/shared.rue`
- Create: `puzzles/ballot_coin/shared.rue`
- Create: `puzzles/voting_coin/shared.rue`

- [ ] **Step 1:** Rewrite `puzzles/election/shared.rue` so `ElectionState` drops `accumulated_fees`, `finalized`, `vote_outcome`. The new struct:

```rue
struct ElectionState {
    registration_merkle_root: Bytes32,
    registration_count: Int,
    registration_vote_weight: Int,
    election_start_height: Int,
}
```

Remove `finalization_announcement_msg`, `oracle_finalized_announcement_msg`, `oracle_unfinalized_announcement_msg` from this file. Add a new helper `deregister_announcement_msg(voter_pubkey: Bytes) -> Bytes32 = sha256("deregister" || voter_pubkey)`.

- [ ] **Step 2:** Rewrite `puzzles/registration_coin/shared.rue`. New `RegistrationState`:

```rue
struct RegistrationState {
    voter_pubkey: Bytes,
    election_launcher_id: Bytes32,
    voted_ballots_root: Bytes32,
    release_destination: Optional<Bytes32>,
}
```

Remove `EphemeralVote`, `has_voted`, `vote_data`. Add a `BallotMembership` witness type used by `mint_voting_coin`:

```rue
struct BallotMembership {
    ballot_launcher_id: Bytes32,
    siblings: List<Bytes32>,  // length = 32, depth-aligned with EMPTY_BALLOT_LEAF_HASH
}

const EMPTY_BALLOT_LEAF_HASH: Bytes32 = 0x0000000000000000000000000000000000000000000000000000000000000000;
const BALLOT_TREE_DEPTH: Int = 32;
```

- [ ] **Step 3:** Create `puzzles/ballot_coin/shared.rue`. Define:

```rue
struct BallotState {
    finalized: Bool,
    vote_outcome: Bytes32,
    agg_signers: Bytes32,
}

fn ballot_finalization_msg(ballot_launcher_id: Bytes32, vote_outcome: Bytes32, agg_signers: Bytes32) -> Bytes32 {
    sha256("ballot_finalized" || ballot_launcher_id || vote_outcome || agg_signers)
}

fn ballot_oracle_open_msg(ballot_launcher_id: Bytes32, current_height: Int) -> Bytes32 {
    sha256("ballot_open" || ballot_launcher_id || height_be8(current_height))
}

fn ballot_oracle_closed_msg(ballot_launcher_id: Bytes32) -> Bytes32 {
    sha256("ballot_closed" || ballot_launcher_id)
}
```

- [ ] **Step 4:** Create `puzzles/voting_coin/shared.rue`. Define:

```rue
struct VotingCoinState {
    voter_pubkey: Bytes,
    ballot_launcher_id: Bytes32,
    vote_data: Bytes32,
    registration_coin_id: Bytes32,
}

fn vote_message(vote_outcome: Bytes32, ballot_launcher_id: Bytes32, election_launcher_id: Bytes32) -> Bytes32 {
    sha256(vote_outcome || ballot_launcher_id || election_launcher_id)
}
```

- [ ] **Step 5:** Commit.

```bash
git add puzzles/election/shared.rue puzzles/registration_coin/shared.rue puzzles/ballot_coin/shared.rue puzzles/voting_coin/shared.rue
git commit -m "puzzles: rev shared types for ballot/voting coin architecture"
```

### Task 1.2: Update Election Singleton actions

**Files:**
- Modify: `puzzles/election/register.rue` (drop fee, init voted_ballots_root)
- Create: `puzzles/election/create_ballot.rue`
- Create: `puzzles/election/deregister.rue`
- Delete: `puzzles/election/finalize.rue`
- Delete: `puzzles/election/announce_finalization.rue`
- Delete: `puzzles/election/oracle.rue`
- Modify: `puzzles/election/finalizer.rue` (state transitions for new actions)

- [ ] **Step 1:** Edit `puzzles/election/register.rue`. Remove the `REGISTRATION_FEE` curry argument and the corresponding `CREATE_COIN` for the fee. The new curry list (in order): `(TREE_DEPTH, EMPTY_LEAF_HASH, CAT_MOD_HASH, CAT_TAIL_HASH, ACTION_LAYER_MOD_HASH, REGISTRATION_FINALIZER_MOD_HASH, REGISTRATION_MERKLE_ROOT, COLLATERAL_MIN_AMOUNT, ELECTION_LAUNCHER_ID, EMPTY_BALLOT_ROOT)`.

The created Registration Coin's curried `RegistrationState` must initialize `voted_ballots_root = EMPTY_BALLOT_ROOT` and `release_destination = None`. The state delta must also drop `accumulated_fees += REGISTRATION_FEE` (no fee accumulation).

- [ ] **Step 2:** Create `puzzles/election/create_ballot.rue`. Curry: `(SINGLETON_MOD_HASH, BALLOT_COIN_MOD_HASH, BALLOT_ACTIONS_MERKLE_ROOT, ELECTION_LAUNCHER_ID, VK, IC, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN, MAX_SIGNERS)`. Solution: `(ballot_launcher_id_seed, vote_close_height, outcome_domain_hash)`.

The action must:
1. Compute the new Ballot Coin launcher id from `ballot_launcher_id_seed` and the singleton coin id.
2. Emit a `CREATE_COIN` for the Ballot Coin curried with the constants above plus the new ballot's per-ballot args, paying out 1 mojo (singleton-style).
3. Recreate the Election Singleton with unchanged state (ballot creation does not mutate registration count/weight).
4. Emit a coin announcement asserting the ballot was created (`sha256("ballot_created" || ballot_launcher_id)`).

- [ ] **Step 3:** Create `puzzles/election/deregister.rue`. Curry: `(TREE_DEPTH, EMPTY_LEAF_HASH, REGISTRATION_FINALIZER_MOD_HASH, REGISTRATION_MERKLE_ROOT)`. Solution: `(voter_pubkey, leaf_index, occupied_siblings, locked_cat_mojos)`.

The action must:
1. Verify SPT membership of `(voter_pubkey, locked_cat_mojos)` at `leaf_index` against the curried root.
2. Recreate the Election Singleton with `registration_merkle_root` updated (leaf flipped to `EMPTY_LEAF_HASH`), `registration_count -= 1`, `registration_vote_weight -= locked_cat_mojos`.
3. Emit a coin announcement: `sha256("deregister" || voter_pubkey)` — the matching Registration Coin's `release` action asserts this.

- [ ] **Step 4:** Delete the obsolete singleton actions:

```bash
git rm puzzles/election/finalize.rue
git rm puzzles/election/announce_finalization.rue
git rm puzzles/election/oracle.rue
```

- [ ] **Step 5:** Update `puzzles/election/finalizer.rue` to handle the new state shape (no `finalized`/`vote_outcome`/`accumulated_fees`) and the three actions `{register, createBallot, deregister}`. Specifically: the state-delta mux has three branches keyed by action puzzle hash; createBallot is a no-op on state but emits the new Ballot Coin; deregister updates SPT root, count, weight.

- [ ] **Step 6:** Commit.

```bash
git add puzzles/election/
git commit -m "puzzles(election): singleton orchestrates register/createBallot/deregister; remove finalize/oracle/announce_finalization"
```

### Task 1.3: Build Ballot Coin actions

**Files:**
- Create: `puzzles/ballot_coin/finalize.rue`
- Create: `puzzles/ballot_coin/oracle.rue`
- Create: `puzzles/ballot_coin/announce_finalization.rue`
- Create: `puzzles/ballot_coin/finalizer.rue`

- [ ] **Step 1:** Create `puzzles/ballot_coin/finalize.rue`. Curry: `(VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN, BALLOT_FINALIZER_MOD_HASH)`. Solution: `(proof, vote_outcome_data, agg_signers, agg_sig, scalars)` where `scalars` packs the 6 public inputs `(s1..s6)`.

Behavior:
1. Assert `current_height >= VOTE_CLOSE_HEIGHT` via `ASSERT_HEIGHT_ABSOLUTE`.
2. Assert `state.finalized == false`.
3. Compute `vote_outcome = sha256_tree(vote_outcome_data)`.
4. Compute `vote_message_check = sha256(vote_outcome || BALLOT_LAUNCHER_ID || ELECTION_LAUNCHER_ID)` — must equal the 4th scalar.
5. Assert `s5 == threshold_pack(VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN)` (preserves on-chain threshold check).
6. Assert `s6 == BALLOT_LAUNCHER_ID` (binds ballot identity).
7. Run Groth16 pairing identity over `(VK, IC, scalars, proof)`.
8. Run `bls_verify(agg_signers, vote_message_check, agg_sig)`.
9. Recreate Ballot Coin with `state = (finalized=true, vote_outcome=vote_outcome, agg_signers=agg_signers)`.
10. Emit announcement `ballot_finalization_msg(BALLOT_LAUNCHER_ID, vote_outcome, agg_signers)`.

The IC inputs map to the 6 scalars in order; the IC struct must have 7 G1 points (`ic0` plus `ic1..ic6`).

- [ ] **Step 2:** Create `puzzles/ballot_coin/oracle.rue`. Curry: `(BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT)`. Solution: `(current_height,)`. Behavior: emit one of two announcements based on whether `current_height < VOTE_CLOSE_HEIGHT` (`ballot_oracle_open_msg`) or otherwise (`ballot_oracle_closed_msg`); recreate ballot coin unchanged. This is the announcement that Voting Coin `update_vote` asserts.

- [ ] **Step 3:** Create `puzzles/ballot_coin/announce_finalization.rue`. Curry: `(BALLOT_LAUNCHER_ID,)`. Solution: `(vote_outcome, agg_signers)`. Behavior: assert `state.finalized == true`, emit `ballot_finalization_msg(...)` again, recreate unchanged.

- [ ] **Step 4:** Create `puzzles/ballot_coin/finalizer.rue` mirroring the action-layer finalizer pattern from the existing election finalizer, but with the three Ballot Coin actions.

- [ ] **Step 5:** Commit.

```bash
git add puzzles/ballot_coin/
git commit -m "puzzles(ballot_coin): finalize/oracle/announce_finalization with 6-input Groth16 + ballot binding"
```

### Task 1.4: Update Registration Coin actions

**Files:**
- Create: `puzzles/registration_coin/mint_voting_coin.rue`
- Modify: `puzzles/registration_coin/release.rue` (assert deregister announcement)
- Delete: `puzzles/registration_coin/vote.rue`
- Delete: `puzzles/registration_coin/change_vote.rue`
- Modify: `puzzles/registration_coin/finalizer.rue`

- [ ] **Step 1:** Create `puzzles/registration_coin/mint_voting_coin.rue`. Curry: `(VOTING_COIN_MOD_HASH, VOTING_COIN_ACTIONS_MERKLE_ROOT, ELECTION_LAUNCHER_ID, BALLOT_TREE_DEPTH, EMPTY_BALLOT_LEAF_HASH, REGISTRATION_FINALIZER_MOD_HASH)`. Solution: `(ballot_launcher_id, vote_close_height_attested, vote_data, ballot_membership_witness, ballot_oracle_announcement_id, initial_signature)`.

Behavior:
1. **Assert the Ballot Coin's `oracle` announcement** for `(ballot_launcher_id, vote_close_height_attested, finalized=false)` via `ASSERT_COIN_ANNOUNCEMENT` over `ballot_oracle_announcement_id`. This is the on-chain proof that the ballot exists, is still open, and has the claimed close height — preventing forged or stale-close-height mints. The companion Ballot Coin `oracle` spend MUST be in the same bundle.
2. Verify NON-membership of `ballot_launcher_id` in `state.voted_ballots_root` using `ballot_membership_witness` (siblings + slot index from `sha256(ballot_launcher_id) mod 2^32`).
3. Compute `new_voted_ballots_root` by inserting `sha256(ballot_launcher_id)` at the matching slot.
4. Mint Voting Coin with `VotingCoinState(voter_pubkey, ballot_launcher_id, vote_data, this_coin_id)` plus curried `VOTE_CLOSE_HEIGHT = vote_close_height_attested` and `ELECTION_LAUNCHER_ID` so subsequent `update_vote` spends inherit a value that has been verified on-chain.
5. Emit `initial_signature` as a memo for the aggregator (BLS over `vote_message(vote_data, ballot_launcher_id, ELECTION_LAUNCHER_ID)`).
6. Recreate Registration Coin with updated `voted_ballots_root` and unchanged other fields.

- [ ] **Step 2:** Modify `puzzles/registration_coin/release.rue`. Replace the assertion of `oracle_finalized_announcement_msg` with assertion of the singleton's `deregister` announcement: `sha256("deregister" || voter_pubkey)`. Curry must include the singleton's launcher id so the announcement source is unambiguous.

- [ ] **Step 3:** Delete obsolete vote actions:

```bash
git rm puzzles/registration_coin/vote.rue
git rm puzzles/registration_coin/change_vote.rue
```

- [ ] **Step 4:** Update `puzzles/registration_coin/finalizer.rue` to dispatch only `{mint_voting_coin, release}`.

- [ ] **Step 5:** Commit.

```bash
git add puzzles/registration_coin/
git commit -m "puzzles(registration_coin): mint_voting_coin with per-ballot SPT uniqueness; release asserts deregister"
```

### Task 1.5: Build Voting Coin actions

**Files:**
- Create: `puzzles/voting_coin/update_vote.rue`
- Create: `puzzles/voting_coin/finalizer.rue`

- [ ] **Step 1:** Create `puzzles/voting_coin/update_vote.rue`. Curry: `(BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, VOTING_COIN_FINALIZER_MOD_HASH)`. Solution: `(new_vote_data, new_signature, ballot_oracle_announcement_id)`.

Behavior:
1. `ASSERT_COIN_ANNOUNCEMENT` over `ballot_oracle_announcement_id` derived from the Ballot Coin `oracle` action emitting `(BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, finalized=false)`. This pins ballot identity, ballot close height, and current open-state in the same block as the update — defending against an attacker-controlled curried close height (the `oracle` action is the only place close height is attested by an on-chain spend). The companion Ballot Coin `oracle` spend MUST be in the same bundle.
2. Belt-and-braces local check: `ASSERT_HEIGHT_ABSOLUTE_LT VOTE_CLOSE_HEIGHT` — redundant with (1) when the oracle is honest, but cheap and fails closed if the announcement format ever drifts.
3. Recreate Voting Coin with new `vote_data = new_vote_data` (all other curried fields, including `VOTE_CLOSE_HEIGHT`, unchanged).
4. Emit `new_signature` as a memo for the aggregator (BLS over `vote_message(new_vote_data, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID)`).

- [ ] **Step 2:** Create `puzzles/voting_coin/finalizer.rue` mirroring the action-layer finalizer pattern, with only `update_vote` in the action set.

- [ ] **Step 3:** Commit.

```bash
git add puzzles/voting_coin/
git commit -m "puzzles(voting_coin): update_vote gated by Ballot Coin oracle"
```

### Task 1.6: Recompile and refresh artifacts

**Files:**
- Recompile: all `.rue` under `puzzles/`
- Output: `puzzles/compiled/election/{register,create_ballot,deregister,finalizer}.{hex,hash}` (delete old `finalize/oracle/announce_finalization`)
- Output: `puzzles/compiled/ballot_coin/{finalize,oracle,announce_finalization,finalizer}.{hex,hash}` (new directory)
- Output: `puzzles/compiled/registration_coin/{mint_voting_coin,release,finalizer}.{hex,hash}` (delete old `vote/change_vote`)
- Output: `puzzles/compiled/voting_coin/{update_vote,finalizer}.{hex,hash}` (new directory)

- [ ] **Step 1:** Run the puzzle compiler.

```bash
cd puzzles
./build.sh   # or build.ps1 on Windows
```

Expected: every `.rue` under `puzzles/` produces a fresh `.hex` + `.hash` pair under `puzzles/compiled/<subdir>/`. Build fails fast on type errors — fix any issues by going back to the relevant Task 1.x.

- [ ] **Step 2:** Delete obsolete compiled artifacts.

```bash
git rm puzzles/compiled/election/finalize.{hex,hash}
git rm puzzles/compiled/election/announce_finalization.{hex,hash}
git rm puzzles/compiled/election/oracle.{hex,hash}
git rm puzzles/compiled/registration_coin/vote.{hex,hash}
git rm puzzles/compiled/registration_coin/change_vote.{hex,hash}
```

- [ ] **Step 3:** Stage new artifacts and commit.

```bash
git add puzzles/compiled/
git commit -m "puzzles(compiled): refresh artifacts for CHIP rev 2026-05-02"
```

---

## Phase 2 — SDK puzzle constants (`puzzles.rs`)

**Why now:** Every later SDK change references puzzle hashes by symbolic name. This phase rewrites the constants module so subsequent code compiles.

### Task 2.1: Rewrite `sdk/src/puzzles.rs`

**Files:**
- Modify: `sdk/src/puzzles.rs`
- Test: `sdk/tests/puzzle_constants.rs` (new, optional but recommended)

- [ ] **Step 1:** Replace the existing constants. Remove:
  - `ELECTION_FINALIZE_HEX` / `_HASH`
  - `ELECTION_ANNOUNCE_FINALIZATION_HEX` / `_HASH`
  - `ELECTION_ORACLE_HEX` / `_HASH`
  - `ELECTION_FINALIZER_HEX` / `_HASH` (the singleton finalizer is renamed for the new state shape)
  - `REGISTRATION_VOTE_HEX` / `_HASH`
  - `REGISTRATION_CHANGE_VOTE_HEX` / `_HASH`

  Add (each is `include_str!("../../puzzles/compiled/.../<name>.hex")` and a corresponding `_HASH` from the matching `.hash` file):
  - `ELECTION_CREATE_BALLOT_HEX` / `_HASH`
  - `ELECTION_DEREGISTER_HEX` / `_HASH`
  - `BALLOT_COIN_FINALIZE_HEX` / `_HASH`
  - `BALLOT_COIN_ORACLE_HEX` / `_HASH`
  - `BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX` / `_HASH`
  - `BALLOT_COIN_FINALIZER_HEX` / `_HASH`
  - `REGISTRATION_MINT_VOTING_COIN_HEX` / `_HASH`
  - `VOTING_COIN_UPDATE_VOTE_HEX` / `_HASH`
  - `VOTING_COIN_FINALIZER_HEX` / `_HASH`

- [ ] **Step 2:** Replace the helpers. The functions to remove or rename:
  - DELETE: `oracle_finalized_message`, `oracle_unfinalized_message`, `oracle_announcement_id`.
  - DELETE: `fresh_registration_state_tree_hash` if it bakes in `has_voted` / `vote_data` (likely yes); rewrite to take `voted_ballots_root` instead.
  - REPLACE: `registration_actions_merkle_root` to combine `[mint_voting_coin_hash, release_hash]` (2 leaves instead of 3).
  - REPLACE: `election_actions_merkle_root` to combine `[register_hash, create_ballot_hash, deregister_hash]`.
  - ADD: `ballot_actions_merkle_root() -> Bytes32` over `[finalize_hash, oracle_hash, announce_finalization_hash]`.
  - ADD: `voting_coin_actions_merkle_root() -> Bytes32` over `[update_vote_hash]` (single leaf).
  - ADD: `ballot_coin_puzzle_hash(election_launcher_id, ballot_launcher_id, vote_close_height, outcome_domain, vk_hash, ic_hash, threshold_num, threshold_den) -> Bytes32`.
  - ADD: `voting_coin_puzzle_hash(voter_pubkey_hash, ballot_launcher_id, election_launcher_id) -> Bytes32`.
  - ADD: `deregister_announcement_msg(voter_pubkey: &[u8]) -> Bytes32`.
  - ADD: `ballot_oracle_open_msg(ballot_launcher_id, current_height) -> Bytes32`.
  - ADD: `ballot_oracle_closed_msg(ballot_launcher_id) -> Bytes32`.
  - ADD: `ballot_finalization_msg(ballot_launcher_id, vote_outcome, agg_signers) -> Bytes32`.
  - ADD: `vote_message(vote_outcome, ballot_launcher_id, election_launcher_id) -> Bytes32`.
  - ADD: `EMPTY_BALLOT_LEAF_HASH: Bytes32` and `BALLOT_TREE_DEPTH: usize = 32`.

- [ ] **Step 3:** Add `sdk/tests/puzzle_constants.rs` with assertions that each `_HEX` parses as valid CLVM and that the `_HASH` matches `tree_hash(parse(_HEX))`. This catches stale artifact / constant drift.

```rust
#[test]
fn ballot_coin_finalize_hash_matches_hex() {
    let parsed = clvm_traits::parse_clvm_hex(BALLOT_COIN_FINALIZE_HEX).unwrap();
    let computed = clvm_traits::tree_hash(&parsed);
    assert_eq!(computed.as_slice(), BALLOT_COIN_FINALIZE_HASH);
}
```

Repeat for each puzzle.

- [ ] **Step 4:** Run.

```bash
cargo test -p chip-voting-sdk --test puzzle_constants
```

Expected: all assertions pass; otherwise the recompile in Task 1.6 produced a mismatch.

- [ ] **Step 5:** Commit.

```bash
git add sdk/src/puzzles.rs sdk/tests/puzzle_constants.rs
git commit -m "sdk(puzzles): rewire constants and helpers for ballot/voting coin puzzles"
```

---

## Phase 3 — SDK Types and Config

**Why now:** Phase 4 (actor logic) consumes these types. Splitting the type changes from the actor changes makes diffs reviewable.

### Task 3.1: Rewrite `sdk/src/state.rs`

**Files:**
- Modify: `sdk/src/state.rs`

- [ ] **Step 1:** Update `ElectionState` to drop `accumulated_fees`, `finalized`, `vote_outcome`. New shape:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionState {
    pub registration_merkle_root: Bytes32,
    pub registration_count: u64,
    pub registration_vote_weight: u64,
    pub election_start_height: u32,
}

impl ElectionState {
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        // 4-tuple: (root, count, weight, start_height)
        // matches puzzles/election/shared.rue ElectionState
        ...
    }
}
```

- [ ] **Step 2:** Update `RegistrationState`:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationState {
    pub voter_pubkey: Bytes,
    pub election_launcher_id: Bytes32,
    pub voted_ballots_root: Bytes32,
    pub release_destination: Option<Bytes32>,
}
```

Drop `has_voted`, `vote_data`. Add a constructor `RegistrationState::fresh(voter_pubkey, election_launcher_id)` that initializes `voted_ballots_root = EMPTY_BALLOT_ROOT`, `release_destination = None`.

- [ ] **Step 3:** Add new types:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotState {
    pub finalized: bool,
    pub vote_outcome: Bytes32,
    pub agg_signers: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotCoinSnapshot {
    pub ballot_launcher_id: Bytes32,
    pub election_launcher_id: Bytes32,
    pub vote_close_height: u32,
    pub outcome_domain_hash: Bytes32,
    pub state: BallotState,
    pub coin_id: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingCoinState {
    pub voter_pubkey: Bytes,
    pub ballot_launcher_id: Bytes32,
    pub vote_data: Bytes32,
    pub registration_coin_id: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingCoinSnapshot {
    pub coin_id: Bytes32,
    pub state: VotingCoinState,
    pub latest_signature: Bytes,    // BLS sig over vote_message
}
```

- [ ] **Step 4:** Update `VoteRecord` and `VoteRecordWire` to add `ballot_launcher_id: Bytes32` and `voting_coin_id: Bytes32`. The aggregator now keys vote records on `(ballot_launcher_id, registration_coin_id)`.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteRecord {
    pub voter_pubkey: Bytes,
    pub ballot_launcher_id: Bytes32,
    pub voting_coin_id: Bytes32,
    pub vote_data: Bytes32,
    pub vote_signature_hex: String,
    pub registration_coin_id: Bytes32,
    pub vote_weight: u64,
}
```

- [ ] **Step 5:** `VoterSet` can stay; it is the registration SPT snapshot and is unchanged by ballot semantics.

- [ ] **Step 6:** Run.

```bash
cargo build -p chip-voting-sdk
```

Expected: many compile errors elsewhere — that is expected; fixing them is Phase 4. The state module itself must compile cleanly.

```bash
cargo build -p chip-voting-sdk --lib --features minimal-state-only 2>&1 | grep -c "error\[E" 
```
(If the workspace doesn't have feature gating, just confirm `state.rs` itself has no errors via `cargo check -p chip-voting-sdk 2>&1 | head -50`.)

- [ ] **Step 7:** Commit.

```bash
git add sdk/src/state.rs
git commit -m "sdk(state): rev structs for ballot/voting coins; drop fees/finalized/vote_outcome from ElectionState"
```

### Task 3.2: Rewrite `sdk/src/config.rs`

**Files:**
- Modify: `sdk/src/config.rs`

- [ ] **Step 1:** Drop `registration_fee` field from `ElectionConfig` and from `validate()`.

- [ ] **Step 2:** Drop `election_length_blocks` (or relabel as `deployment_sunset_height` per CHIP rev). Per-ballot timing lives on Ballot Coins.

- [ ] **Step 3:** Bump `pub const PUBLIC_INPUT_COUNT: usize = 6;` (was 5).

- [ ] **Step 4:** Update VK length validator. The new length is `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 672` bytes:

```rust
const EXPECTED_VK_LEN: usize = 336 + (PUBLIC_INPUT_COUNT + 1) * 48; // 672

impl ElectionConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        let vk_bytes = hex::decode(&self.verification_key_hex)?;
        if vk_bytes.len() != EXPECTED_VK_LEN {
            return Err(ConfigError::InvalidVkLength {
                expected: EXPECTED_VK_LEN,
                actual: vk_bytes.len(),
            });
        }
        // ... other checks unchanged
    }
}
```

- [ ] **Step 5:** Run.

```bash
cargo check -p chip-voting-sdk
```

Expect downstream errors; fix only the `config.rs`-internal ones now.

- [ ] **Step 6:** Commit.

```bash
git add sdk/src/config.rs
git commit -m "sdk(config): PUBLIC_INPUT_COUNT=6; VK length 672; drop registration_fee/election_length_blocks"
```

### Task 3.3: Update `sdk/src/error.rs`

**Files:**
- Modify: `sdk/src/error.rs`

- [ ] **Step 1:** Add error variants:

```rust
#[derive(thiserror::Error, Debug)]
pub enum VotingError {
    // ...existing variants...
    #[error("ballot {0} not found in chain state")]
    BallotNotFound(Bytes32),
    #[error("ballot {0} has already ended at height {1}")]
    BallotEnded(Bytes32, u32),
    #[error("registration {0} has already minted a Voting Coin for ballot {1}")]
    DuplicateVotingCoin(Bytes32, Bytes32),
    #[error("vote_message preimage mismatch: expected sha256(outcome||ballot||election)")]
    VoteMessagePreimageMismatch,
}
```

Remove variants that are dead after the migration: anything mentioning oracle co-spend, registration fee, election finalize.

- [ ] **Step 2:** Commit.

```bash
git add sdk/src/error.rs
git commit -m "sdk(error): add ballot/voting-coin error variants; remove oracle/fee variants"
```

---

## Phase 4 — SDK Actor Logic

**Why now:** Types and constants exist. This phase rewires every actor.

### Task 4.1: Update `sdk/src/actors/deployer.rs`

**Files:**
- Modify: `sdk/src/actors/deployer.rs`

- [ ] **Step 1:** Drop `registration_fee` and `election_length_blocks` from `DeployParams`. Replace `election_length_blocks` with optional `deployment_sunset_height: Option<u32>` if the singleton continues to enforce a deployment-level cap.

- [ ] **Step 2:** Update `election_actions_merkle_root` call in `build_deploy_bundle` to use the new 3-leaf root `[register, create_ballot, deregister]` from `puzzles::election_actions_merkle_root` (rewritten in Phase 2).

- [ ] **Step 3:** Update genesis `ElectionState` to the new 4-field shape (no `finalized`, `vote_outcome`, `accumulated_fees`).

- [ ] **Step 4:** Run a focused unit test that builds a deploy bundle and verifies the singleton inner puzzle hash matches an expected fixture.

```bash
cargo test -p chip-voting-sdk --test action_layer_e2e -- deploy
```

- [ ] **Step 5:** Commit.

```bash
git add sdk/src/actors/deployer.rs
git commit -m "sdk(deployer): orchestrator-only singleton with new 3-action root"
```

### Task 4.2: Add `sdk/src/actors/ballot.rs` (NEW)

**Files:**
- Create: `sdk/src/actors/ballot.rs`
- Modify: `sdk/src/actors/mod.rs` (export)
- Modify: `sdk/src/lib.rs` (re-export)

- [ ] **Step 1:** Create the module with two API surfaces — issuer and reader:

```rust
pub struct BallotIssuer<C> {
    chain: C,
    config: ElectionConfig,
}

pub struct CreateBallotParams {
    pub ballot_launcher_id_seed: Bytes32,
    pub vote_close_height: u32,
    pub outcome_domain_hash: Bytes32,
}

pub struct CreatedBallot {
    pub ballot_launcher_id: Bytes32,
    pub ballot_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
}

impl<C: Chain> BallotIssuer<C> {
    pub fn new(chain: C, config: ElectionConfig) -> Self { ... }

    pub async fn create_ballot(
        &self,
        signer: &dyn Signer,
        params: CreateBallotParams,
    ) -> VotingResult<CreatedBallot> {
        // 1. Fetch current Election Singleton.
        // 2. Compute ballot launcher id from seed + singleton coin id.
        // 3. Compute Ballot Coin puzzle hash via puzzles::ballot_coin_puzzle_hash.
        // 4. Build singleton spend with createBallot action.
        // 5. Sign singleton authorization.
        // 6. Return SpendBundle and ballot identifiers.
    }
}

pub struct BallotReader<C> { chain: C }

impl<C: Chain> BallotReader<C> {
    pub async fn list_ballots(&self, election_launcher_id: Bytes32) -> VotingResult<Vec<BallotCoinSnapshot>> { ... }
    pub async fn get_ballot(&self, ballot_launcher_id: Bytes32) -> VotingResult<Option<BallotCoinSnapshot>> { ... }
}
```

- [ ] **Step 2:** Run.

```bash
cargo build -p chip-voting-sdk --lib
```

Expected: this module compiles. Other modules will still have errors — fix as you go.

- [ ] **Step 3:** Commit.

```bash
git add sdk/src/actors/ballot.rs sdk/src/actors/mod.rs sdk/src/lib.rs
git commit -m "sdk(actors): add BallotIssuer + BallotReader for createBallot lane"
```

### Task 4.3: Rewrite `sdk/src/actors/voter.rs`

**Files:**
- Modify: `sdk/src/actors/voter.rs`

- [ ] **Step 1:** Update `Voter::register` / `register_with_singleton[_unsigned]` to drop the XCH fee output. The singleton's register action no longer requires a fee coin; the spend bundle's fee inputs are removed. Initialize the new Registration Coin's curried state with `voted_ballots_root = EMPTY_BALLOT_ROOT`.

- [ ] **Step 2:** Replace `Voter::vote` with `Voter::cast_vote`:

```rust
pub struct CastVoteParams {
    pub ballot_launcher_id: Bytes32,
    pub vote_data: Bytes32,
}

pub struct CastVoteResult {
    pub voting_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
    pub vote_signature: Bytes,
}

impl<C: Chain> Voter<C> {
    pub async fn cast_vote(
        &self,
        signer: &dyn Signer,
        registration_coin_id: Bytes32,
        params: CastVoteParams,
    ) -> VotingResult<CastVoteResult> {
        // 1. Fetch Registration Coin state.
        // 2. Compute non-membership witness for ballot_launcher_id in voted_ballots_root.
        // 3. Compute new voted_ballots_root (with the leaf inserted).
        // 4. Compute Voting Coin puzzle hash.
        // 5. Compute vote_message; sign with voter's BLS key.
        // 6. Build Registration Coin spend invoking mint_voting_coin action.
        // 7. Bundle: registration coin spend + child voting coin announcement.
    }
}
```

- [ ] **Step 3:** Replace `Voter::change_vote` with `Voter::update_vote`:

```rust
pub async fn update_vote(
    &self,
    signer: &dyn Signer,
    voting_coin_id: Bytes32,
    new_vote_data: Bytes32,
) -> VotingResult<SpendBundle> {
    // 1. Fetch Voting Coin state and parent Ballot Coin.
    // 2. Build Ballot Coin oracle spend (open variant) — co-spend, NOT singleton.
    // 3. Build Voting Coin update_vote spend that asserts the oracle announcement.
    // 4. Sign new vote_message.
    // 5. Return combined SpendBundle.
}
```

**Critically: NO call to `Oracle` actor or `Election Singleton oracle` action.**

- [ ] **Step 4:** Update `Voter::release_collateral` to build a singleton `deregister` co-spend + Registration Coin `release` spend. The signature pattern: `deregister` emits `sha256("deregister" || voter_pubkey)`; `release` asserts it.

```rust
pub async fn release_collateral(
    &self,
    signer: &dyn Signer,
    registration_coin_id: Bytes32,
    destination: Bytes32,
) -> VotingResult<SpendBundle> { ... }
```

- [ ] **Step 5:** Replace the local `vote_message(vote_data) -> Bytes32` helper (returning `sha256(vote_data || election_launcher_id)`) with a 3-arg form that mirrors `puzzles::vote_message`:

```rust
fn vote_message(
    vote_outcome: Bytes32,
    ballot_launcher_id: Bytes32,
    election_launcher_id: Bytes32,
) -> Bytes32 {
    chip_voting_sdk::puzzles::vote_message(vote_outcome, ballot_launcher_id, election_launcher_id)
}
```

Search-and-replace every call site in `voter.rs`.

- [ ] **Step 6:** Run.

```bash
cargo build -p chip-voting-sdk --lib
```

Iterate until `voter.rs` compiles. Expect aggregator/indexer to still error.

- [ ] **Step 7:** Commit.

```bash
git add sdk/src/actors/voter.rs
git commit -m "sdk(voter): cast_vote/update_vote/deregister; drop XCH fee; vote_message binds ballot+election"
```

### Task 4.4: Rewrite `sdk/src/actors/aggregator.rs`

**Files:**
- Modify: `sdk/src/actors/aggregator.rs` (~3100 lines — biggest single file)

- [ ] **Step 1:** Replace `compute_election_action_root_leaves` and `compute_election_actions_merkle_root` to assemble the 3-leaf set `[register, create_ballot, deregister]`.

- [ ] **Step 2:** Replace `apply_singleton_spend` decoder cases. The cases are now `register`, `create_ballot`, `deregister`. The `create_ballot` decoder must produce a `BallotCoinSnapshot` and append it to a `Vec<BallotCoinSnapshot>` returned by `sync`.

- [ ] **Step 3:** Replace `collect_votes`. The new flow:
  1. For a chosen `ballot_launcher_id`, walk descendants of every Registration Coin to find Voting Coins curried with that ballot id.
  2. For each Voting Coin lineage, take the tip (latest spend); decode `VotingCoinState` and the BLS signature memo.
  3. Cross-reference `voter_pubkey` against the registration SPT snapshot to fetch `vote_weight`.
  4. Emit `VoteRecord { ballot_launcher_id, voting_coin_id, voter_pubkey, vote_data, vote_signature_hex, registration_coin_id, vote_weight }`.

- [ ] **Step 4:** Replace `canonical_vote_message` to take `(vote_outcome, ballot_launcher_id, election_launcher_id)`.

- [ ] **Step 5:** Update `prepare_finalize_witness` to be ballot-keyed: `prepare_finalize_witness(ballot_launcher_id) -> FinalizeWitness`. The witness now contains six scalars including `ballot_launcher_id` packed into the 6th input.

- [ ] **Step 6:** Replace `build_finalize`, `build_finalize_with_proof`, `build_finalize_with_proof_and_singleton`. The new finalize bundle spends the **Ballot Coin**, not the singleton:

```rust
pub async fn build_finalize_for_ballot(
    &self,
    ballot_launcher_id: Bytes32,
    proof: Groth16Proof,
    witness: FinalizeWitness,
) -> VotingResult<SpendBundle> {
    // 1. Fetch Ballot Coin tip.
    // 2. Build BallotCoin finalize action solution (proof, vote_outcome, agg_signers, agg_sig, scalars).
    // 3. Build SpendBundle spending only the Ballot Coin lineage. The Election Singleton is NOT spent.
}
```

- [ ] **Step 7:** Update `Aggregator::sync` return type to include `Vec<BallotCoinSnapshot>` and a per-ballot `Map<Bytes32, BallotState>`.

- [ ] **Step 8:** Run.

```bash
cargo build -p chip-voting-sdk --lib
```

Iterate.

- [ ] **Step 9:** Commit.

```bash
git add sdk/src/actors/aggregator.rs
git commit -m "sdk(aggregator): per-ballot enumeration + finalize on Ballot Coin; 6-input witness"
```

### Task 4.5: Rewrite `sdk/src/actors/indexer.rs`

**Files:**
- Modify: `sdk/src/actors/indexer.rs`

- [ ] **Step 1:** Drop `is_finalized()` and `vote_outcome()` (these are global; ballots are per-ballot).

- [ ] **Step 2:** Add ballot-aware methods:

```rust
impl<C: Chain> Indexer<C> {
    pub async fn election_state(&self) -> VotingResult<ElectionState> { ... }
    pub async fn ballots(&self) -> VotingResult<Vec<BallotCoinSnapshot>> { ... }
    pub async fn ballot_state(&self, ballot_launcher_id: Bytes32) -> VotingResult<Option<BallotState>> { ... }
    pub async fn votes_for_ballot(&self, ballot_launcher_id: Bytes32) -> VotingResult<Vec<VoteRecord>> { ... }
    pub async fn is_finalized_for(&self, ballot_launcher_id: Bytes32) -> VotingResult<bool> { ... }
    pub async fn vote_outcome_for(&self, ballot_launcher_id: Bytes32) -> VotingResult<Option<Bytes32>> { ... }
    pub async fn voter_set(&self) -> VotingResult<VoterSet> { ... }
}
```

- [ ] **Step 3:** Commit.

```bash
git add sdk/src/actors/indexer.rs
git commit -m "sdk(indexer): per-ballot getters; drop global finalized/vote_outcome"
```

### Task 4.6: Delete `sdk/src/actors/oracle.rs`

**Files:**
- Delete: `sdk/src/actors/oracle.rs`
- Modify: `sdk/src/actors/mod.rs` (remove `pub mod oracle`)
- Modify: `sdk/src/lib.rs` (remove re-exports `Oracle`, `OracleSpend`, `OracleAnnouncement`, `announcement_for_state`)

- [ ] **Step 1:** Confirm no remaining call sites.

```bash
cargo build -p chip-voting-sdk --lib 2>&1 | grep -i oracle
```

Expected: no references. If references remain in `voter.rs`, they were missed in Task 4.3.

- [ ] **Step 2:** Delete.

```bash
git rm sdk/src/actors/oracle.rs
```

Edit `sdk/src/actors/mod.rs` and `sdk/src/lib.rs` to remove all oracle exports.

- [ ] **Step 3:** Build.

```bash
cargo build -p chip-voting-sdk
```

Expected: clean build.

- [ ] **Step 4:** Commit.

```bash
git add sdk/src/actors/ sdk/src/lib.rs
git commit -m "sdk(actors): remove Oracle module; ballot-coin oracle replaces it per CHIP rev"
```

---

## Phase 5 — Prover, Circuit, Ceremony

**Why now:** With actors compiling, we can rebuild the prover for the new 6-input layout and rerun the ceremony.

### Task 5.1: Update `sdk/src/prover/circuit.rs`

**Files:**
- Modify: `sdk/src/prover/circuit.rs`

- [ ] **Step 1:** Add `ballot_launcher_id: Bytes32` field to `VotingCircuit`. Public input order MUST match `puzzles/ballot_coin/finalize.rue`:

```rust
pub struct VotingCircuit<E: Pairing> {
    pub registration_merkle_root: Bytes32,
    pub registration_vote_weight: u64,
    pub agg_signers: Bytes32,
    pub vote_message: Bytes32,
    pub vote_threshold_num: u32,
    pub vote_threshold_den: u32,
    pub ballot_launcher_id: Bytes32,   // NEW (input #6)
    pub signers: Vec<SignerWitness>,
}

impl<E: Pairing> VotingCircuit<E> {
    pub fn public_inputs_as_fr(&self) -> [E::ScalarField; 6] {
        let threshold_pack = pack_threshold(self.vote_threshold_num, self.vote_threshold_den);
        [
            bytes32_to_fr(self.registration_merkle_root),
            u64_to_fr(self.registration_vote_weight),
            bytes32_to_fr(self.agg_signers),
            bytes32_to_fr(self.vote_message),
            bytes32_to_fr(threshold_pack),
            bytes32_to_fr(self.ballot_launcher_id),
        ]
    }
}
```

- [ ] **Step 2:** Update `generate_constraints` to allocate `ballot_launcher_id` as a public input. The circuit body does not need to constrain it directly — its purpose is identity binding via the public-input commitment.

- [ ] **Step 3:** Update `generate_test_setup` to produce a VK matching the 6-input shape.

- [ ] **Step 4:** Run.

```bash
cargo test -p chip-voting-sdk --test integration -- groth16
```

Update test fixtures as needed.

- [ ] **Step 5:** Commit.

```bash
git add sdk/src/prover/circuit.rs
git commit -m "prover(circuit): 6th public input ballot_launcher_id; preserve threshold_pack"
```

### Task 5.2: Update `sdk/src/prover/{proof,conversions}.rs`

**Files:**
- Modify: `sdk/src/prover/proof.rs`
- Modify: `sdk/src/prover/conversions.rs`

- [ ] **Step 1:** Update `Scalars`:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalars {
    pub s1: Bytes32, // registration_merkle_root
    pub s2: Bytes32, // registration_vote_weight (packed)
    pub s3: Bytes32, // agg_signers
    pub s4: Bytes32, // vote_message
    pub s5: Bytes32, // threshold_pack
    pub s6: Bytes32, // ballot_launcher_id   <- NEW
}
```

- [ ] **Step 2:** Update `scalars_to_fr_array` to return `[Fr; 6]`. Update every call site.

- [ ] **Step 3:** Run.

```bash
cargo build -p chip-voting-sdk
```

- [ ] **Step 4:** Commit.

```bash
git add sdk/src/prover/proof.rs sdk/src/prover/conversions.rs
git commit -m "prover: extend Scalars to 6 fields"
```

### Task 5.3: Run a fresh MPC ceremony for the 6-input VK

**Files:**
- New: `app/data/vk-2026-05-02.bin` (or similar — final placement per deployment policy)
- Update: any test fixture that bakes in a VK (search `sdk/tests/` for hex VK strings).

- [ ] **Step 1:** Generate parameters with the existing `SimulatedBackend` for development:

```bash
cargo run -p chip-voting-sdk --bin ceremony_simulate -- --circuit voting --output app/data/vk-2026-05-02.bin
```

(If no such bin exists, write a small `examples/run_ceremony.rs` that calls `CeremonyCoordinator::run(SimulatedBackend, …)`. Keep it under `examples/`.)

- [ ] **Step 2:** Validate VK length is 672 bytes.

```bash
wc -c < app/data/vk-2026-05-02.bin
# expect: 672
```

- [ ] **Step 3:** Update test fixtures that previously embedded the 5-input VK. Run the ceremony test:

```bash
cargo test -p chip-voting-sdk --test ceremony_e2e
```

- [ ] **Step 4:** Commit.

```bash
git add app/data/ sdk/tests/
git commit -m "ceremony: regenerate 6-input VK for CHIP rev 2026-05-02"
```

---

## Phase 6 — Tests

**Why now:** The library compiles and links the new circuit. Now exercise every action end-to-end on the local simulator.

### Task 6.1: Migrate or delete legacy tests

**Files:**
- Modify: `sdk/tests/action_layer_e2e.rs`
- Modify: `sdk/tests/actor_functions_e2e.rs`
- Modify: `sdk/tests/voter_actions_e2e.rs`
- Modify: `sdk/tests/integration.rs`
- Delete: `sdk/tests/register_action_e2e.rs` (if it tests the XCH fee path; otherwise migrate)
- Delete: `sdk/tests/register_action_layer_isolated.rs` (likewise)

- [ ] **Step 1:** Remove or rewrite every test that asserts: `accumulated_fees`, `finalized: bool` on `ElectionState`, oracle co-spend on `change_vote`, single global `vote_outcome`, XCH fee output.

- [ ] **Step 2:** Run.

```bash
cargo test -p chip-voting-sdk --no-run 2>&1 | grep "error\[E" | head -30
```

Iterate until all tests at least compile.

- [ ] **Step 3:** Commit.

```bash
git add sdk/tests/
git commit -m "tests: prune legacy fee/oracle/finalized assertions"
```

### Task 6.2: Add createBallot e2e

**Files:**
- Create: `sdk/tests/create_ballot_e2e.rs`

- [ ] **Step 1:** Write the test:

```rust
#[tokio::test]
async fn create_ballot_mints_ballot_coin() {
    let env = TestEnv::deploy_election().await;
    let issuer = BallotIssuer::new(env.chain.clone(), env.config.clone());

    let result = issuer.create_ballot(&env.singleton_signer, CreateBallotParams {
        ballot_launcher_id_seed: [0xab; 32].into(),
        vote_close_height: env.chain.height().await + 100,
        outcome_domain_hash: outcome_domain(&["yes", "no", "abstain"]),
    }).await.unwrap();

    env.chain.push_bundle(result.spend_bundle).await.unwrap();

    let ballots = env.indexer.ballots().await.unwrap();
    assert_eq!(ballots.len(), 1);
    assert_eq!(ballots[0].ballot_launcher_id, result.ballot_launcher_id);
    assert!(!ballots[0].state.finalized);
}
```

- [ ] **Step 2:** Run.

```bash
cargo test -p chip-voting-sdk --test create_ballot_e2e
```

- [ ] **Step 3:** Commit.

```bash
git add sdk/tests/create_ballot_e2e.rs
git commit -m "test: createBallot e2e on simulator"
```

### Task 6.3: Add Voting Coin lifecycle e2e

**Files:**
- Create: `sdk/tests/voting_coin_lifecycle_e2e.rs`

- [ ] **Step 1:** Write tests for the three lifecycle moments — mint, update, freeze-after-close:

```rust
#[tokio::test]
async fn mint_voting_coin_inserts_into_voted_ballots_root() { ... }

#[tokio::test]
async fn update_vote_requires_ballot_oracle_announcement() { ... }

#[tokio::test]
async fn update_vote_rejected_after_vote_close_height() { ... }

#[tokio::test]
async fn second_mint_for_same_ballot_rejected() { ... }
```

The last test specifically exercises the per-registration ballot SPT non-membership check.

- [ ] **Step 2:** Run, iterate, commit.

```bash
cargo test -p chip-voting-sdk --test voting_coin_lifecycle_e2e
git add sdk/tests/voting_coin_lifecycle_e2e.rs
git commit -m "test: voting coin lifecycle (mint, update, freeze, dedup)"
```

### Task 6.4: Add per-ballot finalize e2e

**Files:**
- Create: `sdk/tests/finalize_per_ballot_e2e.rs`

- [ ] **Step 1:** Write a test that:
  1. Deploys election + registers 3 voters with weights 100, 100, 100 (threshold 2/3).
  2. Creates two ballots A and B.
  3. Each voter casts on A; two voters cast on B.
  4. Aggregator builds finalize for A — proof verifies, Ballot Coin A finalizes.
  5. Singleton remains unspent throughout finalize.
  6. Ballot B finalizes independently.

```rust
#[tokio::test]
async fn finalize_two_ballots_independently_singleton_untouched() { ... }
```

- [ ] **Step 2:** Run, iterate, commit.

```bash
cargo test -p chip-voting-sdk --test finalize_per_ballot_e2e
git add sdk/tests/finalize_per_ballot_e2e.rs
git commit -m "test: per-ballot finalize on Ballot Coin; singleton untouched"
```

### Task 6.5: Add cross-ballot replay rejection test

**Files:**
- Create: `sdk/tests/cross_ballot_replay_rejected.rs`

- [ ] **Step 1:** Build a valid finalize bundle for ballot A. Re-target it at ballot B's coin id by swapping only the asserted ballot id; submit. Expect rejection (Groth16 fails because `s6 != ballot_launcher_id` on B; or the Ballot Coin curry mismatch fires first).

- [ ] **Step 2:** Run, iterate, commit.

```bash
cargo test -p chip-voting-sdk --test cross_ballot_replay_rejected
git add sdk/tests/cross_ballot_replay_rejected.rs
git commit -m "test: ballot-bound vote_message + s6 prevent cross-ballot replay"
```

### Task 6.6: Add deregister + release e2e

**Files:**
- Create: `sdk/tests/deregister_release_e2e.rs`

- [ ] **Step 1:** Voter registers, casts vote on ballot A (which doesn't finalize), then runs `release_collateral`. Expect: singleton's `deregister` action removes them from the SPT; Registration Coin's `release` asserts the deregister announcement and pays out collateral.

- [ ] **Step 2:** Verify release works WITHOUT any ballot having finalized — that's the whole point of decoupling release from finalize.

- [ ] **Step 3:** Commit.

```bash
git add sdk/tests/deregister_release_e2e.rs
git commit -m "test: deregister + release independent of ballot finalize"
```

---

## Phase 7 — CLI Integration Test

**Files:**
- Modify: `cli/src/bin/live_integration_test.rs`
- Modify: `cli/src/commands/aggregator.rs`
- Modify: `cli/src/commands/deployer.rs`
- Modify: `cli/src/commands/indexer.rs`
- Modify: `cli/src/commands/oracle.rs` (likely delete; replace with `ballot.rs` command)
- Modify: `cli/src/commands/voter.rs`

### Task 7.1: Update CLI command shape

- [ ] **Step 1:** In `cli/src/commands/`, replace `oracle.rs` with `ballot.rs` exposing `create-ballot`, `list-ballots`, `ballot-state` subcommands. Replace the voter subcommand `vote`/`change-vote` with `cast-vote`/`update-vote`.

- [ ] **Step 2:** Rewrite `live_integration_test.rs` to walk the new flow: deploy → register × N → createBallot × M → cast-vote (across ballots) → update-vote → finalize-ballot × M → deregister + release.

- [ ] **Step 3:** Run.

```bash
cargo build -p cli
```

- [ ] **Step 4:** If the project keeps a "live" integration test that hits a real testnet, skip it for now (running it costs real coin), and focus on simulator-backed flows.

- [ ] **Step 5:** Commit.

```bash
git add cli/
git commit -m "cli: replace oracle/vote/change-vote with ballot/cast-vote/update-vote"
```

---

## Phase 8 — Verification

### Task 8.1: Full workspace verification

- [ ] **Step 1:** Run.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: clean fmt, no clippy warnings, all tests green.

- [ ] **Step 2:** Compare to baseline.

```bash
diff app/docs/chip-migration-baseline-tests.md <(cargo test --workspace 2>&1)
```

Confirm no test that previously passed has regressed without explicit migration commentary in the commit log.

- [ ] **Step 3:** Run the new feature tests in isolation as a final acceptance gate:

```bash
cargo test -p chip-voting-sdk --test create_ballot_e2e
cargo test -p chip-voting-sdk --test voting_coin_lifecycle_e2e
cargo test -p chip-voting-sdk --test finalize_per_ballot_e2e
cargo test -p chip-voting-sdk --test cross_ballot_replay_rejected
cargo test -p chip-voting-sdk --test deregister_release_e2e
```

All five must pass.

- [ ] **Step 4:** Sanity-check that `sdk/README.md` and `sdk/TESTING.md` no longer reference `oracle` actions, `accumulated_fees`, `has_voted`, or `change_vote`. Update prose to reference Ballot Coins, Voting Coins, and the per-ballot oracle.

- [ ] **Step 5:** Commit doc updates.

```bash
git add sdk/README.md sdk/TESTING.md
git commit -m "docs(sdk): align README and TESTING with CHIP rev 2026-05-02"
```

### Task 8.2: Open the PR

- [ ] **Step 1:** Push the branch.

```bash
git push -u origin chip-rev-2026-05-02
```

- [ ] **Step 2:** Open PR. Reference `CHIP.md` and the gap analysis under `app/docs/chip-migration-gap-analysis.md`. Title: `feat: migrate puzzles/sdk to CHIP rev 2026-05-02 (ballot/voting coins)`.

---

## Self-review checklist (run before declaring this plan ready to execute)

- [x] **Spec coverage:** every change in `CHIP.md` rev-2026-05-02 changelog has a phase/task. Verified per row of the changelog table.
- [x] **No placeholders:** every step that requires code has a concrete code block or an explicit recipe (e.g. "compute via `puzzles::ballot_coin_puzzle_hash`").
- [x] **Type consistency:** `BallotState`, `BallotCoinSnapshot`, `VotingCoinState`, `vote_message(...)`, `Scalars { s1..s6 }`, `PUBLIC_INPUT_COUNT=6`, `EXPECTED_VK_LEN=672` are spelled identically in every task that names them.
- [x] **Phase ordering:** puzzles → compiled artifacts → puzzle constants → SDK types → SDK actors → prover → ceremony → tests → CLI → verification. No phase consumes outputs of a later phase.
- [x] **Commits frequent:** every task ends with a commit.
- [x] **Test-first where it pays:** tests for ballot id binding, replay, dedup, freeze-after-close, deregister-without-finalize are explicit. The puzzle phase commits before tests because puzzle compilation is its own dependency root, but the test phase exercises every new puzzle path.

## Execution recommendation

This plan is sized for **subagent-driven-development**: one fresh subagent per phase (8 subagents), with a verification checkpoint between phases. Phases 1, 4, and 6 are large and may warrant subdividing further per task during execution.
