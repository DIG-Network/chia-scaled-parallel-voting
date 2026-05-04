# CHIP.md compliance worklist

> Auto-derived from [`chip-compliance.md`](./chip-compliance.md) at end of Phase A
> (audit pass). Drives Phases B (known-divergence revert), C (per-divergence
> reconciliation), and D (test-gap fills). Rows are repeated here for human
> review; the matrix is the machine-readable source.

## Divergences (implementation must change)

- **SPT-LEAF-FORMAT** (CHIP.md §88-89, 144): `Occupied leaf: ` `sha256(pubkey)`
  - Implementation: `sdk/src/merkle.rs:150` `active_leaf_hash` uses
    `sha256(pubkey || COLLATERAL_AMOUNT.to_be_bytes())`;
    `puzzles/election/register.rue:188-194` and
    `puzzles/election/deregister.rue:78-82` mirror with
    `sha256(pk_b + int_to_8_bytes_be(COLLATERAL_AMOUNT))`;
    callers in `sdk/src/actors/aggregator.rs:715,1278,1315` rebuild siblings
    with the divergent leaf formula.
  - Required change (Phase B):
    1. Replace `active_leaf_hash(pubkey, _collateral)` body with
       `sha256(pubkey)`; remove the `collateral_amount` parameter at every
       call site (compile errors will guide the sweep).
    2. In `register.rue` and `deregister.rue` change the leaf computation
       from `sha256(pk_b + int_to_8_bytes_be(COLLATERAL_AMOUNT))` to
       `sha256(pk_b)`. Recompile to hex; update
       `sdk/tests/puzzle_constants.rs` pinned hashes for `register.hash`
       and `deregister.hash`.
    3. Drop the `collateral_amount` field from `SparseMerkleTree` and the
       `with_collateral_amount` constructor — it's no longer needed for
       leaf reconstruction. (`empty_subtree` is collateral-independent.)
    4. Update existing e2e tests (`voter_register_full_flow.rs`,
       `register_action_e2e.rs`, `voter_cast_vote_e2e.rs`,
       `voter_revote_e2e.rs`, `voter_release_collateral_e2e.rs`,
       `finalize_per_ballot_e2e.rs`) — they should pass automatically
       once they call the corrected SDK helper, but local leaf-builders
       (if any) need their `int_to_8_bytes_be(COLLATERAL_AMOUNT)` arg
       removed.
    5. Add positive + negative `chip_spec_compliance.rs` tests pinning
       `sha256(pubkey)` accepted and `sha256(pubkey || locked_cat_mojos_be8)`
       rejected by `register.rue`. (Already drafted in the plan as Phase B
       Tasks B1, B6.)

## Test gaps (positive test must be added)

These rows have `impl_locus` filled and the implementation appears to match
spec, but no executing test in the current suite actively exercises the claim
(per the honesty rule: a passing test that does not pin the claim is not
coverage). Negative-test gaps are tracked separately under "Test gaps —
negative" below.

- **SPT-DEPTH** (CHIP.md §87, 142): `Fixed depth 32 (must match `TREE_DEPTH` in config and puzzles)`
  - Implementation locus: `sdk/src/config.rs:35`, `puzzles/election/register.rue` (curry), `puzzles/registration_coin/shared.rue::BALLOT_TREE_DEPTH`.
  - Note: `sdk/tests/integration.rs::tree_depth_constant_is_32` asserts the SDK constant equals 32 but does NOT exercise CLVM. A flavor-2 test should run `register.rue` with a witness whose siblings list has length != 32 and assert CLVM rejection (also covers the negative).
  - Test plan: CLVM-isolated `run_program` on `register.rue` curried with `TREE_DEPTH=32` and a 31-element siblings vector; expect trap. Mirror for `BALLOT_TREE_DEPTH` in `mint_voting_coin.rue`.

- **SPT-EMPTY-LEAF** (CHIP.md §90, 145): `EMPTY_LEAF_HASH = sha256(0x00 × 48)`
  - Implementation locus: `sdk/src/config.rs:62`, register/deregister `EMPTY_LEAF_HASH` curry.
  - Note: `sdk/src/config.rs::tests::empty_leaf_hash_is_sha256_of_48_zero_bytes` is a pure-SDK property test; no CLVM execution. Need a flavor-2 test.
  - Test plan: CLVM-isolated `run_program` on `register.rue` with `EMPTY_LEAF_HASH` curry set to a wrong value; build a valid empty-slot proof against the correct hash; expect CLVM root-mismatch trap.

- **SPT-INTERNAL-NODE-NO-PREFIX** (CHIP.md §146): `no `0x02` CLVM tree-hash prefix`
  - Implementation locus: `sdk/src/merkle.rs:329` (`sha256_concat`), `compute_root` in register/deregister/mint_voting_coin.
  - Test plan: Build a witness whose root was computed with a `0x02`-prefixed internal-node hash (the CLVM tree-hash variant). Run register; expect CLVM root-mismatch trap. Confirms the spec-pinned plain-sha256 internal node.

- **SPT-TRACKS-VOTERS** (CHIP.md §93): `The SPT tracks **eligible voters**, not vote choices`
  - Implementation locus: `SparseMerkleTree::leaves` is `BTreeMap<u32, [u8; 48]>`, register.rue inserts only pubkey-derived leaves.
  - Note: cited test (`voter_register_against_simulator_full_flow`) inserts pubkey leaves and reads them back — but does not prove "vote choices are not in this tree". Hard to write a focused positive — best treated as an architectural property covered indirectly. Flag as ARCHITECTURAL.
  - Test plan: assertion-style — assert that no on-chain action under `puzzles/election/` writes anything other than pubkey-derived leaves (could be a static-source test, e.g. grep-based). LOWER PRIORITY.

- **BALLOT-SPT-LEAF** (CHIP.md §95): `leaves are `sha256(ballot_launcher_id)``
  - Implementation locus: `mint_voting_coin.rue::compute_ballot_root`, `sdk/src/puzzles.rs:481-1525` (mirror).
  - Test plan: CLVM-isolated `run_program` on `mint_voting_coin.rue` with a ballot leaf computed as `sha256(ballot_launcher_id || 0x00)` (wrong); expect root-mismatch trap.

- **CIRCUIT-PUBLIC-INPUT-COUNT** (CHIP.md §97, 150): `extended in this revision to **6 scalars**`
  - Implementation locus: `sdk/src/config.rs:54`, `sdk/src/prover/proof.rs:132-150`, `puzzles/ballot_coin/finalize.rue:18-23`.
  - Test plan: build a proof with `[Fr; 5]` (drop s6); attempt to drive `finalize.rue`; expect either pre-flight rejection (`ElectionConfig::validate` already checks VK length) or in-puzzle trap.

- **CIRCUIT-INPUTS-ORDER** (CHIP.md §150): `This CHIP revision pins **6 public-input scalars**, in order`
  - Implementation locus: `proof.rs::Scalars` ordered fields s1..s6, `circuit.rs::public_inputs_as_fr`, `finalize.rue` s1..s6 doc and assertions.
  - Test plan: CLVM-isolated `run_program` on `finalize.rue` with permuted Scalars (e.g. swap s1 and s2); expect IC linear-comb assertion failure or pairing failure.

- **CIRCUIT-INPUT-{1..6}** (CHIP.md §152-157): six rows, one per scalar.
  - Implementation locus: `proof.rs::Scalars` per-field, `finalize.rue` s_i ← sha256(...) lines.
  - Test plan: pinned positive coverage exists indirectly through `finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow` IF that test passes (the design doc note states it currently does not pass against the simulator due to a Scalars canonical-encoding mismatch). Until that test is green, these rows have no flavor-1 positive coverage. Treat as deferred until Phase G — add focused flavor-2 tests if `finalize_per_ballot_e2e` is still red after Phase B-C. NEEDS DESIGN DECISION.

- **CIRCUIT-VK-LENGTH** (CHIP.md §159): `VK byte length is therefore fixed at `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 336 + 7 * 48 = 672` bytes for this revision.`
  - Implementation locus: `sdk/src/config.rs::validate` (asserts VK length).
  - Test plan: pure-SDK `ElectionConfig::validate` test with VK of length 671 / 673 — expect Err. Pair with flavor-2 `run_program` on `finalize.rue` with a truncated VK to confirm on-chain rejection.

- **CIRCUIT-IC-MATCH** (CHIP.md §150): `Ordering and IC layout MUST match the Ballot Coin's **`finalize.rue`** and `circuit.rs` for that deployment exactly`
  - Test plan: only `finalize_per_ballot_e2e` truly pins this. See note under CIRCUIT-INPUT-{1..6}.

- **VOTE-MSG-PREIMAGE** (CHIP.md §163): `This CHIP **pins** the preimage`
  - Implementation locus: `sdk/src/puzzles.rs::vote_message`, `finalize.rue:102-105`, `update_vote.rue`.
  - Test plan: pure-SDK property test asserting `vote_message(outcome, ballot_id, election_id) == sha256(outcome || ballot_id || election_id)`. Pair with flavor-2 `run_program` on `finalize.rue` with a wrong vote_message preimage; expect BLS verify failure.

- **VOTE-MSG-COMPONENTS-ORDER** (CHIP.md §174): `All three components MUST be present and concatenated in this exact order`
  - Test plan: same as VOTE-MSG-PREIMAGE; the negative is constructing a bundle with `sha256(ballot_id || outcome || election_id)` (permuted) and asserting CLVM rejection on `finalize.rue` (BLS verify against the canonical preimage will fail).

- **VOTE-MSG-AGREE** (CHIP.md §174): `Ballot Coin `finalize.rue`, Voting Coin `cast.rue` / `update.rue`, the off-chain aggregator, and the Groth16 circuit MUST all agree on this preimage`
  - Note: `finalize_per_ballot_e2e` is the existing simulator-level positive (when green). Until then, only individual call-site tests would pin this.
  - Test plan: per-callsite property test asserting each component computes the same preimage from the same inputs.

- **ELECTION-NO-FEE** (CHIP.md §191): `Implementations MUST NOT curry a `REGISTRATION_FEE` ...`
  - Implementation locus: confirmed absent in source (see comments in deployer.rs:24,304; voter.rs:391; aggregator.rs:1820,2521,2613).
  - Note: `voter_register_against_simulator_full_flow` exercises a register action with no fee — but it would still pass even if a `REGISTRATION_FEE` curry got reintroduced as long as the fee value were 0 mojos. Not active coverage.
  - Test plan: source-level (grep-based) test asserting no `REGISTRATION_FEE` / `accumulated_fees` identifier appears in `puzzles/election/` or `sdk/src/state.rs::ElectionState`. Pair with a CLVM-isolated `run_program` on `register.rue` whose curried args include a non-zero `registration_fee` — expect compile / curry-arity error. (LOWER PRIORITY: source-level grep is tactically equivalent.)

- **ELECTION-CHIP0050-DISPATCH** (CHIP.md §197): `Each action is dispatched through the standard CHIP-0050 **action-layer puzzle**`
  - Implementation locus: `deployer.rs` action-merkle-root construction; `action_spends.rs` action-layer wrap.
  - Note: `voter_register_against_simulator_full_flow` uses the action layer in flight, so a regression that broke the action-layer wrap would fail this test. Marginal positive coverage — but does not pin "CHIP-0050 standard" specifically. Acceptable as positive; mark `aligned` after Phase B/C.
  - Test plan: bind to CHIP-0050 by asserting the ACTION_LAYER_MOD_HASH is the canonical chia_puzzles constant. Source-level + simulator e2e.

- **ELECTION-NO-LEGACY-ACTIONS** (CHIP.md §205): `The legacy singleton actions ... MUST be omitted ...`
  - Implementation locus: `puzzles/election/` only contains `register.rue`, `create_ballot.rue`, `deregister.rue`, `finalizer.rue`, `shared.rue` — confirmed.
  - Note: `deployer_actions_merkle_root_is_deterministic` pins the merkle root over those three actions. A regression that re-added a fourth action would shift the root and break the test. Acceptable as positive; mark `aligned` after Phase B/C.
  - Test plan: source-level (file presence) test + the existing root determinism test.

- **ELECTION-REGISTER-ROLE** / **ELECTION-CREATEBALLOT-ROLE** / **ELECTION-DEREGISTER-ROLE** (CHIP.md §201-203):
  - Existing simulator e2e tests `voter_register_against_simulator_full_flow`, `launch_ballot_against_simulator_full_flow`, `voter_release_collateral_against_simulator_full_flow` actively pin these by exercising the full singleton action path. Acceptable; mark `aligned` after Phase B/C verifies they still pass against the post-revert puzzles.

- **BALLOT-COIN-STATE** (CHIP.md §215): `Ballot Coin state: `(finalized: bool, vote_outcome: Bytes32, agg_signers: Bytes32)``
  - Implementation locus: `state.rs:277-288`, `puzzles/ballot_coin/shared.rue:30-38`.
  - Note: `ballot_reader_lists_and_gets_after_create_ballot` reads `BallotState` fields, which would compile-fail if the struct shape drifted. Treat as positive; mark `aligned`.

- **BALLOT-FINALIZE-CURRY / BALLOT-ORACLE-CURRY / BALLOT-ANNOUNCE-CURRY** (CHIP.md §221-223):
  - Test plan: CLVM-isolated curry-shape tests — load the `.hex` artifact, curry the spec-listed args; assert resulting puzzle hash matches `puzzle_constants.rs` pinned hash. Pair with negative test using wrong arg count.

- **BALLOT-FINALIZE-ROLE / BALLOT-FINALIZE-RECREATE** (CHIP.md §233):
  - Test plan: covered by `finalize_per_ballot_full_simulator_flow` IF green. Until then, flavor-2 runs of `finalize.rue` with rigged inputs.

- **BALLOT-ORACLE-ROLE / BALLOT-ANNOUNCE-ROLE** (CHIP.md §234-235):
  - Test plan: covered indirectly by `voter_revote_e2e` (consumes oracle announcement) and `voter_cast_vote_e2e` (consumes oracle announcement). For `announce_finalization` specifically, no test exercises it post-finalize — gap. Add a focused simulator e2e: finalize → block N → another spend that asserts the re-announcement.

- **BALLOT-FINALIZE-SNAPSHOTS** (CHIP.md §221): `*_SNAPSHOT` curries
  - `launch_ballot_against_simulator_full_flow` captures snapshots and curries them into the Ballot Coin's finalize action — but it does not finalize, so the binding (snapshot vs. proof public input) is not actively pinned. Pair with a Phase D negative test that mints a finalize bundle whose proof was generated against a different `registration_merkle_root_snapshot`; expect CLVM trap.

- **REG-COIN-STATE / REG-COIN-NO-HAS-VOTED** (CHIP.md §258, 270): `RegistrationState` 4-field shape
  - Implementation locus: `state.rs:128-145`, `puzzles/registration_coin/shared.rue`.
  - Note: `voter_register_against_simulator_full_flow` constructs `RegistrationState::fresh` and round-trips it through CLVM. A regression that re-added `has_voted` or `vote_data` would change `clvm_tree_hash` and break the test. Treat as positive; mark `aligned`.

- **REG-MINT-VOTING-COIN-{LINEAGE,NONMEMBERSHIP,CURRY}** (CHIP.md §267):
  - `voter_cast_vote_against_simulator_full_flow` exercises the full mint pipeline. Active coverage; mark `aligned`.

- **REG-RELEASE-DEREGISTER / REG-RELEASE-NOT-FINALIZE / SEC-COLLATERAL-RELEASE** (CHIP.md §268, 325):
  - `voter_release_collateral_against_simulator_full_flow` exercises the deregister-gated release. Active coverage; mark `aligned`.

- **VOTING-COIN-STATE / VOTING-UPDATE-VOTE-{ORACLE,RECREATE} / VOTING-NO-SINGLETON / SEC-TIMING** (CHIP.md §276, 282, 327):
  - `voter_update_vote_against_simulator_full_flow` exercises a full update-vote with oracle co-spend, no singleton. Active coverage; mark `aligned`.

- **AGGREGATOR-LATEST-LINEAGE / FLOW-FINALIZE-NOT-SINGLETON / SEC-TWO-CHECK / SEC-NO-SINGLETON-DOS** (CHIP.md §284, 296, 319, 329):
  - `finalize_per_ballot_full_simulator_flow` is the canonical positive — but is currently red per design-doc note. Treated as deferred; revisit in Phase G.

- **FLOW-DEPLOY-GENESIS** (CHIP.md §291): genesis state shape
  - `deployer_genesis_inner_puzzle_hash_is_deterministic` pins the genesis state through its hash. Active coverage; mark `aligned`.

- **LINEAGE-THREE-LINK** (CHIP.md §83):
  - `voter_cast_vote_against_simulator_full_flow` walks the full chain Singleton → Registration Coin → Voting Coin (links a + c). `launch_ballot_against_simulator_full_flow` walks Singleton → Ballot Coin (link b). Together they cover all three; mark `aligned`.

- **SEC-BALLOT-AUTHENTICITY** (CHIP.md §315):
  - `voter_cast_vote_against_simulator_full_flow` binds `ballot_launcher_id` via oracle co-spend. Active coverage for the Voting-Coin side. The `finalize` side (asserting same launcher id) is deferred to `finalize_per_ballot_e2e` — see note above.

- **SEC-SINGLE-VOTE-PER-BALLOT** (CHIP.md §317):
  - `voter_cast_vote_against_simulator_full_flow` exercises non-membership + insert. Active coverage; mark `aligned`.
  - Add Phase D negative: attempt to mint a second Voting Coin for the same `ballot_launcher_id`; expect non-membership proof to fail.

- **SEC-THRESHOLD-PRESERVED** (CHIP.md §321):
  - The s5 scalar is asserted on-chain via `finalize.rue` (covered by `finalize_per_ballot_e2e`). Until that test is green, no positive coverage. Deferred.

## Test gaps — negative

Every row currently has `negative_test = MISSING`. Phase D produces them.

The negative-test gap for the divergent SPT-LEAF-FORMAT row is the negative
test pinned by Phase B (`chip_spt_leaf_format_rejects_appended_weight_leaf`).

For the remaining 57 rows, each MUST or MUST NOT row needs a CLVM-isolated
test that constructs a spec-violating input and asserts CLVM / simulator
rejection. Rows whose claim is purely structural ("This CHIP **pins** ...")
are not strictly MUST-form but still benefit from a negative — typically a
variant-encoding test. The Phase D template (in the plan document) iterates
this.

Negative-test gap entries are not enumerated individually here; Phase D
walks the matrix and emits one commit per row.
