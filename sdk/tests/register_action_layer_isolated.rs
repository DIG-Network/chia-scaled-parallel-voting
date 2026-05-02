// ============================================================================
// tests/register_action_layer_isolated.rs — Voter::register's action layer in isolation
// ============================================================================
//
// SCOPE: extracts the EXACT action-layer + register-action puzzle+solution
// that Voter::register builds, places a coin at the action-layer puzzle
// hash directly (NO singleton outer wrap), and submits to the simulator.
//
// PURPOSE: pinpoint whether the live mainnet `clvm raise` is from
//   * the inner action layer / register action (this test would fail), or
//   * the singleton outer wrap (this test would PASS).
//
// HISTORICAL: the live test surfaced a curry-tree-hash bug in
// `puzzles::curry_tree_hash` (was wrapping `Vec<TreeHash>` as a CLVM
// list instead of the curry envelope). After fixing that, the live
// test STILL fails — this test is the next bisection step.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes, Bytes32, Coin};
use chia_puzzle_types::{EveProof, Proof};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chip_voting_sdk::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_election_finalizer_full,
    build_singleton_spend, load_action_puzzle, ActionSpend,
};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::{EMPTY_LEAF_HASH, PUBLIC_INPUT_COUNT, TREE_DEPTH};
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams};
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};

/// WHAT: the EXACT action-layer-wrapped register-action spend
///       Voter::register builds, run as a STANDALONE coin
///       (no singleton outer). Drives the consensus runner and
///       reports the trap if any.
/// HOW:
///   1. Choose deterministic test inputs (election launcher_id,
///      voter pubkey, fake CAT parent coin id).
///   2. Build the election finalizer + the genesis ElectionState
///      cons tree — exactly the trailing-tail shape
///      `(root . (count . (fees . (finalized . vote_outcome))))`
///      with no NIL terminator (matches the on-chain Rue convention).
///   3. Build the action-layer puzzle (curry of action.rue with
///      finalizer + merkle_root + state).
///   4. Place a coin at its tree hash on the simulator.
///   5. Build the register action (curried with the same constants
///      the deployer's `election_register_action_hash` curries in).
///   6. Build the action-layer solution (selectors + proofs +
///      register's own solution).
///   7. ALSO build a fake "CAT parent" coin that emits the
///      `create_reg` announcement so the register action's
///      `AssertCoinAnnouncement` is satisfied. Coin spend has
///      a quoted-conditions puzzle.
///   8. Submit (action-layer-spend + cat-parent-spend) as a paired
///      bundle. Expect SUCCESS.
/// WHY: if this test PASSES, the bug must be in the singleton
///      outer wrap. If it FAILS, we've reproduced the bug at the
///      action layer level (which we can debug iteratively without
///      mainnet).
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (singleton merkle root no longer carries finalize/announce/oracle leaves; \
            register-action curry shape may also drop the registration_fee arg)"]
fn register_action_layer_executes_on_simulator_without_singleton() {
    let mut sim = Simulator::new();
    let (voter_sk, voter_pk) = common::test_voter(0xCAu8);
    let launcher_id = Bytes32::new([0xAB; 32]);
    let cat_tail_hash = Bytes32::new([0x77; 32]);
    let collateral_amount: u64 = 1_000;
    // CHIP rev 2026-05-02: registration_fee dropped from DeployParams; this
    // local is retained only to keep the legacy register-action curry shape
    // valid for compile (the test is `#[ignore]`-d below).
    let registration_fee: u64 = 0;

    // ── 1. Build the election finalizer ──────────────────────
    let mut ctx = SpendContext::new();
    let elect_finalizer = build_election_finalizer_full(&mut ctx, launcher_id).unwrap();

    // ── 2. Build the merkle root (mirror deployer's path) ────
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        // CHIP rev 2026-05-02: registration_fee + election_length_blocks dropped.
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params.clone());
    let merkle_root = deployer.election_actions_merkle_root(launcher_id);

    // ── 3. Genesis state CLVM (trailing-tail shape) ──────────
    let smt = SparseMerkleTree::new();
    let empty_root = smt.root();
    let state_value: (Bytes32, (u64, (u64, (u8, Bytes32)))) =
        (empty_root, (0u64, (0u64, (0u8, Bytes32::default()))));
    let state_node = state_value.to_clvm(&mut *ctx).unwrap();

    // ── 4. Build the action layer puzzle + insert coin ───────
    let action_layer_node =
        build_action_layer_puzzle(&mut ctx, elect_finalizer, merkle_root, state_node).unwrap();
    let action_layer_ph = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());
    // amount = 1 mojo so the singleton invariant of odd amount is
    // preserved (even though we're not actually wrapping with the
    // singleton outer here — the register action's recreation
    // assumes amount is the singleton's current amount).
    let coin = Coin::new(Bytes32::new([0xCC; 32]), action_layer_ph, 1);
    sim.insert_coin(coin);

    // ── 5. Build the register action (curried) ───────────────
    let register_program_node =
        load_action_puzzle(&mut ctx, puzzles::ELECTION_REGISTER_HEX).unwrap();
    let register_curried = CurriedProgram {
        program: register_program_node,
        args: clvm_curried_args!(
            TREE_DEPTH,
            Bytes32::new(EMPTY_LEAF_HASH),
            puzzles::PuzzleHashes::cat_outer(),
            cat_tail_hash,
            puzzles::PuzzleHashes::action_layer(),
            puzzles::PuzzleHashes::registration_finalizer(),
            puzzles::registration_actions_merkle_root(),
            collateral_amount,
            registration_fee,
            launcher_id
        ),
    }
    .to_clvm(&mut *ctx)
    .unwrap();

    // ── 6. Build a fake CAT parent that emits the announcement ──
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id);
    let create_reg_msg =
        compute_create_reg_msg(launcher_id, &voter_pk, reg_outer_ph, collateral_amount);
    // (q . ((60 create_reg_msg)))
    let condition: (u8, (Bytes32, ())) = (60u8, (create_reg_msg, ()));
    let conditions_list: ((u8, (Bytes32, ())), ()) = (condition, ());
    let announcer_puzzle: (u8, ((u8, (Bytes32, ())), ())) = (1u8, conditions_list);
    let announcer_node = announcer_puzzle.to_clvm(&mut *ctx).unwrap();
    let announcer_ph = Bytes32::new(tree_hash(&ctx, announcer_node).to_bytes());
    let announcer_coin = Coin::new(Bytes32::new([0xBB; 32]), announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_id = announcer_coin.coin_id();
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let announcer_spend =
        common::coin_spend_from_nodes(&ctx, announcer_coin, announcer_node, announcer_solution);

    // ── 7. Build the register action solution ────────────────
    // Per register.rue: (new_voter_pubkey, slot, siblings, ...cat_parent_coin_id)
    let slot = SparseMerkleTree::slot_for_pubkey(&voter_pk);
    let siblings: Vec<Bytes32> = smt.prove(slot);
    let voter_pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let register_solution_value: (Bytes, (u64, (Vec<Bytes32>, Bytes32))) =
        (voter_pk_bytes, (slot as u64, (siblings, announcer_id)));
    let register_solution = register_solution_value.to_clvm(&mut *ctx).unwrap();

    // ── 8. Wrap as ActionSpend, build action-layer solution ──
    let action_spends = vec![ActionSpend {
        puzzle: register_curried,
        solution: register_solution,
    }];
    // Election finalizer takes `..._my_solution: Any` — pass nil.
    let elect_finalizer_solution = ().to_clvm(&mut *ctx).unwrap();
    let action_layer_solution = build_action_layer_solution(
        &mut ctx,
        &election_action_root_leaves(&deployer, launcher_id, cat_tail_hash, &params),
        &action_spends,
        elect_finalizer_solution,
    )
    .unwrap();

    let register_spend =
        common::coin_spend_from_nodes(&ctx, coin, action_layer_node, action_layer_solution);

    // ── 9. Sign + bundle ─────────────────────────────────────
    // The register action emits `AggSigMe(voter_pk, registration_message)`
    // — the voter must sign that message augmented with the coin's id +
    // network agg_sig data.
    let registration_message = registration_message(launcher_id, &voter_pk);
    let sig = common::sign_aggsig_me(&voter_sk, registration_message, &coin);
    let bundle = common::make_bundle(vec![announcer_spend, register_spend], sig);

    sim.new_transaction(bundle).unwrap_or_else(|e| {
        panic!(
            "simulator must accept the action-layered register spend (no singleton wrap); got: {:?}",
            e
        );
    });
    assert!(
        sim.coin_state(coin.coin_id())
            .unwrap()
            .spent_height
            .is_some(),
        "action-layer coin must be spent"
    );
}

/// WHAT: same flow as above, but WRAPPED IN THE SINGLETON OUTER —
///       this is the EXACT shape `Voter::register` produces on
///       mainnet. If THIS test fails (and the action-layer-only
///       test above passes), the bug is isolated to the singleton
///       outer wrap path.
/// HOW:  build everything as in the action-layer-only test, then
///       wrap the inner spend with `build_singleton_spend` using a
///       synthetic eve lineage proof. Insert the SINGLETON-wrapped
///       coin (at the singleton outer puzzle hash). Submit.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (singleton merkle root no longer carries finalize/announce/oracle leaves)"]
fn register_action_layer_with_singleton_outer_executes_on_simulator() {
    let mut sim = Simulator::new();
    let (voter_sk, voter_pk) = common::test_voter(0xCAu8);
    let cat_tail_hash = Bytes32::new([0x77; 32]);
    let collateral_amount: u64 = 1_000;
    // CHIP rev 2026-05-02: registration_fee dropped from DeployParams; this
    // local is retained only to keep the legacy register-action curry shape
    // valid for compile (the test is `#[ignore]`-d below).
    let registration_fee: u64 = 0;

    // The launcher_id is the COIN ID of the launcher coin
    // (which is the parent of the eve singleton). We must
    // derive it from the funder + launcher amount so it matches
    // when consensus computes coin ids.
    let funder_id = Bytes32::new([0xFF; 32]);
    let launcher_coin = Coin::new(
        funder_id,
        Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH),
        1,
    );
    let launcher_id = launcher_coin.coin_id();

    let mut ctx = SpendContext::new();
    let elect_finalizer = build_election_finalizer_full(&mut ctx, launcher_id).unwrap();

    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        // CHIP rev 2026-05-02: registration_fee + election_length_blocks dropped.
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params.clone());
    let merkle_root = deployer.election_actions_merkle_root(launcher_id);

    let smt = SparseMerkleTree::new();
    let empty_root = smt.root();
    let state_value: (Bytes32, (u64, (u64, (u8, Bytes32)))) =
        (empty_root, (0u64, (0u64, (0u8, Bytes32::default()))));
    let state_node = state_value.to_clvm(&mut *ctx).unwrap();

    let action_layer_node =
        build_action_layer_puzzle(&mut ctx, elect_finalizer, merkle_root, state_node).unwrap();
    let inner_ph = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());

    // ── SINGLETON OUTER: place coin at singleton(launcher, inner_ph) ──
    let singleton_outer_ph = puzzles::election_singleton_puzzle_hash(launcher_id, inner_ph);
    sim.insert_coin(launcher_coin);

    // The eve singleton coin: parent = launcher_id, puzzle_hash =
    // singleton(launcher_id, inner_ph), amount = 1.
    let eve_coin = Coin::new(launcher_id, singleton_outer_ph, 1);
    sim.insert_coin(eve_coin);

    // Build the action-layer solution exactly as before.
    let register_program_node =
        load_action_puzzle(&mut ctx, puzzles::ELECTION_REGISTER_HEX).unwrap();
    let register_curried = CurriedProgram {
        program: register_program_node,
        args: clvm_curried_args!(
            TREE_DEPTH,
            Bytes32::new(EMPTY_LEAF_HASH),
            puzzles::PuzzleHashes::cat_outer(),
            cat_tail_hash,
            puzzles::PuzzleHashes::action_layer(),
            puzzles::PuzzleHashes::registration_finalizer(),
            puzzles::registration_actions_merkle_root(),
            collateral_amount,
            registration_fee,
            launcher_id
        ),
    }
    .to_clvm(&mut *ctx)
    .unwrap();

    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id);
    let create_reg_msg =
        compute_create_reg_msg(launcher_id, &voter_pk, reg_outer_ph, collateral_amount);
    let condition: (u8, (Bytes32, ())) = (60u8, (create_reg_msg, ()));
    let conditions_list: ((u8, (Bytes32, ())), ()) = (condition, ());
    let announcer_puzzle: (u8, ((u8, (Bytes32, ())), ())) = (1u8, conditions_list);
    let announcer_node = announcer_puzzle.to_clvm(&mut *ctx).unwrap();
    let announcer_ph = Bytes32::new(tree_hash(&ctx, announcer_node).to_bytes());
    let announcer_coin = Coin::new(Bytes32::new([0xBB; 32]), announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_id = announcer_coin.coin_id();
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let announcer_spend =
        common::coin_spend_from_nodes(&ctx, announcer_coin, announcer_node, announcer_solution);

    let slot = SparseMerkleTree::slot_for_pubkey(&voter_pk);
    let siblings: Vec<Bytes32> = smt.prove(slot);
    let voter_pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let register_solution_value: (Bytes, (u64, (Vec<Bytes32>, Bytes32))) =
        (voter_pk_bytes, (slot as u64, (siblings, announcer_id)));
    let register_solution = register_solution_value.to_clvm(&mut *ctx).unwrap();

    let action_spends = vec![ActionSpend {
        puzzle: register_curried,
        solution: register_solution,
    }];
    let elect_finalizer_solution = ().to_clvm(&mut *ctx).unwrap();
    let action_layer_solution = build_action_layer_solution(
        &mut ctx,
        &election_action_root_leaves(&deployer, launcher_id, cat_tail_hash, &params),
        &action_spends,
        elect_finalizer_solution,
    )
    .unwrap();

    // ── Wrap with the singleton outer ──
    let lineage_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funder_id,
        parent_amount: launcher_coin.amount,
    });
    let register_singleton_spend = build_singleton_spend(
        &mut ctx,
        eve_coin,
        launcher_id,
        action_layer_node,
        action_layer_solution,
        lineage_proof,
    )
    .unwrap();

    let registration_message = registration_message(launcher_id, &voter_pk);
    let sig = common::sign_aggsig_me(&voter_sk, registration_message, &eve_coin);
    let bundle = common::make_bundle(vec![announcer_spend, register_singleton_spend], sig);

    sim.new_transaction(bundle).unwrap_or_else(|e| {
        panic!(
            "simulator must accept the SINGLETON-WRAPPED register spend; got: {:?}",
            e
        );
    });
    assert!(
        sim.coin_state(eve_coin.coin_id())
            .unwrap()
            .spent_height
            .is_some(),
        "eve singleton coin must be spent"
    );
}

// ─── Helpers ───────────────────────────────────────────────────────

fn compute_create_reg_msg(
    election_launcher_id: Bytes32,
    voter_pk: &chia_bls::PublicKey,
    reg_outer_ph: Bytes32,
    amount: u64,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"create_reg");
    h.update(election_launcher_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(reg_outer_ph.as_ref());
    h.update(amount.to_be_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

fn registration_message(election_launcher_id: Bytes32, voter_pk: &chia_bls::PublicKey) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"register");
    h.update(voter_pk.to_bytes());
    h.update(election_launcher_id.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// Build the leaves used to construct the action-layer's MerkleTree
/// proof. Order MUST match what the deployer uses internally
/// (sorted by `hash_atom_b32` of each leaf).
fn election_action_root_leaves(
    deployer: &ElectionDeployer,
    launcher_id: Bytes32,
    _cat_tail_hash: Bytes32,
    _params: &DeployParams,
) -> Vec<Bytes32> {
    // Mirror the SDK's internal `election_action_root_leaves` from
    // voter.rs by using the deployer's PRIVATE per-action hash
    // computations through the public merkle_root path. We rebuild
    // the same leaf set from scratch here.
    use clvmr::Allocator;
    let mut a = Allocator::new();

    let load = |alloc: &mut Allocator, hex_str: &str| -> clvmr::NodePtr {
        let bytes = hex::decode(hex_str.trim().trim_start_matches("0x")).unwrap();
        chia_protocol::Program::from(bytes).to_clvm(alloc).unwrap()
    };

    // register
    let register_node = load(&mut a, puzzles::ELECTION_REGISTER_HEX);
    let register_curried = CurriedProgram {
        program: register_node,
        args: clvm_curried_args!(
            TREE_DEPTH,
            Bytes32::new(EMPTY_LEAF_HASH),
            puzzles::PuzzleHashes::cat_outer(),
            deployer.params.cat_tail_hash,
            puzzles::PuzzleHashes::action_layer(),
            puzzles::PuzzleHashes::registration_finalizer(),
            puzzles::registration_actions_merkle_root(),
            deployer.params.collateral_amount,
            // CHIP rev 2026-05-02: registration_fee dropped; placeholder.
            0u64,
            launcher_id
        ),
    }
    .to_clvm(&mut a)
    .unwrap();
    let register_leaf = Bytes32::new(tree_hash(&a, register_curried).to_bytes());

    // finalize — MUST use the same struct curry shape as the
    // spender (Aggregator::build_finalize_with_proof) and the
    // production leaf builders (compute_election_action_root_leaves
    // / election_action_root_leaves). See finalize.rue: VK and IC
    // are STRUCTS the puzzle accesses by field, not flat blobs.
    // CHIP rev 2026-05-02: ELECTION_FINALIZE_HEX removed; finalize moved to
    // the Ballot Coin. Use the new constant just to make this helper
    // compile — the assertion that the finalize_leaf appears in the
    // singleton's merkle root is no longer meaningful (the singleton no
    // longer hosts a finalize action), and the tests using this helper
    // are `#[ignore]`-d.
    let finalize_node = load(&mut a, puzzles::BALLOT_COIN_FINALIZE_HEX);
    let vk_bytes = &deployer.params.verification_key.raw_bytes;
    // Canonical chunked VK layout for the 6-input circuit:
    //   alpha_g1(48) || beta_g2(96) || gamma_g2(96) || delta_g2(96)
    //   || ic0..ic6 (7 * 48) = 672 bytes.
    // (Pre-CHIP-2026-05-02 this was 576 bytes / 5 ICs.)
    assert!(
        vk_bytes.len() >= 672,
        "finalize curry: vk too short to slice into VK + IC structs (got {})",
        vk_bytes.len(),
    );
    let vk_struct = (
        Bytes::new(vk_bytes[0..48].to_vec()),
        (
            Bytes::new(vk_bytes[48..144].to_vec()),
            (
                Bytes::new(vk_bytes[144..240].to_vec()),
                (Bytes::new(vk_bytes[240..336].to_vec()), ()),
            ),
        ),
    );
    let ic_struct = (
        Bytes::new(vk_bytes[336..384].to_vec()),
        (
            Bytes::new(vk_bytes[384..432].to_vec()),
            (
                Bytes::new(vk_bytes[432..480].to_vec()),
                (
                    Bytes::new(vk_bytes[480..528].to_vec()),
                    (
                        Bytes::new(vk_bytes[528..576].to_vec()),
                        (
                            Bytes::new(vk_bytes[576..624].to_vec()),
                            (Bytes::new(vk_bytes[624..672].to_vec()), ()),
                        ),
                    ),
                ),
            ),
        ),
    );
    let finalize_curried = CurriedProgram {
        program: finalize_node,
        args: clvm_curried_args!(
            vk_struct,
            ic_struct,
            // CHIP rev 2026-05-02: election_length_blocks dropped; placeholder.
            0u64,
            launcher_id
        ),
    }
    .to_clvm(&mut a)
    .unwrap();
    let finalize_leaf = Bytes32::new(tree_hash(&a, finalize_curried).to_bytes());

    // CHIP rev 2026-05-02: announce_finalization + oracle moved to the
    // Ballot Coin. Aliased so the helper compiles; tests using it are
    // `#[ignore]`-d.
    let announce_node = load(&mut a, puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX);
    let announce_leaf = Bytes32::new(tree_hash(&a, announce_node).to_bytes());

    let oracle_node = load(&mut a, puzzles::BALLOT_COIN_ORACLE_HEX);
    let oracle_leaf = Bytes32::new(tree_hash(&a, oracle_node).to_bytes());

    let mut leaves = vec![register_leaf, finalize_leaf, announce_leaf, oracle_leaf];
    leaves.sort_by(|x, y| {
        puzzles::hash_atom_b32(x)
            .as_ref()
            .cmp(puzzles::hash_atom_b32(y).as_ref())
    });
    leaves
}
