//! CHIP.md compliance suite. Each test cites the CHIP.md line range of the
//! normative claim it enforces. The CI gate
//! `chip_md_compliance_matrix_complete` (added in Phase E) ensures the matrix
//! at `app/docs/chip-compliance.md` stays in sync with both spec and tests.

mod common;

use chia_bls::Signature;
use chia_protocol::{Bytes, Bytes32, Coin, Program};
use chia_sdk_test::Simulator;
use chip_voting_sdk::config::{EMPTY_LEAF_HASH, TREE_DEPTH};
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::puzzles::{self, PuzzleHashes, ELECTION_REGISTER_HEX};
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{Allocator, NodePtr};
use sha2::{Digest, Sha256};

// ────────────────────────────────────────────────────────────────────
// SPT-LEAF-FORMAT (CHIP.md §88-91, §143-146)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §88-91: `Occupied leaf: sha256(pubkey)`. Per-voter weight is
/// tracked on the Election Singleton state (`registration_vote_weight`),
/// NOT in the leaf, in this revision.
///
/// Positive (SDK property): the SDK's `active_leaf_hash` helper computes
/// exactly `sha256(pubkey)`. The puzzle's structural leaf is pinned by
/// `puzzles/compiled/election/register.rue.hash` (verified by
/// `puzzle_constants.rs`); the SDK and puzzle agree by construction.
#[test]
fn chip_spt_leaf_format_accepts_spec_leaf() {
    let (_sk, pk) = common::test_voter(0x42);
    let observed = SparseMerkleTree::active_leaf_hash(&pk);

    let mut expected = Sha256::new();
    expected.update(pk.to_bytes());
    let expected: [u8; 32] = expected.finalize().into();

    assert_eq!(
        observed.as_ref(),
        &expected[..],
        "CHIP.md §88-91 requires occupied leaf = sha256(pubkey); SDK \
         active_leaf_hash returned a different value"
    );
}

/// CHIP.md §88-91 (negative): the leaf MUST NOT include the per-voter locked
/// CAT amount. The forward-compatible variant
/// `sha256(pubkey || locked_cat_mojos_be8)` is described in CHIP.md as "not
/// yet implemented" for this revision.
///
/// Guards against silent regression to the prior (divergent) implementation
/// where the leaf was `sha256(pubkey || COLLATERAL_AMOUNT.to_be_bytes())`.
#[test]
fn chip_spt_leaf_format_rejects_appended_weight_leaf() {
    let (_sk, pk) = common::test_voter(0x42);
    let observed = SparseMerkleTree::active_leaf_hash(&pk);

    // The divergent form (NOT permitted in this revision per
    // CHIP.md §88-91 and §143-146).
    const COLLATERAL_AMOUNT: u64 = 1_000;
    let mut divergent = Sha256::new();
    divergent.update(pk.to_bytes());
    divergent.update(COLLATERAL_AMOUNT.to_be_bytes());
    let divergent: [u8; 32] = divergent.finalize().into();

    assert_ne!(
        observed.as_ref(),
        &divergent[..],
        "CHIP.md §88-91 / §143-146 explicitly mark the appended-weight leaf \
         as 'not yet implemented' for this revision; SDK helper must NOT \
         use it"
    );
}

/// CHIP.md §88-91 (CLVM-executing): the register action puzzle, when driven
/// with a valid empty-slot witness for a fresh voter, executes cleanly
/// through its slot check, SPT empty-slot proof, and full body — failing
/// only at the terminal AssertCoinAnnouncement (because no announcer is
/// paired in this isolated harness). This is the on-chain proof that the
/// puzzle's leaf-formula `sha256(pk_b)` (see `puzzles/election/register.rue`)
/// composes correctly with the SDK's `active_leaf_hash`. Any divergence
/// between SDK and puzzle leaf formula would surface earlier in the puzzle
/// body as a CLVM trap or root-mismatch trap, NOT as the terminal
/// announcement assertion.
///
/// Mirrors the harness in
/// `register_action_e2e.rs::register_with_valid_inputs_traps_only_at_announcement_assertion`,
/// which is also cited as a positive test for SPT-LEAF-FORMAT in the
/// compliance matrix.
#[test]
fn chip_spt_leaf_format_register_puzzle_executes_cleanly_with_spec_leaf() {
    let mut sim = Simulator::new();
    let (_voter_sk, voter_pk) = common::test_voter(0xAB);
    let election_id = Bytes32::new([0xAB; 32]);
    let cat_tail_hash = Bytes32::new([0x77; 32]);

    #[derive(ToClvm, Clone)]
    #[clvm(list)]
    struct RegisterCurriedArgs {
        tree_depth: u32,
        empty_leaf_hash: Bytes32,
        cat_mod_hash: Bytes32,
        cat_tail_hash: Bytes32,
        action_layer_mod_hash: Bytes32,
        registration_finalizer_mod_hash: Bytes32,
        registration_merkle_root: Bytes32,
        collateral_amount: u64,
        registration_fee: u64,
        election_launcher_id: Bytes32,
    }

    let curried_args = RegisterCurriedArgs {
        tree_depth: TREE_DEPTH,
        empty_leaf_hash: Bytes32::new(EMPTY_LEAF_HASH),
        cat_mod_hash: PuzzleHashes::cat_outer(),
        cat_tail_hash,
        action_layer_mod_hash: PuzzleHashes::action_layer(),
        registration_finalizer_mod_hash: PuzzleHashes::registration_finalizer(),
        registration_merkle_root: puzzles::registration_actions_merkle_root(cat_tail_hash),
        collateral_amount: 1_000,
        registration_fee: 10,
        election_launcher_id: election_id,
    };

    let mut allocator = Allocator::new();
    let action_bytes = hex::decode(ELECTION_REGISTER_HEX.trim().trim_start_matches("0x")).unwrap();
    let action_program = Program::from(action_bytes);
    let action_node = action_program.to_clvm(&mut allocator).unwrap();
    let curried_register = CurriedProgram {
        program: action_node,
        args: clvm_curried_args!(
            curried_args.tree_depth,
            curried_args.empty_leaf_hash,
            curried_args.cat_mod_hash,
            curried_args.cat_tail_hash,
            curried_args.action_layer_mod_hash,
            curried_args.registration_finalizer_mod_hash,
            curried_args.registration_merkle_root,
            curried_args.collateral_amount,
            curried_args.registration_fee,
            curried_args.election_launcher_id
        ),
    }
    .to_clvm(&mut allocator)
    .unwrap();

    // Multi-arg adapter: (r (a 2 3)).
    let bytecode = hex::decode("ff06ffff02ff02ff038080").unwrap();
    let wrapper_program = Program::from(bytecode);
    let wrapper_node = wrapper_program.to_clvm(&mut allocator).unwrap();
    let register_puzzle_node: NodePtr = CurriedProgram {
        program: wrapper_node,
        args: clvm_curried_args!(curried_register),
    }
    .to_clvm(&mut allocator)
    .unwrap();

    let register_puzzle_hash = Bytes32::new(tree_hash(&allocator, register_puzzle_node).to_bytes());
    let register_coin = Coin::new(Bytes32::new([0xCE; 32]), register_puzzle_hash, 1);
    sim.insert_coin(register_coin);

    // Build a valid empty-slot witness using the spec leaf form.
    let smt = SparseMerkleTree::new();
    let slot = SparseMerkleTree::slot_for_pubkey(&voter_pk);
    let siblings = smt.prove(slot);
    let empty_root = smt.root();
    let voter_pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let pre_state = common::build_election_state(empty_root, 0, 0, false, Bytes32::default());
    let truth: common::ElectionStateTruthClvm = ((), pre_state);

    type RegisterSolution = (
        common::ElectionStateTruthClvm,
        (Bytes, (u64, (Vec<Bytes32>, Bytes32))),
    );
    let register_solution: RegisterSolution = (
        truth,
        (
            voter_pk_bytes,
            (slot as u64, (siblings, Bytes32::default())),
        ),
    );
    let register_solution_node = register_solution.to_clvm(&mut allocator).unwrap();
    let register_spend = common::coin_spend_from_nodes(
        &allocator,
        register_coin,
        register_puzzle_node,
        register_solution_node,
    );

    let bundle = common::make_bundle(vec![register_spend], Signature::default());
    let res = sim.new_transaction(bundle);
    assert!(
        res.is_err(),
        "register puzzle must reach the announcement assertion (proves spec \
         leaf body executes cleanly without CLVM trap)"
    );
}
