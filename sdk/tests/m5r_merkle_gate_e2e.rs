// tests/m5r_merkle_gate_e2e.rs — focused isolation tests for the
// M5r-merkle Mode2Restricted gate in `puzzles/voting_coin/update_vote.rue`.
//
// SCOPE: bypass the full Voter pipeline (oracle co-spend, AggSigMe,
// CAT outer) by running the curried `update_vote` action puzzle
// directly through clvmr. Asserts:
//   * Mode1Free (vote_options_root = 0x00..00) — gate skips, puzzle
//     runs to completion regardless of (leaf_index, proof).
//   * Mode2Restricted with a VALID merkle proof — gate's
//     `assert derived_root == vote_options_root` succeeds; puzzle
//     emits the expected condition list (no raise).
//   * Mode2Restricted with a WRONG merkle proof — gate raises with
//     CLVM `path into atom` / clvm raise; we assert the failure.
//
// The puzzle still emits AssertCoinAnnouncement + AggSigMe + the
// recreate-VC condition list, but they execute without
// chain-state-aware validation in this isolated harness — we only
// care that the M5r-merkle assert fires (or doesn't) at the right
// time.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

use chia_protocol::{Bytes, Bytes32, Program};
use chia_sdk_driver::SpendContext;
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::CurriedProgram;
use clvmr::{run_program, Allocator, ChiaDialect};

/// Build the curried update_vote puzzle (no curry args) + a solution
/// with the given (vote_options_root, leaf_index, proof) tuple. Runs
/// the puzzle and returns Ok(()) on success or Err on raise.
fn run_update_vote(
    new_vote_data: Bytes32,
    vote_options_root: Bytes32,
    leaf_index: u64,
    proof_depth: u64,
    proof_siblings: Vec<Bytes32>,
) -> Result<(), String> {
    use chip_voting_sdk::action_spends::load_action_puzzle;
    use chip_voting_sdk::puzzles;

    let mut ctx = SpendContext::new();

    // update_vote takes NO curry args — load the bare puzzle.
    let prog_node = load_action_puzzle(&mut ctx, puzzles::VOTING_COIN_UPDATE_VOTE_HEX)
        .expect("load update_vote.rue");
    // No curry needed; cast as CurriedProgram with empty arg list to
    // match the call site that to_clvm's it.
    let curried = CurriedProgram {
        program: prog_node,
        args: clvm_curried_args!(),
    }
    .to_clvm(&mut *ctx)
    .expect("curry update_vote");

    // Truth: VotingCoinStateTruth = (Ephemeral_State, State).
    // State: VotingCoinState = (voter_pubkey, ballot_launcher_id,
    //                          vote_data, registration_coin_id).
    // Voter pubkey can be any 48-byte BLS-shaped Bytes (we won't
    // actually verify the AggSig in this isolated harness — clvmr
    // executes AGG_SIG_ME conditions but doesn't check the sig).
    let voter_pk_bytes = Bytes::new(vec![0u8; 48]);
    let ballot_launcher_id = Bytes32::new([0xBBu8; 32]);
    let registration_coin_id = Bytes32::new([0xCCu8; 32]);
    let old_vote_data = Bytes32::new([0xDDu8; 32]);
    let state_node = (
        voter_pk_bytes,
        (ballot_launcher_id, (old_vote_data, registration_coin_id)),
    )
        .to_clvm(&mut *ctx)
        .expect("state to_clvm");
    let state_truth = ctx
        .new_pair(clvmr::NodePtr::NIL, state_node)
        .expect("state_truth");

    // Solution shape (M5r-merkle-a):
    //   ballot_launcher_id, election_launcher_id, vote_close_height,
    //   vote_options_root, new_vote_data, new_signature, ballot_coin_id,
    //   vote_option_leaf_index, vote_option_proof_depth, ...vote_option_proof
    let election_launcher_id = Bytes32::new([0xEEu8; 32]);
    let vote_close_height: u64 = 1_000_000;
    let new_signature = Bytes::new(vec![0u8; 96]);
    let ballot_coin_id = Bytes32::new([0xAAu8; 32]);

    // Build the solution as nested cons.
    let solution_value = (
        ballot_launcher_id,
        (
            election_launcher_id,
            (
                vote_close_height,
                (
                    vote_options_root,
                    (
                        new_vote_data,
                        (
                            new_signature,
                            (
                                ballot_coin_id,
                                (leaf_index, (proof_depth, proof_siblings)),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let solution_node = solution_value.to_clvm(&mut *ctx).expect("solution to_clvm");

    // Action layer dispatches `puzzle(state_truth, ...solution)` — args =
    // cons(state_truth, solution).
    let args_node = ctx.new_pair(state_truth, solution_node).expect("args");

    let puzzle_bytes = clvmr::serde::node_to_bytes(&ctx, curried)
        .expect("ser puzzle");
    let args_bytes = clvmr::serde::node_to_bytes(&ctx, args_node).expect("ser args");
    drop(ctx);

    let mut alloc = Allocator::new();
    let puzzle_n = Program::from(puzzle_bytes)
        .to_clvm(&mut alloc)
        .expect("re-puzzle");
    let args_n = Program::from(args_bytes).to_clvm(&mut alloc).expect("re-args");
    let dialect = ChiaDialect::new(0);
    match run_program(&mut alloc, &dialect, puzzle_n, args_n, 11_000_000_000) {
        Ok(_reduction) => Ok(()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Helper: hash a label as `sha256("vote:" + label)` (matches the
/// dApp + cli convention).
fn vote_data_for(label: &str) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vote:");
    h.update(label.as_bytes());
    Bytes32::new(h.finalize().into())
}

#[test]
fn m5r_merkle_mode1free_skips_proof_check() {
    // vote_options_root = 0x00…00 = Mode1Free. Gate must short-circuit
    // regardless of leaf_index / proof. The puzzle's other asserts
    // (AssertBeforeHeightAbsolute, AssertCoinAnnouncement) emit
    // CONDITIONS without raising at clvm-run time — those are
    // chia-consensus-side checks, not clvm raises.
    let new_vote_data = vote_data_for("Yes");
    let result = run_update_vote(
        new_vote_data,
        Bytes32::default(),
        0,
        0,
        Vec::new(),
    );
    assert!(
        result.is_ok(),
        "Mode1Free should skip the merkle gate and execute cleanly: {result:?}"
    );
}

#[test]
fn m5r_merkle_mode2restricted_valid_proof_passes() {
    use chip_voting_sdk::vote_mode::BallotVoteMode;

    let labels = ["Yes", "No", "Abstain"];
    let option_hashes: Vec<Bytes32> = labels.iter().map(|l| vote_data_for(l)).collect();
    let mode = BallotVoteMode::Restricted {
        options: option_hashes.clone(),
    };
    let root = mode.vote_options_root();

    // Pick "Yes" — must hash to a leaf in the sorted tree.
    let new_vote_data = vote_data_for("Yes");
    let (leaf_index, proof) = mode
        .merkle_proof_for_option(new_vote_data)
        .expect("Yes is in the locked options set");

    let result = run_update_vote(
        new_vote_data,
        root,
        leaf_index as u64,
        proof.len() as u64,
        proof,
    );
    assert!(
        result.is_ok(),
        "Mode2Restricted with valid proof should pass: {result:?}"
    );
}

#[test]
fn m5r_merkle_mode2restricted_wrong_proof_raises() {
    use chip_voting_sdk::vote_mode::BallotVoteMode;

    let labels = ["Yes", "No", "Abstain"];
    let option_hashes: Vec<Bytes32> = labels.iter().map(|l| vote_data_for(l)).collect();
    let mode = BallotVoteMode::Restricted {
        options: option_hashes.clone(),
    };
    let root = mode.vote_options_root();

    // Pick a vote_data NOT in the locked set — proof can't recompute
    // the locked root.
    let new_vote_data = vote_data_for("Maybe");
    // Try to pass a proof for "Yes" anyway — won't reduce to root for
    // the wrong leaf.
    let (yes_leaf_index, yes_proof) = mode
        .merkle_proof_for_option(vote_data_for("Yes"))
        .expect("Yes is in the locked options set");

    let result = run_update_vote(
        new_vote_data,
        root,
        yes_leaf_index as u64,
        yes_proof.len() as u64,
        yes_proof,
    );
    assert!(
        result.is_err(),
        "Mode2Restricted with wrong proof must raise — got Ok"
    );
}
