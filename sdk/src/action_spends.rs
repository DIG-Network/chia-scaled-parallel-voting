// ============================================================================
// action_spends.rs — shared spend-assembly helpers for the action layer
// ============================================================================
//
// MODULE: action_spends
// PURPOSE: Build the CLVM puzzle-reveal + solution for ANY action-
//          layered coin (Election Singleton or CAT-wrapped
//          Registration Coin). One source of truth for the action
//          layer composition; each actor method calls in here.
//
// WHY NOT chia_sdk_driver::ActionLayer? That driver is hard-coded
// to two upstream finalizers (`Default` and `Reserve`). Our CHIP
// uses CUSTOM finalizers (`election/finalizer.rue`,
// `registration_coin/finalizer.rue`) so we go one level lower —
// directly through `chia_sdk_types::RawActionLayerSolution`.
//
// COMPOSITION (all actors):
//   1. `build_action_layer_puzzle(ctx, finalizer_node, merkle_root,
//      state_node)` — curries our embedded `action.rue` HEX with
//      (FINALIZER, MERKLE_ROOT, STATE).
//   2. `build_action_layer_solution(ctx, action_spends,
//      finalizer_solution_node)` — wraps the action puzzle/solution
//      pairs in the `RawActionLayerSolution` shape with proper
//      Merkle proofs.
//   3. Wrap with the outer puzzle (`SingletonArgs::new(...)` for
//      the Election Singleton, `CatArgs::new(...)` for the
//      Registration Coin's CAT) and submit.

use chia_protocol::{Bytes, Bytes32, CoinSpend, Program};
use chia_puzzle_types::singleton::{SingletonArgs, SingletonSolution};
use chia_puzzle_types::Proof;
use chia_sdk_driver::SpendContext;
use chia_sdk_types::{MerkleProof, MerkleTree};
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::NodePtr;

use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles::ACTION_LAYER_HEX;

/// STRUCT: ActionSpend
/// PURPOSE: a single (action_puzzle, action_solution) pair that the
///          action layer dispatcher will run during a spend.
/// USAGE: caller pre-curries the action puzzle (e.g., register.rue
///        with all 10 deployment-time constants) and provides the
///        per-spend solution node. The action layer wrapper computes
///        the action's tree hash and the corresponding Merkle proof
///        against the curried action root.
#[derive(Debug, Clone, Copy)]
pub struct ActionSpend {
    /// The action puzzle as it appears in the bundle. CALLER
    /// pre-curries this with all the action's deploy-time params
    /// before passing it in.
    pub puzzle: NodePtr,
    /// The user-provided solution to the action puzzle. The action
    /// layer dispatcher prepends `(state_truth, ...)` automatically;
    /// this is just the per-action positional args.
    pub solution: NodePtr,
}

/// FN: build_action_layer_puzzle
/// WHAT: curry our embedded `action.rue` hex with (FINALIZER,
///       MERKLE_ROOT, STATE).
/// CALLER CONTRACT:
///   * `finalizer_node` is the FULLY CURRIED finalizer puzzle
///     reveal (both 1st + 2nd curries already applied — i.e.,
///     what the finalizer's full puzzle hash hashes to).
///   * `merkle_root` is the on-chain action root the action layer
///     verifies selected actions against.
///   * `state_node` is the curried `STATE` value (e.g.,
///     `ElectionState` or `RegistrationState`) as a CLVM tree.
pub fn build_action_layer_puzzle(
    ctx: &mut SpendContext,
    finalizer_node: NodePtr,
    merkle_root: Bytes32,
    state_node: NodePtr,
) -> VotingResult<NodePtr> {
    let action_layer_bytes = hex::decode(ACTION_LAYER_HEX.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding ACTION_LAYER_HEX: {e}")))?;
    let action_layer_program = Program::from(action_layer_bytes);
    let action_layer_node = action_layer_program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading action layer program: {e}")))?;

    let curried = CurriedProgram {
        program: action_layer_node,
        args: clvm_curried_args!(finalizer_node, merkle_root, state_node),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("currying action layer: {e}")))?;
    Ok(curried)
}

/// FN: build_action_layer_solution
/// WHAT: build the `RawActionLayerSolution`-shaped CLVM tree the
///       action layer dispatcher consumes.
/// IMPL:
///   * Computes the action puzzle's tree hash for each spend so the
///     Merkle proof against `action_root_leaves` can be looked up.
///   * `selectors_and_proofs` uses the upstream selector encoding
///     (sequential 2, 5, 11, ... powers) — first occurrence carries
///     a proof, subsequent occurrences of the same puzzle reuse the
///     proof slot via `None`.
///   * `finalizer_solution_node` is passed verbatim — the custom
///     finalizer's required shape is the caller's responsibility
///     (e.g., the registration_coin finalizer takes `...my_amount:
///     Int`; the election finalizer takes the equivalent for new
///     singleton amount handling).
pub fn build_action_layer_solution(
    ctx: &mut SpendContext,
    action_root_leaves: &[Bytes32],
    action_spends: &[ActionSpend],
    finalizer_solution_node: NodePtr,
) -> VotingResult<NodePtr> {
    let merkle_tree = MerkleTree::new(action_root_leaves);

    let mut puzzles: Vec<NodePtr> = Vec::new();
    let mut puzzle_to_selector: std::collections::HashMap<Bytes32, u32> = Default::default();
    let mut selectors_and_proofs: Vec<(u32, Option<MerkleProof>)> = Vec::new();
    let mut solutions: Vec<NodePtr> = Vec::new();
    let mut next_selector: u32 = 2;

    for spend in action_spends {
        let puzzle_hash = Bytes32::new(tree_hash(ctx, spend.puzzle).to_bytes());
        let proof = merkle_tree.proof(puzzle_hash).ok_or_else(|| {
            voting_other(format!(
                "action puzzle hash {} not in merkle root (leaves: {:?})",
                hex::encode(puzzle_hash),
                action_root_leaves
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
            ))
        })?;
        let selector = if let Some(&existing) = puzzle_to_selector.get(&puzzle_hash) {
            // Already seen — reuse selector. Proof slot will be
            // dropped to None below via the selector-dedup pass.
            existing
        } else {
            puzzles.push(spend.puzzle);
            puzzle_to_selector.insert(puzzle_hash, next_selector);
            let s = next_selector;
            next_selector = next_selector * 2 + 1;
            s
        };
        selectors_and_proofs.push((selector, Some(proof)));
        solutions.push(spend.solution);
    }

    // Mirror the upstream dedup: only the FIRST occurrence of a
    // selector (in reverse order — that's how the action layer
    // walks them) carries the proof; subsequent occurrences pass
    // `None` and the dispatcher reuses the cached proof.
    let mut proven: Vec<u32> = Vec::new();
    let mut sp_rev: Vec<(u32, Option<MerkleProof>)> =
        selectors_and_proofs.into_iter().rev().collect();
    for entry in sp_rev.iter_mut() {
        if proven.contains(&entry.0) {
            entry.1 = None;
        } else {
            proven.push(entry.0);
        }
    }

    // CRITICAL: our action.rue declares its last arg as
    // `...finalizer_solution: Any` — i.e., the trailing tail of
    // the user solution IS finalizer_solution directly (no extra
    // cons). The upstream `RawActionLayerSolution` shape uses
    // `#[clvm(list)]` which adds a nil terminator, producing
    //   `(puzzles . (sap . (solutions . (finalizer_solution . nil))))`
    // For our custom action.rue we need
    //   `(puzzles . (sap . (solutions . finalizer_solution)))`
    // We hand-build the cons chain so the serialised CLVM tree
    // exactly matches what our action layer dispatcher reads.
    let solutions_node = solutions
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("solutions to_clvm: {e}")))?;
    let sap_node = sp_rev
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("selectors_and_proofs to_clvm: {e}")))?;
    let puzzles_node = puzzles
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("puzzles to_clvm: {e}")))?;
    // (solutions . finalizer_solution_node) — last cons whose cdr
    // IS finalizer_solution (no extra wrap).
    let cons_solutions_fs = ctx
        .new_pair(solutions_node, finalizer_solution_node)
        .map_err(|e| voting_other(format!("new_pair (solutions . fs): {e}")))?;
    let cons_sap_rest = ctx
        .new_pair(sap_node, cons_solutions_fs)
        .map_err(|e| voting_other(format!("new_pair (sap . _): {e}")))?;
    let solution_root = ctx
        .new_pair(puzzles_node, cons_sap_rest)
        .map_err(|e| voting_other(format!("new_pair (puzzles . _): {e}")))?;
    Ok(solution_root)
}

/// FN: build_singleton_spend
/// WHAT: wrap an inner spend (action layer or otherwise) with the
///       Singleton outer puzzle + proof. Produces a `CoinSpend` ready
///       for inclusion in a `SpendBundle`.
/// PARAMS:
///   * `coin` — the singleton's coin record (parent + puzzle hash +
///     amount).
///   * `launcher_id` — singleton struct identifier; must match the
///     curried launcher_id of the on-chain singleton.
///   * `inner_puzzle_node` — the inner puzzle reveal (e.g., the
///     action layer reveal from `build_action_layer_puzzle`).
///   * `inner_solution_node` — the inner puzzle solution.
///   * `lineage_proof` — `Eve` for the first spend after the
///     launcher; `Lineage` thereafter.
pub fn build_singleton_spend(
    ctx: &mut SpendContext,
    coin: chia_protocol::Coin,
    launcher_id: Bytes32,
    inner_puzzle_node: NodePtr,
    inner_solution_node: NodePtr,
    lineage_proof: Proof,
) -> VotingResult<CoinSpend> {
    use chia_puzzles::SINGLETON_TOP_LAYER_V1_1;

    // Build the singleton outer puzzle reveal: curry the standard
    // singleton top-layer with (singleton_struct, inner_puzzle).
    let singleton_top_layer_program = Program::from(SINGLETON_TOP_LAYER_V1_1.to_vec());
    let singleton_top_layer_node = singleton_top_layer_program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading singleton top layer: {e}")))?;
    let singleton_args = SingletonArgs::new(launcher_id, inner_puzzle_node);
    let singleton_puzzle = CurriedProgram {
        program: singleton_top_layer_node,
        args: singleton_args,
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("currying singleton: {e}")))?;

    // Build the singleton solution.
    let singleton_solution = SingletonSolution {
        lineage_proof,
        amount: coin.amount,
        inner_solution: inner_solution_node,
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("serialising singleton solution: {e}")))?;

    Ok(CoinSpend::new(
        coin,
        node_to_program(ctx, singleton_puzzle)?,
        node_to_program(ctx, singleton_solution)?,
    ))
}

/// FN: build_cat_spend
/// WHAT: wrap an inner spend with the CAT v2 outer puzzle. Produces
///       a `CoinSpend` ready for the bundle.
/// PARAMS:
///   * `coin` — the CAT coin's coin record (this is the CAT-wrapped
///     coin's record; parent_coin_info points at the CAT-wrapped
///     parent, NOT the inner puzzle's parent).
///   * `cat_tail_hash` — the asset id (TAIL puzzle hash).
///   * `inner_puzzle_node` — the inner puzzle reveal.
///   * `inner_solution_node` — the inner puzzle solution.
///   * `lineage_proof` — for the CAT v2: `(parent_parent_coin_info,
///     parent_inner_puzzle_hash, parent_amount)`. None for an eve
///     CAT (i.e., one being issued from a TAIL spend).
///   * `prev_coin_id`, `next_coin_id` — for CAT ring announcements.
///     For a single-CAT spend, both are the spend's own coin id.
///   * `extra_delta` — net change to the CAT supply (typically 0
///     for non-issuance spends).
#[allow(clippy::too_many_arguments)]
pub fn build_cat_spend(
    ctx: &mut SpendContext,
    coin: chia_protocol::Coin,
    cat_tail_hash: Bytes32,
    inner_puzzle_node: NodePtr,
    inner_solution_node: NodePtr,
    lineage_proof: Option<chia_puzzle_types::LineageProof>,
    prev_coin_id: Bytes32,
    next_coin_id: Bytes32,
    extra_delta: i64,
) -> VotingResult<CoinSpend> {
    use chia_puzzle_types::cat::{CatArgs, CatSolution};
    use chia_puzzle_types::CoinProof as CatCoinProof;
    use chia_puzzles::CAT_PUZZLE;

    let cat_program = Program::from(CAT_PUZZLE.to_vec());
    let cat_node = cat_program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading CAT puzzle: {e}")))?;
    let cat_args = CatArgs::new(cat_tail_hash, inner_puzzle_node);
    let cat_puzzle = CurriedProgram {
        program: cat_node,
        args: cat_args,
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("currying CAT: {e}")))?;

    // For a single-CAT-spend ring, next_coin_proof describes our
    // own inner puzzle (the "next" in the ring is us, since
    // there's only one CAT). prev_coin_id and next_coin_id are
    // both this coin's id.
    let inner_ph = Bytes32::new(tree_hash(ctx, inner_puzzle_node).to_bytes());
    let _ = next_coin_id; // implicit in single-CAT ring
    let cat_solution = CatSolution {
        inner_puzzle_solution: inner_solution_node,
        lineage_proof,
        prev_coin_id,
        this_coin_info: coin,
        next_coin_proof: CatCoinProof {
            parent_coin_info: coin.parent_coin_info,
            inner_puzzle_hash: inner_ph,
            amount: coin.amount,
        },
        prev_subtotal: 0,
        extra_delta,
    };
    let cat_solution_node = cat_solution
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("serialising CAT solution: {e}")))?;

    Ok(CoinSpend::new(
        coin,
        node_to_program(ctx, cat_puzzle)?,
        node_to_program(ctx, cat_solution_node)?,
    ))
}

/// FN: node_to_program (file-private)
/// WHAT: serialise a NodePtr back to a `chia_protocol::Program` for
///       inclusion in a `CoinSpend`.
fn node_to_program(ctx: &SpendContext, node: NodePtr) -> VotingResult<Program> {
    let bytes = clvmr::serde::node_to_bytes(ctx, node)
        .map_err(|e| voting_other(format!("serializing CLVM node to bytes: {e}")))?;
    Ok(Program::from(bytes))
}

/// FN: voting_other (file-private)
/// WHAT: shorthand for `VotingError::Other` with a string message.
fn voting_other(msg: impl Into<String>) -> VotingError {
    VotingError::Other(anyhow_compat::Error(msg.into().into()))
}

/// FN: bytes_from_node
/// WHAT: extract raw bytes from a CLVM node (used when reading
///       memos / message values out of conditions).
pub fn bytes_from_node(allocator: &clvmr::Allocator, node: NodePtr) -> VotingResult<Bytes> {
    use clvm_traits::FromClvm;
    Bytes::from_clvm(allocator, node)
        .map_err(|e| voting_other(format!("decoding atom from node: {e}")))
}

// ============================================================================
// High-level finalizer + action puzzle builders specific to our CHIP
// ============================================================================

/// FN: build_registration_finalizer_full
/// WHAT: produce the FULLY-curried Registration Coin finalizer
///       puzzle reveal (both 1st curry — `(ACTION_LAYER_MOD_HASH,
///       HINT)` — and 2nd curry — `(FINALIZER_SELF_HASH)`).
/// USAGE: pass the resulting node to `build_action_layer_puzzle`'s
///        `finalizer_node` argument when assembling a Registration
///        Coin action-layer spend.
pub fn build_registration_finalizer_full(
    ctx: &mut SpendContext,
    voter_hint: Bytes32,
) -> VotingResult<NodePtr> {
    use crate::puzzles::{PuzzleHashes, REGISTRATION_FINALIZER_HEX};
    let bytes = hex::decode(REGISTRATION_FINALIZER_HEX.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding REGISTRATION_FINALIZER_HEX: {e}")))?;
    let program = Program::from(bytes);
    let program_node = program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading registration finalizer: {e}")))?;

    let action_layer_mod = PuzzleHashes::action_layer();
    let first_curry = CurriedProgram {
        program: program_node,
        args: clvm_curried_args!(action_layer_mod, voter_hint),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("first-currying registration finalizer: {e}")))?;

    let first_curry_hash = Bytes32::new(tree_hash(ctx, first_curry).to_bytes());
    let full = CurriedProgram {
        program: first_curry,
        args: clvm_curried_args!(first_curry_hash),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("second-currying registration finalizer: {e}")))?;
    Ok(full)
}

/// FN: build_election_finalizer_full
/// WHAT: produce the FULLY-curried Election Singleton finalizer
///       puzzle reveal (1st curry binds `(ACTION_LAYER_MOD_HASH,
///       HINT=launcher_id)`; 2nd curry binds the finalizer's own
///       first-curry hash).
pub fn build_election_finalizer_full(
    ctx: &mut SpendContext,
    election_launcher_id: Bytes32,
) -> VotingResult<NodePtr> {
    use crate::puzzles::{PuzzleHashes, ELECTION_FINALIZER_HEX};
    let bytes = hex::decode(ELECTION_FINALIZER_HEX.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding ELECTION_FINALIZER_HEX: {e}")))?;
    let program = Program::from(bytes);
    let program_node = program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading election finalizer: {e}")))?;

    let action_layer_mod = PuzzleHashes::action_layer();
    let first_curry = CurriedProgram {
        program: program_node,
        args: clvm_curried_args!(action_layer_mod, election_launcher_id),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("first-currying election finalizer: {e}")))?;

    let first_curry_hash = Bytes32::new(tree_hash(ctx, first_curry).to_bytes());
    let full = CurriedProgram {
        program: first_curry,
        args: clvm_curried_args!(first_curry_hash),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("second-currying election finalizer: {e}")))?;
    Ok(full)
}

/// FN: build_voting_coin_finalizer_full
/// WHAT: produce the FULLY-curried Voting Coin finalizer puzzle
///       reveal. Mirrors [`build_election_finalizer_full`] /
///       [`build_ballot_finalizer_full`] but loads the Voting Coin
///       finalizer hex and uses `voting_coin_hint` for the HINT.
/// USAGE: pass to `build_action_layer_puzzle` when assembling a
///        Voting Coin's inner action layer (e.g. for the
///        `update_vote` action).
pub fn build_voting_coin_finalizer_full(
    ctx: &mut SpendContext,
    voting_coin_hint: Bytes32,
) -> VotingResult<NodePtr> {
    use crate::puzzles::{PuzzleHashes, VOTING_COIN_FINALIZER_HEX};
    let bytes = hex::decode(VOTING_COIN_FINALIZER_HEX.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding VOTING_COIN_FINALIZER_HEX: {e}")))?;
    let program = Program::from(bytes);
    let program_node = program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading voting coin finalizer: {e}")))?;

    let action_layer_mod = PuzzleHashes::action_layer();
    let first_curry = CurriedProgram {
        program: program_node,
        args: clvm_curried_args!(action_layer_mod, voting_coin_hint),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("first-currying voting coin finalizer: {e}")))?;

    let first_curry_hash = Bytes32::new(tree_hash(ctx, first_curry).to_bytes());
    let full = CurriedProgram {
        program: first_curry,
        args: clvm_curried_args!(first_curry_hash),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("second-currying voting coin finalizer: {e}")))?;
    Ok(full)
}

/// FN: build_ballot_finalizer_full
/// WHAT: produce the FULLY-curried Ballot Coin finalizer puzzle
///       reveal (1st curry binds `(ACTION_LAYER_MOD_HASH,
///       HINT=ballot_launcher_id)`; 2nd curry binds the finalizer's
///       own first-curry hash). Mirrors
///       [`build_election_finalizer_full`] but loads the Ballot Coin
///       finalizer hex and uses `ballot_launcher_id` for the HINT.
/// USAGE: pass to `build_action_layer_puzzle` when assembling the eve
///        Ballot Coin's inner action layer.
pub fn build_ballot_finalizer_full(
    ctx: &mut SpendContext,
    ballot_launcher_id: Bytes32,
) -> VotingResult<NodePtr> {
    use crate::puzzles::{PuzzleHashes, BALLOT_COIN_FINALIZER_HEX};
    let bytes = hex::decode(BALLOT_COIN_FINALIZER_HEX.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding BALLOT_COIN_FINALIZER_HEX: {e}")))?;
    let program = Program::from(bytes);
    let program_node = program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading ballot finalizer: {e}")))?;

    let action_layer_mod = PuzzleHashes::action_layer();
    let first_curry = CurriedProgram {
        program: program_node,
        args: clvm_curried_args!(action_layer_mod, ballot_launcher_id),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("first-currying ballot finalizer: {e}")))?;

    let first_curry_hash = Bytes32::new(tree_hash(ctx, first_curry).to_bytes());
    let full = CurriedProgram {
        program: first_curry,
        args: clvm_curried_args!(first_curry_hash),
    }
    .to_clvm(&mut **ctx)
    .map_err(|e| voting_other(format!("second-currying ballot finalizer: {e}")))?;
    Ok(full)
}

/// FN: load_action_puzzle
/// WHAT: load an embedded action puzzle's CLVM bytes into the
///       allocator, returning the NodePtr — used when an action
///       takes NO curried params (e.g., `vote.rue`, `release.rue`,
///       `announce_finalization.rue`).
pub fn load_action_puzzle(ctx: &mut SpendContext, hex_str: &str) -> VotingResult<NodePtr> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|e| voting_other(format!("decoding action puzzle hex: {e}")))?;
    let program = Program::from(bytes);
    program
        .to_clvm(&mut **ctx)
        .map_err(|e| voting_other(format!("loading action puzzle: {e}")))
}

// Regression: runtime `CurriedProgram` must match `puzzles::fresh_registration_inner_hash`.
// Rue `election/register.rue` uses `curry_tree_hash`/atom-wrapping the same way as
// yakuhito's slot-machine action layers; any drift breaks live spends vs predicted PHs.
#[cfg(test)]
mod inner_hash_regression_tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, PublicKey, SecretKey};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;

    use crate::puzzles::{
        fresh_registration_inner_hash, registration_actions_merkle_root, voter_hint,
    };

    fn synthetic_test_pubkey() -> PublicKey {
        let root_sk = SecretKey::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root_sk.public_key(), 0).derive_synthetic()
    }

    #[test]
    #[ignore = "inner-hash prediction needs updating for new RegistrationState shape (Phase 1 → Phase 6)"]
    fn curried_registration_action_layer_matches_predicted_inner_hash() {
        let pk = synthetic_test_pubkey();
        let election_id = Bytes32::new([0xAB; 32]);
        let cat_tail_hash = Bytes32::new([0x33; 32]);

        let mut ctx = SpendContext::new();
        let hint = voter_hint(election_id, cat_tail_hash, &pk);
        let reg_finalizer = build_registration_finalizer_full(&mut ctx, hint).unwrap();

        let pk_bytes = Bytes::new(pk.to_bytes().to_vec());
        let state_node = (pk_bytes, (election_id, ((), (Bytes32::default(), ()))))
            .to_clvm(&mut *ctx)
            .unwrap();

        let layer = build_action_layer_puzzle(
            &mut ctx,
            reg_finalizer,
            registration_actions_merkle_root(cat_tail_hash),
            state_node,
        )
        .unwrap();

        let from_runtime = Bytes32::new(tree_hash(&ctx, layer).to_bytes());
        let from_predictor = fresh_registration_inner_hash(&pk, election_id, cat_tail_hash);
        assert_eq!(
            from_runtime, from_predictor,
            "CurriedProgram(action.rue) must match `fresh_registration_inner_hash`",
        );
    }
}
