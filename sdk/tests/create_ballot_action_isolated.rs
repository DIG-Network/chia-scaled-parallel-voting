// tests/create_ballot_action_isolated.rs — run the create_ballot action
// puzzle directly (no action layer / no singleton) to isolate whether the
// raise originates in create_ballot.rue's body or the action-layer wrapper.

use chia_protocol::{Bytes32, Program};
use chia_sdk_driver::SpendContext;
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::CurriedProgram;
use clvmr::{run_program, Allocator, ChiaDialect};

#[test]
fn create_ballot_action_runs_in_isolation() {
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;
    use chip_voting_sdk::action_spends::load_action_puzzle;
    use chip_voting_sdk::puzzles;

    let mut ctx = SpendContext::new();

    let election_id = Bytes32::new([0xAB; 32]);
    let singleton_launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);

    let create_ballot_program_node =
        load_action_puzzle(&mut ctx, puzzles::ELECTION_CREATE_BALLOT_HEX).expect("load");
    let create_ballot_curried = CurriedProgram {
        program: create_ballot_program_node,
        args: clvm_curried_args!(singleton_launcher_ph, election_id),
    }
    .to_clvm(&mut *ctx)
    .expect("curry");

    // Synthesize a StateTruth: (ephemeral_state . actual_state) where
    // actual_state is an arbitrary cons (the action returns Truth
    // unchanged, so the actual values don't matter for the action body).
    let actual_state: clvmr::NodePtr = (
        Bytes32::new([0u8; 32]),
        (0u64, (0u64, 0u64)),
    )
        .to_clvm(&mut *ctx)
        .unwrap();
    let state_truth = ctx
        .new_pair(clvmr::NodePtr::NIL, actual_state)
        .expect("state_truth");

    // Solution: (singleton_coin_id, ballot_seed, vote_close_height, ...outcome_domain_hash)
    let singleton_coin_id = Bytes32::new([0x12; 32]);
    let ballot_seed = Bytes32::new([0xab; 32]);
    let vote_close_height: u64 = 1000;
    let outcome_domain_hash = Bytes32::new([0xcd; 32]);
    let solution_value = (
        singleton_coin_id,
        (ballot_seed, (vote_close_height, outcome_domain_hash)),
    );
    let solution_node = solution_value.to_clvm(&mut *ctx).expect("solution");

    // The action puzzle expects (Truth, singleton_coin_id, ballot_seed,
    // vote_close_height, ...outcome_domain_hash). When the action layer
    // dispatches it does `puzzle(state_truth, ...solution)`, which builds
    // args = cons(state_truth, solution).
    let args_node = ctx.new_pair(state_truth, solution_node).expect("args");

    // Serialize and run.
    let puzzle_bytes =
        clvmr::serde::node_to_bytes(&ctx, create_ballot_curried).expect("ser puzzle");
    let args_bytes = clvmr::serde::node_to_bytes(&ctx, args_node).expect("ser args");

    let mut alloc = Allocator::new();
    let puzzle_n = Program::from(puzzle_bytes).to_clvm(&mut alloc).expect("re-puzzle");
    let args_n = Program::from(args_bytes).to_clvm(&mut alloc).expect("re-args");

    let dialect = ChiaDialect::new(0);
    match run_program(&mut alloc, &dialect, puzzle_n, args_n, 11_000_000_000) {
        Ok(reduction) => {
            println!(
                "create_ballot action ran OK; cost={} output(serialized {} bytes)",
                reduction.0,
                clvmr::serde::node_to_bytes(&alloc, reduction.1).map(|b| b.len()).unwrap_or(0)
            );
        }
        Err(e) => panic!("create_ballot action raised in isolation: {e:?}"),
    }
}

/// Layer 2: action puzzle wrapped by the action-layer dispatcher (still
/// no singleton outer). If THIS raises but the bare action doesn't, the
/// drift is in the action-layer assembly (selector/proof/finalizer).
#[test]
fn create_ballot_action_with_action_layer_only() {
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;
    use chip_voting_sdk::action_spends::{
        build_action_layer_puzzle, build_action_layer_solution, build_election_finalizer_full,
        load_action_puzzle, ActionSpend,
    };
    use chip_voting_sdk::actors::aggregator::{
        compute_election_action_root_leaves, election_actions_merkle_root_for_config,
    };
    use chip_voting_sdk::config::{ElectionConfig, PUBLIC_INPUT_COUNT};
    use chip_voting_sdk::ceremony::VerificationKey;
    use chip_voting_sdk::actors::deployer::ElectionDeployer;
    use chip_voting_sdk::DeployParams;
    use chip_voting_sdk::puzzles;

    // Build a real ElectionConfig via the deployer (so launcher_id +
    // cat_tail_hash are realistic and the merkle root prediction is
    // self-consistent).
    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
    let collateral_amount: u64 = 1_000;
    let dummy_funder_pk = chia_bls::PublicKey::default();
    let dummy_funder_coin = chia_protocol::Coin::new(
        Bytes32::new([0; 32]),
        Bytes32::new([0; 32]),
        1_000_000,
    );
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params);
    let (_spends, config): (Vec<chia_protocol::CoinSpend>, ElectionConfig) =
        deployer.build_deploy_bundle(dummy_funder_coin, dummy_funder_pk).expect("deploy");

    let election_id = config.election_launcher_id().expect("launcher id");
    let singleton_launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);

    let mut ctx = SpendContext::new();

    // Build the curried create_ballot action.
    let create_ballot_program_node =
        load_action_puzzle(&mut ctx, puzzles::ELECTION_CREATE_BALLOT_HEX).expect("load");
    let create_ballot_curried = CurriedProgram {
        program: create_ballot_program_node,
        args: clvm_curried_args!(singleton_launcher_ph, election_id),
    }
    .to_clvm(&mut *ctx)
    .expect("curry");

    // Build the action layer wrapper (matches the on-chain inner puzzle).
    let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id).expect("fin");
    let merkle_root = election_actions_merkle_root_for_config(&config);
    // State node — use genesis (matches what the singleton holds at deploy).
    let state_node: clvmr::NodePtr = (
        chip_voting_sdk::merkle::SparseMerkleTree::new().root(),
        (0u64, (0u64, 0u64)),
    )
        .to_clvm(&mut *ctx)
        .unwrap();
    let action_layer_node =
        build_action_layer_puzzle(&mut ctx, elect_finalizer, merkle_root, state_node).expect("al");

    // Build the action-layer solution.
    let singleton_coin_id = Bytes32::new([0x12; 32]);
    let ballot_seed = Bytes32::new([0xab; 32]);
    let vote_close_height: u64 = 1000;
    let outcome_domain_hash = Bytes32::new([0xcd; 32]);
    let solution_value = (
        singleton_coin_id,
        (ballot_seed, (vote_close_height, outcome_domain_hash)),
    );
    let create_ballot_solution = solution_value.to_clvm(&mut *ctx).expect("sol");
    let action_spends = vec![ActionSpend {
        puzzle: create_ballot_curried,
        solution: create_ballot_solution,
    }];
    let elect_finalizer_solution = ().to_clvm(&mut *ctx).expect("fin sol");
    let action_layer_solution = build_action_layer_solution(
        &mut ctx,
        &compute_election_action_root_leaves(&config),
        &action_spends,
        elect_finalizer_solution,
    )
    .expect("al sol");

    // Run the action-layer puzzle directly (no singleton outer).
    let puzzle_bytes =
        clvmr::serde::node_to_bytes(&ctx, action_layer_node).expect("ser puzzle");
    let sol_bytes =
        clvmr::serde::node_to_bytes(&ctx, action_layer_solution).expect("ser sol");

    let mut alloc = Allocator::new();
    let puzzle_n = Program::from(puzzle_bytes).to_clvm(&mut alloc).expect("re-puzzle");
    let sol_n = Program::from(sol_bytes).to_clvm(&mut alloc).expect("re-sol");

    let dialect = ChiaDialect::new(0);
    match run_program(&mut alloc, &dialect, puzzle_n, sol_n, 11_000_000_000) {
        Ok(reduction) => {
            println!("action-layer ran OK; cost={}", reduction.0);
        }
        Err(e) => panic!("action-layer raised: {e:?}"),
    }
}
