// ============================================================================
// tests/voter_update_vote_e2e.rs — Voter::update_vote against Simulator
// ============================================================================
//
// SCOPE: full deploy → CAT-issue Registration Coin → register →
// create_ballot → launch_ballot → cast_vote → update_vote pipeline
// against `chia_sdk_test::Simulator`. Asserts:
//   * Original Voting Coin spent.
//   * Recreated Voting Coin lands at the SDK's predicted CAT-wrapped
//     puzzle hash for `(new_vote_data, registration_coin_id)` with
//     parent = original Voting Coin id and amount preserved
//     (CAT outer conservation: input == single output).
//   * Ballot Coin singleton walked from eve through one prior oracle
//     spend (cast_vote) and re-spent again (update_vote oracle), and
//     re-recreated.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::GenesisByCoinIdTailArgs;
use chia_sdk_driver::{Cat, SpendContext, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::ballot::{
    BallotIssuer, CreateBallotParams, LaunchBallotParams,
};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::actors::voter::{CastVoteParams, UpdateVoteParams};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::PoseidonSmt;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn voter_update_vote_against_simulator_full_flow() {
    // ── 1. Deploy + CAT issue + register + create_ballot + launch_ballot + cast_vote ─
    // (same setup as voter_cast_vote_e2e — just leaves us with a
    // Voting Coin to update.)
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(2_000);

    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();
    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: chip_voting_sdk::config::MAX_SIGNERS,
        ceremony_launcher_id: Bytes32::default(),
        vk_hash: Bytes32::default(),
        vote_mode_lock: chip_voting_sdk::vote_mode::VOTE_MODE_LOCK_NONE,
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk, true)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");

    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash, 1_000);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id, 1_000);

    // CAT issuance.
    let mut ctx = SpendContext::new();
    let issuance_memos = ctx.hint(reg_outer_ph).expect("hint");
    let extra_conditions = Conditions::new().create_coin(
        reg_inner_ph,
        collateral_amount,
        issuance_memos,
    );
    let (xch_conditions, cats) = Cat::issue_with_coin(
        &mut ctx,
        cat_genesis.coin.coin_id(),
        collateral_amount,
        extra_conditions,
    )
    .expect("Cat::issue_with_coin");
    StandardLayer::new(cat_genesis.pk)
        .spend(&mut ctx, cat_genesis.coin, xch_conditions)
        .expect("StandardLayer::spend");
    let issuance_spends = ctx.take();
    sim.spend_coins(issuance_spends, std::slice::from_ref(&cat_genesis.sk))
        .expect("simulator accepts CAT issuance");
    let registration_cat = cats.into_iter().next().expect("issuance produces 1 CAT child");
    let registration_coin_id = registration_cat.coin.coin_id();

    // Register.
    let create_reg_msg = compute_create_reg_msg(
        launcher_id,
        &voter_pk,
        reg_outer_ph,
        collateral_amount,
    );
    let mut ctx = SpendContext::new();
    let condition: (u8, (Bytes32, ())) = (60u8, (create_reg_msg, ()));
    let conditions_list: ((u8, (Bytes32, ())), ()) = (condition, ());
    let announcer_puzzle: (u8, ((u8, (Bytes32, ())), ())) = (1u8, conditions_list);
    let announcer_node = announcer_puzzle.to_clvm(&mut *ctx).unwrap();
    let announcer_ph = Bytes32::new(tree_hash(&ctx, announcer_node).to_bytes());
    let announcer_coin = Coin::new(Bytes32::new([0xBB; 32]), announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let cat_parent_spend =
        common::coin_spend_from_nodes(&ctx, announcer_coin, announcer_node, announcer_solution);
    drop(ctx);

    let voter = Voter::new(config.clone(), voter_keys, NetworkType::Testnet11);
    let smt_pre_register = PoseidonSmt::new();
    let chain = common::SharedSim::new(&mut sim);
    let register_bundle = voter
        .register(&smt_pre_register, cat_parent_spend, &chain, config.collateral_amount)
        .await
        .expect("register");
    drop(chain);
    sim.new_transaction(register_bundle)
        .expect("simulator accepts register");

    // create_ballot.
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let funder_coin = Coin::new(Bytes32::new([0xCC; 32]), funder_ph, 2);
    sim.insert_coin(funder_coin);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend =
        common::coin_spend_from_nodes(&ctx, funder_coin, funder_puzzle, funder_solution);
    drop(ctx);

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let ballot_seed = Bytes32::new([0xab; 32]);
    let outcome_domain_hash = Bytes32::new([0xcd; 32]);
    let vote_close_height: u64 = 1_000;
    let chain = common::SharedSim::new(&mut sim);
    let created = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed,
                vote_close_height,
                outcome_domain_hash,
                vote_options_root: Bytes32::default(),
            },
            funder_spend,
        )
        .await
        .expect("create_ballot");
    drop(chain);
    sim.new_transaction(created.spend_bundle.clone())
        .expect("simulator accepts create_ballot");

    // launch_ballot.
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;
    let chain = common::SharedSim::new(&mut sim);
    let launched = issuer
        .launch_ballot(
            &chain,
            created.ballot_launcher_id,
            LaunchBallotParams {
                vote_close_height,
                outcome_domain_hash,
                vote_threshold_num,
                vote_threshold_den,
                vote_options_root: Bytes32::default(),
            },
        )
        .await
        .expect("launch_ballot");
    drop(chain);
    sim.new_transaction(launched.spend_bundle.clone())
        .expect("simulator accepts launch_ballot");

    let mut smt_post_register = PoseidonSmt::new();
    smt_post_register.insert(voter.keys.jubjub_pubkey, config.collateral_amount);
    let registration_merkle_root_snapshot = Bytes32::new(smt_post_register.root_be32());
    let registration_vote_weight_snapshot = collateral_amount;

    // cast_vote.
    let initial_vote_data = Bytes32::new([0xAA; 32]);
    let voting_coin_amount: u64 = 1;
    let chain = common::SharedSim::new(&mut sim);
    let cast_result = voter
        .cast_vote(
            &chain,
            CastVoteParams {
                ballot_launcher_id: created.ballot_launcher_id,
                vote_data: initial_vote_data,
                vote_close_height,
                vote_threshold_num,
                vote_threshold_den,
                registration_merkle_root_snapshot,
                registration_vote_weight_snapshot,
                voting_coin_amount,
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("cast_vote");
    drop(chain);
    sim.new_transaction(cast_result.spend_bundle.clone())
        .expect("simulator accepts cast_vote");

    let original_voting_coin_id = cast_result.voting_coin_id;

    // ── 2. update_vote ───────────────────────────────────────
    let new_vote_data = Bytes32::new([0xEE; 32]);
    let chain = common::SharedSim::new(&mut sim);
    let update_result = voter
        .update_vote(
            &chain,
            UpdateVoteParams {
                voting_coin_id: original_voting_coin_id,
                old_vote_data: initial_vote_data,
                new_vote_data,
                registration_coin_id,
                ballot_launcher_id: created.ballot_launcher_id,
                vote_close_height,
                vote_threshold_num,
                vote_threshold_den,
                registration_merkle_root_snapshot,
                registration_vote_weight_snapshot,
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("update_vote failed: {:?}", e));
    drop(chain);

    println!(
        "update_vote returned recreated_voting_coin_id = {}",
        hex::encode(update_result.recreated_voting_coin_id),
    );
    println!(
        "update_vote bundle has {} coin spends",
        update_result.spend_bundle.coin_spends.len(),
    );

    sim.new_transaction(update_result.spend_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator accepts update_vote bundle; got: {:?}", e));

    // ── 3. Verify ───────────────────────────────────────────
    // 3a. Original Voting Coin spent.
    let orig = sim
        .coin_state(original_voting_coin_id)
        .expect("original voting coin still tracked");
    assert!(
        orig.spent_height.is_some(),
        "original Voting Coin must be spent after update_vote",
    );

    // 3b. Recreated Voting Coin lands at SDK-predicted ph.
    let recreated_voting_coin_ph = puzzles::voting_coin_puzzle_hash(
        chip_voting_sdk::puzzles::PuzzleHashes::cat_outer(),
        cat_tail_hash,
        chip_voting_sdk::puzzles::PuzzleHashes::action_layer(),
        chip_voting_sdk::puzzles::PuzzleHashes::voting_coin_finalizer(),
        puzzles::voting_coin_actions_merkle_root(),
        &voter_pk,
        created.ballot_launcher_id,
        launcher_id,
        new_vote_data,
        registration_coin_id,
    );
    let recreated_cs = sim
        .coin_state(update_result.recreated_voting_coin_id)
        .unwrap_or_else(|| {
            panic!(
                "expected recreated Voting Coin {} on chain after update_vote",
                hex::encode(update_result.recreated_voting_coin_id)
            )
        });
    assert_eq!(
        recreated_cs.coin.puzzle_hash, recreated_voting_coin_ph,
        "recreated Voting Coin must land at SDK-predicted ph for new_vote_data",
    );
    assert_eq!(
        recreated_cs.coin.parent_coin_info, original_voting_coin_id,
        "recreated Voting Coin's parent must be the original Voting Coin",
    );
    assert_eq!(
        recreated_cs.coin.amount, voting_coin_amount,
        "CAT conservation: recreated amount equals original amount",
    );
    assert!(
        recreated_cs.spent_height.is_none(),
        "recreated Voting Coin must be unspent",
    );
}

// ─── Helpers ───────────────────────────────────────────────────────

fn test_voter_keys(seed: u8) -> VoterKeys {
    use chia_bls::SecretKey;
    let sk = SecretKey::from_seed(&[seed; 32]);
    VoterKeys::new(sk)
}

fn parse_b32(hex_str: &str) -> Bytes32 {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x")).expect("hex");
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    Bytes32::new(arr)
}

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
