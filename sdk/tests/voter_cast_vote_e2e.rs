// ============================================================================
// tests/voter_cast_vote_e2e.rs — Voter::cast_vote against Simulator
// ============================================================================
//
// SCOPE: full deploy → CAT-issue Registration Coin → register →
// create_ballot → launch_ballot → cast_vote pipeline against
// `chia_sdk_test::Simulator`. Asserts:
//   * Registration Coin spent.
//   * A new Voting Coin lands at the SDK's predicted CAT-wrapped
//     puzzle hash with parent = registration_coin_id and amount =
//     `voting_coin_amount`.
//   * The recreated Registration Coin lands at amount =
//     `collateral_amount - voting_coin_amount` (CAT conservation).
//   * The Ballot Coin singleton has been re-created (oracle
//     co-spend).
//
// WHY: this exercises every layer the new Voter::cast_vote driver
// touches simultaneously — CAT outer + action layer + per-ballot
// merkle root reconstruction + singleton outer (Ballot Coin oracle
// co-spend) + AggSigMe over the canonical vote_message.

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
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::actors::voter::CastVoteParams;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn voter_cast_vote_against_simulator_full_flow() {
    // ── 1. Set up simulator + CAT genesis ────────────────────
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

    // ── 2. Deploy Election Singleton ─────────────────────────
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk, true)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");

    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 3. Voter setup ──────────────────────────────────────
    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash, 1_000);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id, 1_000);

    // ── 4. Mint Registration Coin via Cat::issue_with_coin ──
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
        .expect("StandardLayer::spend(cat_genesis)");
    let issuance_spends = ctx.take();
    sim.spend_coins(issuance_spends, std::slice::from_ref(&cat_genesis.sk))
        .expect("simulator accepts CAT issuance bundle");

    let registration_cat = cats.into_iter().next().expect("issuance produces 1 CAT child");
    assert_eq!(registration_cat.coin.puzzle_hash, reg_outer_ph);
    let registration_coin_id = registration_cat.coin.coin_id();

    // ── 5. Run Voter::register (announcer-only cat_parent_spend) ─
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
    let cat_parent_spend = common::coin_spend_from_nodes(
        &ctx,
        announcer_coin,
        announcer_node,
        announcer_solution,
    );
    drop(ctx);

    let voter = Voter::new(config.clone(), voter_keys, NetworkType::Testnet11);
    let smt_pre_register = SparseMerkleTree::new();
    let chain = common::SharedSim::new(&mut sim);
    let register_bundle = voter
        .register(&smt_pre_register, cat_parent_spend, &chain, config.collateral_amount)
        .await
        .expect("Voter::register");
    drop(chain);
    sim.new_transaction(register_bundle)
        .expect("simulator accepts register bundle");

    // ── 6. create_ballot ───────────────────────────────────
    // Build a 2-mojo funder coin for the launcher mint (mirrors the
    // pattern in create_ballot_e2e.rs).
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
        .expect("simulator accepts create_ballot bundle");

    // ── 7. launch_ballot ──────────────────────────────────
    // The post-register Election Singleton state is what the
    // BallotIssuer captures into the per-ballot finalize curry, so
    // those values become what the Voter must mirror at cast_vote.
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
        .expect("simulator accepts launch_ballot bundle");

    // The registration_*_snapshot values curried into finalize MUST
    // match what `BallotIssuer::launch_ballot` actually used. After
    // the voter registered, weight = collateral_amount and root =
    // depth-32 SMT containing voter_pk. Mirror locally.
    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register.insert(&voter_pk, config.collateral_amount).expect("smt insert");
    let registration_merkle_root_snapshot = smt_post_register.root();
    let registration_vote_weight_snapshot = collateral_amount; // exactly 1 voter post-register

    // ── 8. cast_vote ──────────────────────────────────────
    let vote_data = Bytes32::new([0xAA; 32]);
    let voting_coin_amount: u64 = 1;

    let chain = common::SharedSim::new(&mut sim);
    let cast_result = voter
        .cast_vote(
            &chain,
            CastVoteParams {
                ballot_launcher_id: created.ballot_launcher_id,
                vote_data,
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
        .unwrap_or_else(|e| panic!("cast_vote failed: {:?}", e));
    drop(chain);

    println!(
        "cast_vote returned voting_coin_id = {}",
        hex::encode(cast_result.voting_coin_id),
    );
    println!(
        "cast_vote bundle has {} coin spends",
        cast_result.spend_bundle.coin_spends.len(),
    );

    sim.new_transaction(cast_result.spend_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator accepts cast_vote bundle; got: {:?}", e));

    // ── 9. Verify outputs ─────────────────────────────────
    // 9a. Registration Coin spent.
    let post_reg = sim
        .coin_state(registration_coin_id)
        .expect("registration coin still in simulator state");
    assert!(
        post_reg.spent_height.is_some(),
        "Registration Coin must be spent after cast_vote",
    );

    // 9b. Voting Coin lands at predicted PH with right amount/parent.
    let voting_cs = sim
        .coin_state(cast_result.voting_coin_id)
        .unwrap_or_else(|| {
            panic!(
                "expected Voting Coin {} on chain after cast_vote",
                hex::encode(cast_result.voting_coin_id)
            )
        });
    let voting_coin_full_ph = puzzles::voting_coin_puzzle_hash(
        chip_voting_sdk::puzzles::PuzzleHashes::cat_outer(),
        cat_tail_hash,
        chip_voting_sdk::puzzles::PuzzleHashes::action_layer(),
        chip_voting_sdk::puzzles::PuzzleHashes::voting_coin_finalizer(),
        puzzles::voting_coin_actions_merkle_root(),
        &voter_pk,
        created.ballot_launcher_id,
        launcher_id,
        vote_data,
        registration_coin_id,
    );
    assert_eq!(
        voting_cs.coin.puzzle_hash, voting_coin_full_ph,
        "Voting Coin must land at SDK-predicted CAT-wrapped puzzle hash",
    );
    assert_eq!(
        voting_cs.coin.parent_coin_info, registration_coin_id,
        "Voting Coin's parent must be the spent Registration Coin",
    );
    assert_eq!(
        voting_cs.coin.amount, voting_coin_amount,
        "Voting Coin amount must equal CastVoteParams.voting_coin_amount",
    );
    assert!(
        voting_cs.spent_height.is_none(),
        "Voting Coin must be unspent immediately after cast_vote",
    );

    // 9c. Recreated Registration Coin amount sums to conservation.
    // Find the CAT child of the spent Registration Coin that ISN'T
    // the Voting Coin — that's the recreated Registration Coin (with
    // updated voted_ballots_root + same fresh-shape minus the
    // ballot-membership update). Its amount = collateral_amount -
    // voting_coin_amount. We don't predict its puzzle hash strictly
    // here (post-cast_vote state differs from `fresh`), but the CAT
    // outer's conservation rule guarantees the amount.
    let recreated_amount = collateral_amount - voting_coin_amount;
    let reg_children: Vec<_> = sim.children(registration_coin_id);
    let recreated_reg = reg_children
        .iter()
        .find(|cs| cs.coin.amount == recreated_amount)
        .unwrap_or_else(|| {
            panic!(
                "expected a child of the spent Registration Coin at amount {} (CAT \
                 conservation: input collateral_amount = recreated + voting_coin_amount)",
                recreated_amount
            )
        });
    assert_eq!(
        recreated_reg.coin.parent_coin_info, registration_coin_id,
        "recreated Reg Coin must be parented by the spent Reg Coin",
    );

    // 9d. Ballot Coin singleton has been re-created (oracle is a
    // permissionless co-spend that recreates the ballot).
    let ballot_singleton_record = sim
        .coin_state(launched.eve_ballot_coin_id)
        .expect("eve Ballot Coin still tracked");
    assert!(
        ballot_singleton_record.spent_height.is_some(),
        "eve Ballot Coin must be spent (oracle co-spend) after cast_vote",
    );

    // 9e. Aggregator::collect_votes_for_ballot recovers the vote.
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = chip_voting_sdk::Aggregator::new(
        config.clone(),
        chain,
        NetworkType::Testnet11,
    );
    agg.sync().await.expect("aggregator sync");
    let votes = agg
        .collect_votes_for_ballot(created.ballot_launcher_id)
        .await
        .expect("collect_votes_for_ballot");
    assert_eq!(
        votes.len(),
        1,
        "expected exactly 1 VoteRecord for this ballot",
    );
    let v = &votes[0];
    assert_eq!(v.voter_pubkey, voter_pk, "vote record voter pubkey");
    assert_eq!(v.vote_data, vote_data, "vote record data");
    assert_eq!(
        v.ballot_launcher_id, created.ballot_launcher_id,
        "vote record ballot id",
    );
    assert_eq!(
        v.voting_coin_id, cast_result.voting_coin_id,
        "vote record voting coin id",
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
