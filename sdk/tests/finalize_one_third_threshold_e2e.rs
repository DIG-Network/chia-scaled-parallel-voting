// ============================================================================
// tests/finalize_one_third_threshold_e2e.rs — finalize with (1/3) threshold
// ============================================================================
//
// SCOPE: deploy → CAT-issue 2 Registration Coins → register voter1 +
// voter2 → create_ballot (threshold 1/3) → launch_ballot →
// voter1.cast_vote (only voter1 votes) → advance height →
// build_finalize_for_ballot → submit.
//
// Demonstrates SDK Gap (2):
// `Aggregator::prepare_finalize_witness_with_threshold`'s pre-check 4
// rejects votes whenever `2 * votes.len() <= registration_count`.
// With 2 registered voters and 1 vote, that's `2 * 1 <= 2` → rejected
// with `BelowThreshold`, despite the curried `(1, 3)` threshold being
// satisfied weight-wise: signed_weight (1000) * 3 >= 1 *
// total_weight (2000).
//
// EXPECTED: this test PANICS pre-fix (BelowThreshold) and PASSES
// post-fix (the weight-based check matches the curried threshold).

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use ark_std::rand::SeedableRng;
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::GenesisByCoinIdTailArgs;
use chia_sdk_driver::{Cat, SpendContext, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::aggregator::BuildFinalizeForBallotParams;
use chip_voting_sdk::actors::ballot::{BallotIssuer, CreateBallotParams, LaunchBallotParams};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::actors::voter::CastVoteParams;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::prover::circuit::generate_test_setup;
use chip_voting_sdk::{Aggregator, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn finalize_one_third_threshold_with_one_of_two_voters() {
    // ── 1. Trusted setup + sim + cat genesis ────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(10_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x0CDEF1);
    let (proving_key, vk) = generate_test_setup(&mut rng).expect("generate_test_setup");
    let vk_bytes = vk.chia_chunked_bytes().expect("vk chunked bytes");

    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vk_bytes,
        },
        cat_tail_hash,
        collateral_amount,
        election_start_height: 0,
        label: None,
    };

    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");
    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 2. Two voters; mint both Registration Coins in one issuance ─
    let voter1_keys = test_voter_keys(0x03u8);
    let voter2_keys = test_voter_keys(0x04u8);
    let voter1_pk = voter1_keys.pubkey;
    let voter2_pk = voter2_keys.pubkey;

    let reg_inner_ph_1 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter1_pk, launcher_id, cat_tail_hash,
    );
    let reg_outer_ph_1 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter1_pk, launcher_id,
    );
    let reg_inner_ph_2 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter2_pk, launcher_id, cat_tail_hash,
    );
    let reg_outer_ph_2 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter2_pk, launcher_id,
    );

    let mut ctx = SpendContext::new();
    let memos_1 = ctx.hint(reg_outer_ph_1).expect("hint v1");
    let memos_2 = ctx.hint(reg_outer_ph_2).expect("hint v2");
    let extra_conditions = Conditions::new()
        .create_coin(reg_inner_ph_1, collateral_amount, memos_1)
        .create_coin(reg_inner_ph_2, collateral_amount, memos_2);
    let total_amount = 2 * collateral_amount;
    let (xch_conditions, cats) = Cat::issue_with_coin(
        &mut ctx,
        cat_genesis.coin.coin_id(),
        total_amount,
        extra_conditions,
    )
    .expect("Cat::issue_with_coin (two voters)");
    StandardLayer::new(cat_genesis.pk)
        .spend(&mut ctx, cat_genesis.coin, xch_conditions)
        .expect("StandardLayer::spend(cat_genesis)");
    let issuance_spends = ctx.take();
    sim.spend_coins(issuance_spends, std::slice::from_ref(&cat_genesis.sk))
        .expect("simulator accepts CAT issuance bundle");

    let registration_coin_1_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_1)
        .map(|c| c.coin.coin_id())
        .expect("voter1 CAT child");
    let _registration_coin_2_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_2)
        .map(|c| c.coin.coin_id())
        .expect("voter2 CAT child");

    // ── 3. Register both voters ─────────────────────────────
    let smt_pre_v1 = SparseMerkleTree::new();
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter1_keys, collateral_amount, smt_pre_v1).await;
    let mut smt_post_v1 = SparseMerkleTree::new();
    smt_post_v1.insert(&voter1_pk).expect("smt insert v1");
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter2_keys, collateral_amount, smt_post_v1.clone()).await;
    let mut smt_post_v2 = smt_post_v1.clone();
    smt_post_v2.insert(&voter2_pk).expect("smt insert v2");
    let registration_merkle_root_snapshot = smt_post_v2.root();
    let registration_vote_weight_snapshot = 2 * collateral_amount;

    // ── 4. create_ballot + launch_ballot with (1, 3) threshold ─
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let funder_coin_2 = Coin::new(Bytes32::new([0xCC; 32]), funder_ph, 2);
    sim.insert_coin(funder_coin_2);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend =
        common::coin_spend_from_nodes(&ctx, funder_coin_2, funder_puzzle, funder_solution);
    drop(ctx);

    let pre_ballot_height = sim.height() as u64;
    let vote_close_height: u64 = pre_ballot_height + 5;
    let outcome_domain_hash = Bytes32::new([0xCD; 32]);
    // 1/3 threshold: weight check is 1000 * 3 >= 1 * 2000 (3000 >= 2000),
    // satisfied; but COUNT-based check is 2*1 > 2 (false) — rejects pre-fix.
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 3;

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let chain = common::SharedSim::new(&mut sim);
    let created = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed: Bytes32::new([0xab; 32]),
                vote_close_height,
                outcome_domain_hash,
            },
            funder_spend,
        )
        .await
        .expect("create_ballot");
    drop(chain);
    sim.new_transaction(created.spend_bundle.clone())
        .expect("simulator accepts create_ballot");

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
            },
        )
        .await
        .expect("launch_ballot");
    drop(chain);
    sim.new_transaction(launched.spend_bundle.clone())
        .expect("simulator accepts launch_ballot");

    // ── 5. Only voter1 casts ───────────────────────────────
    let voter1 = Voter::new(config.clone(), voter1_keys, NetworkType::Testnet11);
    let vote_outcome = Bytes32::new([0xAA; 32]);

    let chain = common::SharedSim::new(&mut sim);
    let cast_v1 = voter1
        .cast_vote(
            &chain,
            CastVoteParams {
                ballot_launcher_id: created.ballot_launcher_id,
                vote_data: vote_outcome,
                vote_close_height,
                vote_threshold_num,
                vote_threshold_den,
                registration_merkle_root_snapshot,
                registration_vote_weight_snapshot,
                voting_coin_amount: 1,
            },
        )
        .await
        .expect("voter1 cast_vote");
    drop(chain);
    sim.new_transaction(cast_v1.spend_bundle.clone())
        .expect("simulator accepts voter1 cast_vote");

    // ── 6. Advance + finalize ──────────────────────────────
    while (sim.height() as u64) <= vote_close_height {
        sim.create_block();
    }

    let canonical_msg = chip_voting_sdk::actors::aggregator::canonical_vote_message(
        vote_outcome,
        created.ballot_launcher_id,
        launcher_id,
    );
    let v1_sig = voter1.keys.sign_unsafe(canonical_msg.as_ref());
    let votes = vec![chip_voting_sdk::state::VoteRecord {
        voter_pubkey: voter1_pk,
        vote_data: vote_outcome,
        vote_signature_hex: hex::encode(v1_sig.to_bytes()),
        registration_coin_id: registration_coin_1_id,
        ballot_launcher_id: created.ballot_launcher_id,
        voting_coin_id: cast_v1.voting_coin_id,
    }];

    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");

    let finalize_bundle = agg
        .build_finalize_for_ballot(BuildFinalizeForBallotParams {
            ballot_launcher_id: created.ballot_launcher_id,
            vote_outcome,
            votes: &votes,
            vote_close_height,
            vote_threshold_num,
            vote_threshold_den,
            registration_merkle_root_snapshot,
            registration_vote_weight_snapshot,
            proving_key: &proving_key,
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "build_finalize_for_ballot MUST succeed for (1/3) threshold with \
                 weight 1000/2000 = 50% (>= 33.3%): {:?}",
                e
            )
        });
    drop(agg);

    sim.new_transaction(finalize_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator accepts finalize bundle: {:?}", e));

    let post = walk_to_unspent(&sim, created.ballot_launcher_id);
    assert!(post.coin.amount % 2 == 1, "post-finalize Ballot Coin must be odd-amount");
    assert_ne!(
        post.coin.puzzle_hash,
        launched.eve_ballot_puzzle_hash,
        "post-finalize Ballot Coin must transition state finalized=false→true",
    );
}

// ─── Helpers ───────────────────────────────────────────────────────

async fn register_voter(
    sim: &mut Simulator,
    cat_tail_hash: Bytes32,
    launcher_id: Bytes32,
    config: &chip_voting_sdk::config::ElectionConfig,
    voter_keys: &VoterKeys,
    collateral_amount: u64,
    smt_pre_register: SparseMerkleTree,
) {
    let voter_pk = voter_keys.pubkey;
    let reg_outer_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter_pk,
        launcher_id,
    );

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
    let announcer_parent = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"announcer-onethird");
        h.update(voter_pk.to_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        Bytes32::new(arr)
    };
    let announcer_coin = Coin::new(announcer_parent, announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let cat_parent_spend = common::coin_spend_from_nodes(
        &ctx,
        announcer_coin,
        announcer_node,
        announcer_solution,
    );
    drop(ctx);

    let voter = Voter::new(
        config.clone(),
        VoterKeys::new(voter_keys.secret.clone()),
        NetworkType::Testnet11,
    );
    let chain = common::SharedSim::new(sim);
    let register_bundle = voter
        .register(&smt_pre_register, cat_parent_spend, &chain)
        .await
        .expect("Voter::register");
    drop(chain);
    sim.new_transaction(register_bundle)
        .expect("simulator accepts register bundle");
}

fn walk_to_unspent(sim: &Simulator, launcher_id: Bytes32) -> chia_protocol::CoinState {
    let mut current_id = launcher_id;
    loop {
        let children: Vec<_> = sim.children(current_id);
        let child = children
            .into_iter()
            .find(|c| c.coin.amount % 2 == 1)
            .expect("singleton lineage has odd-amount child");
        if child.spent_height.is_none() {
            return child;
        }
        current_id = child.coin.coin_id();
    }
}

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
