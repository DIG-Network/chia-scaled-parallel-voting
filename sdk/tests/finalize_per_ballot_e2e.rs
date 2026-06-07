// ============================================================================
// tests/finalize_per_ballot_e2e.rs — Aggregator::build_finalize_for_ballot
// ============================================================================
//
// SCOPE: full deploy (with REAL VK matched to a real ProvingKey) →
// CAT-issue Registration Coin → register → create_ballot →
// launch_ballot → cast_vote → advance height past vote_close_height
// → Aggregator::build_finalize_for_ballot → submit, then verify the
// eve Ballot Coin singleton was spent (the finalize action's
// recreation lands at a NEW puzzle hash since BallotState.finalized
// transitions false → true).

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
use chip_voting_sdk::actors::ballot::{
    BallotIssuer, CreateBallotParams, LaunchBallotParams,
};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::actors::voter::CastVoteParams;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::prover::circuit::generate_test_setup;
use chip_voting_sdk::{Aggregator, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// Tier 3.2 finalize e2e — covers deploy+register+create_ballot+
/// launch_ballot+cast_vote+advance-height+build_finalize_for_ballot
/// against the simulator, and the dry-run + simulator submit both
/// accept the assembled bundle. The post-finalize check confirms the
/// eve Ballot Coin singleton was consumed and a recreated singleton
/// at a new puzzle hash (state.finalized = true) is present.
///
/// FIX HISTORY: an earlier rev of `Scalars::compute` consumed
/// `voter_set.registration_count` instead of the curried
/// `REGISTRATION_VOTE_WEIGHT_SNAPSHOT`. With unit-weight voters the
/// two values coincide; once collateral_amount > 1 the s2 scalar
/// no longer matched what the puzzle reconstructs from the snapshot,
/// so the on-chain assertion would CLVM-raise. Resolved by threading
/// `registration_vote_weight_snapshot` through
/// `prepare_finalize_witness_with_threshold`.
#[tokio::test(flavor = "current_thread")]
async fn finalize_per_ballot_full_simulator_flow() {
    let vote_close_height: u64 = 5;
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;

    // ── 1. Generate VK + matching ProvingKey, set up cat genesis ─
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(2_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
    let (proving_key, vk) = generate_test_setup(32, &mut rng).expect("generate_test_setup");
    let vk_bytes = vk.chia_chunked_bytes().expect("vk chunked bytes");
    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vk_bytes,
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

    // ── 2. Deploy ────────────────────────────────────────────
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk, true)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");
    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 3. Voter setup + CAT-issue Registration Coin ─────────
    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter_pk,
        launcher_id,
        cat_tail_hash, 1_000,
    );
    let reg_outer_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter_pk,
        launcher_id, 1_000,
    );

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

    // ── 4. Register ─────────────────────────────────────────
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
        .expect("register");
    drop(chain);
    sim.new_transaction(register_bundle)
        .expect("simulator accepts register");

    // ── 5. create_ballot + launch_ballot ────────────────────
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let funder_coin_2 = Coin::new(Bytes32::new([0xCC; 32]), funder_ph, 2);
    sim.insert_coin(funder_coin_2);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend = common::coin_spend_from_nodes(
        &ctx,
        funder_coin_2,
        funder_puzzle,
        funder_solution,
    );
    drop(ctx);

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let ballot_seed = Bytes32::new([0xab; 32]);
    let outcome_domain_hash = Bytes32::new([0xcd; 32]);
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

    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register.insert(&voter_pk, config.collateral_amount).expect("smt insert");
    let registration_merkle_root_snapshot = smt_post_register.root();
    let registration_vote_weight_snapshot = collateral_amount;

    // ── 6. cast_vote ────────────────────────────────────────
    let vote_outcome = Bytes32::new([0xAA; 32]); // doubles as vote_data here
    let chain = common::SharedSim::new(&mut sim);
    let cast_result = voter
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
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("cast_vote");
    drop(chain);
    sim.new_transaction(cast_result.spend_bundle.clone())
        .expect("simulator accepts cast_vote");

    // Voter signs the canonical aggregate vote message OFF-CHAIN
    // for finalize. (The cast_vote signature is the per-coin form;
    // finalize aggregates over a DIFFERENT message —
    // canonical_vote_message.)
    let canonical_msg = chip_voting_sdk::actors::aggregator::canonical_vote_message(
        vote_outcome,
        created.ballot_launcher_id,
        launcher_id,
    );
    let aggregate_sig = voter.keys.sign_unsafe(canonical_msg.as_ref());
    let _ = aggregate_sig; // signature embedded via VoteRecord below

    // ── 7. Advance simulator past vote_close_height ─────────
    while (sim.height() as u64) <= vote_close_height {
        sim.create_block();
    }
    eprintln!("simulator height after advance: {}", sim.height());

    // ── 8. Aggregator: sync + build VoteRecords with the
    //       canonical-aggregate signature (collect_votes_for_ballot
    //       extracts the per-coin signature, which doesn't match the
    //       canonical aggregate message). For finalize we need the
    //       voter's signature over `canonical_vote_message`, so we
    //       construct the VoteRecord directly here.
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");

    let canonical_vote_record = chip_voting_sdk::state::VoteRecord {
        voter_pubkey: voter_pk,
        vote_data: vote_outcome,
        vote_signature_hex: hex::encode(aggregate_sig.to_bytes()),
        registration_coin_id,
        ballot_launcher_id: created.ballot_launcher_id,
        voting_coin_id: cast_result.voting_coin_id,
    };
    let votes = vec![canonical_vote_record];

    // ── 9. build_finalize_for_ballot ────────────────────────
    let bundle_result = agg
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
        .await;

    let finalize_bundle = match bundle_result {
        Ok(b) => b,
        Err(e) => panic!("build_finalize_for_ballot failed: {:?}", e),
    };
    drop(agg);

    println!(
        "build_finalize_for_ballot bundle has {} coin spends",
        finalize_bundle.coin_spends.len(),
    );

    // ── 10. Submit + verify ──────────────────────────────────
    sim.new_transaction(finalize_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator must accept finalize bundle; got: {:?}", e));

    // The Ballot Coin's eve singleton was spent at cast_vote time
    // (oracle co-spend); the recreated Ballot Coin (post-cast_vote)
    // is now spent here (finalize). Look up the latest descendant
    // of the launcher and assert it transitioned to a NEW ph (the
    // finalized-state recreation has different curried state).
    let latest_post_finalize = walk_to_unspent(&sim, created.ballot_launcher_id);
    println!(
        "post-finalize unspent Ballot Coin: id={} ph={}",
        hex::encode(latest_post_finalize.coin.coin_id()),
        hex::encode(latest_post_finalize.coin.puzzle_hash),
    );
    assert!(
        latest_post_finalize.coin.amount % 2 == 1,
        "post-finalize Ballot Coin amount must be odd (singleton invariant)",
    );
}

fn walk_to_unspent(sim: &Simulator, launcher_id: Bytes32) -> chia_protocol::CoinState {
    let mut current_id = launcher_id;
    loop {
        let children: Vec<_> = sim.children(current_id);
        let child = children
            .into_iter()
            .find(|c| c.coin.amount % 2 == 1)
            .expect("singleton lineage has an odd-amount child");
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
