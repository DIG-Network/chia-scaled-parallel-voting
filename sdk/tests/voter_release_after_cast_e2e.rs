// ============================================================================
// tests/voter_release_after_cast_e2e.rs — release_collateral after cast_vote
// ============================================================================
//
// SCOPE: drives `Voter::release_collateral` AFTER a successful
// `cast_vote`. Pre-Gap-3 fix this fails because the SDK predicts the
// Registration Coin's CAT-wrapped puzzle hash from a "fresh"
// RegistrationState (`voted_ballots_root = empty_ballot_root()`)
// while the on-chain coin's actual puzzle hash reflects the post-cast
// `voted_ballots_root` (with `ballot_launcher_id` inserted at its
// SPT slot).
//
// EXPECTED:
//   * Pre-fix: `Voter::release_collateral` returns
//     `"registration coin puzzle hash ... doesn't match predicted
//     fresh-state CAT-wrapped ph ..."`.
//   * Post-fix: returns Ok(_), the simulator accepts the bundle, the
//     Registration Coin is spent, and a new CAT child appears at
//     `CAT(tail_hash, destination)` with `amount == collateral_amount -
//     voting_coin_amount` (the residual collateral after the
//     voting-coin mint).
//
// WHY: pins the Gap (3) fix at the post-cast Registration Coin
// puzzle-hash boundary. `voter_release_collateral_e2e.rs` covers the
// never-cast path; this is the first regression for the post-cast
// path, which the live integration test exercises end-to-end.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::{CatArgs, GenesisByCoinIdTailArgs};
use chia_sdk_driver::{Cat, SpendContext, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::ballot::{BallotIssuer, CreateBallotParams, LaunchBallotParams};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::actors::voter::CastVoteParams;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn voter_release_collateral_after_cast_vote_full_flow() {
    // ── 1. Set up the simulator + the CAT genesis coin ───────
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

    // ── 3. Voter setup + Registration Coin issuance ─────────
    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id);

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
    let registration_coin_id_at_register = registration_cat.coin.coin_id();

    // ── 4. Run Voter::register ────────────────────────────────
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
    sim.new_transaction(register_bundle).expect("simulator accepts register");

    // ── 5. Build a (1, 2) ballot + cast voter's vote ─────────
    // Use a (1, 2) threshold so the on-chain finalize is achievable;
    // we don't actually finalize here (we go straight to release),
    // but the cast_vote spend uses the same params.
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let funder_coin_2 = Coin::new(Bytes32::new([0xCC; 32]), funder_ph, 2);
    sim.insert_coin(funder_coin_2);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend = common::coin_spend_from_nodes(
        &ctx, funder_coin_2, funder_puzzle, funder_solution,
    );
    drop(ctx);

    let pre_ballot_height = sim.height() as u64;
    let vote_close_height: u64 = pre_ballot_height + 5;
    let outcome_domain_hash = Bytes32::new([0xCD; 32]);
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;
    let registration_merkle_root_snapshot = {
        let mut s = SparseMerkleTree::new();
        s.insert(&voter_pk, config.collateral_amount).expect("smt insert");
        s.root()
    };
    let registration_vote_weight_snapshot = collateral_amount;

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let chain = common::SharedSim::new(&mut sim);
    let created = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed: Bytes32::new([0xab; 32]),
                vote_close_height,
                outcome_domain_hash,
                vote_options_root: Bytes32::default(),
            },
            funder_spend,
        )
        .await
        .expect("create_ballot");
    drop(chain);
    sim.new_transaction(created.spend_bundle.clone()).expect("create_ballot accepted");

    let chain = common::SharedSim::new(&mut sim);
    let _launched = issuer
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
    sim.new_transaction(_launched.spend_bundle.clone()).expect("launch_ballot accepted");

    let voting_coin_amount: u64 = 1;
    let vote_outcome = Bytes32::new([0xAA; 32]);

    let chain = common::SharedSim::new(&mut sim);
    let _cast = voter
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
                voting_coin_amount,
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("voter cast_vote");
    drop(chain);
    sim.new_transaction(_cast.spend_bundle.clone()).expect("simulator accepts cast_vote");

    // The original Registration Coin has been spent. There's now a
    // RECREATED Registration Coin at a NEW puzzle hash (post-cast
    // voted_ballots_root) with `amount == collateral_amount -
    // voting_coin_amount`. Find it.
    let post_register_orig = sim
        .coin_state(registration_coin_id_at_register)
        .expect("original registration coin still tracked");
    assert!(
        post_register_orig.spent_height.is_some(),
        "original Registration Coin must be spent by cast_vote",
    );

    let recreated_amount = collateral_amount - voting_coin_amount;
    let post_cast_reg_coin = find_recreated_registration_coin(
        &sim,
        registration_coin_id_at_register,
        recreated_amount,
    );
    let post_cast_reg_coin_id = post_cast_reg_coin.coin_id();

    // ── 6. release_collateral against the post-cast Registration Coin
    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register.insert(&voter_pk, config.collateral_amount).expect("smt insert");

    let destination = Bytes32::new([0xDD; 32]);
    let chain = common::SharedSim::new(&mut sim);
    let release_bundle = voter
        .release_collateral(
            &chain,
            &smt_post_register,
            post_cast_reg_coin_id,
            destination,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Voter::release_collateral MUST succeed against the post-cast Registration Coin \
                 (Gap 3 fix): {:?}",
                e
            )
        });
    drop(chain);

    sim.new_transaction(release_bundle)
        .unwrap_or_else(|e| panic!("simulator accepts release bundle: {:?}", e));

    // ── 7. Assert outputs ─────────────────────────────────────
    let post_reg = sim
        .coin_state(post_cast_reg_coin_id)
        .expect("post-cast Registration Coin tracked");
    assert!(
        post_reg.spent_height.is_some(),
        "post-cast Registration Coin must be spent after release_collateral",
    );

    // The released CAT child carries `recreated_amount` mojos
    // (collateral_amount - voting_coin_amount), since the voting
    // coin already consumed `voting_coin_amount` from the original
    // collateral.
    let dest_cat_th = CatArgs::curry_tree_hash(cat_tail_hash, destination.into());
    let dest_cat_ph = Bytes32::new(dest_cat_th.to_bytes());
    let coin_states = sim.lookup_puzzle_hashes(indexmap::indexset![dest_cat_ph], false);
    assert!(
        coin_states.iter().any(|cs| {
            cs.coin.amount == recreated_amount
                && cs.coin.parent_coin_info == post_cast_reg_coin_id
        }),
        "expected a new CAT child at {} with amount {} and parent {} after release_collateral; \
         got {} unrelated coins",
        hex::encode(dest_cat_ph),
        recreated_amount,
        hex::encode(post_cast_reg_coin_id),
        coin_states.len(),
    );
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Walk the simulator from the original Registration Coin id to the
/// recreated post-cast Registration Coin (same voter, same election —
/// distinguishable by `amount == collateral_amount - voting_coin_amount`
/// and parent == original registration coin id).
fn find_recreated_registration_coin(
    sim: &Simulator,
    parent_id: Bytes32,
    expected_amount: u64,
) -> chia_protocol::Coin {
    let children = sim.children(parent_id);
    children
        .into_iter()
        .map(|cs| cs.coin)
        .find(|c| c.amount == expected_amount)
        .expect("recreated Registration Coin not found among children of original")
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
