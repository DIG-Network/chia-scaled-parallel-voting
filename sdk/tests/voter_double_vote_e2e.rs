// ============================================================================
// tests/voter_double_vote_e2e.rs — SEC-SINGLE-VOTE-PER-BALLOT (CHIP.md §317)
// ============================================================================
//
// SCOPE: full deploy → CAT-issue Registration Coin → register →
// create_ballot → launch_ballot → cast_vote (B1) → ATTEMPT cast_vote
// (B1 again).
//
// CLAIM (CHIP.md §317): "Enforced on Registration Coin via the
// per-registration ballot SPT — `mint_voting_coin` proves
// non-membership before inserting `ballot_launcher_id`."
//
// WHAT THIS TEST PINS:
//   * The FIRST cast_vote runs through the simulator (CLVM-executing
//     proof of the on-chain non-membership path: `mint_voting_coin.rue`
//     proves the ballot's slot in `voted_ballots_root` was empty AND
//     inserts the new occupied leaf — see `compute_ballot_root` lines
//     106-130).
//   * The SECOND `Voter::cast_vote` for the same ballot returns Err
//     because the SDK can no longer find a fresh-state Registration
//     Coin (the recreated post-cast Registration Coin's
//     `voted_ballots_root` is no longer empty, so its puzzle hash is
//     no longer the `fresh_registration_coin_puzzle_hash`).
//
//     This is the SDK-level pre-flight guard. The deeper on-chain
//     enforcement is structurally pinned by the puzzle's
//     non-membership proof verification — which the FIRST successful
//     cast_vote already exercises end-to-end. If a hand-built bundle
//     attempted to spend the post-cast Registration Coin via
//     `mint_voting_coin` again with siblings claiming non-membership
//     of an already-occupied slot, `compute_ballot_root` would
//     reconstruct a root NOT equal to the curried `voted_ballots_root`
//     and the puzzle would trap.
//
// COMPLEMENT: `chip_spec_compliance.rs::chip_single_vote_per_ballot_run_program_traps_on_occupied_slot`
// runs `clvmr::run_program` against `mint_voting_coin.rue` directly to
// pin the puzzle-level non-membership trap.

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
use chip_voting_sdk::actors::voter::CastVoteParams;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn voter_double_vote_for_same_ballot_rejected() {
    // ── 1. Set up simulator + CAT genesis (mirrors voter_cast_vote_e2e) ──
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
    let _registration_coin_id = registration_cat.coin.coin_id();

    // ── 5. register ────────────────────────────────────────
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

    // ── 6. create_ballot + launch_ballot (one ballot — call it B1) ─
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

    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;

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
    sim.new_transaction(_launched.spend_bundle.clone())
        .expect("simulator accepts launch_ballot bundle");

    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register.insert(&voter_pk, config.collateral_amount).expect("smt insert");
    let registration_merkle_root_snapshot = smt_post_register.root();
    let registration_vote_weight_snapshot = collateral_amount;

    // ── 7. FIRST cast_vote on B1 — MUST succeed (CLVM-executing
    //       proof that the on-chain non-membership-then-insert path
    //       runs cleanly through `mint_voting_coin.rue`) ──────────
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
        .expect("first cast_vote must succeed");
    drop(chain);

    sim.new_transaction(cast_result.spend_bundle.clone())
        .expect("simulator must accept FIRST cast_vote bundle");

    // ── 8. SECOND cast_vote on the SAME ballot B1 — MUST fail.
    // After the first cast_vote, the Registration Coin's
    // `voted_ballots_root` is no longer empty (B1 is now an
    // occupied leaf); the SDK looks up the voter's Registration Coin
    // by `fresh_registration_coin_puzzle_hash` (which curries an
    // EMPTY voted_ballots_root). The recreated post-cast Registration
    // Coin has a DIFFERENT puzzle hash, so the SDK cannot find a
    // fresh-state Registration Coin to spend — guard fires.
    //
    // This is the SDK-level pre-flight guard for SEC-SINGLE-VOTE-PER-BALLOT.
    // The deeper on-chain mechanism (the `mint_voting_coin.rue`
    // non-membership proof against an occupied slot) is exercised
    // CLVM-end-to-end by the FIRST cast above (positive path) and
    // by `chip_single_vote_per_ballot_run_program_traps_on_occupied_slot`
    // in `chip_spec_compliance.rs` (negative path via run_program).
    let chain = common::SharedSim::new(&mut sim);
    let second_result = voter
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
        .await;
    drop(chain);
    assert!(
        second_result.is_err(),
        "CHIP.md §317 (SEC-SINGLE-VOTE-PER-BALLOT): a SECOND cast_vote \
         for the SAME ballot from the same Registration Coin lineage \
         MUST be rejected. The SDK pre-flight guard is the first line \
         of defense (no fresh-state Registration Coin found because \
         `voted_ballots_root` is now non-empty). Got Ok which means \
         the guard regressed."
    );
    let err_msg = format!("{:?}", second_result.err().unwrap());
    assert!(
        err_msg.contains("no unspent Registration Coin"),
        "expected 'no unspent Registration Coin at predicted ph' error \
         from SDK guard, got: {}",
        err_msg
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
