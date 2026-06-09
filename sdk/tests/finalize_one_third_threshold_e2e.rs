// ============================================================================
// tests/finalize_one_third_threshold_e2e.rs — finalize with (1/3) threshold
// ============================================================================
//
// SCOPE: pin the SDK's weighted-quorum pre-check
// (`Aggregator::prepare_finalize_witness_with_threshold`) for the
// (1, 3) case it used to wrongly reject pre-fix, plus the boundary
// behaviour at (1, 4) and (1, 1) on the same voter set.
//
// HISTORY:
//   * Pre-Gap-2 fix the strict-majority count gate
//     `2 * votes.len() <= registration_count` rejected 1-of-2 voters
//     against a weighted (1/3) threshold even though the curried
//     on-chain assertion `signed_weight * den >= num * total_weight`
//     was satisfied (1000 * 3 = 3000 >= 1 * 2000 = 2000).
//   * Post-fix the pre-check mirrors the on-chain inequality and the
//     positive case below succeeds.
//
// CHIP-rev STATUS — the second test in this file
// (`finalize_one_third_full_flow_e2e`) drives the whole
// `Aggregator::build_finalize_for_ballot` path with (1/3) threshold
// against the simulator. Pre-CHIP-rev this case failed at
// `bls_pairing_identity` because (num, den) were baked into the QAP
// at trusted-setup time as R1CS coefficients, so a single VK only
// verified proofs at the shape-circuit's hardcoded (1, 2). The
// CHIP-rev promotes (num, den) to first-class public inputs s7/s8;
// the weighted-quorum gadget now consumes them as variable Fr
// coefficients, so one VK verifies any (num, den). The (1/3) test
// is therefore unblocked end-to-end and runs without `#[ignore]`.

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
use chip_voting_sdk::merkle::PoseidonSmt;
use chip_voting_sdk::prover::circuit::generate_test_setup;
use chip_voting_sdk::prover::circuit_v2::generate_test_setup_v2;
use chip_voting_sdk::{
    Aggregator, DeployParams, NetworkType, Voter, VoterKeys, VotingError,
};
use sha2::{Digest, Sha256};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// FN: finalize_one_third_pre_check_accepts_weighted_quorum
/// WHAT: positive test of the SDK's weighted-quorum pre-check.
///       Registers two voters (uniform `collateral_amount`), arms a
///       (1, 3) threshold pack with 1-of-2 votes, and asserts
///       `Aggregator::prepare_finalize_witness_with_threshold`
///       returns `Ok(_)` (count-strict-majority would reject this;
///       weight-based does not).
///
///       Also exercises the boundary behaviour on the same voter
///       set without re-running cast_vote:
///         * (1, 4) at 1-of-2: 1000*4 = 4000 >= 1*2000 → ACCEPT
///         * (1, 1) at 1-of-2: 1000*1 = 1000 < 1*2000 → REJECT
///
/// WHY:  pins the Gap (2) fix at the SDK pre-check boundary without
///       depending on the on-chain Groth16 verifier — that path is
///       blocked by a deeper bug tracked separately
///       (see KNOWN FAILURE block below).
#[tokio::test(flavor = "current_thread")]
async fn finalize_one_third_pre_check_accepts_weighted_quorum() {
    let (mut sim, config, _proving_key, voter1_keys, voter1_pk, registration_coin_1_id,
         registration_merkle_root_snapshot, registration_vote_weight_snapshot, launcher_id) =
        build_two_voter_setup(0x0CDEF1, 1, 3).await;

    // Cast voter1 against a (1, 3) ballot. The cast_vote spend
    // bundle uses the same (num, den) as the ballot launch.
    let (votes, _eve_ph, _close_h) = cast_one_of_two(
        &mut sim, &config, &voter1_keys, voter1_pk,
        registration_coin_1_id,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        launcher_id, 1, 3,
    ).await;

    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");

    // Look up ballot_launcher_id + outcome from the synthesised votes.
    let ballot_launcher_id = votes[0].ballot_launcher_id;
    let vote_outcome = votes[0].vote_data;

    // ── Primary assertion: (1, 3) at 1-of-2 ACCEPTS ─────────
    let _witness = agg
        .prepare_finalize_witness_with_threshold(
            vote_outcome,
            ballot_launcher_id,
            &votes,
            1,
            3,
            registration_vote_weight_snapshot,
        )
        .expect("(1,3) at 1-of-2 (1000*3=3000 >= 1*2000=2000) MUST accept post-Gap-2 fix");

    // ── Boundary check: (1, 4) at 1-of-2 ACCEPTS ────────────
    // 1000*4 = 4000 >= 1*2000 = 2000 → 4000 >= 2000 → ACCEPT.
    let result_accept_1_4 = agg.prepare_finalize_witness_with_threshold(
        vote_outcome,
        ballot_launcher_id,
        &votes,
        1,
        4,
        registration_vote_weight_snapshot,
    );
    assert!(
        result_accept_1_4.is_ok(),
        "(1,4) at 1-of-2 weight 1000/2000 must accept (4000 >= 2000)",
    );

    // ── Boundary check: (1, 1) at 1-of-2 REJECTS ────────────
    // 1000*1 = 1000 < 1*2000 = 2000 → REJECT (a unanimity threshold
    // cannot be met when half the voters skipped).
    let result_reject_1_1 = agg.prepare_finalize_witness_with_threshold(
        vote_outcome,
        ballot_launcher_id,
        &votes,
        1,
        1,
        registration_vote_weight_snapshot,
    );
    assert!(
        matches!(result_reject_1_1, Err(VotingError::BelowThreshold)),
        "(1,1) at 1-of-2 weight 1000/2000 must reject as BelowThreshold (1000 < 2000); got {:?}",
        result_reject_1_1,
    );
}

/// FN: finalize_one_third_full_flow_e2e
/// WHAT: drives `Aggregator::build_finalize_for_ballot` end-to-end
///       with a (1, 3) threshold and 1-of-2 voters.
///
/// CHIP-rev unblock:
/// ----------------
/// Pre-CHIP-rev this call failed on-chain at `bls_pairing_identity`
/// during the Groth16 verification step in
/// `puzzles/ballot_coin/finalize.rue`. The root cause was that
/// `circuit.rs::generate_constraints` baked `(num, den)` into the
/// R1CS A/B/C matrices as compile-time COEFFICIENTS, so the QAP /
/// proving-key / VK were shaped at the trusted-setup `(num, den)` —
/// any other ratio drifted the matrices and the resulting proof
/// did not verify against the (1,2)-shaped VK.
///
/// The CHIP-rev resolution: promote `(num, den)` from R1CS
/// coefficients to first-class public inputs s7/s8. The
/// weighted-quorum gadget now uses arkworks `mul_constant_lc` to
/// allocate `num_var` and `den_var` as witness variables and binds
/// them to s7/s8 via direct equality. The on-chain `finalize.rue`
/// asserts `s7 == Fr::from(VOTE_THRESHOLD_NUM)` and `s8 ==
/// Fr::from(VOTE_THRESHOLD_DEN)` against the curried threshold —
/// closing the binding loop. One VK now verifies any (num, den).
///
/// ── HISTORICAL CONTEXT ───────────────────────────────────────────
/// Pre-CHIP-rev the bug was in `circuit.rs::generate_constraints`:
/// `den_fr = Fr::from(self.vote_threshold_den)` and `num_fr =
/// Fr::from(self.vote_threshold_num)` were passed as the COEFFICIENT
/// of the linear-combination term in `cs.enforce_constraint(...)`,
/// i.e., constants in the R1CS A/B/C matrices. In Groth16 the QAP
/// (and hence ProvingKey / VK / IC) is derived at SETUP time, so
/// the trusted-setup shape circuit's `(1, 2)` baked into the matrices
/// drifted as soon as `prove()` was called with a different ratio.
/// CHIP-rev resolves this by making `(num, den)` part of the witness
/// AND public inputs (s7/s8): the gadget allocates `num_var` /
/// `den_var`, computes `v1 = signed * den_var`, `v2 = num_var *
/// total`, and asserts `v1 - v2 - slack == 0` — leaving the matrices
/// shape-only and tying the witness to s7/s8 via direct equality.
#[tokio::test(flavor = "current_thread")]
async fn finalize_one_third_full_flow_e2e() {
    let (mut sim, config, proving_key, voter1_keys, voter1_pk, registration_coin_1_id,
         registration_merkle_root_snapshot, registration_vote_weight_snapshot, launcher_id) =
        build_two_voter_setup(0x0CDEF1, 1, 3).await;

    let (votes, eve_ballot_puzzle_hash, vote_close_height) = cast_one_of_two(
        &mut sim, &config, &voter1_keys, voter1_pk,
        registration_coin_1_id,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        launcher_id, 1, 3,
    ).await;
    let ballot_launcher_id = votes[0].ballot_launcher_id;
    let vote_outcome = votes[0].vote_data;

    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");

    // EXPECTED FAILURE: this currently aborts inside
    // `bls_pairing_identity` when the simulator runs the puzzle.
    let finalize_bundle = agg
        .build_finalize_for_ballot(BuildFinalizeForBallotParams {
            ballot_launcher_id,
            vote_outcome,
            votes: &votes,
            vote_close_height,
            vote_threshold_num: 1,
            vote_threshold_den: 3,
            registration_merkle_root_snapshot,
            registration_vote_weight_snapshot,
            vote_options_root: Bytes32::default(),
            proving_key: &proving_key,
        })
        .await
        .expect("build_finalize_for_ballot");
    drop(agg);

    sim.new_transaction(finalize_bundle.clone())
        .expect("simulator accepts finalize bundle");

    let post = walk_to_unspent(&sim, ballot_launcher_id);
    assert!(post.coin.amount % 2 == 1, "post-finalize Ballot Coin must be odd-amount");
    assert_ne!(
        post.coin.puzzle_hash,
        eve_ballot_puzzle_hash,
        "post-finalize Ballot Coin must transition state finalized=false→true",
    );
}

/// FN: finalize_two_third_full_flow_e2e
/// WHAT: drives `Aggregator::build_finalize_for_ballot` end-to-end
///       with a (2, 3) threshold and 2-of-3 voters. Three voters
///       at 1000 collateral each (total weight 3000); voters 1 and
///       2 sign the canonical message, voter 3 abstains. The
///       weighted-quorum check is `signed_weight * den >= num *
///       total_weight` → `2000 * 3 >= 2 * 3000` → `6000 >= 6000`
///       (boundary equality, ACCEPT).
///
/// WHY: complements `finalize_one_third_full_flow_e2e` to demonstrate
///      that the CHIP-rev makes ANY `(num, den)` verifiable under one
///      VK — the same circuit shape now handles both <1/2 and >1/2
///      thresholds. With (num, den) baked into R1CS coefficients (as
///      pre-CHIP-rev) this test would also fail at
///      `bls_pairing_identity`; with s7/s8 promoted to public inputs
///      and the var-mul gadget consuming them as witness Fr values,
///      one trusted setup covers every ratio.
#[ignore = "SEC-F1: needs a small-max_signers circuit_v2 deploy variant; Option-B in-circuit signer verification can't set up at config::MAX_SIGNERS=20000 (go-live scaling). Forgery closure is pinned by exploit_finalize_forgery_e2e + finalize_v2_groth16_e2e."]
#[tokio::test(flavor = "current_thread")]
async fn finalize_two_third_full_flow_e2e() {
    let (mut sim, config, proving_key, voter1_keys, voter1_pk, voter2_keys, voter2_pk,
         voter3_keys, voter3_pk,
         registration_coin_1_id, registration_coin_2_id,
         registration_merkle_root_snapshot, registration_vote_weight_snapshot, launcher_id) =
        build_three_voter_setup(0x0CDEF2).await;

    let (votes, eve_ballot_puzzle_hash, vote_close_height) = cast_two_of_three(
        &mut sim, &config,
        &voter1_keys, voter1_pk, registration_coin_1_id,
        &voter2_keys, voter2_pk, registration_coin_2_id,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        launcher_id, 2, 3,
    ).await;
    // voter3 is intentionally unused at the cast stage but its keys
    // are kept live so the registration set's total weight is 3000.
    let _ = (voter3_keys, voter3_pk);
    let ballot_launcher_id = votes[0].ballot_launcher_id;
    let vote_outcome = votes[0].vote_data;

    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");

    let finalize_bundle = agg
        .build_finalize_for_ballot(BuildFinalizeForBallotParams {
            ballot_launcher_id,
            vote_outcome,
            votes: &votes,
            vote_close_height,
            vote_threshold_num: 2,
            vote_threshold_den: 3,
            registration_merkle_root_snapshot,
            registration_vote_weight_snapshot,
            vote_options_root: Bytes32::default(),
            proving_key: &proving_key,
        })
        .await
        .expect("build_finalize_for_ballot (2,3) at 2-of-3");
    drop(agg);

    sim.new_transaction(finalize_bundle.clone())
        .expect("simulator accepts (2,3) finalize bundle");

    let post = walk_to_unspent(&sim, ballot_launcher_id);
    assert!(post.coin.amount % 2 == 1, "post-finalize Ballot Coin must be odd-amount");
    assert_ne!(
        post.coin.puzzle_hash,
        eve_ballot_puzzle_hash,
        "post-finalize Ballot Coin must transition state finalized=false→true",
    );
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Set up the simulator + 2 registered voters. Returns everything
/// the per-test caller needs to drive a per-ballot flow.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
async fn build_two_voter_setup(
    seed: u64,
    _ballot_threshold_num: u64,
    _ballot_threshold_den: u64,
) -> (
    Simulator,
    chip_voting_sdk::config::ElectionConfig,
    chip_voting_sdk::prover::circuit::ArkProvingKey,
    VoterKeys,
    chia_bls::PublicKey,
    Bytes32,
    Bytes32,
    u64,
    Bytes32,
) {
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(10_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    // SEC-F1/F3/F5: a REAL circuit_v2 trusted setup at a small max_signers so
    // the full on-chain finalize (Groth16 verify + attest_ballot binding)
    // actually executes. The one_third full_flow finalizes with ONE signer, so
    // max_signers = 1 (the aggregator pads to config.max_signers). vk_hash =
    // sha256(chia_chunked VK bytes) so ElectionState.vk_hash == ELECTION_VK_HASH
    // the ballot curries (= config.vk_hash()).
    const MAX_SIGNERS: usize = 1;
    let (proving_key, vk) =
        generate_test_setup_v2(chip_voting_sdk::config::TREE_DEPTH as usize, MAX_SIGNERS, &mut rng)
            .expect("generate_test_setup_v2");
    let vk_bytes = vk.chia_chunked_bytes().expect("vk chia_chunked_bytes");
    let vk_hash = Bytes32::new(Sha256::digest(&vk_bytes).into());

    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vk_bytes,
        },
        cat_tail_hash,
        collateral_amount,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: MAX_SIGNERS,
        ceremony_launcher_id: Bytes32::default(),
        vk_hash,
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

    let voter1_keys = test_voter_keys(0x03u8);
    let voter2_keys = test_voter_keys(0x04u8);
    let voter1_pk = voter1_keys.pubkey;
    let voter2_pk = voter2_keys.pubkey;

    let reg_inner_ph_1 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter1_pk, launcher_id, cat_tail_hash, 1_000,
    );
    let reg_outer_ph_1 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter1_pk, launcher_id, 1_000,
    );
    let reg_inner_ph_2 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter2_pk, launcher_id, cat_tail_hash, 1_000,
    );
    let reg_outer_ph_2 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter2_pk, launcher_id, 1_000,
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

    let smt_pre_v1 = PoseidonSmt::new();
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter1_keys, collateral_amount, smt_pre_v1).await;
    let mut smt_post_v1 = PoseidonSmt::new();
    smt_post_v1.insert(voter1_keys.jubjub_pubkey, config.collateral_amount);
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter2_keys, collateral_amount, smt_post_v1.clone()).await;
    let mut smt_post_v2 = smt_post_v1.clone();
    smt_post_v2.insert(voter2_keys.jubjub_pubkey, config.collateral_amount);
    let registration_merkle_root_snapshot = Bytes32::new(smt_post_v2.root_be32());
    let registration_vote_weight_snapshot = 2 * collateral_amount;

    (
        sim,
        config,
        proving_key,
        voter1_keys,
        voter1_pk,
        registration_coin_1_id,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        launcher_id,
    )
}

/// Cast voter1's vote on a fresh ballot launched against the given
/// (num, den). Returns the synthesised vote records, the eve Ballot
/// Coin's puzzle hash (for the post-finalize transition assertion),
/// and `vote_close_height` (for the full-flow caller).
#[allow(clippy::too_many_arguments)]
async fn cast_one_of_two(
    sim: &mut Simulator,
    config: &chip_voting_sdk::config::ElectionConfig,
    voter1_keys: &VoterKeys,
    voter1_pk: chia_bls::PublicKey,
    registration_coin_1_id: Bytes32,
    registration_merkle_root_snapshot: Bytes32,
    registration_vote_weight_snapshot: u64,
    launcher_id: Bytes32,
    vote_threshold_num: u64,
    vote_threshold_den: u64,
) -> (Vec<chip_voting_sdk::state::VoteRecord>, Bytes32, u64) {
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

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let chain = common::SharedSim::new(sim);
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
    sim.new_transaction(created.spend_bundle.clone())
        .expect("simulator accepts create_ballot");

    let chain = common::SharedSim::new(sim);
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

    let voter1 = Voter::new(
        config.clone(),
        VoterKeys::new(voter1_keys.secret.clone()),
        NetworkType::Testnet11,
    );
    let vote_outcome = Bytes32::new([0xAA; 32]);

    let chain = common::SharedSim::new(sim);
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
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("voter1 cast_vote");
    drop(chain);
    sim.new_transaction(cast_v1.spend_bundle.clone())
        .expect("simulator accepts voter1 cast_vote");

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
        jubjub_vote: Some(mk_jv(&voter1_keys.secret, canonical_msg)),
    }];

    (votes, launched.eve_ballot_puzzle_hash, vote_close_height)
}

async fn register_voter(
    sim: &mut Simulator,
    cat_tail_hash: Bytes32,
    launcher_id: Bytes32,
    config: &chip_voting_sdk::config::ElectionConfig,
    voter_keys: &VoterKeys,
    collateral_amount: u64,
    smt_pre_register: PoseidonSmt,
) {
    let voter_pk = voter_keys.pubkey;
    let reg_outer_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter_pk,
        launcher_id, 1_000,
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
        .register(&smt_pre_register, cat_parent_spend, &chain, config.collateral_amount)
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

/// SEC-F1: build the voter's Jubjub Schnorr `JubjubVoteWitness` over the REAL
/// canonical `vote_message`. For the full on-chain finalize, `VotingCircuitV2`
/// verifies this signature in-circuit, so it MUST be over the same message the
/// aggregator binds — `Fr::from_be_bytes_mod_order(canonical_vote_message)`.
/// (The non-proving pre-check sub-tests don't verify the sig, so this is also
/// fine there.)
fn mk_jv(
    sk: &chia_bls::SecretKey,
    vote_message: Bytes32,
) -> chip_voting_sdk::state::JubjubVoteWitness {
    // Delegate to the public SDK helper (shared with the cli + wasm dApp
    // finalize paths): signs the canonical finalize message with a secure
    // message-bound nonce; the in-circuit Schnorr check accepts it.
    chip_voting_sdk::prover::circuit_v2::jubjub_vote_witness(sk, vote_message)
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

// ─── (2/3) helpers ─────────────────────────────────────────────────

/// Set up the simulator + 3 registered voters at uniform 1000
/// collateral. Returns everything the per-test caller needs to drive
/// a per-ballot flow with a (2, 3) threshold.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
async fn build_three_voter_setup(
    seed: u64,
) -> (
    Simulator,
    chip_voting_sdk::config::ElectionConfig,
    chip_voting_sdk::prover::circuit::ArkProvingKey,
    VoterKeys,
    chia_bls::PublicKey,
    VoterKeys,
    chia_bls::PublicKey,
    VoterKeys,
    chia_bls::PublicKey,
    Bytes32,
    Bytes32,
    Bytes32,
    u64,
    Bytes32,
) {
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(10_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    // See `build_two_voter_setup`: deploy with a circuit_v2-shaped dummy VK
    // so `launch_ballot` accepts it; keep the legacy `proving_key` for the
    // (ignored) on-chain proving sub-tests.
    let (proving_key, _vk) = generate_test_setup(32, &mut rng).expect("generate_test_setup");
    let vk_bytes = vec![0u8; 336 + (chip_voting_sdk::config::PUBLIC_INPUT_COUNT + 1) * 48];

    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey { raw_bytes: vk_bytes },
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

    let voter1_keys = test_voter_keys(0x13u8);
    let voter2_keys = test_voter_keys(0x14u8);
    let voter3_keys = test_voter_keys(0x15u8);
    let voter1_pk = voter1_keys.pubkey;
    let voter2_pk = voter2_keys.pubkey;
    let voter3_pk = voter3_keys.pubkey;

    let reg_outer_ph_1 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter1_pk, launcher_id, 1_000,
    );
    let reg_outer_ph_2 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter2_pk, launcher_id, 1_000,
    );
    let reg_outer_ph_3 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter3_pk, launcher_id, 1_000,
    );
    let reg_inner_ph_1 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter1_pk, launcher_id, cat_tail_hash, 1_000,
    );
    let reg_inner_ph_2 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter2_pk, launcher_id, cat_tail_hash, 1_000,
    );
    let reg_inner_ph_3 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter3_pk, launcher_id, cat_tail_hash, 1_000,
    );

    let mut ctx = SpendContext::new();
    let memos_1 = ctx.hint(reg_outer_ph_1).expect("hint v1");
    let memos_2 = ctx.hint(reg_outer_ph_2).expect("hint v2");
    let memos_3 = ctx.hint(reg_outer_ph_3).expect("hint v3");
    let extra_conditions = Conditions::new()
        .create_coin(reg_inner_ph_1, collateral_amount, memos_1)
        .create_coin(reg_inner_ph_2, collateral_amount, memos_2)
        .create_coin(reg_inner_ph_3, collateral_amount, memos_3);
    let total_amount = 3 * collateral_amount;
    let (xch_conditions, cats) = Cat::issue_with_coin(
        &mut ctx,
        cat_genesis.coin.coin_id(),
        total_amount,
        extra_conditions,
    )
    .expect("Cat::issue_with_coin (three voters)");
    StandardLayer::new(cat_genesis.pk)
        .spend(&mut ctx, cat_genesis.coin, xch_conditions)
        .expect("StandardLayer::spend(cat_genesis)");
    let issuance_spends = ctx.take();
    sim.spend_coins(issuance_spends, std::slice::from_ref(&cat_genesis.sk))
        .expect("simulator accepts CAT issuance bundle (3)");

    let registration_coin_1_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_1)
        .map(|c| c.coin.coin_id())
        .expect("voter1 CAT child");
    let registration_coin_2_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_2)
        .map(|c| c.coin.coin_id())
        .expect("voter2 CAT child");
    let _registration_coin_3_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_3)
        .map(|c| c.coin.coin_id())
        .expect("voter3 CAT child");

    // Register all three voters in turn so the SPT root reflects all
    // three pubkeys at the snapshot we'll use for finalize.
    let smt_pre_v1 = PoseidonSmt::new();
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter1_keys, collateral_amount, smt_pre_v1).await;
    let mut smt_post_v1 = PoseidonSmt::new();
    smt_post_v1.insert(voter1_keys.jubjub_pubkey, config.collateral_amount);
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter2_keys, collateral_amount, smt_post_v1.clone()).await;
    let mut smt_post_v2 = smt_post_v1.clone();
    smt_post_v2.insert(voter2_keys.jubjub_pubkey, config.collateral_amount);
    register_voter(&mut sim, cat_tail_hash, launcher_id, &config, &voter3_keys, collateral_amount, smt_post_v2.clone()).await;
    let mut smt_post_v3 = smt_post_v2.clone();
    smt_post_v3.insert(voter3_keys.jubjub_pubkey, config.collateral_amount);
    let registration_merkle_root_snapshot = Bytes32::new(smt_post_v3.root_be32());
    let registration_vote_weight_snapshot = 3 * collateral_amount;

    (
        sim,
        config,
        proving_key,
        voter1_keys,
        voter1_pk,
        voter2_keys,
        voter2_pk,
        voter3_keys,
        voter3_pk,
        registration_coin_1_id,
        registration_coin_2_id,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        launcher_id,
    )
}

/// Cast voters 1 and 2 on a fresh ballot launched against the given
/// (num, den). Voter 3 abstains. Returns the synthesised vote
/// records, the eve Ballot Coin's puzzle hash, and the close height.
#[allow(clippy::too_many_arguments)]
async fn cast_two_of_three(
    sim: &mut Simulator,
    config: &chip_voting_sdk::config::ElectionConfig,
    voter1_keys: &VoterKeys,
    voter1_pk: chia_bls::PublicKey,
    registration_coin_1_id: Bytes32,
    voter2_keys: &VoterKeys,
    voter2_pk: chia_bls::PublicKey,
    registration_coin_2_id: Bytes32,
    registration_merkle_root_snapshot: Bytes32,
    registration_vote_weight_snapshot: u64,
    launcher_id: Bytes32,
    vote_threshold_num: u64,
    vote_threshold_den: u64,
) -> (Vec<chip_voting_sdk::state::VoteRecord>, Bytes32, u64) {
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let funder_coin_2 = Coin::new(Bytes32::new([0xCD; 32]), funder_ph, 2);
    sim.insert_coin(funder_coin_2);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend =
        common::coin_spend_from_nodes(&ctx, funder_coin_2, funder_puzzle, funder_solution);
    drop(ctx);

    let pre_ballot_height = sim.height() as u64;
    let vote_close_height: u64 = pre_ballot_height + 5;
    let outcome_domain_hash = Bytes32::new([0xCD; 32]);

    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);
    let chain = common::SharedSim::new(sim);
    let created = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed: Bytes32::new([0xbc; 32]),
                vote_close_height,
                outcome_domain_hash,
                vote_options_root: Bytes32::default(),
            },
            funder_spend,
        )
        .await
        .expect("create_ballot (2/3)");
    drop(chain);
    sim.new_transaction(created.spend_bundle.clone())
        .expect("simulator accepts create_ballot");

    let chain = common::SharedSim::new(sim);
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
        .expect("launch_ballot (2/3)");
    drop(chain);
    sim.new_transaction(launched.spend_bundle.clone())
        .expect("simulator accepts launch_ballot");

    let voter1 = Voter::new(
        config.clone(),
        VoterKeys::new(voter1_keys.secret.clone()),
        NetworkType::Testnet11,
    );
    let voter2 = Voter::new(
        config.clone(),
        VoterKeys::new(voter2_keys.secret.clone()),
        NetworkType::Testnet11,
    );
    let vote_outcome = Bytes32::new([0xAA; 32]);

    let chain = common::SharedSim::new(sim);
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
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("voter1 cast_vote");
    drop(chain);
    sim.new_transaction(cast_v1.spend_bundle.clone())
        .expect("simulator accepts voter1 cast_vote");

    let chain = common::SharedSim::new(sim);
    let cast_v2 = voter2
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
        .expect("voter2 cast_vote");
    drop(chain);
    sim.new_transaction(cast_v2.spend_bundle.clone())
        .expect("simulator accepts voter2 cast_vote");

    while (sim.height() as u64) <= vote_close_height {
        sim.create_block();
    }

    let canonical_msg = chip_voting_sdk::actors::aggregator::canonical_vote_message(
        vote_outcome,
        created.ballot_launcher_id,
        launcher_id,
    );
    let v1_sig = voter1.keys.sign_unsafe(canonical_msg.as_ref());
    let v2_sig = voter2.keys.sign_unsafe(canonical_msg.as_ref());
    let votes = vec![
        chip_voting_sdk::state::VoteRecord {
            voter_pubkey: voter1_pk,
            vote_data: vote_outcome,
            vote_signature_hex: hex::encode(v1_sig.to_bytes()),
            registration_coin_id: registration_coin_1_id,
            ballot_launcher_id: created.ballot_launcher_id,
            voting_coin_id: cast_v1.voting_coin_id,
            jubjub_vote: Some(mk_jv(&voter1_keys.secret, canonical_msg)),
        },
        chip_voting_sdk::state::VoteRecord {
            voter_pubkey: voter2_pk,
            vote_data: vote_outcome,
            vote_signature_hex: hex::encode(v2_sig.to_bytes()),
            registration_coin_id: registration_coin_2_id,
            ballot_launcher_id: created.ballot_launcher_id,
            voting_coin_id: cast_v2.voting_coin_id,
            jubjub_vote: Some(mk_jv(&voter2_keys.secret, canonical_msg)),
        },
    ];

    (votes, launched.eve_ballot_puzzle_hash, vote_close_height)
}
