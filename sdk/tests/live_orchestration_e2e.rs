// ============================================================================
// tests/live_orchestration_e2e.rs — full live-test phase sequence (simulator)
// ============================================================================
//
// SCOPE: end-to-end regression for the live-network integration test's
// orchestration. Mirrors `cli/src/bin/live_integration_test.rs`'s phase
// sequence one-for-one, against `chia_sdk_test::Simulator`:
//
//   deploy → CAT-issue 2 Registration Coins → register voter1 +
//   register voter2 → create_ballot → launch_ballot →
//   cast_vote voter1 → cast_vote voter2 →
//   advance height past vote_close_height →
//   finalize → release_collateral voter1 → release_collateral voter2.
//
// HISTORY:
//   * Earlier this file was scoped to ONE voter and stopped after
//     finalize (no release) because of three SDK gaps:
//       (1) `Voter::cast_vote` only resolved the launcher → eve
//           Ballot Coin transition; a second voter's cast failed
//           because the eve was already spent.
//       (2) `Aggregator::prepare_finalize_witness_with_threshold`
//           gated on COUNT, not on the curried `(num, den)` weight.
//       (3) `Voter::release_collateral` predicted a fresh-state
//           Registration Coin ph; post-cast the on-chain ph differs.
//   * Gaps (1) (commit `4613831`) and (3) (this commit's parent)
//     are now fixed — this test exercises both. Gap (2) is the
//     deeper Groth16-non-majority bug; it's avoided here by using
//     a (1, 2) threshold with 2-of-2 voters (strict majority works
//     today; the (1, 3) failure is pinned by
//     `finalize_one_third_threshold_e2e.rs` instead).
//
// CHIP.md anchors: §289-298 (full data flow); §202 (createBallot
// mints Ballot Coin); §211-221 (Ballot Coin finalize curry shape);
// §233 (Ballot Coin finalize role + AssertHeightAbsolute); §284
// (per-ballot vote collection); §296 (FLOW-FINALIZE-NOT-SINGLETON).

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use ark_std::rand::SeedableRng;
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::{CatArgs, GenesisByCoinIdTailArgs};
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
use chip_voting_sdk::{Aggregator, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// Tier 4 live-orchestration e2e: 2 voters, 2-block voting window,
/// drives every phase the live integration test runs in the same
/// order. Asserts:
///   * Both Registration Coins are spent after their respective
///     cast_vote spends.
///   * The eve Ballot Coin is spent post-finalize (transition
///     `finalized=false → true` recreates at a new puzzle hash).
///   * Both voters' release_collateral CAT children land at the
///     destination CAT puzzle hash with the expected residual amount.
///   * The aggregator's `collect_votes_for_ballot` recovers both
///     `VoteRecord`s from the post-cast_vote chain.
#[ignore = "SEC-F1: needs a small-max_signers circuit_v2 deploy variant; Option-B in-circuit signer verification can't set up at config::MAX_SIGNERS=20000 (go-live scaling). Forgery closure is pinned by exploit_finalize_forgery_e2e + finalize_v2_groth16_e2e."]
#[tokio::test(flavor = "current_thread")]
async fn chip_live_orchestration_simulator_full_flow() {
    // ── 1. Trusted-setup keys + simulator + cat genesis ──────
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(10_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE_2026);
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
        label: Some("live-orch-e2e".into()),
    };

    // ── 2. Deploy ───────────────────────────────────────────
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk, true)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator must accept deploy bundle");
    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 3. Two voters ───────────────────────────────────────
    let voter1_keys = test_voter_keys(0x03u8);
    let voter2_keys = test_voter_keys(0x04u8);
    let voter1_pk = voter1_keys.pubkey;
    let voter2_pk = voter2_keys.pubkey;

    // ── 3a. Issue both voters' Registration CATs in one bundle ──
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
    let registration_coin_2_id = cats
        .iter()
        .find(|c| c.coin.puzzle_hash == reg_outer_ph_2)
        .map(|c| c.coin.coin_id())
        .expect("voter2 CAT child");

    // ── 3b. Run Voter::register for both ─────────────────────
    register_voter(
        &mut sim, cat_tail_hash, launcher_id, &config, &voter1_keys,
        collateral_amount, PoseidonSmt::new(),
    ).await;
    let mut smt_after_v1 = PoseidonSmt::new();
    smt_after_v1.insert(voter1_keys.jubjub_pubkey, config.collateral_amount);
    register_voter(
        &mut sim, cat_tail_hash, launcher_id, &config, &voter2_keys,
        collateral_amount, smt_after_v1.clone(),
    ).await;
    let mut smt_after_v2 = smt_after_v1.clone();
    smt_after_v2.insert(voter2_keys.jubjub_pubkey, config.collateral_amount);

    // ── 4. createBallot: launcher eve coin ──────────────────
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

    // 2-block voting window per the task spec, widened to absorb
    // create_ballot + launch_ballot + 2 cast_vote spends (4 blocks)
    // plus a buffer.
    let pre_ballot_height = sim.height() as u64;
    let vote_close_height: u64 = pre_ballot_height + 6;
    let outcome_domain_hash = Bytes32::new([0xCD; 32]);
    // (1, 2) threshold — strict majority. With 2-of-2 voters this
    // satisfies the on-chain weighted-quorum check today
    // (Gap (2)-deeper at non-majority thresholds is tracked via
    // `finalize_one_third_threshold_e2e.rs`).
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;

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
    sim.new_transaction(created.spend_bundle.clone())
        .expect("simulator must accept create_ballot bundle");

    // ── 5. launch_ballot: eve Ballot Coin ───────────────────
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
        .expect("simulator must accept launch_ballot bundle");

    // The registration snapshot the BallotIssuer captured into the
    // per-ballot finalize curry — both cast_vote and finalize MUST
    // mirror these exact values or the eve Ballot Coin's puzzle
    // hash diverges.
    let registration_merkle_root_snapshot = Bytes32::new(smt_after_v2.root_be32());
    let registration_vote_weight_snapshot = 2 * collateral_amount;

    // ── 6. Cast both votes BEFORE the close height ──────────
    assert!(
        (sim.height() as u64) < vote_close_height,
        "cast_votes must precede vote_close_height={vote_close_height}; sim.height()={}",
        sim.height(),
    );

    let vote_outcome = Bytes32::new([0xAA; 32]);
    let voter1 = Voter::new(config.clone(), voter1_keys, NetworkType::Testnet11);
    let voter2 = Voter::new(config.clone(), voter2_keys, NetworkType::Testnet11);

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
                vote_options_root: Bytes32::default(),
                vote_option_proof: None,
            },
        )
        .await
        .expect("voter1 cast_vote");
    drop(chain);
    sim.new_transaction(cast_v1.spend_bundle.clone())
        .expect("simulator accepts voter1 cast_vote");

    // Voter 2 casts AFTER voter 1. Exercises Gap (1)'s fix:
    // `Voter::cast_vote` must walk the Ballot Coin singleton lineage
    // past the eve to the recreated Ballot Coin, OR (depending on
    // order) handle the recreated coin's parent as the eve.
    let chain = common::SharedSim::new(&mut sim);
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
        .expect("voter2 cast_vote (Gap 1: lineage walk past eve)");
    drop(chain);
    sim.new_transaction(cast_v2.spend_bundle.clone())
        .expect("simulator accepts voter2 cast_vote");

    // Sanity: both Registration Coins are now spent.
    for (label, reg_id) in [
        ("voter1", registration_coin_1_id),
        ("voter2", registration_coin_2_id),
    ] {
        assert!(
            sim.coin_state(reg_id)
                .unwrap_or_else(|| panic!("{label} reg coin tracked"))
                .spent_height
                .is_some(),
            "{label} Registration Coin must be spent after cast_vote",
        );
    }

    // ── 7. Advance simulator past vote_close_height ─────────
    while (sim.height() as u64) <= vote_close_height {
        sim.create_block();
    }

    // ── 8. Build VoteRecords for finalize ───────────────────
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
            jubjub_vote: Some(mk_jv(&voter1.keys.secret)),
        },
        chip_voting_sdk::state::VoteRecord {
            voter_pubkey: voter2_pk,
            vote_data: vote_outcome,
            vote_signature_hex: hex::encode(v2_sig.to_bytes()),
            registration_coin_id: registration_coin_2_id,
            ballot_launcher_id: created.ballot_launcher_id,
            voting_coin_id: cast_v2.voting_coin_id,
            jubjub_vote: Some(mk_jv(&voter2.keys.secret)),
        },
    ];

    // Cross-check the aggregator's `collect_votes_for_ballot`
    // recovers BOTH VoteRecords (the live test's path).
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");
    let collected = agg
        .collect_votes_for_ballot(created.ballot_launcher_id)
        .await
        .expect("collect_votes_for_ballot");
    assert_eq!(
        collected.len(),
        2,
        "expected 2 VoteRecords after both voters cast (got {})",
        collected.len(),
    );

    // ── 9. Finalize the Ballot Coin ──────────────────────────
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
            vote_options_root: Bytes32::default(),
            proving_key: &proving_key,
        })
        .await
        .unwrap_or_else(|e| panic!("build_finalize_for_ballot failed: {:?}", e));
    drop(agg);

    sim.new_transaction(finalize_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator must accept finalize bundle; got: {:?}", e));

    let post_finalize = walk_to_unspent(&sim, created.ballot_launcher_id);
    assert!(
        post_finalize.coin.amount % 2 == 1,
        "post-finalize Ballot Coin must remain odd-amount (singleton invariant)",
    );
    assert_ne!(
        post_finalize.coin.puzzle_hash, launched.eve_ballot_puzzle_hash,
        "post-finalize Ballot Coin must land at a new puzzle hash \
         (state transitioned finalized=false→true)",
    );

    // ── 10. Release collateral for voter1 ───────────────────
    // Exercises Gap (3)'s fix end-to-end:
    // `Voter::release_collateral` walks the registration coin's CAT
    // lineage backward to recover the post-cast `voted_ballots_root`
    // and uses it to predict the on-chain ph.
    let recreated_amount = collateral_amount - 1; // voting_coin_amount = 1

    let post_cast_reg_coin_1 = find_recreated_registration_coin(
        &sim, registration_coin_1_id, recreated_amount,
    );
    let post_cast_reg_coin_1_id = post_cast_reg_coin_1.coin_id();

    // Pre-release SMT contains BOTH voters (the on-chain root).
    let mut smt = PoseidonSmt::new();
    smt.insert(voter1.keys.jubjub_pubkey, config.collateral_amount);
    smt.insert(voter2.keys.jubjub_pubkey, config.collateral_amount);

    let dest1 = Bytes32::new([0xD1; 32]);
    let chain = common::SharedSim::new(&mut sim);
    let release_bundle = voter1
        .release_collateral(&chain, &smt, post_cast_reg_coin_1_id, dest1)
        .await
        .unwrap_or_else(|e| panic!("voter1::release_collateral: {:?}", e));
    drop(chain);
    sim.new_transaction(release_bundle)
        .unwrap_or_else(|e| panic!("simulator accepts voter1 release: {:?}", e));

    let dest1_cat_th = CatArgs::curry_tree_hash(cat_tail_hash, dest1.into());
    let dest1_cat_ph = Bytes32::new(dest1_cat_th.to_bytes());
    let dest1_states = sim.lookup_puzzle_hashes(indexmap::indexset![dest1_cat_ph], false);
    assert!(
        dest1_states.iter().any(|cs| {
            cs.coin.amount == recreated_amount
                && cs.coin.parent_coin_info == post_cast_reg_coin_1_id
        }),
        "voter1: expected released CAT child at {} amount {} parent {}",
        hex::encode(dest1_cat_ph),
        recreated_amount,
        hex::encode(post_cast_reg_coin_1_id),
    );

    // ── 11. Release collateral for voter2 ───────────────────
    // Exercises Gap (4)'s fix: chaining a SECOND voter's release
    // after voter1's deregister requires an SMT snapshot reflecting
    // voter1's leaf wiped to EMPTY_LEAF_HASH. Now that
    // `Aggregator::sync` walks `deregister` announcements (see
    // `apply_singleton_spend` in `aggregator.rs`), the synced SMT
    // matches the on-chain post-voter1-deregister root and voter2's
    // release succeeds.
    let post_cast_reg_coin_2 = find_recreated_registration_coin(
        &sim, registration_coin_2_id, recreated_amount,
    );
    let post_cast_reg_coin_2_id = post_cast_reg_coin_2.coin_id();

    // Resync the aggregator post-voter1-deregister and use the
    // resulting SMT (which must reflect voter1's leaf wiped).
    let chain = common::SharedSim::new(&mut sim);
    let mut agg2 = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    let snapshot = agg2.sync().await.expect("aggregator sync post-deregister");
    drop(agg2);
    let smt_post_v1_deregister = snapshot.smt.clone();

    let dest2 = Bytes32::new([0xD2; 32]);
    let chain = common::SharedSim::new(&mut sim);
    let release_bundle_2 = voter2
        .release_collateral(
            &chain, &smt_post_v1_deregister, post_cast_reg_coin_2_id, dest2,
        )
        .await
        .unwrap_or_else(|e| panic!("voter2::release_collateral (Gap 4): {:?}", e));
    drop(chain);
    sim.new_transaction(release_bundle_2)
        .unwrap_or_else(|e| panic!("simulator accepts voter2 release: {:?}", e));

    let dest2_cat_th = CatArgs::curry_tree_hash(cat_tail_hash, dest2.into());
    let dest2_cat_ph = Bytes32::new(dest2_cat_th.to_bytes());
    let dest2_states = sim.lookup_puzzle_hashes(indexmap::indexset![dest2_cat_ph], false);
    assert!(
        dest2_states.iter().any(|cs| {
            cs.coin.amount == recreated_amount
                && cs.coin.parent_coin_info == post_cast_reg_coin_2_id
        }),
        "voter2: expected released CAT child at {} amount {} parent {}",
        hex::encode(dest2_cat_ph),
        recreated_amount,
        hex::encode(post_cast_reg_coin_2_id),
    );
}

// ─── Helpers ────────────────────────────────────────────────────────

/// SEC-F1: build a well-formed Jubjub Schnorr `JubjubVoteWitness` for a
/// voter. The finalize threshold pre-check does not verify the signature
/// (it only reads the SMT weight + checks the weighted quorum), so any
/// well-formed witness over a dummy message suffices here; the voter's
/// jubjub pubkey just has to match the SMT leaf.
fn mk_jv(sk: &chia_bls::SecretKey) -> chip_voting_sdk::state::JubjubVoteWitness {
    let keys = chip_voting_sdk::VoterKeys::new(sk.clone());
    let cfg = chip_voting_sdk::prover::circuit_v2::poseidon_config();
    let m = ark_bls12_381::Fr::from(1u64);
    let (sig_r, sig_s) = chip_voting_sdk::prover::circuit_v2::schnorr_sign(
        &cfg,
        keys.jubjub_secret,
        ark_ed_on_bls12_381::Fr::from(7u64),
        m,
    );
    chip_voting_sdk::state::JubjubVoteWitness {
        pubkey: keys.jubjub_pubkey,
        sig_r,
        sig_s,
    }
}

/// Walk children of `parent_id` and return the first coin with
/// `amount == expected_amount` — the recreated post-cast Registration
/// Coin (CAT-conservation: collateral_amount minus voting_coin_amount).
fn find_recreated_registration_coin(
    sim: &Simulator,
    parent_id: Bytes32,
    expected_amount: u64,
) -> chia_protocol::Coin {
    sim.children(parent_id)
        .into_iter()
        .map(|cs| cs.coin)
        .find(|c| c.amount == expected_amount)
        .unwrap_or_else(|| {
            panic!(
                "recreated Registration Coin not found among children of {} (expected amount {})",
                hex::encode(parent_id),
                expected_amount,
            )
        })
}

/// Run `Voter::register` against the supplied pre-register SMT
/// snapshot. Mirrors the announcer-only `cat_parent_spend` pattern
/// from `voter_register_full_flow.rs`.
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
        let mut h = sha2::Sha256::new();
        use sha2::Digest;
        h.update(b"announcer-parent");
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
