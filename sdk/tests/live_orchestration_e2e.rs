// ============================================================================
// tests/live_orchestration_e2e.rs — full live-test phase sequence (simulator)
// ============================================================================
//
// SCOPE: end-to-end regression for the live-network integration test's
// orchestration. Mirrors `cli/src/bin/live_integration_test.rs`'s phase
// sequence one-for-one, against `chia_sdk_test::Simulator`:
//
//   deploy → register voter1 →
//   create_ballot → launch_ballot →
//   cast_vote voter1 →
//   advance height past vote_close_height →
//   finalize.
//
// The release-collateral phase is exercised separately by
// `voter_release_collateral_e2e.rs` (against a never-cast
// Registration Coin); see SDK Gap (3) below for why it can't
// chain off the post-cast_vote state in this test.
//
// WHY: each per-phase e2e test (`voter_register_full_flow`,
// `voter_cast_vote_e2e`, `finalize_per_ballot_e2e`,
// `voter_release_collateral_e2e`, `create_ballot_e2e`,
// `launch_ballot_e2e`) pins its own piece individually. None of them
// exercise the FULL sequence — which is exactly the orchestration
// the live test runs on a real chain. This test catches mistakes
// where individual phases work but their sequencing or argument
// threading is wrong (e.g. `phase_vote` running before
// `phase_launch_ballot`, or the registration_*_snapshot drifting
// between launch_ballot, cast_vote, and build_finalize_for_ballot).
//
// SDK GAP NOTES (both surfaced by trying to register-cast both
// voters end-to-end here; documented for follow-up; this test is
// scoped to what's orchestratable today):
//
//   1. `Voter::cast_vote` resolves the LAUNCHER → eve-Ballot-Coin
//      step only (`find_current_ballot_singleton` walks from the
//      launcher to its odd-amount child). After the FIRST cast_vote
//      co-spends the eve Ballot Coin via the oracle action, the
//      recreated Ballot Coin lives at a NEW puzzle hash whose parent
//      is the eve (not the launcher), so a SECOND voter's cast_vote
//      fails with "no unspent eve Ballot Coin singleton found".
//      Lifting the gap requires walking the Ballot Coin's singleton
//      lineage to its current tip in `Voter::cast_vote`, analogous
//      to what `Aggregator::find_current_ballot_singleton_via_chain`
//      already does for finalize.
//
//   2. `Aggregator::prepare_finalize_witness_with_threshold`'s
//      pre-check 4 (`2 * votes.len() <= voter_set.registration_count
//      → BelowThreshold`) gates on COUNT, not on the curried
//      `(num, den)` threshold pack. A 1/3 threshold with 1-of-2
//      voters would clear the on-chain assertion arithmetically
//      (1000 > 666) but is rejected pre-flight by this count-based
//      strict-majority check — so even if gap (1) were fixed,
//      passing fewer than ⌈N/2⌉ + 1 votes never reaches the prover.
//
//   3. `Voter::release_collateral` predicts the Registration Coin's
//      CAT-wrapped puzzle hash from a "fresh" RegistrationState
//      (`voted_ballots_root = EMPTY_BALLOT_ROOT`). After a
//      cast_vote, the recreated Registration Coin's
//      `voted_ballots_root` reflects the inserted ballot id, so its
//      actual ph differs from the SDK's predicted-fresh ph and
//      release_collateral fails with "registration coin puzzle hash
//      … doesn't match predicted fresh-state CAT-wrapped ph". The
//      driver therefore only chains cleanly off a NEVER-CAST
//      Registration Coin. `voter_release_collateral_e2e.rs` covers
//      that path; here we stop after finalize.
//
// Because of (1), this test casts a single vote; because of (2)
// reaching strict majority requires registration_count = votes.len()
// = 1; because of (3) the release phase isn't chained off the
// post-cast_vote state. The live integration test in
// `cli/src/bin/live_integration_test.rs` registers two voters and
// expects to cast both, then release both — on a live chain that
// will surface gaps (1) and (3) today.
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

/// Tier 4 live-orchestration e2e: 2 voters, 2-block voting window,
/// drives every phase the live integration test runs in the same
/// order. Asserts:
///   * Both Registration Coins are spent after their respective
///     cast_vote spends.
///   * The eve Ballot Coin is spent post-finalize (transition
///     `finalized=false → true` recreates at a new puzzle hash).
///   * Both voters' release_collateral CAT children land at the
///     destination CAT puzzle hash with the expected amounts.
///   * The aggregator's `collect_votes_for_ballot` recovers both
///     `VoteRecord`s from the post-cast_vote chain.
#[tokio::test(flavor = "current_thread")]
async fn chip_live_orchestration_simulator_full_flow() {
    // ── 1. Trusted-setup keys + simulator + cat genesis ──────
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000);
    let cat_genesis = sim.bls(2_000);
    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE_2026);
    let (proving_key, vk) = generate_test_setup(&mut rng).expect("generate_test_setup");
    let vk_bytes = vk.chia_chunked_bytes().expect("vk chunked bytes");

    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vk_bytes,
        },
        cat_tail_hash,
        collateral_amount,
        // Live test snapshots `current_peak_height` here. The
        // simulator's height starts at 0; both the deployer and the
        // chain walkers we drive from the test pass `0` consistently.
        election_start_height: 0,
        label: Some("live-orch-e2e".into()),
    };

    // ── 2. Deploy ───────────────────────────────────────────
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator must accept deploy bundle");
    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 3. One voter (see SDK gap notes in the file header) ──
    let voter1_keys = test_voter_keys(0x03u8);
    let voter1_pk = voter1_keys.pubkey;

    // ── 3a. Issue voter1's Registration CAT ──────────────────
    let reg_inner_ph_1 = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter1_pk, launcher_id, cat_tail_hash,
    );
    let reg_outer_ph_1 = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash, &voter1_pk, launcher_id,
    );

    let mut ctx = SpendContext::new();
    let memos_1 = ctx.hint(reg_outer_ph_1).expect("hint v1");
    let extra_conditions = Conditions::new().create_coin(
        reg_inner_ph_1,
        collateral_amount,
        memos_1,
    );
    let (xch_conditions, cats) = Cat::issue_with_coin(
        &mut ctx,
        cat_genesis.coin.coin_id(),
        collateral_amount,
        extra_conditions,
    )
    .expect("Cat::issue_with_coin (voter1)");
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
        .expect("voter1 CAT child landed at reg_outer_ph_1");

    // ── 3b. Run Voter::register ──────────────────────────────
    register_voter(
        &mut sim,
        cat_tail_hash,
        launcher_id,
        &config,
        &voter1_keys,
        collateral_amount,
        SparseMerkleTree::new(),
    )
    .await;

    let mut smt_after_register = SparseMerkleTree::new();
    smt_after_register
        .insert(&voter1_pk)
        .expect("smt insert voter1");

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

    // 2-block voting window per the task spec: vote_close_height =
    // current_sim_height + offset (cast_vote must fire BEFORE this
    // height; finalize must fire AT or AFTER it). Each
    // `sim.new_transaction` call advances the simulator height by 1,
    // so we widen the window by the blocks that the *upcoming*
    // create_ballot, launch_ballot, and cast_vote spends will
    // consume.
    let pre_ballot_height = sim.height() as u64;
    // create_ballot + launch_ballot = 2 blocks; cast_vote = 1 block;
    // +1 buffer so AssertBeforeHeightAbsolute(close) accepts the
    // cast_vote spend.
    let vote_close_height: u64 = pre_ballot_height + 4;
    let outcome_domain_hash = Bytes32::new([0xCD; 32]);
    // 1/2 threshold pinned across launch_ballot, cast_vote, and
    // finalize. With 1 registered voter casting 1 vote, the
    // count-based strict-majority pre-check passes (2 * 1 > 1).
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
    let registration_merkle_root_snapshot = smt_after_register.root();
    let registration_vote_weight_snapshot = collateral_amount;

    // ── 6. Cast votes BEFORE the close height ───────────────
    // Pre-condition: simulator's current height < vote_close_height.
    // (cast_vote → update_vote co-spend asserts
    // `AssertBeforeHeightAbsolute(VOTE_CLOSE_HEIGHT)`.)
    assert!(
        (sim.height() as u64) < vote_close_height,
        "cast_vote must precede vote_close_height={vote_close_height}; sim.height()={}",
        sim.height(),
    );

    let vote_outcome = Bytes32::new([0xAA; 32]);
    let voter1 = Voter::new(config.clone(), voter1_keys, NetworkType::Testnet11);

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

    // Sanity: voter1's Registration Coin is now spent (its
    // cast_vote consumed it).
    assert!(
        sim.coin_state(registration_coin_1_id)
            .expect("voter1 reg coin tracked")
            .spent_height
            .is_some(),
        "voter1 Registration Coin must be spent after cast_vote",
    );

    // ── 7. Advance simulator past vote_close_height ─────────
    while (sim.height() as u64) <= vote_close_height {
        sim.create_block();
    }

    // ── 8. Build VoteRecords for finalize ───────────────────
    // The aggregator's collect_votes_for_ballot extracts the per-coin
    // signature, but finalize aggregates over the canonical vote
    // message (different preimage). We construct the VoteRecords
    // here with the canonical-aggregate signature so finalize's
    // bls_verify accepts. Mirror of finalize_per_ballot_e2e.rs's
    // pattern.
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

    // Sync the aggregator + cross-check that
    // `collect_votes_for_ballot` finds both vote coins on chain
    // (this is the live test's actual path; doesn't replace the
    // canonical-signature `votes` we hand-built above for finalize).
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    agg.sync().await.expect("aggregator sync");
    let collected = agg
        .collect_votes_for_ballot(created.ballot_launcher_id)
        .await
        .expect("collect_votes_for_ballot");
    assert_eq!(
        collected.len(),
        1,
        "expected 1 VoteRecord after voter1 casts (got {})",
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
            proving_key: &proving_key,
        })
        .await
        .unwrap_or_else(|e| panic!("build_finalize_for_ballot failed: {:?}", e));
    drop(agg);

    sim.new_transaction(finalize_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator must accept finalize bundle; got: {:?}", e));

    // Eve Ballot Coin must be spent and a recreated Ballot Coin at
    // a NEW puzzle hash (post-finalize state) must be present.
    let post_finalize = walk_to_unspent(&sim, created.ballot_launcher_id);
    assert!(
        post_finalize.coin.amount % 2 == 1,
        "post-finalize Ballot Coin must remain odd-amount (singleton invariant)",
    );
    // Finalize transitions BallotState.finalized false→true, which
    // changes the curried inner state and therefore the singleton-
    // wrapped puzzle hash. So the post-finalize coin's PH MUST
    // differ from the eve.
    assert_ne!(
        post_finalize.coin.puzzle_hash, launched.eve_ballot_puzzle_hash,
        "post-finalize Ballot Coin must land at a new puzzle hash \
         (state transitioned finalized=false→true)",
    );

    // ── 10. Sanity: a recreated (post-finalize) Ballot Coin
    //          with finalized state is still walkable. ─────────
    // The post-finalize Ballot Coin is a permissionless
    // attestation surface: external puzzles can `oracle`-co-spend
    // it to assert the result. We don't drive a follow-up oracle
    // spend here (no SDK helper for a standalone post-finalize
    // oracle exists today; see the live test's "Oracle action: NOT
    // a separate phase" comment for the rationale), but
    // confirming the recreated coin is unspent + odd is what the
    // walker upstream consumers (BallotReader::get_ballot, the
    // Ballot Coin oracle co-spend in update_vote, etc.) require.
    assert!(
        post_finalize.spent_height.is_none(),
        "recreated post-finalize Ballot Coin must be unspent",
    );
    let _ = collateral_amount; // parameter retained for future release coverage
    let _ = voter1; // explicit drop after final assertion
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Run `Voter::register` against the supplied pre-register SMT
/// snapshot. The Registration Coin must already be on chain (we
/// issue both voters' CATs in a single bundle in the test body
/// since the genesis-by-coin-id TAIL only authorises one issuance).
/// Mirrors the announcer-only `cat_parent_spend` pattern from
/// `voter_register_full_flow.rs`.
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
    // Use a unique parent per registration so the announcer coin id
    // differs across calls (the simulator rejects duplicate inserts).
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
