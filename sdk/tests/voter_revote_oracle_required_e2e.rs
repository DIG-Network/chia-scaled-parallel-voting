// ============================================================================
// tests/voter_update_vote_no_oracle_e2e.rs — VOTING-UPDATE-VOTE-ORACLE
// ============================================================================
//
// CHIP.md §282 (VOTING-UPDATE-VOTE-ORACLE): the Voting Coin's
// `update_vote` action "Asserts the Ballot Coin's `oracle`
// announcement that the ballot is still open (current height <
// `VOTE_CLOSE_HEIGHT`)".
//
// SCOPE: full deploy → CAT-issue Registration Coin → register →
// create_ballot → launch_ballot → cast_vote → BUILD VALID update_vote
// BUNDLE → STRIP THE BALLOT COIN ORACLE CO-SPEND → submit → MUST be
// rejected.
//
// CLVM EXECUTION: the simulator runs the modified bundle through
// every CLVM puzzle in it, including the Voting Coin's `update_vote`
// action puzzle. The action emits an `AssertCoinAnnouncement` (84)
// condition asserting an announcement from the Ballot Coin's oracle.
// With the oracle spend stripped, no coin in the bundle creates that
// announcement, so consensus rejects the spend at the
// AssertCoinAnnouncement check.
//
// WHY: a successful update_vote without the oracle co-spend would let
// a malicious mint that lied about `vote_close_height` be silently
// accepted — the oracle assertion is the cryptographic anchor that
// pins the supplied `vote_close_height` to the Ballot Coin's actual
// curried close height.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes32, Coin, SpendBundle};
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
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

#[tokio::test(flavor = "current_thread")]
async fn chip_voting_update_vote_without_oracle_assertion_traps() {
    // ── 1-7. Full setup mirroring voter_revote_e2e through cast_vote ─
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
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id);

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
    let smt_pre_register = SparseMerkleTree::new();
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

    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register.insert(&voter_pk, config.collateral_amount).expect("smt insert");
    let registration_merkle_root_snapshot = smt_post_register.root();
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

    // ── 8. Build a VALID update_vote bundle via Voter::update_vote ──
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
        .expect("update_vote (valid bundle, used as scaffold to strip oracle)");
    drop(chain);

    // The valid bundle has TWO coin spends:
    //   coin_spends[0] = ballot_singleton_spend (the Ballot Coin
    //                    oracle co-spend — what we're about to strip)
    //   coin_spends[1] = cat_update_spend (the CAT-wrapped Voting
    //                    Coin running update_vote)
    //
    // (Confirmed in `actors/voter.rs::update_vote` — `let coin_spends
    // = vec![ballot_singleton_spend, cat_update_spend];`)
    assert_eq!(
        update_result.spend_bundle.coin_spends.len(),
        2,
        "expected the valid update_vote bundle to have exactly 2 coin \
         spends (oracle co-spend + Voting Coin update_vote spend)"
    );
    let voting_coin_spend = update_result.spend_bundle.coin_spends[1].clone();

    // ── 9. STRIP THE ORACLE CO-SPEND, submit, expect rejection ──
    // We keep the SAME aggregate signature from the valid bundle —
    // the AggSigMe over `vote_message(new)` for the Voting Coin
    // spend is unchanged. If the bundle is rejected, the rejection
    // is structurally either:
    //   (a) the Voting Coin's `update_vote` puzzle's
    //       AssertCoinAnnouncement on the Ballot Coin oracle
    //       announcement (no announcer in the bundle creates it), OR
    //   (b) some other unmet structural invariant.
    // Either way, the spend MUST be rejected — that's what
    // VOTING-UPDATE-VOTE-ORACLE pins. The successful end-to-end run
    // of `voter_update_vote_against_simulator_full_flow` (which
    // includes the oracle co-spend) is the positive control proving
    // this exact harness DOES succeed when the oracle is paired.
    let no_oracle_bundle = SpendBundle::new(
        vec![voting_coin_spend],
        update_result.spend_bundle.aggregated_signature.clone(),
    );

    let res = sim.new_transaction(no_oracle_bundle);
    assert!(
        res.is_err(),
        "CHIP.md §282 (VOTING-UPDATE-VOTE-ORACLE): an update_vote \
         bundle WITHOUT the Ballot Coin oracle co-spend MUST be \
         rejected by consensus. The on-chain mechanism is the \
         AssertCoinAnnouncement(84) condition emitted by \
         update_vote.rue against the oracle's `ballot_oracle_open` \
         announcement; with no announcer, the assertion fails. If \
         this test reports OK, the oracle gating regressed and an \
         update_vote can land WITHOUT proving the ballot is still \
         open."
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
