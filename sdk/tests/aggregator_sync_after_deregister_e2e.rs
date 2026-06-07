// ============================================================================
// tests/aggregator_sync_after_deregister_e2e.rs — Aggregator deregister branch
// ============================================================================
//
// SCOPE: pins the aggregator sync's deregister-branch handling — the
//        path inside `aggregator::apply_singleton_spend` (commit
//        9c1ffbec) that detects the singleton's `deregister`
//        announcement, wipes the voter's SMT leaf, and decrements the
//        registration count + total weight.
//
// FLOW:
//   1. Deploy Election Singleton + issue real CAT Registration Coin
//      (same pattern as `voter_release_collateral_e2e.rs`).
//   2. Run `Voter::register` to land the voter in the on-chain SMT.
//   3. `Aggregator::sync` — assert voter set has 1 voter, SMT root
//      reflects the inserted leaf.
//   4. Run `Voter::release_collateral` (which co-spends the
//      Election Singleton's `deregister` action).
//   5. `Aggregator::sync` AGAIN — assert the deregister branch wiped
//      the voter (registration_count == 0, voter_set empty, SMT root
//      back to empty).
//
// WHY: `live_orchestration_e2e.rs` exercises a 2-voter multi-step
//      flow that incidentally touches post-deregister sync. This
//      test is the focused single-voter parity — if a future refactor
//      regressed the deregister branch detection (`deregister_announcement_msg`
//      probe inside `apply_singleton_spend`), this single test would
//      pinpoint it without the noise of finalization, multiple
//      voters, or multiple ballots.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::GenesisByCoinIdTailArgs;
use chia_sdk_driver::{Cat, SpendContext, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::aggregator::Aggregator;
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: Aggregator::sync() after a `release_collateral` spend
///       wipes the voter's SMT leaf and zeroes the registration
///       count + total weight.
/// HOW:  deploy → issue CAT registration coin → register → sync
///       (assert 1 voter) → release_collateral → sync (assert 0).
/// WHY:  pins the deregister discrimination branch inside
///       `apply_singleton_spend` (commit 9c1ffbec) — the SDK has to
///       detect the on-chain `deregister_announcement_msg` and roll
///       back the SMT, otherwise post-deregister state would drift
///       from on-chain reality.
#[tokio::test(flavor = "current_thread")]
async fn aggregator_sync_after_deregister_wipes_voter() {
    // ── 1. Set up the simulator + the CAT genesis coin ───────
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000); // funds the deploy
    let cat_genesis = sim.bls(2_000); // funds the CAT eve issuance

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

    // ── 3. Voter setup + CAT issuance ────────────────────────
    let voter_keys = test_voter_keys(0x05u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash, 1_000);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id, 1_000);

    let mut ctx = SpendContext::new();
    let issuance_memos = ctx.hint(reg_outer_ph).expect("hint");
    let extra_conditions = Conditions::new().create_coin(
        reg_inner_ph,
        collateral_amount,
        issuance_memos,
    );
    let (xch_conditions, cats) =
        Cat::issue_with_coin(&mut ctx, cat_genesis.coin.coin_id(), collateral_amount, extra_conditions)
            .expect("Cat::issue_with_coin");
    StandardLayer::new(cat_genesis.pk)
        .spend(&mut ctx, cat_genesis.coin, xch_conditions)
        .expect("StandardLayer::spend(cat_genesis)");
    let issuance_spends = ctx.take();
    sim.spend_coins(issuance_spends, std::slice::from_ref(&cat_genesis.sk))
        .expect("simulator accepts CAT issuance bundle");

    let registration_cat = cats.into_iter().next().expect("issuance produces 1 CAT child");
    let registration_coin_id = registration_cat.coin.coin_id();

    // ── 4. Voter::register ───────────────────────────────────
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
    let announcer_coin = Coin::new(Bytes32::new([0xBC; 32]), announcer_ph, 1);
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
        .unwrap_or_else(|e| panic!("Voter::register failed: {:?}", e));
    drop(chain);
    sim.new_transaction(register_bundle)
        .expect("simulator must accept register bundle");

    // ── 5. Aggregator::sync() — must reflect the new voter ───
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    let snapshot = agg.sync().await.expect("aggregator sync post-register");
    assert_eq!(
        snapshot.voter_set.voters.len(),
        1,
        "post-register sync must surface exactly 1 voter",
    );
    assert_eq!(
        snapshot.voter_set.registration_count, 1,
        "post-register sync must report registration_count = 1",
    );
    let post_register_root = snapshot.smt.root();
    assert_ne!(
        post_register_root,
        SparseMerkleTree::new().root(),
        "post-register SMT root MUST differ from empty",
    );
    drop(agg);

    // ── 6. Voter::release_collateral (co-spends `deregister`) ─
    // Build the post-register SMT for release_collateral by
    // mirroring the on-chain insert.
    let mut smt_post_register = SparseMerkleTree::new();
    smt_post_register
        .insert(&voter_pk, config.collateral_amount)
        .expect("local SMT insert must succeed (post-register state)");

    let destination = Bytes32::new([0xDE; 32]);
    let chain = common::SharedSim::new(&mut sim);
    let release_bundle = voter
        .release_collateral(
            &chain,
            &smt_post_register,
            registration_coin_id,
            destination,
        )
        .await
        .unwrap_or_else(|e| panic!("Voter::release_collateral failed: {:?}", e));
    drop(chain);

    sim.new_transaction(release_bundle)
        .expect("simulator must accept release bundle");

    // ── 7. Aggregator::sync() AGAIN — deregister branch wipes ─
    let chain = common::SharedSim::new(&mut sim);
    let mut agg2 = Aggregator::new(config.clone(), chain, NetworkType::Testnet11);
    let snapshot2 = agg2.sync().await.expect("aggregator sync post-deregister");

    assert!(
        snapshot2.voter_set.voters.is_empty(),
        "post-deregister sync MUST drop the voter from the voter set; \
         got {} voters",
        snapshot2.voter_set.voters.len(),
    );
    assert_eq!(
        snapshot2.voter_set.registration_count, 0,
        "post-deregister sync MUST decrement registration_count to 0",
    );
    assert_eq!(
        snapshot2.smt.root(),
        SparseMerkleTree::new().root(),
        "post-deregister SMT root MUST equal the empty SPT root",
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
