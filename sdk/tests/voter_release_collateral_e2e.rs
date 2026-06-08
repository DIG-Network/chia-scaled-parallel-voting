// ============================================================================
// tests/voter_release_collateral_e2e.rs — Voter::release_collateral against Simulator
// ============================================================================
//
// SCOPE: drives `Voter::release_collateral` end-to-end:
//   1. Deploy Election Singleton (cat_tail_hash chosen so it matches a
//      real `genesis_by_coin_id` TAIL keyed to a known XCH coin).
//   2. Issue a real CAT-wrapped Registration Coin via
//      `chia_sdk_driver::Cat::issue_with_coin`. The Registration Coin
//      lands at the SDK's predicted `fresh_registration_coin_puzzle_hash`
//      with parent = the eve CAT (a parseable CAT spend, so
//      `reconstruct_cat_lineage` can later derive the lineage proof).
//   3. Run `Voter::register` with the standard "dummy announcer"
//      `cat_parent_spend` pattern (a quoted-conditions p2 puzzle that
//      emits the `create_reg` announcement only). After this the
//      on-chain SMT contains the voter and the singleton state has
//      advanced.
//   4. Run `Voter::release_collateral`. Expects the Registration Coin
//      to be spent and a new CAT child to appear at
//      `CatArgs::curry_tree_hash(tail_hash, destination)` with
//      amount = collateral_amount.
//
// WHY: pins down the FULL release_collateral path (singleton
//      deregister + CAT-wrapped registration release co-spend, the
//      AggSigMe signature aggregation, the CAT lineage reconstruction)
//      against the simulator. This is the e2e the handoff describes
//      as Tier 2.1 follow-up — the missing coverage for
//      `Voter::release_collateral` (commit fc374bc).

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::cat::{CatArgs, GenesisByCoinIdTailArgs};
use chia_sdk_driver::{Cat, SpendContext, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::PoseidonSmt;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: `Voter::release_collateral` builds a bundle the simulator
///       accepts after a real CAT Registration Coin is on chain and
///       the voter has been registered.
/// HOW:
///   1. Deploy with a `cat_tail_hash` keyed to a known XCH coin via
///      `GenesisByCoinIdTailArgs::curry_tree_hash`.
///   2. Mint the Registration Coin: spend the genesis XCH coin
///      through `Cat::issue_with_coin`, with `extra_conditions`
///      emitting `CreateCoin(reg_inner_ph, COLLATERAL_AMOUNT)` —
///      the CAT outer wraps it to land at the predicted CAT outer ph.
///   3. Register the voter via the standard
///      `voter_register_full_flow` pattern (announcer-only
///      `cat_parent_spend`).
///   4. Insert the voter's pubkey into a local SMT (mirrors the
///      on-chain SMT advance after register) and call
///      `release_collateral`.
///   5. Submit the bundle. Assert the Registration Coin is spent and
///      a new CAT child appears at `CAT(tail_hash, destination)` with
///      amount = collateral_amount.
/// WHY: this is the FIRST end-to-end test for
///      `Voter::release_collateral`. Any drift between the SDK's
///      release-action assembly, the CAT outer wrap, the singleton
///      deregister wrap, the BLS signature aggregation, or the CAT
///      lineage reconstruction would surface here.
#[tokio::test(flavor = "current_thread")]
async fn voter_release_collateral_against_simulator_full_flow() {
    // ── 1. Set up the simulator + the CAT genesis coin ───────
    // The genesis-by-coin-id TAIL is keyed to a single XCH coin; that
    // coin's id determines the asset id. We compute the asset id
    // BEFORE deploying so the deployment's `cat_tail_hash` matches.
    let mut sim = Simulator::new();
    let funder = sim.bls(100_000); // funds the deploy
    let cat_genesis = sim.bls(2_000); // funds the CAT eve issuance

    let cat_tail_hash: Bytes32 =
        GenesisByCoinIdTailArgs::curry_tree_hash(cat_genesis.coin.coin_id()).into();

    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        // Zero-buffer VK is fine here — the registration coin's
        // release action doesn't reference the VK (only the Ballot
        // Coin's finalize does).
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

    // ── 3. Voter setup ───────────────────────────────────────
    // Same seed pattern as voter_register_full_flow.rs so the slot
    // encoding is exercised the same way.
    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(&voter_pk, launcher_id, cat_tail_hash, 1_000);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id, 1_000);

    // ── 4. Mint a real CAT Registration Coin ─────────────────
    //
    // Cat::issue_with_coin runs the GenesisByCoinId TAIL and
    // immediately spends the eve CAT with `extra_conditions`. We
    // emit a single CreateCoin(reg_inner_ph, collateral_amount) —
    // the CAT outer wraps it so the resulting child Cat lands at
    // CatArgs::curry_tree_hash(tail_hash, reg_inner_ph) ==
    // reg_outer_ph (the SDK's predicted CAT-wrapped registration ph).
    //
    // The Registration Coin's PARENT is the eve CAT spend —
    // a parseable CAT spend, which is what
    // `Voter::reconstruct_cat_lineage` needs to derive the lineage
    // proof at release time.
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
    assert_eq!(
        registration_cat.coin.puzzle_hash,
        reg_outer_ph,
        "CAT child must land at SDK-predicted fresh_registration_coin_puzzle_hash",
    );
    assert_eq!(
        registration_cat.coin.amount, collateral_amount,
        "CAT child must carry COLLATERAL_AMOUNT mojos",
    );
    assert!(
        sim.coin_state(registration_cat.coin.coin_id()).is_some(),
        "Registration Coin must exist on chain after issuance",
    );
    let registration_coin_id = registration_cat.coin.coin_id();

    // ── 5. Run Voter::register ────────────────────────────────
    // Standard "announcer-only" cat_parent_spend pattern from
    // voter_register_full_flow.rs: a quoted-conditions p2 puzzle
    // that emits ONLY the create_reg announcement. The Registration
    // Coin is already on chain (from step 4); register's job is
    // just to advance the Election Singleton's SMT + count + weight.
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
    let smt_pre_register = PoseidonSmt::new();

    let chain = common::SharedSim::new(&mut sim);
    let register_bundle = voter
        .register(&smt_pre_register, cat_parent_spend, &chain, config.collateral_amount)
        .await
        .unwrap_or_else(|e| panic!("Voter::register failed: {:?}", e));
    drop(chain);
    sim.new_transaction(register_bundle)
        .unwrap_or_else(|e| panic!("simulator must accept register bundle: {:?}", e));

    // ── 6. Build the post-register SMT for release_collateral ─
    // The on-chain Election Singleton's SMT now contains the voter.
    // `Voter::release_collateral` validates that the supplied SMT
    // root matches the on-chain root, so we mirror that here by
    // inserting the voter's pubkey into a local SMT.
    let mut smt_post_register = PoseidonSmt::new();
    smt_post_register.insert(voter.keys.jubjub_pubkey, config.collateral_amount);


    // ── 7. Run Voter::release_collateral ──────────────────────
    let destination = Bytes32::new([0xDD; 32]);
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

    println!(
        "release_collateral bundle has {} coin spends",
        release_bundle.coin_spends.len()
    );

    sim.new_transaction(release_bundle)
        .unwrap_or_else(|e| panic!("simulator must accept release bundle: {:?}", e));

    // ── 8. Assert outputs ─────────────────────────────────────
    // 8a. Registration Coin is spent.
    let post_reg = sim
        .coin_state(registration_coin_id)
        .expect("registration coin still in simulator state");
    assert!(
        post_reg.spent_height.is_some(),
        "Registration Coin must be spent after release_collateral",
    );

    // 8b. A new CAT child appears at CAT(tail_hash, destination).
    // The release action emits CreateCoin(destination, collateral_amount)
    // from inside the CAT outer; CAT-wrapping yields a child at the
    // CAT-curried-with-destination puzzle hash.
    let dest_cat_th = CatArgs::curry_tree_hash(cat_tail_hash, destination.into());
    let dest_cat_ph = Bytes32::new(dest_cat_th.to_bytes());
    let coin_states = sim.lookup_puzzle_hashes(indexmap::indexset![dest_cat_ph], false);
    assert!(
        coin_states.iter().any(|cs| {
            cs.coin.amount == collateral_amount
                && cs.coin.parent_coin_info == registration_coin_id
        }),
        "expected a new CAT child at {} with amount {} and parent {} after release_collateral; \
         got {} unrelated coins",
        hex::encode(dest_cat_ph),
        collateral_amount,
        hex::encode(registration_coin_id),
        coin_states.len(),
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
