// ============================================================================
// tests/launch_ballot_e2e.rs — BallotIssuer::launch_ballot full simulator flow
// ============================================================================
//
// SCOPE: drives `BallotIssuer::launch_ballot` end-to-end against
// `chia_sdk_test::Simulator`:
//   1. Deploy an Election Singleton.
//   2. `BallotIssuer::create_ballot` → mint a 2-mojo launcher eve coin
//      at `SINGLETON_LAUNCHER_HASH` (parent = current Election
//      Singleton coin id).
//   3. `BallotIssuer::launch_ballot(launcher_coin_id, params)` →
//      consume the launcher and mint the eve Ballot Coin singleton at
//      amount=1 (odd, satisfies singleton outer parity invariant).
//   4. Submit the launcher second-spend bundle.
//   5. Assert the eve Ballot Coin lands on chain at the predicted full
//      singleton-wrapped puzzle hash, with parent = launcher_coin_id,
//      amount = 1.
//
// WHY: pins down the FULL launcher-second-spend pipeline (per-ballot
//      action currying → ballot inner action layer → singleton outer
//      → launcher CoinSpend) against the simulator so any drift between
//      the SDK's predicted PH and the actual chia singleton-launcher
//      mint surfaces locally.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ballot::{
    BallotIssuer, CreateBallotParams, LaunchBallotParams,
};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::{DeployParams, NetworkType};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: `BallotIssuer::launch_ballot` builds a launcher second-spend
///       that the simulator accepts, and the predicted
///       `eve_ballot_puzzle_hash` lands on chain at the right singleton
///       puzzle hash with the predicted coin id.
/// HOW:
///   1. Deploy an Election Singleton on a fresh simulator.
///   2. Mint a launcher eve coin via `BallotIssuer::create_ballot`.
///   3. Call `BallotIssuer::launch_ballot(launcher_coin_id, params)`.
///   4. Submit the launcher second-spend bundle.
///   5. Look up the eve Ballot Coin by coin id and assert its puzzle
///      hash matches the SDK's prediction, parent = launcher_coin_id,
///      amount = 1.
/// WHY: this is the FIRST full path that mints an actual on-chain
///      Ballot Coin singleton. Tier 2.2+ work (cast_vote, update_vote,
///      finalize) all gate on this spend landing exactly where the SDK
///      predicts; any divergence between the action curry, action
///      layer, ballot finalizer, or singleton wrap and the simulator's
///      view would surface here.
#[tokio::test(flavor = "current_thread")]
async fn launch_ballot_against_simulator_full_flow() {
    // ── 1. Deploy ────────────────────────────────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000);

    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        // Zero-buffer VK is sufficient: the eve Ballot Coin's
        // `finalize` action is never RUN in this test (only its
        // curried tree hash matters for the prediction). Self-
        // consistency between the SDK's predicted PH and the
        // launcher's mint PH is what we validate.
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

    // ── 2. Funder coin for create_ballot's launcher mint ─────
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

    // ── 3. create_ballot ───────────────────────────────────
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
        .expect("simulator must accept create_ballot bundle");

    // ── 4. launch_ballot ──────────────────────────────────
    let chain = common::SharedSim::new(&mut sim);
    let launched = issuer
        .launch_ballot(
            &chain,
            created.ballot_launcher_id,
            LaunchBallotParams {
                vote_close_height,
                outcome_domain_hash,
                vote_threshold_num: 1,
                vote_threshold_den: 2,
                vote_options_root: Bytes32::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("launch_ballot failed: {:?}", e));

    drop(chain);

    println!(
        "launch_ballot returned eve_ballot_puzzle_hash = {}",
        hex::encode(launched.eve_ballot_puzzle_hash)
    );
    println!(
        "launch_ballot returned eve_ballot_coin_id = {}",
        hex::encode(launched.eve_ballot_coin_id)
    );
    println!(
        "launch_ballot bundle has {} coin spends",
        launched.spend_bundle.coin_spends.len()
    );

    sim.new_transaction(launched.spend_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator must accept launch_ballot bundle; got: {:?}", e));

    // ── 5. Verify the eve Ballot Coin landed ──────────────────
    // Look it up by predicted coin id; assert puzzle hash, parent,
    // and amount all match the SDK's prediction.
    let cs = sim
        .coin_state(launched.eve_ballot_coin_id)
        .unwrap_or_else(|| {
            panic!(
                "expected eve Ballot Coin {} on chain after launch_ballot",
                hex::encode(launched.eve_ballot_coin_id)
            )
        });

    assert_eq!(
        cs.coin.puzzle_hash, launched.eve_ballot_puzzle_hash,
        "eve Ballot Coin must land at SDK-predicted singleton-wrapped puzzle hash",
    );
    assert_eq!(
        cs.coin.parent_coin_info, launched.ballot_launcher_id,
        "eve Ballot Coin's parent must be the launcher coin id",
    );
    assert_eq!(
        cs.coin.amount, 1,
        "eve Ballot Coin must mint at amount=1 (odd, so the singleton outer's \
         parity invariant holds when later spent; the remaining 1 mojo from \
         the 2-mojo launcher coin becomes implicit fee)",
    );
    assert!(
        cs.spent_height.is_none(),
        "eve Ballot Coin must be unspent immediately after launch_ballot",
    );

    // The launcher coin itself must be spent now.
    let launcher_cs = sim
        .coin_state(launched.ballot_launcher_id)
        .expect("launcher coin must remain in simulator state after spend");
    assert!(
        launcher_cs.spent_height.is_some(),
        "launcher coin must be SPENT after launch_ballot bundle is submitted",
    );

    // Sanity: launched.ballot_launcher_id == created.ballot_launcher_id
    assert_eq!(
        launched.ballot_launcher_id, created.ballot_launcher_id,
        "launch_ballot's reported ballot_launcher_id must match create_ballot's",
    );
}
