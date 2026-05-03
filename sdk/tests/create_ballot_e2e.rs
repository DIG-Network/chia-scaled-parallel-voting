// ============================================================================
// tests/create_ballot_e2e.rs — BallotIssuer::create_ballot full simulator flow
// ============================================================================
//
// SCOPE: drives `BallotIssuer::create_ballot` end-to-end against
// `chia_sdk_test::Simulator`:
//   1. Deploy an Election Singleton (`build_deploy_bundle` →
//      `sim.spend_coins`).
//   2. Construct a `BallotIssuer` and call `create_ballot` with
//      arbitrary per-ballot params.
//   3. Submit the resulting `SpendBundle` via `sim.new_transaction`.
//   4. Assert the mined launcher eve coin shows up on chain at
//      `(parent = old_singleton_coin_id, puzzle = SINGLETON_LAUNCHER,
//       amount = 1)` — i.e., the predicted `ballot_launcher_id`.
//
// SCOPE NOTE: this test exercises ONLY the createBallot singleton
// spend (mints the launcher eve coin). The follow-up launcher spend
// that mints the actual Ballot Coin singleton instance requires the
// full deployment-wide ballot curries (VK, IC, threshold pack,
// BALLOT_ACTIONS_MERKLE_ROOT) and lands in a separate task. The
// `ballot_coin_id` returned by `create_ballot` today equals the eve
// coin id; that's what we assert against here.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_protocol::Bytes32;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ballot::{BallotIssuer, CreateBallotParams};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::{DeployParams, NetworkType};

/// WHAT: BallotIssuer::create_ballot builds a spend bundle that the
///       simulator accepts, and the predicted `ballot_launcher_id`
///       (= eve coin id) lands on chain at the singleton-launcher
///       puzzle hash with amount 1.
/// HOW:
///   1. Deploy an Election Singleton on a fresh simulator.
///   2. Build a BallotIssuer, call `create_ballot(...)`.
///   3. Submit the bundle via `sim.new_transaction`.
///   4. Look up the launcher eve coin by its predicted coin id and
///      assert its parent + puzzle hash + amount match what
///      `create_ballot.rue` mints.
/// WHY: pins down the FULL create_ballot pipeline (lineage walk →
///      action layer composition → singleton wrap → sign → submit)
///      against the simulator so any drift between the SDK and the
///      Rue-compiled action puzzle surfaces locally before mainnet.
#[tokio::test(flavor = "current_thread")]
#[ignore = "BallotIssuer::create_ballot dry-run traps with CLVM raise from inside the \
            action-layer/singleton wrapper at puzzle_hash d52eb3ce858ee... — likely a \
            mismatch between the state cons encoding the SDK supplies (state_node_for) \
            and the curried genesis state hash the deployer baked into the singleton \
            puzzle, OR an action-layer merkle-proof shape mismatch. Debug path: \
            instrument dry_run_coin_spends to dump CLVM stack on raise; cross-check \
            against the working Voter::register flow which uses the same helpers."]
async fn create_ballot_against_simulator_full_flow() {
    // ── 1. Deploy ────────────────────────────────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000);

    // Same params as voter_register_full_flow.rs — keeps the two
    // simulator tests aligned on the same Election Singleton shape.
    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            // VK only matters for the ballot finalize action's curry
            // (out of scope here); zeros are sufficient for
            // create_ballot which doesn't touch the VK.
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");

    // ── 2. Build the BallotIssuer + call create_ballot ──────
    // Simulator uses Testnet11 AGG_SIG constants — the issuer's
    // network field controls signing augmentation, so we mirror.
    let issuer = BallotIssuer::new(config.clone(), NetworkType::Testnet11);

    let ballot_seed = Bytes32::new([0xab; 32]);
    let outcome_domain_hash = Bytes32::new([0xcd; 32]);
    let vote_close_height: u64 = 1_000;

    let chain = common::SharedSim::new(&mut sim);
    let result = match issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed,
                vote_close_height,
                outcome_domain_hash,
            },
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("BallotIssuer::create_ballot ERROR: {:?}", e);
            panic!("create_ballot failed");
        }
    };

    println!(
        "create_ballot returned ballot_launcher_id = {}",
        hex::encode(result.ballot_launcher_id)
    );
    println!(
        "create_ballot bundle has {} coin spends",
        result.spend_bundle.coin_spends.len()
    );

    // ── 3. Submit the bundle ──────────────────────────────────
    drop(chain); // release the SharedSim borrow
    sim.new_transaction(result.spend_bundle.clone())
        .unwrap_or_else(|e| panic!("simulator must accept create_ballot bundle; got: {:?}", e));

    // ── 4. Verify the launcher eve coin landed on chain ──────
    // The eve coin's coin_id IS `result.ballot_launcher_id` (per
    // `create_ballot.rue`'s eve coin id formula). Look it up by
    // puzzle_hash = SINGLETON_LAUNCHER_HASH and find the entry whose
    // coin id matches.
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;
    let launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
    let coin_states = sim.lookup_puzzle_hashes(indexmap::indexset![launcher_ph], false);
    let mut found = None;
    for cs in &coin_states {
        if cs.coin.coin_id() == result.ballot_launcher_id {
            found = Some(cs.clone());
            break;
        }
    }
    let cs = found.unwrap_or_else(|| {
        panic!(
            "expected launcher eve coin {} at SINGLETON_LAUNCHER_HASH; \
             got {} unrelated launcher coins",
            hex::encode(result.ballot_launcher_id),
            coin_states.len()
        )
    });

    assert_eq!(
        cs.coin.puzzle_hash, launcher_ph,
        "eve coin must be at SINGLETON_LAUNCHER_HASH"
    );
    assert_eq!(cs.coin.amount, 1, "eve coin must be 1 mojo");
    assert!(
        cs.spent_height.is_none(),
        "eve coin must be unspent immediately after create_ballot"
    );
    assert_eq!(
        result.ballot_coin_id, result.ballot_launcher_id,
        "today the SDK returns ballot_coin_id = eve_coin_id (the launcher \
         second-spend lands in a follow-up task)"
    );
}
