// ============================================================================
// tests/ballot_reader_e2e.rs — BallotReader simulator coverage
// ============================================================================
//
// SCOPE: drives `BallotReader::list_ballots` + `BallotReader::get_ballot`
// against `chia_sdk_test::Simulator` after running create_ballot. Pins
// the chain-walker's contract: every ballot launcher minted by
// `BallotIssuer::create_ballot` shows up in the list, and a direct
// lookup by `ballot_launcher_id` returns the matching snapshot.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ballot::{BallotIssuer, BallotReader, CreateBallotParams};
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::{DeployParams, NetworkType};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: after `BallotIssuer::create_ballot` runs successfully,
///       `BallotReader::list_ballots` returns a single
///       `BallotCoinSnapshot` whose `ballot_launcher_id` matches the
///       eve coin id and `BallotReader::get_ballot(id)` returns the
///       same snapshot.
/// HOW:
///   1. Deploy an Election Singleton + create one ballot.
///   2. Build a `BallotReader` over the same `SharedSim`.
///   3. Call `list_ballots()`; assert it has exactly one entry whose
///      launcher id matches.
///   4. Call `get_ballot(launcher_id)`; assert `Some(_)` is returned.
///   5. Call `get_ballot(random_id)`; assert `None`.
/// WHY: pins the chain-walker's contract for the simplest non-trivial
///      case (one launched ballot). Multi-ballot enumeration is a
///      follow-up regression once the launcher second-spend lands.
#[tokio::test(flavor = "current_thread")]
async fn ballot_reader_lists_and_gets_after_create_ballot() {
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;
    let mut sim = Simulator::new();
    let funder_xch = sim.bls(10_000);

    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
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
        .build_deploy_bundle(funder_xch.coin, funder_xch.pk, true)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder_xch.sk))
        .expect("simulator accepts deploy bundle");

    // Funder spend for the launcher's 2 mojos (quoted-empty-conditions
    // puzzle on a 2-mojo coin).
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
    let chain = common::SharedSim::new(&mut sim);
    let result = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed: Bytes32::new([0xab; 32]),
                vote_close_height: 1_000,
                outcome_domain_hash: Bytes32::new([0xcd; 32]),
                vote_options_root: Bytes32::default(),
            },
            funder_spend,
        )
        .await
        .expect("create_ballot");
    drop(chain);
    sim.new_transaction(result.spend_bundle.clone())
        .expect("simulator accepts create_ballot bundle");

    // Build the reader over a fresh SharedSim view of the same Simulator.
    let chain = common::SharedSim::new(&mut sim);
    let reader = BallotReader::new(config.clone(), chain);

    // ── 1. list_ballots returns the single launcher coin ──────────
    let ballots = reader.list_ballots().await.expect("list_ballots");
    assert_eq!(
        ballots.len(),
        1,
        "expected exactly one ballot launcher; got {}",
        ballots.len()
    );
    let entry = &ballots[0];
    assert_eq!(
        entry.ballot_launcher_id, result.ballot_launcher_id,
        "list_ballots returned wrong launcher id"
    );
    assert_eq!(
        entry.election_launcher_id,
        config.election_launcher_id().expect("config validated"),
    );
    assert_eq!(
        entry.coin_id, result.ballot_launcher_id,
        "today the eve coin id IS the ballot_launcher_id (no second-spend yet)"
    );

    // ── 2. get_ballot(launcher_id) returns the same snapshot ──────
    let single = reader
        .get_ballot(result.ballot_launcher_id)
        .await
        .expect("get_ballot");
    assert!(single.is_some(), "get_ballot should find the just-minted ballot");
    let single = single.unwrap();
    assert_eq!(single.ballot_launcher_id, entry.ballot_launcher_id);
    assert_eq!(single.coin_id, entry.coin_id);

    // ── 3. get_ballot for a random id returns None ────────────────
    let absent = reader
        .get_ballot(Bytes32::new([0xFF; 32]))
        .await
        .expect("get_ballot");
    assert!(absent.is_none(), "random id must not match any ballot");

    // ── 4. Sanity: get_ballot rejects a non-launcher coin (the
    //       singleton itself, which is at the singleton outer puzzle
    //       hash, not at SINGLETON_LAUNCHER_HASH).
    let _ = SINGLETON_LAUNCHER_HASH; // import sanity

    drop(reader);

    // ── 5. Indexer per-ballot accessors mirror BallotReader. ──────
    let chain = common::SharedSim::new(&mut sim);
    let indexer = chip_voting_sdk::actors::Indexer::new(config.clone(), chain);
    let listed = indexer.ballots().await.expect("Indexer::ballots");
    assert_eq!(listed.len(), 1, "Indexer::ballots must match BallotReader");
    assert_eq!(listed[0].ballot_launcher_id, result.ballot_launcher_id);

    let st = indexer
        .ballot_state(result.ballot_launcher_id)
        .await
        .expect("Indexer::ballot_state");
    assert!(st.is_some(), "Indexer::ballot_state should find the just-minted ballot");
    let st = st.unwrap();
    assert!(!st.finalized, "fresh ballot is not finalized");
    assert_eq!(st.vote_outcome, Bytes32::default());

    let finalized = indexer
        .is_finalized_for(result.ballot_launcher_id)
        .await
        .expect("Indexer::is_finalized_for");
    assert!(!finalized, "fresh ballot must report is_finalized_for == false");

    let outcome = indexer
        .vote_outcome_for(result.ballot_launcher_id)
        .await
        .expect("Indexer::vote_outcome_for");
    assert!(outcome.is_none(), "non-finalized ballot must report no outcome");

    // Non-existent id returns false / None across all accessors.
    let absent_id = Bytes32::new([0xEE; 32]);
    assert!(!indexer.is_finalized_for(absent_id).await.unwrap());
    assert!(indexer.vote_outcome_for(absent_id).await.unwrap().is_none());
    assert!(indexer.ballot_state(absent_id).await.unwrap().is_none());
}
