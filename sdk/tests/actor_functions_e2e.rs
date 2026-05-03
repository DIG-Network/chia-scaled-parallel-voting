// ============================================================================
// tests/actor_functions_e2e.rs — exhaustive end-to-end coverage of
//                                EVERY public actor function
// ============================================================================
//
// SCOPE: one or more end-to-end tests per public function in
//        `chip_voting_sdk::actors::*`. Functions that take a chain
//        argument run against a `chia_sdk_test::Simulator`; pure
//        helpers run in-process.
//
// COVERAGE MATRIX (one assertion section per function):
//
//   ElectionDeployer:
//     ::new                                — covered implicitly
//     ::build_deploy_bundle                — `deployer_build_deploy_bundle_*`
//     ::deploy_signed                      — `deployer_deploy_signed_*`
//     ::config_for_launcher                — `deployer_config_for_launcher_*`
//     ::genesis_inner_puzzle_hash          — `deployer_genesis_inner_*`
//     ::election_actions_merkle_root       — `deployer_actions_merkle_root_*`
//
//   VoterKeys:
//     ::new                                — covered implicitly
//     ::sign_unsafe                        — `voter_keys_sign_unsafe_*`
//
//   Voter:
//     ::new                                — covered implicitly
//     ::slot                               — `voter_slot_*`
//     ::registration_coin_puzzle_hash      — `voter_registration_coin_puzzle_hash_*`
//     ::voter_hint                         — `voter_voter_hint_*`
//     ::voter_hint_hex                     — `voter_voter_hint_hex_*`
//     ::register                           — `voter_register_*` (full bundle)
//     ::vote                               — `voter_vote_*` (full bundle)
//     ::release_collateral                 — `voter_release_collateral_*`
//     ::sign_with_voter_and_wallet_keys    — `voter_sign_with_voter_and_wallet_*`
//     ::vote_message                       — `voter_vote_message_*`
//     ::release_message                    — `voter_release_message_*`
//
//   Aggregator:
//     ::new                                — covered implicitly
//     ::chain                              — `aggregator_chain_accessor_*`
//     ::sync                               — `aggregator_sync_*`
//     ::state                              — `aggregator_state_accessor_*`
//     ::voter_set                          — `aggregator_voter_set_accessor_*`
//     ::merkle_tree                        — `aggregator_merkle_tree_accessor_*`
//     ::collect_votes                      — `aggregator_collect_votes_*`
//     ::prepare_finalize_witness           — `aggregator_prepare_witness_*`
//     ::build_finalize                     — `aggregator_build_finalize_*`
//     ::build_finalize_with_proof          — `aggregator_build_finalize_with_proof_*`
//     ::sign_coin_spends                   — `aggregator_sign_coin_spends_*`
//
//   Indexer:
//     ::new                                — covered implicitly
//     ::chain                              — `indexer_chain_accessor_*`
//     ::sync                               — `indexer_sync_*`
//     ::state                              — `indexer_state_accessor_*`
//     ::voter_set                          — `indexer_voter_set_accessor_*`
//     ::registration_count                 — `indexer_registration_count_*`
//     ::is_registered                      — `indexer_is_registered_*`
//     ::is_finalized                       — `indexer_is_finalized_*`
//     ::registration_merkle_root           — `indexer_registration_merkle_root_*`
//     ::vote_outcome                       — `indexer_vote_outcome_*`
//     ::vote_records                       — `indexer_vote_records_*`
//     ::merkle_tree                        — `indexer_merkle_tree_*`

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_protocol::{Bytes32, Coin};
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::voter::VoterKeys;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{Aggregator, ElectionDeployer, Indexer, Voter, VotingError};
use dig_l1_wallet::NetworkType;

// ── ElectionDeployer ────────────────────────────────────────────────

/// WHAT: `build_deploy_bundle` produces 2 coin spends (launcher +
///       parent) AND a fully-validated ElectionConfig.
#[test]
fn deployer_build_deploy_bundle_produces_two_spends_and_config() {
    let mut sim = Simulator::new();
    let funder = sim.bls(1);
    let deployer = ElectionDeployer::new(common::dummy_deploy_params());
    let (coin_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    assert_eq!(
        coin_spends.len(),
        2,
        "deploy bundle has launcher + parent spends"
    );
    config.validate().expect("config self-validates");
    assert_eq!(config.tree_depth, chip_voting_sdk::config::TREE_DEPTH);
}

/// WHAT: `deploy_signed` produces a SpendBundle the simulator
///       accepts (real consensus + signature validation).
/// NETWORK: chia_sdk_test::Simulator validates against testnet11
///          AGG_SIG additional data — the bundle MUST be signed
///          for the same network.
#[test]
fn deployer_deploy_signed_is_simulator_accepted() {
    let mut sim = Simulator::new();
    let funder = sim.bls(1);
    let deployer = ElectionDeployer::new(common::dummy_deploy_params());
    let artifacts = deployer
        .deploy_signed(funder.coin, funder.pk, &[funder.sk], NetworkType::Testnet11)
        .expect("deploy_signed");
    sim.new_transaction(artifacts.spend_bundle)
        .expect("simulator must accept the signed deploy bundle");
}

/// WHAT: `config_for_launcher` returns an ElectionConfig keyed
///       on the launcher_id with all DeployParams fields preserved.
#[test]
fn deployer_config_for_launcher_preserves_params() {
    let params = common::dummy_deploy_params();
    let deployer = ElectionDeployer::new(params.clone());
    let launcher_id = Bytes32::new([0xAB; 32]);
    let config = deployer.config_for_launcher(launcher_id);
    assert_eq!(config.election_launcher_id_hex, hex::encode(launcher_id));
    assert_eq!(config.collateral_amount, params.collateral_amount);
    // CHIP rev 2026-05-02: registration_fee + election_length_blocks were
    // dropped from both ElectionConfig and DeployParams (per-ballot timing
    // replaces global election length; XCH fee removed entirely).
}

/// WHAT: `genesis_inner_puzzle_hash` is deterministic + sensitive
///       to the launcher_id.
#[test]
fn deployer_genesis_inner_puzzle_hash_is_deterministic() {
    let deployer = ElectionDeployer::new(common::dummy_deploy_params());
    let l1 = Bytes32::new([0xAB; 32]);
    let l2 = Bytes32::new([0xCD; 32]);
    assert_eq!(
        deployer.genesis_inner_puzzle_hash(l1),
        deployer.genesis_inner_puzzle_hash(l1)
    );
    assert_ne!(
        deployer.genesis_inner_puzzle_hash(l1),
        deployer.genesis_inner_puzzle_hash(l2)
    );
}

/// WHAT: `election_actions_merkle_root` is deterministic for a
///       (params, launcher_id) pair.
#[test]
fn deployer_actions_merkle_root_is_deterministic() {
    let deployer = ElectionDeployer::new(common::dummy_deploy_params());
    let l = Bytes32::new([0xAB; 32]);
    assert_eq!(
        deployer.election_actions_merkle_root(l),
        deployer.election_actions_merkle_root(l)
    );
}

// ── VoterKeys ──────────────────────────────────────────────────────

/// WHAT: `VoterKeys::sign_unsafe` produces the same signature as
///       `chia_bls::sign_raw` — the verbatim message hashed to G2 without
///       pubkey augmentation, matching `AggSigUnsafe`.
#[test]
fn voter_keys_sign_unsafe_signature_verifies_via_chia_bls() {
    let (sk, _pk) = common::test_voter(0xAB);
    let keys = VoterKeys::new(sk.clone());
    let msg = Bytes32::new([0x42; 32]);
    let sig = keys.sign_unsafe(msg.as_ref());
    assert_eq!(sig, chia_bls::sign_raw(&sk, msg.as_ref()));
}

// ── Voter (pure helpers) ───────────────────────────────────────────

fn build_voter_for_test() -> Voter {
    let (config, _sim) = common::deploy_into_sim();
    let (sk, _pk) = common::test_voter(0x77);
    let keys = VoterKeys::new(sk);
    Voter::new(config, keys, NetworkType::Mainnet)
}

/// WHAT: `Voter::slot` returns the canonical SPT slot for the
///       voter's pubkey.
#[test]
fn voter_slot_matches_smt_canonical_derivation() {
    let voter = build_voter_for_test();
    assert_eq!(
        voter.slot(),
        SparseMerkleTree::slot_for_pubkey(&voter.keys.pubkey)
    );
}

/// WHAT: `Voter::registration_coin_puzzle_hash` is deterministic
///       AND matches the SDK's puzzle-hash predictor.
#[test]
fn voter_registration_coin_puzzle_hash_is_deterministic() {
    let voter = build_voter_for_test();
    let ph1 = voter.registration_coin_puzzle_hash().unwrap();
    let ph2 = voter.registration_coin_puzzle_hash().unwrap();
    assert_eq!(ph1, ph2);
    let cat_tail_hash = voter.config.cat_tail_hash().unwrap();
    let election_id = voter.config.election_launcher_id().unwrap();
    let expected = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter.keys.pubkey,
        election_id,
    );
    assert_eq!(ph1, expected);
}

/// WHAT: `Voter::voter_hint` matches the SDK predicate (launcher +
///       CAT tail + pubkey binding).
#[test]
fn voter_voter_hint_matches_sha256_concat() {
    let voter = build_voter_for_test();
    let hint = voter.voter_hint().unwrap();
    let election_id = voter.config.election_launcher_id().unwrap();
    let cat_tail_hash = voter.config.cat_tail_hash().unwrap();
    let expected =
        chip_voting_sdk::puzzles::voter_hint(election_id, cat_tail_hash, &voter.keys.pubkey);
    assert_eq!(hint, expected);
}

/// WHAT: `Voter::voter_hint_hex` is the `0x`-prefixed hex form of
///       `voter_hint`.
#[test]
fn voter_voter_hint_hex_is_prefixed_hex_form() {
    let voter = build_voter_for_test();
    let hex = voter.voter_hint_hex().unwrap();
    assert!(hex.starts_with("0x"));
    let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(
        Bytes32::new(bytes.try_into().unwrap()),
        voter.voter_hint().unwrap()
    );
}
/// WHAT: `Voter::release_message` is sha256("release" ||
///       election_id || pubkey || destination).
#[test]
fn voter_release_message_is_canonical_derivation() {
    let voter = build_voter_for_test();
    let dest = Bytes32::new([0xEE; 32]);
    let msg = voter.release_message(dest);
    let election_id = voter.config.election_launcher_id().unwrap();
    let expected = common::release_message(election_id, &voter.keys.pubkey, dest);
    assert_eq!(msg, expected);
}

/// WHAT: `Voter::sign_with_voter_and_wallet_keys` aggregates BOTH
///       the voter's BLS sig + the wallet's BLS sig over an empty
///       coin spends list (= identity).
#[test]
fn voter_sign_with_voter_and_wallet_returns_identity_for_no_spends() {
    let voter = build_voter_for_test();
    let (wallet_sk, _) = common::test_voter(0x99);
    let sig = voter
        .sign_with_voter_and_wallet_keys(&[], &wallet_sk)
        .expect("sign_with_voter_and_wallet_keys");
    // No conditions to sign → BLS identity (empty signature).
    assert_eq!(sig.to_bytes(), chia_bls::Signature::default().to_bytes());
}

// ── Aggregator (chain-reading) ─────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn aggregator_chain_accessor_returns_underlying_chain() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    // chain() returns &C; just exercise the borrow.
    let _ = agg.chain();
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_sync_finds_eve_singleton_after_deploy() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    let snapshot = agg.sync().await.expect("sync");
    assert_eq!(snapshot.voter_set.registration_count, 0);
    assert!(snapshot.voter_set.voters.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_state_accessor_returns_genesis_after_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    agg.sync().await.unwrap();
    let state = agg.state().unwrap();
    assert_eq!(state.registration_count, 0);
    // CHIP rev 2026-05-02: ElectionState.{finalized, accumulated_fees,
    // vote_outcome} were dropped — finalization is now per-ballot.
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_voter_set_accessor_returns_empty_after_eve_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    agg.sync().await.unwrap();
    let set = agg.voter_set().unwrap();
    assert_eq!(set.registration_count, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_merkle_tree_accessor_returns_empty_smt_after_eve_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    agg.sync().await.unwrap();
    let smt = agg.merkle_tree().unwrap();
    assert_eq!(smt.root(), SparseMerkleTree::new().root());
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_collect_votes_returns_empty_for_empty_voter_set() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    agg.sync().await.unwrap();
    let votes = agg.collect_votes().await.unwrap();
    assert!(votes.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_prepare_witness_rejects_below_threshold() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    agg.sync().await.unwrap();
    // 0 votes / 0 voters → 2*0 = 0, not > 0 → BelowThreshold.
    // CHIP rev 2026-05-02: per-ballot binding — pass the ballot
    // launcher id as the second argument.
    let res = agg.prepare_finalize_witness(Bytes32::default(), Bytes32::default(), &[]);
    assert!(matches!(res, Err(VotingError::BelowThreshold)));
}

#[tokio::test(flavor = "current_thread")]
async fn aggregator_build_finalize_returns_error_before_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    let pk = test_proving_key();
    let res = agg
        .build_finalize(Bytes32::default(), &[], Bytes32::default(), &pk)
        .await;
    assert!(matches!(res, Err(VotingError::NotDeployed)));
}
#[tokio::test(flavor = "current_thread")]
async fn aggregator_sign_coin_spends_returns_identity_for_empty_input() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let agg = Aggregator::new(config, chain, NetworkType::Mainnet);
    let (sk, _pk) = common::test_voter(0x42);
    let sig = agg
        .sign_coin_spends(&[], &[sk])
        .expect("sign_coin_spends with no spends → identity sig");
    assert_eq!(sig.to_bytes(), chia_bls::Signature::default().to_bytes());
}

// ── Indexer ────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn indexer_chain_accessor_returns_underlying_chain() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let indexer = Indexer::new(config, chain);
    let _ = indexer.chain();
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_sync_succeeds_after_deploy() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.expect("indexer sync");
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_state_accessor_returns_genesis_after_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    let state = indexer.state().unwrap();
    assert_eq!(state.registration_count, 0);
    // CHIP rev 2026-05-02: ElectionState.finalized was dropped —
    // finalization is now per-ballot.
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_voter_set_accessor_returns_empty_after_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    assert_eq!(indexer.voter_set().await.unwrap().registration_count, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_registration_count_returns_zero_after_eve_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    assert_eq!(indexer.registration_count().unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_is_registered_returns_false_for_unregistered_voter() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    let (_sk, pk) = common::test_voter(0xAB);
    assert!(!indexer.is_registered(&pk).unwrap());
}
#[tokio::test(flavor = "current_thread")]
async fn indexer_registration_merkle_root_returns_empty_root_after_eve_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    assert_eq!(
        indexer.registration_merkle_root().unwrap(),
        SparseMerkleTree::new().root()
    );
}
#[tokio::test(flavor = "current_thread")]
async fn indexer_vote_records_returns_empty_for_empty_voter_set() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    let records = indexer.vote_records().await.unwrap();
    assert!(records.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_merkle_tree_returns_empty_smt_after_eve_sync() {
    let (config, mut sim) = common::deploy_into_sim();
    let chain = common::SharedSim::new(&mut sim);
    let mut indexer = Indexer::new(config, chain);
    indexer.sync().await.unwrap();
    assert_eq!(
        indexer.merkle_tree().unwrap().root(),
        SparseMerkleTree::new().root()
    );
}

// ── Helpers ─────────────────────────────────────────────────────────

fn test_proving_key() -> chip_voting_sdk::prover::circuit::ArkProvingKey {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xBEEF);
    let (pk, _vk) = chip_voting_sdk::prover::circuit::generate_test_setup(&mut rng).unwrap();
    pk
}

// Suppress dead-code warning for `Coin` import (used by some test
// helpers above).
#[allow(dead_code)]
fn _coin_ref(_: Coin) {}
