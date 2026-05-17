// ============================================================================
// tests/ceremony_deploy_e2e.rs — CeremonyDeployer simulator smoke
// ============================================================================
//
// SCOPE: drives `CeremonyDeployer::build_deploy_bundle` end-to-end
// against `chia_sdk_test::Simulator`:
//   1. Mint a funded BLS wallet on a fresh simulator.
//   2. Build the genesis Ceremony Singleton bundle.
//   3. Submit via `sim.spend_coins`.
//   4. Assert the predicted launcher_id matches
//      `CeremonyDeployer::derive_launcher_id`.
//
// SCOPE NOTE: this test exercises ONLY the genesis launcher spend.
// The follow-up `contribute` action (which spends the eve singleton)
// requires the action-layer dispatch to accept a participant
// AGG_SIG_UNSAFE — covered in a separate `ceremony_contribute_e2e.rs`
// once the merkle-root convention is verified end-to-end.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

use chia_protocol::Bytes32;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ceremony::{CeremonyDeployer, CeremonyParams};

/// WHAT: `CeremonyDeployer::build_deploy_bundle` produces a bundle
///       that the simulator accepts, and the returned `launcher_id`
///       matches `CeremonyDeployer::derive_launcher_id(parent_coin_id,
///       1)`.
/// HOW:
///   1. Spin up a Simulator + 10_000-mojo funded wallet (`sim.bls`).
///   2. Build a CeremonyDeployer with arbitrary parameters.
///   3. Call `build_deploy_bundle(funder.coin, funder.pk)`.
///   4. Submit via `sim.spend_coins(spends, &[funder.sk])`.
///   5. Cross-check `launcher_id` against `derive_launcher_id`.
/// WHY: pins down the FULL CeremonyDeployer pipeline (genesis state
///      hash → action-layer curry → singleton wrap → standard p2
///      funder spend → sign → submit) against the simulator so any
///      drift between the SDK and the Rue-compiled finalizer/contribute
///      puzzle surfaces locally before mainnet.
#[tokio::test(flavor = "current_thread")]
async fn ceremony_deploy_against_simulator_smoke() {
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000);

    let params = CeremonyParams {
        start_block_height: 0,
        ceremony_length_blocks: 1_000,
        min_participants: 1,
        max_voters: 20_000,
        vk_seed: Bytes32::new([0x42; 32]),
        label: Some("simulator-smoke".into()),
    };
    let deployer = CeremonyDeployer::new(params);

    let (deploy_spends, launcher_id) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");

    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts ceremony deploy bundle");

    let predicted = CeremonyDeployer::derive_launcher_id(funder.coin.coin_id(), 1);
    assert_eq!(
        launcher_id, predicted,
        "deployer's launcher_id must match deterministic derivation"
    );
}
