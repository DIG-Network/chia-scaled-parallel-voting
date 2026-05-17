//! Regression: deployer's on-chain eve singleton puzzle hash MUST equal
//! the Aggregator's predicted hash for the SAME `election_start_height`.
//!
//! Failure mode this guards against (observed on mainnet 2026-05-05):
//! the live test passed `election_start_height=current_peak()` to
//! `DeployParams`, so the on-chain eve singleton's curried state used
//! that real height. But `Aggregator::new` defaulted
//! `election_start_height = 0` and never received the real value via
//! `with_election_start_height(...)`. Sync queried for the wrong
//! puzzle hash and silently retried `NotDeployed` for 15 minutes
//! before timing out — even though the coins were on chain the whole
//! time.
//!
//! This test asserts that for any non-zero `election_start_height`:
//!   * the deployer's `genesis_inner_puzzle_hash` (the value baked into
//!     the on-chain launcher's CreateCoin output and therefore the eve
//!     singleton's actual puzzle_hash) and
//!   * the Aggregator helper's prediction
//! agree byte-for-byte. Any drift in either function (state shape,
//! curry order, finalizer chain, action root) is caught here without
//! touching the chain.

use chia_protocol::Bytes32;
use chip_voting_sdk::actors::aggregator::{
    compute_eve_inner_puzzle_hash, compute_eve_singleton_puzzle_hash,
};
use chip_voting_sdk::actors::deployer::{DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;

fn placeholder_vk() -> VerificationKey {
    VerificationKey {
        raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
    }
}

fn deploy_params(start_height: u64) -> DeployParams {
    DeployParams {
        verification_key: placeholder_vk(),
        cat_tail_hash: Bytes32::new([0x77; 32]),
        collateral_amount: 100,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: chip_voting_sdk::config::MAX_SIGNERS,
        ceremony_launcher_id: Bytes32::default(),
        vk_hash: Bytes32::default(),
        vote_mode_lock: chip_voting_sdk::vote_mode::VOTE_MODE_LOCK_NONE,
        election_start_height: start_height,
        label: Some("deployer-aggregator-parity".into()),
    }
}

fn launcher_id_for_test() -> Bytes32 {
    // Any deterministic non-zero launcher id; the parity must hold for
    // every value, so a fixed test value is fine.
    Bytes32::new([0xAB; 32])
}

#[test]
fn deployer_inner_hash_equals_aggregator_inner_hash_at_zero_height() {
    let height = 0u64;
    let d = ElectionDeployer::new(deploy_params(height));
    let launcher = launcher_id_for_test();

    let deployer_inner = d.genesis_inner_puzzle_hash(launcher);
    let agg_inner = compute_eve_inner_puzzle_hash(&d.config_for_launcher(launcher), height);

    assert_eq!(
        deployer_inner, agg_inner,
        "election_start_height=0: deployer's genesis_inner_puzzle_hash must equal \
         compute_eve_inner_puzzle_hash"
    );
}

#[test]
fn deployer_inner_hash_equals_aggregator_inner_hash_at_mainnet_height() {
    // The exact mainnet height observed during the failing live run.
    // Any real chain peak triggers the same divergence if either side
    // hard-codes the height. Pin a real value so future regressions can
    // diagnose against this exact case.
    let height = 8_681_056u64;
    let d = ElectionDeployer::new(deploy_params(height));
    let launcher = launcher_id_for_test();

    let deployer_inner = d.genesis_inner_puzzle_hash(launcher);
    let agg_inner = compute_eve_inner_puzzle_hash(&d.config_for_launcher(launcher), height);

    assert_eq!(
        deployer_inner, agg_inner,
        "election_start_height={height}: deployer + Aggregator MUST agree on inner hash"
    );
}

#[test]
fn deployer_outer_hash_equals_aggregator_outer_hash_at_mainnet_height() {
    let height = 8_681_056u64;
    let d = ElectionDeployer::new(deploy_params(height));
    let launcher = launcher_id_for_test();

    let deployer_inner = d.genesis_inner_puzzle_hash(launcher);
    let deployer_outer =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher, deployer_inner);

    let agg_outer =
        compute_eve_singleton_puzzle_hash(&d.config_for_launcher(launcher), height);

    assert_eq!(
        deployer_outer, agg_outer,
        "deployer + Aggregator MUST agree on the eve singleton OUTER puzzle hash \
         (the value Aggregator::sync queries against on chain). \
         If this diverges, sync returns NotDeployed even though the deployment \
         is on chain — exactly the mainnet-2026-05-05 failure."
    );
}

#[test]
fn aggregator_default_height_diverges_from_nonzero_deploy() {
    // Documents the *observed* divergence so callers know they must
    // call `.with_election_start_height(...)` after constructing an
    // Aggregator that targets a deployment at non-zero height.
    let nonzero_height = 8_681_056u64;
    let d = ElectionDeployer::new(deploy_params(nonzero_height));
    let launcher = launcher_id_for_test();

    let deployer_outer = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
        launcher,
        d.genesis_inner_puzzle_hash(launcher),
    );
    let agg_outer_with_default =
        compute_eve_singleton_puzzle_hash(&d.config_for_launcher(launcher), 0);

    assert_ne!(
        deployer_outer, agg_outer_with_default,
        "If this assertion fails, the divergence is no longer reproducible — \
         either the deployer no longer reads election_start_height, or the \
         Aggregator helper now ignores its height argument. Either change \
         is a real spec drift; investigate before relaxing this test."
    );
}
