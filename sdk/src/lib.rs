// Doc comments throughout this crate use a structured shape
// (`/// FN: name`, `/// WHAT: ...`, `/// USAGE: ...`, ...) optimised
// for LLM consumption. Clippy interprets the indented continuation
// lines as malformed Markdown lists; silence those specific lints
// crate-wide so the docstring style stays uniform without hundreds
// of per-item allows.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

//! # chip-voting-sdk
//!
//! Reference Rust SDK for the Chia voting CHIP.
//!
//! This crate provides:
//! * Per-actor public APIs ([`actors`]) — `ElectionDeployer`,
//!   `Voter`, `Aggregator`, `Indexer`.
//! * A multi-party Groth16 trusted-setup ceremony API ([`ceremony`]) —
//!   `CeremonyCoordinator`, `CeremonyParticipant`, pluggable
//!   `MpcBackend`, transcript audit chain.
//! * Embedded compiled puzzle bytecode + tree hashes from
//!   `puzzles/compiled/` ([`puzzles`]).
//! * A sparse Merkle tree (depth 32) for the registered voter set
//!   ([`merkle`]).
//! * Off-chain Groth16 prover plumbing ([`prover`]).
//!
//! ## Design philosophy
//!
//! * **The SDK never broadcasts.** All mutating operations return a
//!   `chia_protocol::SpendBundle`; integrators broadcast via their
//!   own RPC / decentralised peer / coinset.org fallback.
//! * **Configuration is portable.** `ElectionConfig` serialises to
//!   JSON; every participant uses an identical copy. Sharing it (e.g.,
//!   posting on the election's website) is safe and required.
//! * **Backends are pluggable.** Wallet I/O ([`actors::deployer::WalletProvider`]),
//!   chain I/O ([`actors::aggregator::ChainReader`]), and MPC crypto
//!   ([`ceremony::MpcBackend`]) are all behind traits. The SDK
//!   doesn't pin a specific Chia client stack or MPC implementation.
//!
//! ## Quick start
//!
//! See per-actor module docs for full examples:
//! * [`actors::deployer`] — bootstrap a new election
//! * [`actors::voter`] — register, vote, recover collateral
//! * [`actors::aggregator`] — finalize an election
//! * [`actors::indexer`] — read on-chain state
//! * [`ceremony`] — run the MPC trusted-setup ceremony

pub mod action_spends;
pub mod actors;
pub mod ceremony;
pub mod chain;
#[cfg(test)]
mod clvm_runner;
pub mod config;
pub mod error;
pub mod merkle;
pub mod prover;
pub mod puzzles;
pub mod state;

// ── Public re-exports ─────────────────────────────────────────────────

pub use actors::ballot::{BallotIssuer, BallotReader, CreateBallotParams, CreatedBallot};
pub use actors::deployer::{DeployParams, DeploymentArtifacts};
pub use actors::voter::VoterKeys;
pub use actors::{Aggregator, ElectionDeployer, Indexer, Voter};
pub use config::{ElectionConfig, MAX_SIGNERS, PUBLIC_INPUT_COUNT, TREE_DEPTH};
pub use error::{VotingError, VotingResult};
pub use state::{ElectionState, RegistrationState, VoteRecord, VoterSet};

pub use ceremony::{
    CeremonyCoordinator, CeremonyParticipant, MpcBackend, SimulatedBackend, Transcript,
    VerificationKey,
};

// Groth16 prover surface — the type-safe entry points for off-chain
// proof generation and verification. The arkworks `Bls12_381` keys
// live behind newtype wrappers (`ArkProvingKey`, `ArkVerifyingKey`)
// so callers don't need a direct arkworks dependency.
pub use prover::circuit::{
    generate_test_setup, ArkProvingKey, ArkVerifyingKey, SignerWitness, VotingCircuit,
};
pub use prover::{Groth16Proof, Scalars};

// The recommended upstream signing helper. Wraps
// `chia_sdk_signer::RequiredSignature::from_coin_spends` and the
// network's `agg_sig_me_additional_data`.
pub use actors::deployer::sign_bundle_signature;

/// FN: dry_run_coin_spends
/// WHAT: run every `coin_spend.puzzle_reveal` locally against its
///       `solution` and report the first one that traps. Returns
///       `Ok(())` if all puzzles execute cleanly, otherwise a
///       descriptive error pointing at the offending coin id +
///       puzzle hash so the operator can correlate with on-chain
///       state.
/// USAGE: pre-broadcast diagnostic — much more useful than the
///        opaque `clvm raise` errors that come back from
///        `RequiredSignature::from_coin_spends`.
pub fn dry_run_coin_spends(coin_spends: &[chia_protocol::CoinSpend]) -> error::VotingResult<()> {
    use clvm_traits::ToClvm;
    use clvmr::{run_program, Allocator, ChiaDialect};

    let dialect = ChiaDialect::new(0);
    for (i, cs) in coin_spends.iter().enumerate() {
        let mut allocator = Allocator::new();
        let puzzle_node = cs.puzzle_reveal.to_clvm(&mut allocator).map_err(|e| {
            error::VotingError::Other(error::anyhow_compat::Error(
                format!(
                    "dry_run[{i}]: puzzle {} to_clvm: {e}",
                    hex::encode(cs.coin.puzzle_hash)
                )
                .into(),
            ))
        })?;
        // Pre-flight: verify the puzzle reveal's tree hash actually
        // matches the coin's declared puzzle hash. If not, consensus
        // would reject with WrongPuzzleHash; surfacing the mismatch
        // here pinpoints the assembly bug instead of bouncing off
        // the network.
        let actual_ph = clvm_utils::tree_hash(&allocator, puzzle_node);
        if actual_ph.to_bytes().as_slice() != cs.coin.puzzle_hash.as_ref() {
            return Err(error::VotingError::Other(error::anyhow_compat::Error(
                format!(
                    "dry_run[{i}]: PUZZLE-HASH MISMATCH for coin {}\n  \
                     declared: {}\n  actual:   {}",
                    hex::encode(cs.coin.coin_id()),
                    hex::encode(cs.coin.puzzle_hash),
                    hex::encode(actual_ph),
                )
                .into(),
            )));
        }
        let solution_node = cs.solution.to_clvm(&mut allocator).map_err(|e| {
            error::VotingError::Other(error::anyhow_compat::Error(
                format!(
                    "dry_run[{i}]: solution for coin {} to_clvm: {e}",
                    hex::encode(cs.coin.coin_id())
                )
                .into(),
            ))
        })?;
        match run_program(
            &mut allocator,
            &dialect,
            puzzle_node,
            solution_node,
            11_000_000_000,
        ) {
            Ok(_) => {} // success, conditions discarded
            Err(e) => {
                return Err(error::VotingError::Other(error::anyhow_compat::Error(
                    format!(
                        "dry_run[{i}]: coin {} (puzzle_hash {}) FAILED to execute: {e:?}",
                        hex::encode(cs.coin.coin_id()),
                        hex::encode(cs.coin.puzzle_hash),
                    )
                    .into(),
                )));
            }
        }
    }
    Ok(())
}

/// FN: validate_bundle_for_consensus
/// WHAT: run a `SpendBundle` through `chia_consensus::
///       validate_clvm_and_signature` — the SAME function full
///       nodes call to admit a bundle into mempool. Surfaces the
///       actual `ErrorCode` (`AssertHeightRelativeFailed`,
///       `BadAggregateSignature`, `CostExceeded`,
///       `GeneratorRuntimeError`, …) on rejection.
/// WHY:  `dry_run_coin_spends` only runs CLVM in isolation; it
///       does NOT enforce consensus rules like
///       `ASSERT_HEIGHT_RELATIVE`, AGG_SIG augmentation,
///       cost-per-byte accounting, or the bundle-level aggregated
///       signature verification. A bundle that passes
///       `dry_run_coin_spends` can still be rejected by
///       `chia_query::push_tx` with the opaque `status=FAILED`
///       (which carries no error string — the peer protocol's
///       `TransactionAck` only conveys the `1=SUCCESS / 2=PENDING
///       / 3=FAILED` byte). Calling this function pre-broadcast
///       turns that opaque rejection into a typed `ErrorCode` we
///       can act on / log.
///
/// NETWORK CONSTANTS: this currently uses
/// `chia_consensus::consensus_constants::TEST_CONSTANTS` because
/// upstream's mainnet constants are mostly identical for our
/// purposes (same `genesis_challenge`, same
/// `agg_sig_*_additional_data`, same `max_block_cost_clvm`) — and
/// `TEST_CONSTANTS` is the only `ConsensusConstants` value the
/// crate exposes outside its own test module. If a future
/// mainnet hard-fork bumps these values divergently, replace
/// with `MAINNET_CONSTANTS` once upstream re-exports it.
///
/// HEIGHT: caller-supplied current chain peak height. The mempool
/// admission path uses `peak_height + 1` (the height the bundle
/// would land at). Pass `chain.peak_height().await` + 1.
pub fn validate_bundle_for_consensus(
    bundle: &chia_protocol::SpendBundle,
    height: u32,
) -> error::VotingResult<u64> {
    use chia_consensus::consensus_constants::TEST_CONSTANTS;
    use chia_consensus::spendbundle_validation::validate_clvm_and_signature;
    let max_cost = TEST_CONSTANTS.max_block_cost_clvm;
    match validate_clvm_and_signature(bundle, max_cost, &TEST_CONSTANTS, height) {
        Ok((conds, _pairs, _dur)) => Ok(conds.cost),
        Err(error_code) => Err(error::VotingError::Other(error::anyhow_compat::Error(
            format!("consensus pre-flight rejected at height {height}: {error_code:?}",).into(),
        ))),
    }
}

/// FN: verify_bundle_signatures
/// WHAT: locally verify that every AGG_SIG_* condition emitted by
///       `bundle.coin_spends` is satisfied by
///       `bundle.aggregated_signature` for the given `network`.
/// WHY:  catches signing bugs BEFORE broadcast — a bundle with a
///       bad signature would otherwise be silently dropped by
///       farmers' mempools. Used by the live integration test as a
///       pre-broadcast gate; downstream callers can use it for the
///       same purpose.
/// PIPELINE:
///   1. `RequiredSignature::from_coin_spends` walks every coin spend's
///      conditions and builds the (pubkey, augmented_message) pairs
///      consensus expects.
///   2. `chia_bls::aggregate_verify` checks the aggregated signature
///      against those pairs.
pub fn verify_bundle_signatures(
    bundle: &chia_protocol::SpendBundle,
    network: chia_query::NetworkType,
) -> error::VotingResult<()> {
    use chia_sdk_signer::{AggSigConstants, RequiredSignature};
    use clvmr::Allocator;
    use dig_l1_wallet::transaction::get_agg_sig_data;

    let agg = AggSigConstants::new(get_agg_sig_data(network));
    let mut allocator = Allocator::new();
    let required = RequiredSignature::from_coin_spends(&mut allocator, &bundle.coin_spends, &agg)
        .map_err(|e| {
        error::VotingError::Other(error::anyhow_compat::Error(
            format!("RequiredSignature::from_coin_spends: {e}").into(),
        ))
    })?;
    let pairs: Vec<(chia_bls::PublicKey, Vec<u8>)> = required
        .into_iter()
        .map(|sig| match sig {
            RequiredSignature::Bls(b) => (b.public_key, b.message()),
            other => {
                panic!("verify_bundle_signatures: unexpected non-BLS signature variant: {other:?}")
            }
        })
        .collect();
    let pairs_ref: Vec<(&chia_bls::PublicKey, &[u8])> =
        pairs.iter().map(|(pk, m)| (pk, m.as_slice())).collect();
    if !chia_bls::aggregate_verify(&bundle.aggregated_signature, pairs_ref) {
        return Err(error::VotingError::Other(error::anyhow_compat::Error(
            "verify_bundle_signatures: aggregate_verify FAILED".into(),
        )));
    }
    Ok(())
}

// Re-export Chia primitives so callers don't need a direct chia-protocol dep
// just to construct the types they pass to us.
pub use chia_bls::{PublicKey, SecretKey, Signature};
pub use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};

// Re-export recommended ecosystem types for ergonomic top-level use.
pub use actors::aggregator::wait_for_current_singleton;
pub use chain::wait_for_unspent_coin_at_puzzle_hash;
pub use chia_query::{ChiaQuery, ChiaQueryConfig, NetworkType};
// Re-export the coinset.org HTTP client. `chia_query`'s router does
// peer → peer-retry → coinset, returning the FIRST peer's TxStatus
// even when that status is `FAILED` (which is `Ok(TxStatus { status:
// "FAILED" })`, not an `Err`). For broadcasts where we care about a
// canonical full-node verdict (e.g. the finalize bundle, where one
// stale peer's FAILED ack would otherwise block a perfectly valid
// bundle), callers can construct a `CoinsetClient` directly and
// bypass the peer pool entirely.
pub use chia_bls::master_to_wallet_unhardened;
pub use chia_puzzle_types::{
    cat::CatArgs, standard::StandardArgs, DeriveSynthetic, LineageProof, Memos, Proof,
};
pub use chia_puzzles::SINGLETON_LAUNCHER_HASH;
pub use chia_query::coinset::CoinsetClient;
pub use chia_sdk_driver::{
    Cat, CatInfo, CatSpend, Launcher, Puzzle, SingleCatSpend, Spend, SpendContext,
    SpendWithConditions, Spends, StandardLayer,
};
pub use chia_sdk_signer::{AggSigConstants, RequiredBlsSignature, RequiredSignature};
pub use chia_sdk_types::Conditions;
pub use clvm_traits;
pub use clvm_utils;
pub use clvmr;
pub use dig_l1_wallet::{CoinSelectionStrategy, L1Wallet, L1WalletConfig};
