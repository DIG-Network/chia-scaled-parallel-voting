// ============================================================================
// actors/ — per-role public API for the voting lifecycle
// ============================================================================
//
// MODULE: actors
// PURPOSE: One actor type per role in the voting lifecycle. Each
//          actor owns the operations relevant to its role and exposes
//          a stable async API that returns `chia_protocol::SpendBundle`
//          for callers to broadcast.
//
// ROLES:
//   | Actor                | Operations                                            |
//   |----------------------|-------------------------------------------------------|
//   | [`ElectionDeployer`] | One-time genesis deploy of the Election Singleton     |
//   | [`Voter`]            | register, vote, release_collateral                    |
//   | [`Aggregator`]       | sync state, collect votes, build Groth16 proof, finalize |
//   | [`Indexer`]          | read-only state queries                               |
//   | [`Oracle`]           | permissionless oracle-action spend for the (un)finalized vote result |
//
// SHARED CONTRACT:
//   * NO BROADCAST — every mutating method returns a SpendBundle for
//     the caller to push via their own `chia_query::ChiaQuery` /
//     coinset.org / peer-pool client. Keeps the SDK transport-agnostic
//     and lets callers batch / re-try / fee-bump on their own terms.
//   * GENERIC OVER `ChainReader` — Aggregator and Indexer are generic
//     `<C: ChainReader = chia_query::ChiaQuery>` so production code
//     uses real chain queries while tests inject a `SharedSimulator`.
//   * SIGNED VIA UPSTREAM — every signing path delegates to
//     `dig_l1_wallet::transaction::sign_coin_spends` →
//     `chia_sdk_signer::RequiredSignature::from_coin_spends`, the
//     canonical Chia signing pipeline.

pub mod aggregator;
pub mod deployer;
pub mod indexer;
pub mod oracle;
pub mod voter;

pub use aggregator::Aggregator;
pub use deployer::{DeploymentArtifacts, ElectionDeployer};
pub use indexer::Indexer;
pub use oracle::{announcement_for_state, Oracle, OracleAnnouncement, OracleSpend};
pub use voter::Voter;
