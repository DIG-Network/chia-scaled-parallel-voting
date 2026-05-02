// ============================================================================
// actors/ballot.rs — createBallot lane (CHIP rev 2026-05-02)
// ============================================================================
//
// MODULE: actors::ballot
// PURPOSE: Two actors that bracket the per-Ballot-Coin lifecycle
//          introduced in CHIP rev 2026-05-02:
//
//   * [`BallotIssuer`] — the Election Singleton operator's tool. Drives
//     the singleton's `createBallot` action, minting a fresh Ballot
//     Coin lineage with curried `vote_close_height` and
//     `outcome_domain_hash`. Each call produces one Ballot Coin
//     announcement that subsequent Voting Coins bind themselves to via
//     the Ballot Coin oracle.
//
//   * [`BallotReader`] — read-only enumerator. Walks the chain and
//     surfaces every Ballot Coin associated with the current
//     `ElectionConfig` as a [`BallotCoinSnapshot`]. Mirrors
//     [`Indexer`](crate::actors::Indexer) for ballot-shaped state.
//
// MULTI-BALLOT NOTE: Per the CHIP rev 2026-05-02 spec rework,
//   `finalized` and `vote_outcome` are per-Ballot-Coin properties
//   (not properties of the global ElectionState). Reading them lives
//   here rather than on the Indexer's election-scope accessors.
//
// STUB STATUS: full singleton spend assembly (createBallot) and the
//   on-chain ballot lineage walker land in Phase 6 once the test
//   infrastructure can drive a simulator end-to-end. The public
//   surface is in place today so callers can compile against the
//   final API.

use chia_protocol::{Bytes32, SpendBundle};
use dig_l1_wallet::NetworkType;

use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::state::BallotCoinSnapshot;

/// STRUCT: CreateBallotParams
/// PURPOSE: typed bundle for [`BallotIssuer::create_ballot`]
///          arguments.
/// FIELDS:
///   * `ballot_seed` — per-spend seed mixed into the ballot identifier
///     so successive `createBallot` spends in the same block produce
///     distinct announcements (see `puzzles/election/create_ballot.rue`).
///   * `vote_close_height` — block height at which the ballot stops
///     accepting vote edits. Curried into the Voting Coin's
///     `update_vote` action and asserted by the Ballot Coin's oracle.
///   * `outcome_domain_hash` — 32-byte commitment to the allowed
///     outcome set (e.g. tree-hash of the structured proposal).
///     Carried in the createBallot announcement; the Ballot Coin
///     curries it for finalize.
#[derive(Clone, Debug)]
pub struct CreateBallotParams {
    pub ballot_seed: Bytes32,
    pub vote_close_height: u64,
    pub outcome_domain_hash: Bytes32,
}

/// STRUCT: CreatedBallot
/// PURPOSE: outputs from [`BallotIssuer::create_ballot`].
/// FIELDS:
///   * `ballot_launcher_id` — singleton launcher id of the new Ballot
///     Coin. Stable across the ballot's lifetime; the canonical
///     identity used by `BallotReader::get_ballot` and
///     `Voter::cast_vote`.
///   * `ballot_coin_id` — coin id of the eve Ballot Coin minted by
///     this spend. Useful for ledger-side tracking until the lineage
///     advances.
///   * `spend_bundle` — fully-signed bundle pushable to the mempool by
///     the caller. Per the SDK's no-broadcast rule the issuer NEVER
///     pushes the bundle itself.
#[derive(Clone, Debug)]
pub struct CreatedBallot {
    pub ballot_launcher_id: Bytes32,
    pub ballot_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
}

/// STRUCT: BallotIssuer
/// PURPOSE: drives the Election Singleton's `createBallot` action
///          to mint a fresh Ballot Coin lineage.
/// FIELDS:
///   * `config`  — shared ElectionConfig.
///   * `network` — selects mainnet/testnet AGG_SIG additional data
///     (mirrors the `Voter`'s field — every spend the issuer signs
///     must be augmented under the right network).
///
/// Like every other actor in this crate the issuer is broadcast-free:
/// `create_ballot` returns a [`CreatedBallot`] carrying a signed
/// `SpendBundle` for the caller to push.
pub struct BallotIssuer {
    pub config: ElectionConfig,
    pub network: NetworkType,
}

impl BallotIssuer {
    /// FN: new
    /// WHAT: construct from a validated config + network.
    pub fn new(config: ElectionConfig, network: NetworkType) -> Self {
        Self { config, network }
    }

    /// Build a `createBallot` spend bundle.
    ///
    /// **STUB — full implementation deferred to Phase 6.**
    ///
    /// The eventual flow (per CHIP rev 2026-05-02):
    ///   1. Locate the current Election Singleton via the launcher
    ///      lineage walker.
    ///   2. Drive the singleton's `createBallot` action with
    ///      `(ballot_seed, vote_close_height, outcome_domain_hash)`
    ///      in the action solution. The action emits the
    ///      `createBallot` announcement and returns conditions that
    ///      mint a fresh launcher coin → eve Ballot Coin curried
    ///      with `(election_launcher_id, ballot_launcher_id,
    ///      vote_close_height, outcome_domain_hash, ...)`.
    ///   3. Sign the bundle with the operator's wallet keys via
    ///      [`crate::actors::deployer::sign_bundle_signature`].
    pub async fn create_ballot<C: ChainReader>(
        &self,
        _chain: &C,
        _params: CreateBallotParams,
    ) -> VotingResult<CreatedBallot> {
        Err(VotingError::Other(anyhow_compat::Error(
            "BallotIssuer::create_ballot stubbed pending Phase 6 \
             (singleton-spend assembly + ballot lineage)"
                .to_string()
                .into(),
        )))
    }
}

/// STRUCT: BallotReader
/// PURPOSE: read-only enumerator for Ballot Coins on chain.
/// GENERIC: `C` defaults to `chia_query::ChiaQuery` for source-compat
///          with existing callers; tests can supply a `SharedSimulator`.
/// FIELDS:
///   * `config` — shared ElectionConfig (used to derive the parent
///     Election Singleton lineage).
///   * `chain`  — ChainReader impl driving the on-chain walk.
///
/// Stateless on construction: every method talks to `chain`
/// fresh. (Cf. `Indexer`, which caches the last-synced state — the
/// reader is intentionally lighter weight because Ballot Coin lookups
/// are inherently per-launcher-id.)
pub struct BallotReader<C: ChainReader = chia_query::ChiaQuery> {
    pub config: ElectionConfig,
    chain: C,
}

impl<C: ChainReader> BallotReader<C> {
    /// FN: new
    /// WHAT: construct from a validated config + a ChainReader impl.
    pub fn new(config: ElectionConfig, chain: C) -> Self {
        Self { config, chain }
    }

    /// Shared reference to the underlying chain reader.
    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// FN: list_ballots
    /// WHAT: enumerate every Ballot Coin associated with this
    ///       election as a snapshot.
    /// STATUS: STUB pending Phase 6. The ballot-lineage walker that
    ///         populates the `Vec<BallotCoinSnapshot>` is scheduled
    ///         alongside the rest of the multi-ballot test
    ///         infrastructure.
    pub async fn list_ballots(&self) -> VotingResult<Vec<BallotCoinSnapshot>> {
        Err(VotingError::Other(anyhow_compat::Error(
            "BallotReader::list_ballots stubbed pending Phase 6 \
             (ballot lineage walker)"
                .to_string()
                .into(),
        )))
    }

    /// FN: get_ballot
    /// WHAT: look up a single Ballot Coin by its launcher id.
    /// RETURNS: `Ok(None)` if no ballot with that launcher id exists
    ///          under the current config; `Ok(Some(snapshot))`
    ///          otherwise.
    /// STATUS: STUB pending Phase 6.
    pub async fn get_ballot(
        &self,
        _ballot_launcher_id: Bytes32,
    ) -> VotingResult<Option<BallotCoinSnapshot>> {
        Err(VotingError::Other(anyhow_compat::Error(
            "BallotReader::get_ballot stubbed pending Phase 6 \
             (ballot lineage walker)"
                .to_string()
                .into(),
        )))
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// The mutating / chain-walking methods above are stubs pending Phase 6,
// so there is nothing to unit-test in isolation today. End-to-end
// coverage of `BallotIssuer::create_ballot` and `BallotReader::*` lives
// in `tests/integration.rs` once Phase 6 stands up the simulator
// harness.
