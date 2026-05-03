// ============================================================================
// actors/indexer.rs — read-only state observer
// ============================================================================
//
// MODULE: actors::indexer
// PURPOSE: Headless dashboard / monitoring view of an election. Same
//          chain-walk logic as `Aggregator::sync` but without any
//          spend-bundle production.
// USAGE: block explorers, status pages, exchanges that need to know if
//        an election is finalized before honouring a withdrawal of
//        the underlying CAT.
// CACHE: same `state + voter_set + smt + ballots` quadruple as
//        Aggregator, populated by `sync()`. All queries return
//        `NotDeployed` until the first sync.
//
// MULTI-BALLOT NOTE (CHIP rev 2026-05-02):
//   Per the spec rework, finalization and `vote_outcome` are
//   per-Ballot-Coin properties, NOT properties of the global
//   ElectionState. The previous global `is_finalized()` /
//   `vote_outcome()` accessors have therefore been removed; their
//   replacements are the per-ballot async accessors below
//   (`is_finalized_for(launcher_id)`, `vote_outcome_for(launcher_id)`,
//   etc.). Several of these are stubbed pending Phase 6 ballot-lineage
//   walker test infrastructure — the surface exists today so callers
//   can compile against the final API.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;

use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{VotingError, VotingResult};
use crate::merkle::SparseMerkleTree;
use crate::state::{BallotCoinSnapshot, BallotState, ElectionState, VoteRecord, VoterSet};

// Indexer delegates the chain-walk + memo-extraction logic to the
// shared `sync_state` / `extract_votes` free functions in
// `actors::aggregator`. This gives us a single source of truth for
// the parsing semantics — any change in one side is automatically
// inherited by the other.

/// STRUCT: Indexer
/// PURPOSE: read-only chain observer.
/// GENERIC: `C` defaults to `chia_query::ChiaQuery` for source-compat
///          with existing callers; tests can supply a `SharedSimulator`.
pub struct Indexer<C: ChainReader = chia_query::ChiaQuery> {
    pub config: ElectionConfig,
    chain: C,
    state: Option<ElectionState>,
    voter_set: Option<VoterSet>,
    smt: Option<SparseMerkleTree>,
    /// Per-Ballot-Coin snapshots recovered from the most recent sync.
    /// Pending Phase 6 test infrastructure the aggregator returns an
    /// empty vec here; the field exists so callers can begin coding
    /// against the final API.
    ballots: Option<Vec<BallotCoinSnapshot>>,
    /// Same per-config eve puzzle hash the Aggregator computes —
    /// caches the result of `compute_eve_singleton_puzzle_hash` so
    /// repeated `sync()` calls don't recompute the curry chain.
    eve_singleton_puzzle_hash: Bytes32,
    /// Birth height for the eve singleton. Mirrors the aggregator's
    /// equivalent field — needed because both
    /// `compute_eve_singleton_puzzle_hash` and `sync_with_chain`
    /// take `election_start_height` post-CHIP-rev-2026-05-02. The
    /// indexer doesn't know the launch height a priori (callers
    /// don't supply it via `Indexer::new`), so we default to `0`,
    /// matching the choice in `voter.rs::register_for_election`'s
    /// eve fast path. A future task can plumb a real value through
    /// the constructor or read it from the chain via the launcher
    /// coin's `confirmed_block_index`.
    election_start_height: u64,
}

impl<C: ChainReader> Indexer<C> {
    /// Construct from a validated config + a ChainReader impl.
    pub fn new(config: ElectionConfig, chain: C) -> Self {
        // ARITY-FIX: `compute_eve_singleton_puzzle_hash` now takes
        // `(config, election_start_height)`. We default to `0` here —
        // see the doc-comment on `Self::election_start_height` for the
        // rationale. Voter.rs makes the same choice in its register
        // fast path.
        let election_start_height: u64 = 0;
        let eve_singleton_puzzle_hash =
            crate::actors::aggregator::compute_eve_singleton_puzzle_hash(
                &config,
                election_start_height,
            );
        Self {
            config,
            chain,
            state: None,
            voter_set: None,
            smt: None,
            ballots: None,
            eve_singleton_puzzle_hash,
            election_start_height,
        }
    }

    /// Shared reference to the underlying chain reader.
    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// FN: sync
    /// WHAT: refresh the cache from the chain.
    /// IMPL: delegates to the shared
    ///       `actors::aggregator::sync_with_chain` free function so
    ///       the Indexer and Aggregator interpret on-chain state
    ///       byte-identically. Handles both the eve (genesis) case
    ///       and the post-spend lineage walk that recovers the
    ///       latest singleton coin + voter set from emitted
    ///       register-action announcements.
    pub async fn sync(&mut self) -> VotingResult<()> {
        // ARITY-FIX: `sync_with_chain` now takes a 4th arg
        // `election_start_height` (was 3 args pre-CHIP-rev-2026-05-02).
        let snapshot = crate::actors::aggregator::sync_with_chain(
            &self.chain,
            &self.config,
            self.eve_singleton_puzzle_hash,
            self.election_start_height,
        )
        .await?;
        self.state = Some(snapshot.state);
        self.voter_set = Some(snapshot.voter_set);
        self.smt = Some(snapshot.smt);
        self.ballots = Some(snapshot.ballots);
        Ok(())
    }

    /// Last-synced ElectionState. `NotDeployed` if no sync yet.
    ///
    /// Sync semantics: this is a read-through accessor over the
    /// already-cached state. It does NOT trigger a chain-walk. Call
    /// `sync()` first.
    pub fn state(&self) -> VotingResult<&ElectionState> {
        self.state.as_ref().ok_or(VotingError::NotDeployed)
    }

    /// FN: election_state
    /// WHAT: async clone-returning variant of `state()` for callers
    ///       that want to await a fresh view. Currently returns the
    ///       last-synced cached state (does not auto-sync); shape
    ///       matches the Aggregator's API for symmetry.
    pub async fn election_state(&self) -> VotingResult<ElectionState> {
        Ok(self.state()?.clone())
    }

    /// Last-synced VoterSet. See `state()`.
    pub fn voter_set_ref(&self) -> VotingResult<&VoterSet> {
        self.voter_set.as_ref().ok_or(VotingError::NotDeployed)
    }

    /// FN: voter_set
    /// WHAT: async clone-returning variant of `voter_set_ref()`. The
    ///       async signature mirrors the multi-ballot accessors below
    ///       so callers don't have to mix sync and async at the call
    ///       site.
    pub async fn voter_set(&self) -> VotingResult<VoterSet> {
        Ok(self.voter_set_ref()?.clone())
    }

    /// Convenience: registered voter count.
    pub fn registration_count(&self) -> VotingResult<u64> {
        Ok(self.state()?.registration_count)
    }

    /// Convenience: is `pubkey` in the registered set?
    /// COST: O(n) linear scan — for high-throughput UIs maintain your
    ///       own `HashSet<[u8; 48]>` cached from `voter_set().voters`.
    pub fn is_registered(&self, pubkey: &PublicKey) -> VotingResult<bool> {
        let set = self.voter_set_ref()?;
        Ok(set.voters.iter().any(|v| v == pubkey))
    }

    /// Current SPT root. Same data the aggregator's circuit consumes
    /// as a public input.
    pub fn registration_merkle_root(&self) -> VotingResult<Bytes32> {
        Ok(self.state()?.registration_merkle_root)
    }

    // ========================================================================
    // Per-ballot accessors (CHIP rev 2026-05-02)
    // ========================================================================
    //
    // The global `is_finalized()` and `vote_outcome()` accessors that
    // used to live here have been removed: under multi-ballot
    // semantics, both are properties of an individual Ballot Coin and
    // are not meaningful at the election scope. The accessors below
    // replace them. Several are stubbed pending Phase 6 (ballot-
    // lineage walker test infrastructure) — the surface exists today
    // so callers can begin compiling against the final API.

    /// FN: ballots
    /// WHAT: list every Ballot Coin (or its launcher eve coin) for
    ///       this election by walking the chain. Delegates to
    ///       [`crate::actors::ballot::list_ballots_via_chain`].
    /// NOTE: bypasses the cached `self.ballots` populated by
    ///       `sync()` so callers get a fresh on-chain view per call.
    ///       This matches the behaviour of the other per-ballot
    ///       async accessors below.
    pub async fn ballots(&self) -> VotingResult<Vec<BallotCoinSnapshot>> {
        crate::actors::ballot::list_ballots_via_chain(&self.config, &self.chain).await
    }

    /// FN: ballot_state
    /// WHAT: per-ballot `BallotState` (`finalized` / `vote_outcome` /
    ///       `agg_signers`) for the ballot identified by
    ///       `ballot_launcher_id`. Returns `None` if no ballot with
    ///       that id exists under this election.
    /// IMPL: delegates to
    ///       [`crate::actors::ballot::get_ballot_via_chain`] and
    ///       extracts the snapshot's `state` field.
    pub async fn ballot_state(
        &self,
        ballot_launcher_id: Bytes32,
    ) -> VotingResult<Option<BallotState>> {
        let snapshot = crate::actors::ballot::get_ballot_via_chain(
            &self.config,
            &self.chain,
            ballot_launcher_id,
        )
        .await?;
        Ok(snapshot.map(|s| s.state))
    }

    /// FN: votes_for_ballot
    /// WHAT: every `VoteRecord` cast against the ballot identified by
    ///       `ballot_launcher_id`.
    /// IMPL: requires `sync()` has populated the voter set; delegates
    ///       to the same per-voter hint-walking logic as
    ///       [`crate::actors::aggregator::collect_votes_for_ballot_via_chain`]
    ///       (so the indexer + aggregator stay byte-identical on the
    ///       chain-walk side).
    pub async fn votes_for_ballot(
        &self,
        ballot_launcher_id: Bytes32,
    ) -> VotingResult<Vec<VoteRecord>> {
        let voter_set = self.voter_set.as_ref().ok_or(VotingError::NotDeployed)?;
        crate::actors::aggregator::collect_votes_for_ballot_via_chain(
            &self.config,
            &self.chain,
            ballot_launcher_id,
            voter_set,
        )
        .await
    }

    /// FN: is_finalized_for
    /// WHAT: per-ballot replacement for the removed global
    ///       `is_finalized()` accessor. Returns `false` if no ballot
    ///       with that id exists or the ballot hasn't been finalized.
    /// IMPL: pulls `BallotState.finalized` from `ballot_state`.
    pub async fn is_finalized_for(&self, ballot_launcher_id: Bytes32) -> VotingResult<bool> {
        let st = self.ballot_state(ballot_launcher_id).await?;
        Ok(st.map(|s| s.finalized).unwrap_or(false))
    }

    /// FN: vote_outcome_for
    /// WHAT: per-ballot replacement for the removed global
    ///       `vote_outcome()` accessor. Returns `None` for an
    ///       unfinalized ballot OR a non-existent one;
    ///       `Some(outcome_bytes)` for a finalized one.
    /// IMPL: pulls `BallotState.vote_outcome` from `ballot_state` and
    ///       gates on `BallotState.finalized`.
    pub async fn vote_outcome_for(
        &self,
        ballot_launcher_id: Bytes32,
    ) -> VotingResult<Option<Bytes32>> {
        let st = self.ballot_state(ballot_launcher_id).await?;
        Ok(st.and_then(|s| if s.finalized { Some(s.vote_outcome) } else { None }))
    }

    /// FN: vote_records
    /// WHAT: live tally — every voter who has cast a vote so far,
    ///       across all ballots. For per-ballot enumeration use
    ///       `votes_for_ballot(launcher_id)` once Phase 6 lands.
    /// IMPL: delegates to
    ///       `actors::aggregator::extract_votes` for byte-identical
    ///       parsing of the on-chain memo layout. Returns empty vec
    ///       when the voter set is empty (the most common pre-voting
    ///       state).
    pub async fn vote_records(&self) -> VotingResult<Vec<VoteRecord>> {
        let voter_set = self.voter_set_ref()?;
        crate::actors::aggregator::extract_votes(&self.chain, &self.config, voter_set).await
    }

    /// Last-synced SPT.
    pub fn merkle_tree(&self) -> VotingResult<&SparseMerkleTree> {
        self.smt.as_ref().ok_or(VotingError::NotDeployed)
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// Indexer tests live in tests/integration.rs because constructing one
// needs a live `ChiaQuery` (or simulator). The cache invariant is
// tested there via end-to-end deploy + sync.
