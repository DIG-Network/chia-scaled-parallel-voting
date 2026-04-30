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
// CACHE: same `state + voter_set + smt` triplet as Aggregator,
//        populated by `sync()`. All queries return `NotDeployed`
//        until the first sync.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;

use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{VotingError, VotingResult};
use crate::merkle::SparseMerkleTree;
use crate::state::{ElectionState, VoteRecord, VoterSet};

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
    /// Same per-config eve puzzle hash the Aggregator computes —
    /// caches the result of `compute_eve_singleton_puzzle_hash` so
    /// repeated `sync()` calls don't recompute the curry chain.
    eve_singleton_puzzle_hash: Bytes32,
}

impl<C: ChainReader> Indexer<C> {
    /// Construct from a validated config + a ChainReader impl.
    pub fn new(config: ElectionConfig, chain: C) -> Self {
        let eve_singleton_puzzle_hash =
            crate::actors::aggregator::compute_eve_singleton_puzzle_hash(&config);
        Self {
            config,
            chain,
            state: None,
            voter_set: None,
            smt: None,
            eve_singleton_puzzle_hash,
        }
    }

    /// Shared reference to the underlying chain reader.
    pub fn chain(&self) -> &C { &self.chain }

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
        let snapshot = crate::actors::aggregator::sync_with_chain(
            &self.chain,
            &self.config,
            self.eve_singleton_puzzle_hash,
        )
        .await?;
        self.state = Some(snapshot.state);
        self.voter_set = Some(snapshot.voter_set);
        self.smt = Some(snapshot.smt);
        Ok(())
    }

    /// Last-synced ElectionState. `NotDeployed` if no sync yet.
    pub fn state(&self) -> VotingResult<&ElectionState> {
        self.state.as_ref().ok_or(VotingError::NotDeployed)
    }

    /// Last-synced VoterSet. See `state()`.
    pub fn voter_set(&self) -> VotingResult<&VoterSet> {
        self.voter_set.as_ref().ok_or(VotingError::NotDeployed)
    }

    /// Convenience: registered voter count.
    pub fn registration_count(&self) -> VotingResult<u64> {
        Ok(self.state()?.registration_count)
    }

    /// Convenience: is `pubkey` in the registered set?
    /// COST: O(n) linear scan — for high-throughput UIs maintain your
    ///       own `HashSet<[u8; 48]>` cached from `voter_set().voters`.
    pub fn is_registered(&self, pubkey: &PublicKey) -> VotingResult<bool> {
        let set = self.voter_set()?;
        Ok(set.voters.iter().any(|v| v == pubkey))
    }

    /// Convenience: has the election been finalized?
    pub fn is_finalized(&self) -> VotingResult<bool> {
        Ok(self.state()?.finalized)
    }

    /// Current SPT root. Same data the aggregator's circuit consumes
    /// as a public input.
    pub fn registration_merkle_root(&self) -> VotingResult<Bytes32> {
        Ok(self.state()?.registration_merkle_root)
    }

    /// Vote outcome bytes — only meaningful after `is_finalized()` is
    /// true.
    pub fn vote_outcome(&self) -> VotingResult<Bytes32> {
        Ok(self.state()?.vote_outcome)
    }

    /// FN: vote_records
    /// WHAT: live tally — every voter who has cast a vote so far.
    /// IMPL: delegates to
    ///       `actors::aggregator::extract_votes` for byte-identical
    ///       parsing of the on-chain memo layout. Returns empty vec
    ///       when the voter set is empty (the most common pre-voting
    ///       state).
    pub async fn vote_records(&self) -> VotingResult<Vec<VoteRecord>> {
        let voter_set = self.voter_set()?;
        crate::actors::aggregator::extract_votes(
            &self.chain,
            &self.config,
            voter_set,
        )
        .await
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
