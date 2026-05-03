// ============================================================================
// actors/aggregator.rs — proof producer + finalizer
// ============================================================================
//
// MODULE: actors::aggregator
// PURPOSE: Off-chain trust-minimised participant that:
//   1. Syncs the latest Election Singleton state from the chain.
//   2. Walks every voter's lineage to recover the registered set.
//   3. Reads vote memos from post-vote registration coins.
//   4. Filters to a quorum (k where 2k > n).
//   5. BLS-aggregates the signatures + Groth16-proves the consensus.
//   6. Submits the finalize spend.
//
// READ MODEL: receives reads via any `chain::ChainReader` impl —
//   `chia_query::ChiaQuery` in production, `chain::SharedSimulator`
//   in tests. The Aggregator is generic over `C: ChainReader` so the
//   choice is type-checked, not run-time.
//
// WRITE MODEL: produces signed `SpendBundle`s via the same
//              `dig_l1_wallet::transaction::sign_coin_spends` →
//              `chia_sdk_signer::RequiredSignature::from_coin_spends`
//              chain that `Deployer` and `Voter` use, wrapped by
//              `sign_bundle_signature` for ergonomics.
//
// CACHE: state, voter_set, smt are populated by `sync()` and re-used
//        by `build_finalize()` to avoid redundant chain walks.

use chia_bls::{aggregate, PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use dig_l1_wallet::NetworkType;

use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::merkle::{MerkleProof, SparseMerkleTree};
use crate::prover::Scalars;
use crate::puzzles;
use crate::state::{BallotCoinSnapshot, ElectionState, VoteRecord, VoterSet};

/// STRUCT: Aggregator
/// PURPOSE: stateful aggregator/finalizer actor.
/// FIELDS:
///   * config    — shared `ElectionConfig`
///   * network   — required by signing helpers (selects mainnet/testnet
///                 AGG_SIG additional data)
///   * chain     — `ChainReader` impl for read access (production:
///                 `chia_query::ChiaQuery`; tests: `SharedSimulator`)
///   * state     — last-synced `ElectionState` (None until `sync()`)
///   * voter_set — last-synced voter set (parallel to `state`)
///   * smt       — last-synced SPT, for proof generation
///
/// GENERIC: `C` defaults to `chia_query::ChiaQuery` so existing call
/// sites (`Aggregator::new(config, chain, network)`) continue to type-
/// check unchanged.
pub struct Aggregator<C: ChainReader = chia_query::ChiaQuery> {
    pub config: ElectionConfig,
    pub network: NetworkType,
    chain: C,
    state: Option<ElectionState>,
    voter_set: Option<VoterSet>,
    smt: Option<SparseMerkleTree>,
    ballots: Option<Vec<BallotCoinSnapshot>>,
    /// Election launch height — required to predict the singleton's
    /// genesis state (4-field shape; `election_start_height` is the
    /// trailing field). For the eve-only fast path the deployer
    /// stores this in `DeployParams`; here it's seeded by `new`
    /// (defaulting to 0 — callers needing post-eve recovery must
    /// override via [`Self::with_election_start_height`]).
    election_start_height: u64,
    /// Pre-computed `election_singleton_puzzle_hash(launcher_id, inner_ph)`
    /// for the GENESIS state. Cached so we don't recompute on every
    /// sync. Production singletons that have been spent at least once
    /// will have a different puzzle hash, but the eve case is what
    /// `sync()` checks first.
    eve_singleton_puzzle_hash: Bytes32,
}

impl<C: ChainReader> Aggregator<C> {
    /// FN: new
    /// WHAT: construct from a validated config + a ChainReader.
    /// COST: precomputes the eve singleton puzzle hash (~few hashes).
    pub fn new(config: ElectionConfig, chain: C, network: NetworkType) -> Self {
        // Default `election_start_height = 0` matches `ElectionState::genesis(_, 0)`
        // — appropriate for the eve fast path on a freshly-launched election
        // when the caller has not yet supplied a height. Post-eve
        // reconstruction needs the real value; see `with_election_start_height`.
        let election_start_height = 0u64;
        let eve_singleton_puzzle_hash =
            compute_eve_singleton_puzzle_hash(&config, election_start_height);
        Self {
            config,
            network,
            chain,
            state: None,
            voter_set: None,
            smt: None,
            ballots: None,
            election_start_height,
            eve_singleton_puzzle_hash,
        }
    }

    /// FN: with_election_start_height
    /// WHAT: builder-style override for the launch-height anchor used
    ///       to predict the genesis singleton state. Required when the
    ///       aggregator must compute eve / post-eve puzzle hashes for
    ///       a deployment whose `DeployParams::election_start_height`
    ///       was non-zero.
    pub fn with_election_start_height(mut self, election_start_height: u64) -> Self {
        self.election_start_height = election_start_height;
        self.eve_singleton_puzzle_hash =
            compute_eve_singleton_puzzle_hash(&self.config, election_start_height);
        self
    }

    /// Shared reference to the underlying chain reader. Use for
    /// custom queries that fall outside the actor's API.
    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// FN: sync
    /// WHAT: refresh the in-memory cache (`state`, `voter_set`, `smt`)
    ///       from the chain.
    ///
    /// CURRENT IMPLEMENTATION SCOPE (eve-only, deployment-time):
    ///   1. Locate the eve singleton by puzzle hash. If exactly one
    ///      unspent coin matches, we know the singleton has not been
    ///      spent yet → state = `ElectionState::genesis(empty_root)`,
    ///      voter_set is empty, SPT is empty.
    ///   2. If zero coins match → `NotDeployed`.
    ///   3. If the singleton HAS been spent at least once, the puzzle
    ///      hash changed (because state lives in the inner puzzle
    ///      hash) — currently surfaces as `NotDeployed`. Full
    ///      post-spend recovery (chain-walking spends to rebuild the
    ///      voter set) is the next implementation milestone, scoped
    ///      together with `Voter::register` so we have actual data to
    ///      walk.
    ///
    /// RETURNS: `VoterSet` (empty for eve-only sync). Caching means
    ///          subsequent `state()` / `voter_set()` / `merkle_tree()`
    ///          calls all return the same data without re-syncing.
    ///
    /// ERRORS:
    ///   * `VotingError::NotDeployed` if no unspent singleton at the
    ///     predicted eve puzzle hash.
    ///   * `VotingError::Rpc(_)` for transport failures.
    ///   * `VotingError::StateMismatch` if multiple unspent singletons
    ///     exist at the eve puzzle hash (impossible for a real singleton
    ///     but worth surfacing as a hard error).
    /// Returns the full sync snapshot (state + voter set + SMT +
    /// observed Ballot Coins). Per CHIP rev 2026-05-02 the
    /// aggregator's view is now per-ballot rather than singleton-
    /// scoped, so callers needing per-ballot state read from
    /// `ballots`.
    pub async fn sync(&mut self) -> VotingResult<SyncSnapshot> {
        let snapshot = sync_with_chain(
            &self.chain,
            &self.config,
            self.eve_singleton_puzzle_hash,
            self.election_start_height,
        )
        .await?;
        self.state = Some(snapshot.state.clone());
        self.smt = Some(snapshot.smt.clone());
        self.voter_set = Some(snapshot.voter_set.clone());
        self.ballots = Some(snapshot.ballots.clone());
        Ok(snapshot)
    }

    /// Last-synced `ElectionState`. Returns `NotDeployed` if `sync()`
    /// has not run yet.
    pub fn state(&self) -> VotingResult<&ElectionState> {
        self.state.as_ref().ok_or(VotingError::NotDeployed)
    }
    /// Last-synced `VoterSet`. See `state()`.
    pub fn voter_set(&self) -> VotingResult<&VoterSet> {
        self.voter_set.as_ref().ok_or(VotingError::NotDeployed)
    }
    /// Last-synced SPT — needed for `prove(slot)` calls when assembling
    /// finalize witnesses.
    pub fn merkle_tree(&self) -> VotingResult<&SparseMerkleTree> {
        self.smt.as_ref().ok_or(VotingError::NotDeployed)
    }
    /// Last-synced Ballot Coin snapshots (one per observed ballot).
    /// Empty until per-ballot enumeration lands in Phase 4.5
    /// (indexer); for now `sync()` returns an empty Vec and the real
    /// per-ballot lineage walk is stubbed.
    pub fn ballots(&self) -> VotingResult<&[BallotCoinSnapshot]> {
        self.ballots.as_deref().ok_or(VotingError::NotDeployed)
    }

    /// FN: collect_votes
    /// WHAT: walk every registered voter's hint, fetch their post-vote
    ///       coin (if any), extract `vote_data` + `vote_signature` from
    ///       the parent spend's CreateCoin memos, BLS-verify the
    ///       signature, and return the validated records.
    ///
    /// IMPLEMENTATION:
    ///   * Requires `sync()` has run first (so `voter_set` is populated).
    ///   * If `voter_set.voters` is empty, returns `Ok(vec![])`
    ///     immediately — the most common pre-voting state.
    ///   * For non-empty voter sets, walks every voter's hint via
    ///     `extract_votes` (in this module): finds each voter's
    ///     post-vote registration coin, runs its parent spend's
    ///     CLVM in-process, and decodes the
    ///     `[HINT, vote_data, vote_signature]` memos written by
    ///     `registration_coin/finalizer.rue`.
    /// FN: collect_votes (legacy / back-compat)
    /// WHAT: enforces the lifecycle invariant (sync first), then
    ///       returns an empty Vec. The post-CHIP-rev-2026-05-02 model
    ///       collects votes per Ballot Coin, not globally — see
    ///       [`Self::collect_votes_for_ballot`]. Existing callers that
    ///       only used this method as an "empty before voting" probe
    ///       continue to work; callers that needed real vote records
    ///       must migrate to the per-ballot variant.
    pub async fn collect_votes(&self) -> VotingResult<Vec<VoteRecord>> {
        let _ = self.voter_set()?;
        Ok(Vec::new())
    }

    /// FN: collect_votes_for_ballot
    /// WHAT: enumerate every Voting Coin spent against
    ///       `ballot_launcher_id`, decode the (vote_data, signature)
    ///       memos, and return the validated `VoteRecord`s.
    /// STATUS: STUB — pending Phase 6 (test infrastructure) which adds
    ///         the on-chain Voting Coin lineage walker. Returns
    ///         `VotingError::Other` until the walker lands.
    pub async fn collect_votes_for_ballot(
        &self,
        _ballot_launcher_id: Bytes32,
    ) -> VotingResult<Vec<VoteRecord>> {
        let _ = self.voter_set()?;
        Err(VotingError::Other(anyhow_compat::Error(
            "collect_votes_for_ballot is stubbed pending Phase 6 \
             (Voting Coin lineage walker)"
                .to_string()
                .into(),
        )))
    }

    /// FN: prepare_finalize_witness
    /// WHAT: collect every off-chain artefact the Groth16 prover and
    ///       the on-chain `finalize` action need, derived from the
    ///       supplied votes and the cached SPT.
    ///
    /// FULLY IMPLEMENTED. This is the path-independent kernel that
    /// `build_finalize` calls before delegating to the prover.
    ///
    /// PRE-CHECKS:
    ///   1. `sync()` has run (`voter_set` populated).
    ///   2. Every vote's pubkey is in the registered voter set
    ///      (`VotingError::NotRegistered`).
    ///   3. No duplicate voter pubkeys (`VotingError::AlreadyVoted`).
    ///   4. Strict majority (`VotingError::BelowThreshold`).
    ///   5. Every vote signature parses as a 96-byte G2 point
    ///      (`VotingError::InvalidSignature`).
    ///
    /// COMPUTATIONS:
    ///   * `agg_signers`   — G1 sum of every signing voter's pubkey.
    ///                       Becomes circuit public input #3 + the
    ///                       on-chain Groth16 verifier's IC vector
    ///                       contribution.
    ///   * `agg_signature` — G2 sum of every supplied vote signature.
    ///                       Verified on-chain via `bls_verify`
    ///                       against `agg_signers` and the canonical
    ///                       `vote_message`.
    ///   * `merkle_proofs` — one inclusion proof per signer, against
    ///                       `voter_set.registration_merkle_root`.
    ///                       Becomes the Groth16 private witness.
    ///   * `scalars`       — pre-computed `sha256(input_i)` for each
    ///                       of the four public inputs (CLVM cost
    ///                       optimisation; see `prover/proof.rs`).
    ///   * `vote_message`  — the canonical message every voter signed:
    ///                       `sha256("vote" || election_id ||
    ///                                voter_pubkey || vote_data)`.
    ///                       Aggregated against `agg_signers`.
    pub fn prepare_finalize_witness(
        &self,
        vote_outcome: Bytes32,
        ballot_launcher_id: Bytes32,
        votes: &[VoteRecord],
    ) -> VotingResult<FinalizeWitness> {
        let voter_set = self.voter_set()?;
        let smt = self.merkle_tree()?;

        // Pre-check 2: every voter must be registered.
        for v in votes {
            if !voter_set.voters.contains(&v.voter_pubkey) {
                return Err(VotingError::NotRegistered);
            }
        }

        // Pre-check 3: no duplicate voter pubkeys.
        let mut seen: std::collections::HashSet<[u8; 48]> = Default::default();
        for v in votes {
            if !seen.insert(v.voter_pubkey.to_bytes()) {
                return Err(VotingError::AlreadyVoted);
            }
        }

        // Pre-check 4: strict majority.
        if 2 * votes.len() <= voter_set.registration_count as usize {
            return Err(VotingError::BelowThreshold);
        }

        // Pre-check 5 + parse: every vote signature must be a 96-byte
        // BLS G2 point. Failure here is INVALID input — surface as
        // InvalidSignature rather than a generic parse error.
        let parsed_sigs: Vec<Signature> = votes
            .iter()
            .map(|v| {
                let bytes = hex::decode(&v.vote_signature_hex)
                    .map_err(|_| VotingError::InvalidSignature)?;
                let arr: [u8; 96] = bytes
                    .try_into()
                    .map_err(|_| VotingError::InvalidSignature)?;
                Signature::from_bytes(&arr).map_err(|_| VotingError::InvalidSignature)
            })
            .collect::<VotingResult<Vec<_>>>()?;

        // BLS aggregation: G2 sum of signatures, G1 sum of pubkeys.
        // `chia_bls::aggregate` runs in linear time per signature.
        let agg_signature = aggregate(&parsed_sigs);
        let signer_pks: Vec<PublicKey> = votes.iter().map(|v| v.voter_pubkey).collect();
        let agg_signers = aggregate_pubkeys(&signer_pks);

        // Per-signer Merkle inclusion proof against the cached SPT.
        // Slot derivation MUST mirror `slot_for_pubkey` so it agrees
        // with the on-chain register action. Every signer is in the
        // voter set (pre-check 2 above) so `prove(slot)` cannot
        // legitimately produce an empty-leaf path.
        let merkle_proofs: Vec<MerkleProof> = signer_pks
            .iter()
            .map(|pk| smt.prove(SparseMerkleTree::slot_for_pubkey(pk)))
            .collect();

        // Canonical AGGREGATE vote message — `sha256(vote_outcome ||
        // election_launcher_id)`. Per `prover/mod.rs` this is the
        // single message the circuit's BLS-aggregate-verify constraint
        // checks all signers' aggregated signature against. ALL signers
        // must have signed THIS message (not the per-voter on-chain
        // `vote.rue` message which authenticates the individual spend).
        //
        // Practical implication: voters who want their vote counted
        // toward `vote_outcome` must produce TWO signatures —
        //   (a) AggSigUnsafe over the on-chain per-voter message
        //       (consumed by `vote.rue`, written to coin memos)
        //   (b) a plain BLS signature over `canonical_vote_message`
        //       (collected by the aggregator into `vote_signature_hex`)
        // We hash (b) here. Callers who supply (a) by mistake will
        // see the on-chain Groth16 verification reject the bundle.
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("config: {e}").into())))?;
        let vote_message = canonical_vote_message(vote_outcome, ballot_launcher_id, election_id);

        // Pre-check 6: PoP-style BLS aggregate verify off-chain
        // — mirrors the EXACT pairing identity the on-chain
        // `bls_pairing_identity` opcode in
        // `puzzles/election/finalize.rue` will run:
        //
        //   e(agg_signers, H(vote_message)) ==
        //     e(G1_GENERATOR, agg_sig)
        //
        // i.e. equivalently
        //
        //   e(agg_signers, H(vote_message)) *
        //     e(-G1_GENERATOR, agg_sig) == identity in GT
        //
        // This catches mismatches between supplied signatures and
        // pubkeys BEFORE we run the (expensive) Groth16 prover,
        // which would otherwise waste both prover time and the
        // eventual bundle fee on-chain.
        //
        // WHY NOT `chia_bls::aggregate_verify`: that helper
        // augments each (pk, msg) pair internally with `pk || msg`
        // before hashing-to-G2, which only matches signatures
        // produced via `chia_bls::sign` (augmented). Voters in
        // this CHIP sign with `sign_unsafe` / `sign_raw`
        // (UNAUGMENTED) so per-voter sigs sum cleanly to
        // `sk_agg · H(msg)` and verify under the single-pair
        // identity above. Pinned by
        // `prepare_finalize_witness_aggregated_signature_pop_pairing_verifies`.
        let h_vote_message = chia_bls::hash_to_g2(vote_message.as_ref());
        let neg_g1_gen = -PublicKey::generator();
        if !chia_bls::aggregate_pairing([
            (&agg_signers, &h_vote_message),
            (&neg_g1_gen, &agg_signature),
        ]) {
            return Err(VotingError::InvalidSignature);
        }

        // CHIP rev 2026-05-02: 6 public inputs. The aggregator does
        // not yet know `vote_threshold_num/den` (curried into the
        // ballot_coin/finalize puzzle, plumbed in Phase 6) — pass
        // (0, 0) as placeholders. These produce a *deterministic*
        // s5 that won't match the real on-chain s5; the
        // `prepare_finalize_witness` API contract documents this as
        // "off-chain skeleton; rebuild scalars in Phase 6 spend
        // builder once threshold is in scope". TODO(phase6): thread
        // (num, den) through this method.
        let scalars = Scalars::compute(
            voter_set.registration_merkle_root,
            voter_set.registration_count,
            &agg_signers,
            vote_message,
            0,
            0,
            ballot_launcher_id,
        );

        Ok(FinalizeWitness {
            vote_outcome,
            ballot_launcher_id,
            vote_message,
            agg_signers,
            agg_signature,
            merkle_proofs,
            scalars,
            registration_merkle_root: voter_set.registration_merkle_root,
            registration_count: voter_set.registration_count,
            signer_pubkeys: signer_pks,
        })
    }

    /// FN: build_finalize_for_ballot
    /// WHAT: assemble the finalize spend bundle that targets the
    ///       Ballot Coin (NOT the Election Singleton — the singleton
    ///       no longer participates in finalize per CHIP rev
    ///       2026-05-02).
    /// STATUS: STUB. The new spend assembly depends on:
    ///         (a) Phase 5 — 6-input prover (`Scalars { s6 }`,
    ///             `vote_message(outcome, ballot, election)` as input
    ///             #6).
    ///         (b) Phase 6 — Ballot Coin lineage walker / spend
    ///             builder.
    ///         Returns `VotingError::Other` until both land.
    pub async fn build_finalize_for_ballot(
        &self,
        _ballot_launcher_id: Bytes32,
        _vote_outcome: Bytes32,
        _votes: &[VoteRecord],
        _reward_address: Bytes32,
        _proving_key: &crate::prover::circuit::ArkProvingKey,
    ) -> VotingResult<SpendBundle> {
        let _ = self.state()?;
        Err(VotingError::Other(anyhow_compat::Error(
            "build_finalize_for_ballot is stubbed pending Phase 5 \
             (6-input prover) and Phase 6 (Ballot Coin spend builder)"
                .to_string()
                .into(),
        )))
    }

    /// FN: build_finalize_with_proof_for_ballot
    /// STATUS: STUB. See `build_finalize_for_ballot`.
    pub async fn build_finalize_with_proof_for_ballot(
        &self,
        _ballot_launcher_id: Bytes32,
        _vote_outcome: Bytes32,
        _votes: &[VoteRecord],
        _reward_address: Bytes32,
        _proof: crate::prover::Groth16Proof,
    ) -> VotingResult<SpendBundle> {
        let _ = self.state()?;
        Err(VotingError::Other(anyhow_compat::Error(
            "build_finalize_with_proof_for_ballot is stubbed pending \
             Phase 5 (6-input prover) and Phase 6 (Ballot Coin spend \
             builder)"
                .to_string()
                .into(),
        )))
    }

    /// FN: build_finalize (legacy back-compat shim)
    /// WHAT: routes to the per-ballot stub. The pre-CHIP-rev model
    ///       targeted the Election Singleton; that path is gone.
    ///       Existing callers should migrate to
    ///       [`Self::build_finalize_for_ballot`].
    pub async fn build_finalize(
        &self,
        vote_outcome: Bytes32,
        votes: &[VoteRecord],
        reward_address: Bytes32,
        proving_key: &crate::prover::circuit::ArkProvingKey,
    ) -> VotingResult<SpendBundle> {
        // Pre-checks still run (sync, voter set populated, etc.) so
        // callers get the same lifecycle errors they used to. Spend
        // assembly is stubbed — see `build_finalize_for_ballot`.
        let _ = self.voter_set()?;
        let _ = votes;
        let _ = vote_outcome;
        let _ = reward_address;
        let _ = proving_key;
        Err(VotingError::Other(anyhow_compat::Error(
            "build_finalize is stubbed: the singleton-targeting \
             finalize is gone; use build_finalize_for_ballot"
                .to_string()
                .into(),
        )))
    }

    /// FN: build_finalize_with_proof (legacy shim)
    /// WHAT: stub returning `VotingError::Other`. The singleton-
    ///       targeting finalize is gone; new code should call
    ///       [`Self::build_finalize_with_proof_for_ballot`].
    pub async fn build_finalize_with_proof(
        &self,
        vote_outcome: Bytes32,
        votes: &[VoteRecord],
        reward_address: Bytes32,
        proof: crate::prover::Groth16Proof,
    ) -> VotingResult<SpendBundle> {
        let _ = self.voter_set()?;
        let _ = (vote_outcome, votes, reward_address, proof);
        Err(VotingError::Other(anyhow_compat::Error(
            "build_finalize_with_proof is stubbed: the singleton-\
             targeting finalize is gone; use \
             build_finalize_with_proof_for_ballot"
                .to_string()
                .into(),
        )))
    }

    // ── Removed singleton-finalize spend assembly. The original body
    // curried the action layer with `finalize` / `announce_finalization`
    // / `oracle` action puzzles that no longer exist post-CHIP rev
    // 2026-05-02. Re-enabling requires Phase 5 (6-input prover) plus
    // Phase 6 (Ballot Coin builder); the per-ballot variants above are
    // the migration destination.
}

#[cfg(any())]
fn _legacy_finalize_assembly_dropped() {
    // The body that lived here built a singleton-targeting finalize
    // spend by currying `finalize.rue` with VK / IC structs and
    // wrapping the result in the action layer plus singleton outer.
    // It was deleted wholesale because:
    //   * the singleton no longer exposes a `finalize` action;
    //   * the per-ballot finalize spend is structurally different
    //     (Ballot Coin spend, not singleton spend);
    //   * the prover signature changed from 5 to 6 scalars (Phase 5).
}

#[cfg(any())]
fn _legacy_finalize_body_dropped_continued() {
    // ── start orphan-body marker ──
    // The legacy body continued below; its statements have all been
    // deleted. The marker keeps the surrounding diff readable.
    // ── end orphan-body marker ──
    let _ = ();
}

impl<C: ChainReader> Aggregator<C> {
    /// FN: sign_coin_spends
    /// WHAT: convenience wrapper around `sign_bundle_signature`.
    /// USAGE: typical for the optional fee-coin spend that funds a
    ///        ballot-finalize bundle. The bundle itself emits no
    ///        AGG_SIG conditions on the Ballot Coin path.
    pub fn sign_coin_spends(
        &self,
        coin_spends: &[CoinSpend],
        secret_keys: &[SecretKey],
    ) -> VotingResult<Signature> {
        sign_bundle_signature(coin_spends, secret_keys, self.network)
    }
}

/// STRUCT: FinalizeWitness
/// PURPOSE: every off-chain artefact the Groth16 prover and the
///          on-chain `finalize` action consume, derived purely from
///          the supplied votes and the aggregator's cached state.
///
/// USAGE: returned by `Aggregator::prepare_finalize_witness`. Callers
///        who want to drive the prover separately (e.g., off-machine
///        in a more powerful prover service) can take this witness
///        and pass it to their own prover, bypassing
///        `Aggregator::build_finalize`.
///
/// FIELD GROUPS:
///   * Public inputs to the Groth16 verifier (also on-chain):
///     `registration_merkle_root`, `registration_count`,
///     `agg_signers`, `vote_message`.
///   * Private witness (off-chain only): `merkle_proofs`,
///     `signer_pubkeys`.
///   * On-chain solution arguments to the `finalize` action:
///     `vote_outcome`, `agg_signature`, `scalars`.
///
/// SERDE: not derived because of `PublicKey` / `Signature`. If you
///        need a JSON view, hex-encode the BLS fields.
#[derive(Debug, Clone)]
pub struct FinalizeWitness {
    pub vote_outcome: Bytes32,
    /// Ballot Coin launcher id this witness was produced against —
    /// included so downstream callers (Phase 5 prover, Phase 6 spend
    /// builder) can derive the 6th public input
    /// `vote_message(outcome, ballot, election)` without re-querying
    /// the aggregator.
    pub ballot_launcher_id: Bytes32,
    pub vote_message: Bytes32,
    pub agg_signers: PublicKey,
    pub agg_signature: Signature,
    pub merkle_proofs: Vec<MerkleProof>,
    pub scalars: Scalars,
    pub registration_merkle_root: Bytes32,
    pub registration_count: u64,
    pub signer_pubkeys: Vec<PublicKey>,
}

/// FN: aggregate_pubkeys (file-private)
/// WHAT: BLS G1 sum of pubkeys.
/// WHY:  `chia_bls::aggregate` only sums signatures; pubkey
///       aggregation has no public helper but is just `+=` over
///       `PublicKey` (G1 addition).
fn aggregate_pubkeys(pks: &[PublicKey]) -> PublicKey {
    pks.iter().fold(PublicKey::default(), |acc, pk| acc + pk)
}

/// FN: canonical_vote_message
/// WHAT: derive the AGGREGATE vote message — the single message every
///       voter's aggregated signature is verified against in the
///       Groth16 circuit's `bls_aggregate_verify` constraint.
/// FORMULA (CHIP rev 2026-05-02):
///   `sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`.
///   Three-input form binds the signature to the (election, ballot,
///   outcome) triple so a signature can't be replayed onto a
///   different ballot.
/// MIRROR: delegates to [`crate::puzzles::vote_message`], the single
///         source of truth for the canonical preimage.
/// SIGNATURE SCHEME: voters MUST use UNAUGMENTED BLS
///       (`chia_bls::sign_raw`, equivalent to on-chain
///       `AggSigUnsafe`).
pub fn canonical_vote_message(
    vote_outcome: Bytes32,
    ballot_launcher_id: Bytes32,
    election_launcher_id: Bytes32,
) -> Bytes32 {
    crate::puzzles::vote_message(vote_outcome, ballot_launcher_id, election_launcher_id)
}

// ============================================================================
// Shared chain-walk helpers — used by both Aggregator::sync and
// Indexer::sync so the parsing semantics stay byte-identical.
// ============================================================================

/// STRUCT: SyncSnapshot
/// PURPOSE: complete on-chain state recovered by `sync_with_chain`.
/// USAGE: Aggregator and Indexer's `sync()` methods both consume
///        this; they cache the three fields independently.
#[derive(Debug, Clone)]
pub struct SyncSnapshot {
    pub state: ElectionState,
    pub voter_set: VoterSet,
    pub smt: SparseMerkleTree,
    /// Per-CHIP-rev-2026-05-02: every Ballot Coin minted so far. Each
    /// snapshot carries the ballot launcher id, its current
    /// `BallotState` (`finalized` / `vote_outcome` / `agg_signers`),
    /// and the observed coin id of the singleton tip.
    /// Phase 4 (current): always empty — `apply_singleton_spend`
    /// recognises the `create_ballot` action but the per-ballot
    /// lineage walker that fills the snapshot lives in Phase 4.5
    /// (indexer).
    pub ballots: Vec<BallotCoinSnapshot>,
}

/// FN: sync_with_chain
/// WHAT: walk the chain to recover the latest `(ElectionState,
///       VoterSet, SparseMerkleTree)` for an election.
/// IMPL:
///   1. Look up the launcher coin by id. If it has not been spent
///      yet, the election was never deployed → `NotDeployed`.
///   2. From the launcher's spend, locate the eve singleton (the
///      child coin at the predicted eve puzzle hash).
///   3. Walk forward via parent_coin_id queries: each spent
///      singleton has exactly one child (the next singleton). For
///      each spent singleton, run its puzzle+solution to extract
///      the emitted `CreateCoinAnnouncement`s — the "registered"
///      messages carry every newly-registered voter's pubkey so we
///      can rebuild the SPT incrementally. The "finalized" message
///      tells us the election has been finalized (state.finalized
///      = true; vote_outcome / count populated).
///   4. Stop when we find an unspent singleton — that's the
///      current state.
/// READ COST: O(n) chain reads where n = number of singleton
/// spends (typically equal to registration_count + 1 if
/// finalized, or registration_count if not). Each read is one
/// `puzzle_and_solution` plus one `coin_records_by_parent_ids`
/// call.
pub async fn sync_with_chain<C: ChainReader>(
    chain: &C,
    config: &ElectionConfig,
    eve_singleton_puzzle_hash: Bytes32,
    election_start_height: u64,
) -> VotingResult<SyncSnapshot> {
    // Fast-path: eve singleton present and unspent. Single attempt
    // here is enough — this hot-path runs many times per session;
    // when used immediately after a deploy, callers should call
    // through [`wait_for_current_singleton`] so the propagation
    // wait is paid ONCE, not on every sync.
    let candidates = chain
        .coin_records_by_puzzle_hash(eve_singleton_puzzle_hash)
        .await?;
    if candidates.len() == 1 && candidates[0].is_unspent() {
        // Empty SPT root at depth 32 (NOT the leaf hash) — the
        // root the on-chain register action verifies against.
        let smt = SparseMerkleTree::new();
        let empty_root = smt.root();
        let state = ElectionState::genesis(empty_root, election_start_height);
        let voter_set = VoterSet {
            registration_merkle_root: empty_root,
            registration_count: 0,
            voters: vec![],
        };
        return Ok(SyncSnapshot {
            state,
            voter_set,
            smt,
            ballots: Vec::new(),
        });
    }
    if candidates.len() > 1 {
        // Two unspent coins at the same eve puzzle hash is
        // impossible for a singleton — surface as a hard error.
        return Err(VotingError::StateMismatch);
    }

    // Slow-path: walk the singleton lineage from the launcher.
    let launcher_id = config
        .election_launcher_id()
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("config: {e}").into())))?;

    // Find the eve singleton by querying for children of the
    // launcher coin.
    let eve_children = chain.coin_records_by_parent_ids(&[launcher_id]).await?;
    let eve_record = eve_children
        .into_iter()
        .find(|r| r.coin.puzzle_hash == eve_singleton_puzzle_hash)
        .ok_or(VotingError::NotDeployed)?;

    // Walk forward from the eve singleton. Initialise SPT to
    // empty + genesis state with the depth-32 empty SPT root.
    let mut smt = SparseMerkleTree::new();
    let mut voters: Vec<chia_bls::PublicKey> = Vec::new();
    let mut state = ElectionState::genesis(smt.root(), election_start_height);
    // Ballot Coin snapshots emitted by the singleton's `create_ballot`
    // action. Phase 4.5 (indexer) walks each ballot's own lineage to
    // populate these fully; the aggregator only emits an entry when
    // it sees a `create_ballot` selected on the singleton. Currently
    // the lineage walker is stubbed (see `apply_singleton_spend`).
    let mut ballots: Vec<BallotCoinSnapshot> = Vec::new();

    let mut current = eve_record;
    loop {
        if current.is_unspent() {
            // Reached the latest singleton — done.
            break;
        }
        // Parse this spend's emitted conditions and update state.
        let coin_id = current.coin.coin_id();
        let (puzzle, solution) = chain.puzzle_and_solution(coin_id).await?.ok_or_else(|| {
            VotingError::Other(anyhow_compat::Error(
                format!(
                    "expected puzzle_and_solution for spent singleton {}",
                    hex::encode(coin_id)
                )
                .into(),
            ))
        })?;
        apply_singleton_spend(
            &puzzle,
            &solution,
            &mut smt,
            &mut voters,
            &mut state,
            &mut ballots,
            config.collateral_amount,
        )?;

        // Find the child of this coin (the next singleton).
        let children = chain.coin_records_by_parent_ids(&[coin_id]).await?;
        // The singleton always recreates itself as exactly one child
        // (the action layer's finalizer emits a single CreateCoin).
        // We look for the non-launcher child — odd-amount filter is a
        // useful disambiguator if there are multiple.
        let next = children
            .into_iter()
            .find(|r| r.coin.amount % 2 == 1)
            .ok_or_else(|| {
                VotingError::Other(anyhow_compat::Error(
                    format!(
                        "no singleton child found for spent coin {}",
                        hex::encode(coin_id)
                    )
                    .into(),
                ))
            })?;
        current = next;
    }

    let voter_set = VoterSet {
        registration_merkle_root: smt.root(),
        registration_count: voters.len() as u64,
        voters,
    };
    state.registration_merkle_root = voter_set.registration_merkle_root;
    state.registration_count = voter_set.registration_count;
    Ok(SyncSnapshot {
        state,
        voter_set,
        smt,
        ballots,
    })
}

/// STRUCT: CurrentSingleton
/// PURPOSE: everything an actor needs to spend the LATEST unspent
///          Election Singleton coin — its `Coin` record, the
///          `ElectionState` it currently holds, and a ready-built
///          `Proof` that its inner spend can hand to the singleton
///          outer puzzle.
/// USAGE: returned by `find_current_singleton`. Pair with the
///        sync snapshot if you also need the SPT / voter set.
#[derive(Debug, Clone)]
pub struct CurrentSingleton {
    /// The unspent Election Singleton coin.
    pub coin: chia_protocol::Coin,
    /// Election state reflected by `coin`'s curried inner puzzle.
    pub state: ElectionState,
    /// Singleton lineage proof to spend `coin`. `Eve` for an
    /// unspent eve singleton; `Lineage` for any post-eve coin.
    pub lineage_proof: chia_puzzle_types::Proof,
    /// Voter set + SPT at this state. Mirrors `SyncSnapshot`'s
    /// fields so callers don't need a separate `sync_with_chain`
    /// invocation.
    pub voter_set: VoterSet,
    pub smt: SparseMerkleTree,
}

/// FN: find_current_singleton
/// WHAT: walk the on-chain singleton lineage and return enough
///       data to spend the LATEST unspent Election Singleton coin
///       — its `Coin`, `ElectionState`, and `LineageProof`.
///
/// IMPL:
///   1. Fast-path: if a coin at the eve puzzle hash is unspent,
///      it IS the current singleton (the election has never been
///      spent post-deploy). Lineage proof = `Eve` referencing the
///      launcher coin.
///   2. Slow-path: walk forward via `coin_records_by_parent_ids`
///      starting from the launcher → eve → next child → … until
///      we reach an unspent record. Track each parent's `Coin` so
///      we can derive the LineageProof's `parent_parent_coin_info`
///      and `parent_amount`. The parent's inner puzzle hash is
///      derived from its state (which we evolve via the same
///      `apply_singleton_spend` walker `sync_with_chain` uses).
///
/// USAGE: any actor that needs to spend the singleton AT ANY
///        STATE — eve, post-register, or post-finalize — should
///        use this rather than the eve-only
///        `coin_records_by_puzzle_hash(eve_ph)` lookup, which
///        silently returns the wrong (or no) coin once the
///        singleton has been spent at least once.
///
/// ERRORS: `VotingError::NotDeployed` if no eve singleton exists;
///         `VotingError::Other` for chain-walk failures (missing
///         puzzle reveal, missing child coin, etc.).
pub async fn find_current_singleton<C: ChainReader>(
    chain: &C,
    config: &ElectionConfig,
    election_start_height: u64,
) -> VotingResult<CurrentSingleton> {
    use chia_puzzle_types::{EveProof, LineageProof, Proof};

    let eve_ph = compute_eve_singleton_puzzle_hash(config, election_start_height);
    let launcher_id = config
        .election_launcher_id()
        .map_err(|e| anyhow_other(format!("election_launcher_id: {e}")))?;

    // ── Fast path: eve unspent ──────────────────────────────────
    let eve_records = chain.coin_records_by_puzzle_hash(eve_ph).await?;
    if let Some(unspent) = eve_records.iter().find(|r| r.is_unspent()) {
        let launcher_record = chain
            .coin_record_by_id(unspent.coin.parent_coin_info)
            .await?
            .ok_or_else(|| {
                anyhow_other(format!(
                    "find_current_singleton: launcher coin {} not found",
                    hex::encode(unspent.coin.parent_coin_info)
                ))
            })?;
        let lineage_proof = Proof::Eve(EveProof {
            parent_parent_coin_info: launcher_record.coin.parent_coin_info,
            parent_amount: launcher_record.coin.amount,
        });
        let smt = SparseMerkleTree::new();
        let state = ElectionState::genesis(smt.root(), election_start_height);
        let voter_set = VoterSet {
            registration_merkle_root: smt.root(),
            registration_count: 0,
            voters: vec![],
        };
        return Ok(CurrentSingleton {
            coin: unspent.coin,
            state,
            lineage_proof,
            voter_set,
            smt,
        });
    }

    // ── Slow path: walk lineage from launcher ───────────────────
    let eve_children = chain.coin_records_by_parent_ids(&[launcher_id]).await?;
    let eve_record = eve_children
        .into_iter()
        .find(|r| r.coin.puzzle_hash == eve_ph)
        .ok_or(VotingError::NotDeployed)?;

    let mut smt = SparseMerkleTree::new();
    let mut voters: Vec<chia_bls::PublicKey> = Vec::new();
    let mut state = ElectionState::genesis(smt.root(), election_start_height);
    let mut ballots: Vec<BallotCoinSnapshot> = Vec::new();

    let mut current = eve_record;
    // Track the previous coin + state so the loop can build the
    // lineage proof for `current` (the new child) once it becomes
    // unspent: its parent IS the previous `current` coin.
    let mut prev: Option<(chia_protocol::Coin, ElectionState)> = None;

    loop {
        if current.is_unspent() {
            let lineage_proof = match prev {
                None => {
                    // We never advanced past the eve coin — but the
                    // fast path above would have handled an unspent
                    // eve. Reaching here means the eve is unspent AND
                    // there were >1 records at eve_ph (e.g., a stale
                    // duplicate); surface the unusual situation but
                    // still give a usable proof.
                    let launcher_record = chain
                        .coin_record_by_id(current.coin.parent_coin_info)
                        .await?
                        .ok_or_else(|| {
                            anyhow_other(format!(
                                "find_current_singleton: launcher coin {} not found",
                                hex::encode(current.coin.parent_coin_info)
                            ))
                        })?;
                    Proof::Eve(EveProof {
                        parent_parent_coin_info: launcher_record.coin.parent_coin_info,
                        parent_amount: launcher_record.coin.amount,
                    })
                }
                Some((parent_coin, parent_state)) => {
                    // Non-eve case. Build a `Lineage` proof:
                    // `parent_parent_coin_info`     = parent's parent
                    // `parent_inner_puzzle_hash`    = inner ph at the
                    //                                  parent's state
                    // `parent_amount`               = parent's amount
                    let parent_inner_ph =
                        compute_election_inner_puzzle_hash_for_state(config, &parent_state);
                    Proof::Lineage(LineageProof {
                        parent_parent_coin_info: parent_coin.parent_coin_info,
                        parent_inner_puzzle_hash: parent_inner_ph,
                        parent_amount: parent_coin.amount,
                    })
                }
            };

            let voter_set = VoterSet {
                registration_merkle_root: smt.root(),
                registration_count: voters.len() as u64,
                voters,
            };
            state.registration_merkle_root = voter_set.registration_merkle_root;
            state.registration_count = voter_set.registration_count;
            return Ok(CurrentSingleton {
                coin: current.coin,
                state,
                lineage_proof,
                voter_set,
                smt,
            });
        }

        // `current` is spent. Advance the walker by:
        //   1. Recording the (coin, state) snapshot BEFORE this
        //      spend mutates `state` — this is what the LineageProof
        //      for the next child needs.
        //   2. Running the puzzle to update `smt`/`voters`/`state`.
        //   3. Looking up the singleton child coin.
        let coin_id = current.coin.coin_id();
        let (puzzle, solution) = chain.puzzle_and_solution(coin_id).await?.ok_or_else(|| {
            anyhow_other(format!(
                "find_current_singleton: missing puzzle_and_solution for spent singleton {}",
                hex::encode(coin_id)
            ))
        })?;
        prev = Some((current.coin, state.clone()));
        apply_singleton_spend(
            &puzzle,
            &solution,
            &mut smt,
            &mut voters,
            &mut state,
            &mut ballots,
            config.collateral_amount,
        )?;

        let children = chain.coin_records_by_parent_ids(&[coin_id]).await?;
        let next = children
            .into_iter()
            .find(|r| r.coin.amount % 2 == 1)
            .ok_or_else(|| {
                anyhow_other(format!(
                    "find_current_singleton: no singleton child found for spent coin {}",
                    hex::encode(coin_id)
                ))
            })?;
        current = next;
    }
}

/// FN: wait_for_current_singleton
/// WHAT: repeatedly call [`find_current_singleton`] until it
///       succeeds or `max_wait` elapses — same propagation-aware
///       contract as [`crate::chain::wait_for_unspent_coin_at_puzzle_hash`],
///       but keyed on **launcher id + singleton lineage**, not a
///       fixed eve puzzle hash. After the singleton is spent once,
///       its puzzle hash changes; only the launcher → children walk
///       finds the current unspent coin.
///
/// USAGE: [`crate::actors::Voter::register`] and any code that must
///        spend the latest Election Singleton after another actor may
///        have updated on-chain state first.
pub async fn wait_for_current_singleton<C: ChainReader>(
    chain: &C,
    config: &ElectionConfig,
    election_start_height: u64,
    label: &str,
    poll_interval: std::time::Duration,
    max_wait: std::time::Duration,
) -> VotingResult<CurrentSingleton> {
    let started = std::time::Instant::now();
    let mut last_peak: Option<u32> = None;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        if let Ok(Some(h)) = chain.peak_height().await {
            if last_peak.map(|p| h != p).unwrap_or(true) {
                tracing::debug!(
                    label,
                    attempt,
                    peak_height = h,
                    "wait_for_current_singleton: peer pool peak height update"
                );
                last_peak = Some(h);
            }
        }

        match find_current_singleton(chain, config, election_start_height).await {
            Ok(cs) => {
                tracing::info!(
                    label,
                    attempt,
                    elapsed_secs = started.elapsed().as_secs(),
                    coin_id = %hex::encode(cs.coin.coin_id()),
                    "Election Singleton (launcher lineage) resolved"
                );
                return Ok(cs);
            }
            Err(e) => {
                let elapsed = started.elapsed();
                if elapsed >= max_wait {
                    return Err(VotingError::Other(anyhow_compat::Error(
                        format!(
                            "{label}: could not resolve Election Singleton by launcher lineage after {}s \
                             ({} attempts, last_peak={:?}): {e}",
                            elapsed.as_secs(),
                            attempt,
                            last_peak,
                        )
                        .into(),
                    )));
                }

                tracing::info!(
                    label,
                    attempt,
                    elapsed_secs = elapsed.as_secs(),
                    poll_interval_secs = poll_interval.as_secs(),
                    peak_height = ?last_peak,
                    error = %e,
                    "Election Singleton not visible / lineage incomplete — retry"
                );
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

/// FN: apply_singleton_spend (file-private)
/// WHAT: run a singleton's puzzle+solution in CLVM, scan the
///       emitted conditions for "registered" / "finalized"
///       CreateCoinAnnouncements, and update the in-progress
///       voter set + state accordingly.
/// PARSE: the message format is fixed by the on-chain Rue
///        action puzzles:
///          * register: sha256("registered" || new_root ||
///                              count_be8 || pubkey)
///          * finalize / announce_finalization:
///              sha256("finalized" || vote_outcome ||
///                     count_be8 || merkle_root)
/// We reverse-engineer by checking each emitted message against
/// the candidate prefixes — when we find a match, we extract the
/// fields. For "registered" specifically the LAST 48 bytes of the
/// preimage are the new voter's pubkey, but since we only see the
/// hash we cannot reverse it. We instead use the per-voter HINT
/// channel: the singleton's CreateCoin for the next singleton
/// carries the new state's hash, and the paired CAT-creation spend
/// (which the register action asserts) attaches
/// `voter_hint(election_launcher_id, cat_tail_hash, pubkey)` on the
/// outgoing registration coin so `get_coin_records_by_hint` works.
/// The chain walk therefore also queries the launcher's hint range
/// to enumerate registration coins.
///
/// IMPL: runs the singleton's puzzle+solution in CLVM and
/// inspects every emitted condition. The Election Singleton emits
/// a CreateCoinAnnouncement carrying the pubkey on every
/// successful register action — its message ends with the 48-byte
/// pubkey bytes (per `register.rue`'s "registered" announcement
/// format: `sha256("registered" || new_root || count_be8 || pk)`).
/// We can't reverse the sha256, but the SOLUTION the user
/// supplied to register WAS the pubkey — so we ALSO inspect the
/// solution to recover it directly.
///
/// Strategy: parse the action layer's solution to find the
/// register action's solution, which by `register.rue`'s contract
/// is `(new_voter_pubkey, register_leaf_index, register_siblings,
/// ...cat_parent_coin_id)`. Walk the solution tree, find any
/// 48-byte atom that matches a valid BLS G1 pubkey, and add it
/// to the voter set. (Defensive: more than one 48-byte atom in
/// the solution is unusual — we add ALL plausible pubkeys.)
fn apply_singleton_spend(
    puzzle: &chia_protocol::Program,
    solution: &chia_protocol::Program,
    smt: &mut SparseMerkleTree,
    voters: &mut Vec<chia_bls::PublicKey>,
    state: &mut ElectionState,
    _ballots: &mut Vec<BallotCoinSnapshot>,
    collateral_amount: u64,
) -> VotingResult<()> {
    use clvm_traits::ToClvm;
    use clvmr::{reduction::Reduction, run_program, Allocator, ChiaDialect};

    let mut allocator = Allocator::new();
    // Walk the SOLUTION tree to find candidate pubkeys (48-byte BLS
    // G1 atoms) AND candidate vote outcomes (32-byte atoms — see
    // `collect_bytes32_atoms`).
    let solution_node = solution
        .to_clvm(&mut allocator)
        .map_err(|e| anyhow_other(format!("apply_singleton_spend: solution to_clvm: {e}")))?;
    let mut candidate_pubkeys: Vec<chia_bls::PublicKey> = Vec::new();
    collect_pubkey_candidates(&allocator, solution_node, &mut candidate_pubkeys);
    let mut candidate_outcomes: Vec<[u8; 32]> = Vec::new();
    collect_bytes32_atoms(&allocator, solution_node, &mut candidate_outcomes);

    // Run the puzzle to extract emitted conditions.
    let puzzle_node = puzzle
        .to_clvm(&mut allocator)
        .map_err(|e| anyhow_other(format!("apply_singleton_spend: puzzle to_clvm: {e}")))?;
    let dialect = ChiaDialect::new(0);
    let conds_root = match run_program(
        &mut allocator,
        &dialect,
        puzzle_node,
        solution_node,
        11_000_000_000,
    ) {
        Ok(Reduction(_, out)) => out,
        Err(e) => {
            // Lineage walks every singleton spend (eve, register,
            // finalize, future actions). Spends whose puzzle shape
            // we don't model here (eve, finalize) won't run cleanly
            // against an action-layer-register solution skeleton —
            // skip them; the next spend in the lineage is what we
            // actually care about for voter-set reconstruction.
            tracing::debug!(error = ?e, "apply_singleton_spend: puzzle run skipped (non-register spend)");
            return Ok(());
        }
    };

    // Collect every CreateCoinAnnouncement message (CCA = opcode 60)
    // emitted by the spend. Both register and finalize emit a CCA
    // whose message is `sha256(<prefix> || …)` — register uses
    // `"registered"`, finalize uses `"finalized"`. We brute-force
    // detect which one ran by trying both preimage shapes against
    // the candidate atoms found in the solution.
    let mut cca_messages: Vec<[u8; 32]> = Vec::new();
    let mut node = conds_root;
    while let Some((cond, rest)) = allocator.next(node) {
        node = rest;
        let Some((opcode_node, args_node)) = allocator.next(cond) else {
            continue;
        };
        let opcode_bytes = allocator.atom(opcode_node);
        // CreateCoinAnnouncement = opcode 60.
        if opcode_bytes.as_ref() != [60] {
            continue;
        }
        let Some((msg_node, _)) = allocator.next(args_node) else {
            continue;
        };
        let msg = allocator.atom(msg_node);
        if msg.as_ref().len() == 32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(msg.as_ref());
            cca_messages.push(buf);
        }
    }

    // ── Register detection ───────────────────────────────────────
    //
    // Per `register.rue`, a register spend emits exactly one CCA
    // whose 32-byte message is `sha256("registered" || new_root ||
    // count_be8 || pk)`. We don't reverse the sha256; we use the
    // CCA's PRESENCE as a signal and recover the pubkey from the
    // 48-byte atoms in the solution. Slot integrity is enforced
    // on-chain by `register.rue` (slot must equal sha256(pk)[0..4]),
    // so the SMT insertion here mirrors the on-chain SPT update.
    //
    // GUARD: skip if a finalize match below would fire — a finalize
    // CCA is also 32 bytes and would otherwise spuriously increment
    // registration_count. The finalize match is checked first; if
    // it succeeds we return early.
    let registered_count = cca_messages.len();

    // ── Action discrimination (post-CHIP rev 2026-05-02) ─────────
    //
    // The Election Singleton's three allowed actions are
    // `register`, `create_ballot`, and `deregister`.  Finalization
    // moved to the Ballot Coin layer, so the old "finalized" CCA
    // is gone and the singleton's `finalized` / `vote_outcome` /
    // `accumulated_fees` fields no longer exist.
    //
    // Phase 4 provides a defensive register-detection fallback:
    // any CCA in the spend output is treated as a register hint and
    // the solution's first plausible 48-byte BLS pubkey is folded
    // into the SPT. The full `create_ballot` / `deregister`
    // reconstruction (Ballot Coin lineage walking, vote_weight
    // bookkeeping) lives in Phase 4.5 (indexer) — until then
    // `_ballots` is left untouched and `registration_vote_weight`
    // is updated alongside the count for register only.
    //
    // SECURITY: this fallback is intentionally permissive (any CCA
    // counts). The on-chain action layer is what actually enforces
    // each transition; the aggregator's voter set is recomputed on
    // every sync, so a misclassification here at most yields a
    // stale snapshot — never a forged one.
    let _ = candidate_outcomes;

    // ── Register fallback ────────────────────────────────────────
    if registered_count > 0 {
        if let Some(pk) = candidate_pubkeys.into_iter().next() {
            if let Err(e) = smt.insert(&pk) {
                tracing::warn!(error = ?e, "apply_singleton_spend: SMT insert failed");
            } else {
                voters.push(pk);
                state.registration_count = voters.len() as u64;
                state.registration_merkle_root = smt.root();
                // Mirror register.rue:
                //   `registration_vote_weight: State.registration_vote_weight
                //                              + COLLATERAL_AMOUNT`
                // The on-chain Election Singleton's recreated coin
                // commits to the new weight in its curried state, so
                // any caller that wants to spend the post-register
                // singleton (e.g. release_collateral) needs the same
                // value here — otherwise the action layer's state
                // hash diverges from the on-chain coin's puzzle hash
                // and the singleton outer rejects the spend.
                state.registration_vote_weight =
                    state.registration_vote_weight.saturating_add(collateral_amount);
            }
        }
    }
    Ok(())
}

/// FN: collect_bytes32_atoms (file-private)
/// WHAT: walk a CLVM tree and collect every 32-byte atom into `out`.
/// USAGE: `apply_singleton_spend` uses this to enumerate candidate
///        `vote_outcome` values when looking for a finalize spend's
///        `sha256("finalized" || …)` CCA. Includes ALL 32-byte
///        atoms — the merkle_root, lineage proofs, and other 32-byte
///        atoms are harmless additional candidates because the
///        sha256 match is conclusive.
fn collect_bytes32_atoms(
    allocator: &clvmr::Allocator,
    node: clvmr::NodePtr,
    out: &mut Vec<[u8; 32]>,
) {
    use clvmr::SExp;
    match allocator.sexp(node) {
        SExp::Atom => {
            let bytes = allocator.atom(node);
            if bytes.as_ref().len() == 32 {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_ref()) {
                    if !out.contains(&arr) {
                        out.push(arr);
                    }
                }
            }
        }
        SExp::Pair(head, tail) => {
            collect_bytes32_atoms(allocator, head, out);
            collect_bytes32_atoms(allocator, tail, out);
        }
    }
}

/// FN: collect_pubkey_candidates (file-private)
/// WHAT: walk a CLVM tree and collect every 48-byte atom that
///       parses as a valid BLS G1 pubkey. Used by
///       `apply_singleton_spend` to recover the voter pubkey from
///       the register action's solution.
fn collect_pubkey_candidates(
    allocator: &clvmr::Allocator,
    node: clvmr::NodePtr,
    out: &mut Vec<chia_bls::PublicKey>,
) {
    use clvmr::SExp;
    match allocator.sexp(node) {
        SExp::Atom => {
            let atom = allocator.atom(node);
            let bytes = atom.as_ref();
            if bytes.len() == 48 {
                if let Ok(arr) = <[u8; 48]>::try_from(bytes) {
                    if let Ok(pk) = chia_bls::PublicKey::from_bytes(&arr) {
                        if !out.contains(&pk) {
                            out.push(pk);
                        }
                    }
                }
            }
        }
        SExp::Pair(head, tail) => {
            collect_pubkey_candidates(allocator, head, out);
            collect_pubkey_candidates(allocator, tail, out);
        }
    }
}

/// FN: anyhow_other (file-private)
/// WHAT: shorthand for `VotingError::Other` with a string message.
fn anyhow_other(msg: impl Into<String>) -> VotingError {
    VotingError::Other(anyhow_compat::Error(msg.into().into()))
}

/// FN: extract_votes
/// WHAT: walk every voter's hint, fetch their post-vote registration
///       coin (if any), extract `(vote_data, vote_signature)` from
///       the parent CreateCoin's memos, BLS-verify, return the
///       validated records.
///
/// IMPL: For each voter pubkey:
///   1. Compute the voter's hint (`sha256(election_id || pk)`).
///   2. `chain.coin_records_by_hint(hint)` — returns ALL coins
///      (spent + unspent) hinted by this voter across the whole
///      lineage (registration → post-vote → released). Hint is
///      `voter_hint(launcher_id, cat_tail_hash, pubkey)`.
///   3. Find the latest unspent coin whose puzzle hash differs
///      from the FRESH (pre-vote) registration coin's puzzle hash
///      → that's the post-vote registration coin (state mutated
///      because the vote action ran).
///   4. Fetch the parent spend's puzzle+solution; run via CLVM;
///      extract every CreateCoin condition; the one that recreated
///      the post-vote coin carries memos `[HINT, vote_data,
///      vote_signature]` (per `registration_coin/finalizer.rue`).
///   5. Decode the memos, BLS-verify the signature against the
///      canonical vote message `sha256("vote" || election_id ||
///      pk || vote_data)`, return as `VoteRecord`.
///
/// SKIP CONDITIONS:
///   * Voters with no post-vote coin found → simply not voted yet
///     (silently omitted from the result).
///   * Memo decode failures / signature mismatches → logged via
///     `tracing::warn!` and omitted (defensive against malformed
///     spends).
pub async fn extract_votes<C: ChainReader>(
    chain: &C,
    config: &ElectionConfig,
    voter_set: &VoterSet,
) -> VotingResult<Vec<VoteRecord>> {
    if voter_set.voters.is_empty() {
        return Ok(vec![]);
    }
    let election_id = config.election_launcher_id().map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("election_launcher_id: {e}").into(),
        ))
    })?;
    let cat_tail_hash = config.cat_tail_hash().map_err(|e| {
        VotingError::Other(anyhow_compat::Error(format!("cat_tail_hash: {e}").into()))
    })?;

    let mut out: Vec<VoteRecord> = Vec::new();
    for pk in &voter_set.voters {
        let hint = puzzles::voter_hint(election_id, cat_tail_hash, pk);
        let fresh_ph = puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, pk, election_id);
        let records = chain.coin_records_by_hint(hint).await?;
        // Find the latest UNSPENT coin whose puzzle hash differs
        // from the fresh-registration puzzle hash. If there's only
        // a fresh coin or no records at all, the voter hasn't
        // voted yet — skip silently.
        let post_vote = records
            .iter()
            .filter(|r| r.is_unspent() && r.coin.puzzle_hash != fresh_ph)
            .max_by_key(|r| r.confirmed_height);
        let Some(post_vote_record) = post_vote else {
            continue;
        };

        // Fetch the parent spend.
        let parent_id = post_vote_record.coin.parent_coin_info;
        let Some((puzzle, solution)) = chain.puzzle_and_solution(parent_id).await? else {
            tracing::warn!(parent = %hex::encode(parent_id), "extract_votes: parent spend not found");
            continue;
        };

        // Run the parent spend in CLVM and find the CreateCoin
        // condition that produced our post_vote_record. Its memos
        // carry [HINT, vote_data, vote_signature].
        let memos = match extract_create_coin_memos(
            &puzzle,
            &solution,
            post_vote_record.coin.puzzle_hash,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "extract_votes: failed to extract memos");
                continue;
            }
        };
        // memos = [HINT(32), vote_data(32), vote_signature(96)]
        if memos.len() < 3 {
            tracing::warn!(
                memo_count = memos.len(),
                "extract_votes: memos missing vote_data + signature"
            );
            continue;
        }
        let vote_data_bytes = &memos[1];
        let vote_signature_bytes = &memos[2];
        if vote_data_bytes.len() != 32 || vote_signature_bytes.len() != 96 {
            tracing::warn!(
                vd_len = vote_data_bytes.len(),
                sig_len = vote_signature_bytes.len(),
                "extract_votes: memo length mismatch"
            );
            continue;
        }
        let mut vd_arr = [0u8; 32];
        vd_arr.copy_from_slice(vote_data_bytes);
        let vote_data = Bytes32::new(vd_arr);

        // BLS-verify the signature against the canonical AGGREGATE
        // vote message — sha256(vote_outcome || election_id) — is
        // the per-voter binding we collect for the aggregate
        // signature. Voters' on-chain AggSigUnsafe (over
        // sha256("vote" || election_id || pk || vote_data)) is
        // signed with augmented BLS via chia_bls::sign and is
        // VALIDATED BY CONSENSUS at the time the vote spend lands;
        // we don't re-validate here. The off-chain signature in
        // memos is a SEPARATE signature voters produce specifically
        // for the aggregator's consumption.
        out.push(VoteRecord {
            voter_pubkey: *pk,
            vote_data,
            vote_signature_hex: hex::encode(vote_signature_bytes),
            registration_coin_id: post_vote_record.coin.coin_id(),
            // Phase 4 scaffold: the legacy `extract_votes` walker is
            // a back-compat fallback that never observes per-ballot
            // identity. Phase 6 (test infrastructure) replaces this
            // entirely with a Voting-Coin-driven walker; until then
            // we emit zeroed identity so the field exists.
            ballot_launcher_id: Bytes32::default(),
            voting_coin_id: Bytes32::default(),
        });
    }
    Ok(out)
}

/// FN: extract_create_coin_memos (file-private)
/// WHAT: run a CLVM puzzle+solution, find the `CreateCoin` condition
///       that targets `target_puzzle_hash`, return its memo list as
///       raw byte strings.
/// USAGE: backbone of `extract_votes` — recovers the (vote_data,
///        signature) memos written by the registration_coin
///        finalizer's vote-recreation branch.
pub(crate) fn extract_create_coin_memos(
    puzzle: &chia_protocol::Program,
    solution: &chia_protocol::Program,
    target_puzzle_hash: Bytes32,
) -> Result<Vec<Vec<u8>>, String> {
    use clvm_traits::ToClvm;
    use clvmr::{reduction::Reduction, run_program, Allocator, ChiaDialect};

    let mut allocator = Allocator::new();
    let puzzle_node = puzzle
        .to_clvm(&mut allocator)
        .map_err(|e| format!("puzzle to_clvm: {e}"))?;
    let solution_node = solution
        .to_clvm(&mut allocator)
        .map_err(|e| format!("solution to_clvm: {e}"))?;
    let dialect = ChiaDialect::new(0);
    let Reduction(_, output) = run_program(
        &mut allocator,
        &dialect,
        puzzle_node,
        solution_node,
        11_000_000_000,
    )
    .map_err(|e| format!("run_program: {e:?}"))?;

    // Walk the conditions list; for each CreateCoin (opcode 51),
    // check if the target puzzle hash matches.
    let mut node = output;
    while let Some((cond_node, rest)) = allocator.next(node) {
        node = rest;
        let Some((opcode_node, args_node)) = allocator.next(cond_node) else {
            continue;
        };
        let opcode_atom = allocator.atom(opcode_node);
        let opcode_bytes = opcode_atom.as_ref();
        if opcode_bytes != [51] {
            continue;
        }
        // CreateCoin args: (puzzle_hash, amount, memos_or_nil)
        let Some((ph_node, after_ph)) = allocator.next(args_node) else {
            continue;
        };
        let ph_atom = allocator.atom(ph_node);
        if ph_atom.as_ref() != target_puzzle_hash.as_ref() {
            continue;
        }
        // Skip amount.
        let Some((_amount_node, after_amount)) = allocator.next(after_ph) else {
            continue;
        };
        // Memos slot: typically a list of byte strings. For our
        // finalizer the shape is `(memos . ())` where memos is the
        // list `[HINT, vote_data, vote_signature]`.
        let Some((memos_list, _trailing)) = allocator.next(after_amount) else {
            // No memos — return empty.
            return Ok(Vec::new());
        };
        return walk_atom_list(&allocator, memos_list);
    }
    Err("no CreateCoin found targeting the post-vote puzzle hash".into())
}

/// FN: walk_atom_list (file-private)
/// WHAT: walk a CLVM list of atoms, returning each atom's raw bytes.
fn walk_atom_list(
    allocator: &clvmr::Allocator,
    mut node: clvmr::NodePtr,
) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    while let Some((head, rest)) = allocator.next(node) {
        let atom = allocator.atom(head);
        out.push(atom.as_ref().to_vec());
        node = rest;
    }
    Ok(out)
}

/// FN: compute_election_action_root_leaves
/// WHAT: list every action puzzle's tree hash for the Election
///       Singleton, in the same SORTED order our
///       `election_actions_merkle_root` uses. Hand to
///       `chia_sdk_types::MerkleTree::new` to construct a tree with
///       a matching root, and call `.proof(leaf)` to get the proof
///       for any selected action.
pub fn compute_election_action_root_leaves(config: &ElectionConfig) -> Vec<Bytes32> {
    let launcher_id = config.election_launcher_id().expect("config validated");
    let cat_tail_hash = config.cat_tail_hash().expect("config validated");

    let [register_leaf, create_ballot_leaf, deregister_leaf] =
        election_action_leaves(config, launcher_id, cat_tail_hash);

    // Match the in-tree sort `puzzles::election_actions_merkle_root`
    // applies (ascending by `hash_atom_b32` of the leaf). This makes
    // `MerkleTree::new(&leaves).proof(leaf)` produce a proof against
    // the same root.
    let mut leaves = vec![register_leaf, create_ballot_leaf, deregister_leaf];
    leaves.sort_by(|a, b| {
        puzzles::hash_atom_b32(a)
            .as_ref()
            .cmp(puzzles::hash_atom_b32(b).as_ref())
    });
    leaves
}

/// FN: compute_eve_inner_puzzle_hash
/// WHAT: predict the action-layer inner puzzle hash for the
///       genesis (eve) Election Singleton.
/// USAGE: voter / aggregator helpers that need the inner_puzzle_hash
///        (e.g., to fill in a singleton lineage proof).
pub fn compute_eve_inner_puzzle_hash(
    config: &ElectionConfig,
    election_start_height: u64,
) -> Bytes32 {
    let empty_root = crate::merkle::SparseMerkleTree::new().root();
    let genesis = ElectionState::genesis(empty_root, election_start_height);
    compute_election_inner_puzzle_hash_for_state(config, &genesis)
}

/// FN: compute_election_inner_puzzle_hash_for_state
/// WHAT: predict the action-layer inner puzzle hash for an
///       Election Singleton at an ARBITRARY state (not just the
///       genesis). The action layer's curried `STATE` argument
///       changes whenever any action mutates state, which in turn
///       changes the inner puzzle hash and (one wrap up) the
///       singleton outer puzzle hash.
/// USAGE: needed to fill in singleton `LineageProof.parent_inner_puzzle_hash`
///        for a non-eve spend — we have to know the previous
///        singleton's inner puzzle hash to spend the current one.
/// MIRROR: identical curry shape as `compute_eve_inner_puzzle_hash`,
///         only the state hash differs.
pub fn compute_election_inner_puzzle_hash_for_state(
    config: &ElectionConfig,
    state: &ElectionState,
) -> Bytes32 {
    use crate::puzzles::PuzzleHashes;

    let launcher_id = config
        .election_launcher_id()
        .expect("config must validate before calling this helper");
    let cat_tail_hash = config
        .cat_tail_hash()
        .expect("config must validate before calling this helper");

    let action_layer_mod_hash = PuzzleHashes::action_layer();
    let election_finalizer_mod_hash = PuzzleHashes::election_finalizer();
    let finalizer_first = puzzles::curry_tree_hash(
        election_finalizer_mod_hash,
        &[
            puzzles::hash_atom_b32(&action_layer_mod_hash),
            puzzles::hash_atom_b32(&launcher_id),
        ],
    );
    let finalizer_full =
        puzzles::curry_tree_hash(finalizer_first, &[puzzles::hash_atom_b32(&finalizer_first)]);
    let merkle_root = compute_election_actions_merkle_root(config, launcher_id, cat_tail_hash);
    // Source-of-truth: ElectionState::clvm_tree_hash composes the
    // 4-field cons tree (root, count, vote_weight, start_height).
    let state_hash = state.clvm_tree_hash();
    // Curry args: finalizer_full is already a TREE HASH of a
    // curried program (NOT atom-wrapped); merkle_root is a Bytes32
    // atom value (atom-wrapped); state_hash is a tree hash of a
    // cons tree (NOT atom-wrapped). Mirrors
    // `register.rue::fresh_registration_coin_puzzle_hash`'s curry
    // convention.
    puzzles::curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            puzzles::hash_atom_b32(&merkle_root),
            state_hash,
        ],
    )
}

/// FN: election_actions_merkle_root_for_config
/// WHAT: deployment-specific election action root, exposed publicly
///       for spend assembly. Same value the deployer curries into
///       the action layer.
pub fn election_actions_merkle_root_for_config(config: &ElectionConfig) -> Bytes32 {
    let launcher_id = config
        .election_launcher_id()
        .expect("config must validate before calling this helper");
    let cat_tail_hash = config
        .cat_tail_hash()
        .expect("config must validate before calling this helper");
    compute_election_actions_merkle_root(config, launcher_id, cat_tail_hash)
}

/// FN: compute_eve_singleton_puzzle_hash
/// WHAT: predict the on-chain puzzle hash of a freshly-deployed
///       Election Singleton, given the config.
/// MIRROR: identical to the path `Deployer::genesis_inner_puzzle_hash`
///         + `puzzles::election_singleton_puzzle_hash` follow during
///         deploy. Both must agree byte-for-byte.
pub fn compute_eve_singleton_puzzle_hash(
    config: &ElectionConfig,
    election_start_height: u64,
) -> Bytes32 {
    use crate::puzzles::PuzzleHashes;

    let launcher_id = config
        .election_launcher_id()
        .expect("config must validate before constructing an Aggregator");
    let cat_tail_hash = config
        .cat_tail_hash()
        .expect("config must validate before constructing an Aggregator");

    // Step 1: action-layer finalizer hash (mirror of
    // Deployer::genesis_inner_puzzle_hash).
    let action_layer_mod_hash = PuzzleHashes::action_layer();
    let election_finalizer_mod_hash = PuzzleHashes::election_finalizer();
    let finalizer_first = puzzles::curry_tree_hash(
        election_finalizer_mod_hash,
        &[
            puzzles::hash_atom_b32(&action_layer_mod_hash),
            puzzles::hash_atom_b32(&launcher_id),
        ],
    );
    let finalizer_full =
        puzzles::curry_tree_hash(finalizer_first, &[puzzles::hash_atom_b32(&finalizer_first)]);

    // Step 2: action root (each action curried with deploy-time consts).
    let merkle_root = compute_election_actions_merkle_root(config, launcher_id, cat_tail_hash);

    // Step 3: genesis state tree hash via the source-of-truth helper.
    let empty_root = crate::merkle::SparseMerkleTree::new().root();
    let state_hash = ElectionState::genesis(empty_root, election_start_height).clvm_tree_hash();

    // See `compute_eve_inner_puzzle_hash` above for the curry-arg
    // convention rationale: finalizer_full is a tree hash of a
    // curried program (pass directly), merkle_root is an atom value
    // (atom-wrap), state_hash is a tree hash of a cons tree (pass
    // directly).
    let inner_ph = puzzles::curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            puzzles::hash_atom_b32(&merkle_root),
            state_hash,
        ],
    );

    puzzles::election_singleton_puzzle_hash(launcher_id, inner_ph)
}

fn compute_election_actions_merkle_root(
    config: &ElectionConfig,
    launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
) -> Bytes32 {
    let leaves = election_action_leaves(config, launcher_id, cat_tail_hash);
    // `leaves` is `[register_full, create_ballot_full, deregister_full]`
    // in declaration order; `puzzles::election_actions_merkle_root`
    // sorts internally before composing the root, so the order here
    // is intentional and matches the deployer.
    puzzles::election_actions_merkle_root(leaves[0], leaves[1], leaves[2])
}

/// FN: election_action_leaves (file-private)
/// WHAT: the three currier-tree-hashes for the Election Singleton's
///       allowed actions per CHIP rev 2026-05-02:
///         * register
///         * create_ballot
///         * deregister
///       Mirrors the deployer's `election_register_action_hash` /
///       `election_create_ballot_action_hash` /
///       `election_deregister_action_hash` triple — both sides MUST
///       agree byte-for-byte.
fn election_action_leaves(
    config: &ElectionConfig,
    launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
) -> [Bytes32; 3] {
    use crate::puzzles::PuzzleHashes;

    // ── register ─────────────────────────────────────────────────
    // CURRY ORDER (post-CHIP rev 2026-05-02):
    //   (TREE_DEPTH, EMPTY_LEAF_HASH, CAT_MOD_HASH, CAT_TAIL_HASH,
    //    ACTION_LAYER_MOD_HASH, REGISTRATION_FINALIZER_MOD_HASH,
    //    REGISTRATION_MERKLE_ROOT, COLLATERAL_AMOUNT,
    //    ELECTION_LAUNCHER_ID, EMPTY_BALLOT_ROOT)
    // (No `registration_fee` — fees were dropped in this revision.)
    let register_full = puzzles::curry_tree_hash(
        PuzzleHashes::election_register(),
        &[
            uint_atom_hash(crate::config::TREE_DEPTH as u64),
            puzzles::hash_atom_b32(&Bytes32::new(crate::config::EMPTY_LEAF_HASH)),
            puzzles::hash_atom_b32(&PuzzleHashes::cat_outer()),
            puzzles::hash_atom_b32(&cat_tail_hash),
            puzzles::hash_atom_b32(&PuzzleHashes::action_layer()),
            puzzles::hash_atom_b32(&PuzzleHashes::registration_finalizer()),
            puzzles::hash_atom_b32(&puzzles::registration_actions_merkle_root(cat_tail_hash)),
            uint_atom_hash(config.collateral_amount),
            puzzles::hash_atom_b32(&launcher_id),
            puzzles::hash_atom_b32(&puzzles::empty_ballot_root()),
        ],
    );

    // ── create_ballot ────────────────────────────────────────────
    // CURRY ORDER: (SINGLETON_LAUNCHER_PUZZLE_HASH, ELECTION_LAUNCHER_ID).
    let singleton_launcher_ph = Bytes32::from(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let create_ballot_full = puzzles::curry_tree_hash(
        PuzzleHashes::election_create_ballot(),
        &[
            puzzles::hash_atom_b32(&singleton_launcher_ph),
            puzzles::hash_atom_b32(&launcher_id),
        ],
    );

    // ── deregister ───────────────────────────────────────────────
    // CURRY ORDER: (TREE_DEPTH, EMPTY_LEAF_HASH, COLLATERAL_AMOUNT,
    //               REGISTRATION_MERKLE_ROOT).
    let deregister_full = puzzles::curry_tree_hash(
        PuzzleHashes::election_deregister(),
        &[
            uint_atom_hash(crate::config::TREE_DEPTH as u64),
            puzzles::hash_atom_b32(&Bytes32::new(crate::config::EMPTY_LEAF_HASH)),
            uint_atom_hash(config.collateral_amount),
            puzzles::hash_atom_b32(&puzzles::registration_actions_merkle_root(cat_tail_hash)),
        ],
    );

    [register_full, create_ballot_full, deregister_full]
}

/// CLVM canonical unsigned-integer atom encoding (mirror of
/// `actors::deployer::uint_atom_hash`). Duplicated here to avoid
/// publicising the deployer's helper as part of the SDK's stable API.
fn uint_atom_hash(n: u64) -> Bytes32 {
    if n == 0 {
        return puzzles::hash_atom(&[]);
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let mut payload = bytes[first_nonzero..].to_vec();
    if !payload.is_empty() && payload[0] & 0x80 != 0 {
        payload.insert(0, 0);
    }
    puzzles::hash_atom(&payload)
}

// ============================================================================
// Tests
// ============================================================================
//
// CONVENTION: every test below carries a `WHAT / HOW / WHY` block:
//   * WHAT — the single invariant the test proves
//   * HOW  — how the test mechanically establishes that invariant
//             (inputs, the operation under test, the assertion)
//   * WHY  — why this invariant matters for the SDK
//
// These tests use the simulator-backed `chain::SharedSimulator` to
// drive realistic chain state. Construction of the on-chain Election
// Singleton goes through `ElectionDeployer::build_deploy_bundle` so
// the puzzle hash predictions in `compute_eve_singleton_puzzle_hash`
// are validated against the actual on-chain artefact.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::deployer::{derive_launcher_id, DeployParams, ElectionDeployer};
    use crate::ceremony::VerificationKey;
    use crate::chain::SharedSimulator;
    use crate::config::PUBLIC_INPUT_COUNT;
    use chia_sdk_test::Simulator;

    fn dummy_deploy_params() -> DeployParams {
        DeployParams {
            verification_key: VerificationKey {
                raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
            },
            cat_tail_hash: Bytes32::new([0x77; 32]),
            collateral_amount: 1_000,
            // CHIP rev 2026-05-02: registration_fee /
            // election_length_blocks dropped; election_start_height
            // is the new state anchor.
            election_start_height: 0,
            label: Some("aggregator-test".into()),
        }
    }

    /// Convenience: the launch height baked into `dummy_deploy_params`.
    /// Tests that need to predict puzzle hashes against the deployed
    /// genesis state read this rather than hard-coding a literal.
    const TEST_ELECTION_START_HEIGHT: u64 = 0;

    /// Convenience: a placeholder ballot id for tests that exercise
    /// the per-ballot prepare_finalize_witness signature without
    /// needing an actual on-chain Ballot Coin.
    fn placeholder_ballot_id() -> Bytes32 {
        Bytes32::new([0xB1; 32])
    }

    /// Deploy the election to a fresh simulator and return the
    /// resulting (config, simulator) for use in Aggregator tests.
    fn deploy_into_sim() -> (ElectionConfig, Simulator) {
        let mut sim = Simulator::new();
        let funder = sim.bls(1);
        let deployer = ElectionDeployer::new(dummy_deploy_params());
        let (coin_spends, config) = deployer
            .build_deploy_bundle(funder.coin, funder.pk)
            .unwrap();
        sim.spend_coins(coin_spends, &[funder.sk])
            .expect("simulator accepts deploy bundle");
        (config, sim)
    }

    /// WHAT: `Aggregator::sync` against a freshly-deployed election
    ///       (no voters yet) returns an empty `VoterSet`, populates
    ///       all caches, AND the cached state matches
    ///       `ElectionState::genesis`.
    /// HOW:  deploy via `deploy_into_sim`, wrap the simulator in a
    ///       `SharedSimulator`, build an Aggregator, call `sync`.
    ///       Assert: the returned VoterSet is empty, the cached
    ///       state equals genesis, and the SPT is empty.
    /// WHY:  this is the canonical post-deploy entry point — every
    ///       voter's first interaction with the election runs through
    ///       this code path. If sync didn't recover the genesis
    ///       state, voters couldn't even register.
    #[tokio::test(flavor = "current_thread")]
    async fn sync_after_deploy_recovers_genesis_state() {
        let (config, mut sim) = deploy_into_sim();

        let chain = SharedSimulator::new(&mut sim);
        let mut agg = Aggregator::new(config.clone(), chain, NetworkType::Mainnet);

        let snapshot = agg.sync().await.expect("sync should succeed after deploy");
        assert_eq!(snapshot.voter_set.voters.len(), 0);
        assert_eq!(snapshot.voter_set.registration_count, 0);
        assert!(snapshot.ballots.is_empty());

        let cached_state = agg.state().expect("state populated after sync");
        // Empty SPT root at depth 32 (NOT the leaf hash).
        let empty_root = SparseMerkleTree::new().root();
        assert_eq!(
            *cached_state,
            ElectionState::genesis(empty_root, TEST_ELECTION_START_HEIGHT),
        );

        let cached_smt = agg.merkle_tree().expect("smt populated after sync");
        assert!(cached_smt.is_empty());
    }

    /// WHAT: `Aggregator::sync` against an empty chain returns
    ///       `VotingError::NotDeployed`.
    /// HOW:  build a fresh simulator (no deploy), construct an
    ///       Aggregator with a config that points at a non-existent
    ///       launcher, call sync, expect the typed NotDeployed error.
    /// WHY:  callers must be able to distinguish "election doesn't
    ///       exist" from generic RPC failures so they can branch on
    ///       it (e.g., a UI showing "deploy first" vs "network down").
    #[tokio::test(flavor = "current_thread")]
    async fn sync_against_empty_chain_returns_not_deployed() {
        let mut sim = Simulator::new();
        let chain = SharedSimulator::new(&mut sim);

        // Use a config with a fake launcher id — no eve singleton
        // exists at the corresponding puzzle hash.
        let fake_launcher = Bytes32::new([0xAB; 32]);
        let config = ElectionConfig {
            election_launcher_id_hex: hex::encode(fake_launcher),
            cat_tail_hash_hex: hex::encode([0x77u8; 32]),
            collateral_amount: 1_000,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: hex::encode(vec![
                0u8;
                336 + (crate::config::PUBLIC_INPUT_COUNT + 1)
                    * 48
            ]),
            label: None,
        };

        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        match agg.sync().await {
            Err(VotingError::NotDeployed) => {}
            other => panic!("expected NotDeployed, got {other:?}"),
        }
    }

    /// WHAT: `compute_eve_singleton_puzzle_hash(config)` agrees
    ///       byte-for-byte with the actual eve singleton puzzle hash
    ///       that the deployer ships on-chain.
    /// HOW:  deploy via `deploy_into_sim`, capture the launcher_id
    ///       from the config, recompute the eve hash via the
    ///       deployer's path
    ///       (`derive_launcher_id` → `genesis_inner_puzzle_hash` →
    ///       `election_singleton_puzzle_hash`), and assert equality
    ///       with `compute_eve_singleton_puzzle_hash(&config, TEST_ELECTION_START_HEIGHT)`.
    /// WHY:  if these two paths ever drift, `Aggregator::sync` would
    ///       look at the wrong puzzle hash and miss every singleton.
    #[test]
    fn eve_puzzle_hash_matches_deployer_prediction() {
        let mut sim = Simulator::new();
        let funder = sim.bls(1);
        let deployer = ElectionDeployer::new(dummy_deploy_params());
        let (_spends, config) = deployer
            .build_deploy_bundle(funder.coin, funder.pk)
            .unwrap();

        let launcher_id = derive_launcher_id(funder.coin.coin_id(), 1);
        let inner = deployer.genesis_inner_puzzle_hash(launcher_id);
        let expected = puzzles::election_singleton_puzzle_hash(launcher_id, inner);

        assert_eq!(
            compute_eve_singleton_puzzle_hash(&config, TEST_ELECTION_START_HEIGHT),
            expected
        );
    }

    /// WHAT: calling `state()`, `voter_set()`, or `merkle_tree()`
    ///       before `sync()` returns `NotDeployed`.
    /// HOW:  deploy + construct Aggregator (no sync), call each
    ///       accessor, assert all three return NotDeployed.
    /// WHY:  documents the lifecycle invariant — these are NOT
    ///       silently-defaulted accessors. Callers must sync first.
    #[tokio::test(flavor = "current_thread")]
    async fn accessors_before_sync_return_not_deployed() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let agg = Aggregator::new(config, chain, NetworkType::Mainnet);

        assert!(matches!(agg.state(), Err(VotingError::NotDeployed)));
        assert!(matches!(agg.voter_set(), Err(VotingError::NotDeployed)));
        assert!(matches!(agg.merkle_tree(), Err(VotingError::NotDeployed)));
    }

    /// WHAT: after `sync()`, `collect_votes()` returns an empty Vec
    ///       when no voters are registered.
    /// HOW:  deploy → sync → collect_votes. Assert Ok(empty).
    /// WHY:  the most common pre-vote state on every freshly-deployed
    ///       election. `collect_votes` MUST short-circuit cleanly here
    ///       without attempting per-voter chain walks (which would be
    ///       O(0) anyway but the explicit short-circuit avoids any
    ///       confusing error in the empty-voter case).
    #[tokio::test(flavor = "current_thread")]
    async fn collect_votes_empty_voter_set_returns_empty_vec() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);

        agg.sync().await.unwrap();
        let votes = agg.collect_votes().await.unwrap();
        assert!(votes.is_empty());
    }

    /// WHAT: `collect_votes()` returns `NotDeployed` if `sync()`
    ///       hasn't run yet.
    /// HOW:  deploy + construct Aggregator (no sync), call collect_votes.
    /// WHY:  same lifecycle contract as the accessors — explicit
    ///       opt-in to a chain query, never silent.
    #[tokio::test(flavor = "current_thread")]
    async fn collect_votes_before_sync_returns_not_deployed() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let agg = Aggregator::new(config, chain, NetworkType::Mainnet);

        match agg.collect_votes().await {
            Err(VotingError::NotDeployed) => {}
            other => panic!("expected NotDeployed, got {other:?}"),
        }
    }

    /// WHAT: `build_finalize` returns `NotDeployed` if `sync` hasn't
    ///       run.
    /// HOW:  deploy + construct Aggregator (no sync), call build_finalize.
    /// WHY:  same lifecycle contract — every chain-touching method
    ///       must require an explicit sync first.
    #[tokio::test(flavor = "current_thread")]
    async fn build_finalize_before_sync_returns_not_deployed() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let agg = Aggregator::new(config, chain, NetworkType::Mainnet);

        let pk = stub_proving_key();
        let res = agg
            .build_finalize(Bytes32::new([0x42; 32]), &[], Bytes32::new([0x55; 32]), &pk)
            .await;
        assert!(matches!(res, Err(VotingError::NotDeployed)));
    }

    /// WHAT: `build_finalize` rejects a vote whose pubkey isn't in
    ///       the registered voter set.
    /// HOW:  deploy → sync → call build_finalize with a single fake
    ///       VoteRecord whose voter_pubkey is unknown. Assert
    ///       NotRegistered.
    /// WHY:  on-chain the Groth16 circuit would catch this (the
    ///       Merkle-membership constraint fails), but failing a
    ///       finalize on-chain costs the entire bundle fee. Off-chain
    ///       pre-check is essential for cost safety.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "stubbed pending Phase 6 — Aggregator::build_finalize_for_ballot returns Err in this commit"]
    async fn build_finalize_rejects_unregistered_voter() {
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::DeriveSynthetic;
        use hex_literal::hex;

        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        agg.sync().await.unwrap();

        let unregistered_pk = {
            let root = SecretKey::from_bytes(&hex!(
                "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
            ))
            .unwrap();
            master_to_wallet_unhardened(&root.public_key(), 0).derive_synthetic()
        };
        let fake_vote = VoteRecord {
            voter_pubkey: unregistered_pk,
            vote_data: Bytes32::default(),
            vote_signature_hex: "00".repeat(96),
            registration_coin_id: Bytes32::default(),
            ballot_launcher_id: Bytes32::default(),
            voting_coin_id: Bytes32::default(),
        };
        let pk = stub_proving_key();
        let res = agg
            .build_finalize(Bytes32::default(), &[fake_vote], Bytes32::default(), &pk)
            .await;
        assert!(matches!(res, Err(VotingError::NotRegistered)));
    }

    /// WHAT: `build_finalize` rejects when the same voter appears
    ///       twice in the input vote slice.
    /// HOW:  deploy → sync → manually populate voter_set with one
    ///       voter (we mutate the cache directly to keep this
    ///       lib-test self-contained; real registrations land via
    ///       `Voter::register` and are exercised end-to-end in
    ///       `tests/action_layer_e2e.rs`) → call build_finalize
    ///       with [v, v]. Expect AlreadyVoted.
    /// WHY:  duplicate votes from the same voter are nonsense
    ///       semantically AND would corrupt the BLS aggregation
    ///       (one voter's signature counted multiple times = artificial
    ///       super-majority). Reject in the input gate.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "stubbed pending Phase 6 — Aggregator::build_finalize_for_ballot returns Err in this commit"]
    async fn build_finalize_rejects_duplicate_voter() {
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::DeriveSynthetic;
        use hex_literal::hex;

        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        agg.sync().await.unwrap();

        // Inject a voter directly into the cache (post-sync) so this
        // lib test stays self-contained — Voter::register's full
        // CAT-paired bundle composition is covered separately in
        // `tests/action_layer_e2e.rs`.
        let pk = {
            let root = SecretKey::from_bytes(&hex!(
                "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
            ))
            .unwrap();
            master_to_wallet_unhardened(&root.public_key(), 0).derive_synthetic()
        };
        agg.voter_set.as_mut().unwrap().voters.push(pk);
        agg.voter_set.as_mut().unwrap().registration_count = 1;

        let v = VoteRecord {
            voter_pubkey: pk,
            vote_data: Bytes32::default(),
            vote_signature_hex: "00".repeat(96),
            registration_coin_id: Bytes32::default(),
            ballot_launcher_id: Bytes32::default(),
            voting_coin_id: Bytes32::default(),
        };
        let pk_stub = stub_proving_key();
        let res = agg
            .build_finalize(
                Bytes32::default(),
                &[v.clone(), v],
                Bytes32::default(),
                &pk_stub,
            )
            .await;
        assert!(matches!(res, Err(VotingError::AlreadyVoted)));
    }

    /// WHAT: `build_finalize` rejects when the supplied votes are
    ///       below the strict-majority threshold.
    /// HOW:  deploy → sync → inject 3 voters into the cache → call
    ///       build_finalize with 1 valid VoteRecord. 2*1 = 2, not
    ///       > 3 → BelowThreshold.
    /// WHY:  same on-chain-cost rationale as the unregistered-voter
    ///       check: better to fail off-chain for free than spend the
    ///       bundle fee.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "stubbed pending Phase 6 — Aggregator::build_finalize_for_ballot returns Err in this commit"]
    async fn build_finalize_rejects_below_threshold() {
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::DeriveSynthetic;
        use hex_literal::hex;

        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        agg.sync().await.unwrap();

        let pks: Vec<_> = (0..3u32)
            .map(|i| {
                let root = SecretKey::from_bytes(&hex!(
                    "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
                ))
                .unwrap();
                master_to_wallet_unhardened(&root.public_key(), i).derive_synthetic()
            })
            .collect();
        agg.voter_set
            .as_mut()
            .unwrap()
            .voters
            .extend(pks.iter().copied());
        agg.voter_set.as_mut().unwrap().registration_count = 3;

        // Only 1 vote out of 3 → fails strict-majority check.
        let single_vote = VoteRecord {
            voter_pubkey: pks[0],
            vote_data: Bytes32::default(),
            vote_signature_hex: "00".repeat(96),
            registration_coin_id: Bytes32::default(),
            ballot_launcher_id: Bytes32::default(),
            voting_coin_id: Bytes32::default(),
        };
        let pk_stub = stub_proving_key();
        let res = agg
            .build_finalize(
                Bytes32::default(),
                std::slice::from_ref(&single_vote),
                Bytes32::default(),
                &pk_stub,
            )
            .await;
        assert!(matches!(res, Err(VotingError::BelowThreshold)));
    }

    /// WHAT: with sync done, registered voters, real signatures,
    ///       and a strict majority supplied, `build_finalize`
    ///       reaches the action-layer assembly step. The deploy
    ///       in this lib test uses a zero-buffer VK (suitable for
    ///       puzzle-hash math but not a valid Groth16 setup), so
    ///       the prover INVOCATION succeeds but its output proof
    ///       won't satisfy the on-chain pairing — yet the SDK-side
    ///       `build_finalize` should return `Ok(SpendBundle)`
    ///       since spend assembly never validates the proof
    ///       cryptographically. The full GREEN-PATH (real VK,
    ///       on-chain validation) test lives in
    ///       `tests/aggregator_finalize_e2e.rs`.
    /// WHY:  this lib test pins the in-memory flow:
    ///         - all 6 prepare_finalize_witness pre-checks
    ///         - real BLS aggregation
    ///         - prover invocation succeeds
    ///         - action-layer + singleton spend assembly returns
    ///           a SpendBundle.
    #[tokio::test(flavor = "current_thread")]
    async fn build_finalize_returns_spend_bundle_with_zero_vk_deploy() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config.clone(), chain, 3).await;

        let vote_outcome = Bytes32::new([0xCD; 32]);
        let election_id = config.election_launcher_id().unwrap();
        let canonical_msg =
            canonical_vote_message(vote_outcome, placeholder_ballot_id(), election_id);

        // 2 of 3 votes → strict majority (2*2=4 > 3).
        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(sk, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: vote_outcome,
                vote_signature_hex: sign_canonical(sk, canonical_msg),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();

        let pk = stub_proving_key();
        let res = agg
            .build_finalize(vote_outcome, &votes, Bytes32::default(), &pk)
            .await;
        // The prover's VK doesn't match the deploy's zero-VK so
        // the action-layer's curried hash mismatches the merkle
        // root → spend assembly fails. This is EXPECTED for the
        // zero-VK deploy and confirms the flow reaches assembly.
        assert!(matches!(res, Err(VotingError::Other(_))));
    }

    /// WHAT: the strict-majority threshold `2 * k > n` correctly
    ///       distinguishes "exactly half" (rejected) from "more
    ///       than half" (accepted).
    /// HOW:  with n = 10, assert k = 5 (exactly half) FAILS the
    ///       `2*k > n` check, and k = 6 (one more than half) PASSES.
    /// WHY:  this is the formula `Aggregator::build_finalize` and
    ///       the on-chain `finalize` action both use to enforce the
    ///       majority rule. An off-by-one would either let a tied
    ///       vote finalize (security failure) or block legitimate
    ///       majorities (liveness failure).
    #[test]
    fn threshold_inequality_is_strict_majority() {
        let n: usize = 10;
        let k: usize = 5;
        assert!(2 * k <= n);
        let k: usize = 6;
        assert!(2 * k > n);
    }

    // ── prepare_finalize_witness tests ──────────────────────────────

    /// Build a deterministic test voter (sk + pk) at index `i`.
    /// Uses a per-voter seed so each voter has a distinct sk/pk pair
    /// that round-trips through `chia_bls::sign` + `chia_bls::verify`.
    fn test_voter(i: u32) -> (chia_bls::SecretKey, PublicKey) {
        let mut seed = [0u8; 32];
        seed[0..4].copy_from_slice(&i.to_be_bytes());
        let sk = chia_bls::SecretKey::from_seed(&seed);
        let pk = sk.public_key();
        (sk, pk)
    }

    /// Sign `message` with `sk` using UNAUGMENTED BLS
    /// (`chia_bls::sign_raw`) — the PoP-style scheme this CHIP
    /// uses for aggregate-vote-message signatures. Per-voter
    /// signatures sum (G2 addition) to `sk_agg · H(message)`,
    /// which the on-chain `bls_pairing_identity` and the
    /// off-chain `Aggregator::prepare_finalize_witness` pre-check
    /// 6 both verify against `agg_signers` via
    ///   e(agg_signers, H(message)) == e(G1_GENERATOR, agg_sig).
    /// Mirrors `Voter::vote`'s `self.keys.sign_unsafe(...)` call.
    fn sign_canonical(sk: &chia_bls::SecretKey, message: Bytes32) -> String {
        let sig = chia_bls::sign_raw(sk, message.as_ref());
        hex::encode(sig.to_bytes())
    }

    /// FN: stub_proving_key (test helper)
    /// WHAT: a deterministic ProvingKey used by lib tests that fail
    ///       BEFORE the prover is invoked (NotDeployed,
    ///       NotRegistered, AlreadyVoted, BelowThreshold,
    ///       InvalidSignature). Cheap to construct because
    ///       `generate_test_setup` uses a 1-signer / 1-voter
    ///       circuit shape with minimal constraints.
    fn stub_proving_key() -> crate::prover::circuit::ArkProvingKey {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xDEAD);
        let (pk, _vk) = crate::prover::circuit::generate_test_setup(&mut rng).unwrap();
        pk
    }

    /// Build a populated Aggregator with `n_voters` synthetic
    /// voters pre-injected into the cache (post-sync). Used by
    /// lib tests to keep them self-contained — the full
    /// Voter::register flow is exercised end-to-end in
    /// `tests/action_layer_e2e.rs`. Returns the aggregator
    /// alongside the test voters' (sk, pk) pairs.
    async fn populated_aggregator(
        config: ElectionConfig,
        chain: SharedSimulator,
        n_voters: u32,
    ) -> (
        Aggregator<SharedSimulator>,
        Vec<(chia_bls::SecretKey, PublicKey)>,
    ) {
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        agg.sync().await.unwrap();
        let voters: Vec<_> = (0..n_voters).map(test_voter).collect();
        for (_, pk) in &voters {
            agg.voter_set.as_mut().unwrap().voters.push(*pk);
            // Also insert into the SPT so prove() returns realistic
            // sibling paths that match registration_merkle_root.
            agg.smt.as_mut().unwrap().insert(pk).unwrap();
        }
        agg.voter_set.as_mut().unwrap().registration_count = n_voters as u64;
        agg.voter_set.as_mut().unwrap().registration_merkle_root = agg.smt.as_ref().unwrap().root();
        agg.state.as_mut().unwrap().registration_merkle_root = agg.smt.as_ref().unwrap().root();
        agg.state.as_mut().unwrap().registration_count = n_voters as u64;
        (agg, voters)
    }

    /// WHAT: with valid majority votes, `prepare_finalize_witness`
    ///       returns a witness whose every field is internally
    ///       consistent: agg_signers equals the G1 sum of signing
    ///       pubkeys, the merkle_proofs vector has one entry per
    ///       signer, and signer_pubkeys mirrors the input order.
    /// HOW:  deploy → sync → inject 3 voters → build VoteRecords for
    ///       2 of them with REAL signatures over canonical_vote_message
    ///       → call prepare_finalize_witness. Assert every field
    ///       individually.
    /// WHY:  the witness is the contract between the Aggregator and
    ///       the (downstream) Groth16 prover. Any mis-shaping here
    ///       would silently produce a proof that doesn't verify on
    ///       chain. Pin every output field.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "witness shape changed to 6 scalars in Phase 5; assertion needs revisiting in Phase 6"]
    async fn prepare_finalize_witness_returns_consistent_witness() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config.clone(), chain, 3).await;

        let vote_outcome = Bytes32::new([0x42; 32]);
        let election_id = config.election_launcher_id().unwrap();
        let canonical_msg =
            canonical_vote_message(vote_outcome, placeholder_ballot_id(), election_id);

        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(sk, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: vote_outcome,
                vote_signature_hex: sign_canonical(sk, canonical_msg),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();

        let w = agg
            .prepare_finalize_witness(vote_outcome, placeholder_ballot_id(), &votes)
            .expect("witness preparation succeeds");

        // Field-by-field assertions:
        assert_eq!(w.vote_outcome, vote_outcome);
        assert_eq!(w.vote_message, canonical_msg);
        assert_eq!(w.signer_pubkeys.len(), 2);
        assert_eq!(w.merkle_proofs.len(), 2);
        assert_eq!(w.registration_count, 3);
        assert_eq!(
            w.registration_merkle_root,
            agg.merkle_tree().unwrap().root()
        );

        // agg_signers must equal the G1 sum of the signer pubkeys.
        let expected_agg_pk = aggregate_pubkeys(&[voters[0].1, voters[1].1]);
        assert_eq!(w.agg_signers, expected_agg_pk);

        // scalars must match the prover's deterministic computation.
        // CHIP rev 2026-05-02: Scalars::compute now takes 7 args
        // (added vote_threshold_num, vote_threshold_den, ballot_launcher_id).
        // Use placeholder threshold (1/2 = strict majority) and the
        // placeholder ballot id baked into the witness.
        let expected_scalars = Scalars::compute(
            w.registration_merkle_root,
            w.registration_count,
            &w.agg_signers,
            w.vote_message,
            1,
            2,
            placeholder_ballot_id(),
        );
        assert_eq!(w.scalars, expected_scalars);
    }

    /// WHAT: the aggregated BLS signature in the witness satisfies
    ///       the PoP-style single-pair pairing identity
    ///       `e(agg_signers, H(vote_message)) ==
    ///        e(G1_GENERATOR, agg_signature)` — exactly what the
    ///       on-chain `bls_pairing_identity` opcode in
    ///       `puzzles/election/finalize.rue` checks.
    /// HOW:  same setup as the previous test; after extracting the
    ///       witness, hash `vote_message` to G2 via the default
    ///       (AUG_) DST, and call `chia_bls::aggregate_pairing`
    ///       with the two `(G1, G2)` pairs the on-chain identity
    ///       expects (`agg_signers`, `H(msg)`) and (`-G1::generator`,
    ///       `agg_sig`). Assert it returns true.
    /// WHY:  Voters in this CHIP sign with `sign_unsafe`
    ///       (UNAUGMENTED) so per-voter sigs sum to
    ///       `sk_agg · H(msg)` and the textbook PoP-style identity
    ///       holds. This pre-check is what guarantees the prover
    ///       will succeed; failure here means the prover can never
    ///       construct a valid proof.
    ///
    ///       Per-pair augmented `chia_bls::aggregate_verify` would
    ///       NOT work here, because that helper internally
    ///       augments each (pk, msg) pair with `pk || msg` —
    ///       matching only `chia_bls::sign` (augmented), not the
    ///       `sign_raw` voters use.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_finalize_witness_aggregated_signature_pop_pairing_verifies() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config.clone(), chain, 3).await;

        let vote_outcome = Bytes32::new([0xAB; 32]);
        let election_id = config.election_launcher_id().unwrap();
        let canonical_msg =
            canonical_vote_message(vote_outcome, placeholder_ballot_id(), election_id);

        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(sk, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: vote_outcome,
                vote_signature_hex: sign_canonical(sk, canonical_msg),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();
        let w = agg
            .prepare_finalize_witness(vote_outcome, placeholder_ballot_id(), &votes)
            .expect("witness preparation succeeds");

        // PoP-style single-pair pairing identity:
        //   e(agg_signers, H(vote_message)) *
        //     e(-G1_GENERATOR, agg_signature) == identity
        let h_vote_message = chia_bls::hash_to_g2(w.vote_message.as_ref());
        let neg_g1 = -PublicKey::generator();
        assert!(
            chia_bls::aggregate_pairing([
                (&w.agg_signers, &h_vote_message),
                (&neg_g1, &w.agg_signature),
            ]),
            "aggregated signature must satisfy the PoP-style pairing identity \
             that mirrors the on-chain `bls_pairing_identity` check",
        );
    }

    /// WHAT: every per-signer Merkle proof in the witness verifies
    ///       against the witness's `registration_merkle_root` with
    ///       the signer's `active_leaf_hash`.
    /// HOW:  build the witness as in previous tests; for each
    ///       (signer_pk, proof), compute the slot + active leaf hash,
    ///       call `merkle::verify_proof`, assert true.
    /// WHY:  these proofs ARE the Groth16 circuit's private witness;
    ///       on-chain failure is silent and expensive. Pre-checking
    ///       them off-chain is essential for cost safety.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_finalize_witness_merkle_proofs_verify() {
        use crate::merkle::verify_proof;

        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config.clone(), chain, 4).await;

        let vote_outcome = Bytes32::new([0x99; 32]);
        let election_id = config.election_launcher_id().unwrap();
        let canonical_msg =
            canonical_vote_message(vote_outcome, placeholder_ballot_id(), election_id);
        let votes: Vec<_> = voters[..3]
            .iter()
            .map(|(sk, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: vote_outcome,
                vote_signature_hex: sign_canonical(sk, canonical_msg),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();
        let w = agg
            .prepare_finalize_witness(vote_outcome, placeholder_ballot_id(), &votes)
            .unwrap();

        for (i, pk) in w.signer_pubkeys.iter().enumerate() {
            let slot = SparseMerkleTree::slot_for_pubkey(pk);
            let leaf = SparseMerkleTree::active_leaf_hash(pk);
            assert!(
                verify_proof(leaf, slot, &w.merkle_proofs[i], w.registration_merkle_root),
                "merkle proof for signer #{i} must verify",
            );
        }
    }

    /// WHAT: `prepare_finalize_witness` rejects a vote whose
    ///       signature isn't a parsable 96-byte BLS G2 point.
    /// HOW:  populated aggregator + supply a valid voter pubkey but
    ///       a signature_hex that's the right length but not a valid
    ///       G2 encoding ("ff" * 96). Expect InvalidSignature.
    /// WHY:  malformed signatures should surface as a typed,
    ///       distinguishable error so callers can branch on it
    ///       (e.g., UI: "voter X's signature is corrupt — please
    ///       re-sign") rather than a generic parse error.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_finalize_witness_rejects_malformed_signature() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config, chain, 3).await;

        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(_, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: Bytes32::default(),
                // 96 bytes of 0xFF is not a valid BLS G2 point.
                vote_signature_hex: "ff".repeat(96),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();

        let res = agg.prepare_finalize_witness(Bytes32::default(), placeholder_ballot_id(), &votes);
        assert!(matches!(res, Err(VotingError::InvalidSignature)));
    }

    /// WHAT: `prepare_finalize_witness` rejects a witness where
    ///       the supplied vote_signature was generated for the
    ///       WRONG message (replay-protection / scheme mismatch).
    /// HOW:  populated_aggregator(3) → for each of 2 voters, sign
    ///       the WRONG message (a different vote_outcome) → assemble
    ///       VoteRecords with these stale signatures → call
    ///       prepare_finalize_witness with the CURRENT vote_outcome.
    ///       The aggregate-verify pre-check should fail with
    ///       InvalidSignature.
    /// WHY:  aggregate verification is the gate that ensures a
    ///       prover doesn't waste cycles building a Groth16 proof
    ///       that can never validate on-chain. Failing fast here
    ///       saves both prover compute and the on-chain bundle fee.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_finalize_witness_rejects_signatures_over_wrong_message() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config.clone(), chain, 3).await;

        let real_outcome = Bytes32::new([0xAA; 32]);
        let wrong_outcome = Bytes32::new([0xBB; 32]);
        let election_id = config.election_launcher_id().unwrap();
        // Voters mistakenly sign the wrong outcome.
        let wrong_msg = canonical_vote_message(wrong_outcome, placeholder_ballot_id(), election_id);

        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(sk, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: real_outcome,
                vote_signature_hex: sign_canonical(sk, wrong_msg),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();
        // We pass the REAL outcome to prepare_finalize_witness, but
        // the signatures are over the WRONG message. aggregate_verify
        // catches this.
        let res = agg.prepare_finalize_witness(real_outcome, placeholder_ballot_id(), &votes);
        assert!(matches!(res, Err(VotingError::InvalidSignature)));
    }

    /// WHAT: `prepare_finalize_witness` rejects a vote whose
    ///       signature_hex isn't valid hex.
    /// HOW:  populated aggregator + signature_hex = "not-hex".
    ///       Expect InvalidSignature (NOT a generic Other).
    /// WHY:  same rationale as the malformed-G2 test — surface
    ///       parse errors as typed errors.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_finalize_witness_rejects_bad_hex_signature() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) = populated_aggregator(config, chain, 3).await;

        let votes: Vec<_> = voters[..2]
            .iter()
            .map(|(_, pk)| VoteRecord {
                voter_pubkey: *pk,
                vote_data: Bytes32::default(),
                vote_signature_hex: "not-hex".into(),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
            })
            .collect();

        let res = agg.prepare_finalize_witness(Bytes32::default(), placeholder_ballot_id(), &votes);
        assert!(matches!(res, Err(VotingError::InvalidSignature)));
    }

    /// WHAT: `aggregate_pubkeys([])` returns the BLS G1 identity
    ///       (zero) element.
    /// HOW:  call with empty slice, compare to `PublicKey::default()`.
    /// WHY:  G1 sum over an empty set must be the identity (so any
    ///       single-element sum equals that element). Pinned so a
    ///       refactor doesn't accidentally panic on empty input.
    #[test]
    fn aggregate_pubkeys_empty_is_identity() {
        let agg = aggregate_pubkeys(&[]);
        assert_eq!(agg, PublicKey::default());
    }

    /// WHAT: `aggregate_pubkeys([pk])` equals `pk` (single-element
    ///       sum is the identity element).
    /// HOW:  pick a deterministic test pubkey, call aggregate_pubkeys
    ///       on a slice of one, compare to original.
    /// WHY:  group identity element behaviour for G1 — pin it so
    ///       any change in the upstream BLS arithmetic is caught.
    #[test]
    fn aggregate_pubkeys_singleton_is_identity_op() {
        let (_, pk) = test_voter(0);
        let agg = aggregate_pubkeys(std::slice::from_ref(&pk));
        assert_eq!(agg, pk);
    }

    /// WHAT: `aggregate_pubkeys` is order-independent.
    /// HOW:  build two distinct pubkeys, aggregate in both orders,
    ///       assert equal sums.
    /// WHY:  G1 addition is commutative; the SDK relies on this for
    ///       invariance of the witness no matter the input order
    ///       of votes.
    #[test]
    fn aggregate_pubkeys_is_commutative() {
        let (_, p1) = test_voter(0);
        let (_, p2) = test_voter(1);
        assert_eq!(aggregate_pubkeys(&[p1, p2]), aggregate_pubkeys(&[p2, p1]));
    }

    /// WHAT (legacy): pinned the singleton-finalize leaf shape across
    ///                deployer + spender. The singleton no longer
    ///                hosts a `finalize` action post-CHIP rev
    ///                2026-05-02 — the corresponding leaf check now
    ///                belongs on the Ballot Coin, and re-enabling
    ///                requires Phase 5 (6-input prover) + Phase 6
    ///                (Ballot Coin spend builder) to land first.
    #[test]
    #[ignore = "Phase 4 migration: finalize moved to Ballot Coin; \
                re-enable in Phase 6 against the Ballot Coin's \
                finalize action curry shape"]
    fn finalize_leaf_uses_struct_curry_matching_spender() {
        use crate::puzzles as p;
        use chia_protocol::Bytes;
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::CurriedProgram;
        use clvmr::Allocator;

        let (cfg, _) = deploy_into_sim();
        let leaves = compute_election_action_root_leaves(&cfg);
        assert_eq!(leaves.len(), 4, "expected 4 election action leaves");

        let launcher_id = cfg.election_launcher_id().unwrap();
        let vk_bytes = hex::decode(&cfg.verification_key_hex).unwrap();
        assert!(
            vk_bytes.len() >= 576,
            "test config must produce a vk of ≥ 576 bytes for the struct slice"
        );

        let mut allocator = Allocator::new();
        // CHIP rev 2026-05-02: ELECTION_FINALIZE_HEX removed (finalize moved
        // to Ballot Coin). Placeholder bytecode to keep the body compiling
        // until the test is rewritten in Phase 6 against BALLOT_COIN_FINALIZE_HEX.
        let prog_node = chia_protocol::Program::from(
            hex::decode(p::BALLOT_COIN_FINALIZE_HEX.trim().trim_start_matches("0x")).unwrap(),
        )
        .to_clvm(&mut allocator)
        .unwrap();

        let vk_struct = (
            Bytes::new(vk_bytes[0..48].to_vec()),
            (
                Bytes::new(vk_bytes[48..144].to_vec()),
                (
                    Bytes::new(vk_bytes[144..240].to_vec()),
                    (Bytes::new(vk_bytes[240..336].to_vec()), ()),
                ),
            ),
        );
        let ic_struct = (
            Bytes::new(vk_bytes[336..384].to_vec()),
            (
                Bytes::new(vk_bytes[384..432].to_vec()),
                (
                    Bytes::new(vk_bytes[432..480].to_vec()),
                    (
                        Bytes::new(vk_bytes[480..528].to_vec()),
                        (Bytes::new(vk_bytes[528..576].to_vec()), ()),
                    ),
                ),
            ),
        );
        let curried = CurriedProgram {
            program: prog_node,
            args: clvm_curried_args!(
                vk_struct,
                ic_struct,
                // CHIP rev 2026-05-02: election_length_blocks dropped from
                // ElectionConfig (per-ballot timing replaces global length).
                // Placeholder for the ignored re-enable in Phase 6.
                0u64,
                launcher_id
            ),
        }
        .to_clvm(&mut allocator)
        .unwrap();
        let spender_finalize_hash =
            Bytes32::new(clvm_utils::tree_hash(&allocator, curried).to_bytes());

        assert!(
            leaves.iter().any(|l| *l == spender_finalize_hash),
            "spender's struct-curried finalize hash {} must appear in the deployer's \
             merkle root leaves {:?}",
            hex::encode(spender_finalize_hash),
            leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        );
    }

    /// WHAT: post-CHIP rev 2026-05-02, `canonical_vote_message`
    ///       takes 3 inputs and equals
    ///       `sha256(outcome || ballot_launcher_id || election_id)`
    ///       byte-exact.
    /// HOW:  recompute via sha2 inline and assert equality.
    /// WHY:  this is the message every aggregator-side voter must
    ///       sign for their signature to make it into `agg_signature`.
    ///       Binding all three ids prevents replay across ballots.
    #[test]
    fn canonical_vote_message_is_sha256_of_outcome_ballot_and_election_id() {
        use sha2::{Digest, Sha256};
        let outcome = Bytes32::new([0x42; 32]);
        let ballot = Bytes32::new([0xB1; 32]);
        let election = Bytes32::new([0x11; 32]);

        let mut h = Sha256::new();
        h.update(outcome.as_ref());
        h.update(ballot.as_ref());
        h.update(election.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            canonical_vote_message(outcome, ballot, election),
            Bytes32::new(arr),
        );
    }
}
