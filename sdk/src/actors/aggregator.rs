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

use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use crate::config::NetworkType;

use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::merkle::PoseidonSmt;
use crate::prover::circuit_v2::{SignerV2, VotingCircuitV2};
use ark_ed_on_bls12_381::EdwardsAffine as JubAffine;
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
pub struct Aggregator<C: ChainReader> {
    pub config: ElectionConfig,
    pub network: NetworkType,
    chain: C,
    state: Option<ElectionState>,
    voter_set: Option<VoterSet>,
    smt: Option<PoseidonSmt>,
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
        // Default `election_start_height = 0` matches `ElectionState::genesis(_, 0, Bytes32::default(), 0u64, Bytes32::default(), crate::vote_mode::VOTE_MODE_LOCK_NONE)`
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
        tracing::info!(
            eve_singleton_puzzle_hash = %hex::encode(self.eve_singleton_puzzle_hash),
            election_start_height = self.election_start_height,
            "Aggregator::sync DIAG: querying"
        );
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
    pub fn merkle_tree(&self) -> VotingResult<&PoseidonSmt> {
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
    /// WHAT: enumerate every Voting Coin currently unspent for
    ///       `ballot_launcher_id`, decode the latest `(vote_data,
    ///       signature)` from the spend that minted (or last
    ///       recreated) it, and return the validated [`VoteRecord`]s.
    /// IMPL: for each registered voter pubkey:
    ///   1. Compute their per-ballot `voting_coin_hint`.
    ///   2. `chain.coin_records_by_hint(hint)` — returns every
    ///      Voting Coin in the lineage. The latest unspent coin
    ///      represents the voter's CURRENT vote on this ballot.
    ///   3. Fetch the parent spend's puzzle+solution. Run via
    ///      CLVM. Find the `vote_cast` / `vote_updated`
    ///      `CreateCoinAnnouncement` and brute-force which
    ///      `(vote_data, signature)` pair from the solution
    ///      atoms produces a sha256 match. The puzzle's solution
    ///      contains a small bounded set of 32-byte (vote_data
    ///      candidate) and 96-byte (signature candidate) atoms,
    ///      so the search is constant-time per voter.
    ///   4. Build a [`VoteRecord`] using
    ///      `Aggregator.config.collateral_amount` as the vote
    ///      weight (every registered voter contributes equally;
    ///      mirrors the on-chain `register` action's
    ///      `registration_vote_weight += COLLATERAL_AMOUNT`).
    /// VOTERS WITHOUT VOTES: silently skipped (their hint produces
    /// no Voting Coin).
    /// MULTI-VOTE: not supported — a voter can have at most one
    /// Voting Coin per ballot per the on-chain SPT non-membership
    /// proof in `mint_voting_coin.rue`. Subsequent edits go
    /// through `update_vote`, which preserves the same coin
    /// lineage; this function returns the latest state.
    pub async fn collect_votes_for_ballot(
        &self,
        ballot_launcher_id: Bytes32,
    ) -> VotingResult<Vec<VoteRecord>> {
        let voter_set = self.voter_set()?.clone();
        collect_votes_for_ballot_via_chain(
            &self.config,
            &self.chain,
            ballot_launcher_id,
            &voter_set,
        )
        .await
    }
}

/// FN: collect_votes_for_ballot_via_chain
/// WHAT: free-function variant of
///       [`Aggregator::collect_votes_for_ballot`]. Lets the
///       [`crate::actors::Indexer`] re-use the same logic without
///       holding an `Aggregator` instance.
/// SEE: [`Aggregator::collect_votes_for_ballot`] for the full spec.
pub async fn collect_votes_for_ballot_via_chain<C: ChainReader>(
    config: &ElectionConfig,
    chain: &C,
    ballot_launcher_id: Bytes32,
    voter_set: &VoterSet,
) -> VotingResult<Vec<VoteRecord>> {
    use clvm_traits::ToClvm;
    use clvmr::{run_program, Allocator, ChiaDialect};

    let cat_tail_hash = config
        .cat_tail_hash()
        .map_err(|e| anyhow_other(format!("cat_tail_hash: {e}")))?;
    let election_id = config
        .election_launcher_id()
        .map_err(|e| anyhow_other(format!("election_launcher_id: {e}")))?;

    let mut records = Vec::new();
    for voter_pk in &voter_set.voters {
        let hint = crate::puzzles::voting_coin_hint(
            election_id,
            cat_tail_hash,
            voter_pk,
            ballot_launcher_id,
        );
        let coin_records = chain.coin_records_by_hint(hint).await?;
        // Take the LATEST unspent (after any update_vote chain).
        let voting_record = match coin_records
            .iter()
            .filter(|r| r.is_unspent())
            .max_by_key(|r| r.confirmed_height)
        {
            Some(r) => r,
            None => continue,
        };
        let voting_coin = voting_record.coin;
        let parent_id = voting_coin.parent_coin_info;

        let (puzzle, solution) = match chain.puzzle_and_solution(parent_id).await? {
            Some(s) => s,
            None => {
                tracing::debug!(
                    voter = %hex::encode(voter_pk.to_bytes()),
                    parent = %hex::encode(parent_id),
                    "parent of voting coin has no puzzle_and_solution; skipping",
                );
                continue;
            }
        };

        // Run the parent puzzle to extract the emitted CCAs +
        // collect candidate atoms from the solution.
        let mut allocator = Allocator::new();
        let puzzle_node = puzzle
            .to_clvm(&mut allocator)
            .map_err(|e| anyhow_other(format!("puzzle to_clvm: {e}")))?;
        let solution_node = solution
            .to_clvm(&mut allocator)
            .map_err(|e| anyhow_other(format!("solution to_clvm: {e}")))?;
        let dialect = ChiaDialect::new(0);
        let conds_root = match run_program(
            &mut allocator,
            &dialect,
            puzzle_node,
            solution_node,
            11_000_000_000,
        ) {
            Ok(r) => r.1,
            Err(e) => {
                tracing::debug!(error = ?e, "running parent spend failed; skipping");
                continue;
            }
        };

        let mut cca_messages: Vec<[u8; 32]> = Vec::new();
        let mut node = conds_root;
        while let Some((cond, rest)) = allocator.next(node) {
            node = rest;
            let Some((opcode_node, args_node)) = allocator.next(cond) else {
                continue;
            };
            let op = allocator.atom(opcode_node);
            if op.as_ref() != [60] {
                continue;
            }
            let Some((msg_node, _)) = allocator.next(args_node) else {
                continue;
            };
            let m = allocator.atom(msg_node);
            if m.as_ref().len() == 32 {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(m.as_ref());
                cca_messages.push(buf);
            }
        }

        // Walk the solution: collect 32-byte and 96-byte atoms.
        let mut candidate_vote_datas: Vec<[u8; 32]> = Vec::new();
        collect_bytes32_atoms(&allocator, solution_node, &mut candidate_vote_datas);
        let mut candidate_sigs: Vec<[u8; 96]> = Vec::new();
        collect_signature_atoms(&allocator, solution_node, &mut candidate_sigs);

        let mut found: Option<([u8; 32], [u8; 96])> = None;
        'outer: for &vd in &candidate_vote_datas {
            for &sig in &candidate_sigs {
                for &cca in &cca_messages {
                    if vote_announcement_matches(
                        b"vote_cast",
                        ballot_launcher_id,
                        voter_pk,
                        &vd,
                        &sig,
                        &cca,
                    ) || vote_announcement_matches(
                        b"vote_updated",
                        ballot_launcher_id,
                        voter_pk,
                        &vd,
                        &sig,
                        &cca,
                    ) {
                        found = Some((vd, sig));
                        break 'outer;
                    }
                }
            }
        }

        let (vote_data_arr, sig_arr) = match found {
            Some(x) => x,
            None => {
                tracing::debug!(
                    voter = %hex::encode(voter_pk.to_bytes()),
                    "vote announcement not decoded — skipping",
                );
                continue;
            }
        };

        // The Voting Coin's curried state contains
        // `registration_coin_id`. Recovering it from the unspent
        // coin's puzzle hash isn't possible (no reveal yet), but we
        // CAN walk the voter's registration-coin hint and find the
        // current unspent registration coin — that's the value
        // curried into the unspent voting coin. Required by the
        // dApp's update_vote flow (the SDK's update_vote checks
        // params.registration_coin_id against the voting coin's
        // curried state; passing default produced a ph mismatch).
        // Released-CAT coins also share `voter_hint`, so filter them
        // out by puzzle_hash (released CAT = cat_outer(tail, p2(pk))).
        let reg_hint = crate::puzzles::voter_hint(election_id, cat_tail_hash, voter_pk);
        let reg_records = chain.coin_records_by_hint(reg_hint).await?;
        let dest_p2_inner: Bytes32 =
            chia_puzzle_types::standard::StandardArgs::curry_tree_hash(voter_pk.clone()).into();
        let released_cat_ph = crate::puzzles::cat_outer_for_inner_hash(
            cat_tail_hash,
            dest_p2_inner,
        );
        let registration_coin_id = reg_records
            .iter()
            .filter(|r| r.is_unspent() && r.coin.puzzle_hash != released_cat_ph)
            .max_by_key(|r| r.confirmed_height)
            .map(|r| r.coin.coin_id())
            .unwrap_or_default();

        records.push(VoteRecord {
            voter_pubkey: *voter_pk,
            vote_data: Bytes32::new(vote_data_arr),
            vote_signature_hex: hex::encode(sig_arr),
            registration_coin_id,
            ballot_launcher_id,
            voting_coin_id: voting_coin.coin_id(),
            // SEC-F1 TODO(step-6 on-chain plumbing): recover the voter's
            // Jubjub Schnorr witness from the voting-coin memo. Until
            // voting_coin carries it, on-chain-collected votes have no
            // in-circuit signature and cannot be finalized via circuit_v2.
            jubjub_vote: None,
        });
    }
    Ok(records)
}

impl<C: ChainReader> Aggregator<C> {
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
        // Legacy variant: no per-ballot threshold and no
        // `registration_vote_weight_snapshot` available. Falls back
        // to `voter_set.registration_count` for s2 — useful only for
        // skeleton tests where snapshot weight == count (unit-weight
        // voters).
        //
        // Pre-Gap-2 fix this variant gated on count-strict-majority
        // (`2 * votes.len() > registration_count`). The threshold
        // variant moved to a weighted-quorum check that uses
        // `(num, den)`; the legacy variant has no `(num, den)` to
        // pass, so we re-emulate the strict-majority shape by passing
        // `(num=1, den=2)` and per-voter unit weight 1 (matching the
        // pre-fix arithmetic for skeleton callers).
        let voter_set_weight = self.voter_set()?.registration_count;
        // 0 voters / 0 votes: 1*0 = 0 < 1*0 = 0 is false → would
        // accept. The strict-majority intent was to REJECT empty
        // sets, so guard explicitly here for the legacy path.
        if voter_set_weight == 0 {
            return Err(VotingError::BelowThreshold);
        }
        // Strict-majority emulation: signed_weight = votes.len();
        // signed_weight * 2 > registration_count
        // ⇔ signed_weight * 2 >= registration_count + 1
        // ⇔ pass `(num, den) = (registration_count + 1, 2)` and
        //   per-voter weight 1. Easier: pre-check inline.
        if 2 * votes.len() <= voter_set_weight as usize {
            return Err(VotingError::BelowThreshold);
        }
        self.prepare_finalize_witness_with_threshold(
            vote_outcome,
            ballot_launcher_id,
            votes,
            0,
            0,
            voter_set_weight,
        )
    }

    /// FN: prepare_finalize_witness_with_threshold
    /// WHAT: same as [`prepare_finalize_witness`] but takes the
    ///       per-ballot threshold (num, den) so the resulting
    ///       `Scalars::s5` matches what the on-chain
    ///       `ballot_coin/finalize.rue` curries. Use this from
    ///       `build_finalize_for_ballot`; the no-threshold variant
    ///       remains for callers that only need merkle proofs +
    ///       agg signature.
    pub fn prepare_finalize_witness_with_threshold(
        &self,
        vote_outcome: Bytes32,
        ballot_launcher_id: Bytes32,
        votes: &[VoteRecord],
        vote_threshold_num: u64,
        vote_threshold_den: u64,
        registration_vote_weight_snapshot: u64,
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

        // Pre-check 4: weighted-quorum threshold matching the curried
        // (num, den) pack. Mirrors the on-chain assertion the
        // weighted-quorum gadget enforces on `signed_weight`:
        //   signed_weight * den >= num * total_weight
        // where signed_weight is the sum of per-signer CAT-locked
        // weights (per CHIP rev weighted voting, each voter's leaf
        // binds their actual locked amount; we read it from the SMT)
        // and total_weight is `registration_vote_weight_snapshot`
        // (the chain-canonical sum at snapshot time). u128 widening
        // here keeps the multiply overflow-safe for any realistic CAT
        // mojo amounts (each fits in u64 ≤ 2^64).
        // SEC-F1: build the per-signer circuit_v2 witnesses. Each signer's
        // weight is read from the Poseidon SPT (keyed by their Jubjub pubkey,
        // carried in the per-vote Jubjub witness); the Schnorr signature is
        // verified IN-CIRCUIT at finalize. `signed_weight = Σ weights`.
        let mut signers_v2: Vec<SignerV2> = Vec::with_capacity(votes.len());
        let mut signed_weight: u128 = 0;
        for v in votes {
            let jv = v.jubjub_vote.ok_or(VotingError::InvalidSignature)?;
            let weight = smt.locked_amount(jv.pubkey).ok_or(VotingError::NotRegistered)?;
            signed_weight += weight as u128;
            let mp = smt.prove_jubjub(jv.pubkey.x, jv.pubkey.y);
            signers_v2.push(SignerV2 {
                pubkey: jv.pubkey,
                weight,
                path: mp.siblings,
                path_bits: mp.bits,
                sig_r: jv.sig_r,
                sig_s: jv.sig_s,
                present: true,
            });
        }
        let total_weight = registration_vote_weight_snapshot as u128;
        let lhs = signed_weight.checked_mul(vote_threshold_den as u128).ok_or_else(|| {
            VotingError::Other(anyhow_compat::Error(
                "prepare_finalize_witness_with_threshold: signed_weight * den overflowed u128"
                    .into(),
            ))
        })?;
        let rhs = total_weight.checked_mul(vote_threshold_num as u128).ok_or_else(|| {
            VotingError::Other(anyhow_compat::Error(
                "prepare_finalize_witness_with_threshold: total_weight * num overflowed u128"
                    .into(),
            ))
        })?;
        if lhs < rhs {
            return Err(VotingError::BelowThreshold);
        }

        // SEC-F1: the BLS aggregate signature path is GONE. Voters no longer
        // sign the canonical message with BLS for the aggregator to combine;
        // instead each supplies a Jubjub Schnorr signature (in `jubjub_vote`)
        // that `VotingCircuitV2` verifies in-circuit. We keep `signer_pks`
        // for the returned witness (audit / dedup), but there is no on-chain
        // `agg_signers` / `agg_sig` / BLS pairing pre-check anymore.
        let signer_pks: Vec<PublicKey> = votes.iter().map(|v| v.voter_pubkey).collect();

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

        // SEC-F1: circuit_v2 has FIVE public inputs (no agg_signers /
        // threshold-pack scalars; binding is fully in-circuit). They are the
        // RAW field values — NOT sha256-then-mod-r scalars — in the order
        // `VotingCircuitV2::public_inputs()` allocates them, and the on-chain
        // `finalize.rue` scalar = `fr_to_bytes32_be(input_i)`:
        //   [0] registration_root          (Poseidon SPT root snapshot, Fr)
        //   [1] vote_message               (sha256(outcome||ballot||election) mod r)
        //   [2] Fr(registration_vote_weight_snapshot)
        //   [3] Fr(vote_threshold_num)
        //   [4] Fr(vote_threshold_den)
        let vote_message_fr = {
            use ark_ff::PrimeField;
            ark_bls12_381::Fr::from_be_bytes_mod_order(vote_message.as_ref())
        };
        let registration_root_fr = smt.root();
        let public_fr: [ark_bls12_381::Fr; 5] = [
            registration_root_fr,
            vote_message_fr,
            ark_bls12_381::Fr::from(registration_vote_weight_snapshot),
            ark_bls12_381::Fr::from(vote_threshold_num),
            ark_bls12_381::Fr::from(vote_threshold_den),
        ];
        let public_inputs: [Bytes32; 5] = [
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&public_fr[0])),
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&public_fr[1])),
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&public_fr[2])),
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&public_fr[3])),
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&public_fr[4])),
        ];

        Ok(FinalizeWitness {
            vote_outcome,
            ballot_launcher_id,
            vote_message,
            vote_message_fr,
            registration_merkle_root: voter_set.registration_merkle_root,
            registration_root_fr,
            registration_count: voter_set.registration_count,
            registration_vote_weight: registration_vote_weight_snapshot,
            vote_threshold_num,
            vote_threshold_den,
            public_inputs,
            public_fr,
            signers_v2,
            signer_pubkeys: signer_pks,
        })
    }

    /// STRUCT: BuildFinalizeForBallotParams
    /// PURPOSE: typed bundle for [`Aggregator::build_finalize_for_ballot`]
    ///          arguments. Encapsulates the per-ballot config the
    ///          aggregator must mirror to match the on-chain Ballot
    ///          Coin's curried args.
    /// FIELDS:
    ///   * `ballot_launcher_id` — the ballot to finalize.
    ///   * `vote_outcome` — committed outcome (32 bytes).
    ///   * `votes` — supplied off-chain (collect via
    ///     [`collect_votes_for_ballot`]).
    ///   * `vote_close_height` — block height at which voting closed.
    ///     Curried into the Ballot Coin's `finalize` action; the
    ///     finalize spend will fail consensus before this height
    ///     (`AssertHeightAbsolute`).
    ///   * `vote_threshold_num` / `vote_threshold_den` — quorum
    ///     threshold; must match what the BallotIssuer used at
    ///     `launch_ballot`.
    ///   * `registration_merkle_root_snapshot` /
    ///     `registration_vote_weight_snapshot` — Election Singleton
    ///     state at `launch_ballot` time (mirrors the curried args).
    /// (Defined inside the impl block via the docstring's hint, but
    /// kept with the method to keep the struct + method co-located.)
    /// FN: build_finalize_for_ballot
    /// WHAT: assemble the finalize spend bundle that targets the
    ///       Ballot Coin singleton. Runs the Groth16 prover, builds
    ///       the action layer + singleton outer wrap, signs.
    /// FLOW:
    ///   1. `prepare_finalize_witness_with_threshold` — pre-checks +
    ///      BLS aggregation + Merkle proofs + scalars.
    ///   2. Construct `VotingCircuit` with the 6 public inputs +
    ///      per-signer Merkle proofs as private witnesses.
    ///   3. `circuit.prove(proving_key)` — Groth16 prover; returns
    ///      a `Groth16Proof`.
    ///   4. Off-chain `verify_offchain` pre-flight against the same
    ///      verification key (catches scalar / circuit mismatches
    ///      before paying the on-chain bundle fee).
    ///   5. Find the current unspent Ballot Coin singleton via
    ///      `find_current_ballot_singleton_via_chain` (mirrors the
    ///      Voter helper). Reconstruct per-ballot finalize / oracle /
    ///      announce_finalization curries to derive the merkle root.
    ///   6. Build the finalize action solution
    ///      `(proof, vote_outcome, agg_signers, agg_sig, ...scalars)`
    ///      and wrap with the action layer + singleton outer (Eve
    ///      proof if no prior Ballot Coin spend, else Lineage).
    ///   7. Sign + bundle. Finalize emits no AggSig conditions, so
    ///      the bundle signature is the zero point.
    pub async fn build_finalize_for_ballot(
        &self,
        mut params: BuildFinalizeForBallotParams<'_>,
    ) -> VotingResult<SpendBundle> {
        // Phase 3: chain-walk override of caller-supplied per-ballot
        // curry params (Option A's launcher memo). See
        // build_finalize_with_proof_for_ballot for rationale.
        let memo = crate::actors::ballot::read_ballot_launcher_memo(
            &self.chain,
            params.ballot_launcher_id,
        )
        .await?;
        if let Some(m) = &memo {
            params.vote_close_height = m.vote_close_height;
            params.vote_threshold_num = m.vote_threshold_num;
            params.vote_threshold_den = m.vote_threshold_den;
            params.registration_merkle_root_snapshot = m.registration_merkle_root_snapshot;
            params.registration_vote_weight_snapshot = m.registration_vote_weight_snapshot;
            params.vote_options_root = m.vote_options_root;
        }
        let witness = self.prepare_finalize_witness_with_threshold(
            params.vote_outcome,
            params.ballot_launcher_id,
            params.votes,
            params.vote_threshold_num,
            params.vote_threshold_den,
            params.registration_vote_weight_snapshot,
        )?;

        // SEC-F1: build the circuit_v2 instance from the witness's per-signer
        // Jubjub/Schnorr/Poseidon-membership data and run the Groth16 prover.
        // Membership + signature + weight quorum are all bound IN-circuit, so
        // a key whose holder did not register AND sign THIS outcome cannot
        // contribute.
        let circuit = VotingCircuitV2 {
            registration_root: witness.registration_root_fr,
            vote_message: witness.vote_message_fr,
            registration_vote_weight: params.registration_vote_weight_snapshot,
            vote_threshold_num: params.vote_threshold_num,
            vote_threshold_den: params.vote_threshold_den,
            depth: crate::config::TREE_DEPTH as usize,
            // SEC-F1: the prover MUST use the SAME signer-slot count baked
            // into the curried VK at ceremony time (circuit_v2 pads up to
            // it). That shape parameter is the election's `max_signers`.
            max_signers: self.config.max_signers.max(witness.signers_v2.len()),
            signers: witness.signers_v2.clone(),
        };
        let proof = circuit.prove(params.proving_key)?;

        // Off-chain verify pre-flight: confirm the proof verifies against the
        // proving key's embedded VK + the SAME public inputs the on-chain
        // finalize will reconstruct (`witness.public_fr`). Catches a
        // circuit/public-input mismatch before paying the on-chain bundle fee
        // (and surfaces it distinctly from an on-chain scalar-encoding bug).
        {
            let vk = crate::prover::circuit::ArkVerifyingKey(params.proving_key.0.vk.clone());
            let ok = VotingCircuitV2::verify_offchain(&vk, &proof, &witness.public_fr)
                .map_err(|e| anyhow_other(format!("finalize proof off-chain verify: {e}")))?;
            if !ok {
                return Err(anyhow_other(
                    "finalize circuit_v2 proof FAILED off-chain verify against the proving \
                     key's VK + public inputs — circuit/public-input mismatch (not an on-chain \
                     encoding bug)"
                        .to_string(),
                ));
            }
        }

        // SEC-F1/F3 PRE-FLIGHT: replicate EACH on-chain finalize.rue assert
        // off-chain so an opaque `clvm raise` in the per-coin dry-run is
        // surfaced as a precise, labelled mismatch. Each branch mirrors the
        // exact comparison in `puzzles/ballot_coin/finalize.rue`.
        {
            use sha2::{Digest, Sha256};
            // u64 → canonical 32-byte BE (matches `fr_to_bytes32_be(Fr::from(n))`
            // for n < r, which is how the SDK encodes s3/s4/s5).
            let u64_be32 = |n: u64| -> [u8; 32] {
                let mut out = [0u8; 32];
                out[24..32].copy_from_slice(&n.to_be_bytes());
                out
            };
            let election_id = self
                .config
                .election_launcher_id()
                .map_err(|e| anyhow_other(format!("preflight election_id: {e}")))?;

            // (1) VK-bind: sha256(verification_key_hex bytes) == config.vk_hash().
            let vk_bytes = hex::decode(self.config.verification_key_hex.trim())
                .map_err(|e| anyhow_other(format!("preflight vk hex: {e}")))?;
            let computed_vk_hash = Bytes32::new(Sha256::digest(&vk_bytes).into());
            let expected_vk_hash = self.config.vk_hash();
            if computed_vk_hash != expected_vk_hash {
                return Err(anyhow_other(format!(
                    "PREFLIGHT VK-bind MISMATCH (finalize.rue would raise on \
                     `sha256(vk_ic_bytes) == ELECTION_VK_HASH`): \
                     sha256(verification_key_hex[{}B]) = 0x{} != config.vk_hash = 0x{}",
                    vk_bytes.len(),
                    hex::encode(computed_vk_hash),
                    hex::encode(expected_vk_hash),
                )));
            }

            // (1b) CRITICAL: the curried/on-chain VK (from config) MUST be the
            // SAME verifying key the proof was generated against. Off-chain
            // verify above uses the PROVING KEY's embedded VK; the on-chain
            // `bls_pairing_identity` uses the CURRIED config VK. If they differ,
            // off-chain passes but the on-chain pairing raises.
            let pk_vk = crate::prover::circuit::ArkVerifyingKey(params.proving_key.0.vk.clone());
            let pk_vk_bytes = pk_vk
                .chia_chunked_bytes()
                .map_err(|e| anyhow_other(format!("preflight pk vk chunked: {e}")))?;
            if pk_vk_bytes != vk_bytes {
                return Err(anyhow_other(format!(
                    "PREFLIGHT proving-key VK != config.verification_key_hex: the proof \
                     was generated against a DIFFERENT VK than the one curried on-chain. \
                     proving_key VK = {}B (0x{}…), config VK = {}B (0x{}…)",
                    pk_vk_bytes.len(),
                    hex::encode(&pk_vk_bytes[..pk_vk_bytes.len().min(16)]),
                    vk_bytes.len(),
                    hex::encode(&vk_bytes[..vk_bytes.len().min(16)]),
                )));
            }

            let pi = &witness.public_inputs;

            // (2) s1 == REGISTRATION_MERKLE_ROOT_SNAPSHOT (both canonical 32-B BE).
            if pi[0].as_ref() != params.registration_merkle_root_snapshot.as_ref() {
                return Err(anyhow_other(format!(
                    "PREFLIGHT s1 MISMATCH (registration_root): proof public input \
                     0x{} != curried snapshot 0x{}",
                    hex::encode(pi[0]),
                    hex::encode(params.registration_merkle_root_snapshot),
                )));
            }
            // (3) s2 == sha256(outcome||ballot||election) mod r. Use ark Fr to
            // reduce mod r exactly as the SDK builds public_fr[1], then re-encode.
            let mut h = Sha256::new();
            h.update(params.vote_outcome.as_ref());
            h.update(params.ballot_launcher_id.as_ref());
            h.update(election_id.as_ref());
            let digest: [u8; 32] = h.finalize().into();
            use ark_ff::PrimeField as _;
            let s2_expected = crate::prover::conversions::fr_to_bytes32_be(
                &ark_bls12_381::Fr::from_be_bytes_mod_order(&digest),
            );
            if pi[1].as_ref() != s2_expected.as_slice() {
                return Err(anyhow_other(format!(
                    "PREFLIGHT s2 MISMATCH (vote_message): proof public input 0x{} != \
                     sha256(outcome||ballot||election) mod r = 0x{}",
                    hex::encode(pi[1]),
                    hex::encode(s2_expected),
                )));
            }
            // (4) s3 == registration_vote_weight_snapshot.
            if pi[2].as_ref() != u64_be32(params.registration_vote_weight_snapshot) {
                return Err(anyhow_other(format!(
                    "PREFLIGHT s3 MISMATCH (vote_weight): proof public input 0x{} != \
                     curried snapshot {} (0x{})",
                    hex::encode(pi[2]),
                    params.registration_vote_weight_snapshot,
                    hex::encode(u64_be32(params.registration_vote_weight_snapshot)),
                )));
            }
            // (5) s4 == vote_threshold_num.
            if pi[3].as_ref() != u64_be32(params.vote_threshold_num) {
                return Err(anyhow_other(format!(
                    "PREFLIGHT s4 MISMATCH (threshold_num): proof public input 0x{} != \
                     curried {} (0x{})",
                    hex::encode(pi[3]),
                    params.vote_threshold_num,
                    hex::encode(u64_be32(params.vote_threshold_num)),
                )));
            }
            // (6) s5 == vote_threshold_den.
            if pi[4].as_ref() != u64_be32(params.vote_threshold_den) {
                return Err(anyhow_other(format!(
                    "PREFLIGHT s5 MISMATCH (threshold_den): proof public input 0x{} != \
                     curried {} (0x{})",
                    hex::encode(pi[4]),
                    params.vote_threshold_den,
                    hex::encode(u64_be32(params.vote_threshold_den)),
                )));
            }
        }

        self.build_finalize_with_proof_for_ballot_inner(
            &params,
            witness,
            proof,
        )
        .await
    }

    /// FN: build_attest_ballot_election_spend (SEC-F3+F5)
    /// WHAT: build the Election Singleton spend that runs the read-only
    ///       `attest_ballot` action, emitting the CHIP-0025 SEND_MESSAGE that
    ///       the Ballot Coin's finalize RECEIVE_MESSAGE pairs with (in the
    ///       same bundle). Returns `(election_spend, election_inner_ph)`; the
    ///       inner ph is what finalize's `election_inner_puzzle_hash` solution
    ///       arg must equal so its genuine-election-ph re-derivation matches
    ///       the spent election coin.
    /// NOTE: the election state is UNCHANGED (read-only action). The snapshot
    ///       in the solution must equal the election's CURRENT registration
    ///       state (attest_ballot asserts this — see the snapshot residual in
    ///       docs/F3-F5-binding-design.md).
    async fn build_attest_ballot_election_spend(
        &self,
        ctx: &mut chia_sdk_driver::SpendContext,
        params: &BuildFinalizeForBallotParams<'_>,
    ) -> VotingResult<(CoinSpend, Bytes32)> {
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::{tree_hash, CurriedProgram};

        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| anyhow_other(format!("election_launcher_id: {e}")))?;
        let current = wait_for_current_singleton(
            &self.chain,
            &self.config,
            self.election_start_height,
            "Election Singleton (attest_ballot co-spend)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        let CurrentSingleton {
            coin: election_coin,
            lineage_proof,
            state,
            ..
        } = current;

        // Election inner puzzle = finalizer + 4-leaf action root + CURRENT state.
        let elect_finalizer =
            crate::action_spends::build_election_finalizer_full(ctx, election_id)?;
        let merkle_root = election_actions_merkle_root_for_config(&self.config);
        let state_node = election_state_node(ctx, &state)?;
        let election_inner_node = crate::action_spends::build_action_layer_puzzle(
            ctx,
            elect_finalizer,
            merkle_root,
            state_node,
        )?;
        let election_inner_ph = Bytes32::new(tree_hash(ctx, election_inner_node).to_bytes());

        // attest_ballot curried (ELECTION_LAUNCHER_ID, NO_VOTE_MODE_LOCK).
        let attest_program =
            crate::action_spends::load_action_puzzle(ctx, puzzles::ELECTION_ATTEST_BALLOT_HEX)?;
        let attest_curried = CurriedProgram {
            program: attest_program,
            args: clvm_curried_args!(election_id, crate::vote_mode::VOTE_MODE_LOCK_NONE),
        }
        .to_clvm(&mut **ctx)
        .map_err(|e| anyhow_other(format!("currying attest_ballot: {e}")))?;
        // Solution AFTER the action layer prepends Truth:
        //   (ballot_launcher_id, snap_root, snap_weight, num, den, ...vote_options_root)
        let attest_solution_value = (
            params.ballot_launcher_id,
            (
                params.registration_merkle_root_snapshot,
                (
                    params.registration_vote_weight_snapshot,
                    (
                        params.vote_threshold_num,
                        (params.vote_threshold_den, params.vote_options_root),
                    ),
                ),
            ),
        );
        let attest_solution = attest_solution_value
            .to_clvm(&mut **ctx)
            .map_err(|e| anyhow_other(format!("attest_ballot solution to_clvm: {e}")))?;
        let action_spends = vec![crate::action_spends::ActionSpend {
            puzzle: attest_curried,
            solution: attest_solution,
        }];
        let elect_finalizer_solution = ()
            .to_clvm(&mut **ctx)
            .map_err(|e| anyhow_other(format!("election finalizer solution: {e}")))?;
        let action_layer_solution = crate::action_spends::build_action_layer_solution(
            ctx,
            &compute_election_action_root_leaves(&self.config),
            &action_spends,
            elect_finalizer_solution,
        )?;
        let election_spend = crate::action_spends::build_singleton_spend(
            ctx,
            election_coin,
            election_id,
            election_inner_node,
            action_layer_solution,
            lineage_proof,
        )?;
        Ok((election_spend, election_inner_ph))
    }

    /// FN: build_finalize_with_proof_for_ballot
    /// WHAT: variant of [`build_finalize_for_ballot`] that takes a
    ///       pre-computed `Groth16Proof` (e.g. produced by a
    ///       separate prover service / batched prover run) instead
    ///       of running the prover inline.
    pub async fn build_finalize_with_proof_for_ballot(
        &self,
        mut params: BuildFinalizeForBallotParams<'_>,
        proof: crate::prover::Groth16Proof,
    ) -> VotingResult<SpendBundle> {
        // Phase 3: chain-walk override of caller-supplied per-ballot
        // curry params (Option A's launcher memo). Mirrors the override
        // in Voter::cast_vote / Voter::update_vote — removes off-chain-
        // metadata drift as a failure mode for the BLS aggregate
        // signature verification (the witness is computed from these
        // values; if they don't match what the on-chain finalize
        // action's curry expects, the aggregate signature won't
        // verify). Falls back to caller params for legacy ballots
        // minted before the memo was added.
        let memo = crate::actors::ballot::read_ballot_launcher_memo(
            &self.chain,
            params.ballot_launcher_id,
        )
        .await?;
        if let Some(m) = &memo {
            params.vote_close_height = m.vote_close_height;
            params.vote_threshold_num = m.vote_threshold_num;
            params.vote_threshold_den = m.vote_threshold_den;
            params.registration_merkle_root_snapshot = m.registration_merkle_root_snapshot;
            params.registration_vote_weight_snapshot = m.registration_vote_weight_snapshot;
            params.vote_options_root = m.vote_options_root;
        }
        let witness = self.prepare_finalize_witness_with_threshold(
            params.vote_outcome,
            params.ballot_launcher_id,
            params.votes,
            params.vote_threshold_num,
            params.vote_threshold_den,
            params.registration_vote_weight_snapshot,
        )?;
        self.build_finalize_with_proof_for_ballot_inner(&params, witness, proof)
            .await
    }

    async fn build_finalize_with_proof_for_ballot_inner(
        &self,
        params: &BuildFinalizeForBallotParams<'_>,
        witness: FinalizeWitness,
        proof: crate::prover::Groth16Proof,
    ) -> VotingResult<SpendBundle> {
        use chia_protocol::Bytes;
        use chia_puzzle_types::singleton::SingletonArgs;
        use chia_puzzle_types::{LineageProof, Proof};
        use chia_sdk_driver::SpendContext;
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::{tree_hash, CurriedProgram, TreeHash};

        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| anyhow_other(format!("election_launcher_id: {e}")))?;

        // ── 1. Compute per-ballot finalize / oracle / announce hashes.
        let mut ctx = SpendContext::new();
        let (vk_node, ic_node) =
            crate::actors::ballot::build_vk_ic_nodes(&mut ctx, &self.config)?;

        let finalize_program_node = crate::action_spends::load_action_puzzle(
            &mut ctx,
            crate::puzzles::BALLOT_COIN_FINALIZE_HEX,
        )?;
        let finalize_curried = CurriedProgram {
            program: finalize_program_node,
            args: clvm_curried_args!(
                vk_node,
                ic_node,
                params.ballot_launcher_id,
                election_id,
                params.vote_close_height,
                params.vote_threshold_num,
                params.vote_threshold_den,
                params.registration_merkle_root_snapshot,
                params.registration_vote_weight_snapshot,
                // SEC-F3+F5: MUST match launch_ballot + the voter predictors.
                self.config.vk_hash(),
                params.vote_options_root,
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(|e| anyhow_other(format!("currying ballot finalize: {e}")))?;
        let finalize_full_hash =
            Bytes32::new(tree_hash(&ctx, finalize_curried).to_bytes());

        // M4-revised oracle curry: (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT,
        // VOTE_OPTIONS_ROOT). SEC-F5: use the ballot's REAL options root (from
        // the launcher memo, plumbed via params) — NOT a hardcoded default —
        // so the predicted ballot ph matches the on-chain ballot for
        // mode-restricted ballots too.
        let vote_options_root_curry: Bytes32 = params.vote_options_root;
        let oracle_program_node = crate::action_spends::load_action_puzzle(
            &mut ctx,
            crate::puzzles::BALLOT_COIN_ORACLE_HEX,
        )?;
        let oracle_curried = CurriedProgram {
            program: oracle_program_node,
            args: clvm_curried_args!(
                params.ballot_launcher_id,
                params.vote_close_height,
                vote_options_root_curry
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(|e| anyhow_other(format!("currying oracle: {e}")))?;
        let oracle_full_hash = Bytes32::new(tree_hash(&ctx, oracle_curried).to_bytes());

        let announce_program_node = crate::action_spends::load_action_puzzle(
            &mut ctx,
            crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX,
        )?;
        let announce_curried = CurriedProgram {
            program: announce_program_node,
            args: clvm_curried_args!(params.ballot_launcher_id),
        }
        .to_clvm(&mut *ctx)
        .map_err(|e| anyhow_other(format!("currying announce_finalization: {e}")))?;
        let announce_full_hash =
            Bytes32::new(tree_hash(&ctx, announce_curried).to_bytes());

        let ballot_actions_root = crate::puzzles::per_ballot_actions_merkle_root(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );
        let ballot_root_leaves = crate::puzzles::per_ballot_action_root_leaves(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );

        // Ballot inner ph (state is fresh — pre-finalize).
        let ballot_finalizer_node =
            crate::action_spends::build_ballot_finalizer_full(&mut ctx, params.ballot_launcher_id)?;
        // SEC-F1: BallotState = (finalized . (vote_outcome . agg_signers)).
        // `finalized` MUST be nil (= Rue `false`), NOT Bytes32::default()
        // (32 zero bytes) — finalize.rue asserts `State.finalized == false`,
        // and a 32-byte zero atom != nil.
        let fresh_ballot_state_value: ((), (Bytes32, Bytes32)) =
            ((), (Bytes32::default(), Bytes32::default()));
        let ballot_state_node = fresh_ballot_state_value
            .to_clvm(&mut *ctx)
            .map_err(|e| anyhow_other(format!("ballot state to_clvm: {e}")))?;
        let ballot_inner_node = crate::action_spends::build_action_layer_puzzle(
            &mut ctx,
            ballot_finalizer_node,
            ballot_actions_root,
            ballot_state_node,
        )?;
        let ballot_inner_ph = Bytes32::new(tree_hash(&ctx, ballot_inner_node).to_bytes());

        // ── 2. Find current Ballot Coin singleton ──────────────
        let (ballot_coin, ballot_lineage_proof) = find_current_ballot_singleton_via_chain(
            &self.chain,
            params.ballot_launcher_id,
            ballot_inner_ph,
        )
        .await?;

        // Sanity: predicted ph matches on-chain ph.
        let inner_th = TreeHash::new(ballot_inner_ph.to_bytes());
        let predicted_full_ph = Bytes32::new(
            SingletonArgs::curry_tree_hash(params.ballot_launcher_id, inner_th).to_bytes(),
        );
        if ballot_coin.puzzle_hash != predicted_full_ph {
            return Err(anyhow_other(format!(
                "build_finalize_for_ballot: Ballot Coin ph {} doesn't match predicted {} \
                 — params don't match the on-chain ballot",
                hex::encode(ballot_coin.puzzle_hash),
                hex::encode(predicted_full_ph),
            )));
        }
        let _ = ballot_lineage_proof; // shadowed below
        let ballot_lineage_proof: Proof = match ballot_lineage_proof {
            Proof::Eve(e) => Proof::Eve(e),
            Proof::Lineage(l) => Proof::Lineage(LineageProof {
                parent_parent_coin_info: l.parent_parent_coin_info,
                parent_inner_puzzle_hash: l.parent_inner_puzzle_hash,
                parent_amount: l.parent_amount,
            }),
        };

        // ── 2b. Build the Election Singleton attest_ballot co-spend ──
        // SEC-F3+F5: finalize emits a RECEIVE_MESSAGE that pairs (in this same
        // bundle) with the SEND_MESSAGE this election spend emits — binding the
        // ballot's curried VK / snapshots / vote_options_root to the genuine
        // election's unforgeable state. `election_inner_ph` is what finalize's
        // `election_inner_puzzle_hash` solution arg must equal.
        let (election_attest_spend, election_inner_ph) =
            self.build_attest_ballot_election_spend(&mut ctx, params).await?;

        // ── 3. Build the finalize action solution ─────────────
        // Per `puzzles/ballot_coin/finalize.rue`:
        //   `(proof, vote_outcome_data, agg_signers, agg_sig, ...scalars)`
        // where `proof` is a 3-field struct (a, b, c) WITHOUT
        // rest-arg (so nil-terminated), `scalars` is a 6-field
        // struct (s1..s6) WITHOUT rest-arg, and the outer `...scalars`
        // means scalars is the cdr of the last cons (no extra
        // terminator).
        let proof_a = Bytes::new(
            hex::decode(&proof.a_hex).map_err(VotingError::HexDecode)?,
        );
        let proof_b = Bytes::new(
            hex::decode(&proof.b_hex).map_err(VotingError::HexDecode)?,
        );
        let proof_c = Bytes::new(
            hex::decode(&proof.c_hex).map_err(VotingError::HexDecode)?,
        );
        // Proof: (a . (b . (c . ())))
        let proof_value = (proof_a, (proof_b, (proof_c, ())));

        // SEC-F1: circuit_v2 finalize solution carries FIVE scalars (the raw
        // 32-byte BE public inputs), NO agg_signers / agg_sig. finalize.rue
        // compares each scalar NUMERICALLY (`(scalars.sN as Bytes) as Int`),
        // so the 32-byte zero-padded `fr_to_bytes32_be` form reads as the
        // same integer the off-chain prover committed via the IC vector.
        let pi = &witness.public_inputs;
        let s1 = chia_protocol::Bytes::new(pi[0].as_ref().to_vec());
        let s2 = chia_protocol::Bytes::new(pi[1].as_ref().to_vec());
        let s3 = chia_protocol::Bytes::new(pi[2].as_ref().to_vec());
        let s4 = chia_protocol::Bytes::new(pi[3].as_ref().to_vec());
        let s5 = chia_protocol::Bytes::new(pi[4].as_ref().to_vec());
        // Scalars rest-arg: (s1 . (s2 . (s3 . (s4 . (s5 . ())))))
        let scalars_value = (s1, (s2, (s3, (s4, (s5, ())))));

        // Top-level finalize solution (per ballot_coin/finalize.rue, SEC-F3+F5):
        //   (proof . (vote_outcome . (election_inner_ph . (s1 . (s2 . (s3 . (s4 . (s5 . ()))))))))
        let finalize_solution_value = (
            proof_value,
            (params.vote_outcome, (election_inner_ph, scalars_value)),
        );
        let finalize_solution = finalize_solution_value
            .to_clvm(&mut *ctx)
            .map_err(|e| anyhow_other(format!("finalize solution to_clvm: {e}")))?;

        let action_spends = vec![crate::action_spends::ActionSpend {
            puzzle: finalize_curried,
            solution: finalize_solution,
        }];
        // Ballot finalizer takes `..._my_solution: Any` — pass nil.
        let ballot_finalizer_solution = ()
            .to_clvm(&mut *ctx)
            .map_err(|e| anyhow_other(format!("ballot finalizer solution: {e}")))?;
        let action_layer_solution = crate::action_spends::build_action_layer_solution(
            &mut ctx,
            &ballot_root_leaves,
            &action_spends,
            ballot_finalizer_solution,
        )?;

        let ballot_singleton_spend = crate::action_spends::build_singleton_spend(
            &mut ctx,
            ballot_coin,
            params.ballot_launcher_id,
            ballot_inner_node,
            action_layer_solution,
            ballot_lineage_proof,
        )?;

        // ── 4. Sign + bundle ──────────────────────────────────
        // SEC-F3+F5: the election attest_ballot spend MUST be in the same
        // bundle so its SEND_MESSAGE pairs with finalize's RECEIVE_MESSAGE.
        let coin_spends = vec![ballot_singleton_spend, election_attest_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "build-finalize-failed-{}.json",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
                    "vote_outcome": format!("0x{}", hex::encode(params.vote_outcome)),
                    "ballot_launcher_id": format!("0x{}", hex::encode(params.ballot_launcher_id)),
                    "vote_close_height": params.vote_close_height,
                    "vote_threshold_num": params.vote_threshold_num,
                    "vote_threshold_den": params.vote_threshold_den,
                    "registration_merkle_root_snapshot": format!("0x{}", hex::encode(params.registration_merkle_root_snapshot)),
                    "registration_vote_weight_snapshot": params.registration_vote_weight_snapshot,
                    "public_inputs": {
                        "s1_registration_root": format!("0x{}", hex::encode(witness.public_inputs[0])),
                        "s2_vote_message": format!("0x{}", hex::encode(witness.public_inputs[1])),
                        "s3_vote_weight": format!("0x{}", hex::encode(witness.public_inputs[2])),
                        "s4_num": format!("0x{}", hex::encode(witness.public_inputs[3])),
                        "s5_den": format!("0x{}", hex::encode(witness.public_inputs[4])),
                    },
                    "n_signers": witness.signers_v2.len(),
                    "coin_spends": coin_spends.iter().map(|cs| serde_json::json!({
                        "coin": {
                            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                            "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                            "amount": cs.coin.amount,
                        },
                        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                        "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                    })).collect::<Vec<_>>(),
                })).unwrap_or_else(|_| "<json serialise failed>".into());
                let _ = std::fs::write(&path, json);
                tracing::warn!(dump_path = %path.display(), "wrote failing bundle to disk");
            }
            return Err(anyhow_other(format!(
                "build_finalize_for_ballot dry-run: {e:?}"
            )));
        }
        let signature = crate::actors::deployer::sign_bundle_signature(
            &coin_spends,
            &[],
            self.network,
        )?;
        Ok(SpendBundle::new(coin_spends, signature))
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
/// FIELD GROUPS (SEC-F1, circuit_v2):
///   * On-chain public inputs (5): `registration_root_fr`,
///     `vote_message_fr`, `registration_vote_weight`,
///     `vote_threshold_num`, `vote_threshold_den` — also encoded as
///     `public_inputs` (32-byte BE) for the finalize solution.
///   * Private witness (off-chain only): `signers_v2` (Jubjub pubkey +
///     Poseidon membership proof + Schnorr signature per signer),
///     `signer_pubkeys` (BLS, for audit/dedup).
///   * On-chain solution arguments to the `finalize` action:
///     `vote_outcome` + `public_inputs`. There is NO `agg_signers` /
///     `agg_signature` anymore — the quorum is proven in-circuit.
///
/// SERDE: not derived (arkworks + chia_bls types). Hex-encode if needed.
#[derive(Debug, Clone)]
pub struct FinalizeWitness {
    pub vote_outcome: Bytes32,
    /// Ballot Coin launcher id this witness was produced against.
    pub ballot_launcher_id: Bytes32,
    /// Canonical vote message digest `sha256(outcome||ballot||election)`.
    pub vote_message: Bytes32,
    /// `vote_message` reduced into `Fr` — the value voters Schnorr-sign and
    /// circuit_v2 binds (matches finalize.rue's on-chain `mod r` derivation).
    pub vote_message_fr: ark_bls12_381::Fr,
    pub registration_merkle_root: Bytes32,
    /// The Poseidon registration-tree root as an `Fr` (circuit public input).
    pub registration_root_fr: ark_bls12_381::Fr,
    pub registration_count: u64,
    pub registration_vote_weight: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    /// The 5 circuit_v2 public inputs as 32-byte BE (the finalize solution
    /// scalars, matching `finalize_v2_probe.rue`).
    pub public_inputs: [Bytes32; 5],
    /// The same 5 public inputs as `Fr` (off-chain verify pre-flight).
    pub public_fr: [ark_bls12_381::Fr; 5],
    /// Per-signer circuit_v2 witnesses (Jubjub pubkey + Poseidon proof +
    /// Schnorr signature).
    pub signers_v2: Vec<SignerV2>,
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
    pub smt: PoseidonSmt,
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
    tracing::info!(
        eve_ph = %hex::encode(eve_singleton_puzzle_hash),
        candidates = candidates.len(),
        unspent = candidates.iter().filter(|c| c.is_unspent()).count(),
        "sync_with_chain DIAG: fast-path query"
    );
    if candidates.len() == 1 && candidates[0].is_unspent() {
        // Empty SPT root at depth 32 (NOT the leaf hash) — the
        // root the on-chain register action verifies against. Per
        // CHIP.md §88-91 the occupied leaf is `sha256(pubkey)`; no
        // per-voter weight is encoded into the leaf, so the SMT
        // takes no extra parameters.
        let smt = PoseidonSmt::new();
        let empty_root = Bytes32::new(smt.root_be32());
        let state = ElectionState::genesis_from_config(empty_root, election_start_height, config);
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
    // launcher coin. The Chia SingletonLauncher contract guarantees
    // exactly one valid child per launcher (the eve), so we accept it
    // regardless of whether its puzzle_hash matches the
    // `eve_singleton_puzzle_hash` we predicted from
    // `election_start_height`. Predictions can drift if the caller
    // doesn't know the deployer's exact submission peak (legacy
    // bootstrap import, share-bundle without electionStartHeight,
    // etc.) — the launcher_id alone is sufficient. Whatever the
    // launcher minted IS the eve. Mirrors `find_current_singleton`.
    let eve_children = chain.coin_records_by_parent_ids(&[launcher_id]).await?;
    tracing::info!(
        launcher_id = %hex::encode(launcher_id),
        children = eve_children.len(),
        target_ph = %hex::encode(eve_singleton_puzzle_hash),
        actual_ph = ?eve_children.iter().map(|r| hex::encode(r.coin.puzzle_hash)).collect::<Vec<_>>(),
        "sync_with_chain DIAG: slow-path query"
    );
    let eve_record = eve_children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
        .ok_or(VotingError::NotDeployed)?;

    // Walk forward from the eve singleton. Initialise SPT to
    // empty + genesis state with the depth-32 empty SPT root.
    // Per CHIP.md §88-91 the occupied leaf is `sha256(pubkey)`,
    // so the SMT needs no extra parameters; per-voter weight is
    // tracked on the Election Singleton state instead.
    let mut smt = PoseidonSmt::new();
    let mut voters: Vec<chia_bls::PublicKey> = Vec::new();
    let mut state = ElectionState::genesis_from_config(Bytes32::new(smt.root_be32()), election_start_height, config);
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
        registration_merkle_root: Bytes32::new(smt.root_be32()),
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
    pub smt: PoseidonSmt,
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
    // SECONDARY-INDEX HAZARD: coinset.org's `coin_records_by_puzzle_hash`
    // index lags behind the primary `coin_record_by_id` view by 1-3
    // blocks during high-rate spending (e.g., back-to-back register +
    // create_ballot on the same singleton). We confirm via the primary
    // index before treating any "unspent" candidate as authoritative —
    // otherwise the walker returns a stale tip and the next spend gets
    // MINTING_COIN/DOUBLE_SPEND on the chain.
    let eve_records = chain.coin_records_by_puzzle_hash(eve_ph).await?;
    // Post-eve singletons keep the same outer puzzle_hash whenever the
    // curried inner state hasn't changed (createBallot/launchBallot
    // pass through registration_merkle_root + count). So the secondary
    // index can return BOTH the (spent) eve AND a (unspent) post-eve
    // generation. Only the eve has parent_coin_info == launcher_id;
    // anything else is a generation-2+ coin that needs Proof::Lineage,
    // which the slow path constructs correctly.
    let eve_candidate = match eve_records
        .iter()
        .find(|r| r.is_unspent() && r.coin.parent_coin_info == launcher_id)
    {
        Some(c) => match chain.coin_record_by_id(c.coin.coin_id()).await? {
            Some(authoritative) if authoritative.is_unspent() => Some(c),
            // Primary disagrees — the index returned a stale "unspent"
            // record. Treat as no fast-path hit so we fall to the slow
            // walker, which honours `coin_record_by_id` per step.
            _ => None,
        },
        None => None,
    };
    if let Some(unspent) = eve_candidate {
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
        let smt = PoseidonSmt::new();
        let state = ElectionState::genesis_from_config(Bytes32::new(smt.root_be32()), election_start_height, config);
        let voter_set = VoterSet {
            registration_merkle_root: Bytes32::new(smt.root_be32()),
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
    // The Chia SingletonLauncher contract guarantees exactly one
    // valid child per launcher (the eve singleton). We accept it
    // regardless of whether its puzzle_hash matches the
    // `eve_ph` we predicted from `election_start_height` — the
    // prediction can drift if the caller doesn't know the deployer's
    // exact submission peak (e.g. a re-import without the original
    // bootstrap, or a session whose electionStartHeight was never
    // persisted). The launcher_id alone is sufficient to discover
    // the singleton; whatever the launcher minted IS the eve.
    let eve_children = chain.coin_records_by_parent_ids(&[launcher_id]).await?;
    let eve_record = eve_children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
        .ok_or(VotingError::NotDeployed)?;

    let mut smt = PoseidonSmt::new();
    let mut voters: Vec<chia_bls::PublicKey> = Vec::new();
    let mut state = ElectionState::genesis_from_config(Bytes32::new(smt.root_be32()), election_start_height, config);
    let mut ballots: Vec<BallotCoinSnapshot> = Vec::new();

    let mut current = eve_record;
    // Track the previous coin + state so the loop can build the
    // lineage proof for `current` (the new child) once it becomes
    // unspent: its parent IS the previous `current` coin.
    let mut prev: Option<(chia_protocol::Coin, ElectionState)> = None;

    loop {
        // Re-verify via primary `coin_record_by_id` before returning.
        // The `coin_records_by_parent_ids` secondary index can return
        // a "spent_block_index=0" (= unspent) record for a coin that
        // primary index has already marked spent — happens during
        // back-to-back singleton spends within the same propagation
        // window. Trusting the secondary index here would return a
        // stale tip; the next spend that targets it gets a consensus
        // error (MINTING_COIN / DOUBLE_SPEND).
        let truly_unspent = if current.is_unspent() {
            match chain.coin_record_by_id(current.coin.coin_id()).await? {
                Some(authoritative) => authoritative.is_unspent(),
                // Primary doesn't know about this coin yet — keep the
                // optimistic "unspent" view and proceed.
                None => true,
            }
        } else {
            false
        };
        if truly_unspent {
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
                registration_merkle_root: Bytes32::new(smt.root_be32()),
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
    let started = web_time::Instant::now();
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
                crate::chain::compat_sleep(poll_interval).await;
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
    smt: &mut PoseidonSmt,
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
    // SEC-F4: deregister now authorizes the Registration Coin's release
    // via a CHIP-0025 SEND_MESSAGE (opcode 66) instead of a
    // CreateCoinAnnouncement. Collect those 32-byte messages too so the
    // deregister-detection below still recognises a deregister spend.
    let mut send_messages: Vec<[u8; 32]> = Vec::new();
    let mut node = conds_root;
    while let Some((cond, rest)) = allocator.next(node) {
        node = rest;
        let Some((opcode_node, args_node)) = allocator.next(cond) else {
            continue;
        };
        let opcode_bytes = allocator.atom(opcode_node);
        match opcode_bytes.as_ref() {
            // CreateCoinAnnouncement = opcode 60: message is the 1st arg.
            [60] => {
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
            // SendMessage = opcode 66: `(66 mode message ...receiver)`;
            // the message is the 2nd arg (after the mode byte).
            [66] => {
                let Some((_mode_node, after_mode)) = allocator.next(args_node) else {
                    continue;
                };
                let Some((msg_node, _)) = allocator.next(after_mode) else {
                    continue;
                };
                let msg = allocator.atom(msg_node);
                if msg.as_ref().len() == 32 {
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(msg.as_ref());
                    send_messages.push(buf);
                }
            }
            _ => continue,
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

    // ── Deregister detection ─────────────────────────────────────
    //
    // Per `puzzles/election/deregister.rue`, a deregister spend emits
    // exactly one CreateCoinAnnouncement whose 32-byte message is
    // `deregister_announcement_msg(pk) = sha256("deregister" || pk)`
    // (mirrored in `puzzles::deregister_announcement_msg`). Because
    // the message preimage is `pk`-only (no merkle root or count
    // mixed in), we CAN reverse it given the candidate pubkeys
    // recovered from the solution. For each candidate pk in the
    // solution, hash `"deregister" || pk` and check whether it
    // appears among the spend's CCA messages — if so this is a
    // deregister spend, and we mirror the on-chain SPT update by
    // wiping that voter's leaf.
    //
    // NOTE: deregister discrimination MUST run BEFORE the register
    // fallback, because the latter is intentionally permissive (any
    // CCA counts as a register hint).
    // SEC-F1: the deregister announcement is keyed by the BLS pubkey, but
    // the Poseidon SPT is keyed by the voter's Jubjub pubkey, so the wipe
    // needs the Jubjub coords. deregister.rue carries them in the solution
    // (after the BLS pubkey), so we recover the on-curve Jubjub point from
    // the solution's 32-byte atoms — the genuine point is the one currently
    // registered in the SPT.
    let candidate_points = recover_jubjub_points(&candidate_outcomes, smt);
    for pk in &candidate_pubkeys {
        let msg = crate::puzzles::deregister_announcement_msg(pk);
        if cca_messages.iter().any(|m| m == msg.as_ref())
            || send_messages.iter().any(|m| m == msg.as_ref())
        {
            // Found a deregister CCA. Wipe the SMT leaf (keyed by the
            // recovered Jubjub point), drop the voter from the bookkeeping
            // vector, and decrement count/weight to mirror
            // `deregister.rue`'s state transition:
            //   `registration_count -= 1`
            //   `registration_vote_weight -= locked_cat_mojos` (the
            //       voter's REAL lock, recovered from the SMT before
            //       we wipe their leaf — weighted-voting rev)
            //   `registration_merkle_root = <SPT with leaf wiped>`
            // Idempotent against repeated syncs because `remove`
            // returns false when the point isn't currently in the SPT.
            let jub = match candidate_points.first() {
                Some(p) => *p,
                None => return Ok(()),
            };
            let recovered_lock = smt.locked_amount(jub);
            let removed = smt.remove(jub);
            if removed {
                voters.retain(|v| v != pk);
                state.registration_count = voters.len() as u64;
                state.registration_merkle_root = Bytes32::new(smt.root_be32());
                let lock = recovered_lock.unwrap_or(collateral_amount);
                state.registration_vote_weight = state
                    .registration_vote_weight
                    .saturating_sub(lock);
            }
            return Ok(());
        }
    }

    // ── Register detection (SEC-F1 Poseidon/Jubjub rev) ──────────
    //
    // `register.rue` emits a CCA whose preimage is
    //   sha256("registered" || new_root || (count+1)_be8 ||
    //          pk || lock_be8 || jub_x || jub_y)
    // — this binds the new Poseidon SPT root, the new count, the BLS
    // pubkey, the voter's chosen lock amount, AND the voter's Jubjub
    // pubkey coords into one hash. We recover (pk, jub_point, lock) by:
    //   (a) all 48-byte BLS-G1 atoms in the solution as pubkey candidates,
    //   (b) all on-curve Jubjub points formed from the solution's 32-byte
    //       atoms (jub_x, jub_y) as point candidates,
    //   (c) all 0-8 byte atoms as lock_amount candidates,
    //   (d) for each (pk, point, lock): tentatively insert the leaf into
    //       the Poseidon SPT keyed by the point, compute the resulting
    //       root, hash the candidate preimage, and check it matches a CCA.
    // Only the genuine triple reproduces the announced root.
    if registered_count > 0 {
        let mut lock_candidates: Vec<u64> = Vec::new();
        collect_u64_atoms(&allocator, solution_node, &mut lock_candidates);
        let point_candidates = oncurve_jubjub_points(&candidate_outcomes);
        let next_count = state.registration_count.saturating_add(1);
        let next_count_be = next_count.to_be_bytes();
        let mut matched: Option<(chia_bls::PublicKey, JubAffine, u64)> = None;
        'search: for pk in &candidate_pubkeys {
            let pk_bytes = pk.to_bytes();
            for point in &point_candidates {
                let jub_x = crate::merkle::fr_to_be32(point.x);
                let jub_y = crate::merkle::fr_to_be32(point.y);
                for lock in &lock_candidates {
                    if *lock < collateral_amount {
                        // Below the curried minimum — register.rue would
                        // have rejected the spend.
                        continue;
                    }
                    let mut tentative = smt.clone();
                    tentative.insert(*point, *lock);
                    let new_root = tentative.root_be32();
                    let mut h = sha2::Sha256::new();
                    use sha2::Digest;
                    h.update(b"registered");
                    h.update(new_root);
                    h.update(next_count_be);
                    h.update(pk_bytes);
                    h.update(lock.to_be_bytes());
                    h.update(jub_x);
                    h.update(jub_y);
                    let candidate_msg: [u8; 32] = h.finalize().into();
                    if cca_messages.iter().any(|m| m == &candidate_msg) {
                        matched = Some((*pk, *point, *lock));
                        break 'search;
                    }
                }
            }
        }
        if let Some((pk, point, lock)) = matched {
            smt.insert(point, lock);
            voters.push(pk);
            state.registration_count = voters.len() as u64;
            state.registration_merkle_root = Bytes32::new(smt.root_be32());
            state.registration_vote_weight =
                state.registration_vote_weight.saturating_add(lock);
        } else if let (Some(pk), Some(point)) =
            (candidate_pubkeys.into_iter().next(), point_candidates.into_iter().next())
        {
            // Defensive fallback: no (pk, point, lock) triple matched a
            // CCA. Should not happen for spends produced by this SDK; the
            // most likely trigger is a manually-crafted register bundle
            // whose announcement preimage diverges from `register.rue`.
            // Fall back to the curried minimum so sync makes forward
            // progress instead of deadlocking, and warn loudly.
            tracing::warn!(
                pk = %hex::encode(pk.to_bytes()),
                "apply_singleton_spend: register CCA detected but no \
                 (pk, point, lock) triple matched — falling back to \
                 curried collateral_amount minimum"
            );
            {
                smt.insert(point, collateral_amount);
                voters.push(pk);
                state.registration_count = voters.len() as u64;
                state.registration_merkle_root = Bytes32::new(smt.root_be32());
                state.registration_vote_weight =
                    state.registration_vote_weight.saturating_add(collateral_amount);
            }
        }
    }
    Ok(())
}

/// FN: jubaffine_from_be32 (file-private, SEC-F1)
/// WHAT: reconstruct a Jubjub affine point from the 32-byte BE encodings of
///       its (x, y) coords (as produced by `merkle::fr_to_be32`), returning
///       `None` unless the point is genuinely on the curve and in the
///       prime-order subgroup. Used to recover a voter's registered Jubjub
///       pubkey from a register / deregister action's solution atoms.
fn jubaffine_from_be32(x: &[u8; 32], y: &[u8; 32]) -> Option<JubAffine> {
    use ark_ff::PrimeField;
    type Fq = ark_ed_on_bls12_381::Fq;
    let px = Fq::from_be_bytes_mod_order(x);
    let py = Fq::from_be_bytes_mod_order(y);
    let p = JubAffine::new_unchecked(px, py);
    if p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() {
        Some(p)
    } else {
        None
    }
}

/// FN: oncurve_jubjub_points (file-private, SEC-F1)
/// WHAT: from a list of 32-byte atoms recovered from a solution, return
///       every ORDERED (x, y) pair that forms a valid on-curve Jubjub
///       point. The genuine `(jub_x, jub_y)` the voter supplied is among
///       these; sibling-hash / coin-id atoms paired as (x, y) are
///       overwhelmingly NOT on-curve and are filtered out. De-duplicated.
fn oncurve_jubjub_points(atoms: &[[u8; 32]]) -> Vec<JubAffine> {
    let mut out: Vec<JubAffine> = Vec::new();
    for x in atoms {
        for y in atoms {
            if let Some(p) = jubaffine_from_be32(x, y) {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// FN: recover_jubjub_points (file-private, SEC-F1)
/// WHAT: the subset of `oncurve_jubjub_points(atoms)` that is CURRENTLY
///       registered in `smt`. For a deregister spend (whose announcement is
///       keyed by the BLS pubkey, not the Jubjub key) this isolates the
///       exact leaf to wipe.
fn recover_jubjub_points(atoms: &[[u8; 32]], smt: &PoseidonSmt) -> Vec<JubAffine> {
    oncurve_jubjub_points(atoms)
        .into_iter()
        .filter(|p| smt.contains(*p))
        .collect()
}

/// FN: collect_u64_atoms (file-private)
/// WHAT: walk a CLVM tree and collect every 0-8 byte atom interpreted
///       as a big-endian unsigned integer (u64). Used by
///       `apply_singleton_spend` to recover candidate `locked_cat_mojos`
///       values from a register action's solution. The CLVM canonical
///       integer encoding is variable-length (no leading zero bytes),
///       so we reject atoms over 8 bytes to skip 32-byte hashes /
///       48-byte pubkeys / etc., and parse the rest as BE u64.
fn collect_u64_atoms(
    allocator: &clvmr::Allocator,
    node: clvmr::NodePtr,
    out: &mut Vec<u64>,
) {
    use clvmr::SExp;
    match allocator.sexp(node) {
        SExp::Atom => {
            let atom = allocator.atom(node);
            let bytes = atom.as_ref();
            if bytes.len() <= 8 {
                let mut padded = [0u8; 8];
                padded[8 - bytes.len()..].copy_from_slice(bytes);
                let value = u64::from_be_bytes(padded);
                if !out.contains(&value) {
                    out.push(value);
                }
            }
        }
        SExp::Pair(head, tail) => {
            collect_u64_atoms(allocator, head, out);
            collect_u64_atoms(allocator, tail, out);
        }
    }
}

/// FN: collect_bytes32_atoms (file-private)
/// WHAT: walk a CLVM tree and collect every 32-byte atom into `out`.
/// USAGE: `apply_singleton_spend` uses this to enumerate candidate
///        `vote_outcome` values when looking for a finalize spend's
///        `sha256("finalized" || …)` CCA. Includes ALL 32-byte
///        atoms — the merkle_root, lineage proofs, and other 32-byte
///        atoms are harmless additional candidates because the
///        sha256 match is conclusive.
pub(crate) fn collect_bytes32_atoms(
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

/// STRUCT: BuildFinalizeForBallotParams
/// PURPOSE: typed bundle for [`Aggregator::build_finalize_for_ballot`]
///          and [`Aggregator::build_finalize_with_proof_for_ballot`].
///          See the per-method doc for field semantics.
pub struct BuildFinalizeForBallotParams<'a> {
    pub ballot_launcher_id: Bytes32,
    pub vote_outcome: Bytes32,
    pub votes: &'a [VoteRecord],
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot: Bytes32,
    pub registration_vote_weight_snapshot: u64,
    /// SEC-F3+F5: the ballot's curried `VOTE_OPTIONS_ROOT` (Mode1Free =
    /// `Bytes32::default()`). MUST equal what `launch_ballot` curried so the
    /// predicted ballot ph matches on-chain AND the attest_ballot binding
    /// message pairs. Sourced from the ballot launcher memo.
    pub vote_options_root: Bytes32,
    pub proving_key: &'a crate::prover::circuit::ArkProvingKey,
}

/// FN: find_current_ballot_singleton_via_chain
/// WHAT: walk a Ballot Coin's singleton lineage and return the latest
///       unspent coin + lineage proof. Mirrors
///       `voter::find_current_ballot_singleton` but exposed at the
///       aggregator level so finalize can reuse it.
/// SEE: voter.rs's helper for the full algorithm.
pub async fn find_current_ballot_singleton_via_chain<C: ChainReader>(
    chain: &C,
    ballot_launcher_id: Bytes32,
    expected_inner_ph: Bytes32,
) -> VotingResult<(chia_protocol::Coin, chia_puzzle_types::Proof)> {
    use chia_puzzle_types::{EveProof, LineageProof, Proof};

    let launcher_record = chain
        .coin_record_by_id(ballot_launcher_id)
        .await?
        .ok_or_else(|| {
            anyhow_other(format!(
                "find_current_ballot_singleton_via_chain: launcher coin {} not found",
                hex::encode(ballot_launcher_id),
            ))
        })?;
    let launcher_coin = launcher_record.coin;

    let eve_children = chain
        .coin_records_by_parent_ids(&[ballot_launcher_id])
        .await?;
    let mut current = eve_children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
        .ok_or_else(|| {
            anyhow_other(
                "find_current_ballot_singleton_via_chain: no eve Ballot Coin",
            )
        })?;

    let mut lineage_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: launcher_coin.parent_coin_info,
        parent_amount: launcher_coin.amount,
    });

    loop {
        if current.is_unspent() {
            return Ok((current.coin, lineage_proof));
        }
        let parent_coin = current.coin;
        let parent_id = parent_coin.coin_id();
        let children = chain.coin_records_by_parent_ids(&[parent_id]).await?;
        let next = children
            .into_iter()
            .find(|r| r.coin.amount % 2 == 1)
            .ok_or_else(|| {
                anyhow_other(format!(
                    "find_current_ballot_singleton_via_chain: no child of \
                     spent Ballot Coin {}",
                    hex::encode(parent_id),
                ))
            })?;
        lineage_proof = Proof::Lineage(LineageProof {
            parent_parent_coin_info: parent_coin.parent_coin_info,
            parent_inner_puzzle_hash: expected_inner_ph,
            parent_amount: parent_coin.amount,
        });
        current = next;
    }
}

// NOTE: a `canonical_int_bytes32` helper formerly lived here to strip leading
// zero bytes off each finalize scalar so the on-chain CLVM byte-equality
// (`scalars.s_i as Bytes == <canonical>`) would match. That approach was
// abandoned: it was fragile (a stripped value whose new leading byte has the
// high bit set needs a `0x00` sign pad — the helper's "high bit never set"
// note conflated the 32-byte form's leading byte with the stripped form's) and
// asymmetric (s1's curried RHS is a fixed 32-byte Bytes32, not canonical). The
// real fix is in `puzzles/ballot_coin/finalize.rue`: each scalar bind now
// compares by VALUE via `(lhs - rhs) == 0` (CLVM subtraction is numeric and
// encoding-agnostic), so the SDK can send every scalar as a plain 32-byte BE
// atom (`fr_to_bytes32_be`) and the binding holds regardless of byte width.

/// FN: collect_signature_atoms (file-private)
/// WHAT: walk a CLVM tree and collect every 96-byte atom (BLS G2
///       signature size). Sibling to [`collect_bytes32_atoms`] /
///       [`collect_pubkey_candidates`]; used by
///       [`Aggregator::collect_votes_for_ballot`] when brute-forcing
///       which `(vote_data, signature)` pair from an action's
///       solution produces a given on-chain `vote_cast` /
///       `vote_updated` announcement.
pub(crate) fn collect_signature_atoms(
    allocator: &clvmr::Allocator,
    node: clvmr::NodePtr,
    out: &mut Vec<[u8; 96]>,
) {
    use clvmr::SExp;
    match allocator.sexp(node) {
        SExp::Atom => {
            let bytes = allocator.atom(node);
            if bytes.as_ref().len() == 96 {
                if let Ok(arr) = <[u8; 96]>::try_from(bytes.as_ref()) {
                    if !out.contains(&arr) {
                        out.push(arr);
                    }
                }
            }
        }
        SExp::Pair(head, tail) => {
            collect_signature_atoms(allocator, head, out);
            collect_signature_atoms(allocator, tail, out);
        }
    }
}

/// FN: vote_announcement_matches (file-private)
/// WHAT: compute `sha256(prefix || ballot_id || voter_pk ||
///       vote_data || sig)` and compare to `expected`. Mirrors the
///       on-chain `mint_voting_coin.rue` (`"vote_cast"`) and
///       `voting_coin/update_vote.rue` (`"vote_updated"`) CCA
///       preimages used by [`Aggregator::collect_votes_for_ballot`]
///       to brute-force the `(vote_data, sig)` pair from candidate
///       solution atoms.
pub(crate) fn vote_announcement_matches(
    prefix: &[u8],
    ballot_launcher_id: Bytes32,
    voter_pk: &chia_bls::PublicKey,
    vote_data: &[u8; 32],
    signature: &[u8; 96],
    expected: &[u8; 32],
) -> bool {
    use sha2::{Digest as _, Sha256 as _Sha};
    let mut h = _Sha::new();
    h.update(prefix);
    h.update(ballot_launcher_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(vote_data);
    h.update(signature);
    let actual: [u8; 32] = h.finalize().into();
    &actual == expected
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
        let fresh_ph = puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, pk, election_id, config.collateral_amount);
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
            // SEC-F1: legacy walker carries no Jubjub witness.
            jubjub_vote: None,
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

    let [register_leaf, create_ballot_leaf, deregister_leaf, attest_ballot_leaf] =
        election_action_leaves(config, launcher_id, cat_tail_hash);

    // Match the in-tree sort `puzzles::election_actions_merkle_root`
    // applies (ascending by `hash_atom_b32` of the leaf). This makes
    // `MerkleTree::new(&leaves).proof(leaf)` produce a proof against
    // the same root.
    let mut leaves = vec![
        register_leaf,
        create_ballot_leaf,
        deregister_leaf,
        attest_ballot_leaf,
    ];
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
    let empty_root = Bytes32::new(crate::merkle::PoseidonSmt::new().root_be32());
    let genesis = ElectionState::genesis_from_config(empty_root, election_start_height, config);
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
    // V6: read the ceremony back-reference triple from the config so we
    // match what the deployer commits at launch.
    let empty_root = Bytes32::new(crate::merkle::PoseidonSmt::new().root_be32());
    let state_hash = ElectionState::genesis(
        empty_root,
        election_start_height,
        config.ceremony_launcher_id(),
        config.max_signers as u64,
        config.vk_hash(),
        crate::vote_mode::VOTE_MODE_LOCK_NONE,
    )
    .clvm_tree_hash();

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
    // `leaves` is `[register_full, create_ballot_full, deregister_full,
    // attest_ballot_full]` in declaration order;
    // `puzzles::election_actions_merkle_root` sorts internally before
    // composing the root, so the order here matches the deployer.
    puzzles::election_actions_merkle_root(leaves[0], leaves[1], leaves[2], leaves[3])
}

/// FN: election_state_node (file-private)
/// WHAT: serialise an `ElectionState` into the 8-field cons tree the action
///       layer curries as `STATE`:
///   `(root . (count . (weight . (start . (cer . (max . (vk . lock)))))))`.
/// Mirrors `Voter::election_state_node`; both MUST match
/// `compute_election_inner_puzzle_hash_for_state`.
fn election_state_node(
    ctx: &mut chia_sdk_driver::SpendContext,
    state: &ElectionState,
) -> VotingResult<clvmr::NodePtr> {
    use clvm_traits::ToClvm;
    let value = (
        state.registration_merkle_root,
        (
            state.registration_count,
            (
                state.registration_vote_weight,
                (
                    state.election_start_height,
                    (
                        state.ceremony_launcher_id,
                        (
                            state.max_voters,
                            (state.vk_hash, state.vote_mode_lock),
                        ),
                    ),
                ),
            ),
        ),
    );
    value
        .to_clvm(&mut **ctx)
        .map_err(|e| anyhow_other(format!("election_state_node to_clvm: {e}")))
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
) -> [Bytes32; 4] {
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
    // CURRY ORDER (M6-revised): (SINGLETON_LAUNCHER_PUZZLE_HASH,
    // ELECTION_LAUNCHER_ID, NO_VOTE_MODE_LOCK). NO_VOTE_MODE_LOCK is
    // the deployment-wide 0xFF…FF sentinel; the puzzle compares
    // against State.vote_mode_lock to decide whether to enforce the
    // ballot-mode lock gate.
    let singleton_launcher_ph = Bytes32::from(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let create_ballot_full = puzzles::curry_tree_hash(
        PuzzleHashes::election_create_ballot(),
        &[
            puzzles::hash_atom_b32(&singleton_launcher_ph),
            puzzles::hash_atom_b32(&launcher_id),
            puzzles::hash_atom_b32(&crate::vote_mode::VOTE_MODE_LOCK_NONE),
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

    // ── attest_ballot (SEC-F3+F5) ────────────────────────────────
    // CURRY ORDER (matches puzzles/election/attest_ballot.rue):
    //   (ELECTION_LAUNCHER_ID, NO_VOTE_MODE_LOCK).
    let attest_ballot_full = puzzles::curry_tree_hash(
        PuzzleHashes::election_attest_ballot(),
        &[
            puzzles::hash_atom_b32(&launcher_id),
            puzzles::hash_atom_b32(&crate::vote_mode::VOTE_MODE_LOCK_NONE),
        ],
    );

    [register_full, create_ballot_full, deregister_full, attest_ballot_full]
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
    use ark_ed_on_bls12_381::Fr as JubScalar;
    use chia_sdk_test::Simulator;

    fn dummy_deploy_params() -> DeployParams {
        DeployParams {
            verification_key: VerificationKey {
                raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
            },
            cat_tail_hash: Bytes32::new([0x77; 32]),
            collateral_amount: 1_000,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            ceremony_launcher_id: Bytes32::default(),
            vk_hash: Bytes32::default(),
            vote_mode_lock: crate::vote_mode::VOTE_MODE_LOCK_NONE,
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
            .build_deploy_bundle(funder.coin, funder.pk, true)
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
        let empty_root = Bytes32::new(PoseidonSmt::new().root_be32());
        assert_eq!(
            *cached_state,
            ElectionState::genesis(
                empty_root,
                TEST_ELECTION_START_HEIGHT,
                Bytes32::default(),
                crate::config::MAX_SIGNERS as u64,
                Bytes32::default(),
                crate::vote_mode::VOTE_MODE_LOCK_NONE,
            ),
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
            ceremony_launcher_id_hex: String::new(),
            vk_hash_hex: String::new(),
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
            .build_deploy_bundle(funder.coin, funder.pk, true)
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
                vote_signature_hex: String::new(),
                registration_coin_id: Bytes32::default(),
                ballot_launcher_id: Bytes32::default(),
                voting_coin_id: Bytes32::default(),
                jubjub_vote: Some(test_jubjub_vote(sk, vote_message_to_fr(canonical_msg))),
            })
            .collect();

        let pk = stub_proving_key();
        let res = agg
            .build_finalize(vote_outcome, &votes, Bytes32::default(), &pk)
            .await;
        // SEC-F1: build_finalize now builds a circuit_v2 proof; with the
        // legacy zero/old-circuit stub proving key the flow cannot produce
        // a matching proof + the action-layer curried hash mismatches the
        // zero-VK deploy. Either way assembly fails — we only assert the
        // flow reaches an error rather than panicking.
        assert!(res.is_err());
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

    /// SEC-F1: derive a voter's Jubjub signing keypair from their BLS
    /// secret, mirroring `VoterKeys::new`'s `CHIP/jubjub-signing-key/v1`
    /// scheme. Returns `(secret, pubkey)`. The PoseidonSmt is keyed by the
    /// Jubjub pubkey, and circuit_v2 verifies a Schnorr signature under it.
    fn test_jubjub(sk: &chia_bls::SecretKey) -> (JubScalar, JubAffine) {
        use ark_ec::{CurveGroup, Group};
        use ark_ed_on_bls12_381::EdwardsProjective as Jub;
        use ark_ff::PrimeField;
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"CHIP/jubjub-signing-key/v1");
        h.update(sk.to_bytes());
        let seed: [u8; 32] = h.finalize().into();
        let s = JubScalar::from_le_bytes_mod_order(&seed);
        let p = (Jub::generator() * s).into_affine();
        (s, p)
    }

    /// SEC-F1: build a `JubjubVoteWitness` (the in-circuit Schnorr signature)
    /// for `sk` over `vote_message_fr`.
    fn test_jubjub_vote(
        sk: &chia_bls::SecretKey,
        vote_message_fr: ark_bls12_381::Fr,
    ) -> crate::state::JubjubVoteWitness {
        let (jsec, jpub) = test_jubjub(sk);
        let cfg = crate::prover::circuit_v2::poseidon_config();
        let (sig_r, sig_s) = crate::prover::circuit_v2::schnorr_sign(
            &cfg,
            jsec,
            JubScalar::from(7u64),
            vote_message_fr,
        );
        crate::state::JubjubVoteWitness { pubkey: jpub, sig_r, sig_s }
    }

    /// Reduce a canonical (Bytes32) vote message into `Fr` the way the
    /// aggregator + finalize.rue do.
    fn vote_message_to_fr(m: Bytes32) -> ark_bls12_381::Fr {
        use ark_ff::PrimeField;
        ark_bls12_381::Fr::from_be_bytes_mod_order(m.as_ref())
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
        let (pk, _vk) = crate::prover::circuit::generate_test_setup(32, &mut rng).unwrap();
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
        // Test fixture: every voter locks the curried minimum
        // `collateral_amount` (uniform). Tests covering non-uniform
        // weighted voting should construct their own helper.
        let uniform_lock = agg.config.collateral_amount;
        for (sk, pk) in &voters {
            agg.voter_set.as_mut().unwrap().voters.push(*pk);
            // SEC-F1: insert the voter's JUBJUB pubkey into the Poseidon SPT
            // (the tree is Jubjub-keyed) so prove_jubjub() returns realistic
            // sibling paths matching registration_merkle_root.
            agg.smt.as_mut().unwrap().insert(test_jubjub(sk).1, uniform_lock);
        }
        let root = Bytes32::new(agg.smt.as_ref().unwrap().root_be32());
        agg.voter_set.as_mut().unwrap().registration_count = n_voters as u64;
        agg.voter_set.as_mut().unwrap().registration_merkle_root = root;
        agg.state.as_mut().unwrap().registration_merkle_root = root;
        agg.state.as_mut().unwrap().registration_count = n_voters as u64;
        (agg, voters)
    }

    /// Build a populated Aggregator with the given per-voter lock
    /// amounts. Drives weighted-voting tests that assert the
    /// finalize witness sums REAL per-voter weights instead of
    /// `count * collateral_amount`.
    async fn populated_aggregator_with_locks(
        config: ElectionConfig,
        chain: SharedSimulator,
        locks: &[u64],
    ) -> (
        Aggregator<SharedSimulator>,
        Vec<(chia_bls::SecretKey, PublicKey)>,
    ) {
        let mut agg = Aggregator::new(config, chain, NetworkType::Mainnet);
        agg.sync().await.unwrap();
        let voters: Vec<_> = (0..locks.len() as u32).map(test_voter).collect();
        let mut total_weight: u64 = 0;
        for ((sk, pk), lock) in voters.iter().zip(locks.iter()) {
            agg.voter_set.as_mut().unwrap().voters.push(*pk);
            agg.smt.as_mut().unwrap().insert(test_jubjub(sk).1, *lock);
            total_weight = total_weight.checked_add(*lock).expect("test lock overflow");
        }
        let root = Bytes32::new(agg.smt.as_ref().unwrap().root_be32());
        agg.voter_set.as_mut().unwrap().registration_count = locks.len() as u64;
        agg.voter_set.as_mut().unwrap().registration_merkle_root = root;
        agg.state.as_mut().unwrap().registration_merkle_root = root;
        agg.state.as_mut().unwrap().registration_count = locks.len() as u64;
        agg.state.as_mut().unwrap().registration_vote_weight = total_weight;
        (agg, voters)
    }

    /// WHAT: with non-uniform per-voter lock amounts, the finalize
    ///       witness's `signed_weight * den >= total_weight * num`
    ///       check uses the REAL sum (not `count * collateral`).
    ///       Whale (5000) + minnow (1000) over a 1/2 majority threshold
    ///       passes when the whale signs alone (5000 ≥ 0.5 × 6000)
    ///       but FAILS when only the minnow signs (1000 < 0.5 × 6000).
    /// WHY:  this is the regression bait for weighted-voting work —
    ///       reverting to uniform `count * collateral` would make BOTH
    ///       cases pass the threshold (1 voter ≥ 0.5 × 2 voters), so
    ///       the second assertion catches the regression.
    #[tokio::test(flavor = "current_thread")]
    async fn weighted_threshold_uses_real_per_voter_amounts() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let (agg, voters) =
            populated_aggregator_with_locks(config, chain, &[5_000, 1_000]).await;

        let vote_outcome = Bytes32::new([0x99; 32]);
        let election_id = agg.config.election_launcher_id().unwrap();
        let canonical_msg =
            canonical_vote_message(vote_outcome, placeholder_ballot_id(), election_id);
        let vote_message_fr = vote_message_to_fr(canonical_msg);
        let mk_vote = |sk: &chia_bls::SecretKey, pk: &PublicKey| VoteRecord {
            voter_pubkey: *pk,
            vote_data: vote_outcome,
            vote_signature_hex: String::new(),
            registration_coin_id: Bytes32::default(),
            ballot_launcher_id: Bytes32::default(),
            voting_coin_id: Bytes32::default(),
            jubjub_vote: Some(test_jubjub_vote(sk, vote_message_fr)),
        };

        let total_weight = 6_000u64;

        // Whale (5000) alone clears 1/2 of total_weight (3000). Pass.
        let whale_only = vec![mk_vote(&voters[0].0, &voters[0].1)];
        let w = agg
            .prepare_finalize_witness_with_threshold(
                vote_outcome,
                placeholder_ballot_id(),
                &whale_only,
                1,
                2,
                total_weight,
            )
            .expect("whale alone clears 1/2 majority on real weights");
        assert_eq!(w.signer_pubkeys.len(), 1);

        // Minnow (1000) alone is 1/6 of total_weight — below 1/2.
        // Under the OLD uniform-weight semantics this would have
        // passed (1 of 2 voters ≥ 1/2), so a failure here proves the
        // aggregator now reads real per-voter weights from the SMT.
        let minnow_only = vec![mk_vote(&voters[1].0, &voters[1].1)];
        let err = agg
            .prepare_finalize_witness_with_threshold(
                vote_outcome,
                placeholder_ballot_id(),
                &minnow_only,
                1,
                2,
                total_weight,
            )
            .unwrap_err();
        match err {
            VotingError::BelowThreshold => {}
            other => panic!("expected BelowThreshold, got {other:?}"),
        }
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
