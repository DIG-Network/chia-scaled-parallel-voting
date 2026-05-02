// ============================================================================
// actors/voter.rs — single-voter spend driver
// ============================================================================
//
// MODULE: actors::voter
// PURPOSE: Stateful actor representing one voter. Owns:
//          * the voter's BLS keys
//          * the shared ElectionConfig
//          * the network type (selects mainnet/testnet AGG_SIG additional data)
//
// SUPPORTED FLOWS (CHIP rev 2026-05-02):
//   * register          — register-action spend on the Election
//                         Singleton. Mints a CAT-wrapped Registration
//                         Coin at the voter's predicted puzzle hash.
//                         No XCH fee output (fees were dropped in
//                         this revision).
//   * cast_vote         — STUB. Mints the per-(voter, ballot)
//                         Voting Coin via the Registration Coin's
//                         `mint_voting_coin` action. Full
//                         implementation lands in Phase 6 once the
//                         test infrastructure can drive a simulator
//                         end-to-end.
//   * update_vote       — STUB. Updates a Voting Coin's vote
//                         payload via its `update_vote` action,
//                         gated by the Ballot Coin oracle.
//   * release_collateral — STUB. Co-spends the Election Singleton's
//                         `deregister` action with the Registration
//                         Coin's `release` action, sending the CAT
//                         collateral to a destination chosen by the
//                         voter.
//
// SIGNING: every spend bundle is signed via the upstream
//   `dig_l1_wallet::transaction::sign_coin_spends`
//   → `chia_sdk_signer::RequiredSignature::from_coin_spends` chain.
//   That function walks every AGG_SIG condition, augments under the
//   configured network's `agg_sig_me_additional_data`, and produces
//   one aggregated BLS signature.
//
// CHIA-QUERY BRIDGE: the SDK uses `chia_protocol::Bytes32` everywhere,
//   but `chia_query` returns hex-encoded strings. `convert_coin` and
//   `parse_hex32` (file-private) bridge the two.

use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use dig_l1_wallet::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution,
    build_election_finalizer_full, build_singleton_spend, load_action_puzzle,
    ActionSpend,
};
use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles::{self, PuzzleHashes};

/// STRUCT: VoterKeys
/// PURPOSE: voter's BLS identity. Distinct from the wallet's standard
///          p2 / synthetic key — a voter MAY use any L1 wallet to fund
///          their registration.
/// IMMUTABLE: pubkey is derived from secret on construction; both
///            travel together for ergonomic signing.
pub struct VoterKeys {
    pub pubkey: PublicKey,
    pub secret: SecretKey,
}

impl VoterKeys {
    /// FN: new
    /// WHAT: build VoterKeys from a raw secret. Pubkey computed lazily.
    pub fn new(secret: SecretKey) -> Self {
        let pubkey = secret.public_key();
        Self { pubkey, secret }
    }

    /// FN: sign_unsafe
    /// WHAT: BLS-sign `message` verbatim — the same shape an on-chain
    ///       `AggSigUnsafe(VOTER_PUBKEY, vote_message)` condition
    ///       requires (no augmentation). Used for the per-(voter,
    ///       ballot) memo signature on the Voting Coin's
    ///       `update_vote` action (CHIP rev 2026-05-02).
    pub fn sign_unsafe(&self, message: &[u8]) -> Signature {
        chia_bls::sign_raw(&self.secret, message)
    }
}

/// STRUCT: Voter
/// PURPOSE: top-level voter actor.
/// FIELDS:
///   * config  — shared ElectionConfig
///   * keys    — voter BLS keys
///   * network — selects mainnet vs testnet AGG_SIG additional data
///
/// XCH/CAT funding is the CALLER's responsibility — they construct
/// any required CAT issuance / fee spends and pass them in (see
/// `Voter::register`'s `cat_parent_spend` parameter). Keeping the
/// actor wallet-free makes it network-agnostic + trivially
/// testable in a Simulator.
pub struct Voter {
    pub config: ElectionConfig,
    pub keys: VoterKeys,
    pub network: NetworkType,
}

/// STRUCT: CastVoteParams
/// PURPOSE: typed bundle for `Voter::cast_vote` arguments.
/// FIELDS:
///   * `ballot_launcher_id` — singleton launcher id of the Ballot
///     Coin this voter is voting on. Binds the Voting Coin to a
///     single ballot so the SPT slot in `voted_ballots_root`
///     can't be reused across ballots.
///   * `vote_data` — the 32-byte payload the voter is committing
///     to. Typically `sha256(application-specific outcome)`. Sent
///     as a memo on the Voting Coin so the off-chain aggregator
///     can read it back without re-running the puzzle.
pub struct CastVoteParams {
    pub ballot_launcher_id: Bytes32,
    pub vote_data: Bytes32,
}

/// STRUCT: CastVoteResult
/// PURPOSE: outputs from `Voter::cast_vote`.
/// FIELDS:
///   * `voting_coin_id` — coin id of the freshly-minted Voting Coin.
///     Stable for any subsequent `update_vote` / aggregator lookup.
///   * `spend_bundle` — fully-signed spend bundle pushable to the
///     mempool.
///   * `vote_signature` — BLS signature over the canonical
///     vote-message (`puzzles::vote_message(vote_data,
///     ballot_launcher_id, election_launcher_id)`) using
///     `sign_unsafe`. Written into the Voting Coin's memos; the
///     off-chain aggregator BLS-aggregates these per-ballot to
///     produce the finalize witness.
pub struct CastVoteResult {
    pub voting_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
    pub vote_signature: chia_protocol::Bytes,
}

impl Voter {
    pub fn new(config: ElectionConfig, keys: VoterKeys, network: NetworkType) -> Self {
        Self { config, keys, network }
    }

    /// FN: slot
    /// WHAT: this voter's canonical SPT slot.
    /// FORMULA: `u32::from_be_bytes(sha256(pubkey)[0..4])` — see
    ///          `SparseMerkleTree::slot_for_pubkey`.
    pub fn slot(&self) -> u32 {
        crate::merkle::SparseMerkleTree::slot_for_pubkey(&self.keys.pubkey)
    }

    /// FN: registration_coin_puzzle_hash
    /// WHAT: the CAT-wrapped puzzle hash this voter's Registration
    ///       Coin will land on.
    /// USAGE:
    ///   * voter pre-funds the right amount into this puzzle hash
    ///   * aggregator/indexer use it as a filter against
    ///     `chain.get_coin_records_by_hint`
    pub fn registration_coin_puzzle_hash(&self) -> VotingResult<Bytes32> {
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        Ok(puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
        ))
    }

    /// FN: voter_hint
    /// WHAT: stable coin-state hint for tracking this voter's
    ///       Registration Coin lineage across mint_voting_coin /
    ///       release spends.
    /// USAGE: `chain.get_coin_records_by_hint(voter_hint_hex(), ..)`.
    pub fn voter_hint(&self) -> VotingResult<Bytes32> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        Ok(puzzles::voter_hint(election_id, cat_tail_hash, &self.keys.pubkey))
    }

    /// FN: voter_hint_hex
    /// WHAT: `0x`-prefixed hex form of `voter_hint` — the wire shape
    ///       the `chia-query` HTTP API expects.
    pub fn voter_hint_hex(&self) -> VotingResult<String> {
        Ok(format!("0x{}", hex::encode(self.voter_hint()?)))
    }

    /// Build a registration spend bundle.
    ///
    /// The full implementation composes:
    ///
    ///   1. **CAT collateral spend** — the caller pre-builds a CAT
    ///      issuance / spend that creates the Registration Coin at
    ///      its expected puzzle hash with `COLLATERAL_AMOUNT`. The
    ///      CAT spend's inner conditions emit the `create_reg`
    ///      `CreateCoinAnnouncement` that the Election Singleton's
    ///      register action asserts.
    ///   2. **Election Singleton spend** — wraps the action layer
    ///      with the `register` action selected. The action's
    ///      solution carries `(new_voter_pubkey, register_leaf_index,
    ///      register_siblings, ...cat_parent_coin_id)`.
    ///
    /// Per CHIP rev 2026-05-02 there is **no XCH registration fee**;
    /// callers that want to attach a fee output build it externally.
    ///
    /// Final signing uses [`sign_bundle_signature`], which calls
    /// `RequiredSignature::from_coin_spends` to walk every AGG_SIG_*
    /// condition (the voter's `AggSigMe(VOTER_PUBKEY,
    /// registration_message)`).
    pub async fn register<C: ChainReader>(
        &self,
        smt: &crate::merkle::SparseMerkleTree,
        cat_parent_spend: CoinSpend,
        chain: &C,
    ) -> VotingResult<SpendBundle> {
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::CurriedProgram;

        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;

        // ── 1. Find the current Election Singleton ──────────────
        // After CHIP rev 2026-05-02 the launcher walker requires an
        // `election_start_height` to predict the eve singleton's
        // puzzle hash for the fast path. Pass 0 here — the slow
        // path (`coin_records_by_parent_ids`) succeeds regardless,
        // and the eve fast path only matters before any singleton
        // spend has confirmed (in which case
        // `ElectionState::genesis(_, 0)` matches the deployer's
        // default in [`Aggregator::new`]).
        let election_start_height: u64 = 0;
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            election_start_height,
            "Election Singleton (launcher lineage)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        let crate::actors::aggregator::CurrentSingleton {
            coin: singleton_coin,
            lineage_proof: singleton_lineage_proof,
            state: on_chain_state,
            ..
        } = current;

        // ── 2. Build the action layer's outer puzzle ────────────
        let mut ctx = SpendContext::new();
        let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id)?;
        let merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&self.config);
        // Inner puzzle MUST match what's curried into the singleton
        // on-chain (`on_chain_state` from the launcher lineage walk).
        if on_chain_state.registration_merkle_root != smt.root() {
            return Err(voting_other(format!(
                "Voter::register: aggregator SMT root {} does not match on-chain {} — re-sync",
                hex::encode(smt.root()),
                hex::encode(on_chain_state.registration_merkle_root),
            )));
        }
        let election_state_node = self.election_state_node(&mut ctx, &on_chain_state)?;
        let action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            elect_finalizer,
            merkle_root,
            election_state_node,
        )?;

        // ── 3. Build the curried register action puzzle ─────────
        // CURRY ORDER (post-CHIP rev 2026-05-02):
        //   (TREE_DEPTH, EMPTY_LEAF_HASH, CAT_MOD_HASH, CAT_TAIL_HASH,
        //    ACTION_LAYER_MOD_HASH, REGISTRATION_FINALIZER_MOD_HASH,
        //    REGISTRATION_MERKLE_ROOT, COLLATERAL_AMOUNT,
        //    ELECTION_LAUNCHER_ID, EMPTY_BALLOT_ROOT)
        // (No `registration_fee` — fees were dropped in this revision.)
        let register_program_node =
            load_action_puzzle(&mut ctx, puzzles::ELECTION_REGISTER_HEX)?;
        let register_curried = CurriedProgram {
            program: register_program_node,
            args: clvm_curried_args!(
                crate::config::TREE_DEPTH,
                Bytes32::new(crate::config::EMPTY_LEAF_HASH),
                PuzzleHashes::cat_outer(),
                cat_tail_hash,
                PuzzleHashes::action_layer(),
                PuzzleHashes::registration_finalizer(),
                puzzles::registration_actions_merkle_root(),
                self.config.collateral_amount,
                election_id,
                puzzles::empty_ballot_root()
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // ── 4. Build the register action solution ───────────────
        // Solution shape (per register.rue):
        //   (new_voter_pubkey, register_leaf_index, register_siblings,
        //    ...cat_parent_coin_id)
        //
        // SLOT ENCODING: register.rue's `slot_from_pubkey` builds
        //   `0x00 || sha256(pk)[0..4]` and casts to Int. We pass the
        //   slot as the EXACT 5-byte sequence the puzzle constructs
        //   so `==` always succeeds regardless of the slot's value.
        let slot = self.slot();
        let siblings = smt.prove(slot);
        let voter_pk_bytes = chia_protocol::Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let cat_parent_coin_id = cat_parent_spend.coin.coin_id();
        let slot_bytes = {
            let mut buf = Vec::with_capacity(5);
            buf.push(0x00);
            buf.extend_from_slice(&slot.to_be_bytes());
            chia_protocol::Bytes::new(buf)
        };
        let register_solution_value = (
            voter_pk_bytes,
            (slot_bytes, (siblings, cat_parent_coin_id)),
        );
        let register_solution = register_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let action_spends = vec![ActionSpend {
            puzzle: register_curried,
            solution: register_solution,
        }];
        // Election finalizer takes `..._my_solution: Any` — pass nil.
        let elect_finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &crate::actors::aggregator::compute_election_action_root_leaves(&self.config),
            &action_spends,
            elect_finalizer_solution,
        )?;

        // ── 5. Wrap with the singleton outer ────────────────────
        let register_singleton_spend = build_singleton_spend(
            &mut ctx,
            singleton_coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            singleton_lineage_proof,
        )?;

        // ── 6. Sign + bundle ────────────────────────────────────
        // Voter's AggSigMe over the registration message
        // (sha256("register" || pk || election_id)) is automatically
        // collected from the emitted condition by
        // RequiredSignature::from_coin_spends.
        let coin_spends = vec![cat_parent_spend, register_singleton_spend];
        // Pre-flight: dry-run every coin spend's puzzle so a CLVM
        // `raise` surfaces with the EXACT coin id that failed,
        // instead of being buried inside the signer's opaque
        // "sign_coin_spends failed: clvm raise" error message.
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            // Dump the failing bundle to a file so the operator can
            // re-run individual coin spends through `clvm` /
            // `cdv` / a debugger to diagnose the trap.
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "voter-register-failed-{}.json",
                    chrono_compat_now()
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
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
            return Err(voting_other(format!("Voter::register dry-run: {e:?}")));
        }
        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Build a `cast_vote` spend bundle.
    ///
    /// **STUB — full implementation deferred to Phase 6.**
    ///
    /// The eventual flow (per CHIP rev 2026-05-02):
    ///   1. Locate the voter's current Registration Coin via
    ///      `voter_hint`.
    ///   2. Drive the Registration Coin's `mint_voting_coin` action,
    ///      whose solution carries the SPT proof for the ballot's
    ///      slot in `voted_ballots_root` plus the Ballot Coin
    ///      oracle's `open` announcement (proves the ballot is
    ///      still open at this height).
    ///   3. Mint the singleton-style Voting Coin at
    ///      `puzzles::voting_coin_state_tree_hash(...)`'s
    ///      predicted puzzle hash, hinted by
    ///      `puzzles::voting_coin_hint(...)`.
    ///   4. Sign the voter's AggSigMe over the canonical
    ///      `puzzles::vote_message(vote_data, ballot_launcher_id,
    ///      election_launcher_id)`.
    pub async fn cast_vote<C: ChainReader>(
        &self,
        _chain: &C,
        _params: CastVoteParams,
    ) -> VotingResult<CastVoteResult> {
        Err(VotingError::Other(anyhow_compat::Error(
            "Voter::cast_vote stubbed pending Phase 6 (voting coin lineage)".into(),
        )))
    }

    /// Build an `update_vote` spend bundle.
    ///
    /// **STUB — full implementation deferred to Phase 6.**
    ///
    /// The eventual flow (per CHIP rev 2026-05-02):
    ///   1. Locate the voter's current Voting Coin via
    ///      `voting_coin_hint(election_id, cat_tail, pk,
    ///      ballot_launcher_id)`.
    ///   2. Drive the Voting Coin's `update_vote` action. Its
    ///      solution must include the Ballot Coin oracle's `open`
    ///      announcement and a fresh AggSigMe from the voter over
    ///      the new vote payload.
    ///   3. Recreate the Voting Coin at the updated state with the
    ///      new memo signature.
    ///
    /// **Importantly: NO singleton co-spend.** The Voting Coin's
    /// own oracle binding to the Ballot Coin replaces the legacy
    /// Election Singleton oracle action (which was deleted in
    /// commit `9e79ddd`).
    pub async fn update_vote<C: ChainReader>(
        &self,
        _chain: &C,
        _voting_coin_id: Bytes32,
        _new_vote_data: Bytes32,
    ) -> VotingResult<SpendBundle> {
        Err(VotingError::Other(anyhow_compat::Error(
            "Voter::update_vote stubbed pending Phase 6".into(),
        )))
    }

    /// Build a collateral release spend bundle.
    ///
    /// **STUB — full implementation deferred to Phase 6.**
    ///
    /// The eventual flow (per CHIP rev 2026-05-02):
    ///   1. Co-spend the Election Singleton's `deregister` action,
    ///      which announces `puzzles::deregister_announcement_msg(
    ///      voter_pubkey)` and decrements
    ///      `(registration_count, registration_vote_weight)`.
    ///   2. Spend the voter's Registration Coin (located by
    ///      `voter_hint`) via its `release` action; the action
    ///      asserts the singleton's `deregister` announcement,
    ///      emits AggSigMe over the release message, and sends
    ///      the CAT collateral to `destination`.
    ///
    /// The legacy `announce_finalization` action no longer exists
    /// (per-ballot finalization moved to the Ballot Coin); the
    /// release spend is gated entirely on `deregister`.
    pub async fn release_collateral<C: ChainReader>(
        &self,
        _chain: &C,
        _registration_coin_id: Bytes32,
        _destination: Bytes32,
    ) -> VotingResult<SpendBundle> {
        Err(VotingError::Other(anyhow_compat::Error(
            "Voter::release_collateral stubbed pending Phase 6".into(),
        )))
    }

    // ── Internal helpers for spend assembly ─────────────────────

    /// Reconstruct the CAT lineage proof for `cat_coin` by parsing
    /// its parent's actual on-chain spend.
    ///
    /// Salvaged from the pre-CHIP rev 2026-05-02 implementation —
    /// kept here for the eventual Phase 6 implementations of
    /// `cast_vote` / `update_vote` / `release_collateral`, all of
    /// which still need to derive a CAT lineage proof from the
    /// parent spend.
    #[allow(dead_code)]
    async fn reconstruct_cat_lineage<C: ChainReader>(
        &self,
        chain: &C,
        cat_coin: Coin,
    ) -> VotingResult<Option<chia_puzzle_types::LineageProof>> {
        use chia_sdk_driver::{Cat as DriverCat, Puzzle};
        use clvm_traits::ToClvm;
        use clvmr::Allocator;

        let parent_id = cat_coin.parent_coin_info;
        let parent_record = chain
            .coin_record_by_id(parent_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::reconstruct_cat_lineage: parent coin {} not found on chain",
                    hex::encode(parent_id),
                ))
            })?;
        let (puzzle_program, solution_program) = chain
            .puzzle_and_solution(parent_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::reconstruct_cat_lineage: parent coin {} is unspent — \
                     cannot derive lineage proof until it has been spent",
                    hex::encode(parent_id),
                ))
            })?;

        let mut allocator = Allocator::new();
        let parent_puzzle_node = puzzle_program
            .to_clvm(&mut allocator)
            .map_err(|e| voting_other(format!(
                "reconstruct_cat_lineage: parent puzzle to_clvm: {e}",
            )))?;
        let parent_solution_node = solution_program
            .to_clvm(&mut allocator)
            .map_err(|e| voting_other(format!(
                "reconstruct_cat_lineage: parent solution to_clvm: {e}",
            )))?;
        let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);

        let children = DriverCat::parse_children(
            &mut allocator,
            parent_record.coin,
            parent_puzzle,
            parent_solution_node,
        )
        .map_err(|e| voting_other(format!(
            "reconstruct_cat_lineage: Cat::parse_children failed for parent {}: {e:?}",
            hex::encode(parent_id),
        )))?
        .ok_or_else(|| {
            voting_other(format!(
                "reconstruct_cat_lineage: parent coin {} is not a CAT spend — \
                 unexpected on this voter's lineage",
                hex::encode(parent_id),
            ))
        })?;

        let target_id = cat_coin.coin_id();
        let child = children
            .into_iter()
            .find(|c| c.coin.coin_id() == target_id)
            .ok_or_else(|| {
                voting_other(format!(
                    "reconstruct_cat_lineage: child coin {} not found among CAT children of parent {}",
                    hex::encode(target_id),
                    hex::encode(parent_id),
                ))
            })?;

        Ok(child.lineage_proof)
    }

    /// Build the ElectionState CLVM tree node.
    ///
    /// SHAPE: matches the post-CHIP rev 2026-05-02 layout from
    /// `puzzles/election/shared.rue`:
    ///   `(root . (count . (vote_weight . election_start_height)))`
    /// — `election_start_height` is the trailing tail (a `u64`
    /// directly), NOT wrapped in `(_ . NIL)`. The deployer's
    /// `genesis_state_tree_hash` predicts the puzzle hash assuming
    /// this exact shape; an extra NIL terminator here would make
    /// the action layer's curried state-hash diverge from the
    /// launcher's commitment and the singleton outer would reject
    /// every spend.
    fn election_state_node(
        &self,
        ctx: &mut SpendContext,
        state: &crate::state::ElectionState,
    ) -> VotingResult<clvmr::NodePtr> {
        let value = (
            state.registration_merkle_root,
            (
                state.registration_count,
                (
                    state.registration_vote_weight,
                    state.election_start_height,
                ),
            ),
        );
        value.to_clvm(&mut **ctx).map_err(driver_err)
    }

    /// Sign a list of coin spends using the recommended upstream
    /// `RequiredSignature::from_coin_spends` chain. The signing pool
    /// includes both the wallet's payment key and this voter's secret
    /// — so any combination of `AggSigMe(wallet_pk, ...)` and
    /// `AggSigMe(voter_pk, ...)` / `AggSigUnsafe(voter_pk, ...)`
    /// conditions in the bundle gets signed automatically.
    pub fn sign_with_voter_and_wallet_keys(
        &self,
        coin_spends: &[CoinSpend],
        wallet_sk: &SecretKey,
    ) -> VotingResult<Signature> {
        sign_bundle_signature(
            coin_spends,
            &[self.keys.secret.clone(), wallet_sk.clone()],
            self.network,
        )
    }

    /// The bare release message — `AggSigMe` augmentation is computed
    /// by `RequiredSignature::from_coin_spends` at signing time.
    ///
    /// SHAPE: `sha256("release" || election_id || pubkey || destination)`.
    /// The post-CHIP rev 2026-05-02 release flow keeps the same
    /// preimage shape; only the gating (Ballot Coin oracle vs the
    /// singleton's deregister announcement) changed.
    pub fn release_message(&self, destination: Bytes32) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let election_id = self.config.election_launcher_id().expect("config validated");
        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(self.keys.pubkey.to_bytes());
        h.update(destination.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        Bytes32::new(arr)
    }
}

/// FN: voting_other (file-private)
/// WHAT: shorthand for `VotingError::Other` with a string message.
fn voting_other(msg: impl Into<String>) -> VotingError {
    VotingError::Other(anyhow_compat::Error(msg.into().into()))
}

/// Tiny helper that returns a filename-safe ISO-8601-ish timestamp
/// without pulling chrono into the SDK (we already use it in CLI).
fn chrono_compat_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// FN: driver_err (file-private)
/// WHAT: shorthand for converting a chia_sdk_driver / clvm_traits
///       error into a VotingError.
fn driver_err<E: std::fmt::Debug>(e: E) -> VotingError {
    voting_other(format!("clvm/driver: {e:?}"))
}

/// FN: convert_coin
/// WHAT: bridge a `chia_query::Coin` (hex-encoded JSON shape) to a
///       canonical `chia_protocol::Coin`.
/// USAGE: chain-walk paths that consume `chain.get_coin_records_by_hint`
///        results and feed them into `chia_sdk_driver::Cat::parse_children`.
/// ACCEPTS: both `0x`-prefixed and bare hex strings (chia-query has
///          historically been inconsistent about this).
pub fn convert_coin(c: &chia_query::Coin) -> VotingResult<chia_protocol::Coin> {
    let parent_coin_info = parse_hex32(&c.parent_coin_info)?;
    let puzzle_hash = parse_hex32(&c.puzzle_hash)?;
    Ok(chia_protocol::Coin::new(parent_coin_info, puzzle_hash, c.amount))
}

/// FN: parse_hex32 (file-private)
/// WHAT: parse a hex string (with or without `0x` prefix) into a
///       `Bytes32`. Returns `VotingError::Other` on malformed input
///       so callers can propagate without unwrapping.
fn parse_hex32(s: &str) -> VotingResult<Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
            "hex decode {s}: {e}").into())))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(format!("expected 32 bytes from {s}").into()))
    })?;
    Ok(Bytes32::new(arr))
}

// ============================================================================
// Tests
// ============================================================================
//
// These tests exercise the synchronous, pure helpers — message
// derivation, hint computation, coin conversion. The `register`,
// `cast_vote`, `update_vote`, and `release_collateral` async methods
// need a Simulator and live in the integration tests once Phase 6
// stands up.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey as Sk};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    fn test_voter_pk() -> PublicKey {
        let root = Sk::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root.public_key(), 0).derive_synthetic()
    }

    fn good_config() -> ElectionConfig {
        ElectionConfig {
            election_launcher_id_hex: "11".repeat(32),
            cat_tail_hash_hex: "22".repeat(32),
            collateral_amount: 1_000,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: "00".repeat(
                336 + (crate::config::PUBLIC_INPUT_COUNT + 1) * 48,
            ),
            label: None,
        }
    }

    fn voter_keys() -> VoterKeys {
        // A deterministic test voter SK + matching pk derived the same
        // way `test_voter_pk` would derive — but for this test the SK
        // is only used to verify VoterKeys::new copies pubkey through
        // correctly, not that it matches `test_voter_pk`.
        let sk = Sk::from_seed(&[0u8; 32]);
        VoterKeys::new(sk)
    }

    /// WHAT: `VoterKeys::new(sk)` stores the pubkey derived from
    ///       `sk` (so `keys.pubkey == sk.public_key()`).
    /// HOW:  build VoterKeys from a deterministic seed, compare
    ///       `pubkey` to a direct derivation.
    /// WHY:  every signing path assumes the bundled pubkey IS the
    ///       one that the secret signs against. A drift here would
    ///       mean signatures verify against a key the SDK never
    ///       reports.
    #[test]
    fn voter_keys_pubkey_matches_secret() {
        let v = voter_keys();
        assert_eq!(v.pubkey, v.secret.public_key());
    }

    /// WHAT: `release_message(destination)` equals
    ///       `sha256("release" || election_id || pubkey || destination)`
    ///       byte-exact.
    /// HOW:  hand-compute the sha256 inline against the same inputs,
    ///       compare.
    /// WHY:  the on-chain release action emits an
    ///       `AggSigMe(VOTER_PUBKEY, release_message)` and any drift
    ///       would prevent the voter from ever reclaiming their CAT
    ///       collateral.
    #[test]
    fn release_message_is_deterministic_and_correct() {
        let _voter_pk = test_voter_pk();
        let _config = good_config();
        // Reproduce the formula independently and compare against
        // the public helper.
        let voter = Voter {
            config: good_config(),
            keys: voter_keys(),
            network: NetworkType::Testnet11,
        };
        let election_id = voter.config.election_launcher_id().unwrap();
        let destination = Bytes32::new([0xCC; 32]);

        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(voter.keys.pubkey.to_bytes());
        h.update(destination.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let expected = Bytes32::new(arr);

        assert_eq!(voter.release_message(destination), expected);
    }

    /// WHAT: `puzzles::vote_message(outcome, ballot_id, election_id)`
    ///       is byte-identical to `sha256(outcome || ballot_id ||
    ///       election_id)`.
    /// HOW:  hand-compute the sha256 inline and compare.
    /// WHY:  the on-chain Voting Coin's `update_vote` action emits
    ///       an `AggSigUnsafe(VOTER_PUBKEY, vote_message)` over
    ///       these exact bytes. Any drift would mean voter
    ///       signatures can't be verified on-chain or aggregated
    ///       off-chain.
    #[test]
    fn vote_message_three_arg_form_is_deterministic_and_correct() {
        let outcome = Bytes32::new([0x42; 32]);
        let ballot_id = Bytes32::new([0xAB; 32]);
        let election_id = Bytes32::new([0x11; 32]);

        let mut h = Sha256::new();
        h.update(outcome.as_ref());
        h.update(ballot_id.as_ref());
        h.update(election_id.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let expected = Bytes32::new(arr);

        assert_eq!(
            puzzles::vote_message(outcome, ballot_id, election_id),
            expected
        );
    }

    /// WHAT: signing `puzzles::vote_message(...)` with
    ///       `sign_unsafe` (== unaugmented `chia_bls::sign_raw`)
    ///       produces a signature that satisfies the textbook
    ///       PoP-style BLS aggregate pairing identity
    ///         e(pk, H(msg)) == e(G1_GENERATOR, sig).
    /// HOW:  build a deterministic voter, compute the canonical
    ///       message via the public helper, sign it with
    ///       `sign_unsafe`, hash the message to G2 via
    ///       `chia_bls::hash_to_g2` (default DST), and call
    ///       `chia_bls::aggregate_pairing` with the two (G1, G2)
    ///       pairs the on-chain identity expects.
    /// WHY:  pins that the SDK is on the unaugmented (sign_raw /
    ///       sign_unsafe) path — switching to augmented `sign()`
    ///       would silently break the off-chain aggregator's BLS
    ///       sum (the pre-CHIP-rev mainnet symptom).
    #[test]
    fn voter_canonical_signature_pop_pairing_verifies() {
        use chia_bls::{hash_to_g2, PublicKey as Pk};
        let v = voter_keys();
        let outcome = Bytes32::new([0xA5; 32]);
        let ballot_id = Bytes32::new([0xBB; 32]);
        let election_id = Bytes32::new([0x77; 32]);
        let msg = puzzles::vote_message(outcome, ballot_id, election_id);

        // Voter side: sign UNAUGMENTED.
        let sig = v.sign_unsafe(msg.as_ref());

        // On-chain side: e(pk, H(msg)) * e(-G1_GENERATOR, sig) == 1
        let h_msg = hash_to_g2(msg.as_ref());
        let neg_g1 = -Pk::generator();
        assert!(
            chia_bls::aggregate_pairing([(&v.pubkey, &h_msg), (&neg_g1, &sig)]),
            "unaugmented sign_raw signature must satisfy the PoP-style \
             single-pair pairing identity (mirrors finalize.rue on-chain check)",
        );

        // And for safety: the AUGMENTED variant (chia_bls::sign)
        // must NOT satisfy this identity — the two schemes are
        // mutually exclusive.
        let aug_sig = chia_bls::sign(&v.secret, msg.as_ref());
        assert!(
            !chia_bls::aggregate_pairing([(&v.pubkey, &h_msg), (&neg_g1, &aug_sig)]),
            "augmented sign() output must NOT satisfy the PoP-style identity — \
             pins that the SDK is on the unaugmented (sign_raw / sign_unsafe) path",
        );
    }

    /// WHAT: `convert_coin` correctly parses `0x`-prefixed hex
    ///       strings into `Bytes32` fields.
    /// HOW:  build a `chia_query::Coin` with `0x11..11` /
    ///       `0x22..22`, convert, assert the resulting
    ///       `chia_protocol::Coin` carries the expected bytes.
    /// WHY:  `chia-query` JSON responses use `0x`-prefixed hex; if
    ///       the prefix were treated as data, every hash would be
    ///       off by 2 bytes and silently corrupt downstream lookups.
    #[test]
    fn convert_coin_accepts_0x_prefix() {
        let qc = chia_query::Coin {
            parent_coin_info: format!("0x{}", "11".repeat(32)),
            puzzle_hash: format!("0x{}", "22".repeat(32)),
            amount: 1_000,
        };
        let pc = convert_coin(&qc).unwrap();
        assert_eq!(pc.parent_coin_info, Bytes32::new([0x11; 32]));
        assert_eq!(pc.puzzle_hash, Bytes32::new([0x22; 32]));
        assert_eq!(pc.amount, 1_000);
    }

    /// WHAT: `convert_coin` also accepts bare (no-prefix) hex
    ///       strings.
    /// HOW:  build a coin with bare hex, convert, assert the
    ///       amount round-trips (smoke test for the bare path).
    /// WHY:  some `chia-query` versions / endpoints have shipped
    ///       responses without the `0x` prefix. Tolerating both
    ///       avoids a brittle dependency on remote behaviour.
    #[test]
    fn convert_coin_accepts_bare_hex() {
        let qc = chia_query::Coin {
            parent_coin_info: "11".repeat(32),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        let pc = convert_coin(&qc).unwrap();
        assert_eq!(pc.amount, 5);
    }

    /// WHAT: `convert_coin` returns an error for non-hex input.
    /// HOW:  pass `parent_coin_info = "not-hex"`, expect an Err.
    /// WHY:  a malformed coin from a remote peer must surface as a
    ///       typed error rather than panic or silent garbage data.
    #[test]
    fn convert_coin_rejects_bad_hex() {
        let qc = chia_query::Coin {
            parent_coin_info: "not-hex".into(),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        assert!(convert_coin(&qc).is_err());
    }

    /// WHAT: `convert_coin` returns an error if any hash hex is the
    ///       wrong length (≠ 32 bytes).
    /// HOW:  use a 32-char (16-byte) parent_coin_info, expect Err.
    /// WHY:  hex-decode succeeds but the result is the wrong size
    ///       for `Bytes32`. Catching it explicitly avoids a generic
    ///       panic deep in `try_into`.
    #[test]
    fn convert_coin_rejects_short_hash() {
        let qc = chia_query::Coin {
            parent_coin_info: "11".repeat(16),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        assert!(convert_coin(&qc).is_err());
    }
}
