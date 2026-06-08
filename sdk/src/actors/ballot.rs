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
// IMPLEMENTATION STATUS: BallotIssuer::create_ballot, ::launch_ballot
//   and BallotReader's per-ballot accessors are fully implemented and
//   proven end-to-end. Coverage:
//     * sdk/tests/create_ballot_e2e.rs / launch_ballot_e2e.rs (simulator)
//     * sdk/tests/ballot_reader_e2e.rs (simulator)
//     * cli/src/bin/live_integration_test.rs run #11 (mainnet)
//   The on-chain ballot lineage walker reused inside BallotReader walks
//   the full singleton-launcher → eve-Ballot-Coin → recreated lineage,
//   matching the mainnet behavior already exercised.

use chia_protocol::{Bytes32, SpendBundle};
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use clvm_utils::CurriedProgram;
use clvmr::NodePtr;
use crate::config::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_ballot_finalizer_full,
    build_election_finalizer_full, build_singleton_spend, load_action_puzzle, ActionSpend,
};
use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles;
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
    /// M7e: 32-byte vote-mode commitment for the new Ballot Coin.
    /// `Bytes32::default()` (= 0x00…00) means Mode1Free (no
    /// restriction on vote_data); any other value is a sorted-options
    /// merkle root the Ballot Coin's oracle will commit to and
    /// `update_vote` will require a matching merkle proof for. The
    /// election's `State.vote_mode_lock` gates which values are
    /// accepted (sentinel `VOTE_MODE_LOCK_NONE = 0xFF…FF` allows
    /// any; otherwise the value must match the lock byte-for-byte).
    pub vote_options_root: Bytes32,
}

/// STRUCT: LaunchBallotParams
/// PURPOSE: typed bundle for [`BallotIssuer::launch_ballot`]
///          arguments. Holds the per-ballot config that gets curried
///          into the eve Ballot Coin's action puzzles (and
///          consequently into its full singleton-wrapped puzzle hash).
/// FIELDS:
///   * `vote_close_height` — block height at which the ballot stops
///     accepting vote edits. Curried into both the `finalize` action
///     (as a time lock) and the `oracle` action (so co-spends can
///     pin the canonical close height). Must match the
///     `vote_close_height` carried by the original
///     `BallotIssuer::create_ballot` announcement.
///   * `outcome_domain_hash` — 32-byte commitment to the allowed
///     outcome set. Currently informational at launch time
///     (off-chain consumers correlate it via the create_ballot
///     announcement); reserved here for forward compatibility with
///     future on-chain enforcement.
///   * `vote_threshold_num` / `vote_threshold_den` — numerator /
///     denominator of the per-ballot quorum threshold. Curried into
///     the `finalize` action so the on-chain threshold check binds
///     to the values committed at launch. Note: not present in
///     `ElectionConfig` today (threshold is per-ballot, not
///     per-election), so the operator passes them at launch.
#[derive(Clone, Debug)]
pub struct LaunchBallotParams {
    pub vote_close_height: u64,
    pub outcome_domain_hash: Bytes32,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    /// M7e: 32-byte vote-mode commitment curried into the eve Ballot
    /// Coin's oracle action. MUST equal the value passed in the
    /// matching `CreateBallotParams.vote_options_root` so the predicted
    /// ballot puzzle hash matches what `create_ballot` minted.
    /// `Bytes32::default()` (= 0x00…00) for Mode1Free; otherwise a
    /// sorted-options merkle root for Mode2Restricted.
    pub vote_options_root: Bytes32,
}

/// STRUCT: LaunchedBallot
/// PURPOSE: outputs from [`BallotIssuer::launch_ballot`].
/// FIELDS:
///   * `ballot_launcher_id` — singleton launcher id (= the input
///     `launcher_coin_id`). Echoed for caller convenience so they
///     don't have to thread the value through.
///   * `eve_ballot_coin_id` — coin id of the eve Ballot Coin
///     singleton instantiated by the launcher second-spend. Useful
///     for ledger-side tracking until the lineage advances.
///   * `eve_ballot_puzzle_hash` — full singleton-wrapped puzzle hash
///     of the eve Ballot Coin. The launcher second-spend mints a
///     coin at exactly this puzzle hash; aggregator/indexer code
///     can lookup this hash to find the eve Ballot Coin on chain.
///   * `spend_bundle` — fully-signed bundle pushable to the mempool
///     by the caller. Per the SDK's no-broadcast rule the issuer
///     NEVER pushes the bundle itself.
#[derive(Clone, Debug)]
pub struct LaunchedBallot {
    pub ballot_launcher_id: Bytes32,
    pub eve_ballot_coin_id: Bytes32,
    pub eve_ballot_puzzle_hash: Bytes32,
    pub spend_bundle: SpendBundle,
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
    /// See [`crate::actors::Voter::election_start_height`] — same
    /// invariant: every launcher-lineage walk inside this issuer's
    /// methods needs the deployer's curried start height. Defaults to
    /// 0 for back-compat; set via [`BallotIssuer::with_election_start_height`].
    pub election_start_height: u64,
}

impl BallotIssuer {
    /// FN: new
    /// WHAT: construct from a validated config + network.
    pub fn new(config: ElectionConfig, network: NetworkType) -> Self {
        Self {
            config,
            network,
            election_start_height: 0,
        }
    }

    /// Bind the deployer's curried `election_start_height` so the
    /// launcher-lineage walker (used by `create_ballot` /
    /// `launch_ballot`) computes the correct eve singleton puzzle hash.
    pub fn with_election_start_height(mut self, h: u64) -> Self {
        self.election_start_height = h;
        self
    }

    /// Build a `createBallot` spend bundle.
    ///
    /// FLOW (CHIP rev 2026-05-02):
    ///   1. Locate the current Election Singleton via the launcher
    ///      lineage walker (same path as `Voter::register`).
    ///   2. Build the curried `create_ballot` action puzzle whose
    ///      hash is `puzzles::ELECTION_CREATE_BALLOT_HASH_HEX`
    ///      curried with `(SINGLETON_LAUNCHER_PUZZLE_HASH,
    ///      ELECTION_LAUNCHER_ID)` — same shape the deployer uses
    ///      to compute the action's full hash.
    ///   3. Build the action solution
    ///      `(singleton_coin_id, ballot_seed, vote_close_height,
    ///       outcome_domain_hash)`. The trailing `...outcome_domain_hash`
    ///      Rue field is a flat tail (no nil terminator).
    ///   4. Wrap with the action layer + singleton outer (mirrors
    ///      `Voter::register`).
    ///   5. Sign with the operator's wallet keys (the create_ballot
    ///      action itself emits no AggSig conditions, but the
    ///      singleton outer's standard layer may require one — the
    ///      signer auto-walks every emitted AggSig condition).
    ///
    /// LAUNCHER FOLLOW-UP: per the CHIP migration plan we emit
    /// **only the createBallot singleton spend** here. The launcher
    /// eve coin minted by this spend (parent = singleton coin id,
    /// puzzle = `SINGLETON_LAUNCHER_PUZZLE_HASH`, amount = 2) needs
    /// a second spend through the standard launcher puzzle to mint
    /// the actual Ballot Coin singleton instance — that follow-up
    /// requires the full deployment-wide ballot curries (VK, IC,
    /// threshold pack, BALLOT_ACTIONS_MERKLE_ROOT) and is the
    /// caller's responsibility (or a subsequent Phase 6 task). The
    /// returned `ballot_launcher_id` (= eve coin id) is stable and
    /// usable today.
    ///
    /// `ballot_coin_id` returned here is the **eve coin id** (the
    /// 2-mojo launcher coin minted by this spend). When the caller
    /// later spends that launcher through `SINGLETON_LAUNCHER`, the
    /// resulting Ballot Coin singleton will have parent =
    /// eve_coin_id; until then the eve coin id is what's actually
    /// observable on chain after this spend.
    ///
    /// FUNDER COIN: the launcher eve coin must be minted at an even
    /// amount (2) so the Election Singleton's outer puzzle does not
    /// mistake it for the singleton's own recreation (which would
    /// raise via the standard top-layer's
    /// `(assert (not has_odd_output_been_found))`). The Election
    /// Singleton itself only carries 1 mojo — exactly enough to
    /// recreate itself — so the 2 mojos for the launcher MUST come
    /// from a co-spent funder coin. The caller pre-builds that
    /// funder spend (any coin spending ≥ 2 mojos with output total
    /// = its amount − 2; the simplest is a quoted-conditions puzzle
    /// returning `()` over a 2-mojo coin) and passes it in
    /// `funder_spend`. Mirrors the `Voter::register` pattern of
    /// taking a pre-built `cat_parent_spend`.
    pub async fn create_ballot<C: ChainReader>(
        &self,
        chain: &C,
        params: CreateBallotParams,
        funder_spend: chia_protocol::CoinSpend,
    ) -> VotingResult<CreatedBallot> {
        use chia_puzzles::SINGLETON_LAUNCHER_HASH;
        use clvm_traits::clvm_curried_args;

        let election_id = self.config.election_launcher_id().map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("election_launcher_id: {e}").into(),
            ))
        })?;

        // ── 1. Find the current Election Singleton ──────────────
        // Same launcher lineage walker `Voter::register` uses.
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            self.election_start_height,
            "Election Singleton (create_ballot)",
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

        let singleton_coin_id = singleton_coin.coin_id();

        // ── 2. Build the action layer puzzle ────────────────────
        let mut ctx = SpendContext::new();
        let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id)?;
        let merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&self.config);
        let election_state_node = state_node_for(&mut ctx, &on_chain_state)?;
        let action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            elect_finalizer,
            merkle_root,
            election_state_node,
        )?;

        // ── 3. Build the curried create_ballot action puzzle ────
        // CURRY ORDER (per `puzzles/election/create_ballot.rue`,
        // M6-revised): (SINGLETON_LAUNCHER_PUZZLE_HASH,
        // ELECTION_LAUNCHER_ID, NO_VOTE_MODE_LOCK)
        // NO_VOTE_MODE_LOCK is the 32-byte 0xFF…FF sentinel the
        // puzzle compares against State.vote_mode_lock to decide
        // whether the lock gate runs. Same constant in every
        // deployment — currying it ensures puzzle-side bytewise
        // comparison without needing a magic literal in the .rue.
        let singleton_launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
        let no_vote_mode_lock = crate::vote_mode::VOTE_MODE_LOCK_NONE;
        let create_ballot_program_node =
            load_action_puzzle(&mut ctx, puzzles::ELECTION_CREATE_BALLOT_HEX)?;
        let create_ballot_curried = CurriedProgram {
            program: create_ballot_program_node,
            args: clvm_curried_args!(singleton_launcher_ph, election_id, no_vote_mode_lock),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // ── 4. Build the create_ballot action solution ──────────
        // SOLUTION SHAPE per `create_ballot.rue` (M6-revised — after
        // the curried `Truth: ElectionStateTruth` arg the action layer
        // prepends automatically):
        //   `(singleton_coin_id, ballot_seed, vote_close_height,
        //    outcome_domain_hash, ...ballot_vote_options_root)`
        // Rue's trailing `...ballot_vote_options_root: Bytes32` produces
        // a flat-tail cons chain — the cdr of the last cons IS the
        // 32-byte hash directly (no NIL terminator).
        // M7e: thread the caller-supplied per-ballot vote_options_root
        // through. Sentinel 0x00…00 = Mode1Free; otherwise a sorted-
        // options merkle root the Ballot Coin's oracle will commit to.
        let ballot_vote_options_root: Bytes32 = params.vote_options_root;
        let create_ballot_solution_value = (
            singleton_coin_id,
            (
                params.ballot_seed,
                (
                    params.vote_close_height,
                    (params.outcome_domain_hash, ballot_vote_options_root),
                ),
            ),
        );
        let create_ballot_solution = create_ballot_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        // Sanity: the runtime tree hash of our curried action puzzle
        // must match the leaf produced by
        // `compute_election_action_root_leaves`. Surfaces curry-order
        // / atom-wrap drift early instead of as an opaque CLVM raise.
        let runtime_leaf =
            Bytes32::new(clvm_utils::tree_hash(&ctx, create_ballot_curried).to_bytes());
        let predicted_leaves =
            crate::actors::aggregator::compute_election_action_root_leaves(&self.config);
        if !predicted_leaves.contains(&runtime_leaf) {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!(
                    "BallotIssuer::create_ballot: runtime curry hash {} not in \
                     predicted leaves {:?}",
                    hex::encode(runtime_leaf),
                    predicted_leaves.iter().map(hex::encode).collect::<Vec<_>>(),
                )
                .into(),
            )));
        }

        let action_spends = vec![ActionSpend {
            puzzle: create_ballot_curried,
            solution: create_ballot_solution,
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
        let create_ballot_singleton_spend = build_singleton_spend(
            &mut ctx,
            singleton_coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            singleton_lineage_proof,
        )?;

        // ── 6. Compute the eve coin id (= ballot_launcher_id) ───
        // Mirror of `create_ballot.rue`'s formula:
        //   eve_coin_id = sha256(singleton_coin_id ||
        //                        SINGLETON_LAUNCHER_PUZZLE_HASH ||
        //                        int_to_8_bytes_be(2))
        // i.e., the standard Chia coin id for a child coin with
        // parent = singleton_coin_id, puzzle_hash = launcher_ph,
        // amount = 2. The launcher coin is minted at the EVEN amount 2
        // (not the conventional 1) so the singleton outer's
        // single-odd-CreateCoin invariant is preserved — the finalizer
        // already emits one odd CreateCoin (the singleton recreation),
        // and a second odd CreateCoin from this action would trigger
        // the singleton's `(assert (not has_odd_output_been_found))`.
        let eve_coin = chia_protocol::Coin::new(singleton_coin_id, singleton_launcher_ph, 2);
        let eve_coin_id = eve_coin.coin_id();

        // ── 7. Sign + bundle ────────────────────────────────────
        // The createBallot action emits no AggSig conditions of its
        // own. The Election Singleton's outer puzzle may emit one
        // (the standard layer is unsynthetised here — the singleton
        // puzzle is just the singleton wrapper around the action
        // layer, no operator key required for the inner spend). Pass
        // an empty key set; `sign_bundle_signature` returns a
        // zero-aggregate when there are no `AggSigMe` requirements.
        // Bundle: funder + singleton spend. The funder provides the
        // 2 mojos needed for the launcher eve coin; the singleton
        // contributes 1 (its own recreation amount) and emits both
        // CreateCoins. Total: 3 in / 3 out (assuming funder spends
        // exactly 2 mojos with no outputs).
        let coin_spends = vec![funder_spend, create_ballot_singleton_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            // Dump the failing spend so the operator can replay it through
            // the CLVM debugger if needed.
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "create_ballot-failed-{}.json",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
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
            return Err(VotingError::Other(anyhow_compat::Error(
                format!("BallotIssuer::create_ballot dry-run: {e:?}").into(),
            )));
        }
        let signature = sign_bundle_signature(&coin_spends, &[], self.network)?;
        let spend_bundle = SpendBundle::new(coin_spends, signature);

        Ok(CreatedBallot {
            ballot_launcher_id: eve_coin_id,
            ballot_coin_id: eve_coin_id,
            spend_bundle,
        })
    }

    /// FN: launch_ballot
    /// WHAT: build the launcher SECOND-spend for a Ballot Coin —
    ///       i.e., the spend that consumes the 2-mojo launcher eve
    ///       coin minted by [`BallotIssuer::create_ballot`] and mints
    ///       the actual eve Ballot Coin singleton at amount 1 (odd, so
    ///       it satisfies the singleton outer's parity invariant).
    /// FLOW:
    ///   1. Look up the launcher coin on chain by its id (parent =
    ///      Election Singleton at create_ballot time, ph =
    ///      `SINGLETON_LAUNCHER_HASH`, amount = 2).
    ///   2. Snapshot the current Election Singleton state so the
    ///      ballot's `finalize` action can later enforce the
    ///      registration-set the ballot was launched against.
    ///   3. Curry each Ballot Coin action with its per-ballot args:
    ///        * `finalize` ← (VK, IC, BALLOT_LAUNCHER_ID,
    ///          ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT,
    ///          VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN,
    ///          REGISTRATION_MERKLE_ROOT_SNAPSHOT,
    ///          REGISTRATION_VOTE_WEIGHT_SNAPSHOT)
    ///        * `oracle` ← (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT)
    ///        * `announce_finalization` ← (BALLOT_LAUNCHER_ID)
    ///      and tree-hash each to produce the per-ballot leaf set.
    ///   4. Compute the per-ballot ballot actions Merkle root.
    ///   5. Build the Ballot finalizer (1st curry: ACTION_LAYER_MOD,
    ///      HINT=ballot_launcher_id; 2nd curry: self-hash) and the
    ///      action layer puzzle (FINALIZER, MERKLE_ROOT,
    ///      `BallotState::fresh()`). Tree-hash → ballot inner ph.
    ///   6. Compute the eve Ballot Coin's full singleton-wrapped
    ///      puzzle hash via `SingletonArgs::curry_tree_hash(
    ///      launcher_id=launcher_coin_id, inner_ph)`.
    ///   7. Build the launcher CoinSpend with solution
    ///      `(eve_full_ph, 1, ())`: the chia-puzzles 0.20.x launcher
    ///      lacks `ASSERT_MY_AMOUNT`, so the caller chooses the eve
    ///      singleton's amount independent of the launcher's 2-mojo
    ///      input. Setting it to 1 keeps the eve singleton odd (the
    ///      remaining 1 mojo becomes implicit fee).
    ///   8. Sign + bundle. The launcher emits no AGG_SIG conditions,
    ///      so the signature aggregates to the zero point.
    ///
    /// NETWORK FETCH: walks the on-chain singleton lineage to
    /// snapshot `(registration_merkle_root, registration_vote_weight)`
    /// at launch time. The snapshot becomes a curry arg of the
    /// per-ballot `finalize` action, so changing the snapshot after
    /// launch would change the eve Ballot Coin's puzzle hash — the
    /// ballot is permanently bound to the registration state at the
    /// instant `launch_ballot` reads it.
    pub async fn launch_ballot<C: ChainReader>(
        &self,
        chain: &C,
        launcher_coin_id: Bytes32,
        params: LaunchBallotParams,
    ) -> VotingResult<LaunchedBallot> {
        use chia_protocol::{Coin, CoinSpend, Program};
        use chia_puzzle_types::singleton::SingletonArgs;
        use chia_puzzles::{SINGLETON_LAUNCHER, SINGLETON_LAUNCHER_HASH};
        use clvm_traits::clvm_curried_args;
        use clvm_utils::TreeHash;

        let election_id = self.config.election_launcher_id().map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("election_launcher_id: {e}").into(),
            ))
        })?;

        // ── 1. Look up the launcher coin ────────────────────────
        let launcher_record = chain
            .coin_record_by_id(launcher_coin_id)
            .await?
            .ok_or_else(|| {
                VotingError::Other(anyhow_compat::Error(
                    format!(
                        "BallotIssuer::launch_ballot: launcher coin {} not found on chain",
                        hex::encode(launcher_coin_id),
                    )
                    .into(),
                ))
            })?;
        let launcher_coin = launcher_record.coin;
        let launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
        if launcher_coin.puzzle_hash != launcher_ph {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!(
                    "BallotIssuer::launch_ballot: launcher coin puzzle_hash mismatch \
                     (got {}, expected SINGLETON_LAUNCHER_HASH {})",
                    hex::encode(launcher_coin.puzzle_hash),
                    hex::encode(launcher_ph),
                )
                .into(),
            )));
        }
        if launcher_coin.amount != 2 {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!(
                    "BallotIssuer::launch_ballot: launcher coin amount must be 2 \
                     (got {}); see create_ballot.rue's even-amount-launcher rule",
                    launcher_coin.amount,
                )
                .into(),
            )));
        }

        // ── 2. Snapshot current Election Singleton state ────────
        // Walk the lineage to find the latest Election Singleton; the
        // resulting (registration_merkle_root, registration_vote_weight)
        // get curried into the per-ballot `finalize` action so the
        // ballot is permanently bound to the registration state at
        // launch time.
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            self.election_start_height,
            "Election Singleton (launch_ballot)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        let registration_merkle_root_snapshot = current.state.registration_merkle_root;
        let registration_vote_weight_snapshot = current.state.registration_vote_weight;

        // ── 3. Per-ballot fully-curried action hashes ───────────
        let mut ctx = SpendContext::new();

        // VK + IC: derived from the deployment's verification key.
        // These end up as opaque CLVM cons trees curried into the
        // `finalize` action; the `finalize` puzzle never runs in
        // launch_ballot (the eve Ballot Coin is just minted, not
        // spent), but the curry must still be canonical so the
        // predicted puzzle hash matches the eventual on-chain hash.
        let (vk_node, ic_node) = build_vk_ic_nodes(&mut ctx, &self.config)?;

        // finalize curry order MUST match the parameter order at the
        // top of `puzzles/ballot_coin/finalize.rue`:
        //   (VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID,
        //    VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM,
        //    VOTE_THRESHOLD_DEN, REGISTRATION_MERKLE_ROOT_SNAPSHOT,
        //    REGISTRATION_VOTE_WEIGHT_SNAPSHOT, ELECTION_VK_HASH,
        //    VOTE_OPTIONS_ROOT)
        // SEC-F3+F5: ELECTION_VK_HASH (= the deployment's committed vk_hash)
        // and VOTE_OPTIONS_ROOT are curried so the ballot's finalize can bind
        // them to the genuine election via the attest_ballot message.
        let finalize_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_FINALIZE_HEX)?;
        let finalize_curried = CurriedProgram {
            program: finalize_program_node,
            args: clvm_curried_args!(
                vk_node,
                ic_node,
                launcher_coin_id,
                election_id,
                params.vote_close_height,
                params.vote_threshold_num,
                params.vote_threshold_den,
                registration_merkle_root_snapshot,
                registration_vote_weight_snapshot,
                self.config.vk_hash(),
                params.vote_options_root,
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let finalize_full_hash =
            Bytes32::new(clvm_utils::tree_hash(&ctx, finalize_curried).to_bytes());

        // oracle curry order (per `puzzles/ballot_coin/oracle.rue`,
        // M4-revised): (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT,
        // VOTE_OPTIONS_ROOT). M7e: thread the caller-supplied per-ballot
        // value (via LaunchBallotParams).
        let vote_options_root_curry: Bytes32 = params.vote_options_root;
        let oracle_program_node = load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ORACLE_HEX)?;
        let oracle_curried = CurriedProgram {
            program: oracle_program_node,
            args: clvm_curried_args!(
                launcher_coin_id,
                params.vote_close_height,
                vote_options_root_curry
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let oracle_full_hash = Bytes32::new(clvm_utils::tree_hash(&ctx, oracle_curried).to_bytes());

        // announce_finalization curry order (per `announce_finalization.rue`):
        //   (BALLOT_LAUNCHER_ID)
        let announce_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX)?;
        let announce_curried = CurriedProgram {
            program: announce_program_node,
            args: clvm_curried_args!(launcher_coin_id),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let announce_full_hash =
            Bytes32::new(clvm_utils::tree_hash(&ctx, announce_curried).to_bytes());

        // ── 4. Per-ballot ballot_actions_merkle_root ────────────
        let ballot_actions_root = puzzles::per_ballot_actions_merkle_root(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );

        // ── 5. Build the eve Ballot Coin's inner action layer ───
        let ballot_finalizer_node = build_ballot_finalizer_full(&mut ctx, launcher_coin_id)?;

        // BallotState::fresh() on the wire: 3 fields with `...` rest-arg
        // on the last. Cons shape: (false . (zero . zero)) — i.e.,
        // last cons's cdr IS `agg_signers` directly (no NIL terminator).
        // Rust encoding mirrors that with `((), (vote_outcome, agg_signers))`.
        let fresh_state_value: ((), (Bytes32, Bytes32)) =
            ((), (Bytes32::default(), Bytes32::default()));
        let initial_state_node = fresh_state_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let inner_node = build_action_layer_puzzle(
            &mut ctx,
            ballot_finalizer_node,
            ballot_actions_root,
            initial_state_node,
        )?;
        let inner_ph = Bytes32::new(clvm_utils::tree_hash(&ctx, inner_node).to_bytes());

        // ── 6. Eve Ballot Coin's full singleton-wrapped PH ──────
        let inner_th = TreeHash::new(inner_ph.to_bytes());
        let singleton_full_th = SingletonArgs::curry_tree_hash(launcher_coin_id, inner_th);
        let eve_ballot_puzzle_hash = Bytes32::new(singleton_full_th.to_bytes());

        // ── 7. Launcher second-spend ─────────────────────────────
        // Standard chia singleton launcher (chia-puzzles 0.20.x) has
        // NO ASSERT_MY_AMOUNT, so the launcher's solution `amount`
        // is independent of the launcher coin's actual mojos. We
        // mint the eve Ballot Coin at amount 1 (odd, so the singleton
        // outer's parity check passes when later spent); the
        // remaining 1 mojo from the 2-mojo launcher coin becomes
        // implicit fee.
        const EVE_BALLOT_AMOUNT: u64 = 1;
        // Launcher solution shape (per chia-puzzles
        // `singleton_launcher.clsp`): `(singleton_full_puzzle_hash
        // amount key_value_list)` — a 3-element proper list. We use
        // `chia_puzzle_types::singleton::LauncherSolution`'s
        // `#[clvm(list)]` derive to produce the canonical
        // nil-terminated CLVM list shape (the launcher's `mod`
        // expects exactly that).
        use chia_puzzle_types::singleton::LauncherSolution;
        // Commit the per-ballot curry params on-chain via the launcher
        // second-spend's `key_value_list` (Option A: chain-readable
        // curry). Any reader can fetch the launcher's
        // puzzle_and_solution + parse the memo to recover the curry —
        // no off-chain metadata required. Mirrors the order curried
        // into the `finalize` action puzzle.
        let curry_memo = crate::state::BallotLauncherMemo {
            schema_tag: chia_protocol::Bytes::new(
                crate::state::BALLOT_LAUNCHER_MEMO_TAG.to_vec(),
            ),
            vote_close_height: params.vote_close_height,
            outcome_domain_hash: params.outcome_domain_hash,
            vote_threshold_num: params.vote_threshold_num,
            vote_threshold_den: params.vote_threshold_den,
            registration_merkle_root_snapshot,
            registration_vote_weight_snapshot,
            // M8: per-ballot vote-mode commitment so cross-browser
            // dApps can recover the ballot's mode from chain alone.
            vote_options_root: params.vote_options_root,
        };
        let launcher_solution = LauncherSolution {
            singleton_puzzle_hash: eve_ballot_puzzle_hash,
            amount: EVE_BALLOT_AMOUNT,
            key_value_list: curry_memo,
        };
        let launcher_solution_node = launcher_solution
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let launcher_program = Program::from(SINGLETON_LAUNCHER.to_vec());

        let launcher_solution_bytes =
            clvmr::serde::node_to_bytes(&ctx, launcher_solution_node).map_err(|e| {
                VotingError::Other(anyhow_compat::Error(
                    format!("serializing launcher solution: {e}").into(),
                ))
            })?;
        let launcher_spend = CoinSpend::new(
            launcher_coin,
            launcher_program,
            Program::from(launcher_solution_bytes),
        );

        // ── 8. Eve Ballot Coin's coin id ─────────────────────────
        let eve_ballot_coin = Coin::new(launcher_coin_id, eve_ballot_puzzle_hash, EVE_BALLOT_AMOUNT);
        let eve_ballot_coin_id = eve_ballot_coin.coin_id();

        // ── 9. Sign + bundle ─────────────────────────────────────
        // Standard launcher emits no AGG_SIG; signature aggregates to
        // the zero element when `secret_keys` is empty.
        let coin_spends = vec![launcher_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!("BallotIssuer::launch_ballot dry-run: {e:?}").into(),
            )));
        }
        let signature = sign_bundle_signature(&coin_spends, &[], self.network)?;
        let spend_bundle = SpendBundle::new(coin_spends, signature);

        Ok(LaunchedBallot {
            ballot_launcher_id: launcher_coin_id,
            eve_ballot_coin_id,
            eve_ballot_puzzle_hash,
            spend_bundle,
        })
    }
}

/// FN: build_vk_ic_nodes (file-private)
/// WHAT: parse the deployment's `verification_key_hex` (768 bytes
///       under the 8-input CHIP rev) into the on-chain `VK` + `IC`
///       cons trees expected by `puzzles/ballot_coin/finalize.rue`.
/// LAYOUT:
///   * VK (336 bytes): alpha (PublicKey, 48) + beta (Signature, 96)
///     + gamma (Signature, 96) + delta (Signature, 96).
///     Encoded as a 4-field struct WITHOUT `...` → cons shape
///     `(alpha . (beta . (gamma . (delta . ()))))`.
///   * IC (`(PUBLIC_INPUT_COUNT + 1) * 48` bytes = 432 bytes for 8
///     inputs): 9 G1 points × 48 bytes each. Encoded as a 9-field
///     struct WITHOUT `...` → cons shape
///     `(ic0 . (ic1 . ... (ic8 . ())))`.
/// MIRROR: the rest-arg-less Rue struct encoding is what
///         `clvm_traits` produces for nil-terminated nested tuples /
///         `Vec`. We use `Vec<Bytes>::to_clvm` for both the VK list
///         (4 entries) and the IC list (`PUBLIC_INPUT_COUNT + 1`
///         entries).
pub(crate) fn build_vk_ic_nodes(
    ctx: &mut SpendContext,
    config: &ElectionConfig,
) -> VotingResult<(NodePtr, NodePtr)> {
    use chia_protocol::Bytes;

    let ic_count = crate::config::PUBLIC_INPUT_COUNT + 1;
    let vk_bytes = hex::decode(config.verification_key_hex.trim()).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("decoding verification_key_hex: {e}").into(),
        ))
    })?;
    let expected = 336 + ic_count * 48;
    if vk_bytes.len() != expected {
        return Err(VotingError::Other(anyhow_compat::Error(
            format!(
                "verification_key has {} bytes; expected {} (336 base + {} IC * 48)",
                vk_bytes.len(),
                expected,
                ic_count,
            )
            .into(),
        )));
    }

    let alpha = Bytes::new(vk_bytes[0..48].to_vec());
    let beta = Bytes::new(vk_bytes[48..144].to_vec());
    let gamma = Bytes::new(vk_bytes[144..240].to_vec());
    let delta = Bytes::new(vk_bytes[240..336].to_vec());
    let vk_fields: Vec<Bytes> = vec![alpha, beta, gamma, delta];
    let vk_node = vk_fields.to_clvm(&mut **ctx).map_err(driver_err)?;

    let mut ic_fields: Vec<Bytes> = Vec::with_capacity(ic_count);
    for i in 0..ic_count {
        let start = 336 + i * 48;
        ic_fields.push(Bytes::new(vk_bytes[start..start + 48].to_vec()));
    }
    let ic_node = ic_fields.to_clvm(&mut **ctx).map_err(driver_err)?;

    Ok((vk_node, ic_node))
}

/// Build the `ElectionState` CLVM node — must match the
/// `(root . (count . (vote_weight . election_start_height)))` shape
/// the on-chain action layer expects (the trailing field is a
/// `u64` directly, NOT wrapped in `(_ . NIL)`).
fn state_node_for(
    ctx: &mut SpendContext,
    state: &crate::state::ElectionState,
) -> VotingResult<clvmr::NodePtr> {
    // M2: 8-field cons tree
    // (root . (count . (weight . (start . (cer . (max . (vk . lock))))))).
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
    value.to_clvm(&mut **ctx).map_err(driver_err)
}

/// FN: driver_err (file-private)
fn driver_err<E: std::fmt::Debug>(e: E) -> VotingError {
    VotingError::Other(anyhow_compat::Error(
        format!("clvm/driver: {e:?}").into(),
    ))
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
pub struct BallotReader<C: ChainReader> {
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
    /// Delegates to [`list_ballots_via_chain`].
    pub async fn list_ballots(&self) -> VotingResult<Vec<BallotCoinSnapshot>> {
        list_ballots_via_chain(&self.config, &self.chain).await
    }

    /// FN: get_ballot
    /// Delegates to [`get_ballot_via_chain`].
    pub async fn get_ballot(
        &self,
        ballot_launcher_id: Bytes32,
    ) -> VotingResult<Option<BallotCoinSnapshot>> {
        get_ballot_via_chain(&self.config, &self.chain, ballot_launcher_id).await
    }
}

/// FN: list_ballots_via_chain
/// WHAT: enumerate every Ballot Coin (or its launcher eve coin still
///       awaiting a second-spend) associated with `config` by walking
///       the Election Singleton lineage on `chain`.
/// IMPL: walk launcher → eve → child → … → tip. At each spent
///       singleton, list its children and collect any that landed at
///       `SINGLETON_LAUNCHER_HASH` with amount 2 — those are the
///       ballot launcher eve coins minted by `createBallot`. Their
///       coin id IS the canonical `ballot_launcher_id`.
/// PER-BALLOT FIELDS: until the caller runs the launcher second-spend
///       that mints the actual Ballot Coin singleton, per-ballot
///       curried fields (`vote_close_height`, `outcome_domain_hash`)
///       and on-chain `BallotState` are NOT yet committed. For now
///       this walker reports `vote_close_height: 0`,
///       `outcome_domain_hash: zero`, and `BallotState::fresh()` for
///       every entry. Once the Ballot Coin singleton is on-chain
///       (post launcher second-spend), populating these fields is a
///       follow-up (parse the eve Ballot Coin's curried args / latest
///       state from chain). The `ballot_launcher_id` is stable and
///       authoritative today.
/// USAGE: shared by `BallotReader::list_ballots` (owns a chain) and
///        `Indexer::ballots` (borrows its chain).
pub async fn list_ballots_via_chain<C: ChainReader>(
    config: &ElectionConfig,
    chain: &C,
) -> VotingResult<Vec<BallotCoinSnapshot>> {
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;

    let election_id = config.election_launcher_id().map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("election_launcher_id: {e}").into(),
        ))
    })?;
    let launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);

    let mut snapshots: Vec<BallotCoinSnapshot> = Vec::new();

    // Step 1: locate the eve singleton (any odd-amount child of the
    // launcher coin).
    let eve_children = chain.coin_records_by_parent_ids(&[election_id]).await?;
    let mut current = match eve_children.into_iter().find(|r| r.coin.amount % 2 == 1) {
        Some(eve) => eve,
        None => return Ok(snapshots), // election not deployed
    };

    // Step 2: walk the singleton lineage. At each step, fetch children
    // of the current coin and split them: odd-amount → next singleton,
    // amount 2 + launcher_ph → ballot launcher.
    loop {
        let coin_id = current.coin.coin_id();
        let children = chain.coin_records_by_parent_ids(&[coin_id]).await?;

        let mut next_singleton: Option<crate::chain::ChainCoinRecord> = None;
        for child in children.into_iter() {
            if child.coin.puzzle_hash == launcher_ph && child.coin.amount == 2 {
                let ballot_launcher_id = child.coin.coin_id();
                let memo = read_ballot_launcher_memo(chain, ballot_launcher_id).await?;
                let (state, latest_coin_id) =
                    walk_ballot_state_via_chain(chain, ballot_launcher_id).await?;
                snapshots.push(build_ballot_snapshot(
                    ballot_launcher_id,
                    election_id,
                    memo,
                    state,
                    latest_coin_id,
                ));
            } else if child.coin.amount % 2 == 1 {
                next_singleton = Some(child);
            }
        }

        match next_singleton {
            Some(next) if !next.is_unspent() => {
                current = next;
                continue;
            }
            Some(_) | None => break,
        }
    }

    Ok(snapshots)
}

/// FN: get_ballot_via_chain
/// WHAT: direct point-lookup of a Ballot Coin by `ballot_launcher_id`.
/// RETURNS: `Ok(None)` if no ballot with that launcher id exists under
///          `config`; `Ok(Some(snapshot))` otherwise.
/// USAGE: shared by `BallotReader::get_ballot` and `Indexer::ballot_state`.
pub async fn get_ballot_via_chain<C: ChainReader>(
    config: &ElectionConfig,
    chain: &C,
    ballot_launcher_id: Bytes32,
) -> VotingResult<Option<BallotCoinSnapshot>> {
    use chia_puzzles::SINGLETON_LAUNCHER_HASH;

    let launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
    let election_id = config.election_launcher_id().map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("election_launcher_id: {e}").into(),
        ))
    })?;

    let record = match chain.coin_record_by_id(ballot_launcher_id).await? {
        Some(r) => r,
        None => return Ok(None),
    };

    if record.coin.puzzle_hash != launcher_ph || record.coin.amount != 2 {
        return Ok(None);
    }

    let memo = read_ballot_launcher_memo(chain, ballot_launcher_id).await?;
    let (state, latest_coin_id) =
        walk_ballot_state_via_chain(chain, ballot_launcher_id).await?;
    Ok(Some(build_ballot_snapshot(
        ballot_launcher_id,
        election_id,
        memo,
        state,
        latest_coin_id,
    )))
}

/// FN: build_ballot_snapshot
/// WHAT: assemble a `BallotCoinSnapshot` from a known ballot launcher
///       id + the optional curry memo recovered from the launcher's
///       second-spend + the chain-derived latest state and singleton
///       coin id.
/// WHY:  shared by `list_ballots_via_chain` + `get_ballot_via_chain`
///       so the two construction sites stay in lockstep on the
///       memo-merge + state-walk logic.
fn build_ballot_snapshot(
    ballot_launcher_id: Bytes32,
    election_id: Bytes32,
    memo: Option<crate::state::BallotLauncherMemo>,
    state: crate::state::BallotState,
    latest_coin_id: Bytes32,
) -> BallotCoinSnapshot {
    let (
        vote_close_height,
        outcome_domain_hash,
        vote_threshold_num,
        vote_threshold_den,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        vote_options_root,
    ) = match memo {
        Some(m) => (
            m.vote_close_height,
            m.outcome_domain_hash,
            Some(m.vote_threshold_num),
            Some(m.vote_threshold_den),
            Some(m.registration_merkle_root_snapshot),
            Some(m.registration_vote_weight_snapshot),
            Some(m.vote_options_root),
        ),
        None => (0u64, Bytes32::default(), None, None, None, None, None),
    };
    BallotCoinSnapshot {
        ballot_launcher_id,
        election_launcher_id: election_id,
        vote_close_height,
        outcome_domain_hash,
        state,
        coin_id: latest_coin_id,
        vote_threshold_num,
        vote_threshold_den,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
        vote_options_root,
    }
}

/// FN: walk_ballot_state_via_chain
/// WHAT: walk a ballot's singleton lineage from launcher → latest, and
///       derive the current `BallotState` (finalized / vote_outcome /
///       agg_signers) directly from chain. Returns `(state,
///       latest_coin_id)`.
/// HOW:  the eve Ballot Coin is minted with `BallotState::fresh()`
///       curried into its action_layer, so its puzzle_hash IS the
///       fresh-state ph by construction. Because the only state-
///       mutating action in the protocol is `finalize`, ANY divergence
///       between the latest singleton's puzzle_hash and the eve's
///       puzzle_hash means finalize ran somewhere in the lineage. The
///       finalize spend itself is the parent of the post-finalize
///       coin (the first coin in the lineage with a non-fresh ph);
///       parsing its inner_solution via `extract_finalize_outcome`
///       recovers `vote_outcome` directly from the action's solution.
async fn walk_ballot_state_via_chain<C: ChainReader>(
    chain: &C,
    ballot_launcher_id: Bytes32,
) -> VotingResult<(crate::state::BallotState, Bytes32)> {
    let launcher_children = chain
        .coin_records_by_parent_ids(&[ballot_launcher_id])
        .await?;
    let eve = match launcher_children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
    {
        Some(eve) => eve,
        None => {
            // Launcher unspent / no eve yet → ballot not fully launched.
            return Ok((crate::state::BallotState::fresh(), ballot_launcher_id));
        }
    };
    let fresh_ph = eve.coin.puzzle_hash;
    // Track the parent of the post-finalize coin (= the finalize spend).
    // Walk forward; record `prev` so when we find a coin with a
    // non-fresh ph, we know its parent is the finalize spent coin.
    let mut prev: Option<crate::chain::ChainCoinRecord> = None;
    let mut current = eve;
    let mut finalize_spent_coin_id: Option<Bytes32> = None;
    loop {
        if current.coin.puzzle_hash != fresh_ph && finalize_spent_coin_id.is_none() {
            // First coin with non-fresh ph = post-finalize coin. Its
            // parent (the previous coin in our walk) was spent by
            // finalize.
            if let Some(p) = &prev {
                finalize_spent_coin_id = Some(p.coin.coin_id());
            }
        }
        if current.is_unspent() {
            break;
        }
        let coin_id = current.coin.coin_id();
        let children = chain.coin_records_by_parent_ids(&[coin_id]).await?;
        match children.into_iter().find(|r| r.coin.amount % 2 == 1) {
            Some(next) => {
                prev = Some(current);
                current = next;
            }
            None => break,
        }
    }
    let latest_coin_id = current.coin.coin_id();
    if current.coin.puzzle_hash == fresh_ph {
        // No state mutation ever happened → still fresh.
        return Ok((crate::state::BallotState::fresh(), latest_coin_id));
    }
    // Finalized. Try to extract vote_outcome + agg_signers from the
    // finalize spend's puzzle_and_solution. Falls back to defaults
    // when the chain backend can't supply the spend (rare — the spend
    // exists by definition since the post-finalize coin was created).
    let mut vote_outcome = Bytes32::default();
    let mut agg_signers = Bytes32::default();
    if let Some(finalize_id) = finalize_spent_coin_id {
        if let Some((_puzzle, solution)) = chain.puzzle_and_solution(finalize_id).await? {
            if let Some((vo, sg)) = extract_finalize_outcome(&solution) {
                vote_outcome = vo;
                agg_signers = sg;
            }
        }
    }
    let state = crate::state::BallotState {
        finalized: true,
        vote_outcome,
        agg_signers,
    };
    Ok((state, latest_coin_id))
}

/// FN: extract_finalize_outcome
/// WHAT: parse the singleton-wrapped action_layer solution from a
///       finalize spend's `puzzle_and_solution` and extract
///       `(vote_outcome, agg_signers)` from the finalize action's
///       solution. Returns `None` if the solution shape doesn't match
///       (e.g., a non-finalize action invocation, or a malformed spend).
/// SOURCE OF SHAPE:
///   * Singleton wrapper: `(lineage_proof, amount, inner_solution)` —
///     `chia_puzzle_types::singleton::SingletonSolution`.
///   * inner_solution = action_layer solution, hand-built by
///     `build_action_layer_solution` as the cons chain
///     `(puzzles . (sap . (solutions . finalizer_solution)))`.
///   * solutions[0] = the invoked action's solution. For finalize:
///     `(proof . (vote_outcome . (agg_signers . (agg_sig . scalars))))`
///     per `aggregator.rs::build_finalize_with_proof_for_ballot_inner`
///     and `puzzles/ballot_coin/finalize.rue`.
fn extract_finalize_outcome(solution: &chia_protocol::Program) -> Option<(Bytes32, Bytes32)> {
    use chia_puzzle_types::singleton::SingletonSolution;
    use clvm_traits::FromClvm;
    use clvmr::{Allocator, NodePtr};

    let mut alloc = Allocator::new();
    let solution_node: NodePtr = solution.to_clvm(&mut alloc).ok()?;

    // Outer wrapper: SingletonSolution { lineage_proof, amount, inner_solution }.
    let parsed: SingletonSolution<NodePtr> =
        SingletonSolution::from_clvm(&alloc, solution_node).ok()?;
    let inner = parsed.inner_solution;

    // inner = (puzzles . (sap . (solutions . finalizer_solution)))
    let (_puzzles, rest1) = pair(&alloc, inner)?;
    let (_sap, rest2) = pair(&alloc, rest1)?;
    let (solutions, _fs) = pair(&alloc, rest2)?;
    // solutions is a CLVM list; first element = finalize action's solution.
    let (finalize_solution, _rest) = pair(&alloc, solutions)?;
    // finalize_solution = (proof . (vote_outcome . (agg_signers . _)))
    let (_proof, after_proof) = pair(&alloc, finalize_solution)?;
    let (vote_outcome_node, after_vo) = pair(&alloc, after_proof)?;
    let (agg_signers_node, _after_as) = pair(&alloc, after_vo)?;

    let vote_outcome = atom_to_bytes32(&alloc, vote_outcome_node)?;
    // `agg_signers` in the finalize SOLUTION is a variable-length Bytes
    // (the participation bitfield); the on-chain BallotState stores it
    // as a Bytes32 (sha256 / pad / however the action processes it).
    // For now we expose the atom as Bytes32 when its length is 32, and
    // fall back to default otherwise — matches what the dApp consumes
    // (display-only field, never verified locally).
    let agg_signers = atom_to_bytes32(&alloc, agg_signers_node).unwrap_or_default();
    Some((vote_outcome, agg_signers))
}

fn pair(alloc: &clvmr::Allocator, node: clvmr::NodePtr) -> Option<(clvmr::NodePtr, clvmr::NodePtr)> {
    match alloc.sexp(node) {
        clvmr::SExp::Pair(a, b) => Some((a, b)),
        clvmr::SExp::Atom => None,
    }
}

fn atom_to_bytes32(alloc: &clvmr::Allocator, node: clvmr::NodePtr) -> Option<Bytes32> {
    let bytes = alloc.atom(node);
    let slice = bytes.as_ref();
    if slice.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Some(Bytes32::new(arr))
}

/// FN: read_ballot_launcher_memo
/// WHAT: fetch the launcher coin's spent puzzle_and_solution and
///       parse the third element of the launcher solution as a
///       `BallotLauncherMemo`. Returns `Ok(None)` when the launcher
///       is unspent (not yet broadcast / not yet confirmed) OR when
///       the key_value_list doesn't decode as a CHIP memo (legacy
///       ballots, third-party launchers).
/// WHY:  Option A — chain-discoverable curry. Cross-browser
///       observers + share-bundle importers can recover the curry
///       params without external metadata.
pub(crate) async fn read_ballot_launcher_memo<C: ChainReader>(
    chain: &C,
    ballot_launcher_id: Bytes32,
) -> VotingResult<Option<crate::state::BallotLauncherMemo>> {
    use chia_puzzle_types::singleton::LauncherSolution;
    use clvm_traits::{FromClvm, ToClvm};

    let (_puzzle, solution) = match chain.puzzle_and_solution(ballot_launcher_id).await? {
        Some(ps) => ps,
        None => return Ok(None),
    };
    let mut alloc = clvmr::Allocator::new();
    let solution_node = match solution.to_clvm(&mut alloc) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    let parsed: LauncherSolution<crate::state::BallotLauncherMemo> =
        match LauncherSolution::from_clvm(&alloc, solution_node) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
    let memo = parsed.key_value_list;
    if memo.schema_tag.as_ref() != crate::state::BALLOT_LAUNCHER_MEMO_TAG {
        return Ok(None);
    }
    Ok(Some(memo))
}

/// STRUCT: AnnounceFinalizationParams
/// PURPOSE: typed bundle for [`build_announce_finalization_bundle`]
///          arguments. Carries the per-ballot curry data needed to
///          reconstruct the FINALIZED Ballot Coin's puzzle hash, plus
///          the post-finalize state pair (`vote_outcome`,
///          `agg_signers`) the action solution requires.
/// FIELDS:
///   * `ballot_launcher_id` — singleton launcher id of the Ballot Coin
///     to spend.
///   * `vote_close_height`, `vote_threshold_num`, `vote_threshold_den`,
///     `registration_merkle_root_snapshot`,
///     `registration_vote_weight_snapshot` — same per-ballot curries
///     used by `Aggregator::build_finalize_for_ballot`. Must match
///     what the prior `BallotIssuer::launch_ballot` recorded;
///     mismatched curries will fail the on-chain ph sanity check
///     before any spend is built.
///   * `vote_outcome`, `agg_signers` — the FINALIZED state values
///     (the prior `Aggregator::build_finalize_for_ballot` write).
///     The action's solution carries these as a state-truth, and the
///     Ballot Coin's full puzzle hash is derived from them — passing
///     the wrong values will fail the on-chain ph sanity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceFinalizationParams {
    pub ballot_launcher_id: Bytes32,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot: Bytes32,
    pub registration_vote_weight_snapshot: u64,
    pub vote_outcome: Bytes32,
    pub agg_signers: Bytes32,
}

/// FN: build_announce_finalization_bundle
/// WHAT: spend the Ballot Coin running its `announce_finalization`
///       action (per CHIP rev §211-253). The action's only effect is
///       to emit a `CreateCoinAnnouncement` whose message is
///       `sha256("ballot_finalized" || ballot_launcher_id ||
///       vote_outcome || agg_signers)` — the on-chain trigger
///       downstream consumers (treasuries, etc.) latch onto.
/// PRE:  the ballot must already have been finalized via
///       `Aggregator::build_finalize_for_ballot`. The action
///       puzzle traps if the curried `BallotState` has
///       `finalized = false`.
/// FLOW:
///   1. Build the 3 per-ballot action puzzles (finalize, oracle,
///      announce_finalization) with the SAME curries the prior
///      `Aggregator::build_finalize_for_ballot` used. Compute their
///      tree hashes + the merkle root.
///   2. Build the action layer with the FINALIZED state truth
///      `((), (1u8, (vote_outcome, agg_signers)))` — this is what
///      makes the Ballot Coin's inner / full ph differ from the
///      pre-finalize layout.
///   3. Compute the predicted Ballot Coin full ph and walk the
///      lineage to find the current unspent Ballot Coin singleton.
///      Bail with a clear error if the predicted ph doesn't match
///      (means caller's `params` don't match the on-chain state).
///   4. Build the action layer solution running
///      `announce_finalization` with solution `()` — the action
///      reads the state truth from the layer's curried args, no
///      additional input needed.
///   5. Wrap as a singleton spend (Eve or Lineage proof per the
///      walker's return) and dry-run check.
///   6. Sign with empty keys — `announce_finalization` emits no
///      `AggSig*` conditions, so `sign_bundle_signature` returns
///      the BLS identity element (zero G2 point), which is the
///      canonical aggregate when no signatures are required.
/// POST: returns a single-coin-spend `SpendBundle` ready to push.
pub async fn build_announce_finalization_bundle<C: ChainReader>(
    config: &ElectionConfig,
    chain: &C,
    network: crate::config::NetworkType,
    params: AnnounceFinalizationParams,
) -> VotingResult<SpendBundle> {
    use chia_puzzle_types::singleton::SingletonArgs;
    use chia_puzzle_types::{LineageProof, Proof};
    use chia_sdk_driver::SpendContext;
    use clvm_traits::{clvm_curried_args, ToClvm};
    use clvm_utils::{tree_hash, CurriedProgram, TreeHash};

    let election_id = config.election_launcher_id().map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("election_launcher_id: {e}").into(),
        ))
    })?;

    // ── 1. Compute per-ballot finalize / oracle / announce hashes ──
    // Same curries as `Aggregator::build_finalize_for_ballot`. If any
    // diverges, the resulting ballot_actions_root won't match what
    // launch_ballot recorded, the predicted ph will be wrong, and
    // the on-chain check in step 3 will surface a clear error.
    let mut ctx = SpendContext::new();
    let (vk_node, ic_node) = build_vk_ic_nodes(&mut ctx, config)?;

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
        ),
    }
    .to_clvm(&mut *ctx)
    .map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("currying ballot finalize: {e}").into(),
        ))
    })?;
    let finalize_full_hash = Bytes32::new(tree_hash(&ctx, finalize_curried).to_bytes());

    // M4-revised: oracle now currys (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT,
    // VOTE_OPTIONS_ROOT). Defaulting to Mode1Free sentinel until M7e
    // threads `params.vote_options_root` through.
    let vote_options_root_curry: Bytes32 = Bytes32::default();
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
    .map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("currying oracle: {e}").into(),
        ))
    })?;
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
    .map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("currying announce_finalization: {e}").into(),
        ))
    })?;
    let announce_full_hash = Bytes32::new(tree_hash(&ctx, announce_curried).to_bytes());

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

    // ── 2. Build the action layer with the FINALIZED state ────────
    // BallotState shape (per `puzzles/ballot_coin/state.rue`):
    //   `(finalized . (vote_outcome . agg_signers))`
    // CLVM-encoded as `(u8, (Bytes32, Bytes32))`. The action layer
    // wraps it under an empty-list "truth" cell:
    //   `((), state)`
    // Post-finalize, finalized = 1.
    let ballot_finalizer_node =
        crate::action_spends::build_ballot_finalizer_full(&mut ctx, params.ballot_launcher_id)?;
    let finalized_state_value: ((), (u8, (Bytes32, Bytes32))) =
        ((), (1u8, (params.vote_outcome, params.agg_signers)));
    let ballot_state_node = finalized_state_value.to_clvm(&mut *ctx).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("finalized ballot state to_clvm: {e}").into(),
        ))
    })?;
    let ballot_inner_node = crate::action_spends::build_action_layer_puzzle(
        &mut ctx,
        ballot_finalizer_node,
        ballot_actions_root,
        ballot_state_node,
    )?;
    let ballot_inner_ph = Bytes32::new(tree_hash(&ctx, ballot_inner_node).to_bytes());

    // ── 3. Find the current Ballot Coin singleton ─────────────────
    let (ballot_coin, ballot_lineage_proof) =
        crate::actors::aggregator::find_current_ballot_singleton_via_chain(
            chain,
            params.ballot_launcher_id,
            ballot_inner_ph,
        )
        .await?;

    let inner_th = TreeHash::new(ballot_inner_ph.to_bytes());
    let predicted_full_ph = Bytes32::new(
        SingletonArgs::curry_tree_hash(params.ballot_launcher_id, inner_th).to_bytes(),
    );
    if ballot_coin.puzzle_hash != predicted_full_ph {
        return Err(VotingError::Other(anyhow_compat::Error(
            format!(
                "build_announce_finalization_bundle: Ballot Coin ph {} doesn't match predicted \
                 {} — params don't match the on-chain ballot (post-finalize) state",
                hex::encode(ballot_coin.puzzle_hash),
                hex::encode(predicted_full_ph),
            )
            .into(),
        )));
    }
    let ballot_lineage_proof: Proof = match ballot_lineage_proof {
        Proof::Eve(e) => Proof::Eve(e),
        Proof::Lineage(l) => Proof::Lineage(LineageProof {
            parent_parent_coin_info: l.parent_parent_coin_info,
            parent_inner_puzzle_hash: l.parent_inner_puzzle_hash,
            parent_amount: l.parent_amount,
        }),
    };

    // ── 4. Build the action layer solution ───────────────────────
    // announce_finalization's action solution is `()` — the action
    // reads the FINALIZED state from the layer's curried truth and
    // emits the announcement; no per-spend args needed.
    let announce_solution = ().to_clvm(&mut *ctx).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("announce_finalization solution: {e}").into(),
        ))
    })?;
    let action_spends = vec![crate::action_spends::ActionSpend {
        puzzle: announce_curried,
        solution: announce_solution,
    }];
    let ballot_finalizer_solution = ().to_clvm(&mut *ctx).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("ballot finalizer solution: {e}").into(),
        ))
    })?;
    let action_layer_solution = crate::action_spends::build_action_layer_solution(
        &mut ctx,
        &ballot_root_leaves,
        &action_spends,
        ballot_finalizer_solution,
    )?;

    // ── 5. Wrap as singleton spend + dry-run ─────────────────────
    let ballot_singleton_spend = crate::action_spends::build_singleton_spend(
        &mut ctx,
        ballot_coin,
        params.ballot_launcher_id,
        ballot_inner_node,
        action_layer_solution,
        ballot_lineage_proof,
    )?;

    let coin_spends = vec![ballot_singleton_spend];
    crate::dry_run_coin_spends(&coin_spends).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("build_announce_finalization_bundle dry-run: {e:?}").into(),
        ))
    })?;

    // ── 6. Sign + bundle ─────────────────────────────────────────
    // announce_finalization emits zero AggSig conditions, so the
    // empty-keys path returns the BLS identity (zero G2 point) —
    // which is the canonical aggregate when nothing requires signing.
    let signature = crate::actors::deployer::sign_bundle_signature(&coin_spends, &[], network)?;
    Ok(SpendBundle::new(coin_spends, signature))
}

impl BallotIssuer {
    /// FN: announce_finalization
    /// Delegates to [`build_announce_finalization_bundle`] using this
    /// issuer's stored config + network.
    pub async fn announce_finalization<C: ChainReader>(
        &self,
        chain: &C,
        params: AnnounceFinalizationParams,
    ) -> VotingResult<SpendBundle> {
        build_announce_finalization_bundle(&self.config, chain, self.network, params).await
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// End-to-end coverage of `BallotIssuer::create_ballot`,
// `BallotIssuer::launch_ballot`, and `BallotReader::{list_ballots,
// get_ballot}` lives in:
//   * sdk/tests/create_ballot_e2e.rs  — create flow on simulator
//   * sdk/tests/launch_ballot_e2e.rs  — launcher second-spend
//   * sdk/tests/ballot_reader_e2e.rs  — read accessors
//   * sdk/tests/finalize_per_ballot_e2e.rs — full lifecycle (deploy
//     → register → create_ballot → launch_ballot → cast → finalize)
//   * sdk/tests/live_orchestration_e2e.rs — multi-voter orchestration
//   * cli/src/bin/live_integration_test.rs run #11 — mainnet end-to-end
