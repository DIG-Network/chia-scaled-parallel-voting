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
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use clvm_utils::CurriedProgram;
use clvmr::NodePtr;
use dig_l1_wallet::NetworkType;

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
}

impl BallotIssuer {
    /// FN: new
    /// WHAT: construct from a validated config + network.
    pub fn new(config: ElectionConfig, network: NetworkType) -> Self {
        Self { config, network }
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
        let election_start_height: u64 = 0;
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            election_start_height,
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
        // CURRY ORDER (per `puzzles/election/create_ballot.rue`):
        //   (SINGLETON_LAUNCHER_PUZZLE_HASH, ELECTION_LAUNCHER_ID)
        let singleton_launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
        let create_ballot_program_node =
            load_action_puzzle(&mut ctx, puzzles::ELECTION_CREATE_BALLOT_HEX)?;
        let create_ballot_curried = CurriedProgram {
            program: create_ballot_program_node,
            args: clvm_curried_args!(singleton_launcher_ph, election_id),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // ── 4. Build the create_ballot action solution ──────────
        // SOLUTION SHAPE per `create_ballot.rue` (after the curried
        // `Truth: ElectionStateTruth` arg the action layer prepends
        // automatically):
        //   `(singleton_coin_id, ballot_seed, vote_close_height,
        //    ...outcome_domain_hash)`
        // Rue's trailing `...outcome_domain_hash: Bytes32` produces a
        // flat-tail cons chain — the cdr of the last cons IS the
        // 32-byte hash directly (no NIL terminator).
        let create_ballot_solution_value = (
            singleton_coin_id,
            (
                params.ballot_seed,
                (params.vote_close_height, params.outcome_domain_hash),
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
        let election_start_height: u64 = 0;
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            election_start_height,
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
        //    REGISTRATION_VOTE_WEIGHT_SNAPSHOT)
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
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let finalize_full_hash =
            Bytes32::new(clvm_utils::tree_hash(&ctx, finalize_curried).to_bytes());

        // oracle curry order (per `puzzles/ballot_coin/oracle.rue`):
        //   (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT)
        let oracle_program_node = load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ORACLE_HEX)?;
        let oracle_curried = CurriedProgram {
            program: oracle_program_node,
            args: clvm_curried_args!(launcher_coin_id, params.vote_close_height),
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
        let launcher_solution = LauncherSolution {
            singleton_puzzle_hash: eve_ballot_puzzle_hash,
            amount: EVE_BALLOT_AMOUNT,
            key_value_list: (),
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
/// WHAT: parse the deployment's `verification_key_hex` (672 bytes)
///       into the on-chain `VK` + `IC` cons trees expected by
///       `puzzles/ballot_coin/finalize.rue`.
/// LAYOUT:
///   * VK (336 bytes): alpha (PublicKey, 48) + beta (Signature, 96)
///     + gamma (Signature, 96) + delta (Signature, 96).
///     Encoded as a 4-field struct WITHOUT `...` → cons shape
///     `(alpha . (beta . (gamma . (delta . ()))))`.
///   * IC (336 bytes): 7 G1 points × 48 bytes each (`PUBLIC_INPUT_COUNT
///     + 1 = 7`). Encoded as a 7-field struct WITHOUT `...` → cons
///     shape `(ic0 . (ic1 . ... (ic6 . ())))`.
/// MIRROR: the rest-arg-less Rue struct encoding is what
///         `clvm_traits` produces for nil-terminated nested tuples /
///         `Vec`. We use `Vec<Bytes>::to_clvm` for both the VK list
///         (4 entries) and the IC list (7 entries).
pub(crate) fn build_vk_ic_nodes(
    ctx: &mut SpendContext,
    config: &ElectionConfig,
) -> VotingResult<(NodePtr, NodePtr)> {
    use chia_protocol::Bytes;

    let vk_bytes = hex::decode(config.verification_key_hex.trim()).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("decoding verification_key_hex: {e}").into(),
        ))
    })?;
    let expected = 336 + 7 * 48;
    if vk_bytes.len() != expected {
        return Err(VotingError::Other(anyhow_compat::Error(
            format!(
                "verification_key has {} bytes; expected {} (336 base + 7 IC * 48)",
                vk_bytes.len(),
                expected,
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

    let mut ic_fields: Vec<Bytes> = Vec::with_capacity(7);
    for i in 0..7 {
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
    let value = (
        state.registration_merkle_root,
        (
            state.registration_count,
            (state.registration_vote_weight, state.election_start_height),
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
                snapshots.push(BallotCoinSnapshot {
                    ballot_launcher_id: child.coin.coin_id(),
                    election_launcher_id: election_id,
                    vote_close_height: 0,
                    outcome_domain_hash: Bytes32::default(),
                    state: crate::state::BallotState::fresh(),
                    coin_id: child.coin.coin_id(),
                });
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

    Ok(Some(BallotCoinSnapshot {
        ballot_launcher_id,
        election_launcher_id: election_id,
        vote_close_height: 0,
        outcome_domain_hash: Bytes32::default(),
        state: crate::state::BallotState::fresh(),
        coin_id: ballot_launcher_id,
    }))
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
