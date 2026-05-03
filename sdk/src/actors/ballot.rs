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
use dig_l1_wallet::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_election_finalizer_full,
    build_singleton_spend, load_action_puzzle, ActionSpend,
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
