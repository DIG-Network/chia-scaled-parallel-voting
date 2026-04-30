// ============================================================================
// actors/oracle.rs — Election Singleton oracle-action driver
// ============================================================================
//
// MODULE: actors::oracle
// PURPOSE: Anyone-can-call helper that produces the spend (or full
//          spend bundle) for the Election Singleton's `oracle`
//          action. The action emits a `CreateCoinAnnouncement` whose
//          message contains either:
//
//            * State.finalized == true:
//                sha256("oracle_finalized" || vote_outcome ||
//                       count_be8 || merkle_root)
//
//            * State.finalized == false:
//                sha256("oracle_unfinalized" || count_be8 ||
//                       merkle_root)
//
//          Downstream puzzles in the same spend bundle assert this
//          announcement via `AssertCoinAnnouncement` to read the
//          (un)finalized vote result on-chain.
//
// READ MODEL: same `chain::ChainReader` abstraction Aggregator and
//             Indexer use. Generic over `C` so production calls into
//             `chia_query::ChiaQuery` while tests inject
//             `chain::SharedSimulator`.
//
// WRITE MODEL: `build_oracle_spend` returns the SINGLE `CoinSpend`
//              for the singleton's oracle action — pair this in your
//              own `SpendBundle` alongside the spend(s) that need to
//              assert against the announcement. `build_oracle_bundle`
//              wraps the same spend in a fully-signed standalone
//              `SpendBundle` for callers who only want the
//              announcement on-chain (e.g., to publish a notarised
//              vote result).
//
// SIGNING: the oracle action emits NO `AggSig*` conditions, so the
//          aggregated signature for a bundle containing only the
//          oracle spend is the BLS identity. `build_oracle_bundle`
//          produces such a bundle without requiring any caller
//          secret keys.

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use dig_l1_wallet::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_election_finalizer_full,
    build_singleton_spend, load_action_puzzle, ActionSpend,
};
use crate::actors::aggregator::{
    election_actions_merkle_root_for_config, find_current_singleton, CurrentSingleton,
};
use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles;
use crate::state::ElectionState;

/// STRUCT: Oracle
/// PURPOSE: stateless driver for the Election Singleton's `oracle`
///          action. Holds only the election config + chain reader;
///          there's no per-actor secret material because the action
///          is permissionless and emits no AggSig conditions.
/// GENERIC: `C` defaults to `chia_query::ChiaQuery` so existing call
///          sites match the other actor types.
pub struct Oracle<C: ChainReader = chia_query::ChiaQuery> {
    pub config: ElectionConfig,
    pub network: NetworkType,
    chain: C,
}

/// STRUCT: OracleAnnouncement
/// PURPOSE: byte-form preview of what the oracle will emit at the
///          current chain state. Returned by `predict_announcement`
///          so callers can pre-compute their downstream
///          `AssertCoinAnnouncement` arguments without first
///          producing the spend.
/// VARIANT: which arm is returned depends ONLY on
///          `State.finalized` — the puzzle's branch logic.
#[derive(Debug, Clone)]
pub enum OracleAnnouncement {
    /// State.finalized == true. Includes the committed `vote_outcome`.
    Finalized {
        /// Bare `sha256("oracle_finalized" || vote_outcome ||
        ///                 count_be8 || merkle_root)` — the
        /// `CreateCoinAnnouncement.message` value.
        message: Bytes32,
        vote_outcome: Bytes32,
        registration_count: u64,
        registration_merkle_root: Bytes32,
    },
    /// State.finalized == false. `vote_outcome` is omitted from the
    /// preimage (it's zero pre-finalization and would only add noise).
    Unfinalized {
        /// Bare `sha256("oracle_unfinalized" || count_be8 ||
        ///                 merkle_root)` — the
        /// `CreateCoinAnnouncement.message` value.
        message: Bytes32,
        registration_count: u64,
        registration_merkle_root: Bytes32,
    },
}

impl OracleAnnouncement {
    /// The announcement's bare message bytes — use this with the
    /// announcer coin id when computing
    /// `AssertCoinAnnouncement.id`.
    pub fn message(&self) -> Bytes32 {
        match self {
            OracleAnnouncement::Finalized { message, .. }
            | OracleAnnouncement::Unfinalized { message, .. } => *message,
        }
    }

    /// Whether this is the `Finalized` variant.
    pub fn is_finalized(&self) -> bool {
        matches!(self, OracleAnnouncement::Finalized { .. })
    }
}

/// STRUCT: OracleSpend
/// PURPOSE: full output of `Oracle::build_oracle_spend` — the
///          single CoinSpend that emits the announcement, plus the
///          metadata downstream puzzles need to assert against it.
/// USAGE: include `coin_spend` in your own bundle next to the
///        spend(s) that emit `AssertCoinAnnouncement { id:
///        announcement_id }`.
#[derive(Debug, Clone)]
pub struct OracleSpend {
    /// The Election Singleton coin spend that emits the
    /// announcement. Drop this directly into a SpendBundle's
    /// `coin_spends` vector.
    pub coin_spend: CoinSpend,
    /// The Election Singleton coin being spent — its coin id is the
    /// `announcer_coin_id` consensus uses to validate any paired
    /// `AssertCoinAnnouncement` against this spend.
    pub singleton_coin: Coin,
    /// Election state at the time of spend assembly. Matches what
    /// the announcement preimage commits to.
    pub state: ElectionState,
    /// Variant + bare announcement message. The same data
    /// `predict_announcement` returns at the same state.
    pub announcement: OracleAnnouncement,
    /// Pre-computed `sha256(singleton_coin.coin_id() ||
    /// announcement.message)` — the value downstream
    /// `AssertCoinAnnouncement.id` arguments must use.
    pub announcement_id: Bytes32,
}

impl OracleSpend {
    /// Convenience accessor for the singleton coin id.
    pub fn singleton_coin_id(&self) -> Bytes32 {
        self.singleton_coin.coin_id()
    }
}

impl<C: ChainReader> Oracle<C> {
    /// FN: new
    /// WHAT: construct from a validated config + chain reader. No I/O.
    pub fn new(config: ElectionConfig, chain: C, network: NetworkType) -> Self {
        Self { config, chain, network }
    }

    /// Shared reference to the underlying chain reader. Use for
    /// custom queries that fall outside the actor's API.
    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// FN: predict_announcement
    /// WHAT: walk the chain to recover the current Election Singleton
    ///       state and return the announcement an oracle spend
    ///       WOULD emit RIGHT NOW.
    /// USAGE: call before `build_oracle_spend` if you only want to
    ///        know which variant will fire (e.g., to gate UI logic
    ///        on whether the election is finalized) or to
    ///        pre-compute the announcement bytes for a downstream
    ///        puzzle's currying.
    /// CACHE: this method does NOT cache — repeated calls re-walk
    ///        the chain. Production callers reading the oracle
    ///        often should cache the snapshot themselves.
    pub async fn predict_announcement(&self) -> VotingResult<OracleAnnouncement> {
        let snapshot = find_current_singleton(&self.chain, &self.config).await?;
        Ok(announcement_for_state(&snapshot.state))
    }

    /// FN: build_oracle_spend
    /// WHAT: produce the SINGLE `CoinSpend` for the Election
    ///       Singleton's `oracle` action.
    ///
    /// USAGE PATTERN:
    ///   1. Caller calls `oracle.build_oracle_spend()`.
    ///   2. Caller assembles their own bundle with this spend AND
    ///      whichever downstream coin spend(s) want to assert the
    ///      announcement.
    ///   3. Each downstream spend emits an `AssertCoinAnnouncement`
    ///      whose `id` equals `OracleSpend::announcement_id`.
    ///   4. Caller signs every coin spend in the combined bundle
    ///      via the upstream `RequiredSignature::from_coin_spends`
    ///      pipeline (the oracle action itself contributes no
    ///      AggSig requirements).
    ///
    /// IMPL:
    ///   1. Walk the chain via `find_current_singleton` to recover
    ///      the latest unspent singleton coin, its state, and a
    ///      ready-built lineage proof.
    ///   2. Build the action layer puzzle reveal (curried with the
    ///      election finalizer + per-deployment merkle root + the
    ///      singleton's CURRENT state cons tree).
    ///   3. Build the action layer solution selecting the bare
    ///      `oracle.rue` puzzle as the action (no curried args, nil
    ///      action solution — same shape as `announce_finalization`).
    ///   4. Wrap with the singleton outer.
    ///   5. Pre-flight via `dry_run_coin_spends` so any CLVM trap
    ///      surfaces with the offending coin id BEFORE returning.
    pub async fn build_oracle_spend(&self) -> VotingResult<OracleSpend> {
        let mut ctx = SpendContext::new();
        let (oracle_spend, snapshot) = self.assemble_oracle_spend(&mut ctx).await?;

        let announcement = announcement_for_state(&snapshot.state);
        let singleton_coin_id = snapshot.coin.coin_id();
        let announcement_id =
            puzzles::oracle_announcement_id(singleton_coin_id, announcement.message());

        // Pre-flight CLVM execution so a trap (e.g., a stale chain
        // snapshot vs the on-chain state) shows up here with a
        // useful coin id, instead of being buried in a downstream
        // signer error.
        let coin_spends = vec![oracle_spend.clone()];
        crate::dry_run_coin_spends(&coin_spends).map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("Oracle::build_oracle_spend dry-run: {e:?}").into(),
            ))
        })?;

        Ok(OracleSpend {
            coin_spend: oracle_spend,
            singleton_coin: snapshot.coin,
            state: snapshot.state,
            announcement,
            announcement_id,
        })
    }

    /// FN: build_oracle_bundle
    /// WHAT: convenience wrapper around `build_oracle_spend` that
    ///       wraps the single coin spend in a fully-formed
    ///       `SpendBundle` ready to broadcast.
    ///
    /// SIGNING: the oracle action emits no `AggSig*` conditions, so
    ///          this bundle's aggregated signature is the BLS
    ///          identity (no caller secret keys required). The
    ///          signing path still goes through the standard
    ///          `sign_bundle_signature` helper for parity with the
    ///          other actors — `RequiredSignature::from_coin_spends`
    ///          on a bundle with no AggSig conditions cleanly
    ///          returns the identity element.
    ///
    /// CALLER USE: useful when you want to publish the announcement
    ///             on-chain on its own (e.g., to notarise a
    ///             finalized result for off-chain indexers); pair
    ///             with `dry_run_coin_spends` is unnecessary because
    ///             `build_oracle_spend` already ran one.
    pub async fn build_oracle_bundle(&self) -> VotingResult<SpendBundle> {
        let oracle = self.build_oracle_spend().await?;
        let coin_spends = vec![oracle.coin_spend];
        let signature = sign_bundle_signature(&coin_spends, &[], self.network)?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// FN: assemble_oracle_spend (file-private)
    /// WHAT: shared assembly path for `build_oracle_spend` /
    ///       `build_oracle_bundle`. Returns both the assembled
    ///       `CoinSpend` and the underlying `CurrentSingleton`
    ///       snapshot so the caller can derive metadata
    ///       (announcement message + id) without re-walking the
    ///       chain.
    async fn assemble_oracle_spend(
        &self,
        ctx: &mut SpendContext,
    ) -> VotingResult<(CoinSpend, CurrentSingleton)> {
        let election_id = self.config.election_launcher_id().map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("election_launcher_id: {e}").into(),
            ))
        })?;

        // ── 1. Locate the current singleton + its lineage proof ──
        let snapshot = find_current_singleton(&self.chain, &self.config).await?;

        // ── 2. Build the action layer puzzle (current state) ─────
        let elect_finalizer = build_election_finalizer_full(ctx, election_id)?;
        let merkle_root = election_actions_merkle_root_for_config(&self.config);
        let state_node = election_state_to_clvm(ctx, &snapshot.state)?;
        let action_layer_node =
            build_action_layer_puzzle(ctx, elect_finalizer, merkle_root, state_node)?;

        // ── 3. Build the oracle action selection ─────────────────
        // oracle.rue takes (StateTruth) only — no curried args,
        // no per-spend solution params. Mirrors
        // announce_finalization.
        let oracle_action = load_action_puzzle(ctx, puzzles::ELECTION_ORACLE_HEX)?;
        let oracle_solution = ().to_clvm(&mut **ctx).map_err(driver_err)?;
        let action_spends = vec![ActionSpend {
            puzzle: oracle_action,
            solution: oracle_solution,
        }];

        // Election finalizer takes `..._my_solution: Any` — the
        // oracle action does NOT recreate the singleton with new
        // state (state is unchanged), so pass nil. Mirrors
        // announce_finalization.
        let finalizer_solution = ().to_clvm(&mut **ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            ctx,
            &compute_action_root_leaves(&self.config),
            &action_spends,
            finalizer_solution,
        )?;

        // ── 4. Wrap with the singleton outer ─────────────────────
        let coin_spend = build_singleton_spend(
            ctx,
            snapshot.coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            snapshot.lineage_proof,
        )?;

        Ok((coin_spend, snapshot))
    }
}

/// FN: announcement_for_state
/// WHAT: produce the `OracleAnnouncement` variant the on-chain
///       puzzle would emit for `state`.
/// USAGE: backbone of both `predict_announcement` (no spend) and
///        `build_oracle_spend` (spend assembled). Centralises the
///        finalized-vs-unfinalized branch so both paths agree
///        byte-for-byte.
/// MIRROR: matches `puzzles/election/oracle.rue`'s `if
///         State.finalized` branch verbatim.
pub fn announcement_for_state(state: &ElectionState) -> OracleAnnouncement {
    if state.finalized {
        OracleAnnouncement::Finalized {
            message: puzzles::oracle_finalized_message(
                state.vote_outcome,
                state.registration_count,
                state.registration_merkle_root,
            ),
            vote_outcome: state.vote_outcome,
            registration_count: state.registration_count,
            registration_merkle_root: state.registration_merkle_root,
        }
    } else {
        OracleAnnouncement::Unfinalized {
            message: puzzles::oracle_unfinalized_message(
                state.registration_count,
                state.registration_merkle_root,
            ),
            registration_count: state.registration_count,
            registration_merkle_root: state.registration_merkle_root,
        }
    }
}

/// FN: election_state_to_clvm (file-private)
/// WHAT: serialise `ElectionState` into the trailing-tail cons
///       chain shape Rue's `...vote_outcome: Bytes32` produces:
///         (root . (count . (fees . (finalized . vote_outcome))))
/// WHY: must match exactly the curried STATE the singleton's
///      action layer was built with — any divergence (e.g., a
///      stray NIL terminator after vote_outcome) makes the action
///      layer's puzzle hash diverge from the singleton outer's
///      commitment and the spend rejects.
fn election_state_to_clvm(
    ctx: &mut SpendContext,
    state: &ElectionState,
) -> VotingResult<clvmr::NodePtr> {
    let value = (
        state.registration_merkle_root,
        (
            state.registration_count,
            (
                state.accumulated_fees,
                (state.finalized as u8, state.vote_outcome),
            ),
        ),
    );
    value.to_clvm(&mut **ctx).map_err(driver_err)
}

/// FN: compute_action_root_leaves (file-private)
/// WHAT: the leaf set the action layer's MerkleProof builder needs
///       — same convention `voter::election_action_root_leaves`
///       and `aggregator::compute_election_action_root_leaves`
///       use, kept private here to avoid leaking another public
///       symbol with the same job.
fn compute_action_root_leaves(config: &ElectionConfig) -> Vec<Bytes32> {
    crate::actors::aggregator::compute_election_action_root_leaves(config)
}

/// FN: driver_err (file-private)
/// WHAT: shorthand for converting a `chia_sdk_driver` /
///       `clvm_traits` error into a `VotingError`.
fn driver_err<E: std::fmt::Debug>(e: E) -> VotingError {
    VotingError::Other(anyhow_compat::Error(
        format!("clvm/driver: {e:?}").into(),
    ))
}

// ============================================================================
// Tests
// ============================================================================
//
// CONVENTION: every test below carries a `WHAT / HOW / WHY` block.
//
// SCOPE: simulator-backed end-to-end coverage. Pure helpers
// (`announcement_for_state` + the puzzle-hash mirrors in `puzzles.rs`)
// are exercised here through the same code path the production
// `build_oracle_spend` follows, which is the strongest possible
// pin against drift between the SDK helpers and the on-chain Rue
// branch logic.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::deployer::{DeployParams, ElectionDeployer};
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
            registration_fee: 10,
            election_length_blocks: 4_608,
            label: Some("oracle-test".into()),
        }
    }

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

    /// WHAT: `predict_announcement` against a freshly-deployed
    ///       (genesis-state) election returns the `Unfinalized`
    ///       variant carrying the expected zero counters + empty
    ///       SPT root.
    /// HOW:  deploy into a simulator, wrap in `SharedSimulator`,
    ///       construct an `Oracle`, call `predict_announcement`,
    ///       destructure the variant.
    /// WHY:  the unfinalized arm is the most common pre-finalize
    ///       reading any external puzzle would fire against. Pin
    ///       its full shape (variant + counters + root) so a
    ///       refactor cannot accidentally swap the two arms or
    ///       desynchronise the carried state from `state()`.
    #[tokio::test(flavor = "current_thread")]
    async fn predict_announcement_against_genesis_returns_unfinalized() {
        let (config, mut sim) = deploy_into_sim();
        let chain = SharedSimulator::new(&mut sim);
        let oracle = Oracle::new(config, chain, NetworkType::Mainnet);
        let ann = oracle
            .predict_announcement()
            .await
            .expect("predict_announcement must succeed at genesis");

        match ann {
            OracleAnnouncement::Unfinalized {
                message,
                registration_count,
                registration_merkle_root,
            } => {
                assert_eq!(registration_count, 0);
                let empty_root = crate::merkle::SparseMerkleTree::new().root();
                assert_eq!(registration_merkle_root, empty_root);
                let expected = puzzles::oracle_unfinalized_message(0, empty_root);
                assert_eq!(message, expected);
            }
            other => panic!("expected Unfinalized variant, got {other:?}"),
        }
    }

    /// WHAT: `build_oracle_spend` against a freshly-deployed
    ///       election produces a single CoinSpend the simulator
    ///       accepts, AND the returned `OracleSpend.announcement`
    ///       matches what `predict_announcement` predicts.
    /// HOW:  deploy → build oracle spend → assemble bundle (no
    ///       extra signing required because the oracle action
    ///       emits no AggSig conditions) → submit to simulator.
    ///       Assert: simulator accepts; the singleton coin is
    ///       spent; the returned announcement equals
    ///       `predict_announcement`'s output.
    /// WHY:  this is the canonical end-to-end check that the
    ///       Rust assembly (action selector + Merkle proof + state
    ///       cons tree + lineage proof + singleton outer wrap)
    ///       matches the on-chain puzzle's expectations. If any
    ///       single step diverges, the simulator rejects with a
    ///       precise error.
    #[tokio::test(flavor = "current_thread")]
    async fn build_oracle_spend_is_simulator_accepted_at_genesis() {
        let (config, mut sim) = deploy_into_sim();

        // Predict + build via SharedSimulator first, THEN drop the
        // borrow so we can call sim.new_transaction.
        let (coin_spend, predicted, returned) = {
            let chain = SharedSimulator::new(&mut sim);
            let oracle = Oracle::new(config.clone(), chain, NetworkType::Mainnet);
            let predicted = oracle
                .predict_announcement()
                .await
                .expect("predict_announcement");
            let oracle_spend = oracle
                .build_oracle_spend()
                .await
                .expect("build_oracle_spend");
            // Sanity: predict + spend agree on the announcement.
            assert_eq!(
                oracle_spend.announcement.message(),
                predicted.message(),
                "predict_announcement vs build_oracle_spend message must agree"
            );
            (
                oracle_spend.coin_spend.clone(),
                predicted,
                oracle_spend.announcement.clone(),
            )
        };

        // Build a bundle (BLS identity sig — no AggSig from oracle).
        let coin_id = coin_spend.coin.coin_id();
        let bundle = SpendBundle::new(vec![coin_spend], chia_bls::Signature::default());

        sim.new_transaction(bundle)
            .expect("simulator must accept oracle spend bundle");
        assert!(
            sim.coin_state(coin_id).unwrap().spent_height.is_some(),
            "oracle action's singleton coin must be marked spent"
        );

        // The returned announcement matches what we predicted.
        assert_eq!(returned.message(), predicted.message());
        assert!(matches!(returned, OracleAnnouncement::Unfinalized { .. }));
    }

    /// WHAT: `build_oracle_bundle` is identical to
    ///       `build_oracle_spend` + manual sign with no keys.
    /// HOW:  deploy → call build_oracle_bundle → submit to
    ///       simulator. Assert: success + coin is spent.
    /// WHY:  the convenience wrapper is what 90% of callers will
    ///       use. Pinning that it produces a simulator-acceptable
    ///       bundle catches regressions in the no-key signing path
    ///       (e.g., if `sign_bundle_signature` ever changed its
    ///       empty-input behaviour from "identity" to "error").
    #[tokio::test(flavor = "current_thread")]
    async fn build_oracle_bundle_is_simulator_accepted_at_genesis() {
        let (config, mut sim) = deploy_into_sim();

        let bundle = {
            let chain = SharedSimulator::new(&mut sim);
            let oracle = Oracle::new(config, chain, NetworkType::Mainnet);
            oracle
                .build_oracle_bundle()
                .await
                .expect("build_oracle_bundle")
        };

        let coin_id = bundle.coin_spends[0].coin.coin_id();
        sim.new_transaction(bundle)
            .expect("simulator must accept oracle bundle");
        assert!(
            sim.coin_state(coin_id).unwrap().spent_height.is_some(),
            "oracle bundle must spend the singleton"
        );
    }

    /// WHAT: `announcement_for_state` produces the byte-exact same
    ///       message bytes for the `Finalized` variant as the
    ///       on-chain `oracle.rue` puzzle would, given a finalized
    ///       state.
    /// HOW:  hand-build a finalized `ElectionState`, call
    ///       `announcement_for_state`, recompute the expected
    ///       sha256 via the standalone `oracle_finalized_message`
    ///       helper, assert byte equality.
    /// WHY:  pre-finalization is the most common case so the live
    ///       simulator tests above only cover the unfinalized arm.
    ///       This unit test pins the finalized arm's message
    ///       bytes against drift even though we have no easy
    ///       simulator path to a finalized state without running
    ///       the full Groth16 prover.
    #[test]
    fn announcement_for_state_finalized_arm_matches_helper() {
        let state = ElectionState {
            registration_merkle_root: Bytes32::new([0x11; 32]),
            registration_count: 7,
            accumulated_fees: 0,
            finalized: true,
            vote_outcome: Bytes32::new([0x42; 32]),
        };
        let ann = announcement_for_state(&state);
        let OracleAnnouncement::Finalized {
            message,
            vote_outcome,
            registration_count,
            registration_merkle_root,
        } = ann
        else {
            panic!("expected Finalized variant for finalized=true state");
        };
        assert_eq!(vote_outcome, state.vote_outcome);
        assert_eq!(registration_count, state.registration_count);
        assert_eq!(registration_merkle_root, state.registration_merkle_root);
        assert_eq!(
            message,
            puzzles::oracle_finalized_message(
                state.vote_outcome,
                state.registration_count,
                state.registration_merkle_root,
            ),
        );
    }

    /// WHAT: `announcement_for_state` returns the `Unfinalized`
    ///       variant whenever `state.finalized == false`,
    ///       regardless of any other field values.
    /// HOW:  build a non-finalized state with NON-zero
    ///       registration counters + a non-default vote_outcome
    ///       (which a malformed state could carry); assert the
    ///       returned variant ignores `vote_outcome` and reports
    ///       `Unfinalized`.
    /// WHY:  the variant is determined SOLELY by the boolean
    ///       branch in `oracle.rue`. Defensively, even if an
    ///       attacker were to construct a state with
    ///       finalized=false but a junk vote_outcome, the SDK
    ///       must still report Unfinalized — otherwise downstream
    ///       puzzles asserting against the announcement would
    ///       receive misleading Rust-side metadata.
    #[test]
    fn announcement_for_state_unfinalized_arm_ignores_vote_outcome() {
        let state = ElectionState {
            registration_merkle_root: Bytes32::new([0x55; 32]),
            registration_count: 4,
            accumulated_fees: 99,
            finalized: false,
            // Non-zero outcome despite finalized=false (junk).
            vote_outcome: Bytes32::new([0xAB; 32]),
        };
        let ann = announcement_for_state(&state);
        assert!(matches!(ann, OracleAnnouncement::Unfinalized { .. }));
        // The carried message MUST NOT include the bogus outcome.
        let expected = puzzles::oracle_unfinalized_message(
            state.registration_count,
            state.registration_merkle_root,
        );
        assert_eq!(ann.message(), expected);
    }
}
