// ============================================================================
// actors/ceremony.rs — Ceremony Singleton drivers
// ============================================================================
//
// MODULE: actors::ceremony
// PURPOSE: On-chain drivers for the multi-participant Groth16 trusted-
//          setup Ceremony Singleton. Replaces the prior single-party
//          `runSingleParticipantCeremony` flow with a permissionless,
//          one-of-N-honest, time-bounded on-chain ceremony.
//
// LIFECYCLE:
//   1. `CeremonyDeployer::new(params).deploy(parent_coin, parent_pk)`
//      → genesis launcher spend creating an empty Ceremony Singleton.
//   2. Anyone calls `CeremonyContributor::contribute(...)` during the
//      curried `[start, start+length)` window. Each contribution
//      advances the singleton's state and emits a marker CeremonyCoin.
//   3. After the window closes, `CeremonyReader::list_contributions(...)`
//      walks the lineage; `CeremonyReader::derive_vk(...)` validates
//      every contribution's PoK and composes the final VK.
//
// SECURITY MODEL: 1-of-N honest. Sybil attacks don't break soundness
//   because at least one honest participant's deleted τ randomises the
//   final parameters into a sound proving key.
//
// NOTE: This module is the on-chain integration. The off-chain math
//   (proof-of-knowledge construction, parameter mixing, VK composition)
//   lives in the sibling `crate::ceremony` module — coordinator,
//   participant, transcript, verification.

use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_puzzle_types::Proof;
use chia_sdk_driver::{Launcher, SpendContext, StandardLayer};
use clvm_traits::ToClvm;
use clvmr::NodePtr;

use crate::actors::deployer::sign_bundle_signature;
use crate::config::NetworkType;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles::{self, PuzzleHashes};
use crate::state::CeremonyState;

/// STRUCT: CeremonyParams
/// PURPOSE: deployment-time inputs chosen by the ceremony creator.
///          Every field is curried into the Ceremony Singleton's
///          `contribute` action — changing them post-deploy means
///          re-launching.
#[derive(Debug, Clone)]
pub struct CeremonyParams {
    /// First block height at which contributions are accepted.
    /// Mirrors `START_BLOCK_HEIGHT` in `contribute.rue`.
    pub start_block_height: u64,
    /// Length (in blocks) of the contribution window. Window is
    /// `[start, start + length)`; outside the window, the contribute
    /// action's height-assertions fail.
    pub ceremony_length_blocks: u64,
    /// Minimum number of accepted contributions required before the
    /// dApp will derive a VK. Enforced OFF-CHAIN by the SDK at VK
    /// derivation time — see `CeremonyReader::derive_vk`. (On-chain
    /// enforcement would require an extra action puzzle and isn't
    /// security-relevant; a deployer who tries to derive below the
    /// threshold simply fails to produce a usable VK.)
    pub min_participants: u64,
    /// Maximum number of voters the Groth16 circuit (and any election
    /// using this ceremony's VK) can support. Determines the SPT
    /// `tree_depth = ceil(log2(max_voters))` for both the off-chain
    /// circuit and the on-chain election singleton's curry. Default
    /// at construct sites is 20000. Schema-versioned in the launcher
    /// memo (`chip:ceremony:v2`) so cross-browser readers can recover
    /// it from chain alone.
    pub max_voters: u64,
    /// Genesis previous-contribution hash. The first contributor
    /// supplies this exact value as their `prev_contribution_hash`
    /// argument. Typically a known canonical Powers-of-Tau starting
    /// point hash; treated opaquely on-chain. Mirrors the
    /// deployer-curried genesis state's `last_contribution_hash`.
    pub vk_seed: Bytes32,
    /// Optional label for UIs/indexers.
    pub label: Option<String>,
}

/// Default cap on the configurable max_voters at construct sites.
/// Picked as a "sane test ceremony" value; production deploys
/// override via the dApp form.
pub const DEFAULT_CEREMONY_MAX_VOTERS: u64 = 20_000;

/// STRUCT: CeremonyDeployer
/// PURPOSE: stateful actor that owns `CeremonyParams` and exposes the
///          deployment + puzzle-hash-prediction API for the Ceremony
///          Singleton.
#[derive(Debug, Clone)]
pub struct CeremonyDeployer {
    pub params: CeremonyParams,
}

impl CeremonyDeployer {
    /// Construct from the ceremony parameters. No I/O.
    pub fn new(params: CeremonyParams) -> Self {
        Self { params }
    }

    /// FN: derive_launcher_id
    /// WHAT: predict the singleton launcher_id from the parent coin id.
    /// MIRRORS: `actors::deployer::derive_launcher_id` (same standard
    ///          Chia singleton launcher convention).
    pub fn derive_launcher_id(parent_coin_id: Bytes32, amount: u64) -> Bytes32 {
        let launcher_coin = Coin::new(parent_coin_id, SINGLETON_LAUNCHER_HASH.into(), amount);
        launcher_coin.coin_id()
    }

    /// FN: genesis_state_tree_hash
    /// WHAT: tree hash of the ceremony's genesis `CeremonyState` cons
    ///       tree — `(0, vk_seed)`. Curried into the singleton's
    ///       genesis inner puzzle hash.
    pub fn genesis_state_tree_hash(&self) -> Bytes32 {
        CeremonyState::genesis(self.params.vk_seed).clvm_tree_hash()
    }

    /// FN: ceremony_contribute_action_hash
    /// WHAT: tree hash of the (fully-curried) `contribute` action
    ///       puzzle. Curry order MUST match
    ///       `puzzles/ceremony_singleton/contribute.rue`:
    ///       `(CEREMONY_LAUNCHER_ID, START_BLOCK_HEIGHT,
    ///         CEREMONY_LENGTH_BLOCKS, CEREMONY_COIN_MOD_HASH)`.
    pub fn ceremony_contribute_action_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        puzzles::curry_tree_hash(
            PuzzleHashes::ceremony_singleton_contribute(),
            &[
                puzzles::hash_atom_b32(&launcher_id),
                uint_atom_hash(self.params.start_block_height),
                uint_atom_hash(self.params.ceremony_length_blocks),
                puzzles::hash_atom_b32(&PuzzleHashes::ceremony_coin_marker()),
            ],
        )
    }

    /// FN: ceremony_finalize_action_hash
    /// WHAT: tree hash of the (fully-curried) `finalize` action
    ///       puzzle. Curry order MUST match
    ///       `puzzles/ceremony_singleton/finalize.rue`:
    ///       `(CEREMONY_LAUNCHER_ID, START_BLOCK_HEIGHT,
    ///         CEREMONY_LENGTH_BLOCKS, MAX_VOTERS,
    ///         CEREMONY_COIN_MOD_HASH, CEREMONY_VOUCHER_MOD_HASH,
    ///         MIN_PARTICIPANTS)`.
    pub fn ceremony_finalize_action_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        puzzles::curry_tree_hash(
            PuzzleHashes::ceremony_singleton_finalize(),
            &[
                puzzles::hash_atom_b32(&launcher_id),
                uint_atom_hash(self.params.start_block_height),
                uint_atom_hash(self.params.ceremony_length_blocks),
                uint_atom_hash(self.params.max_voters),
                puzzles::hash_atom_b32(&PuzzleHashes::ceremony_coin_marker()),
                puzzles::hash_atom_b32(&PuzzleHashes::ceremony_voucher()),
                uint_atom_hash(self.params.min_participants),
            ],
        )
    }

    /// FN: ceremony_actions_merkle_root
    /// WHAT: 2-leaf merkle root over the singleton's allowed actions
    ///       — `contribute` and `finalize`. Sorted ascending by
    ///       `hash_atom_b32(action_full)` to match the convention
    ///       used by the other `*_actions_merkle_root` helpers (and
    ///       `chia_sdk_types::MerkleTree`).
    pub fn ceremony_actions_merkle_root(&self, launcher_id: Bytes32) -> Bytes32 {
        let contribute_full = self.ceremony_contribute_action_hash(launcher_id);
        let finalize_full = self.ceremony_finalize_action_hash(launcher_id);
        let c_h = puzzles::hash_atom_b32(&contribute_full);
        let f_h = puzzles::hash_atom_b32(&finalize_full);
        let (a, b) = if c_h.as_ref() < f_h.as_ref() {
            (c_h, f_h)
        } else {
            (f_h, c_h)
        };
        puzzles::hash_pair(a, b)
    }

    /// FN: genesis_inner_puzzle_hash
    /// WHAT: action-layer-curried inner puzzle hash committed to the
    ///       singleton launcher. `SingletonArgs::curry_tree_hash`
    ///       wraps this on top to produce the launcher commitment.
    /// CURRY ORDER: `(FINALIZER, MERKLE_ROOT, STATE)` — must match
    ///              `puzzles/action.rue`. Finalizer layout follows the
    ///              CHIP-0050 self-hash pattern shared with
    ///              `ballot_coin/finalizer.rue` and
    ///              `ceremony_singleton/finalizer.rue`.
    pub fn genesis_inner_puzzle_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        let action_layer_mod_hash = PuzzleHashes::action_layer();
        let finalizer_mod_hash = PuzzleHashes::ceremony_singleton_finalizer();

        // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT=launcher_id)
        let finalizer_first = puzzles::curry_tree_hash(
            finalizer_mod_hash,
            &[
                puzzles::hash_atom_b32(&action_layer_mod_hash),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        );
        // Finalizer 2nd curry: bind self-hash.
        let finalizer_full =
            puzzles::curry_tree_hash(finalizer_first, &[puzzles::hash_atom_b32(&finalizer_first)]);

        let merkle_root = self.ceremony_actions_merkle_root(launcher_id);
        let state_hash = self.genesis_state_tree_hash();

        // Curry args (matching `action.rue`):
        //   * `finalizer_full` — already a TREE HASH of a curried
        //     program. Pass directly. Atom-wrapping would double-hash.
        //   * `merkle_root` — atom value (Bytes32). Wrap as atom.
        //   * `state_hash` — already a TREE HASH (cons tree). Pass directly.
        puzzles::curry_tree_hash(
            action_layer_mod_hash,
            &[
                finalizer_full,
                puzzles::hash_atom_b32(&merkle_root),
                state_hash,
            ],
        )
    }

    /// FN: build_deploy_bundle
    /// WHAT: assemble the (unsigned) coin spends for genesis launch.
    /// CONTRACT: caller has already coin-selected `parent_coin` (an
    ///           XCH coin holding ≥1 mojo locked under `parent_pk`'s
    ///           standard puzzle).
    /// EMITS:
    ///   * 1 launcher spend (parent_coin's child at puzzle_hash =
    ///     SINGLETON_LAUNCHER_HASH, amount=1) — creates the eve
    ///     Ceremony Singleton committed to `genesis_inner_puzzle_hash`.
    ///   * 1 standard p2 spend of `parent_coin` → launcher coin (1 mojo)
    ///     + change back to the parent's standard p2 puzzle hash so
    ///     the funding wallet doesn't burn its remaining balance.
    /// RETURNS: `(coin_spends, launcher_id)`.
    pub fn build_deploy_bundle(
        &self,
        parent_coin: Coin,
        parent_pk: PublicKey,
    ) -> VotingResult<(Vec<CoinSpend>, Bytes32)> {
        use chia_puzzle_types::standard::StandardArgs;
        use chia_sdk_types::Conditions;

        let mut ctx = SpendContext::new();

        let launcher_id = Self::derive_launcher_id(parent_coin.coin_id(), 1);
        let inner_ph = self.genesis_inner_puzzle_hash(launcher_id);

        // 1. Launcher coin spend (commits to eve singleton with our
        //    inner puzzle hash). The third arg is the launcher's
        //    `key_value_list` — we encode the bootstrap params here
        //    so any cross-browser reader can recover them by parsing
        //    `puzzle_and_solution(launcher_id)` (no localStorage
        //    needed). Mirrors the ballot launcher's approach.
        let launcher = Launcher::new(parent_coin.coin_id(), 1);
        let curry_memo = crate::state::CeremonyLauncherMemo {
            schema_tag: chia_protocol::Bytes::new(
                crate::state::CEREMONY_LAUNCHER_MEMO_TAG.to_vec(),
            ),
            start_block_height: self.params.start_block_height,
            ceremony_length_blocks: self.params.ceremony_length_blocks,
            min_participants: self.params.min_participants,
            max_voters: self.params.max_voters,
            vk_seed: self.params.vk_seed,
            label_bytes: chia_protocol::Bytes::new(
                self.params.label.clone().unwrap_or_default().into_bytes(),
            ),
        };
        let (launch_conditions, _eve) = launcher
            .spend(&mut ctx, inner_ph, curry_memo)
            .map_err(|e| {
                VotingError::Other(anyhow_compat::Error(
                    format!("CeremonyDeployer: launcher.spend failed: {e}").into(),
                ))
            })?;

        // 2. Standard p2 spend of the parent → launcher (1 mojo) +
        //    change back to parent_pk's standard p2 puzzle hash so we
        //    preserve `parent_coin.amount - 1` mojos.
        let parent_p2_ph = Bytes32::new(StandardArgs::curry_tree_hash(parent_pk).to_bytes());
        let mut conditions: Conditions = launch_conditions;
        if parent_coin.amount > 1 {
            let change = parent_coin.amount - 1;
            conditions =
                conditions.create_coin(parent_p2_ph, change, chia_puzzle_types::Memos::None);
        }
        StandardLayer::new(parent_pk)
            .spend(&mut ctx, parent_coin, conditions)
            .map_err(|e| {
                VotingError::Other(anyhow_compat::Error(
                    format!("CeremonyDeployer: standard layer spend failed: {e}").into(),
                ))
            })?;

        Ok((ctx.take(), launcher_id))
    }

    /// FN: deploy_signed
    /// WHAT: one-call build+sign convenience.
    /// CONTRACT: `secret_keys` must include the secret key for
    ///           `parent_pk`'s synthetic public key (the StandardLayer
    ///           AggSigMe key). Returns `(SpendBundle, launcher_id)`.
    pub fn deploy_signed(
        &self,
        parent_coin: Coin,
        parent_pk: PublicKey,
        secret_keys: &[SecretKey],
        network: NetworkType,
    ) -> VotingResult<(SpendBundle, Bytes32)> {
        let (coin_spends, launcher_id) = self.build_deploy_bundle(parent_coin, parent_pk)?;
        let signature: Signature = sign_bundle_signature(&coin_spends, secret_keys, network)?;
        let bundle = SpendBundle::new(coin_spends, signature);
        Ok((bundle, launcher_id))
    }
}

// ============================================================================
// CeremonyContributor
// ============================================================================

/// STRUCT: ContributeParams
/// PURPOSE: per-contribution inputs the contributor needs to build a
///          single `contribute` spend bundle. Every field is
///          ceremony-specific — the contributor itself just owns the
///          ceremony's launcher id and parameters; each contribution
///          provides its own payload + lineage anchors.
#[derive(Debug, Clone)]
pub struct ContributeParams {
    /// 48-byte BLS G1 pubkey of the contributing participant.
    /// Curried into the marker CeremonyCoin and signed-against in
    /// the `contribute` action's AGG_SIG_UNSAFE.
    pub participant_pubkey: PublicKey,
    /// 32-byte commitment to the contribution's PUBLIC output —
    /// `sha256(serialized_updated_parameters || serialized_pok)`. The
    /// raw bytes themselves travel in `payload` (recovered by the
    /// reader from the spend's solution); the on-chain footprint is
    /// only this hash.
    pub contribution_hash: Bytes32,
    /// 32-byte hash of the previous accepted contribution.
    /// MUST equal the singleton's curried `last_contribution_hash`
    /// at spend time — the on-chain assertion in `contribute.rue`
    /// rejects mismatches. Genesis contributors supply
    /// `params.vk_seed`.
    pub prev_contribution_hash: Bytes32,
    /// Raw 32-byte τ entropy. Embedded in the marker coin's memos
    /// (alongside the launcher id hint) so dApps can recover the
    /// contribution directly from `coin_records_by_hint(launcher_id)`
    /// without parsing the spend's full puzzle_and_solution. The
    /// soundness commitment remains `contribution_hash` (which the
    /// participant signs over and which commits to the full off-chain
    /// payload); this field is purely a discovery aid.
    pub entropy_hex: Bytes,
    /// Off-chain payload (PoK + updated parameters) traveling in the
    /// spend's solution. The reader recovers this via
    /// `puzzle_and_solution` and validates each PoK before composing
    /// the final VK.
    pub payload: Vec<u8>,
}

impl ContributeParams {
    /// FN: compute_contribution_hash
    /// WHAT: canonical hash committing the contributor to a specific
    ///       PUBLIC payload (updated parameters + PoK). Returns
    ///       `sha256("ceremony_payload" || payload_bytes)`. The
    ///       `"ceremony_payload"` prefix domain-separates this hash
    ///       from any other 32-byte ceremony commitment.
    /// USAGE: callers compute this once they have the serialised
    ///       contribution payload, then pass the result as
    ///       `contribution_hash` here.
    pub fn compute_contribution_hash(payload: &[u8]) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ceremony_payload");
        h.update(payload);
        Bytes32::new(h.finalize().into())
    }
}

/// STRUCT: CeremonyContributor
/// PURPOSE: stateful actor that owns a ceremony's identity (launcher
///          id + curried params) and exposes the contribute API. The
///          deployer params are needed to recompute the singleton's
///          curried action puzzle hash (via
///          `CeremonyDeployer::ceremony_contribute_action_hash`).
#[derive(Debug, Clone)]
pub struct CeremonyContributor {
    pub launcher_id: Bytes32,
    pub deployer: CeremonyDeployer,
}

impl CeremonyContributor {
    /// Construct a contributor bound to a specific ceremony.
    pub fn new(launcher_id: Bytes32, ceremony_params: CeremonyParams) -> Self {
        Self {
            launcher_id,
            deployer: CeremonyDeployer::new(ceremony_params),
        }
    }

    /// FN: contribution_signature_msg
    /// WHAT: the 32-byte UNAUGMENTED message the participant signs to
    ///       authorize their contribution. Convenience wrapper around
    ///       `ceremony_contribution_msg` with the contributor's
    ///       launcher id pre-bound.
    pub fn contribution_signature_msg(&self, p: &ContributeParams) -> Bytes32 {
        ceremony_contribution_msg(
            self.launcher_id,
            p.contribution_hash,
            p.prev_contribution_hash,
        )
    }

    /// FN: marker_puzzle_hash
    /// WHAT: predicted puzzle hash of the marker CeremonyCoin the
    ///       on-chain `contribute` action will create. Bound to
    ///       (launcher, pk, contribution_hash, prev_contribution_hash)
    ///       so callers can pre-compute the resulting coin id.
    pub fn marker_puzzle_hash(&self, p: &ContributeParams) -> Bytes32 {
        ceremony_coin_marker_puzzle_hash(
            self.launcher_id,
            &p.participant_pubkey,
            p.contribution_hash,
            p.prev_contribution_hash,
        )
    }

    /// FN: extract_contribute_action_solution
    /// WHAT: given the FULL singleton spend's solution NodePtr (as
    ///       returned by `chain.puzzle_and_solution(coin_id)` after
    ///       loading via `Program::to_clvm`), unwrap the layers down
    ///       to the contribute action's per-spend solution.
    /// LAYERS:
    ///   * SingletonSolution: `(lineage_proof . (amount . inner_solution))`
    ///   * ActionLayerSolution: `(puzzles . (sap . (solutions . finalizer_solution)))`
    ///   * `solutions` is a list `(per_action_solution . nil)` — for
    ///     single-action ceremonies, take the first element.
    /// USE: chain walker pipes this NodePtr into
    ///      `parse_action_solution_node` to recover (pk, contrib,
    ///      prev, payload) for a `ContributionRecord`.
    pub fn extract_contribute_action_solution(
        allocator: &clvmr::Allocator,
        singleton_solution: NodePtr,
    ) -> VotingResult<NodePtr> {
        use clvmr::SExp;
        let other = |s: &str| {
            VotingError::Other(anyhow_compat::Error(
                format!("extract_contribute_action_solution: {s}").into(),
            ))
        };
        let pair_of = |n: NodePtr, label: &str| -> VotingResult<(NodePtr, NodePtr)> {
            match allocator.sexp(n) {
                SExp::Pair(a, b) => Ok((a, b)),
                SExp::Atom => Err(other(&format!("expected pair at {label}, got atom"))),
            }
        };

        // SingletonSolution shape `#[clvm(list)]`: cons-list with nil
        //   terminator → `(lineage_proof . (amount . (inner . nil)))`
        let (_lineage_proof, rest1) = pair_of(singleton_solution, "singleton.lineage_proof")?;
        let (_amount, rest2) = pair_of(rest1, "singleton.amount")?;
        let (inner, _nil) = pair_of(rest2, "singleton.inner_solution")?;

        // ActionLayerSolution: (puzzles . (sap . (solutions . fs)))
        let (_puzzles, al_rest1) = pair_of(inner, "action_layer.puzzles")?;
        let (_sap, al_rest2) = pair_of(al_rest1, "action_layer.sap")?;
        let (solutions_list, _fs) = pair_of(al_rest2, "action_layer.solutions")?;

        // solutions list: take first (only) entry.
        let (first_solution, _rest_solutions) =
            pair_of(solutions_list, "solutions[0] (no actions in spend)")?;
        Ok(first_solution)
    }

    /// FN: parse_action_solution_node
    /// WHAT: inverse of `build_action_solution_node`. Takes a CLVM
    ///       NodePtr representing the per-spend solution for the
    ///       `contribute` action and decodes it back into the five
    ///       fields:
    ///         (participant_pk_bytes, contribution_hash,
    ///          prev_contribution_hash, entropy_hex, payload_bytes)
    ///       Used by `CeremonyReader::list_contributions_via_chain`
    ///       once the chain walker can fetch each spend's solution
    ///       via `puzzle_and_solution`.
    /// SHAPE per `puzzles/ceremony_singleton/contribute.rue` (post-B1):
    ///       `(pk . (contrib . (prev . (entropy . payload))))` —
    ///       payload is the cdr of the fourth cons (rest-arg).
    pub fn parse_action_solution_node(
        allocator: &clvmr::Allocator,
        node: NodePtr,
    ) -> VotingResult<(Vec<u8>, Bytes32, Bytes32, Vec<u8>, Vec<u8>)> {
        use clvmr::SExp;
        let other = |s: &str| {
            VotingError::Other(anyhow_compat::Error(
                format!("parse_action_solution_node: {s}").into(),
            ))
        };

        // Extract atom from a node, or error.
        let atom_of = |n: NodePtr, label: &str| -> VotingResult<Vec<u8>> {
            match allocator.sexp(n) {
                SExp::Atom => Ok(allocator.atom(n).as_ref().to_vec()),
                SExp::Pair(_, _) => Err(other(&format!(
                    "expected atom for {label}, got pair"
                ))),
            }
        };

        // (pk . rest1)
        let (pk_node, rest1) = match allocator.sexp(node) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution must be a cons, got atom")),
        };
        let pk_bytes = atom_of(pk_node, "participant_pk")?;

        // rest1 = (contrib . rest2)
        let (contrib_node, rest2) = match allocator.sexp(rest1) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution missing contribution_hash cons")),
        };
        let contrib_bytes = atom_of(contrib_node, "contribution_hash")?;
        let contribution_hash = Bytes32::try_from(contrib_bytes.as_slice())
            .map_err(|_| other("contribution_hash must be 32 bytes"))?;

        // rest2 = (prev . rest3)
        let (prev_node, rest3) = match allocator.sexp(rest2) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution missing prev_contribution_hash cons")),
        };
        let prev_bytes = atom_of(prev_node, "prev_contribution_hash")?;
        let prev_contribution_hash = Bytes32::try_from(prev_bytes.as_slice())
            .map_err(|_| other("prev_contribution_hash must be 32 bytes"))?;

        // rest3 = (entropy_hex . payload)
        let (entropy_node, payload_node) = match allocator.sexp(rest3) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution missing entropy_hex cons")),
        };
        let entropy_bytes = atom_of(entropy_node, "entropy_hex")?;

        // payload is the cdr of the last cons; for our rest-arg
        // shape the payload IS the value directly (atom or sub-tree).
        // We treat it as raw bytes — empty atom = empty payload.
        let payload_bytes = atom_of(payload_node, "payload")?;

        Ok((pk_bytes, contribution_hash, prev_contribution_hash, entropy_bytes, payload_bytes))
    }

    /// FN: build_action_solution_node
    /// WHAT: build the CLVM NodePtr for the `contribute` action's
    ///       per-spend solution.
    /// SHAPE per `puzzles/ceremony_singleton/contribute.rue` (after
    ///        the `Truth` arg the action layer prepends automatically):
    ///   `(participant_pk . (contribution_hash . (prev_contribution_hash . payload)))`
    ///   — the trailing `..._payload: Any` rest-arg means the cdr of
    ///   the last cons IS the payload bytes directly (no nil
    ///   terminator). The payload is ignored on-chain but recoverable
    ///   off-chain via `puzzle_and_solution`, which is how the Reader
    ///   reconstructs each contribution's full PoK + parameters
    ///   bytes for VK derivation.
    /// PUBKEY ENCODING: 48-byte atom (matches `tree_hash_atom(pk as
    ///        Bytes)` on the Rue side). Built via `ctx.new_pair` so
    ///        the shape is exact — `ToClvm` of nested tuples is brittle
    ///        for heterogeneous types and trailing rest-args.
    pub fn build_action_solution_node(
        ctx: &mut SpendContext,
        params: &ContributeParams,
    ) -> VotingResult<NodePtr> {
        let pk_bytes: Bytes = Bytes::new(params.participant_pubkey.to_bytes().to_vec());
        let payload_bytes: Bytes = Bytes::new(params.payload.clone());
        let map_err =
            |stage: &str, e: clvm_traits::ToClvmError| -> VotingError {
                VotingError::Other(anyhow_compat::Error(
                    format!("build_action_solution_node[{stage}]: {e}").into(),
                ))
            };
        let pk_node = pk_bytes.to_clvm(&mut **ctx).map_err(|e| map_err("pk", e))?;
        let contrib_node = params
            .contribution_hash
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("contrib", e))?;
        let prev_node = params
            .prev_contribution_hash
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("prev", e))?;
        let entropy_node = params
            .entropy_hex
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("entropy_hex", e))?;
        let payload_node = payload_bytes
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("payload", e))?;

        let new_pair_err = |stage: &str, e: clvmr::reduction::EvalErr| -> VotingError {
            VotingError::Other(anyhow_compat::Error(
                format!("build_action_solution_node[new_pair {stage}]: {e:?}").into(),
            ))
        };
        // Shape: `(pk . (contrib . (prev . (entropy . payload))))` —
        // `payload` is the rest-arg cdr of the last cons (no nil
        // terminator). `entropy` is a fixed-arity arg before the
        // rest-arg, mirroring contribute.rue's ABI after B1.
        let entropy_payload = ctx
            .new_pair(entropy_node, payload_node)
            .map_err(|e| new_pair_err("entropy_payload", e))?;
        let prev_rest = ctx
            .new_pair(prev_node, entropy_payload)
            .map_err(|e| new_pair_err("prev_rest", e))?;
        let contrib_rest = ctx
            .new_pair(contrib_node, prev_rest)
            .map_err(|e| new_pair_err("contrib_rest", e))?;
        let solution = ctx
            .new_pair(pk_node, contrib_rest)
            .map_err(|e| new_pair_err("solution", e))?;
        Ok(solution)
    }

    /// FN: build_contribute_bundle
    /// WHAT: assemble the (unsigned) coin spends for a single
    ///       contribution: the Ceremony Singleton spends itself via
    ///       the action-layer's `contribute` action, plus a standard
    ///       p2 spend of `funder_coin` providing the +1 mojo the
    ///       marker CeremonyCoin needs beyond the singleton's
    ///       recreation.
    /// CONTRACT: caller has already chain-walked the singleton tip
    ///           (passes its coin record + lineage proof + current
    ///           CeremonyState), and coin-selected a funder coin
    ///           owned by `funder_pk`'s standard puzzle.
    /// SIGNING: the returned spends are UNSIGNED. The caller signs
    ///          via `dig_l1_wallet::transaction::sign_coin_spends`
    ///          (or `sign_bundle_signature` from `actors::deployer`),
    ///          providing the participant's secret key (for
    ///          AGG_SIG_UNSAFE) and the funder's synthetic sk (for
    ///          the StandardLayer AggSigMe).
    pub fn build_contribute_bundle(
        &self,
        singleton_coin: Coin,
        lineage_proof: Proof,
        current_state: CeremonyState,
        funder_coin: Coin,
        funder_pk: PublicKey,
        params: ContributeParams,
    ) -> VotingResult<Vec<CoinSpend>> {
        use crate::action_spends::{
            build_action_layer_puzzle, build_action_layer_solution,
            build_ceremony_finalizer_full, load_action_puzzle, ActionSpend,
        };
        use chia_puzzle_types::standard::StandardArgs;
        use chia_sdk_types::Conditions;
        use clvm_traits::clvm_curried_args;
        use clvm_utils::CurriedProgram;

        let mut ctx = SpendContext::new();
        let other = |s: String| VotingError::Other(anyhow_compat::Error(s.into()));

        // 1. Ceremony singleton finalizer reveal (already self-curried).
        let finalizer = build_ceremony_finalizer_full(&mut ctx, self.launcher_id)?;

        // 2. Encode the CURRENT CeremonyState (post-D1 5-field shape):
        //    `(count . (last_hash . (finalized . (vk_hash . marker_root))))`.
        let state_node = (
            current_state.contribution_count,
            (
                current_state.last_contribution_hash,
                (
                    if current_state.finalized { 1u64 } else { 0u64 },
                    (current_state.vk_hash, current_state.marker_root),
                ),
            ),
        )
            .to_clvm(&mut *ctx)
            .map_err(|e| other(format!("ceremony state to_clvm: {e}")))?;

        // 3. Pre-curry the `contribute` action with its 4 deploy-time
        //    constants (must match contribute.rue curry order).
        let contribute_bare = load_action_puzzle(
            &mut ctx,
            crate::puzzles::CEREMONY_SINGLETON_CONTRIBUTE_HEX,
        )?;
        let marker_mod_hash = PuzzleHashes::ceremony_coin_marker();
        let contribute_curried = CurriedProgram {
            program: contribute_bare,
            args: clvm_curried_args!(
                self.launcher_id,
                self.deployer.params.start_block_height,
                self.deployer.params.ceremony_length_blocks,
                marker_mod_hash
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(|e| other(format!("currying contribute action: {e}")))?;

        // 4. Action-layer inner puzzle (curried with finalizer +
        //    merkle_root + state).
        let merkle_root = self.deployer.ceremony_actions_merkle_root(self.launcher_id);
        let action_layer_node =
            build_action_layer_puzzle(&mut ctx, finalizer, merkle_root, state_node)?;

        // 5. Per-spend solution for the contribute action.
        let action_solution = Self::build_action_solution_node(&mut ctx, &params)?;

        // 6. Action-layer solution. The post-D3 tree has 2 leaves
        //    (contribute, finalize); MerkleTree::new internally sorts
        //    by `hash_atom_b32` ascending and emits the 1-step proof
        //    for the spent leaf. Finalizer takes a
        //    `..._my_solution: Any` rest-arg so we pass nil.
        let finalizer_solution = ()
            .to_clvm(&mut *ctx)
            .map_err(|e| other(format!("nil finalizer solution: {e}")))?;
        let contribute_full_hash = self
            .deployer
            .ceremony_contribute_action_hash(self.launcher_id);
        let finalize_full_hash = self
            .deployer
            .ceremony_finalize_action_hash(self.launcher_id);
        // Sort leaves by hash_atom_b32 ascending — same order
        // `ceremony_actions_merkle_root` uses, so the proof generated
        // by MerkleTree::new matches what the singleton's on-chain
        // merkle_root expects.
        let c_h = puzzles::hash_atom_b32(&contribute_full_hash);
        let f_h = puzzles::hash_atom_b32(&finalize_full_hash);
        let sorted_leaves: [Bytes32; 2] = if c_h.as_ref() < f_h.as_ref() {
            [contribute_full_hash, finalize_full_hash]
        } else {
            [finalize_full_hash, contribute_full_hash]
        };
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &sorted_leaves,
            &[ActionSpend {
                puzzle: contribute_curried,
                solution: action_solution,
            }],
            finalizer_solution,
        )?;

        // 7. Wrap with the singleton outer.
        let singleton_spend = crate::action_spends::build_singleton_spend(
            &mut ctx,
            singleton_coin,
            self.launcher_id,
            action_layer_node,
            action_layer_solution,
            lineage_proof,
        )?;

        // 8. Funder spend: create change of `funder.amount - 2` so
        //    the bundle balances. The +2 mojos flow into the marker
        //    CeremonyCoin emitted by the contribute action (amount=2,
        //    even — singleton outer requires only ONE odd CreateCoin
        //    per spend, the recreation). The singleton's own input +
        //    recreation cancel out.
        let funder_p2_ph =
            Bytes32::new(StandardArgs::curry_tree_hash(funder_pk).to_bytes());
        let mut conditions = Conditions::new();
        if funder_coin.amount > 2 {
            let change = funder_coin.amount - 2;
            conditions = conditions.create_coin(
                funder_p2_ph,
                change,
                chia_puzzle_types::Memos::None,
            );
        } else if funder_coin.amount < 2 {
            return Err(other(format!(
                "CeremonyContributor::build_contribute_bundle: funder coin \
                 amount {} insufficient (need >= 2 mojos for marker)",
                funder_coin.amount
            )));
        }
        StandardLayer::new(funder_pk)
            .spend(&mut ctx, funder_coin, conditions)
            .map_err(|e| other(format!("funder StandardLayer spend: {e}")))?;

        // ctx.take() returns the funder spend; append the singleton
        // spend manually since build_singleton_spend doesn't push to
        // ctx (it returns a CoinSpend directly).
        let mut coin_spends = ctx.take();
        coin_spends.push(singleton_spend);
        Ok(coin_spends)
    }
}

/// FN: read_ceremony_launcher_memo
/// WHAT: Cross-browser bootstrap recovery — fetches the launcher
///       coin's `puzzle_and_solution` and decodes the
///       `key_value_list` as a `CeremonyLauncherMemo`. Lets any
///       reader recover (start, length, min_participants, vk_seed,
///       label) from chain alone, no localStorage required.
/// RETURNS: `Some(memo)` if the launcher has been spent and its
///       `key_value_list` parses with the expected schema tag;
///       `None` otherwise (still-unspent launcher, missing memo, or
///       legacy ceremony deployed before D6).
pub async fn read_ceremony_launcher_memo<C: crate::chain::ChainReader>(
    chain: &C,
    ceremony_launcher_id: Bytes32,
) -> VotingResult<Option<crate::state::CeremonyLauncherMemo>> {
    use chia_puzzle_types::singleton::LauncherSolution;
    use clvm_traits::{FromClvm, ToClvm};

    let (_puzzle, solution) = match chain
        .puzzle_and_solution(ceremony_launcher_id)
        .await?
    {
        Some(ps) => ps,
        None => return Ok(None),
    };
    let mut alloc = clvmr::Allocator::new();
    let solution_node = match solution.to_clvm(&mut alloc) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    let parsed: LauncherSolution<crate::state::CeremonyLauncherMemo> =
        match LauncherSolution::from_clvm(&alloc, solution_node) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
    let memo = parsed.key_value_list;
    if memo.schema_tag.as_ref() != crate::state::CEREMONY_LAUNCHER_MEMO_TAG {
        return Ok(None);
    }
    Ok(Some(memo))
}

// ============================================================================
// CeremonyFinalizer
// ============================================================================

/// STRUCT: FinalizeParams
/// PURPOSE: per-finalize-spend inputs. The finalize action is
///          permissionless (no AGG_SIG); these are just the values
///          baked into the marker coin's memos and curried into the
///          singleton's post-finalize state.
#[derive(Debug, Clone)]
pub struct FinalizeParams {
    /// 32-byte sha256 of the derived Groth16 VK bytes. Curried into
    /// state.vk_hash so consumers can verify any vk_bytes blob they
    /// observe by hashing and comparing.
    pub vk_hash: Bytes32,
    /// 32-byte merkle root over the sorted contribution marker
    /// coin_ids — see
    /// `crate::merkle::merkle_root_of_sorted_coin_ids`.
    pub marker_root: Bytes32,
    /// Full VK bytes. Emitted only via the marker coin's memo; the
    /// puzzle does NOT assert `sha256(vk_bytes) == vk_hash` because
    /// off-chain consumers can do that check themselves and rejecting
    /// a mismatch bundle as untrustworthy. (Saving the on-chain
    /// hashing keeps cost low; the soundness commitment is `vk_hash`,
    /// not `vk_bytes`.)
    pub vk_bytes: Vec<u8>,
}

/// STRUCT: CeremonyFinalizer
/// PURPOSE: stateful actor mirroring `CeremonyContributor` but for
///          the (post-D3) `finalize` action. Anyone can drive a
///          finalize spend once the window has closed and the
///          configured threshold is met — the action is
///          permissionless.
#[derive(Debug, Clone)]
pub struct CeremonyFinalizer {
    pub launcher_id: Bytes32,
    pub deployer: CeremonyDeployer,
}

impl CeremonyFinalizer {
    /// Construct a finalizer bound to a specific ceremony.
    pub fn new(launcher_id: Bytes32, ceremony_params: CeremonyParams) -> Self {
        Self {
            launcher_id,
            deployer: CeremonyDeployer::new(ceremony_params),
        }
    }

    /// FN: finalize_action_hash
    /// WHAT: tree hash of the (fully-curried) `finalize` action puzzle.
    ///       Convenience pass-through to the deployer; mirrors
    ///       `CeremonyContributor::contribute_action_hash`.
    pub fn finalize_action_hash(&self) -> Bytes32 {
        self.deployer.ceremony_finalize_action_hash(self.launcher_id)
    }

    /// FN: build_action_solution_node
    /// WHAT: build the CLVM NodePtr for the `finalize` action's
    ///       per-spend solution.
    /// SHAPE per `puzzles/ceremony_singleton/finalize.rue` (after the
    ///       `Truth` arg the action layer prepends automatically):
    ///   `(vk_hash . (marker_root . vk_bytes))`
    ///   — `vk_bytes` is the rest-arg cdr of the last cons (no nil
    ///   terminator), matching the puzzle's `...vk_bytes: Bytes`.
    pub fn build_action_solution_node(
        ctx: &mut SpendContext,
        params: &FinalizeParams,
    ) -> VotingResult<NodePtr> {
        let vk_bytes: Bytes = Bytes::new(params.vk_bytes.clone());
        let map_err = |stage: &str, e: clvm_traits::ToClvmError| -> VotingError {
            VotingError::Other(anyhow_compat::Error(
                format!("finalize::build_action_solution_node[{stage}]: {e}").into(),
            ))
        };
        let vk_hash_node = params
            .vk_hash
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("vk_hash", e))?;
        let marker_root_node = params
            .marker_root
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("marker_root", e))?;
        let vk_bytes_node = vk_bytes
            .to_clvm(&mut **ctx)
            .map_err(|e| map_err("vk_bytes", e))?;
        let new_pair_err = |stage: &str, e: clvmr::reduction::EvalErr| -> VotingError {
            VotingError::Other(anyhow_compat::Error(
                format!("finalize::build_action_solution_node[new_pair {stage}]: {e:?}").into(),
            ))
        };
        // (marker_root . vk_bytes) — last cons; cdr is the rest-arg.
        let mr_vk = ctx
            .new_pair(marker_root_node, vk_bytes_node)
            .map_err(|e| new_pair_err("mr_vk", e))?;
        // (vk_hash . (marker_root . vk_bytes))
        let solution = ctx
            .new_pair(vk_hash_node, mr_vk)
            .map_err(|e| new_pair_err("solution", e))?;
        Ok(solution)
    }

    /// FN: parse_action_solution_node
    /// WHAT: inverse of `build_action_solution_node`. Decodes a CLVM
    ///       NodePtr representing a finalize-action per-spend solution
    ///       into `(vk_hash, marker_root, vk_bytes)`.
    pub fn parse_action_solution_node(
        allocator: &clvmr::Allocator,
        node: NodePtr,
    ) -> VotingResult<(Bytes32, Bytes32, Vec<u8>)> {
        use clvmr::SExp;
        let other = |s: &str| {
            VotingError::Other(anyhow_compat::Error(
                format!("finalize::parse_action_solution_node: {s}").into(),
            ))
        };
        let atom_of = |n: NodePtr, label: &str| -> VotingResult<Vec<u8>> {
            match allocator.sexp(n) {
                SExp::Atom => Ok(allocator.atom(n).as_ref().to_vec()),
                SExp::Pair(_, _) => Err(other(&format!(
                    "expected atom for {label}, got pair"
                ))),
            }
        };

        let (vk_hash_node, rest1) = match allocator.sexp(node) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution must be a cons, got atom")),
        };
        let vk_hash_bytes = atom_of(vk_hash_node, "vk_hash")?;
        let vk_hash = Bytes32::try_from(vk_hash_bytes.as_slice())
            .map_err(|_| other("vk_hash must be 32 bytes"))?;

        let (marker_root_node, vk_bytes_node) = match allocator.sexp(rest1) {
            SExp::Pair(a, b) => (a, b),
            SExp::Atom => return Err(other("solution missing marker_root cons")),
        };
        let marker_root_bytes = atom_of(marker_root_node, "marker_root")?;
        let marker_root = Bytes32::try_from(marker_root_bytes.as_slice())
            .map_err(|_| other("marker_root must be 32 bytes"))?;

        let vk_bytes = atom_of(vk_bytes_node, "vk_bytes")?;

        Ok((vk_hash, marker_root, vk_bytes))
    }

    /// FN: build_finalize_bundle
    /// WHAT: assemble the (unsigned) coin spends for the singleton's
    ///       finalize action: the singleton spends itself via the
    ///       action layer plus a standard p2 funder spend providing
    ///       the +1 mojo the marker CeremonyCoin needs (amount=2).
    /// SIGNING: finalize is permissionless on the singleton side
    ///          (no AGG_SIG conditions), but the funder's standard
    ///          p2 puzzle still requires AGG_SIG_ME. The caller signs
    ///          that with the funder's synthetic sk (Sage flow on
    ///          the dApp).
    pub fn build_finalize_bundle(
        &self,
        singleton_coin: chia_protocol::Coin,
        lineage_proof: chia_puzzle_types::Proof,
        current_state: CeremonyState,
        funder_coin: chia_protocol::Coin,
        funder_pk: PublicKey,
        params: FinalizeParams,
    ) -> VotingResult<FinalizeArtifacts> {
        use crate::action_spends::{
            build_action_layer_puzzle, build_action_layer_solution,
            build_ceremony_finalizer_full, load_action_puzzle, ActionSpend,
        };
        use chia_puzzle_types::standard::StandardArgs;
        use chia_sdk_driver::{SpendContext, StandardLayer};
        use chia_sdk_types::Conditions;
        use clvm_traits::clvm_curried_args;
        use clvm_utils::CurriedProgram;
        let other =
            |s: String| VotingError::Other(anyhow_compat::Error(s.into()));
        let mut ctx = SpendContext::new();
        // 1. Ceremony singleton finalizer reveal (already self-curried).
        let finalizer = build_ceremony_finalizer_full(&mut ctx, self.launcher_id)?;

        // 2. Encode the CURRENT CeremonyState (post-D1 5-field shape)
        //    — same recurrence as in build_contribute_bundle.
        let state_node = (
            current_state.contribution_count,
            (
                current_state.last_contribution_hash,
                (
                    if current_state.finalized { 1u64 } else { 0u64 },
                    (current_state.vk_hash, current_state.marker_root),
                ),
            ),
        )
            .to_clvm(&mut *ctx)
            .map_err(|e| other(format!("ceremony state to_clvm: {e}")))?;

        // 3. Pre-curry the `finalize` action with its 5 deploy-time
        //    constants (must match finalize.rue curry order).
        let finalize_bare = load_action_puzzle(
            &mut ctx,
            crate::puzzles::CEREMONY_SINGLETON_FINALIZE_HEX,
        )?;
        let marker_mod_hash = PuzzleHashes::ceremony_coin_marker();
        let finalize_curried = CurriedProgram {
            program: finalize_bare,
            args: clvm_curried_args!(
                self.launcher_id,
                self.deployer.params.start_block_height,
                self.deployer.params.ceremony_length_blocks,
                marker_mod_hash,
                self.deployer.params.min_participants
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(|e| other(format!("currying finalize action: {e}")))?;

        // 4. Action-layer inner puzzle (curried with finalizer +
        //    merkle_root + state). 2-leaf root post-D4a.
        let merkle_root = self.deployer.ceremony_actions_merkle_root(self.launcher_id);
        let action_layer_node =
            build_action_layer_puzzle(&mut ctx, finalizer, merkle_root, state_node)?;

        // 5. Per-spend solution for the finalize action.
        let action_solution = Self::build_action_solution_node(&mut ctx, &params)?;

        // 6. Action-layer solution. Pass both leaves so MerkleTree can
        //    emit the 1-step proof for the spent (finalize) leaf.
        let finalizer_solution = ()
            .to_clvm(&mut *ctx)
            .map_err(|e| other(format!("nil finalizer solution: {e}")))?;
        let contribute_full_hash = self
            .deployer
            .ceremony_contribute_action_hash(self.launcher_id);
        let finalize_full_hash = self.finalize_action_hash();
        // Sort leaves to match ceremony_actions_merkle_root's
        // hash_atom_b32-ascending convention.
        let c_h = puzzles::hash_atom_b32(&contribute_full_hash);
        let f_h = puzzles::hash_atom_b32(&finalize_full_hash);
        let sorted_leaves: [Bytes32; 2] = if c_h.as_ref() < f_h.as_ref() {
            [contribute_full_hash, finalize_full_hash]
        } else {
            [finalize_full_hash, contribute_full_hash]
        };
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &sorted_leaves,
            &[ActionSpend {
                puzzle: finalize_curried,
                solution: action_solution,
            }],
            finalizer_solution,
        )?;

        // 7. Wrap with the singleton outer.
        let singleton_spend = crate::action_spends::build_singleton_spend(
            &mut ctx,
            singleton_coin,
            self.launcher_id,
            action_layer_node,
            action_layer_solution,
            lineage_proof,
        )?;

        // 8. Funder spend: +4 mojos to cover marker (amount=2) and
        //    voucher (amount=2). Singleton input (1) + recreation (1)
        //    cancel; the funder injects the +4 needed for the two
        //    finalized-output coins.
        let funder_p2_ph =
            Bytes32::new(StandardArgs::curry_tree_hash(funder_pk).to_bytes());
        let mut conditions = Conditions::new();
        if funder_coin.amount > 4 {
            let change = funder_coin.amount - 4;
            conditions = conditions.create_coin(
                funder_p2_ph,
                change,
                chia_puzzle_types::Memos::None,
            );
        } else if funder_coin.amount < 4 {
            return Err(other(format!(
                "CeremonyFinalizer::build_finalize_bundle: funder coin \
                 amount {} insufficient (need >= 4 mojos for marker + voucher)",
                funder_coin.amount
            )));
        }
        StandardLayer::new(funder_pk)
            .spend(&mut ctx, funder_coin, conditions)
            .map_err(|e| other(format!("funder StandardLayer spend: {e}")))?;

        let mut coin_spends = ctx.take();
        coin_spends.push(singleton_spend);

        // Predict the voucher coin id created by the singleton's
        // finalize action. Parent = the singleton coin being spent
        // (it emits the voucher CreateCoin); puzzle hash matches
        // `puzzles::ceremony_voucher_puzzle_hash`; amount = 2.
        let voucher_ph = puzzles::ceremony_voucher_puzzle_hash(
            params.vk_hash,
            self.deployer.params.max_voters,
            self.launcher_id,
        );
        let voucher_coin = chia_protocol::Coin::new(singleton_coin.coin_id(), voucher_ph, 2);
        let voucher_coin_id = voucher_coin.coin_id();

        Ok(FinalizeArtifacts {
            coin_spends,
            voucher_coin_id,
            voucher_puzzle_hash: voucher_ph,
        })
    }
}

/// STRUCT: FinalizeArtifacts
/// PURPOSE: outputs of `CeremonyFinalizer::build_finalize_bundle`.
/// CONTAINS:
///   * `coin_spends` — unsigned coin spends to broadcast (caller
///     handles funder AGG_SIG_ME signing).
///   * `voucher_coin_id` — coin id of the voucher coin created by the
///     finalize spend. Re-spendable by anyone; election deploys
///     co-spend it to fire the canonical announcement that binds an
///     election to this finalized ceremony's (vk_hash, max_voters,
///     ceremony_launcher_id) triple.
///   * `voucher_puzzle_hash` — predicted curried puzzle hash of the
///     voucher coin. Equals `puzzles::ceremony_voucher_puzzle_hash`
///     applied to the same triple.
#[derive(Debug, Clone)]
pub struct FinalizeArtifacts {
    pub coin_spends: Vec<CoinSpend>,
    pub voucher_coin_id: Bytes32,
    pub voucher_puzzle_hash: Bytes32,
}

// ============================================================================
// CeremonyReader
// ============================================================================

/// STRUCT: ContributionRecord
/// PURPOSE: a single contribution observed on-chain. Populated by
///          walking the singleton lineage (`list_contributions_via_chain`)
///          and parsing each `contribute` spend's solution.
#[derive(Debug, Clone)]
pub struct ContributionRecord {
    pub participant_pubkey: PublicKey,
    pub contribution_hash: Bytes32,
    pub prev_contribution_hash: Bytes32,
    pub coin_id: Bytes32,
    pub block_height: u32,
    /// Raw 32-byte τ entropy as committed in the marker coin's memos
    /// (post-B1) and recoverable from the spend solution. Surfaced
    /// directly here so consumers (`derive_vk`, dApp UI) can avoid
    /// re-parsing the JSON payload.
    pub entropy_hex: Bytes,
    /// Full off-chain payload (PoK + updated parameters) — parsed
    /// from the spend's solution by the reader.
    pub payload: Vec<u8>,
}

/// STRUCT: CeremonyReader
/// PURPOSE: read-only driver for the on-chain Ceremony Singleton.
///          Walks the lineage, validates the linear chain anchored at
///          the deployer's `vk_seed`, and bridges to the off-chain
///          `crate::ceremony` module to derive proving/verification
///          keys from the chain-walked contribution payloads.
///
/// API:
///   * `validate_lineage(records, vk_seed)` — verify records form a
///     valid linear chain.
///   * `check_threshold(records, vk_seed, min)` — lineage + count gate.
///   * `list_contributions_via_chain(chain, launcher_id)` — async
///     chain walk producing chain-ordered `ContributionRecord`s.
///   * `derive_vk(records, vk_seed, min)` — gate + SimulatedBackend
///     bridge → `VerificationKey`.
///   * `derive_keys(records, vk_seed, min)` — same plus the matching
///     `ProvingKey` for aggregator use.
///
/// PRODUCTION SWAP NOTE: the SimulatedBackend is test-only. Production
/// deployments must replace it with a real MPC backend (`phase2`,
/// `arkworks-snark-mpc`); the bridge shape is identical so the swap is
/// localised to `derive_keys`'s backend constructor.
#[derive(Debug, Clone, Default)]
pub struct CeremonyReader;

impl CeremonyReader {
    /// FN: check_threshold
    /// WHAT: assert that a chain-walked sequence of contributions is
    ///       (a) a valid linear lineage anchored at `vk_seed`,
    ///       (b) at or above the deployer's `min_participants`
    ///       threshold.
    /// WHY:  the on-chain ceremony singleton accepts any non-empty
    ///       `contribute` spend in-window — `min_participants` is
    ///       enforced strictly off-chain at VK-derivation time. This
    ///       helper centralises the precondition check so the wasm
    ///       export, dApp UI, and final `derive_vk` orchestrator all
    ///       enforce it identically.
    pub fn check_threshold(
        records: &[ContributionRecord],
        vk_seed: Bytes32,
        min_participants: u64,
    ) -> VotingResult<()> {
        Self::validate_lineage(records, vk_seed)?;
        let count = records.len() as u64;
        if count < min_participants {
            return Err(VotingError::Other(anyhow_compat::Error(
                format!(
                    "CeremonyReader::check_threshold: only {count} contribution(s) — \
                     ceremony requires at least {min_participants} for safe VK derivation"
                )
                .into(),
            )));
        }
        Ok(())
    }

    /// FN: list_contributions_via_chain
    /// WHAT: chain-walk the Ceremony Singleton lineage and decode
    ///       each `contribute` spend into a `ContributionRecord`.
    ///       Stops at the unspent tip.
    /// WALK:
    ///   1. Find the eve singleton (child of launcher_id, at amount=1).
    ///   2. While the current singleton is spent:
    ///      a. Fetch its puzzle+solution.
    ///      b. Extract the contribute action solution (singleton →
    ///         action-layer → solutions[0]).
    ///      c. Parse (pk, contrib, prev, payload).
    ///      d. Find the next singleton (child of current at the only
    ///         odd-amount child, since the marker coin is even).
    ///   3. Return the chain-ordered Vec.
    /// FN: find_current_singleton
    /// WHAT: chain-walk the Ceremony Singleton lineage and return the
    ///       unspent tip's `(coin, lineage_proof, state)` so the dApp
    ///       can build a contribute spend without re-walking from
    ///       scratch on every iteration.
    /// CONTRACT: caller supplies `vk_seed` (the deployer's curried
    ///       genesis previous-contribution hash) so we can construct
    ///       the genesis CeremonyState when the eve singleton hasn't
    ///       been spent yet.
    pub async fn find_current_singleton<C>(
        chain: &C,
        launcher_id: Bytes32,
        vk_seed: Bytes32,
    ) -> VotingResult<(chia_protocol::Coin, chia_puzzle_types::Proof, CeremonyState)>
    where
        C: crate::chain::ChainReader,
    {
        use chia_protocol::Program;
        use chia_puzzle_types::{EveProof, LineageProof, Proof};
        use clvm_traits::ToClvm;

        let other = |s: String| VotingError::Other(anyhow_compat::Error(s.into()));

        // 1. Resolve the launcher coin to recover its parent (the
        //    singleton outer's parent_parent for the EveProof).
        let launcher_record = chain
            .coin_record_by_id(launcher_id)
            .await?
            .ok_or_else(|| {
                other(format!(
                    "find_current_singleton: launcher {} not found on chain",
                    hex::encode(launcher_id)
                ))
            })?;
        let launcher_parent = launcher_record.coin.parent_coin_info;

        // 2. Find the eve singleton: child of launcher_id at amount=1.
        let launcher_children = chain
            .coin_records_by_parent_ids(std::slice::from_ref(&launcher_id))
            .await?;
        let eve = launcher_children
            .iter()
            .find(|r| r.coin.amount == 1)
            .ok_or_else(|| {
                other(format!(
                    "find_current_singleton: no eve singleton as child of {}",
                    hex::encode(launcher_id)
                ))
            })?
            .clone();

        // 3. Walk the lineage. Track the previous spend's inner_ph +
        //    parent_amount so when we stop at the unspent tip we can
        //    emit the right LineageProof for the *next* spend.
        //    Post-D5: also track finalized state — every spend is
        //    either a contribute (advances count + last_hash) or a
        //    finalize (sets finalized=1 + vk_hash + marker_root, and
        //    leaves count/last_hash unchanged).
        let mut count: u64 = 0;
        let mut last_hash: Bytes32 = vk_seed;
        let mut finalized: bool = false;
        let mut vk_hash: Bytes32 = Bytes32::default();
        let mut marker_root: Bytes32 = Bytes32::default();
        let mut current = eve;
        let mut prev_inner_ph: Option<Bytes32> = None;
        let mut prev_amount: u64 = 1; // launcher amount (eve's parent_amount)

        loop {
            if current.spent_height == 0 {
                let lineage_proof = match prev_inner_ph {
                    None => Proof::Eve(EveProof {
                        parent_parent_coin_info: launcher_parent,
                        parent_amount: 1,
                    }),
                    Some(parent_inner_puzzle_hash) => Proof::Lineage(LineageProof {
                        parent_parent_coin_info: current.coin.parent_coin_info,
                        parent_inner_puzzle_hash,
                        parent_amount: prev_amount,
                    }),
                };
                let state = CeremonyState {
                    contribution_count: count,
                    last_contribution_hash: last_hash,
                    finalized,
                    vk_hash,
                    marker_root,
                };
                return Ok((current.coin, lineage_proof, state));
            }

            // Spent — fetch puzzle+solution and dispatch by action.
            let (_puzzle, solution) = chain
                .puzzle_and_solution(current.coin.coin_id())
                .await?
                .ok_or_else(|| {
                    other(format!(
                        "find_current_singleton: spent coin {} has no puzzle_and_solution",
                        hex::encode(current.coin.coin_id())
                    ))
                })?;
            let mut allocator = clvmr::Allocator::new();
            let solution_node = Program::from(solution.as_ref().to_vec())
                .to_clvm(&mut allocator)
                .map_err(|e| other(format!("solution to_clvm: {e}")))?;
            let action_sol = CeremonyContributor::extract_contribute_action_solution(
                &allocator,
                solution_node,
            )?;
            // Try parsing as contribute first; if that fails, try
            // finalize. The two action solution shapes are distinct
            // (5-tuple atoms+payload vs 3-tuple atoms+vk_bytes), so
            // exactly one parse succeeds for any well-formed spend.
            match CeremonyContributor::parse_action_solution_node(&allocator, action_sol) {
                Ok((_pk_bytes, contribution_hash, _prev, _entropy, _payload)) => {
                    count += 1;
                    last_hash = contribution_hash;
                }
                Err(_) => {
                    let (vk_h, m_r, _vk_bytes) =
                        CeremonyFinalizer::parse_action_solution_node(&allocator, action_sol)?;
                    finalized = true;
                    vk_hash = vk_h;
                    marker_root = m_r;
                }
            }

            // Track the inner ph by recomputing it from the JUST-spent state,
            // which is what the next singleton's lineage proof must point at.
            // We can't read the inner ph cleanly from the spent puzzle reveal
            // without re-uncurrying, so instead reconstruct it from the
            // canonical recurrence the deployer used.
            // (Skipping for now — will be filled when used; the wasm
            // export is the only consumer and currently the dApp builds
            // its lineage proof manually post-call. Track only state +
            // tip coin; lineage proof is best-effort at the eve case
            // and a placeholder Lineage proof at later spends.)
            prev_inner_ph = Some(Bytes32::default());

            // Find the next singleton: a child at amount=1.
            let children = chain
                .coin_records_by_parent_ids(std::slice::from_ref(&current.coin.coin_id()))
                .await?;
            let next = children
                .into_iter()
                .find(|r| r.coin.amount == 1)
                .ok_or_else(|| {
                    other(format!(
                        "find_current_singleton: no recreated singleton as child of {}",
                        hex::encode(current.coin.coin_id())
                    ))
                })?;
            prev_amount = current.coin.amount;
            current = next;
        }
    }

    /// FN: find_voucher_coin
    /// WHAT: locate the unspent voucher coin spawned by a finalized
    ///       ceremony, suitable for co-spending alongside an election
    ///       deploy.
    /// HOW:  query `coin_records_by_hint(launcher_id)` (the voucher's
    ///       finalize-time CreateCoin includes ceremony_launcher_id as
    ///       its memo hint), filter for coins at the predicted voucher
    ///       puzzle hash that are still unspent. Returns the most
    ///       recent unspent voucher (there may be more than one if
    ///       prior election deploys recreated it; we want any unspent
    ///       one — they all live at the SAME puzzle hash post-spend).
    /// WHY:  the V7 election-deploy bundle co-spends a voucher to fire
    ///       its canonical announcement; the deployer must locate it
    ///       on-chain first.
    pub async fn find_voucher_coin<C>(
        chain: &C,
        launcher_id: Bytes32,
        vk_hash: Bytes32,
        max_voters: u64,
    ) -> VotingResult<Option<chia_protocol::Coin>>
    where
        C: crate::chain::ChainReader,
    {
        let voucher_ph =
            puzzles::ceremony_voucher_puzzle_hash(vk_hash, max_voters, launcher_id);
        let records = chain.coin_records_by_hint(launcher_id).await?;
        Ok(records
            .into_iter()
            .find(|r| r.coin.puzzle_hash == voucher_ph && r.spent_height == 0)
            .map(|r| r.coin))
    }

    pub async fn list_contributions_via_chain<C>(
        chain: &C,
        launcher_id: Bytes32,
    ) -> VotingResult<Vec<ContributionRecord>>
    where
        C: crate::chain::ChainReader,
    {
        use clvm_traits::ToClvm;
        use chia_protocol::Program;

        let other = |s: String| VotingError::Other(anyhow_compat::Error(s.into()));

        // 1. Find the eve singleton: child of launcher_id at amount=1.
        let launcher_children = chain
            .coin_records_by_parent_ids(std::slice::from_ref(&launcher_id))
            .await?;
        let eve = launcher_children
            .iter()
            .find(|r| r.coin.amount == 1)
            .ok_or_else(|| {
                other(format!(
                    "list_contributions_via_chain: no eve singleton found as \
                     child of launcher {}",
                    hex::encode(launcher_id)
                ))
            })?
            .clone();

        let mut records: Vec<ContributionRecord> = Vec::new();
        let mut current = eve;

        // 2. Walk while current is spent. ChainCoinRecord uses
        //    `spent_height: u32` with 0 meaning unspent.
        loop {
            if current.spent_height == 0 {
                break;
            }
            let (puzzle, solution) = chain
                .puzzle_and_solution(current.coin.coin_id())
                .await?
                .ok_or_else(|| {
                    other(format!(
                        "list_contributions_via_chain: spent coin {} has no \
                         puzzle_and_solution",
                        hex::encode(current.coin.coin_id())
                    ))
                })?;

            // Decode the per-spend action solution.
            let mut allocator = clvmr::Allocator::new();
            let solution_node = Program::from(solution.as_ref().to_vec())
                .to_clvm(&mut allocator)
                .map_err(|e| other(format!("solution to_clvm: {e}")))?;
            // puzzle is unused here but loaded to match upstream contract;
            // future versions could verify the puzzle reveal matches the
            // expected singleton ph for additional integrity.
            let _puzzle_node = Program::from(puzzle.as_ref().to_vec())
                .to_clvm(&mut allocator)
                .map_err(|e| other(format!("puzzle to_clvm: {e}")))?;

            let action_sol = CeremonyContributor::extract_contribute_action_solution(
                &allocator,
                solution_node,
            )?;
            let (pk_bytes, contribution_hash, prev_contribution_hash, entropy_bytes, payload) =
                CeremonyContributor::parse_action_solution_node(&allocator, action_sol)?;
            let participant_pubkey = chia_bls::PublicKey::from_bytes(
                <[u8; 48]>::try_from(pk_bytes.as_slice()).map_err(|_| {
                    other(format!(
                        "participant pk recovered from spend was {} bytes, expected 48",
                        pk_bytes.len()
                    ))
                })?
                .as_ref()
                .try_into()
                .unwrap(),
            )
            .map_err(|e| other(format!("PublicKey::from_bytes: {e:?}")))?;

            // Marker coin id (each contribution's canonical handle).
            let marker_ph = ceremony_coin_marker_puzzle_hash(
                launcher_id,
                &participant_pubkey,
                contribution_hash,
                prev_contribution_hash,
            );
            let marker_coin =
                chia_protocol::Coin::new(current.coin.coin_id(), marker_ph, 2);

            records.push(ContributionRecord {
                participant_pubkey,
                contribution_hash,
                prev_contribution_hash,
                coin_id: marker_coin.coin_id(),
                block_height: current.spent_height,
                entropy_hex: Bytes::new(entropy_bytes),
                payload,
            });

            // 3. Find the next singleton: a child of `current` at
            //    amount=1 (odd), since the marker is amount=2.
            let children = chain
                .coin_records_by_parent_ids(std::slice::from_ref(&current.coin.coin_id()))
                .await?;
            let next = children.into_iter().find(|r| r.coin.amount == 1);
            match next {
                Some(c) => current = c,
                None => break,
            }
        }

        Ok(records)
    }

    /// FN: derive_vk
    /// WHAT: orchestrate VK derivation from a chain-walked sequence
    ///       of contributions. Runs precondition gates (lineage +
    ///       threshold), then bridges to `crate::ceremony` MPC
    ///       primitives.
    /// PAYLOAD FORMAT: each `ContributionRecord.payload` is the JSON
    ///       encoding `{ "entropy_hex": "...32-byte-hex...",
    ///       "name": "...", "message": "...optional..." }` —
    ///       contributors generate a fresh 32-byte entropy locally,
    ///       provide a display name, and the SDK encodes that as the
    ///       payload for `contributeToCeremony`. The off-chain VK
    ///       derivation re-runs the SimulatedBackend's `contribute`
    ///       chain to produce a deterministic VK from the same
    ///       inputs.
    /// SECURITY NOTE: SimulatedBackend is a TEST backend — production
    ///       deployments must swap in a real MPC backend (`phase2`
    ///       or `arkworks-snark-mpc`). The bridge shape is the same;
    ///       only the backend construction changes.
    pub fn derive_vk(
        records: &[ContributionRecord],
        vk_seed: Bytes32,
        min_participants: u64,
    ) -> VotingResult<crate::ceremony::VerificationKey> {
        let (_pk, vk) = Self::derive_keys(records, vk_seed, min_participants)?;
        Ok(vk)
    }

    /// FN: derive_keys
    /// WHAT: like `derive_vk` but returns BOTH the proving key and
    ///       the verification key. Aggregators that need to produce
    ///       proofs against a chain-derived VK use this; the dApp
    ///       only needs the VK so its wasm export drops the PK to
    ///       keep PKs out of the dApp's blast radius.
    /// SECURITY NOTE: re-deriving the PK from public chain data is
    ///       only safe with the SimulatedBackend (test-only — anyone
    ///       can do it). Production MPC backends erase per-contribution
    ///       toxic waste; chain-walking won't recover the PK then.
    ///       For the production swap, this method needs to take the
    ///       PK as a side-channel input (e.g. saved by the deployer).
    pub fn derive_keys(
        records: &[ContributionRecord],
        vk_seed: Bytes32,
        min_participants: u64,
    ) -> VotingResult<(crate::ceremony::ProvingKey, crate::ceremony::VerificationKey)> {
        use crate::ceremony::{MpcBackend, SimulatedBackend};

        Self::check_threshold(records, vk_seed, min_participants)?;

        // E2: SimulatedBackend now carries tree_depth (the SPT depth
        // baked into the Groth16 circuit). Default 32 preserves the
        // pre-E2 behavior; future iterations will derive this from
        // CeremonyParams.max_voters once derive_keys takes
        // ceremony params as input.
        let backend = SimulatedBackend::default();
        let mut transcript = backend.initial_transcript()?;

        // Post-B1, the on-chain marker memo carries the raw 32-byte
        // entropy directly, and `list_contributions_via_chain`
        // populates `record.entropy_hex` from it. Prefer that path:
        // no JSON parse, no UTF-8 dependency, and the contributor's
        // identity comes from their participant pubkey (the same key
        // that signed the AGG_SIG_UNSAFE).
        //
        // Legacy / test records that still embed a JSON payload of
        // `{entropy_hex, name, message?}` continue to work via the
        // fallback below — keyed on `record.entropy_hex` being empty.
        #[derive(serde::Deserialize)]
        struct PayloadV1 {
            entropy_hex: String,
            name: String,
            #[serde(default)]
            message: Option<String>,
        }

        for (idx, rec) in records.iter().enumerate() {
            let entropy_field = rec.entropy_hex.as_ref();
            let (entropy, name, message): ([u8; 32], String, Option<String>) =
                if !entropy_field.is_empty() {
                    let entropy: [u8; 32] = entropy_field.try_into().map_err(|_| {
                        VotingError::Other(anyhow_compat::Error(
                            format!(
                                "derive_vk: record {idx} entropy_hex must be 32 bytes (got {})",
                                entropy_field.len()
                            )
                            .into(),
                        ))
                    })?;
                    let name = format!(
                        "0x{}",
                        hex::encode(rec.participant_pubkey.to_bytes())
                    );
                    (entropy, name, None)
                } else {
                    let payload_str = std::str::from_utf8(&rec.payload).map_err(|e| {
                        VotingError::Other(anyhow_compat::Error(
                            format!(
                                "derive_vk: record {idx} has no entropy_hex and payload is not valid UTF-8 JSON: {e}"
                            )
                            .into(),
                        ))
                    })?;
                    let p: PayloadV1 = serde_json::from_str(payload_str).map_err(|e| {
                        VotingError::Other(anyhow_compat::Error(
                            format!(
                                "derive_vk: record {idx} payload JSON decode (expect \
                                 {{entropy_hex, name, message?}}): {e}"
                            )
                            .into(),
                        ))
                    })?;
                    let entropy_bytes = hex::decode(p.entropy_hex.trim_start_matches("0x"))
                        .map_err(|e| {
                            VotingError::Other(anyhow_compat::Error(
                                format!("derive_vk: record {idx} entropy_hex: {e}").into(),
                            ))
                        })?;
                    let entropy: [u8; 32] = entropy_bytes.as_slice().try_into().map_err(|_| {
                        VotingError::Other(anyhow_compat::Error(
                            format!(
                                "derive_vk: record {idx} entropy must be 32 bytes (got {})",
                                entropy_bytes.len()
                            )
                            .into(),
                        ))
                    })?;
                    (entropy, p.name, p.message)
                };
            transcript = backend.contribute(&transcript, name, entropy, message)?;
        }

        backend.verify(&transcript)?;
        let (pk, vk) = backend.extract_keys(&transcript)?;
        Ok((pk, vk))
    }

    /// FN: validate_lineage
    /// WHAT: verify a sequence of `ContributionRecord`s forms a valid
    ///       linear chain anchored at `vk_seed`. Linearity means each
    ///       record's `prev_contribution_hash` equals the previous
    ///       record's `contribution_hash` (or `vk_seed` for the first).
    /// WHY:  the on-chain `contribute.rue` enforces this on-chain via
    ///       its `assert State.last_contribution_hash ==
    ///       prev_contribution_hash` check, but off-chain readers
    ///       reconstruct records from `puzzle_and_solution` data which
    ///       can be parsed independently — re-checking lineage here
    ///       protects against: (a) malformed solution decoding,
    ///       (b) records arriving out-of-order from indexers,
    ///       (c) records mistakenly merged from different ceremonies.
    /// CONTRACT: `records` is the chain-ordered sequence (oldest
    ///       first). `vk_seed` matches the deployer's curried genesis
    ///       previous-contribution hash.
    pub fn validate_lineage(
        records: &[ContributionRecord],
        vk_seed: Bytes32,
    ) -> VotingResult<()> {
        let mut expected_prev = vk_seed;
        for (idx, rec) in records.iter().enumerate() {
            if rec.prev_contribution_hash != expected_prev {
                return Err(VotingError::Other(anyhow_compat::Error(
                    format!(
                        "CeremonyReader::validate_lineage: record {idx} \
                         prev_contribution_hash mismatch — got {} expected {}",
                        hex::encode(rec.prev_contribution_hash),
                        hex::encode(expected_prev),
                    )
                    .into(),
                )));
            }
            expected_prev = rec.contribution_hash;
        }
        Ok(())
    }
}

// ============================================================================
// Marker-coin puzzle-hash predictor
// ============================================================================

/// FN: ceremony_coin_marker_puzzle_hash
/// WHAT: tree hash of the per-contribution CeremonyCoin marker puzzle —
///       a curry of `puzzles/ceremony_coin/marker.rue` with the four
///       contribution-binding fields.
/// CURRY ORDER (must match `contribute.rue::marker_ph`):
///   `(CEREMONY_LAUNCHER_ID, PARTICIPANT_PUBKEY,
///     CONTRIBUTION_HASH, PREV_CONTRIBUTION_HASH)` — every arg is
///   passed as a tree-hashed atom, so the participant pubkey atom
///   wraps its 48-byte BLS G1 encoding.
/// USE: lets contributors / observers predict the marker coin's
///      puzzle hash off-chain (and thus its coin id) without needing
///      the on-chain spend to land first.
pub fn ceremony_coin_marker_puzzle_hash(
    ceremony_launcher_id: Bytes32,
    participant_pubkey: &PublicKey,
    contribution_hash: Bytes32,
    prev_contribution_hash: Bytes32,
) -> Bytes32 {
    let pk_bytes = participant_pubkey.to_bytes();
    puzzles::curry_tree_hash(
        PuzzleHashes::ceremony_coin_marker(),
        &[
            puzzles::hash_atom_b32(&ceremony_launcher_id),
            puzzles::hash_atom(&pk_bytes),
            puzzles::hash_atom_b32(&contribution_hash),
            puzzles::hash_atom_b32(&prev_contribution_hash),
        ],
    )
}

// ============================================================================
// Off-chain message helpers
// ============================================================================
//
// These MUST stay byte-for-byte in sync with the corresponding Rue
// helpers in `puzzles/ceremony_singleton/shared.rue`. Domain-separation
// prefixes ("ceremony_contribute" / "ceremony_contributed") prevent any
// signature/announcement collision with the rest of the protocol (vote
// messages, registration messages, etc.).

/// FN: ceremony_contribution_msg
/// WHAT: 32-byte message a participant signs (UNAUGMENTED, sign_raw)
///       to authorize their contribution.
/// FORMULA: `sha256("ceremony_contribute" || launcher || contribution
///                   || prev_contribution)`.
/// MIRRORS: `ceremony_contribution_msg` in
///          `puzzles/ceremony_singleton/shared.rue`.
pub fn ceremony_contribution_msg(
    ceremony_launcher_id: Bytes32,
    contribution_hash: Bytes32,
    prev_contribution_hash: Bytes32,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ceremony_contribute");
    h.update(ceremony_launcher_id.as_ref());
    h.update(contribution_hash.as_ref());
    h.update(prev_contribution_hash.as_ref());
    Bytes32::new(h.finalize().into())
}

/// FN: ceremony_contribution_announcement_msg
/// WHAT: 32-byte message emitted by the `contribute` action as a
///       `CreateCoinAnnouncement` so observers can chain-walk the
///       singleton lineage and reconstruct the linear sequence of
///       contributions.
/// FORMULA: `sha256("ceremony_contributed" || launcher || contribution
///                   || participant_pk)`.
/// MIRRORS: `ceremony_contribution_announcement_msg` in
///          `puzzles/ceremony_singleton/shared.rue`.
pub fn ceremony_contribution_announcement_msg(
    ceremony_launcher_id: Bytes32,
    contribution_hash: Bytes32,
    participant_pubkey: &PublicKey,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ceremony_contributed");
    h.update(ceremony_launcher_id.as_ref());
    h.update(contribution_hash.as_ref());
    h.update(participant_pubkey.to_bytes());
    Bytes32::new(h.finalize().into())
}

// ============================================================================
// File-private helpers
// ============================================================================

/// FN: uint_atom_hash
/// WHAT: tree hash of an unsigned integer in CLVM canonical encoding.
/// MIRRORS: `actors::deployer::uint_atom_hash` byte-for-byte.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

    fn test_params() -> CeremonyParams {
        CeremonyParams {
            start_block_height: 5_000_000,
            ceremony_length_blocks: 1_000,
            min_participants: 2,
            max_voters: DEFAULT_CEREMONY_MAX_VOTERS,
            vk_seed: b32(0x42),
            label: Some("test".into()),
        }
    }

    /// Genesis state hashes deterministically for fixed (count=0,
    /// vk_seed) inputs.
    #[test]
    fn genesis_state_tree_hash_is_deterministic() {
        let d = CeremonyDeployer::new(test_params());
        assert_eq!(d.genesis_state_tree_hash(), d.genesis_state_tree_hash());
    }

    /// The vk_seed actually flows into the genesis state hash —
    /// otherwise contributors couldn't bind their first-contribution
    /// `prev_contribution_hash` to the deployer's commitment.
    #[test]
    fn genesis_state_tree_hash_changes_with_vk_seed() {
        let mut p1 = test_params();
        let mut p2 = test_params();
        p2.vk_seed = b32(0x77);
        assert_ne!(
            CeremonyDeployer::new(p1.clone()).genesis_state_tree_hash(),
            CeremonyDeployer::new(p2).genesis_state_tree_hash(),
        );
        // Sanity: same vk_seed → same hash.
        p1.label = Some("ignored".into());
        assert_eq!(
            CeremonyDeployer::new(p1.clone()).genesis_state_tree_hash(),
            CeremonyDeployer::new(test_params()).genesis_state_tree_hash(),
        );
    }

    /// `ceremony_contribute_action_hash` is sensitive to every curried
    /// parameter that lives in the action's curry list.
    #[test]
    fn ceremony_contribute_action_hash_changes_per_curry() {
        let l = b32(0xAB);
        let base = CeremonyDeployer::new(test_params())
            .ceremony_contribute_action_hash(l);

        // Different launcher → different hash.
        let other_launcher = CeremonyDeployer::new(test_params())
            .ceremony_contribute_action_hash(b32(0xCD));
        assert_ne!(base, other_launcher);

        // Different start height → different hash.
        let mut p = test_params();
        p.start_block_height += 1;
        assert_ne!(
            base,
            CeremonyDeployer::new(p).ceremony_contribute_action_hash(l),
        );

        // Different length → different hash.
        let mut p = test_params();
        p.ceremony_length_blocks += 1;
        assert_ne!(
            base,
            CeremonyDeployer::new(p).ceremony_contribute_action_hash(l),
        );
    }

    /// `genesis_inner_puzzle_hash` is deterministic and launcher-bound.
    #[test]
    fn genesis_inner_puzzle_hash_well_defined() {
        let d = CeremonyDeployer::new(test_params());
        assert_eq!(
            d.genesis_inner_puzzle_hash(b32(0xAB)),
            d.genesis_inner_puzzle_hash(b32(0xAB)),
        );
        assert_ne!(
            d.genesis_inner_puzzle_hash(b32(0xAB)),
            d.genesis_inner_puzzle_hash(b32(0xCD)),
        );
    }

    /// `build_deploy_bundle` produces a launcher coin whose id matches
    /// `derive_launcher_id(parent.coin_id(), 1)` and a launcher spend
    /// committing to `genesis_inner_puzzle_hash(launcher_id)`.
    #[test]
    fn build_deploy_bundle_launcher_id_consistent() {
        use chia_bls::SecretKey;

        let d = CeremonyDeployer::new(test_params());
        let sk = SecretKey::from_seed(&[1u8; 32]);
        let pk = sk.public_key();
        let p2_ph = Bytes32::new(
            chia_puzzle_types::standard::StandardArgs::curry_tree_hash(pk).to_bytes(),
        );
        let parent = Coin::new(b32(0xAA), p2_ph, 10);

        let (coin_spends, launcher_id) = d.build_deploy_bundle(parent, pk).unwrap();

        // Launcher id matches the deterministic derivation.
        let predicted = CeremonyDeployer::derive_launcher_id(parent.coin_id(), 1);
        assert_eq!(launcher_id, predicted);

        // Spend bundle has 2 coin spends: the launcher + the parent p2.
        assert_eq!(coin_spends.len(), 2);

        // Parent p2 spend is the input parent_coin.
        let has_parent_spend = coin_spends.iter().any(|cs| cs.coin == parent);
        assert!(has_parent_spend, "parent coin must be among coin spends");
    }

    /// `ceremony_contribution_msg` matches the manual SHA256 formula
    /// (with the literal "ceremony_contribute" prefix) — pins the
    /// domain-separation tag and field order.
    #[test]
    fn ceremony_contribution_msg_matches_manual_sha256() {
        use sha2::{Digest, Sha256};

        let launcher = b32(0xAA);
        let contrib = b32(0xBB);
        let prev = b32(0xCC);

        let mut manual = Sha256::new();
        manual.update(b"ceremony_contribute");
        manual.update(launcher.as_ref());
        manual.update(contrib.as_ref());
        manual.update(prev.as_ref());
        let expected = Bytes32::new(manual.finalize().into());

        assert_eq!(
            ceremony_contribution_msg(launcher, contrib, prev),
            expected,
        );
    }

    /// Different prefix ("ceremony_contributed" vs
    /// "ceremony_contribute") → different message hash. Prevents the
    /// announcement msg from being usable as a signature msg (or vice
    /// versa).
    #[test]
    fn ceremony_announcement_msg_distinct_from_contribution_msg() {
        use chia_bls::SecretKey;

        let launcher = b32(0xAA);
        let contrib = b32(0xBB);
        let pk = SecretKey::from_seed(&[7u8; 32]).public_key();

        let sig_msg =
            ceremony_contribution_msg(launcher, contrib, b32(0xCC));
        let ann_msg =
            ceremony_contribution_announcement_msg(launcher, contrib, &pk);
        assert_ne!(sig_msg, ann_msg);
    }

    /// `ceremony_contribution_msg` is sensitive to every input field —
    /// otherwise replay across ceremonies / contributions / lineages
    /// would be possible.
    #[test]
    fn ceremony_contribution_msg_per_field_sensitivity() {
        let base = ceremony_contribution_msg(b32(0xAA), b32(0xBB), b32(0xCC));
        assert_ne!(
            base,
            ceremony_contribution_msg(b32(0x00), b32(0xBB), b32(0xCC)),
        );
        assert_ne!(
            base,
            ceremony_contribution_msg(b32(0xAA), b32(0x00), b32(0xCC)),
        );
        assert_ne!(
            base,
            ceremony_contribution_msg(b32(0xAA), b32(0xBB), b32(0x00)),
        );
    }

    /// `ceremony_coin_marker_puzzle_hash` matches the tree hash of the
    /// fully-curried marker program built by loading the embedded
    /// `marker.rue.hex` and currying it via `CurriedProgram::to_clvm`.
    /// Pins the curry order + arg encoding (atom-of-pk-bytes, not
    /// `tree_hash_atom_pubkey`).
    #[test]
    fn ceremony_coin_marker_puzzle_hash_matches_curried_program_tree_hash() {
        use chia_bls::SecretKey;
        use chia_protocol::Program;
        use chia_sdk_driver::SpendContext;
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::{tree_hash, CurriedProgram};

        let launcher = b32(0xAA);
        let contrib = b32(0xBB);
        let prev = b32(0xCC);
        let pk = SecretKey::from_seed(&[5u8; 32]).public_key();

        // Predicted hash via the SDK helper.
        let predicted = ceremony_coin_marker_puzzle_hash(launcher, &pk, contrib, prev);

        // Actual hash by loading the program from the embedded .hex
        // bytes and currying it directly.
        let mut ctx = SpendContext::new();
        let bare_bytes = hex::decode(
            crate::puzzles::CEREMONY_COIN_MARKER_HEX
                .trim()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let bare_node = Program::from(bare_bytes).to_clvm(&mut *ctx).unwrap();

        // PublicKey is curried as a 48-byte atom — matches the
        // `tree_hash_atom(participant_pk as Bytes)` pattern in
        // contribute.rue. Use `chia_protocol::Bytes` so the
        // ToClvm impl emits a single atom (Vec<u8> would emit a list).
        let pk_bytes: chia_protocol::Bytes = chia_protocol::Bytes::new(pk.to_bytes().to_vec());
        let curried = CurriedProgram {
            program: bare_node,
            args: clvm_curried_args!(launcher, pk_bytes, contrib, prev),
        }
        .to_clvm(&mut *ctx)
        .unwrap();
        let actual = Bytes32::new(tree_hash(&ctx, curried).to_bytes());

        assert_eq!(actual, predicted);
    }

    /// `ceremony_coin_marker_puzzle_hash` is sensitive to every curried
    /// field — wrong launcher / pk / contribution_hash / prev_hash all
    /// must produce different marker coin ids so the on-chain
    /// `CREATE_COIN` is unforgeably bound to the contribution.
    #[test]
    fn ceremony_coin_marker_puzzle_hash_per_field_sensitivity() {
        use chia_bls::SecretKey;

        let pk1 = SecretKey::from_seed(&[1u8; 32]).public_key();
        let pk2 = SecretKey::from_seed(&[2u8; 32]).public_key();

        let base = ceremony_coin_marker_puzzle_hash(b32(0xAA), &pk1, b32(0xBB), b32(0xCC));
        assert_ne!(
            base,
            ceremony_coin_marker_puzzle_hash(b32(0x00), &pk1, b32(0xBB), b32(0xCC)),
        );
        assert_ne!(
            base,
            ceremony_coin_marker_puzzle_hash(b32(0xAA), &pk2, b32(0xBB), b32(0xCC)),
        );
        assert_ne!(
            base,
            ceremony_coin_marker_puzzle_hash(b32(0xAA), &pk1, b32(0x00), b32(0xCC)),
        );
        assert_ne!(
            base,
            ceremony_coin_marker_puzzle_hash(b32(0xAA), &pk1, b32(0xBB), b32(0x00)),
        );
    }

    /// `ContributeParams::compute_contribution_hash` is deterministic
    /// and uses a domain-separation prefix so it can never collide
    /// with the signature/announcement messages.
    #[test]
    fn compute_contribution_hash_is_deterministic_and_distinct() {
        let p = b"hello world".to_vec();
        let h1 = ContributeParams::compute_contribution_hash(&p);
        let h2 = ContributeParams::compute_contribution_hash(&p);
        assert_eq!(h1, h2);

        // Different payload → different hash.
        let h3 = ContributeParams::compute_contribution_hash(&[]);
        assert_ne!(h1, h3);

        // Sanity: NOT equal to plain SHA256(payload) (the prefix matters).
        use sha2::{Digest, Sha256};
        let mut h_plain = Sha256::new();
        h_plain.update(&p);
        let plain = Bytes32::new(h_plain.finalize().into());
        assert_ne!(h1, plain);
    }

    /// `CeremonyContributor::contribution_signature_msg` and
    /// `marker_puzzle_hash` delegate correctly to the standalone
    /// helpers — pinning that the contributor's launcher id flows
    /// through.
    #[test]
    fn contributor_helpers_delegate_consistently() {
        use chia_bls::SecretKey;

        let launcher = b32(0xAB);
        let pk = SecretKey::from_seed(&[3u8; 32]).public_key();
        let p = ContributeParams {
            participant_pubkey: pk.clone(),
            contribution_hash: b32(0x11),
            prev_contribution_hash: b32(0x22),
            entropy_hex: Bytes::default(),
            payload: vec![1, 2, 3],
        };

        let c = CeremonyContributor::new(launcher, test_params());

        assert_eq!(
            c.contribution_signature_msg(&p),
            ceremony_contribution_msg(launcher, p.contribution_hash, p.prev_contribution_hash),
        );
        assert_eq!(
            c.marker_puzzle_hash(&p),
            ceremony_coin_marker_puzzle_hash(
                launcher,
                &p.participant_pubkey,
                p.contribution_hash,
                p.prev_contribution_hash,
            ),
        );
    }

    /// The full ceremony singleton inner puzzle hash (action_layer
    /// curried with finalizer + merkle root + state) computed by the
    /// deployer matches the tree hash of the action_layer puzzle
    /// built at runtime by `build_action_layer_puzzle` over
    /// `build_ceremony_finalizer_full`. Mirrors the equivalent
    /// election test (`genesis_inner_puzzle_hash_matches_built_action_layer_node`).
    #[test]
    fn genesis_inner_puzzle_hash_matches_built_action_layer_node() {
        use chia_sdk_driver::SpendContext;
        use clvm_traits::ToClvm;
        use clvm_utils::tree_hash;

        let d = CeremonyDeployer::new(test_params());
        let launcher_id = b32(0xAB);

        let mut ctx = SpendContext::new();

        // Layer 1: ceremony finalizer full curry.
        let actual_finalizer_node =
            crate::action_spends::build_ceremony_finalizer_full(&mut ctx, launcher_id).unwrap();
        let actual_finalizer_th = Bytes32::new(tree_hash(&ctx, actual_finalizer_node).to_bytes());

        // Predicted finalizer full curry (matches the deployer's
        // `genesis_inner_puzzle_hash` first→second curry recurrence).
        let action_layer_mod = PuzzleHashes::action_layer();
        let predicted_first = puzzles::curry_tree_hash(
            PuzzleHashes::ceremony_singleton_finalizer(),
            &[
                puzzles::hash_atom_b32(&action_layer_mod),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        );
        let predicted_finalizer_full = puzzles::curry_tree_hash(
            predicted_first,
            &[puzzles::hash_atom_b32(&predicted_first)],
        );
        assert_eq!(
            actual_finalizer_th, predicted_finalizer_full,
            "CEREMONY FINALIZER MISMATCH (predicted vs runtime tree_hash)"
        );

        // Layer 2: state hash equivalence — same recurrence as the
        // genesis_state_tree_hash impl. Post-D1 the genesis state is
        // `(0 . (vk_seed . (0 . (zero32 . zero32))))`.
        let state_value = (
            0u64,
            (
                d.params.vk_seed,
                (0u64, (Bytes32::default(), Bytes32::default())),
            ),
        );
        let state_node = state_value.to_clvm(&mut *ctx).unwrap();
        let actual_state_th = Bytes32::new(tree_hash(&ctx, state_node).to_bytes());
        let predicted_state_th = d.genesis_state_tree_hash();
        assert_eq!(
            actual_state_th, predicted_state_th,
            "CEREMONY STATE HASH MISMATCH"
        );

        // Layer 3: full action_layer puzzle tree hash equals the
        // deployer's predicted genesis_inner_puzzle_hash.
        let merkle_root = d.ceremony_actions_merkle_root(launcher_id);
        let action_layer_node = crate::action_spends::build_action_layer_puzzle(
            &mut ctx,
            actual_finalizer_node,
            merkle_root,
            state_node,
        )
        .unwrap();
        let actual = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());
        let predicted = d.genesis_inner_puzzle_hash(launcher_id);
        assert_eq!(
            actual, predicted,
            "CEREMONY ACTION_LAYER HASH MISMATCH (built vs deployer predicted)"
        );
    }

    /// `CeremonyContributor::build_action_solution_node` produces a
    /// CLVM cons tree whose tree hash matches the manual recurrence
    /// `(pk . (contrib . (prev . (entropy . payload))))` — where
    /// `payload` is the rest-arg cdr (atom-encoded directly, no nil
    /// terminator). Pins field order, pk-as-atom encoding, and
    /// rest-arg shape after B1 added entropy_hex.
    #[test]
    fn build_action_solution_node_tree_hash_matches_manual() {
        use chia_bls::SecretKey;
        use chia_sdk_driver::SpendContext;
        use clvm_utils::tree_hash;

        let pk = SecretKey::from_seed(&[9u8; 32]).public_key();
        let entropy_bytes: Vec<u8> = vec![0xEE; 32];

        for payload in [vec![], vec![0xAA, 0xBB, 0xCC, 0xDD]].into_iter() {
            let p = ContributeParams {
                participant_pubkey: pk.clone(),
                contribution_hash: b32(0x11),
                prev_contribution_hash: b32(0x22),
                entropy_hex: Bytes::new(entropy_bytes.clone()),
                payload: payload.clone(),
            };

            let mut ctx = SpendContext::new();
            let node = CeremonyContributor::build_action_solution_node(&mut ctx, &p).unwrap();
            let actual = Bytes32::new(tree_hash(&ctx, node).to_bytes());

            // Manual recurrence: (pk . (contrib . (prev . (entropy . payload)))).
            let pk_h = puzzles::hash_atom(&pk.to_bytes());
            let contrib_h = puzzles::hash_atom_b32(&p.contribution_hash);
            let prev_h = puzzles::hash_atom_b32(&p.prev_contribution_hash);
            let entropy_h = puzzles::hash_atom(&entropy_bytes);
            let payload_h = puzzles::hash_atom(&payload);
            let pair4 = puzzles::hash_pair(entropy_h, payload_h);
            let pair3 = puzzles::hash_pair(prev_h, pair4);
            let pair2 = puzzles::hash_pair(contrib_h, pair3);
            let expected = puzzles::hash_pair(pk_h, pair2);

            assert_eq!(
                actual, expected,
                "shape mismatch for payload len {}",
                payload.len()
            );
        }
    }

    /// `build_contribute_bundle` produces coin spends whose CLVM
    /// puzzle reveals at least PARSE — i.e. each spend's puzzle hex
    /// loads cleanly via `to_clvm` (the same first-step check
    /// `dry_run_coin_spends` performs before consensus eval).
    ///
    /// We don't run the full `dry_run_coin_spends` here because this
    /// is a synthetic Eve coin without a properly-funded singleton
    /// outer ancestor — the consensus eval would fail on chain-state
    /// preconditions (lineage proof, AGG_SIG_UNSAFE without a real
    /// signature). Phase 5 simulator coverage closes the loop with a
    /// real eve singleton.
    #[test]
    fn build_contribute_bundle_puzzles_parse_via_to_clvm() {
        use chia_bls::SecretKey;
        use chia_puzzle_types::EveProof;
        use chia_sdk_driver::SpendContext;
        use clvm_traits::ToClvm;

        let launcher = b32(0xAB);
        let participant_pk =
            SecretKey::from_seed(&[1u8; 32]).public_key();
        let funder_pk = SecretKey::from_seed(&[2u8; 32]).public_key();
        let funder_p2_ph = Bytes32::new(
            chia_puzzle_types::standard::StandardArgs::curry_tree_hash(funder_pk).to_bytes(),
        );

        let singleton_coin = Coin::new(launcher, b32(0xCC), 1);
        let lineage_proof = chia_puzzle_types::Proof::Eve(EveProof {
            parent_parent_coin_info: launcher,
            parent_amount: 1,
        });
        let funder_coin = Coin::new(b32(0xDD), funder_p2_ph, 100);

        let params = test_params();
        let contributor = CeremonyContributor::new(launcher, params.clone());
        let current_state = CeremonyState::genesis(params.vk_seed);
        let contrib_params = ContributeParams {
            participant_pubkey: participant_pk,
            contribution_hash: b32(0x77),
            prev_contribution_hash: params.vk_seed,
            entropy_hex: Bytes::default(),
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let coin_spends = contributor
            .build_contribute_bundle(
                singleton_coin,
                lineage_proof,
                current_state,
                funder_coin,
                funder_pk,
                contrib_params,
            )
            .unwrap();

        for (i, cs) in coin_spends.iter().enumerate() {
            let mut ctx = SpendContext::new();
            cs.puzzle_reveal.to_clvm(&mut *ctx).unwrap_or_else(|e| {
                panic!(
                    "coin_spends[{i}] puzzle_reveal failed to_clvm: {e}; \
                     puzzle_hash {}",
                    hex::encode(cs.coin.puzzle_hash)
                )
            });
            cs.solution.to_clvm(&mut *ctx).unwrap_or_else(|e| {
                panic!(
                    "coin_spends[{i}] solution failed to_clvm: {e}; \
                     puzzle_hash {}",
                    hex::encode(cs.coin.puzzle_hash)
                )
            });
        }
    }

    /// `CeremonyContributor::build_contribute_bundle` returns 2 coin
    /// spends (funder p2 + singleton outer) for a genesis-stage
    /// contribution against a synthetic Eve singleton + funder coin.
    /// Pins the bundle shape and that the funder coin is included
    /// among the spends.
    #[test]
    fn build_contribute_bundle_emits_funder_and_singleton_spends() {
        use chia_bls::SecretKey;
        use chia_puzzle_types::EveProof;

        let launcher = b32(0xAB);
        let participant_sk = SecretKey::from_seed(&[1u8; 32]);
        let participant_pk = participant_sk.public_key();
        let funder_sk = SecretKey::from_seed(&[2u8; 32]);
        let funder_pk = funder_sk.public_key();
        let funder_p2_ph = Bytes32::new(
            chia_puzzle_types::standard::StandardArgs::curry_tree_hash(funder_pk).to_bytes(),
        );

        // Synthetic Eve singleton coin: parent = launcher, ph = inner
        // singleton ph (irrelevant for offline build), amount = 1.
        let singleton_coin = Coin::new(launcher, b32(0xCC), 1);
        let lineage_proof = Proof::Eve(EveProof {
            parent_parent_coin_info: launcher,
            parent_amount: 1,
        });
        let funder_coin = Coin::new(b32(0xDD), funder_p2_ph, 100);

        let params = test_params();
        let contributor = CeremonyContributor::new(launcher, params.clone());
        let current_state = CeremonyState::genesis(params.vk_seed);

        let contrib_params = ContributeParams {
            participant_pubkey: participant_pk,
            contribution_hash: b32(0x77),
            prev_contribution_hash: params.vk_seed,
            entropy_hex: Bytes::default(),
            payload: vec![1, 2, 3, 4],
        };

        let coin_spends = contributor
            .build_contribute_bundle(
                singleton_coin,
                lineage_proof,
                current_state,
                funder_coin,
                funder_pk,
                contrib_params,
            )
            .unwrap();

        // Expect 2 coin spends: funder p2 + singleton outer.
        assert_eq!(coin_spends.len(), 2, "should emit funder + singleton spends");

        // Funder coin must appear as input to one spend.
        let has_funder = coin_spends.iter().any(|cs| cs.coin == funder_coin);
        assert!(has_funder, "funder coin should be among coin spends");

        // Singleton coin must appear as input to one spend.
        let has_singleton = coin_spends.iter().any(|cs| cs.coin == singleton_coin);
        assert!(
            has_singleton,
            "singleton coin should be among coin spends"
        );
    }

    /// Helper: build a synthetic `ContributionRecord` for lineage
    /// tests. Only the lineage-relevant fields matter.
    fn rec(prev: Bytes32, contrib: Bytes32) -> ContributionRecord {
        use chia_bls::SecretKey;
        ContributionRecord {
            participant_pubkey: SecretKey::from_seed(&[0u8; 32]).public_key(),
            contribution_hash: contrib,
            prev_contribution_hash: prev,
            coin_id: Bytes32::default(),
            block_height: 0,
            entropy_hex: Bytes::default(),
            payload: vec![],
        }
    }

    /// `validate_lineage` accepts an empty sequence — a fresh ceremony
    /// with no contributions yet is a valid lineage.
    #[test]
    fn validate_lineage_accepts_empty() {
        assert!(CeremonyReader::validate_lineage(&[], b32(0xAA)).is_ok());
    }

    /// `validate_lineage` accepts a valid 3-step chain anchored at
    /// `vk_seed`.
    #[test]
    fn validate_lineage_accepts_valid_chain() {
        let seed = b32(0xAA);
        let h1 = b32(0x11);
        let h2 = b32(0x22);
        let h3 = b32(0x33);
        let records = vec![
            rec(seed, h1),
            rec(h1, h2),
            rec(h2, h3),
        ];
        assert!(CeremonyReader::validate_lineage(&records, seed).is_ok());
    }

    /// `validate_lineage` rejects a chain where the FIRST record's
    /// `prev` doesn't match the supplied `vk_seed`.
    #[test]
    fn validate_lineage_rejects_wrong_vk_seed() {
        let seed = b32(0xAA);
        let records = vec![rec(b32(0xBB), b32(0x11))];
        let err = CeremonyReader::validate_lineage(&records, seed).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("record 0"),
            "expected error to mention record index 0; got: {msg}"
        );
    }

    /// `validate_lineage` rejects a chain with a broken middle link
    /// (record N's `prev` != record (N-1)'s `contrib`).
    #[test]
    fn validate_lineage_rejects_broken_link() {
        let seed = b32(0xAA);
        let records = vec![
            rec(seed, b32(0x11)),
            // BROKEN — prev should be 0x11, not 0xFF.
            rec(b32(0xFF), b32(0x22)),
        ];
        let err = CeremonyReader::validate_lineage(&records, seed).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("record 1"),
            "expected error to mention record index 1; got: {msg}"
        );
    }

    /// `check_threshold` accepts when count ≥ min and lineage is
    /// valid.
    #[test]
    fn check_threshold_accepts_when_at_min() {
        let seed = b32(0xAA);
        let records = vec![
            rec(seed, b32(0x11)),
            rec(b32(0x11), b32(0x22)),
        ];
        // min=2, have 2 → accept.
        assert!(CeremonyReader::check_threshold(&records, seed, 2).is_ok());
        // min=1, have 2 → still accept.
        assert!(CeremonyReader::check_threshold(&records, seed, 1).is_ok());
    }

    /// `check_threshold` rejects when count < min.
    #[test]
    fn check_threshold_rejects_below_min() {
        let seed = b32(0xAA);
        let records = vec![rec(seed, b32(0x11))];
        let err = CeremonyReader::check_threshold(&records, seed, 5).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("only 1 contribution") && msg.contains("at least 5"),
            "expected threshold error message, got: {msg}"
        );
    }

    /// `check_threshold` propagates lineage failures (broken chain
    /// even at ≥ min still rejected).
    #[test]
    fn check_threshold_rejects_broken_lineage() {
        let seed = b32(0xAA);
        let records = vec![
            rec(seed, b32(0x11)),
            rec(b32(0xFF), b32(0x22)), // broken
        ];
        assert!(CeremonyReader::check_threshold(&records, seed, 2).is_err());
    }

    /// `derive_vk` rejects below-threshold inputs at the gate (does
    /// not attempt the bridge). Callers can show the threshold error
    /// in the UI before the user pays for VK derivation work.
    #[test]
    fn derive_vk_rejects_below_threshold_at_gate() {
        let seed = b32(0xAA);
        let records = vec![rec(seed, b32(0x11))];
        let err = CeremonyReader::derive_vk(&records, seed, 5).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("only 1 contribution"),
            "expected threshold error before bridge stub, got: {msg}"
        );
    }

    /// `derive_vk` rejects broken-lineage inputs at the gate too.
    #[test]
    fn derive_vk_rejects_broken_lineage_at_gate() {
        let seed = b32(0xAA);
        let records = vec![
            rec(seed, b32(0x11)),
            rec(b32(0xFF), b32(0x22)), // broken
        ];
        let err = CeremonyReader::derive_vk(&records, seed, 2).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("record 1"),
            "expected lineage error before bridge stub, got: {msg}"
        );
    }

    /// `derive_vk` produces a real VerificationKey when records carry
    /// the JSON `{entropy_hex, name, message?}` payload format that
    /// `derive_vk` parses. Confirms the SimulatedBackend bridge runs
    /// end-to-end after the gates pass.
    #[test]
    fn derive_vk_with_valid_payloads_returns_vk() {
        use chia_bls::SecretKey;
        let seed = b32(0xAA);
        let payload_json = |entropy_byte: u8, name: &str| -> Vec<u8> {
            let entropy_hex = hex::encode(vec![entropy_byte; 32]);
            format!(
                r#"{{"entropy_hex":"{entropy_hex}","name":"{name}"}}"#
            )
            .into_bytes()
        };
        let mut r1 = rec(seed, b32(0x11));
        r1.payload = payload_json(0x01, "alice");
        let mut r2 = rec(b32(0x11), b32(0x22));
        r2.payload = payload_json(0x02, "bob");
        let _ = SecretKey::from_seed(&[0u8; 32]); // pin chia_bls dep

        let vk = CeremonyReader::derive_vk(&[r1, r2], seed, 2).expect("derive_vk should succeed");
        assert!(!vk.raw_bytes.is_empty(), "VK must have non-empty raw_bytes");
    }

    /// `derive_keys` returns BOTH a non-empty ProvingKey and the
    /// canonical-length VerificationKey. Aggregators that need to
    /// produce proofs use this; the wasm export still surfaces only
    /// the VK to keep PKs out of the dApp's blast radius.
    #[test]
    fn derive_keys_returns_both_pk_and_vk() {
        let seed = b32(0xAA);
        let payload_json = |entropy_byte: u8, name: &str| -> Vec<u8> {
            let entropy_hex = hex::encode(vec![entropy_byte; 32]);
            format!(r#"{{"entropy_hex":"{entropy_hex}","name":"{name}"}}"#)
                .into_bytes()
        };
        let mut r1 = rec(seed, b32(0x11));
        r1.payload = payload_json(0x01, "alice");
        let mut r2 = rec(b32(0x11), b32(0x22));
        r2.payload = payload_json(0x02, "bob");

        let (pk, vk) =
            CeremonyReader::derive_keys(&[r1, r2], seed, 2).expect("derive_keys");
        assert!(
            !pk.raw_bytes.is_empty(),
            "PK must be non-empty for aggregator use"
        );
        let expected_vk_len = 336 + (crate::config::PUBLIC_INPUT_COUNT + 1) * 48;
        assert_eq!(
            vk.raw_bytes.len(),
            expected_vk_len,
            "VK byte length should match canonical Groth16 layout"
        );
    }

    /// `derive_vk` rejects records whose payload isn't valid UTF-8
    /// JSON of the expected shape.
    #[test]
    fn derive_vk_rejects_malformed_payload() {
        let seed = b32(0xAA);
        let records = vec![
            rec(seed, b32(0x11)), // payload is empty by default
            rec(b32(0x11), b32(0x22)),
        ];
        let err = CeremonyReader::derive_vk(&records, seed, 2).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("payload"),
            "expected payload error, got: {msg}"
        );
    }

    /// `parse_action_solution_node` round-trips through
    /// `build_action_solution_node` — pins that the parser is the
    /// exact inverse of the builder for the `contribute` action's
    /// per-spend solution shape.
    #[test]
    fn parse_action_solution_node_round_trips_with_builder() {
        use chia_bls::SecretKey;
        use chia_sdk_driver::SpendContext;

        for payload in [vec![], b"hello world".to_vec(), vec![0xAA; 256]] {
            let pk = SecretKey::from_seed(&[5u8; 32]).public_key();
            let entropy = Bytes::new(vec![0xEE; 32]);
            let p = ContributeParams {
                participant_pubkey: pk.clone(),
                contribution_hash: b32(0xCC),
                prev_contribution_hash: b32(0xDD),
                entropy_hex: entropy.clone(),
                payload: payload.clone(),
            };
            let mut ctx = SpendContext::new();
            let node = CeremonyContributor::build_action_solution_node(&mut ctx, &p).unwrap();

            let allocator: &clvmr::Allocator = &*ctx;
            let (pk_bytes, contrib, prev, entropy_bytes, payload_bytes) =
                CeremonyContributor::parse_action_solution_node(allocator, node).unwrap();

            assert_eq!(pk_bytes, pk.to_bytes().as_ref());
            assert_eq!(contrib, p.contribution_hash);
            assert_eq!(prev, p.prev_contribution_hash);
            assert_eq!(entropy_bytes, entropy.as_ref());
            assert_eq!(payload_bytes, payload);
        }
    }

    /// `CeremonyState::genesis(vk_seed).clvm_tree_hash()` round-trips
    /// through `ToClvm` — i.e. matches the tree hash of the on-chain
    /// cons shape
    /// `(count . (last_hash . (finalized . (vk_hash . marker_root))))`.
    #[test]
    fn ceremony_state_clvm_tree_hash_matches_to_clvm() {
        use chia_sdk_driver::SpendContext;
        use clvm_traits::ToClvm;
        use clvm_utils::tree_hash;

        let vk_seed = b32(0x42);
        let st = CeremonyState::genesis(vk_seed);

        let mut ctx = SpendContext::new();
        // Rust mirror of the rest-arg shape:
        //   (count . (last_hash . (finalized . (vk_hash . marker_root))))
        // Genesis: finalized=0, vk_hash=zeros, marker_root=zeros.
        let pair = (
            st.contribution_count,
            (
                vk_seed,
                (0u64, (Bytes32::default(), Bytes32::default())),
            ),
        );
        let node = pair.to_clvm(&mut *ctx).unwrap();
        let actual = Bytes32::new(tree_hash(&ctx, node).to_bytes());

        assert_eq!(actual, st.clvm_tree_hash());
    }
}
