// ============================================================================
// actors/deployer.rs — Election Singleton deployment driver
// ============================================================================
//
// MODULE: actors::deployer
// PURPOSE: One-time bootstrap. Builds (and optionally signs) the
//          spend bundle that creates the Election Singleton on-chain
//          and emits its genesis launcher coin.
//
// LIFECYCLE:
//   1. Run an MPC ceremony → produce a `VerificationKey`.
//   2. Choose `DeployParams` (CAT TAIL, fees, election length, VK).
//   3. `ElectionDeployer::new(params).deploy_signed(parent_coin, …)`.
//   4. Broadcast `DeploymentArtifacts.spend_bundle` via
//      `chia_query::ChiaQuery::push_tx`.
//   5. Distribute `DeploymentArtifacts.config` JSON to all
//      participants — voters, aggregators, indexers all need it.
//
// CRATES USED:
//   * `chia_sdk_driver::Launcher`        → singleton genesis spend
//   * `chia_sdk_driver::SpendContext`    → coin-spend assembly
//   * `chia_sdk_driver::StandardLayer`   → spend the parent XCH coin
//   * `dig_l1_wallet::transaction::sign_coin_spends` → BLS aggregation
//     (which itself wraps `chia_sdk_signer::RequiredSignature::from_coin_spends`)
//
// PUZZLE HASH ARITHMETIC: every `*_action_hash` helper here mirrors
//   exactly the curry layout in the corresponding Rue file. Any drift
//   between the two would silently produce non-spendable singletons.

use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_driver::{Launcher, SpendContext, StandardLayer};
use dig_l1_wallet::transaction::{assemble_spend_bundle, get_agg_sig_data, sign_coin_spends};
use dig_l1_wallet::NetworkType;

use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles::{self, PuzzleHashes};

/// STRUCT: DeployParams
/// PURPOSE: deployment-time inputs chosen by the election creator.
///          All fields end up curried into the on-chain puzzle hash
///          (so changing them post-deploy means re-launching).
#[derive(Debug, Clone)]
pub struct DeployParams {
    /// Output of the MPC ceremony. 576 bytes for our 4-input circuit.
    pub verification_key: crate::ceremony::VerificationKey,
    /// CAT TAIL hash. Identifies the governance token; the on-chain
    /// register action asserts incoming registration coins are CATs of
    /// exactly this asset ID.
    pub cat_tail_hash: Bytes32,
    /// CAT mojos each voter locks at registration. Returned at release.
    pub collateral_amount: u64,
    /// XCH mojos each voter pays at registration. Accumulated in the
    /// singleton; paid out to the finalizer at finalize.
    pub registration_fee: u64,
    /// Time-lock (in L1 blocks) between deploy and earliest `finalize`.
    /// Enforced via `ASSERT_HEIGHT_RELATIVE` to mitigate the bootstrap
    /// attack (single-voter premature finalization).
    pub election_length_blocks: u64,
    /// Optional label for UIs/indexers.
    pub label: Option<String>,
}

/// STRUCT: DeploymentArtifacts
/// PURPOSE: outputs of a successful deploy.
/// CONTAINS:
///   * spend_bundle — fully formed (signed if via `deploy_signed`)
///   * config       — the JSON-serialisable `ElectionConfig` other
///                    participants will need
#[derive(Debug, Clone)]
pub struct DeploymentArtifacts {
    pub spend_bundle: SpendBundle,
    pub config: ElectionConfig,
}

/// STRUCT: ElectionDeployer
/// PURPOSE: stateful actor that owns `DeployParams` and exposes the
///          deployment + puzzle-hash-prediction API.
#[derive(Debug, Clone)]
pub struct ElectionDeployer {
    pub params: DeployParams,
}

/// FN: derive_launcher_id
/// WHAT: predict the singleton launcher_id from the parent coin id +
///       launcher amount.
/// FORMULA: `coin_id(Coin { parent: parent_coin_id, puzzle_hash: SINGLETON_LAUNCHER_HASH, amount })`.
/// USAGE: lets us compute the launcher_id BEFORE actually spending the
///        parent coin, so we can pre-derive the `ElectionConfig` and
///        the inner puzzle hash that the launcher must commit to.
pub fn derive_launcher_id(parent_coin_id: Bytes32, amount: u64) -> Bytes32 {
    let launcher_coin = Coin::new(parent_coin_id, SINGLETON_LAUNCHER_HASH.into(), amount);
    launcher_coin.coin_id()
}

impl ElectionDeployer {
    /// Construct from the deployment parameters. No I/O.
    pub fn new(params: DeployParams) -> Self {
        Self { params }
    }

    /// FN: build_deploy_bundle
    /// WHAT: assemble the (unsigned) coin spends for genesis launch.
    /// CONTRACT: caller has already coin-selected `parent_coin` (an XCH
    ///           coin holding ≥1 mojo locked under `parent_pk`'s
    ///           standard puzzle).
    /// EMITS:
    ///   * 1 launcher spend (parent_coin's child at puzzle_hash =
    ///     SINGLETON_LAUNCHER_HASH, amount=1) — creates the eve
    ///     singleton committed to `inner_ph`
    ///   * 1 standard p2 spend of `parent_coin` → launcher coin (1 mojo)
    ///     + change back to the parent's standard p2 puzzle hash
    ///     (`parent.amount - 1` mojos) so the funding wallet doesn't
    ///     burn its remaining balance.
    /// RETURNS: `(coin_spends, ElectionConfig)`. The ElectionConfig is
    ///          only complete once the launcher_id is known.
    pub fn build_deploy_bundle(
        &self,
        parent_coin: Coin,
        parent_pk: PublicKey,
    ) -> VotingResult<(Vec<CoinSpend>, ElectionConfig)> {
        use chia_puzzle_types::standard::StandardArgs;
        use chia_sdk_types::Conditions;

        let mut ctx = SpendContext::new();

        let launcher_id = derive_launcher_id(parent_coin.coin_id(), 1);
        let config = self.config_for_launcher(launcher_id);

        let inner_ph = self.genesis_inner_puzzle_hash(launcher_id);

        // 1. Launcher coin spend (creates the eve singleton with our
        //    inner puzzle hash committed).
        let launcher = Launcher::new(parent_coin.coin_id(), 1);
        let (launch_conditions, _eve) = launcher
            .spend(&mut ctx, inner_ph, ())
            .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
                "ElectionDeployer: launcher.spend failed: {e}").into())))?;

        // 2. Standard p2 spend of the parent coin → launcher (1 mojo)
        //    + CHANGE coin back to parent's standard p2 puzzle hash
        //    so the funding wallet preserves `parent.amount - 1` mojos.
        //    Without this, ALL of parent_coin.amount above 1 mojo
        //    would be burned by consensus (output sum < input sum).
        let parent_p2_ph = Bytes32::new(StandardArgs::curry_tree_hash(parent_pk).to_bytes());
        let mut conditions: Conditions = launch_conditions;
        if parent_coin.amount > 1 {
            let change = parent_coin.amount - 1;
            conditions = conditions.create_coin(parent_p2_ph, change, chia_puzzle_types::Memos::None);
        }
        StandardLayer::new(parent_pk)
            .spend(&mut ctx, parent_coin, conditions)
            .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
                "ElectionDeployer: standard layer spend failed: {e}").into())))?;

        Ok((ctx.take(), config))
    }

    /// FN: deploy_signed
    /// WHAT: one-call build+sign convenience for the common case.
    /// CONTRACT: `secret_keys` MUST include the secret key for
    ///           `parent_pk`'s synthetic public key (the one that
    ///           actually appears in the standard layer's AggSigMe).
    /// SIGNING PATH: `dig_l1_wallet::transaction::sign_coin_spends`
    ///               → `chia_sdk_signer::RequiredSignature::from_coin_spends`
    ///               (walks every AGG_SIG_* condition, augments with
    ///               the network's `agg_sig_me_additional_data`,
    ///               produces a single aggregated BLS signature).
    pub fn deploy_signed(
        &self,
        parent_coin: Coin,
        parent_pk: PublicKey,
        secret_keys: &[SecretKey],
        network: NetworkType,
    ) -> VotingResult<DeploymentArtifacts> {
        let (coin_spends, config) = self.build_deploy_bundle(parent_coin, parent_pk)?;
        let signature = sign_bundle_signature(&coin_spends, secret_keys, network)?;
        let spend_bundle = assemble_spend_bundle(coin_spends, signature);
        Ok(DeploymentArtifacts { spend_bundle, config })
    }

    /// FN: config_for_launcher
    /// WHAT: build the JSON-friendly `ElectionConfig` for a known
    ///       launcher_id. Used both internally (during deploy) and
    ///       externally (by tools that need to recompute the config
    ///       given an existing election).
    pub fn config_for_launcher(&self, launcher_id: Bytes32) -> ElectionConfig {
        ElectionConfig {
            election_launcher_id_hex: hex::encode(launcher_id),
            cat_tail_hash_hex: hex::encode(self.params.cat_tail_hash),
            collateral_amount: self.params.collateral_amount,
            registration_fee: self.params.registration_fee,
            election_length_blocks: self.params.election_length_blocks,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: hex::encode(self.params.verification_key.serialize()),
            label: self.params.label.clone(),
        }
    }

    /// FN: genesis_inner_puzzle_hash
    /// WHAT: action-layer-curried inner puzzle hash committed to the
    ///       launcher (SingletonArgs::curry_tree_hash wraps this on top).
    /// CURRY ORDER: `(FINALIZER, MERKLE_ROOT, STATE)` — must match
    ///              `puzzles/action.rue`.
    /// FINALIZER LAYOUT: `(FINALIZER_MOD <ACTION_LAYER_MOD_HASH> <HINT=launcher_id>) <self_hash>`
    ///                   per the CHIP-0050 finalizer pattern.
    pub fn genesis_inner_puzzle_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        let action_layer_mod_hash = PuzzleHashes::action_layer();
        let election_finalizer_mod_hash = PuzzleHashes::election_finalizer();

        // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT=launcher_id)
        let finalizer_first = puzzles::curry_tree_hash(
            election_finalizer_mod_hash,
            &[
                puzzles::hash_atom_b32(&action_layer_mod_hash),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        );
        // Finalizer 2nd curry: bind self-hash
        let finalizer_full = puzzles::curry_tree_hash(
            finalizer_first,
            &[puzzles::hash_atom_b32(&finalizer_first)],
        );

        let merkle_root = self.election_actions_merkle_root(launcher_id);
        // The genesis State.registration_merkle_root is the SMT
        // ROOT after 32 levels of empty-pair hashing — NOT the
        // leaf-level EMPTY_LEAF_HASH. The on-chain register action
        // verifies an empty-slot proof against this root, so they
        // MUST agree byte-for-byte. Voter::register passes
        // `SparseMerkleTree::new().root()` (the full root) when
        // building the action layer state for the eve singleton
        // spend; the deployer must commit to the same value.
        let empty_root = crate::merkle::SparseMerkleTree::new().root();
        let state_hash = self.genesis_state_tree_hash(empty_root);

        // Curry args (matching `register.rue::fresh_registration_coin_puzzle_hash`):
        //   * `finalizer_full` — already a TREE HASH of a curried
        //     program. Pass directly. Atom-wrapping would double-hash.
        //   * `merkle_root` — a Bytes32 atom value. Wrap as atom.
        //   * `state_hash` — already a TREE HASH (of the state cons
        //     tree). Pass directly.
        puzzles::curry_tree_hash(
            action_layer_mod_hash,
            &[
                finalizer_full,
                puzzles::hash_atom_b32(&merkle_root),
                state_hash,
            ],
        )
    }

    /// FN: election_actions_merkle_root
    /// WHAT: 4-leaf Merkle root over (register, finalize,
    ///       announce_finalization, oracle) — each pre-curried with
    ///       deployment-time constants (the latter two have no
    ///       per-deployment curries and so use their bare puzzle
    ///       hash as the leaf). The on-chain action layer asserts
    ///       every selected action's puzzle hash is in this tree.
    pub fn election_actions_merkle_root(&self, launcher_id: Bytes32) -> Bytes32 {
        let register_full = self.election_register_action_hash(launcher_id);
        let finalize_full = self.election_finalize_action_hash(launcher_id);
        let announce_full = self.election_announce_finalization_action_hash();
        let oracle_full = self.election_oracle_action_hash();
        puzzles::election_actions_merkle_root(
            register_full,
            finalize_full,
            announce_full,
            oracle_full,
        )
    }

    /// Tree hash of the genesis ElectionState tuple (mirrors the Rue
    /// struct field order in `puzzles/election/shared.rue`).
    fn genesis_state_tree_hash(&self, empty_root: Bytes32) -> Bytes32 {
        let root_h = puzzles::hash_atom_b32(&empty_root);
        let count_h = puzzles::hash_atom(&[]);
        let fees_h = puzzles::hash_atom(&[]);
        let finalized_h = puzzles::hash_atom(&[]);
        let outcome_h = puzzles::hash_atom_b32(&Bytes32::default());

        let pair = puzzles::hash_pair(finalized_h, outcome_h);
        let pair = puzzles::hash_pair(fees_h, pair);
        let pair = puzzles::hash_pair(count_h, pair);
        puzzles::hash_pair(root_h, pair)
    }

    /// Curry the `register` action with its deployment-wide constants.
    /// CURRY ORDER must match the curried-parameter list at the top
    /// of `puzzles/election/register.rue`.
    fn election_register_action_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        puzzles::curry_tree_hash(
            PuzzleHashes::election_register(),
            &[
                uint_atom_hash(crate::config::TREE_DEPTH as u64),
                puzzles::hash_atom_b32(&Bytes32::new(crate::config::EMPTY_LEAF_HASH)),
                puzzles::hash_atom_b32(&PuzzleHashes::cat_outer()),
                puzzles::hash_atom_b32(&self.params.cat_tail_hash),
                puzzles::hash_atom_b32(&PuzzleHashes::action_layer()),
                puzzles::hash_atom_b32(&PuzzleHashes::registration_finalizer()),
                puzzles::hash_atom_b32(&puzzles::registration_actions_merkle_root()),
                uint_atom_hash(self.params.collateral_amount),
                uint_atom_hash(self.params.registration_fee),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        )
    }

    /// Curry the `finalize` action.
    ///
    /// CRITICAL CURRY SHAPE: `finalize.rue` declares its first two
    /// curried params as `VK: VK` (struct of `alpha, beta, gamma,
    /// delta`) and `IC: IC` (struct of `ic0..ic4`) — i.e., CLVM CONS
    /// TREES, not flat byte blobs. The puzzle accesses `VK.alpha`,
    /// `IC.ic0`, etc., so the curry-time argument must be a tuple
    /// the puzzle's struct projection can walk.
    ///
    /// MIRROR: the spender (`Aggregator::build_finalize_with_proof`)
    /// curries with EXACTLY these struct shapes. The deployer's
    /// merkle-root leaf MUST agree byte-for-byte with what the
    /// spender will reveal, otherwise the on-chain action layer's
    /// merkle proof check would reject every finalize spend.
    ///
    /// VK fields: alpha (G1, 48), beta (G2, 96), gamma (G2, 96),
    ///            delta (G2, 96)            — total 336 bytes.
    /// IC fields: ic0..ic4 (G1, 48 each)    — total 240 bytes.
    ///
    /// Earlier incarnation: `hash_atom(vk_bytes[..336])` +
    /// `hash_atom(vk_bytes[336..])` curried in the BASE blobs as
    /// single atoms, producing a leaf for a `finalize` puzzle whose
    /// reveal could never match — every deployed election before
    /// this fix had an unreachable finalize leaf in its merkle root.
    /// Mainnet PHASE 5 surfaced it as `action puzzle hash <X> not
    /// in merkle root (leaves: ...)`. Pinned by the spender↔leaf
    /// equivalence regression test in
    /// `compute_election_action_root_leaves` (sdk/aggregator.rs).
    fn election_finalize_action_hash(&self, launcher_id: Bytes32) -> Bytes32 {
        let vk_bytes = &self.params.verification_key.raw_bytes;
        assert!(
            vk_bytes.len() >= 576,
            "ElectionDeployer::election_finalize_action_hash: \
             vk too short to slice into VK + IC structs (got {} bytes, expected ≥ 576)",
            vk_bytes.len(),
        );
        // ── VK struct = (alpha . (beta . (gamma . (delta . ()))))
        let alpha_h = puzzles::hash_atom(&vk_bytes[0..48]);
        let beta_h = puzzles::hash_atom(&vk_bytes[48..144]);
        let gamma_h = puzzles::hash_atom(&vk_bytes[144..240]);
        let delta_h = puzzles::hash_atom(&vk_bytes[240..336]);
        let nil_h = puzzles::hash_atom(&[]);
        let vk_tail = puzzles::hash_pair(delta_h, nil_h);
        let vk_tail = puzzles::hash_pair(gamma_h, vk_tail);
        let vk_tail = puzzles::hash_pair(beta_h, vk_tail);
        let vk_struct_h = puzzles::hash_pair(alpha_h, vk_tail);

        // ── IC struct = (ic0 . (ic1 . (ic2 . (ic3 . (ic4 . ())))))
        let ic0_h = puzzles::hash_atom(&vk_bytes[336..384]);
        let ic1_h = puzzles::hash_atom(&vk_bytes[384..432]);
        let ic2_h = puzzles::hash_atom(&vk_bytes[432..480]);
        let ic3_h = puzzles::hash_atom(&vk_bytes[480..528]);
        let ic4_h = puzzles::hash_atom(&vk_bytes[528..576]);
        let ic_tail = puzzles::hash_pair(ic4_h, nil_h);
        let ic_tail = puzzles::hash_pair(ic3_h, ic_tail);
        let ic_tail = puzzles::hash_pair(ic2_h, ic_tail);
        let ic_tail = puzzles::hash_pair(ic1_h, ic_tail);
        let ic_struct_h = puzzles::hash_pair(ic0_h, ic_tail);

        puzzles::curry_tree_hash(
            PuzzleHashes::election_finalize(),
            &[
                vk_struct_h,
                ic_struct_h,
                uint_atom_hash(self.params.election_length_blocks),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        )
    }

    /// Curry the `announce_finalization` action — no per-deployment
    /// constants, so the un-curried hash IS the leaf.
    fn election_announce_finalization_action_hash(&self) -> Bytes32 {
        PuzzleHashes::election_announce_finalization()
    }

    /// Curry the `oracle` action — no per-deployment constants
    /// (reads everything from `ElectionStateTruth`), so the
    /// un-curried hash IS the leaf.
    fn election_oracle_action_hash(&self) -> Bytes32 {
        PuzzleHashes::election_oracle()
    }
}

/// FN: sign_bundle_signature
/// WHAT: produce the aggregated BLS signature for an unsigned bundle.
/// WHY EXPOSED: every `*_signed` actor method delegates here so the
///              signing code path is identical across the SDK.
/// UPSTREAM CHAIN:
///   `dig_l1_wallet::transaction::sign_coin_spends`
///   → `chia_sdk_signer::RequiredSignature::from_coin_spends`
///   → walks every AGG_SIG condition, augments with network data,
///     produces required (PublicKey, message) pairs
///   → matches each pair against `secret_keys`
///   → returns aggregated signature
pub fn sign_bundle_signature(
    coin_spends: &[CoinSpend],
    secret_keys: &[SecretKey],
    network: NetworkType,
) -> VotingResult<Signature> {
    let agg_sig_data = get_agg_sig_data(network);
    sign_coin_spends(coin_spends, secret_keys, agg_sig_data).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("sign_coin_spends failed: {e}").into(),
        ))
    })
}

/// FN: uint_atom_hash
/// WHAT: tree hash of an unsigned integer in CLVM canonical encoding.
/// CLVM RULES:
///   * 0 → empty atom
///   * positive: shortest big-endian encoding; if MSB has bit 7 set,
///     prepend 0x00 so it doesn't decode as negative.
/// MIRRORS: the implicit encoding clvm_traits applies to integer
///          curried args.
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
    use crate::ceremony::VerificationKey;
    use crate::config::PUBLIC_INPUT_COUNT;

    fn b32(byte: u8) -> Bytes32 { Bytes32::new([byte; 32]) }

    fn test_params() -> DeployParams {
        DeployParams {
            verification_key: VerificationKey {
                raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
            },
            cat_tail_hash: b32(0x77),
            collateral_amount: 1_000,
            registration_fee: 10,
            election_length_blocks: 4_608,
            label: Some("test".into()),
        }
    }

    /// WHAT: `derive_launcher_id` is a pure function of (parent_id,
    ///       amount).
    /// HOW:  call twice with identical inputs, assert equality.
    /// WHY:  voters / aggregators predict the launcher id off-chain
    ///       BEFORE the deploy spend lands; if the function were
    ///       non-deterministic they couldn't pre-compute coin
    ///       lookups.
    #[test]
    fn derive_launcher_id_is_deterministic() {
        let p = b32(0x42);
        assert_eq!(derive_launcher_id(p, 1), derive_launcher_id(p, 1));
    }

    /// WHAT: `derive_launcher_id` is sensitive to the launcher
    ///       amount (2 different amounts → 2 different ids).
    /// HOW:  hold parent constant, vary amount from 1 to 2, assert
    ///       inequality.
    /// WHY:  the singleton spec includes amount in the launcher coin
    ///       id; a deployer that mis-computed by always assuming
    ///       amount=1 would produce wrong ids when later switching
    ///       to a non-1 launcher.
    #[test]
    fn derive_launcher_id_changes_with_amount() {
        let p = b32(0x42);
        assert_ne!(derive_launcher_id(p, 1), derive_launcher_id(p, 2));
    }

    /// WHAT: every config produced by `config_for_launcher` passes
    ///       its own `.validate()`.
    /// HOW:  build a config from canonical test_params, call
    ///       `.validate()`, expect Ok.
    /// WHY:  voters / aggregators load the config and call
    ///       `.validate()` immediately; a config that fails its own
    ///       validator would leave participants with no usable
    ///       election bootstrap.
    #[test]
    fn config_for_launcher_round_trips_through_validate() {
        let d = ElectionDeployer::new(test_params());
        let config = d.config_for_launcher(b32(0xAB));
        config.validate().expect("config_for_launcher must produce valid configs");
    }

    /// WHAT: `config_for_launcher` correctly hex-encodes the
    ///       verification key into `verification_key_hex`.
    /// HOW:  build a deployer, derive a config, hex-encode the
    ///       deployer's raw VK bytes independently, compare.
    /// WHY:  the VK travels JSON-serialised from deployer to
    ///       aggregator (and to anyone wanting to verify a proof
    ///       off-chain). Wrong encoding → universal verification
    ///       failure.
    #[test]
    fn config_carries_verification_key_correctly() {
        let d = ElectionDeployer::new(test_params());
        let config = d.config_for_launcher(b32(0xAB));
        let expected_vk_hex = hex::encode(&d.params.verification_key.raw_bytes);
        assert_eq!(config.verification_key_hex, expected_vk_hex);
    }

    /// WHAT: `genesis_inner_puzzle_hash` is deterministic for a
    ///       given launcher_id.
    /// HOW:  call twice with the same launcher_id, assert equality.
    /// WHY:  this hash is what the launcher's CreateCoin commits to.
    ///       Non-determinism between coordinator and broadcaster
    ///       would cause the launcher → eve singleton chain to
    ///       break.
    #[test]
    fn genesis_inner_puzzle_hash_is_deterministic() {
        let d = ElectionDeployer::new(test_params());
        let l = b32(0xAB);
        assert_eq!(d.genesis_inner_puzzle_hash(l), d.genesis_inner_puzzle_hash(l));
    }

    /// WHAT: `genesis_inner_puzzle_hash` is sensitive to the
    ///       launcher_id input.
    /// HOW:  call with two different launcher_ids, assert hashes
    ///       differ.
    /// WHY:  every action that recreates the singleton uses the
    ///       launcher_id-bound hint; if the inner hash didn't depend
    ///       on it, cross-election state confusion would be
    ///       possible.
    #[test]
    fn genesis_inner_puzzle_hash_changes_per_launcher() {
        let d = ElectionDeployer::new(test_params());
        assert_ne!(
            d.genesis_inner_puzzle_hash(b32(0xAB)),
            d.genesis_inner_puzzle_hash(b32(0xCD)),
        );
    }

    /// WHAT: `election_actions_merkle_root` is deterministic for a
    ///       given (params, launcher_id) pair.
    /// HOW:  call twice with same launcher_id, assert equality.
    /// WHY:  the root is curried into the action layer puzzle hash.
    ///       Non-determinism would mean the deployer's predicted
    ///       puzzle hash doesn't match the actual on-chain hash.
    #[test]
    fn election_actions_merkle_root_is_deterministic() {
        let d = ElectionDeployer::new(test_params());
        let l = b32(0xAB);
        assert_eq!(
            d.election_actions_merkle_root(l),
            d.election_actions_merkle_root(l),
        );
    }

    /// WHAT: changing ANY curried parameter (VK or fee) changes the
    ///       election actions merkle root.
    /// HOW:  flip the first byte of the VK → new root differs;
    ///       independently change `registration_fee` → new root
    ///       differs.
    /// WHY:  this is the safety net for the action curry — any
    ///       parameter that was supposed to be curried but wasn't
    ///       would manifest as the root staying constant when it
    ///       shouldn't.
    #[test]
    fn election_actions_merkle_root_changes_when_params_change() {
        let mut p1 = test_params();
        let mut p2 = test_params();
        p2.verification_key.raw_bytes[0] = 0xFF;
        let d1 = ElectionDeployer::new(p1.clone());
        let d2 = ElectionDeployer::new(p2);
        let l = b32(0xAB);
        assert_ne!(
            d1.election_actions_merkle_root(l),
            d2.election_actions_merkle_root(l),
        );

        // Different fee → different register action → different root.
        p1.registration_fee = 999;
        let d3 = ElectionDeployer::new(p1);
        assert_ne!(
            d3.election_actions_merkle_root(l),
            ElectionDeployer::new(test_params()).election_actions_merkle_root(l),
        );
    }

    /// WHAT: the deployer's `genesis_inner_puzzle_hash(launcher_id)`
    ///       MUST equal the tree hash of the action-layer puzzle
    ///       Voter::register builds when spending the eve singleton.
    /// HOW:  mirror Voter::register's exact action-layer assembly
    ///       and compare each intermediate hash so a divergence
    ///       points at the offending sub-computation.
    /// WHY:  if these diverge, EVERY first register/finalize on a
    ///       fresh deploy would land at a different puzzle hash than
    ///       the launcher's commitment and the singleton outer would
    ///       reject the spend.
    #[test]
    fn genesis_inner_puzzle_hash_matches_built_action_layer_node() {
        use chia_sdk_driver::SpendContext;
        use clvm_traits::ToClvm;
        use clvm_utils::tree_hash;

        let d = ElectionDeployer::new(test_params());
        let launcher_id = b32(0xAB);

        // ── Layer 1: finalizer hash equivalence ────────────────
        let mut ctx = SpendContext::new();
        let actual_finalizer_node =
            crate::action_spends::build_election_finalizer_full(&mut ctx, launcher_id).unwrap();
        let actual_finalizer_th = Bytes32::new(tree_hash(&ctx, actual_finalizer_node).to_bytes());

        // ── Layer 1a: bare puzzle's own tree hash ──────────────
        // Verify the embedded `.hash` file matches the actual tree
        // hash of the program loaded from the embedded `.hex` file.
        // If these diverge, the build pipeline emitted a stale
        // hash file.
        use chia_protocol::Program;
        let bare_bytes = hex::decode(
            crate::puzzles::ELECTION_FINALIZER_HEX
                .trim()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let bare_program = Program::from(bare_bytes);
        let bare_node = bare_program.to_clvm(&mut *ctx).unwrap();
        let bare_th = Bytes32::new(tree_hash(&ctx, bare_node).to_bytes());
        let embedded_h = PuzzleHashes::election_finalizer();
        assert_eq!(
            bare_th, embedded_h,
            "BARE FINALIZER MISMATCH: tree_hash(loaded program) != embedded .hash file"
        );

        // Bisect the FIRST-curry hash too: build the curried first
        // layer the same way build_election_finalizer_full does and
        // compare its tree hash to what curry_tree_hash predicts.
        use chia_sdk_driver::SpendContext as _SC;
        let mut ctx2 = _SC::new();
        let bare_program_node2 = {
            let bare_bytes = hex::decode(
                crate::puzzles::ELECTION_FINALIZER_HEX
                    .trim()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            Program::from(bare_bytes).to_clvm(&mut *ctx2).unwrap()
        };
        let action_layer_mod = PuzzleHashes::action_layer();
        let actual_first_curry = clvm_utils::CurriedProgram {
            program: bare_program_node2,
            args: clvm_traits::clvm_curried_args!(action_layer_mod, launcher_id),
        }
        .to_clvm(&mut *ctx2)
        .unwrap();
        let actual_first_th =
            Bytes32::new(tree_hash(&ctx2, actual_first_curry).to_bytes());
        let predicted_first = puzzles::curry_tree_hash(
            PuzzleHashes::election_finalizer(),
            &[
                puzzles::hash_atom_b32(&action_layer_mod),
                puzzles::hash_atom_b32(&launcher_id),
            ],
        );
        assert_eq!(
            actual_first_th, predicted_first,
            "FIRST-CURRY MISMATCH: actual {} vs predicted {}",
            hex::encode(actual_first_th),
            hex::encode(predicted_first),
        );

        let predicted_finalizer_full = puzzles::curry_tree_hash(
            predicted_first,
            &[puzzles::hash_atom_b32(&predicted_first)],
        );
        assert_eq!(
            actual_finalizer_th, predicted_finalizer_full,
            "SECOND-CURRY (full finalizer) MISMATCH: actual {} vs predicted {}",
            hex::encode(actual_finalizer_th),
            hex::encode(predicted_finalizer_full),
        );

        // ── Layer 2: state hash equivalence ────────────────────
        // Use the FULL SMT root (Voter::register's
        // `ElectionState::genesis(smt.root())` semantic) so the
        // spender's state CLVM tree hash matches the deployer's
        // committed state hash.
        let empty_root = crate::merkle::SparseMerkleTree::new().root();
        let state_value = (
            empty_root,
            (0u64, (0u64, (0u8, Bytes32::default()))),
        );
        let state_node = state_value.to_clvm(&mut *ctx).unwrap();
        let actual_state_th = Bytes32::new(tree_hash(&ctx, state_node).to_bytes());
        let predicted_state_th = d.genesis_state_tree_hash(empty_root);
        assert_eq!(
            actual_state_th, predicted_state_th,
            "STATE HASH MISMATCH: spender's CLVM tree hash vs deployer's predicted hash"
        );

        // ── Layer 2.5: per-action leaf hash + merkle root ──────
        // The action layer's curried MERKLE_ROOT must match what
        // the spend-side `election_action_root_leaves` produces.
        // Mismatch here = the action dispatcher rejects every
        // spend (no merkle proof verifies).
        let predicted_merkle_root = d.election_actions_merkle_root(launcher_id);
        let dummy_config = crate::config::ElectionConfig {
            election_launcher_id_hex: hex::encode(launcher_id),
            cat_tail_hash_hex: hex::encode(d.params.cat_tail_hash),
            collateral_amount: d.params.collateral_amount,
            registration_fee: d.params.registration_fee,
            election_length_blocks: d.params.election_length_blocks,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: hex::encode(&d.params.verification_key.raw_bytes),
            label: d.params.label.clone(),
        };
        let actual_merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&dummy_config);
        assert_eq!(
            actual_merkle_root, predicted_merkle_root,
            "MERKLE ROOT MISMATCH: spender vs deployer for the action set\n  \
             actual:    {}\n  predicted: {}",
            hex::encode(actual_merkle_root),
            hex::encode(predicted_merkle_root),
        );

        // ── Layer 3: full action_layer puzzle hash ─────────────
        let action_layer_node = crate::action_spends::build_action_layer_puzzle(
            &mut ctx,
            actual_finalizer_node,
            predicted_merkle_root,
            state_node,
        )
        .unwrap();
        let actual = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());
        let predicted = d.genesis_inner_puzzle_hash(launcher_id);

        assert_eq!(
            actual, predicted,
            "ACTION_LAYER HASH MISMATCH: tree_hash(action_layer_node) != \
             genesis_inner_puzzle_hash(launcher_id)\n  finalizer_th: {}\n  state_th: {}\n  \
             merkle_root: {}",
            hex::encode(actual_finalizer_th),
            hex::encode(actual_state_th),
            hex::encode(predicted_merkle_root),
        );
    }

    /// WHAT: `uint_atom_hash(0)` equals `hash_atom(&[])`.
    /// HOW:  direct equality assertion.
    /// WHY:  CLVM canonical encoding of zero IS the empty atom; this
    ///       test pins that edge case so the implementation never
    ///       silently encodes 0 as `[0x00]` (which would hash to a
    ///       different value).
    #[test]
    fn uint_atom_hash_zero_is_empty_atom_hash() {
        assert_eq!(uint_atom_hash(0), puzzles::hash_atom(&[]));
    }

    /// WHAT: `uint_atom_hash(0x7F)` equals `hash_atom(&[0x7F])` —
    ///       no leading-zero pad needed for values < 0x80.
    /// HOW:  direct equality assertion.
    /// WHY:  CLVM positive-integer encoding only pads when the high
    ///       bit is set; pin the no-pad branch.
    #[test]
    fn uint_atom_hash_one_byte_no_pad() {
        assert_eq!(uint_atom_hash(0x7F), puzzles::hash_atom(&[0x7F]));
    }

    /// WHAT: `uint_atom_hash(0x80)` and `uint_atom_hash(0xFF)`
    ///       prepend a leading 0x00 byte (since the high bit is set
    ///       and CLVM would otherwise interpret as negative).
    /// HOW:  compare to `hash_atom(&[0x00, 0x80])` and
    ///       `hash_atom(&[0x00, 0xFF])`.
    /// WHY:  the high-bit pad is the most error-prone CLVM
    ///       integer-encoding rule; missing it would corrupt every
    ///       fee / collateral curry hash.
    #[test]
    fn uint_atom_hash_pads_when_high_bit_set() {
        assert_eq!(uint_atom_hash(0x80), puzzles::hash_atom(&[0x00, 0x80]));
        assert_eq!(uint_atom_hash(0xFF), puzzles::hash_atom(&[0x00, 0xFF]));
    }

    /// WHAT: `uint_atom_hash(0x0123)` produces the 2-byte big-endian
    ///       form `[0x01, 0x23]`.
    /// HOW:  direct equality with `hash_atom(&[0x01, 0x23])`.
    /// WHY:  pins the multi-byte big-endian shortest-encoding
    ///       behaviour; together with the previous tests this
    ///       covers the four CLVM integer encoding cases (zero,
    ///       no-pad, with-pad, multi-byte).
    #[test]
    fn uint_atom_hash_two_byte_value() {
        assert_eq!(uint_atom_hash(0x0123), puzzles::hash_atom(&[0x01, 0x23]));
    }
}
