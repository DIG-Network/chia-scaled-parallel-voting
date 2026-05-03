// ============================================================================
// tests/common/mod.rs — shared fixtures for end-to-end CLVM tests
// ============================================================================
//
// MODULE: tests::common
// PURPOSE: Reusable scaffolding for the integration tests in
//          `tests/`. One source of truth for:
//            * dummy DeployParams + deploy_into_sim
//            * adapter wrapper that lets us spend a coin whose puzzle
//              IS one of our action puzzles directly
//            * canonical Rust types for Election + Registration state
//              that match the Rue struct layouts
//            * helpers for building action solutions and signing
//              against the consensus AggSig conventions
//
// USAGE: `mod common;` at the top of each `tests/*.rs` file. Only the
//        items the importing test uses get pulled in (the rest are
//        dead-code-allowed below).

#![allow(dead_code)] // shared fixtures: each test uses a subset

use async_trait::async_trait;
use chia_bls::{PublicKey, SecretKey};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::deployer::{DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::chain::{ChainCoinRecord, ChainReader};
use chip_voting_sdk::config::{ElectionConfig, PUBLIC_INPUT_COUNT};
use chip_voting_sdk::error::VotingResult;
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{serde::node_to_bytes, Allocator, NodePtr};
use indexmap::indexset;

/// STRUCT: SharedSim
/// PURPOSE: integration-test ChainReader wrapper around a shared
///          mutable `chia_sdk_test::Simulator`. Mirrors the
///          private `chain::SharedSimulator` (which is `cfg(test)`-
///          gated to lib-tests); duplicated here so external
///          tests in `tests/` can drive Aggregator/Indexer
///          actors against a Simulator.
pub struct SharedSim(std::sync::Arc<std::sync::Mutex<*mut Simulator>>);

unsafe impl Send for SharedSim {}
unsafe impl Sync for SharedSim {}

impl SharedSim {
    /// Wrap a `&mut Simulator`. The borrow MUST outlive every
    /// actor that holds the resulting `SharedSim`.
    #[allow(clippy::arc_with_non_send_sync)] // SAFETY contract via Mutex
    pub fn new(sim: &mut Simulator) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(sim as *mut _)))
    }
}

#[async_trait]
impl ChainReader for SharedSim {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let guard = self.0.lock().expect("simulator mutex poisoned");
        let sim: &Simulator = unsafe { &**guard };
        Ok(sim
            .lookup_puzzle_hashes(indexset![puzzle_hash], false)
            .into_iter()
            .filter(|cs| cs.spent_height.is_none())
            .map(|cs| ChainCoinRecord {
                coin: cs.coin,
                spent_height: 0,
                confirmed_height: cs.created_height.unwrap_or(0),
            })
            .collect())
    }

    async fn coin_records_by_hint(&self, hint: Bytes32) -> VotingResult<Vec<ChainCoinRecord>> {
        let guard = self.0.lock().expect("simulator mutex poisoned");
        let sim: &Simulator = unsafe { &**guard };
        let coin_ids = sim.hinted_coins(hint);
        Ok(coin_ids
            .into_iter()
            .filter_map(|id| sim.coin_state(id))
            .map(|cs| ChainCoinRecord {
                coin: cs.coin,
                spent_height: cs.spent_height.unwrap_or(0),
                confirmed_height: cs.created_height.unwrap_or(0),
            })
            .collect())
    }

    async fn puzzle_and_solution(
        &self,
        coin_id: Bytes32,
    ) -> VotingResult<Option<(Program, Program)>> {
        let guard = self.0.lock().expect("simulator mutex poisoned");
        let sim: &Simulator = unsafe { &**guard };
        Ok(sim.puzzle_and_solution(coin_id))
    }

    async fn coin_record_by_id(&self, coin_id: Bytes32) -> VotingResult<Option<ChainCoinRecord>> {
        let guard = self.0.lock().expect("simulator mutex poisoned");
        let sim: &Simulator = unsafe { &**guard };
        Ok(sim.coin_state(coin_id).map(|cs| ChainCoinRecord {
            coin: cs.coin,
            spent_height: cs.spent_height.unwrap_or(0),
            confirmed_height: cs.created_height.unwrap_or(0),
        }))
    }

    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let guard = self.0.lock().expect("simulator mutex poisoned");
        let sim: &Simulator = unsafe { &**guard };
        let mut out = Vec::new();
        for &parent_id in parent_ids {
            for cs in sim.children(parent_id) {
                out.push(ChainCoinRecord {
                    coin: cs.coin,
                    spent_height: cs.spent_height.unwrap_or(0),
                    confirmed_height: cs.created_height.unwrap_or(0),
                });
            }
        }
        Ok(out)
    }

    /// The simulator doesn't expose a peak; tests don't need
    /// propagation tracking. Return `None`.
    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        Ok(None)
    }
}

// ── ElectionState / Truth shapes (match Rue layout) ────────────────
//
// Rue's `...field` syntax produces a flat cons chain ending in the
// trailing field directly (no nil terminator).
//
// ElectionState:
//   `(root . (count . (fees . (finalized . vote_outcome))))`
// ElectionStateTruth:
//   `(ephemeral . state)`
// Action solution shape:
//   `(truth . extra_args)` where action puzzles take `(Truth, ...)`
//   so the solution is `(truth, extra_args)` for a 2-tuple.

pub type ElectionStateClvm = (Bytes32, (u64, (u64, (u8, Bytes32))));
pub type ElectionStateTruthClvm = ((), ElectionStateClvm);

pub type RegistrationStateClvm<R> = (Bytes, (Bytes32, (u8, (Bytes32, R))));
pub type RegistrationStateTruthClvm<E, R> = (E, RegistrationStateClvm<R>);
/// Ephemeral set by the vote action (vote_data, signature).
pub type EphemeralVoteClvm = (Bytes32, Bytes);

/// Solution shape for the `release` action puzzle:
///   (Truth, dest, singleton_coin_id, finalized_outcome,
///    finalized_count, ...finalized_root)
/// The `singleton_coin_id` was added so the puzzle can compute the
/// FULL announcement_id (sha256(announcer_coin_id || message)) that
/// the consensus AssertCoinAnnouncement opcode validates against.
pub type ReleaseSolution<R> = (
    RegistrationStateTruthClvm<(), R>,
    (Bytes32, (Bytes32, (Bytes32, (u64, Bytes32)))),
);

/// Solution shape for the `vote` action puzzle:
///   (Truth, vote_data, ...vote_signature)
pub type VoteSolution<R> = (RegistrationStateTruthClvm<(), R>, (Bytes32, Bytes));

/// Build an ElectionState as a CLVM-encoded tuple.
pub fn build_election_state(
    root: Bytes32,
    count: u64,
    fees: u64,
    finalized: bool,
    vote_outcome: Bytes32,
) -> ElectionStateClvm {
    let f = if finalized { 1u8 } else { 0u8 };
    (root, (count, (fees, (f, vote_outcome))))
}

/// Build a pre-release RegistrationState (release_destination = nil).
pub fn build_registration_state_pre_release(
    voter_pk: &PublicKey,
    election_id: Bytes32,
    has_voted: bool,
    vote_data: Bytes32,
) -> RegistrationStateClvm<()> {
    let pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let hv = if has_voted { 1u8 } else { 0u8 };
    (pk_bytes, (election_id, (hv, (vote_data, ()))))
}

// ── Deploy fixtures ─────────────────────────────────────────────────

/// Canonical test DeployParams. VK is a zero-buffer of the right
/// length — sufficient for puzzle-hash math; never produces real
/// proofs.
pub fn dummy_deploy_params() -> DeployParams {
    DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash: Bytes32::new([0x77; 32]),
        collateral_amount: 1_000,
        // CHIP rev 2026-05-02: registration_fee and election_length_blocks
        // were dropped from DeployParams (per-ballot timing replaces the
        // global election length; XCH fee was removed entirely).
        election_start_height: 0,
        label: Some("integration-test".into()),
    }
}

/// Real test DeployParams that uses a deterministic
/// `generate_test_setup` VK so the finalize action's curried VK
/// matches a known ProvingKey. Returns BOTH the params and the
/// matching ProvingKey for end-to-end finalize tests.
pub fn real_deploy_params_with_pk() -> (
    DeployParams,
    chip_voting_sdk::prover::circuit::ArkProvingKey,
) {
    use ark_std::rand::SeedableRng;
    use chip_voting_sdk::prover::circuit::generate_test_setup;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
    let (pk, vk) = generate_test_setup(&mut rng).expect("generate_test_setup");
    let vk_bytes = vk.chia_chunked_bytes().expect("vk chunked bytes");
    let params = DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vk_bytes,
        },
        cat_tail_hash: Bytes32::new([0x77; 32]),
        collateral_amount: 1_000,
        // CHIP rev 2026-05-02: registration_fee + election_length_blocks dropped.
        election_start_height: 0,
        label: Some("integration-test-real-vk".into()),
    };
    (params, pk)
}

/// Deploy the election to a fresh simulator. Returns the resulting
/// (config, simulator) for use in Aggregator + chain-walk tests.
pub fn deploy_into_sim() -> (ElectionConfig, Simulator) {
    let mut sim = Simulator::new();
    let funder = sim.bls(1);
    let deployer = ElectionDeployer::new(dummy_deploy_params());
    let (coin_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(coin_spends, &[funder.sk])
        .expect("simulator accepts deploy bundle");
    (config, sim)
}

/// Deploy with a real test VK + return the matching ProvingKey.
/// Used by green-path finalize tests that need to actually run
/// the prover and have its VK match the on-chain curried VK.
pub fn deploy_with_real_pk_into_sim() -> (
    ElectionConfig,
    Simulator,
    chip_voting_sdk::prover::circuit::ArkProvingKey,
) {
    let (params, pk) = real_deploy_params_with_pk();
    let mut sim = Simulator::new();
    let funder = sim.bls(1);
    let deployer = ElectionDeployer::new(params);
    let (coin_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(coin_spends, &[funder.sk])
        .expect("simulator accepts deploy bundle");
    (config, sim, pk)
}

// ── Action puzzle adapter ───────────────────────────────────────────
//
// Each action puzzle returns `(StateTruth . Conditions)`; a coin's
// puzzle must return JUST `Conditions`. The adapter strips the
// state_truth via `(r ...)` so the consensus runner sees a plain
// conditions list.

/// Wrap an action puzzle in `(r (a 2 (c 5 ())))` — the SINGLE-ARG
/// adapter:
///   - `r`        (rest)        — drop the `(state_truth . _)` head
///   - `a`        (apply)       — apply the action puzzle
///   - env path 2 — the curried action puzzle
///   - `(c 5 ())` — wrap the user-supplied truth in a 1-element env
///                  list so the action puzzle's `path 2 = truth`
///                  destructure works.
///
/// USE FOR: action puzzles that take only `Truth` (no extra args) —
/// e.g., `announce_finalization`. For multi-arg actions (`vote`,
/// `release`, `register`), use [`build_action_wrapper_multi_node`].
pub fn build_action_wrapper_node(allocator: &mut Allocator, action_puzzle_hex: &str) -> NodePtr {
    let bytecode = hex::decode("ff06ffff02ff02ffff04ff05ff80808080").unwrap();
    let wrapper_program = Program::from(bytecode);
    let wrapper_node = wrapper_program.to_clvm(allocator).unwrap();
    let action_bytes = hex::decode(action_puzzle_hex.trim().trim_start_matches("0x")).unwrap();
    let action_program = Program::from(action_bytes);
    let action_node = action_program.to_clvm(allocator).unwrap();
    CurriedProgram {
        program: wrapper_node,
        args: clvm_curried_args!(action_node),
    }
    .to_clvm(allocator)
    .unwrap()
}

pub fn build_action_wrapper_hash(allocator: &mut Allocator, action_puzzle_hex: &str) -> Bytes32 {
    let node = build_action_wrapper_node(allocator, action_puzzle_hex);
    Bytes32::new(tree_hash(allocator, node).to_bytes())
}

/// Wrap an action puzzle in `(r (a 2 3))` — the MULTI-ARG adapter:
///   - `r`        (rest)        — drop the `(state_truth . _)` head
///   - `a`        (apply)       — apply the action puzzle
///   - env path 2 — the curried action puzzle
///   - env path 3 — `(r env)` = the WHOLE user solution, passed
///                  directly as the action's env (no rewrapping).
///                  The user solution's structural shape becomes the
///                  action puzzle's env, so the action's:
///                    path 2 = first(user_solution) = first arg (Truth)
///                    path 5 = first(rest(user_solution)) = second arg
///                    path 7 = rest(rest(user_solution)) = trailing
///                            `...` arg
///
/// USE FOR: vote / release / register — actions that take `Truth +
/// extra args` with a trailing `...` field.
///
/// SOLUTION SHAPE: callers should construct the solution as the
/// EXACT env the action puzzle expects. E.g. for vote
/// (Truth, vote_data, ...vote_signature):
///   `(truth, (vote_data, vote_signature_bytes))`
/// = `(truth . (vote_data . vote_signature_bytes))` — matches the
/// Rue-compiled env layout (no nil terminator at the end because of
/// the `...`).
pub fn build_action_wrapper_multi_node(
    allocator: &mut Allocator,
    action_puzzle_hex: &str,
) -> NodePtr {
    // (r (a 2 3)) serialised:
    //   ff (cons)
    //   06 (r)
    //   ff (cons)
    //     ff 02 (a)
    //     ff 02 (path 2 = action)
    //     ff 03 (path 3 = (r env) = user solution)
    //     80    (terminator of `a`'s args)
    //   80    (terminator of `r`'s args)
    let bytecode = hex::decode("ff06ffff02ff02ff038080").unwrap();
    let wrapper_program = Program::from(bytecode);
    let wrapper_node = wrapper_program.to_clvm(allocator).unwrap();
    let action_bytes = hex::decode(action_puzzle_hex.trim().trim_start_matches("0x")).unwrap();
    let action_program = Program::from(action_bytes);
    let action_node = action_program.to_clvm(allocator).unwrap();
    CurriedProgram {
        program: wrapper_node,
        args: clvm_curried_args!(action_node),
    }
    .to_clvm(allocator)
    .unwrap()
}

pub fn build_action_wrapper_multi_hash(
    allocator: &mut Allocator,
    action_puzzle_hex: &str,
) -> Bytes32 {
    let node = build_action_wrapper_multi_node(allocator, action_puzzle_hex);
    Bytes32::new(tree_hash(allocator, node).to_bytes())
}

/// Construct a CoinSpend from a NodePtr puzzle + NodePtr solution.
pub fn coin_spend_from_nodes(
    allocator: &Allocator,
    coin: Coin,
    puzzle_node: NodePtr,
    solution_node: NodePtr,
) -> CoinSpend {
    let puzzle_bytes = node_to_bytes(allocator, puzzle_node).unwrap();
    let solution_bytes = node_to_bytes(allocator, solution_node).unwrap();
    CoinSpend::new(
        coin,
        Program::from(puzzle_bytes),
        Program::from(solution_bytes),
    )
}

/// Build a SpendBundle from coin spends + signature.
pub fn make_bundle(coin_spends: Vec<CoinSpend>, sig: chia_bls::Signature) -> SpendBundle {
    SpendBundle::new(coin_spends, sig)
}

// ── Canonical message derivations ──────────────────────────────────
//
// These mirror the on-chain Rue helpers EXACTLY. Tests that build
// signatures use them so the consensus AggSig validation accepts.

/// Canonical vote message:
///   `sha256("vote" || election_id || voter_pubkey || vote_data)`
/// Mirror of `puzzles/registration_coin/vote.rue`.
pub fn vote_message(election_id: Bytes32, voter_pk: &PublicKey, vote_data: Bytes32) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vote");
    h.update(election_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(vote_data.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// Canonical release message:
///   `sha256("release" || election_id || voter_pubkey || destination)`
/// Mirror of `puzzles/registration_coin/release.rue`.
pub fn release_message(
    election_id: Bytes32,
    voter_pk: &PublicKey,
    destination: Bytes32,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"release");
    h.update(election_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(destination.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// Canonical finalization announcement message:
///   `sha256("finalized" || vote_outcome || count_be8 || merkle_root)`
/// Mirror of `puzzles/election/shared.rue::finalization_announcement_msg`.
pub fn finalization_announcement_msg(
    vote_outcome: Bytes32,
    count: u64,
    merkle_root: Bytes32,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"finalized");
    h.update(vote_outcome.as_ref());
    h.update(count.to_be_bytes());
    h.update(merkle_root.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

// ── BLS signing helpers ─────────────────────────────────────────────

/// Sign a message for an `AggSigUnsafe` condition.
/// Consensus expects augmented BLS (chia_bls::sign prepends the pk).
pub fn sign_aggsig_unsafe(sk: &SecretKey, raw_message: Bytes32) -> chia_bls::Signature {
    chia_bls::sign(sk, raw_message.as_ref())
}

/// Sign a message for an `AggSigMe` condition.
///   `aggregated_message = raw_message || coin_id || agg_sig_me_data`
///   then augmented by `chia_bls::sign` (prepends pk).
pub fn sign_aggsig_me(sk: &SecretKey, raw_message: Bytes32, coin: &Coin) -> chia_bls::Signature {
    let agg_sig_data = chia_sdk_types::TESTNET11_CONSTANTS.agg_sig_me_additional_data;
    let mut full = Vec::with_capacity(32 + 32 + 32);
    full.extend_from_slice(raw_message.as_ref());
    full.extend_from_slice(coin.coin_id().as_ref());
    full.extend_from_slice(agg_sig_data.as_ref());
    chia_bls::sign(sk, &full)
}

/// A deterministic test voter (sk + pk).
pub fn test_voter(seed_byte: u8) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_seed(&[seed_byte; 32]);
    let pk = sk.public_key();
    (sk, pk)
}
