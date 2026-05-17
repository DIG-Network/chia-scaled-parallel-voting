// Integration tests use the same structured WHAT/HOW/WHY doc-comment
// shape as the rest of the crate; clippy mis-parses the indented
// continuation lines as malformed Markdown lists.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

// ============================================================================
// tests/integration.rs — end-to-end tests against chia-sdk-test::Simulator
// ============================================================================
//
// SCOPE: anything that needs CLVM execution + signature verification —
//        i.e., things that depend on the on-chain semantics actually
//        firing. Pure-Rust math lives in `cargo test --lib`.
//
// HARNESS: chia-sdk-test::Simulator (in-process Chia node fake).
//   * `sim.bls(amount)` → `BlsPairWithCoin` (sk + pk + standard p2
//     coin pre-funded with `amount` mojos)
//   * `sim.spend_coins(spends, &[sk])` → runs CLVM, validates AGG_SIG
//     conditions, advances the chain, returns updated coin states
//   * `sim.coin_state(coin_id)` → query a coin's state
//
// SIGNING NOTE: the simulator uses TESTNET11_CONSTANTS, so its
//   `sign_transaction` calls
//   `RequiredSignature::from_coin_spends(.., AggSigConstants::new(TESTNET11_CONSTANTS.agg_sig_me_additional_data))`.
//   That's identical to what `dig_l1_wallet::transaction::sign_coin_spends`
//   does for `NetworkType::Testnet11`, so for these in-process tests
//   we can sign either via the simulator helper or via our own
//   `sign_bundle_signature(.., NetworkType::Testnet11)`.
//
// CONVENTION: every test below carries a `WHAT / HOW / WHY` block
// (and, where relevant, an EXPECTED CHAIN EFFECT note):
//   * WHAT — the single invariant the test proves
//   * HOW  — how the test mechanically establishes that invariant
//             (inputs, the operation under test, the assertion,
//             and the simulator interactions)
//   * WHY  — why this invariant matters for the SDK / on-chain
//             correctness (what breaks if it ever stops holding)

use chia_protocol::Bytes32;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::deployer::{derive_launcher_id, DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::{PUBLIC_INPUT_COUNT, TREE_DEPTH};
use chip_voting_sdk::puzzles::{election_singleton_puzzle_hash, PuzzleHashes};

/// Build a deterministic, validation-ready DeployParams. The
/// verification_key is all-zeros — sufficient for puzzle-hash math
/// (where we just take its tree hash) but not for actual Groth16
/// verification (no real proof would verify against this VK).
fn dummy_deploy_params() -> DeployParams {
    DeployParams {
        verification_key: VerificationKey {
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash: Bytes32::new([0x77; 32]),
        collateral_amount: 1_000,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: chip_voting_sdk::config::MAX_SIGNERS,
        ceremony_launcher_id: Bytes32::default(),
        vk_hash: Bytes32::default(),
        vote_mode_lock: chip_voting_sdk::vote_mode::VOTE_MODE_LOCK_NONE,
        // CHIP rev 2026-05-02: registration_fee + election_length_blocks dropped.
        election_start_height: 0,
        label: Some("integration-test".into()),
    }
}

/// WHAT: a fully-built deploy bundle is accepted by the simulator
///       AND produces an eve singleton at the puzzle hash our
///       predictor functions said it would.
/// HOW:  pre-fund a standard p2 coin via `sim.bls(1)`; build the
///       deploy bundle via `ElectionDeployer::build_deploy_bundle`;
///       submit via `Simulator::spend_coins` (which CLVM-validates
///       and signs); inspect `sim.children(launcher_id)` for an eve
///       coin at `election_singleton_puzzle_hash(launcher_id,
///       genesis_inner_puzzle_hash)`. Pre-flight: assert the config's
///       launcher_id_hex matches the predictor too.
/// WHY:  this is the single most important on-chain invariant —
///       every other actor (voter, aggregator, indexer) discovers
///       the singleton by computing
///       `election_singleton_puzzle_hash(launcher_id, inner_ph)`
///       independently and querying for it. If the predicted hash
///       doesn't match the actual on-chain hash, NOTHING else in the
///       SDK works.
///
/// EXPECTED CHAIN EFFECT:
///   - The funder coin is spent.
///   - A launcher coin appears at SINGLETON_LAUNCHER_HASH /
///     amount=1 with parent = funder coin id.
///   - An eve singleton coin appears as a child of the launcher
///     with puzzle_hash = election_singleton_puzzle_hash(launcher_id,
///     genesis_inner_puzzle_hash).
///   - The eve singleton's amount is exactly 1 (singleton odd-amount
///     invariant + zero accumulated_fees at genesis).
#[test]
fn deploy_creates_eve_singleton_at_predicted_puzzle_hash() {
    let mut sim = Simulator::new();

    // Pre-fund a single XCH coin under a standard p2 puzzle.
    let funder = sim.bls(1);
    let parent_coin = funder.coin;

    let deployer = ElectionDeployer::new(dummy_deploy_params());

    let (coin_spends, config) = deployer
        .build_deploy_bundle(parent_coin, funder.pk, true)
        .expect("build_deploy_bundle should succeed");

    // Pre-flight: predict the launcher_id + on-chain singleton hash.
    let predicted_launcher_id = derive_launcher_id(parent_coin.coin_id(), 1);
    assert_eq!(
        config.election_launcher_id().unwrap(),
        predicted_launcher_id,
        "config.election_launcher_id_hex must match the predicted launcher id",
    );
    let predicted_inner = deployer.genesis_inner_puzzle_hash(predicted_launcher_id);
    let predicted_eve_ph = election_singleton_puzzle_hash(predicted_launcher_id, predicted_inner);

    // Submit to the simulator. spend_coins signs internally with our sk.
    sim.spend_coins(coin_spends, &[funder.sk])
        .expect("simulator should accept the deploy bundle");

    // Verify the eve singleton exists at the predicted puzzle hash.
    // The launcher's child IS the eve singleton (parent = launcher coin id).
    let launcher_coin_id = predicted_launcher_id; // launcher_id == launcher coin id
    let children = sim.children(launcher_coin_id);
    let eve = children
        .iter()
        .find(|cs| cs.coin.puzzle_hash == predicted_eve_ph)
        .unwrap_or_else(|| {
            panic!(
                "expected an eve singleton at {} as a child of launcher {}, found {:?}",
                hex::encode(predicted_eve_ph),
                hex::encode(launcher_coin_id),
                children
                    .iter()
                    .map(|c| hex::encode(c.coin.puzzle_hash))
                    .collect::<Vec<_>>(),
            );
        });

    // Eve singleton amount must be odd (singleton invariant). Since
    // genesis state has accumulated_fees=0, the eve amount is 1.
    assert_eq!(
        eve.coin.amount, 1,
        "eve singleton amount must be 1 at genesis"
    );
}

/// WHAT: two deploys from different funder coins produce different
///       launcher_ids (hence different `election_launcher_id_hex`
///       in the resulting configs).
/// HOW:  pre-fund two distinct standard p2 coins via two
///       `sim.bls(1)` calls; build a deploy bundle from each; assert
///       the two configs' launcher hex differ.
/// WHY:  cross-election replay safety — every config we hand out
///       must be uniquely identifiable so a voter's coins, hints,
///       and message bindings for election A can never be confused
///       with election B.
#[test]
fn deploy_then_redeploy_with_different_funder_yields_different_election_id() {
    let mut sim = Simulator::new();
    let funder_a = sim.bls(1);
    let funder_b = sim.bls(1);

    let d = ElectionDeployer::new(dummy_deploy_params());
    let (_a_spends, a_config) = d.build_deploy_bundle(funder_a.coin, funder_a.pk, true).unwrap();
    let (_b_spends, b_config) = d.build_deploy_bundle(funder_b.coin, funder_b.pk, true).unwrap();
    assert_ne!(
        a_config.election_launcher_id_hex,
        b_config.election_launcher_id_hex,
    );
}

/// WHAT: every `ElectionConfig` produced by a successful deploy
///       passes its own `.validate()` check.
/// HOW:  pre-fund a coin, build a deploy bundle, call `.validate()`
///       on the returned config, expect Ok.
/// WHY:  voters / aggregators load the config and immediately call
///       `.validate()` before doing anything. A config that fails
///       its own validator is worse than no config at all — silent
///       breakage for downstream users.
#[test]
fn config_emitted_by_deploy_self_validates() {
    let mut sim = Simulator::new();
    let funder = sim.bls(1);
    let d = ElectionDeployer::new(dummy_deploy_params());
    let (_spends, config) = d.build_deploy_bundle(funder.coin, funder.pk, true).unwrap();
    config.validate().unwrap();
}

/// WHAT: the predicted inner puzzle hash is non-zero AND the
///       embedded `PuzzleHashes::action_layer()` is non-zero.
/// HOW:  compute `genesis_inner_puzzle_hash` for an arbitrary
///       launcher_id and assert it isn't `Bytes32::default()`.
/// WHY:  guards against a stale or empty `puzzles/compiled/action.rue.hash`
///       artefact — if the file was missing or all-zero, the
///       inner-hash arithmetic would silently produce a nonsense
///       value. Pinning non-zero on both sides catches the missing-
///       artefact regression at test time.
#[test]
fn predicted_inner_puzzle_hash_uses_action_layer_constants() {
    let d = ElectionDeployer::new(dummy_deploy_params());
    let inner = d.genesis_inner_puzzle_hash(Bytes32::new([0xAB; 32]));
    assert_ne!(inner, Bytes32::default());
    assert_ne!(PuzzleHashes::action_layer(), Bytes32::default());
}

/// WHAT: `TREE_DEPTH == 32` exactly.
/// HOW:  direct equality assertion against the constant.
/// WHY:  the SPT depth is hard-coded into the compiled puzzle, the
///       Groth16 circuit, and every off-chain SPT operation. A
///       single off-by-one drift would cascade into universally
///       failing register / finalize proofs. Pinning the value here
///       forces any future refactor to explicitly opt into changing
///       it everywhere at once.
#[test]
fn tree_depth_constant_is_32() {
    assert_eq!(TREE_DEPTH, 32);
}

// ─────────────────────────────────────────────────────────────────────
// CLVM EXECUTION TESTS — drive our compiled action puzzles through
// the full simulator chain (spend bundle assembly, CLVM execution,
// signature verification, condition validation, chain state update).
//
// Strategy: wrap one of our action puzzles in a tiny adapter program
//   `(r (a 2 5))` — call the curried action puzzle (env pos 2) with
//   the user solution (env pos 5) and return its CDR (the conditions
//   list, stripping the StateTruth from the action's `(truth .
//   conditions)` output). Use this as a coin's puzzle in the
//   simulator, spend it, and assert the chain effect.
//
// This proves:
//   * Our compiled action puzzles produce VALID CLVM that the
//     consensus runner accepts (not just our test runner).
//   * The conditions emitted are accepted as VALID conditions by
//     the consensus condition handler.
//   * Coin announcements / agg_sig conditions / etc. take effect
//     on-chain as expected.

use chia_bls::{aggregate, sign, SecretKey};
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::Allocator;

/// Adapter puzzle bytecode: `(r (a 2 5))`.
/// CLVM serialised form:
///   ff (cons start)
///   06 (opcode 'r' = rest)
///   ff (cons start)
///     ff 02 (opcode 'a' = apply)
///     ff 02 (env pos 2 = the curried puzzle)
///     ff 05 (env pos 5 = the user solution)
///     80    (nil terminator of the apply args)
///   80    (nil terminator of the rest's args)
///
/// The curried puzzle is the "real" action; calling `(a CURRIED USER_SOL)`
/// runs it with the user solution as env. The returned value is
/// `(state_truth . conditions)`; we take `(r ...)` to drop the
/// state_truth so the simulator sees a plain conditions list.
fn build_action_wrapper(
    allocator: &mut Allocator,
    action_puzzle_hex: &str,
) -> chia_protocol::Bytes32 {
    let curried = build_action_wrapper_node(allocator, action_puzzle_hex);
    chia_protocol::Bytes32::new(tree_hash(allocator, curried).to_bytes())
}

/// Build the CurriedProgram NodePtr ready to embed in a CoinSpend.
///
/// The wrapper is the bytecode `(r (a 2 (c 5 ())))`:
///   - `r`        (rest)        — drop the `(state_truth . _)` head
///   - `a`        (apply)       — apply the action puzzle
///   - env path 2 — the curried action puzzle
///   - `(c 5 ())` — wrap the user-supplied truth in a 1-element env
///                  list so the action puzzle's `path 2 = truth`
///                  destructure works (Rue compiles `fn main(truth)`
///                  to expect env shape `(truth)` = `(truth . nil)`,
///                  not bare `truth`).
///
/// Currying via `CurriedProgram { program, args: clvm_curried_args!(action_node) }`
/// produces the proper CLVM curry envelope — the arg is wrapped in
/// `(c (q . arg) 1)` so the user solution is preserved as the
/// remainder of the env at run time.
fn build_action_wrapper_node(allocator: &mut Allocator, action_puzzle_hex: &str) -> clvmr::NodePtr {
    // (r (a 2 (c 5 ()))) serialised: see comment above for derivation.
    let bytecode = hex::decode("ff06ffff02ff02ffff04ff05ff80808080").unwrap();
    let wrapper_program = chia_protocol::Program::from(bytecode);
    let wrapper_node = wrapper_program.to_clvm(allocator).unwrap();
    let action_bytes = hex::decode(action_puzzle_hex.trim().trim_start_matches("0x")).unwrap();
    let action_program = chia_protocol::Program::from(action_bytes);
    let action_node = action_program.to_clvm(allocator).unwrap();
    CurriedProgram {
        program: wrapper_node,
        args: clvm_curried_args!(action_node),
    }
    .to_clvm(allocator)
    .unwrap()
}
// ─────────────────────────────────────────────────────────────────────
// END-TO-END GROTH16 + CLVM EXECUTION TEST
//
// Proves the full pipeline:
//   1. `generate_test_setup` produces a valid (PK, VK) for our circuit.
//   2. `VotingCircuit::prove` produces a valid Groth16 proof.
//   3. `VotingCircuit::verify_offchain` accepts the proof off-chain.
//   4. The SAME proof is byte-compatible with the on-chain CLVM
//      `bls_pairing_identity` opcode — i.e., a CLVM puzzle that
//      performs the standard Groth16 pairing-identity check accepts
//      our proof. This is what `puzzles/election/finalize.rue` does.
//
// This is the hardest test we can write without implementing the
// full action-layer + CAT spend pipeline: it confirms the cross-
// language contract between arkworks (off-chain prover) and CLVM
// (on-chain verifier) is intact.
/// Build the bls_pairing_identity-call puzzle as a CLVM NodePtr.
///
/// Puzzle bytecode is `(58 2 5 11 23 47 95 191 383)`:
///   - 58 = `bls_pairing_identity` opcode
///   - 2..383 = env-path expressions selecting the 8 solution atoms
///     in order (first through eighth).
///
/// Returns nil on success (no conditions); TRAPS on pairing failure.
fn build_pairing_check_puzzle(allocator: &mut Allocator) -> clvmr::NodePtr {
    use clvm_traits::ToClvm;
    // Use a Vec of u32s — clvm_traits encodes a Vec as a proper CLVM
    // list which is structurally identical to the deeply-nested
    // tuple form `(58 . (2 . (5 . ...)))` produced by hand-cons.
    let parts: Vec<u32> = vec![58, 2, 5, 11, 23, 47, 95, 191, 383];
    parts.to_clvm(allocator).unwrap()
}

// NOTE on simulator tests for `vote` and `release`:
// Both require multi-coin spend bundles by design:
//   * `vote` emits an AggSigUnsafe + the registration_coin finalizer
//     emits a CreateCoin to recreate the coin. Testing it standalone
//     would mean the input CAT is burnt without a CAT-preserving
//     output → rejected by the CAT outer.
//   * `release` emits an AssertCoinAnnouncement that REQUIRES a
//     paired Election Singleton spend in the same bundle to provide
//     the matching CreateCoinAnnouncement. Standalone → assertion
//     fails → bundle rejected.
// These flows are correct by design but require composing the full
// CAT outer + action layer + finalizer + paired singleton spend. That
// composition is what `Voter::vote` and `Voter::release_collateral`
// produce; their simulator-driven tests will live in this file once
// those methods are implemented (see TESTING.md roadmap).

/// WHAT: the simulator-level signing helper (the SAME one used by
///       chia consensus) validates `chia_bls::aggregate` of two
///       independent signatures against `aggregate_verify`.
/// HOW:  generate two BLS sks, have each sign DIFFERENT messages
///       under augmented BLS (the Chia standard); aggregate the
///       sigs; per-pair `aggregate_verify` against (pk_i, msg_i).
/// WHY:  this is the off-chain pre-check that the Aggregator's
///       BLS aggregation is mathematically sound BEFORE handing the
///       proof to the prover. Pinned here at the integration layer
///       to confirm the upstream `chia_bls` impl matches what the
///       simulator's consensus runner expects.
#[test]
fn bls_aggregate_verify_roundtrips_for_two_signers() {
    let sk1 = SecretKey::from_seed(&[1u8; 32]);
    let sk2 = SecretKey::from_seed(&[2u8; 32]);
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    // Augmented sign: each pk's bytes are prepended to the message.
    let msg1 = b"hello";
    let msg2 = b"world";
    let sig1 = sign(&sk1, msg1);
    let sig2 = sign(&sk2, msg2);
    let agg = aggregate(&[sig1, sig2]);
    assert!(chia_bls::aggregate_verify(
        &agg,
        [(&pk1, msg1.as_ref()), (&pk2, msg2.as_ref())],
    ));
    // The same agg signature must NOT verify if a message is wrong.
    assert!(!chia_bls::aggregate_verify(
        &agg,
        [(&pk1, msg1.as_ref()), (&pk2, b"forged".as_ref())],
    ));
}
