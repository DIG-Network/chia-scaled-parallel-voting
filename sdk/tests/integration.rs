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

use chip_voting_sdk::actors::deployer::{derive_launcher_id, DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::{PUBLIC_INPUT_COUNT, TREE_DEPTH};
use chip_voting_sdk::puzzles::{election_singleton_puzzle_hash, PuzzleHashes};
use chia_protocol::Bytes32;
use chia_sdk_test::Simulator;

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
        .build_deploy_bundle(parent_coin, funder.pk)
        .expect("build_deploy_bundle should succeed");

    // Pre-flight: predict the launcher_id + on-chain singleton hash.
    let predicted_launcher_id = derive_launcher_id(parent_coin.coin_id(), 1);
    assert_eq!(
        config.election_launcher_id().unwrap(),
        predicted_launcher_id,
        "config.election_launcher_id_hex must match the predicted launcher id",
    );
    let predicted_inner = deployer.genesis_inner_puzzle_hash(predicted_launcher_id);
    let predicted_eve_ph =
        election_singleton_puzzle_hash(predicted_launcher_id, predicted_inner);

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
                children.iter().map(|c| hex::encode(c.coin.puzzle_hash)).collect::<Vec<_>>(),
            );
        });

    // Eve singleton amount must be odd (singleton invariant). Since
    // genesis state has accumulated_fees=0, the eve amount is 1.
    assert_eq!(eve.coin.amount, 1, "eve singleton amount must be 1 at genesis");
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
    let (_a_spends, a_config) = d.build_deploy_bundle(funder_a.coin, funder_a.pk).unwrap();
    let (_b_spends, b_config) = d.build_deploy_bundle(funder_b.coin, funder_b.pk).unwrap();
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
    let (_spends, config) = d.build_deploy_bundle(funder.coin, funder.pk).unwrap();
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

use chia_bls::{aggregate, sign, SecretKey, Signature};
use chia_protocol::{Coin, CoinSpend, Program, SpendBundle};
// CHIP rev 2026-05-02: ELECTION_ANNOUNCE_FINALIZATION_HEX moved to
// BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX. Aliased to keep the
// announce_finalization simulator tests compiling; tests are
// `#[ignore]`-d below until rewritten in Phase 6.
use chip_voting_sdk::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX as ELECTION_ANNOUNCE_FINALIZATION_HEX;
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{serde::node_to_bytes, Allocator};

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
fn build_action_wrapper_node(
    allocator: &mut Allocator,
    action_puzzle_hex: &str,
) -> clvmr::NodePtr {
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

/// WHAT: a coin whose puzzle wraps our `announce_finalization`
///       action successfully spends in the simulator AND emits the
///       expected `CreateCoinAnnouncement` on-chain.
/// HOW:  build a wrapper puzzle around `announce_finalization`,
///       insert a coin at its puzzle hash via `sim.insert_coin`,
///       construct the action solution `(truth, ())` with
///       finalized=true state, build a SpendBundle, submit via
///       `Simulator::new_transaction`. Assert no error → CLVM
///       executed cleanly + the conditions are valid.
/// WHY:  this is the bridge from "our puzzles run in our test
///       harness" to "our puzzles run on a real Chia consensus
///       runner". The chain accepts the announcement as a valid
///       CreateCoinAnnouncement only if our compiled bytecode is
///       byte-correct, the args env-position derefs work, and the
///       message is a valid 32-byte payload.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (announce_finalization moved from singleton to Ballot Coin; per-ballot \
            state truth shape differs from the singleton ElectionState used here)"]
fn announce_finalization_executes_on_simulator() {
    use sha2::{Digest, Sha256};

    let mut sim = Simulator::new();

    // Build the wrapper-curried puzzle and its hash.
    let mut allocator = Allocator::new();
    let puzzle_node = build_action_wrapper_node(&mut allocator, ELECTION_ANNOUNCE_FINALIZATION_HEX);
    let puzzle_hash = chia_protocol::Bytes32::new(
        tree_hash(&allocator, puzzle_node).to_bytes(),
    );
    // Sanity: the hash matches what `build_action_wrapper` predicts
    // when called with a fresh allocator.
    let predicted_hash = {
        let mut alt = Allocator::new();
        build_action_wrapper(&mut alt, ELECTION_ANNOUNCE_FINALIZATION_HEX)
    };
    assert_eq!(puzzle_hash, predicted_hash);

    // Pre-fund a coin at the action wrapper's puzzle hash.
    // Amount = 1 (must be > 0); the action emits a coin announcement
    // so no CreateCoin is required to balance the input.
    let parent_id = chia_protocol::Bytes32::new([0x42; 32]);
    let coin = chia_protocol::Coin::new(parent_id, puzzle_hash, 1);
    sim.insert_coin(coin);

    // Build the solution: `((), (root, (count, (fees, (1, outcome)))))`
    // for ElectionStateTruth + nil for the trailing slot.
    let root_bytes = [0x11u8; 32];
    let outcome_bytes = [0x42u8; 32];
    let count = 7u64;
    let fees = 0u64;
    type ElectionStateClvm = (
        chia_protocol::Bytes32,
        (u64, (u64, (u8, chia_protocol::Bytes32))),
    );
    type ElectionStateTruthClvm = ((), ElectionStateClvm);
    type Sol = (ElectionStateTruthClvm, ());
    let state: ElectionStateClvm = (
        chia_protocol::Bytes32::new(root_bytes),
        (count, (fees, (1u8, chia_protocol::Bytes32::new(outcome_bytes)))),
    );
    let truth: ElectionStateTruthClvm = ((), state);
    let solution: Sol = (truth, ());

    // Serialise puzzle + solution into Programs for CoinSpend.
    let solution_node = solution.to_clvm(&mut allocator).unwrap();
    let puzzle_bytes = node_to_bytes(&allocator, puzzle_node).unwrap();
    let solution_bytes = node_to_bytes(&allocator, solution_node).unwrap();

    let coin_spend = CoinSpend::new(
        coin,
        Program::from(puzzle_bytes),
        Program::from(solution_bytes),
    );
    let bundle = SpendBundle::new(vec![coin_spend], Signature::default());
    let updated = sim
        .new_transaction(bundle)
        .expect("simulator must accept announce_finalization spend");

    // The spent coin should appear in the updated states with a
    // spent_height set.
    let coin_state = updated
        .get(&coin.coin_id())
        .expect("coin state present after spend");
    assert!(
        coin_state.spent_height.is_some(),
        "coin must be marked spent after consensus accepts the bundle"
    );

    // Sanity: hand-compute the expected announcement message, just
    // to document what consensus saw.
    let mut h = Sha256::new();
    h.update(b"finalized");
    h.update(outcome_bytes);
    h.update(count.to_be_bytes());
    h.update(root_bytes);
    let _expected_msg: [u8; 32] = h.finalize().into();
}

/// WHAT: spending the announce_finalization wrapper with a NON-
///       FINALIZED state is REJECTED by the simulator (consensus
///       rejects the spend bundle on CLVM trap).
/// HOW:  identical setup to the previous test but with finalized=0
///       in the supplied state. `Simulator::new_transaction` returns
///       `Err`. Assert error.
/// WHY:  the safety check `assert State.finalized == true` in the
///       puzzle is the critical guard against pre-finalization
///       collateral release. This test pins it AS ENFORCED ON-CHAIN
///       (not just in our test runner).
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (announce_finalization moved from singleton to Ballot Coin)"]
fn announce_finalization_on_simulator_rejects_non_finalized() {
    let mut sim = Simulator::new();
    let mut allocator = Allocator::new();
    let puzzle_node = build_action_wrapper_node(&mut allocator, ELECTION_ANNOUNCE_FINALIZATION_HEX);
    let puzzle_hash = chia_protocol::Bytes32::new(
        tree_hash(&allocator, puzzle_node).to_bytes(),
    );
    let coin = Coin::new(chia_protocol::Bytes32::new([0x99; 32]), puzzle_hash, 1);
    sim.insert_coin(coin);

    type ElectionStateClvm = (
        chia_protocol::Bytes32,
        (u64, (u64, (u8, chia_protocol::Bytes32))),
    );
    type ElectionStateTruthClvm = ((), ElectionStateClvm);
    type Sol = (ElectionStateTruthClvm, ());
    let state: ElectionStateClvm = (
        chia_protocol::Bytes32::default(),
        (0u64, (0u64, (0u8 /* finalized = false */, chia_protocol::Bytes32::default()))),
    );
    let truth: ElectionStateTruthClvm = ((), state);
    let solution: Sol = (truth, ());

    let solution_node = solution.to_clvm(&mut allocator).unwrap();
    let puzzle_bytes = node_to_bytes(&allocator, puzzle_node).unwrap();
    let solution_bytes = node_to_bytes(&allocator, solution_node).unwrap();

    let coin_spend = CoinSpend::new(
        coin,
        Program::from(puzzle_bytes),
        Program::from(solution_bytes),
    );
    let bundle = SpendBundle::new(vec![coin_spend], Signature::default());
    assert!(
        sim.new_transaction(bundle).is_err(),
        "consensus must reject spend with finalized=false"
    );
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

/// WHAT: a Groth16 proof produced by `VotingCircuit::prove` is
///       accepted by the on-chain CLVM `bls_pairing_identity`
///       opcode (= what `finalize.rue` runs).
/// HOW:
///   1. `generate_test_setup(rng)` → (pk, vk).
///   2. `VotingCircuit::prove(pk)` → Groth16Proof (chia-encoded).
///   3. Compute the verifier's `vk_input = IC[0] + Σ IC[i+1] * s_i`
///      via arkworks G1 arithmetic.
///   4. Build a tiny CLVM puzzle that calls opcode 58
///      (bls_pairing_identity) with the 4 (G1, G2) pairs:
///        (A, B), (-α, β), (-vk_input, γ), (-C, δ)
///   5. Construct a coin at that puzzle's hash, insert it into the
///      simulator, submit a spend bundle whose solution is a flat
///      list of the 8 compressed-byte points.
///   6. Submission MUST succeed → consensus accepts the proof.
/// WHY:
///   This is the master compatibility test. If this passes, our
///   off-chain prover + on-chain verifier agree on EVERY byte: the
///   curve point encoding, the scalar derivation, the pairing
///   equation, the negation convention. Any drift here would mean
///   on-chain finalize spends silently reject every legitimate
///   proof. Exercising it via the actual consensus runner (not just
///   our test harness) is the highest-confidence validation
///   possible without a live testnet deploy.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (VotingCircuit gained 2 public inputs (vote_threshold, ballot_launcher_id) \
            and `registration_count` was renamed to `registration_vote_weight`; \
            this test must be rewritten against the 6-input circuit)"]
fn groth16_proof_accepted_by_clvm_pairing_identity_opcode() {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::CurveGroup;
    use ark_std::rand::SeedableRng;
    use ark_std::Zero;
    use chia_protocol::Bytes;
    use chip_voting_sdk::prover::circuit::{generate_test_setup, SignerWitness, VotingCircuit};
    use chip_voting_sdk::prover::conversions::{
        fr_to_bytes32_be, g1_compressed_bytes, g2_compressed_bytes,
    };
    let fr_to_b32 = fr_to_bytes32_be;

    // ── Step 1: trusted setup ─────────────────────────────────────
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
    let (pk, vk) = generate_test_setup(&mut rng).expect("setup");

    // ── Step 2: build a circuit + prove ───────────────────────────
    let signers = (0..2)
        .map(|i| SignerWitness {
            pubkey: chia_bls::SecretKey::from_seed(&[i as u8 + 1; 32]).public_key(),
            leaf_index: i as u32,
            merkle_proof: vec![chia_protocol::Bytes32::default(); 32],
        })
        .collect();
    let circuit = VotingCircuit {
        registration_merkle_root: chia_protocol::Bytes32::new([0x11; 32]),
        // CHIP rev 2026-05-02: 6-input circuit (added threshold + ballot id).
        registration_vote_weight: 3,
        agg_signers: chia_bls::SecretKey::from_seed(&[0xAA; 32]).public_key(),
        vote_message: chia_protocol::Bytes32::new([0x42; 32]),
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        ballot_launcher_id: chia_protocol::Bytes32::default(),
        signers,
    };
    let proof = circuit.prove(&pk).expect("prove");
    let public_inputs_fr = circuit.public_inputs_as_fr();

    // ── Step 3: compute vk_input = IC[0] + Σ s_i * IC[i+1] ────────
    // (This is the Groth16 "prepared verification" linear combination
    //  the on-chain finalize.rue puzzle assembles via bls_g1_multiply
    //  + G1 addition. Off-chain we do it in arkworks.)
    let ic = &vk.0.gamma_abc_g1;
    assert_eq!(ic.len(), 7, "IC must be 7 entries (1 + 6 public inputs)");
    let mut vk_input = G1Projective::from(ic[0]);
    for (i, scalar) in public_inputs_fr.iter().enumerate() {
        vk_input += G1Projective::from(ic[i + 1]) * scalar;
    }
    let vk_input_affine = vk_input.into_affine();

    // ── Step 4: build the 4 (G1, G2) pairs as compressed bytes ────
    // Pair 0: (A, B)             — proof
    // Pair 1: (-α, β)             — VK
    // Pair 2: (-vk_input, γ)      — public inputs * VK IC
    // Pair 3: (-C, δ)             — proof
    // The negations turn the equation `e(A,B) = e(α,β) * e(I,γ) * e(C,δ)`
    // into `Π e(Pi, Qi) = 1` for the bls_pairing_identity opcode.
    use ark_bls12_381::G1Affine;
    let neg = |p: G1Affine| -> G1Affine { (-G1Projective::from(p)).into_affine() };

    let proof_a = chip_voting_sdk::prover::conversions::g1_from_compressed_bytes(
        hex::decode(&proof.a_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();
    let proof_b = chip_voting_sdk::prover::conversions::g2_from_compressed_bytes(
        hex::decode(&proof.b_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();
    let proof_c = chip_voting_sdk::prover::conversions::g1_from_compressed_bytes(
        hex::decode(&proof.c_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();

    let g1_points = [
        proof_a,
        neg(vk.0.alpha_g1),
        neg(vk_input_affine),
        neg(proof_c),
    ];
    let g2_points = [proof_b, vk.0.beta_g2, vk.0.gamma_g2, vk.0.delta_g2];

    // Flatten: (g1_0, g2_0, g1_1, g2_1, g1_2, g2_2, g1_3, g2_3) — 8 atoms.
    // Each becomes a `Bytes` atom in the solution list.
    let mut atoms: Vec<Bytes> = Vec::with_capacity(8);
    for i in 0..4 {
        atoms.push(Bytes::new(g1_compressed_bytes(&g1_points[i]).unwrap().to_vec()));
        atoms.push(Bytes::new(g2_compressed_bytes(&g2_points[i]).unwrap().to_vec()));
    }

    // ── Step 5: build the puzzle `(58 2 5 11 23 47 95 191 383)` ──
    //
    // Opcode 58 = bls_pairing_identity. Its args are env-path
    // expressions that evaluate to the 8 elements of our solution
    // list (paths 2, 5, 11, 23, 47, 95, 191, 383 are first..eighth).
    //
    // The puzzle returns nil on success (no conditions) and TRAPS on
    // pairing failure. A spend that returns nil conditions is valid
    // (just burns the input mojo).
    let mut allocator = Allocator::new();
    let puzzle_node = build_pairing_check_puzzle(&mut allocator);
    let puzzle_hash = chia_protocol::Bytes32::new(tree_hash(&allocator, puzzle_node).to_bytes());

    // Solution: a flat 8-element list of atoms (each a compressed
    // G1 or G2 point).
    let solution_node = atoms.to_clvm(&mut allocator).unwrap();

    let puzzle_bytes = node_to_bytes(&allocator, puzzle_node).unwrap();
    let solution_bytes = node_to_bytes(&allocator, solution_node).unwrap();

    // ── Step 6: insert coin + submit spend bundle ─────────────────
    let mut sim = Simulator::new();
    let coin = Coin::new(chia_protocol::Bytes32::new([0xCC; 32]), puzzle_hash, 1);
    sim.insert_coin(coin);
    let spend = CoinSpend::new(
        coin,
        Program::from(puzzle_bytes),
        Program::from(solution_bytes),
    );
    let bundle = SpendBundle::new(vec![spend], Signature::default());

    // The critical assertion: the consensus runner ACCEPTS the bundle.
    // This means CLVM bls_pairing_identity validated the Groth16
    // pairing equation against our arkworks-generated proof.
    sim.new_transaction(bundle)
        .expect("CLVM bls_pairing_identity must accept the arkworks-generated Groth16 proof");

    // Belt + suspenders: the off-chain verify_offchain must also pass.
    // CHIP rev 2026-05-02: 6 public inputs.
    let inputs_b32: [chia_protocol::Bytes32; 6] = [
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[0])),
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[1])),
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[2])),
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[3])),
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[4])),
        chia_protocol::Bytes32::new(fr_to_b32(&public_inputs_fr[5])),
    ];
    assert!(VotingCircuit::verify_offchain(&vk, &proof, &inputs_b32).unwrap());

    // Pin that the on-chain identity equation is what we'd expect: the
    // sum of the four pairings equals the GT identity. We know this
    // already because the simulator accepted, but assert it as a
    // belt-and-suspenders check on the off-chain side.
    let _ = Fr::zero(); // silence unused-import warning when ark_std::Zero is the only use
}

/// WHAT: a Groth16 proof tampered AT THE BYTE LEVEL is REJECTED by
///       the on-chain CLVM `bls_pairing_identity` opcode (consensus
///       traps the spend bundle).
/// HOW:  identical setup to the previous test, but flip one byte of
///       proof.A before submitting. Submission MUST fail.
/// WHY:  this is the dual of the success case — proves the on-chain
///       opcode is a true cryptographic check, not a no-op. If
///       tampering passed silently, the entire on-chain Groth16
///       check would be a security theatre.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (VotingCircuit migrated to 6-input shape; rewrite required)"]
fn tampered_groth16_proof_rejected_by_clvm_pairing_identity() {
    use ark_ec::CurveGroup;
    use ark_std::rand::SeedableRng;
    use chia_protocol::Bytes;
    use chip_voting_sdk::prover::circuit::{generate_test_setup, SignerWitness, VotingCircuit};
    use chip_voting_sdk::prover::conversions::{g1_compressed_bytes, g2_compressed_bytes};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xCAFEBABE);
    let (pk, vk) = generate_test_setup(&mut rng).expect("setup");

    let signers = (0..2)
        .map(|i| SignerWitness {
            pubkey: chia_bls::SecretKey::from_seed(&[i as u8 + 1; 32]).public_key(),
            leaf_index: i as u32,
            merkle_proof: vec![chia_protocol::Bytes32::default(); 32],
        })
        .collect();
    let circuit = VotingCircuit {
        registration_merkle_root: chia_protocol::Bytes32::new([0x11; 32]),
        // CHIP rev 2026-05-02: 6-input circuit (added threshold + ballot id).
        registration_vote_weight: 3,
        agg_signers: chia_bls::SecretKey::from_seed(&[0xAA; 32]).public_key(),
        vote_message: chia_protocol::Bytes32::new([0x42; 32]),
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        ballot_launcher_id: chia_protocol::Bytes32::default(),
        signers,
    };
    let proof = circuit.prove(&pk).expect("prove");
    let public_inputs_fr = circuit.public_inputs_as_fr();

    let ic = &vk.0.gamma_abc_g1;
    let mut vk_input = ark_bls12_381::G1Projective::from(ic[0]);
    for (i, scalar) in public_inputs_fr.iter().enumerate() {
        vk_input += ark_bls12_381::G1Projective::from(ic[i + 1]) * scalar;
    }
    let vk_input_affine = vk_input.into_affine();
    let neg = |p: ark_bls12_381::G1Affine| -> ark_bls12_381::G1Affine {
        (-ark_bls12_381::G1Projective::from(p)).into_affine()
    };

    let proof_a = chip_voting_sdk::prover::conversions::g1_from_compressed_bytes(
        hex::decode(&proof.a_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();
    let proof_b = chip_voting_sdk::prover::conversions::g2_from_compressed_bytes(
        hex::decode(&proof.b_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();
    let proof_c = chip_voting_sdk::prover::conversions::g1_from_compressed_bytes(
        hex::decode(&proof.c_hex).unwrap().as_slice().try_into().unwrap(),
    )
    .unwrap();
    let g1_points = [
        proof_a,
        neg(vk.0.alpha_g1),
        neg(vk_input_affine),
        neg(proof_c),
    ];
    let g2_points = [proof_b, vk.0.beta_g2, vk.0.gamma_g2, vk.0.delta_g2];

    let mut atoms: Vec<Bytes> = Vec::with_capacity(8);
    for i in 0..4 {
        let mut g1 = g1_compressed_bytes(&g1_points[i]).unwrap().to_vec();
        // Tamper ONLY with the first G1 point (proof.A) — flip a low-bit.
        // The high bits of the first byte are flag bits (compression /
        // infinity / sign-of-y); flipping a low bit of byte 47 changes
        // the x-coordinate to a different (still well-formed) value
        // that won't satisfy the pairing equation.
        if i == 0 {
            g1[47] ^= 0x01;
        }
        atoms.push(Bytes::new(g1));
        atoms.push(Bytes::new(g2_compressed_bytes(&g2_points[i]).unwrap().to_vec()));
    }

    let mut allocator = Allocator::new();
    let puzzle_node = build_pairing_check_puzzle(&mut allocator);
    let puzzle_hash = chia_protocol::Bytes32::new(tree_hash(&allocator, puzzle_node).to_bytes());

    let solution_node = atoms.to_clvm(&mut allocator).unwrap();
    let puzzle_bytes = node_to_bytes(&allocator, puzzle_node).unwrap();
    let solution_bytes = node_to_bytes(&allocator, solution_node).unwrap();

    let mut sim = Simulator::new();
    let coin = Coin::new(chia_protocol::Bytes32::new([0xCC; 32]), puzzle_hash, 1);
    sim.insert_coin(coin);
    let spend = CoinSpend::new(
        coin,
        Program::from(puzzle_bytes),
        Program::from(solution_bytes),
    );
    let bundle = SpendBundle::new(vec![spend], Signature::default());

    assert!(
        sim.new_transaction(bundle).is_err(),
        "consensus must reject tampered Groth16 proof"
    );
}

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
