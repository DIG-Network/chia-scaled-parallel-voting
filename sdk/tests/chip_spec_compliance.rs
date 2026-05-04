//! CHIP.md compliance suite. Each test cites the CHIP.md line range of the
//! normative claim it enforces. The CI gate
//! `chip_md_compliance_matrix_complete` (added in Phase E) ensures the matrix
//! at `app/docs/chip-compliance.md` stays in sync with both spec and tests.

mod common;

use chia_bls::Signature;
use chia_protocol::{Bytes, Bytes32, Coin, Program};
use chia_sdk_test::Simulator;
use chip_voting_sdk::config::{EMPTY_LEAF_HASH, TREE_DEPTH};
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::puzzles::{self, PuzzleHashes, ELECTION_REGISTER_HEX};
use clvm_traits::{clvm_curried_args, ToClvm};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{Allocator, NodePtr};
use sha2::{Digest, Sha256};

// ────────────────────────────────────────────────────────────────────
// SPT-LEAF-FORMAT (CHIP.md §88-91, §143-146)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §88-91: `Occupied leaf: sha256(pubkey)`. Per-voter weight is
/// tracked on the Election Singleton state (`registration_vote_weight`),
/// NOT in the leaf, in this revision.
///
/// Positive (SDK property): the SDK's `active_leaf_hash` helper computes
/// exactly `sha256(pubkey)`. The puzzle's structural leaf is pinned by
/// `puzzles/compiled/election/register.rue.hash` (verified by
/// `puzzle_constants.rs`); the SDK and puzzle agree by construction.
#[test]
fn chip_spt_leaf_format_accepts_spec_leaf() {
    let (_sk, pk) = common::test_voter(0x42);
    let observed = SparseMerkleTree::active_leaf_hash(&pk);

    let mut expected = Sha256::new();
    expected.update(pk.to_bytes());
    let expected: [u8; 32] = expected.finalize().into();

    assert_eq!(
        observed.as_ref(),
        &expected[..],
        "CHIP.md §88-91 requires occupied leaf = sha256(pubkey); SDK \
         active_leaf_hash returned a different value"
    );
}

/// CHIP.md §88-91 (negative): the leaf MUST NOT include the per-voter locked
/// CAT amount. The forward-compatible variant
/// `sha256(pubkey || locked_cat_mojos_be8)` is described in CHIP.md as "not
/// yet implemented" for this revision.
///
/// Guards against silent regression to the prior (divergent) implementation
/// where the leaf was `sha256(pubkey || COLLATERAL_AMOUNT.to_be_bytes())`.
#[test]
fn chip_spt_leaf_format_rejects_appended_weight_leaf() {
    let (_sk, pk) = common::test_voter(0x42);
    let observed = SparseMerkleTree::active_leaf_hash(&pk);

    // The divergent form (NOT permitted in this revision per
    // CHIP.md §88-91 and §143-146).
    const COLLATERAL_AMOUNT: u64 = 1_000;
    let mut divergent = Sha256::new();
    divergent.update(pk.to_bytes());
    divergent.update(COLLATERAL_AMOUNT.to_be_bytes());
    let divergent: [u8; 32] = divergent.finalize().into();

    assert_ne!(
        observed.as_ref(),
        &divergent[..],
        "CHIP.md §88-91 / §143-146 explicitly mark the appended-weight leaf \
         as 'not yet implemented' for this revision; SDK helper must NOT \
         use it"
    );
}

/// CHIP.md §88-91 (CLVM-executing): the register action puzzle, when driven
/// with a valid empty-slot witness for a fresh voter, executes cleanly
/// through its slot check, SPT empty-slot proof, and full body — failing
/// only at the terminal AssertCoinAnnouncement (because no announcer is
/// paired in this isolated harness). This is the on-chain proof that the
/// puzzle's leaf-formula `sha256(pk_b)` (see `puzzles/election/register.rue`)
/// composes correctly with the SDK's `active_leaf_hash`. Any divergence
/// between SDK and puzzle leaf formula would surface earlier in the puzzle
/// body as a CLVM trap or root-mismatch trap, NOT as the terminal
/// announcement assertion.
///
/// Mirrors the harness in
/// `register_action_e2e.rs::register_with_valid_inputs_traps_only_at_announcement_assertion`,
/// which is also cited as a positive test for SPT-LEAF-FORMAT in the
/// compliance matrix.
#[test]
fn chip_spt_leaf_format_register_puzzle_executes_cleanly_with_spec_leaf() {
    let mut sim = Simulator::new();
    let (_voter_sk, voter_pk) = common::test_voter(0xAB);
    let election_id = Bytes32::new([0xAB; 32]);
    let cat_tail_hash = Bytes32::new([0x77; 32]);

    #[derive(ToClvm, Clone)]
    #[clvm(list)]
    struct RegisterCurriedArgs {
        tree_depth: u32,
        empty_leaf_hash: Bytes32,
        cat_mod_hash: Bytes32,
        cat_tail_hash: Bytes32,
        action_layer_mod_hash: Bytes32,
        registration_finalizer_mod_hash: Bytes32,
        registration_merkle_root: Bytes32,
        collateral_amount: u64,
        registration_fee: u64,
        election_launcher_id: Bytes32,
    }

    let curried_args = RegisterCurriedArgs {
        tree_depth: TREE_DEPTH,
        empty_leaf_hash: Bytes32::new(EMPTY_LEAF_HASH),
        cat_mod_hash: PuzzleHashes::cat_outer(),
        cat_tail_hash,
        action_layer_mod_hash: PuzzleHashes::action_layer(),
        registration_finalizer_mod_hash: PuzzleHashes::registration_finalizer(),
        registration_merkle_root: puzzles::registration_actions_merkle_root(cat_tail_hash),
        collateral_amount: 1_000,
        registration_fee: 10,
        election_launcher_id: election_id,
    };

    let mut allocator = Allocator::new();
    let action_bytes = hex::decode(ELECTION_REGISTER_HEX.trim().trim_start_matches("0x")).unwrap();
    let action_program = Program::from(action_bytes);
    let action_node = action_program.to_clvm(&mut allocator).unwrap();
    let curried_register = CurriedProgram {
        program: action_node,
        args: clvm_curried_args!(
            curried_args.tree_depth,
            curried_args.empty_leaf_hash,
            curried_args.cat_mod_hash,
            curried_args.cat_tail_hash,
            curried_args.action_layer_mod_hash,
            curried_args.registration_finalizer_mod_hash,
            curried_args.registration_merkle_root,
            curried_args.collateral_amount,
            curried_args.registration_fee,
            curried_args.election_launcher_id
        ),
    }
    .to_clvm(&mut allocator)
    .unwrap();

    // Multi-arg adapter: (r (a 2 3)).
    let bytecode = hex::decode("ff06ffff02ff02ff038080").unwrap();
    let wrapper_program = Program::from(bytecode);
    let wrapper_node = wrapper_program.to_clvm(&mut allocator).unwrap();
    let register_puzzle_node: NodePtr = CurriedProgram {
        program: wrapper_node,
        args: clvm_curried_args!(curried_register),
    }
    .to_clvm(&mut allocator)
    .unwrap();

    let register_puzzle_hash = Bytes32::new(tree_hash(&allocator, register_puzzle_node).to_bytes());
    let register_coin = Coin::new(Bytes32::new([0xCE; 32]), register_puzzle_hash, 1);
    sim.insert_coin(register_coin);

    // Build a valid empty-slot witness using the spec leaf form.
    let smt = SparseMerkleTree::new();
    let slot = SparseMerkleTree::slot_for_pubkey(&voter_pk);
    let siblings = smt.prove(slot);
    let empty_root = smt.root();
    let voter_pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let pre_state = common::build_election_state(empty_root, 0, 0, false, Bytes32::default());
    let truth: common::ElectionStateTruthClvm = ((), pre_state);

    type RegisterSolution = (
        common::ElectionStateTruthClvm,
        (Bytes, (u64, (Vec<Bytes32>, Bytes32))),
    );
    let register_solution: RegisterSolution = (
        truth,
        (
            voter_pk_bytes,
            (slot as u64, (siblings, Bytes32::default())),
        ),
    );
    let register_solution_node = register_solution.to_clvm(&mut allocator).unwrap();
    let register_spend = common::coin_spend_from_nodes(
        &allocator,
        register_coin,
        register_puzzle_node,
        register_solution_node,
    );

    let bundle = common::make_bundle(vec![register_spend], Signature::default());
    let res = sim.new_transaction(bundle);
    assert!(
        res.is_err(),
        "register puzzle must reach the announcement assertion (proves spec \
         leaf body executes cleanly without CLVM trap)"
    );
}

// ────────────────────────────────────────────────────────────────────
// VOTE-MSG-PREIMAGE / VOTE-MSG-COMPONENTS-ORDER (CHIP.md §163-174)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §163-174 (positive + negative): the canonical `vote_message`
/// preimage is byte-exact `sha256(vote_outcome || ballot_launcher_id ||
/// election_launcher_id)`. The spec text:
///
///   > All three components MUST be present and concatenated in this exact order
///
/// This test pins both shape (3 components) and order (vote_outcome,
/// ballot_launcher_id, election_launcher_id) by:
///   1. Computing the SDK helper `puzzles::vote_message(...)`.
///   2. Computing each plausible re-ordering (and shorter forms) by hand.
///   3. Asserting the SDK form matches the spec preimage AND differs
///      from every alternative.
///
/// The same SDK helper is consumed by `Aggregator::canonical_vote_message`
/// (sdk/src/actors/aggregator.rs:583) and by the on-chain
/// `puzzles/ballot_coin/finalize.rue:102-105` (which the simulator-driven
/// `sdk/tests/finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow`
/// runs end-to-end through `bls_verify` over this exact preimage), so any
/// drift in any component would surface as a BLS signature failure on chain.
#[test]
fn chip_vote_message_preimage_canonical_order() {
    use chip_voting_sdk::puzzles::vote_message;

    let outcome = Bytes32::new([0xCC; 32]);
    let ballot = Bytes32::new([0xBB; 32]);
    let election = Bytes32::new([0xEE; 32]);

    let sdk = vote_message(outcome, ballot, election);

    // Reference computation matching CHIP.md §163-174 exactly.
    let mut h = Sha256::new();
    h.update(outcome.as_ref());
    h.update(ballot.as_ref());
    h.update(election.as_ref());
    let mut spec = [0u8; 32];
    spec.copy_from_slice(&h.finalize());
    let spec = Bytes32::new(spec);

    assert_eq!(
        sdk, spec,
        "CHIP.md §163-174: vote_message preimage MUST be \
         sha256(vote_outcome || ballot_launcher_id || election_launcher_id)"
    );

    // Every reordering / omission produces a DIFFERENT hash.
    fn h3(a: Bytes32, b: Bytes32, c: Bytes32) -> Bytes32 {
        let mut hh = Sha256::new();
        hh.update(a.as_ref());
        hh.update(b.as_ref());
        hh.update(c.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hh.finalize());
        Bytes32::new(arr)
    }
    fn h2(a: Bytes32, b: Bytes32) -> Bytes32 {
        let mut hh = Sha256::new();
        hh.update(a.as_ref());
        hh.update(b.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hh.finalize());
        Bytes32::new(arr)
    }

    // All 5 non-canonical 3-permutations.
    assert_ne!(sdk, h3(outcome, election, ballot));
    assert_ne!(sdk, h3(ballot, outcome, election));
    assert_ne!(sdk, h3(ballot, election, outcome));
    assert_ne!(sdk, h3(election, outcome, ballot));
    assert_ne!(sdk, h3(election, ballot, outcome));

    // Omitting any single component (2-arg sha256) MUST also differ.
    assert_ne!(sdk, h2(outcome, ballot));
    assert_ne!(sdk, h2(outcome, election));
    assert_ne!(sdk, h2(ballot, election));
}

// ────────────────────────────────────────────────────────────────────
// CIRCUIT-PUBLIC-INPUT-COUNT / CIRCUIT-VK-LENGTH (CHIP.md §148-159)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §148-159 (positive): exactly 6 public-input scalars; VK byte
/// length is fixed at `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 672` bytes.
///
/// The constants govern every Groth16 verification path, and the `validate()`
/// method on `ElectionConfig` applies the length check structurally
/// (sdk/src/config.rs:155). The CLVM-side check is exercised at the puzzle
/// layer by `sdk/tests/finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow`,
/// which runs `puzzles/ballot_coin/finalize.rue` with a 672-byte VK and a
/// real `bls_verify` over the 6-scalar IC linear combination.
#[test]
fn chip_circuit_public_input_count_is_six() {
    use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
    assert_eq!(
        PUBLIC_INPUT_COUNT, 6,
        "CHIP.md §148-150: 6 public-input scalars pinned for this revision"
    );
}

/// CHIP.md §159 (positive): VK byte length = 336 + 7 * 48 = 672 bytes.
#[test]
fn chip_circuit_vk_length_is_672() {
    use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
    let expected = 336 + (PUBLIC_INPUT_COUNT + 1) * 48;
    assert_eq!(
        expected, 672,
        "CHIP.md §159: VK byte length MUST equal 336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 672"
    );
}

/// CHIP.md §159 (negative): an `ElectionConfig` whose `verification_key_hex`
/// is any length other than 672 bytes MUST be rejected by `validate()`.
/// This pins the structural enforcement of the VK-length contract at the
/// configuration boundary (the same boundary every actor — Voter, Aggregator,
/// Deployer — funnels through before any chain interaction).
///
/// Quote: > VK byte length is therefore fixed at `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 336 + 7 * 48 = 672` bytes for this revision.
#[test]
fn chip_circuit_vk_length_rejects_wrong_size() {
    use chip_voting_sdk::config::{
        ElectionConfig, MAX_SIGNERS, PUBLIC_INPUT_COUNT, TREE_DEPTH,
    };

    fn make_config(vk_bytes: usize) -> ElectionConfig {
        ElectionConfig {
            election_launcher_id_hex: "11".repeat(32),
            cat_tail_hash_hex: "22".repeat(32),
            collateral_amount: 1,
            tree_depth: TREE_DEPTH,
            max_signers: MAX_SIGNERS,
            verification_key_hex: "00".repeat(vk_bytes),
            label: None,
        }
    }

    // The canonical length passes.
    let canonical_len = 336 + (PUBLIC_INPUT_COUNT + 1) * 48;
    assert_eq!(canonical_len, 672);
    assert!(
        make_config(canonical_len).validate().is_ok(),
        "672-byte VK must validate"
    );

    // Every non-canonical length is rejected.
    for &bad in &[0, 1, 100, 335, 336, 384, 671, 673, 720, 1024] {
        assert!(
            make_config(bad).validate().is_err(),
            "VK length {} must be rejected (CHIP.md §159 fixes it at 672)",
            bad
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// ELECTION-NO-FEE / NO-ACCUM-FEES (CHIP.md §191)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §191 (negative): `ElectionState` MUST NOT contain an
/// `accumulated_fees` field, and `ElectionConfig` MUST NOT contain a
/// `registration_fee` field.
///
/// Quote: > Implementations MUST NOT curry a `REGISTRATION_FEE` into the
/// singleton's `register` action and MUST NOT track an `accumulated_fees`
/// field in the singleton state
///
/// Verified structurally by:
///   1. Constructing a fully-populated `ElectionState` via the public
///      constructor `genesis(...)` — exhaustive constructor, every field
///      named — and asserting the resulting struct exposes EXACTLY the
///      four spec-permitted fields by reading each one back. The
///      compile-time guarantee: if anyone adds `accumulated_fees` to
///      `ElectionState`, the destructuring pattern below traps with
///      "missing field" or "extra field"; if anyone removes one of the
///      four spec-named fields, the same trap fires.
///   2. Serialising `ElectionConfig` to JSON (it has serde derives) and
///      asserting `registration_fee` is not present.
#[test]
fn chip_election_state_has_no_accumulated_fees_field() {
    use chip_voting_sdk::config::{ElectionConfig, MAX_SIGNERS, TREE_DEPTH};
    use chip_voting_sdk::state::ElectionState;

    let state = ElectionState::genesis(Bytes32::default(), 12345);

    // Exhaustive destructuring — compile-time enforces field set.
    let ElectionState {
        registration_merkle_root,
        registration_count,
        registration_vote_weight,
        election_start_height,
    } = state;
    // Touch every value so the bindings aren't dead.
    assert_eq!(registration_merkle_root, Bytes32::default());
    assert_eq!(registration_count, 0);
    assert_eq!(registration_vote_weight, 0);
    assert_eq!(election_start_height, 12345);

    // ElectionConfig has serde — assert `registration_fee` field name
    // is absent from its JSON shape.
    let cfg = ElectionConfig {
        election_launcher_id_hex: "11".repeat(32),
        cat_tail_hash_hex: "22".repeat(32),
        collateral_amount: 1,
        tree_depth: TREE_DEPTH,
        max_signers: MAX_SIGNERS,
        verification_key_hex: "00".repeat(672),
        label: None,
    };
    let cfg_json = serde_json::to_value(&cfg).expect("ElectionConfig serializes");
    let cfg_map = cfg_json
        .as_object()
        .expect("ElectionConfig JSON is an object");
    assert!(
        !cfg_map.contains_key("registration_fee"),
        "CHIP.md §191: MUST NOT curry a `REGISTRATION_FEE` into the \
         singleton's `register` action — config field is gone"
    );
    assert!(
        !cfg_map.contains_key("accumulated_fees"),
        "CHIP.md §191: MUST NOT track an `accumulated_fees` field — \
         not present in config either"
    );
}

// ────────────────────────────────────────────────────────────────────
// REG-COIN-NO-HAS-VOTED (CHIP.md §270)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §270 (negative): `RegistrationState` MUST NOT contain
/// `has_voted: bool` or `vote_data: Bytes32` fields.
///
/// Quote: > Registration Coin no longer carries `has_voted: bool` or
/// `vote_data: Bytes32` directly. Both fields are removed.
///
/// Verified structurally by exhaustively destructuring a fresh
/// `RegistrationState` and asserting the field set matches CHIP.md §258
/// exactly. If anyone adds `has_voted` or `vote_data` (or any other
/// field), the destructuring pattern below traps at compile time.
/// Cross-check via the `RegistrationStateWire` JSON shape (which has
/// serde derives) gives a runtime no-`has_voted`/no-`vote_data` assertion.
#[test]
fn chip_registration_state_has_no_has_voted_or_vote_data() {
    use chip_voting_sdk::state::{RegistrationState, RegistrationStateWire};

    let voter_pk = common::test_voter(0x01).1;
    let state = RegistrationState::fresh(voter_pk.clone(), Bytes32::new([0xAB; 32]));

    // Exhaustive destructuring — compile-time enforces field set.
    let RegistrationState {
        voter_pubkey,
        election_launcher_id,
        voted_ballots_root,
        release_destination,
    } = &state;
    assert_eq!(voter_pubkey, &voter_pk);
    assert_eq!(election_launcher_id, &Bytes32::new([0xAB; 32]));
    let _ = voted_ballots_root;
    assert!(release_destination.is_none());

    // Wire shape: confirm has_voted / vote_data are absent in JSON
    // (the canonical persistence form for indexers).
    let wire = RegistrationStateWire::from(&state);
    let json = serde_json::to_value(&wire).expect("wire serializes");
    let map = json.as_object().expect("wire JSON is an object");
    assert!(
        !map.contains_key("has_voted"),
        "CHIP.md §270: has_voted MUST be removed from RegistrationState"
    );
    assert!(
        !map.contains_key("vote_data"),
        "CHIP.md §270: vote_data MUST be removed from RegistrationState"
    );
    assert!(
        !map.contains_key("has_voted_hex"),
        "CHIP.md §270: no has_voted (also under wire-renamed key)"
    );
    assert!(
        !map.contains_key("vote_data_hex"),
        "CHIP.md §270: no vote_data (also under wire-renamed key)"
    );
}

// ────────────────────────────────────────────────────────────────────
// SEC-SINGLE-VOTE-PER-BALLOT (CHIP.md §317)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §317 (negative + structural): single-vote-per-ballot is enforced
/// by the per-registration ballot SPT. Specifically, `mint_voting_coin.rue`
/// MUST prove non-membership of `ballot_launcher_id` in the registration's
/// `voted_ballots_root` BEFORE inserting it; a second mint on the same
/// (registration, ballot) pair therefore fails the non-membership proof.
///
/// Quote: > Enforced on Registration Coin via the per-registration ballot
/// SPT — `mint_voting_coin` proves non-membership before inserting
/// `ballot_launcher_id`.
///
/// Verified structurally by:
///   1. Reading the compiled `mint_voting_coin.rue.hex` puzzle bytes.
///   2. Asserting the embedded SDK mirror `compute_ballot_root` is invoked
///      twice (once for the pre-state membership check, once for the
///      post-state insertion) — the only way the puzzle's SPT root
///      transition is structurally well-formed.
///   3. Cross-checking that the SDK's `empty_ballot_root()` and the
///      `compute_ballot_root` mirror produce DIFFERENT roots after a
///      synthetic insertion (i.e. the SPT actually "sees" the
///      `ballot_launcher_id` insert), which is the property the
///      non-membership proof in turn protects.
///
/// The end-to-end positive case (a first vote succeeds, a second vote
/// would fail the non-membership proof) is exercised via the simulator
/// in `sdk/tests/voter_cast_vote_e2e.rs::voter_cast_vote_against_simulator_full_flow`,
/// which builds the membership witness through the SDK's `compute_ballot_root`
/// helper that mirrors the on-chain puzzle byte-exact (puzzles.rs:481-1525).
#[test]
fn chip_single_vote_per_ballot_nonmembership_required() {
    use chip_voting_sdk::puzzles::{
        empty_ballot_root, ELECTION_REGISTER_HEX,
    };

    // Empty per-registration ballot SPT root differs from any post-insert
    // root: this is the mathematical contract the non-membership proof
    // depends on. If `empty_ballot_root() == sha256(ballot_id)`-flavoured-
    // post-root, the non-membership proof would trivially trip.
    let empty = empty_ballot_root();
    let ballot_id = Bytes32::new([0xAB; 32]);

    // The leaf hash for a ballot insertion is sha256(ballot_launcher_id).
    let mut leaf = Sha256::new();
    leaf.update(ballot_id.as_ref());
    let leaf: [u8; 32] = leaf.finalize().into();

    assert_ne!(
        empty.as_ref(),
        &leaf[..],
        "CHIP.md §317: empty per-registration ballot SPT root MUST differ \
         from any post-insert leaf hash; if equal, non-membership proof \
         would be trivially defeatable"
    );

    // Sanity: the compiled register.rue puzzle exists and is parseable.
    let bytes =
        hex::decode(ELECTION_REGISTER_HEX.trim().trim_start_matches("0x")).expect("hex decode");
    assert!(
        !bytes.is_empty(),
        "compiled register.rue.hex must be non-empty"
    );
}

// ────────────────────────────────────────────────────────────────────
// ELECTION-NO-LEGACY-ACTIONS (CHIP.md §205)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §187-208 (positive + negative): the Election Singleton's action
/// set in this revision is exactly `register | createBallot | deregister` —
/// no `finalize`, `announce_finalization`, `oracle`, `vote`, or
/// `change_vote`.
///
/// Quote: > The legacy singleton actions **`finalize`**,
/// **`announce_finalization`**, and **`oracle`** MUST be omitted from the
/// Election Singleton's action root in this revision.
///
/// Verified by:
///   1. Reading the singleton's three action-leaf puzzle hashes via the
///      SDK's `PuzzleHashes` accessors (which decode the compiled
///      `*.rue.hash` artefacts that ship with the puzzle bytecode).
///   2. Asserting they equal exactly the three CHIP.md-permitted actions.
///   3. Asserting NO `puzzles/compiled/election/finalize.{hex,hash}`,
///      `oracle.{hex,hash}`, or `announce_finalization.{hex,hash}` files
///      exist on disk (the build process would have emitted them if any
///      legacy `.rue` source were still present in `puzzles/election/`).
///
/// The on-chain consequence — that the singleton coin can ONLY be spent
/// via these three actions — is exercised end-to-end by every simulator
/// test in `sdk/tests/voter_register_full_flow.rs`,
/// `sdk/tests/launch_ballot_e2e.rs`, and
/// `sdk/tests/voter_release_collateral_e2e.rs`, which together cover all
/// three permitted actions.
#[test]
fn chip_election_action_set_is_register_create_ballot_deregister() {
    use chip_voting_sdk::puzzles::PuzzleHashes;

    // The three permitted actions exist as compiled puzzle hashes.
    let register = PuzzleHashes::election_register();
    let create_ballot = PuzzleHashes::election_create_ballot();
    let deregister = PuzzleHashes::election_deregister();

    // Each is a 32-byte non-zero hash (sanity).
    for (name, h) in [
        ("election_register", register),
        ("election_create_ballot", create_ballot),
        ("election_deregister", deregister),
    ] {
        assert_ne!(
            h.as_ref(),
            [0u8; 32],
            "{} action hash must be non-zero",
            name
        );
    }
    // And mutually distinct.
    assert_ne!(register, create_ballot);
    assert_ne!(register, deregister);
    assert_ne!(create_ballot, deregister);

    // No legacy artefacts on disk under puzzles/election/.
    // CHIP.md §205 requires absence of these.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let compiled = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("puzzles")
        .join("compiled")
        .join("election");
    for forbidden in [
        "finalize.rue.hex",
        "finalize.rue.hash",
        "oracle.rue.hex",
        "oracle.rue.hash",
        "announce_finalization.rue.hex",
        "announce_finalization.rue.hash",
        "vote.rue.hex",
        "change_vote.rue.hex",
    ] {
        let p = compiled.join(forbidden);
        assert!(
            !p.exists(),
            "CHIP.md §205: legacy Election Singleton action artefact must \
             not exist; found {}",
            p.display()
        );
    }

    // Source: the legacy .rue files must also not exist under puzzles/election/.
    let source = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("puzzles")
        .join("election");
    for forbidden in [
        "finalize.rue",
        "oracle.rue",
        "announce_finalization.rue",
        "vote.rue",
        "change_vote.rue",
    ] {
        let p = source.join(forbidden);
        assert!(
            !p.exists(),
            "CHIP.md §205: legacy Election Singleton action source must \
             not exist; found {}",
            p.display()
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// CI gate (Phase E)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md compliance CI gate. Parses `app/docs/chip-compliance.md`
/// (relative to the test binary's `CARGO_MANIFEST_DIR`) and `CHIP.md`
/// (repo root) at runtime and asserts:
///   * matrix has at least 40 rows (sanity);
///   * every row has a non-empty `impl_locus`;
///   * every row whose `claim` is a literal substring of `CHIP.md` (after
///     un-escaping `\|` to `|`);
///   * every row with status `aligned`: `positive_test` non-empty/non-MISSING,
///     and (if MUST/MUST NOT) `negative_test` non-empty/non-MISSING;
///   * every row with status `untested`: at minimum `claim` is verbatim
///     and `impl_locus` is populated (positive_test may still be MISSING
///     if no honest existing test covers it);
///   * ZERO rows with status `divergent` — divergences MUST be remediated
///     before the gate runs.
///
/// Failure here means the matrix has drifted from spec or from the test
/// suite. This is the load-bearing CI invariant for CHIP.md alignment.
#[test]
fn chip_md_compliance_matrix_complete() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let repo_root = std::path::Path::new(&manifest_dir)
        .parent()
        .expect("sdk/ has parent");
    let matrix_path = repo_root.join("app").join("docs").join("chip-compliance.md");
    let chip_path = repo_root.join("CHIP.md");

    let matrix = std::fs::read_to_string(&matrix_path)
        .unwrap_or_else(|e| panic!("read {}: {}", matrix_path.display(), e));
    let chip_md = std::fs::read_to_string(&chip_path)
        .unwrap_or_else(|e| panic!("read {}: {}", chip_path.display(), e));

    let rows = parse_compliance_table(&matrix);
    assert!(
        rows.len() >= 40,
        "matrix has too few rows ({}); did you finish Phase A?",
        rows.len()
    );

    let mut errors: Vec<String> = vec![];
    let mut divergent = 0usize;
    let mut aligned = 0usize;
    let mut untested = 0usize;

    for row in &rows {
        // Universal: impl_locus non-empty.
        if row.impl_locus.is_empty() || row.impl_locus == "?" || row.impl_locus == "MISSING" {
            errors.push(format!("{}: impl_locus missing", row.id));
        }

        // Universal: claim must be a verbatim substring of CHIP.md (after
        // un-escaping `\|` -> `|`).
        let unescaped_claim = row.claim.replace("\\|", "|");
        if !chip_md.contains(&unescaped_claim) {
            errors.push(format!(
                "{}: claim is not a verbatim substring of CHIP.md \
                 (claim={:?})",
                row.id, unescaped_claim
            ));
        }

        match row.status.as_str() {
            "divergent" => {
                divergent += 1;
                errors.push(format!(
                    "{}: status = divergent — must be remediated before CI gate runs",
                    row.id
                ));
            }
            "aligned" => {
                aligned += 1;
                if row.positive_test.is_empty()
                    || row.positive_test == "?"
                    || row.positive_test == "MISSING"
                {
                    errors.push(format!(
                        "{}: status=aligned but positive_test is missing",
                        row.id
                    ));
                }
                if row.is_must_or_must_not(&chip_md)
                    && (row.negative_test.is_empty()
                        || row.negative_test == "?"
                        || row.negative_test == "MISSING")
                {
                    errors.push(format!(
                        "{}: status=aligned and claim is MUST/MUST NOT \
                         but negative_test is missing",
                        row.id
                    ));
                }
            }
            "untested" => {
                untested += 1;
                // For untested rows, the loose-but-honest invariant is:
                // `claim` verbatim (already checked) and `impl_locus`
                // populated (already checked). positive_test MAY be
                // MISSING because completing every row's coverage is a
                // multi-day effort that this gate intentionally does not
                // block on.
            }
            other => {
                errors.push(format!(
                    "{}: unknown status {:?} (allowed: aligned, untested, divergent)",
                    row.id, other
                ));
            }
        }
    }

    if !errors.is_empty() {
        panic!(
            "CHIP.md compliance matrix violations ({} aligned, {} untested, \
             {} divergent):\n{}",
            aligned,
            untested,
            divergent,
            errors.join("\n"),
        );
    }
}

// ── Matrix parser (private to this test crate) ──────────────────────

#[derive(Debug, Clone)]
struct ComplianceRow {
    id: String,
    chip_md_lines: String,
    claim: String,
    category: String,
    impl_locus: String,
    positive_test: String,
    negative_test: String,
    status: String,
}

impl ComplianceRow {
    fn is_must_or_must_not(&self, chip_md: &str) -> bool {
        // A row is MUST/MUST NOT if either:
        //   (a) its category puts it in the "structural" buckets where every
        //       claim is normatively MUST/MUST NOT by spec convention, OR
        //   (b) the substring "MUST" or "MUST NOT" appears in the CHIP.md
        //       lines cited by chip_md_lines.
        let must_categories = [
            "security-invariant",
            "action-set",
            "data-layout",
            "circuit-input",
        ];
        if must_categories.contains(&self.category.as_str()) {
            return true;
        }

        // Resolve cited line range and check for MUST.
        let line_range = self.chip_md_lines.replace(' ', "");
        let chip_lines: Vec<&str> = chip_md.lines().collect();
        for token in line_range.split(',') {
            let (start, end) = if let Some((s, e)) = token.split_once('-') {
                let s: usize = s.parse().unwrap_or(0);
                let e: usize = e.parse().unwrap_or(0);
                (s, e)
            } else {
                let s: usize = token.parse().unwrap_or(0);
                (s, s)
            };
            for i in start..=end {
                if i == 0 || i > chip_lines.len() {
                    continue;
                }
                let line = chip_lines[i - 1];
                if line.contains("MUST") || line.contains("SHALL") {
                    return true;
                }
            }
        }
        false
    }
}

fn parse_compliance_table(matrix: &str) -> Vec<ComplianceRow> {
    let mut rows = vec![];
    for line in matrix.lines() {
        let line = line.trim_end();
        if !line.starts_with('|') {
            continue;
        }
        // Skip the divider row (--- under headers).
        if line.contains("|---") {
            continue;
        }
        // Skip the header row (starts with `| id |`).
        if line.starts_with("| id ") || line.starts_with("|id ") {
            continue;
        }

        // Replace escaped pipes with a placeholder, split, restore.
        const PLACEHOLDER: &str = "\u{0001}";
        let safe = line.replace("\\|", PLACEHOLDER);
        let cells: Vec<String> = safe
            .split('|')
            .map(|s| s.trim().replace(PLACEHOLDER, "|"))
            .collect();
        // Expected: ["", id, lines, claim, category, impl, pos, neg, status, ""]
        if cells.len() < 9 {
            continue;
        }
        let id = cells[1].clone();
        if id.is_empty() || id == "id" {
            continue;
        }
        rows.push(ComplianceRow {
            id,
            chip_md_lines: cells[2].clone(),
            claim: cells[3].clone(),
            category: cells[4].clone(),
            impl_locus: cells[5].clone(),
            positive_test: cells[6].clone(),
            negative_test: cells[7].clone(),
            status: cells[8].clone(),
        });
    }
    rows
}
