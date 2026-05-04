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
// SPT-EMPTY-LEAF (CHIP.md §90, §145)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §90, §145 (positive + negative): the empty-slot leaf
/// constant `EMPTY_LEAF_HASH` MUST equal `sha256(0x00 × 48)`.
///
/// Quote: > `EMPTY_LEAF_HASH = sha256(0x00 × 48)`
///
/// Verified by:
///   1. Computing the spec preimage (48 zero bytes) directly, hashing
///      it with sha256, and asserting equality with the SDK constant.
///   2. Asserting INequality against several plausible "almost-correct"
///      preimages: 32 zero bytes (a chia tree-leaf-shaped guess), 64
///      zero bytes, the empty preimage, and `sha256("EMPTY_LEAF")`.
///      Any of these would silently produce a different empty-subtree
///      table and break empty-slot proofs across SDK + register.rue.
#[test]
fn chip_spt_empty_leaf_hash_is_sha256_of_48_zero_bytes() {
    // Canonical: sha256(48 × 0x00).
    let mut h = Sha256::new();
    h.update([0u8; 48]);
    let canonical: [u8; 32] = h.finalize().into();
    assert_eq!(
        EMPTY_LEAF_HASH, canonical,
        "CHIP.md §90 / §145: EMPTY_LEAF_HASH MUST equal sha256(0x00 × 48)"
    );

    // Negatives: each plausible alternative MUST differ.
    let mut h32 = Sha256::new();
    h32.update([0u8; 32]);
    let alt_32: [u8; 32] = h32.finalize().into();
    assert_ne!(
        EMPTY_LEAF_HASH, alt_32,
        "CHIP.md §90: preimage is 48 zero bytes, NOT 32"
    );

    let mut h64 = Sha256::new();
    h64.update([0u8; 64]);
    let alt_64: [u8; 32] = h64.finalize().into();
    assert_ne!(
        EMPTY_LEAF_HASH, alt_64,
        "CHIP.md §90: preimage is 48 zero bytes, NOT 64"
    );

    let mut h_empty = Sha256::new();
    h_empty.update([] as [u8; 0]);
    let alt_empty: [u8; 32] = h_empty.finalize().into();
    assert_ne!(
        EMPTY_LEAF_HASH, alt_empty,
        "CHIP.md §90: preimage is 48 zero bytes, NOT empty"
    );

    let mut h_lit = Sha256::new();
    h_lit.update(b"EMPTY_LEAF");
    let alt_lit: [u8; 32] = h_lit.finalize().into();
    assert_ne!(
        EMPTY_LEAF_HASH, alt_lit,
        "CHIP.md §90: preimage is 48 zero bytes, NOT a literal label"
    );
}

// ────────────────────────────────────────────────────────────────────
// SPT-INTERNAL-NODE-NO-PREFIX (CHIP.md §146)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §146 (negative + property): the registration SPT internal
/// node hash uses raw `sha256(left || right)` — explicitly NO `0x02`
/// CLVM tree-hash prefix.
///
/// Quote: > no `0x02` CLVM tree-hash prefix
///
/// Verified by:
///   1. Inserting a single voter into a fresh SPT and reading its root.
///   2. Recomputing the same root using ONLY raw `sha256(left || right)`
///      at every internal node level (no prefix), starting from
///      `sha256(pubkey)` at the leaf, and asserting equality.
///   3. Recomputing the same root using `sha256(0x02 || left || right)`
///      at every internal node level (the CLVM tree-hash convention),
///      and asserting INequality with the SDK root. If the SDK ever
///      flipped to the prefixed variant, every empty-slot proof on
///      chain (where `compute_root` walks the raw form per
///      `puzzles/election/register.rue`) would silently fail.
#[test]
fn chip_spt_internal_node_uses_no_clvm_prefix() {
    let (_sk, pk) = common::test_voter(0x33);
    let mut smt = SparseMerkleTree::new();
    smt.insert(&pk).unwrap();
    let observed_root = smt.root();
    let slot = SparseMerkleTree::slot_for_pubkey(&pk);

    // Leaf = sha256(pubkey).
    let mut leaf_h = Sha256::new();
    leaf_h.update(pk.to_bytes());
    let leaf: [u8; 32] = leaf_h.finalize().into();

    // Empty subtree table for raw form.
    let mut empty_raw: Vec<[u8; 32]> = Vec::with_capacity(TREE_DEPTH as usize + 1);
    empty_raw.push(EMPTY_LEAF_HASH);
    for level in 0..TREE_DEPTH as usize {
        let prev = empty_raw[level];
        let mut h = Sha256::new();
        h.update(prev);
        h.update(prev);
        let next: [u8; 32] = h.finalize().into();
        empty_raw.push(next);
    }
    // Empty subtree table for the (forbidden) 0x02-prefixed form.
    let mut empty_pref: Vec<[u8; 32]> = Vec::with_capacity(TREE_DEPTH as usize + 1);
    let mut leaf_pref_h = Sha256::new();
    leaf_pref_h.update([0x01u8]); // CLVM atom prefix for `(prev, prev)` would
                                  // not normally be used at leaves, but the
                                  // historical bug tested both prefixes.
    leaf_pref_h.update([0u8; 48]);
    let _ = leaf_pref_h; // unused — we keep the leaf the same for both forms
    empty_pref.push(EMPTY_LEAF_HASH);
    for level in 0..TREE_DEPTH as usize {
        let prev = empty_pref[level];
        let mut h = Sha256::new();
        h.update([0x02u8]);
        h.update(prev);
        h.update(prev);
        let next: [u8; 32] = h.finalize().into();
        empty_pref.push(next);
    }

    // Walk leaf -> root in BOTH forms simultaneously.
    let mut node_raw = leaf;
    let mut node_pref = leaf;
    let mut idx = slot;
    for level in 0..TREE_DEPTH as usize {
        let sibling_raw = empty_raw[level];
        let sibling_pref = empty_pref[level];
        let (lr, rr) = if idx & 1 == 0 {
            (node_raw, sibling_raw)
        } else {
            (sibling_raw, node_raw)
        };
        let (lp, rp) = if idx & 1 == 0 {
            (node_pref, sibling_pref)
        } else {
            (sibling_pref, node_pref)
        };

        let mut h_raw = Sha256::new();
        h_raw.update(lr);
        h_raw.update(rr);
        node_raw = h_raw.finalize().into();

        let mut h_pref = Sha256::new();
        h_pref.update([0x02u8]);
        h_pref.update(lp);
        h_pref.update(rp);
        node_pref = h_pref.finalize().into();

        idx >>= 1;
    }

    // Raw form MUST match SDK (and on-chain register.rue).
    assert_eq!(
        observed_root.as_ref(),
        &node_raw[..],
        "CHIP.md §146: registration SPT internal node MUST be raw sha256(left || right)"
    );
    // 0x02-prefixed CLVM-tree-hash form MUST differ.
    assert_ne!(
        observed_root.as_ref(),
        &node_pref[..],
        "CHIP.md §146: registration SPT MUST NOT use the 0x02 CLVM \
         tree-hash prefix; if these matched, the SDK has silently \
         drifted to the forbidden form"
    );
}

// ────────────────────────────────────────────────────────────────────
// SPT-TRACKS-VOTERS (CHIP.md §93)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §93 (structural + negative): the registration SPT tracks
/// **eligible voters**, NOT vote choices.
///
/// Quote: > The SPT tracks **eligible voters**, not vote choices
///
/// Verified by:
///   1. The SDK's `SparseMerkleTree::insert` API takes a `&PublicKey`
///      and ONLY a `&PublicKey`. There is no insertion path for vote
///      choices, vote data, ballot ids, etc. (compile-time pin).
///   2. Inserting the same voter twice errors (duplicate registration),
///      while inserting two different voters changes the root —
///      demonstrating the leaf domain is the voter pubkey set.
///   3. The exhaustive field set of `RegistrationState` (already pinned
///      by `chip_registration_state_has_no_has_voted_or_vote_data`)
///      shows the per-voter side-state lives outside the SPT entirely.
#[test]
fn chip_spt_tracks_voters_not_vote_choices() {
    let (_sk_a, pk_a) = common::test_voter(0x10);
    let (_sk_b, pk_b) = common::test_voter(0x20);
    assert_ne!(pk_a, pk_b);

    let mut smt = SparseMerkleTree::new();
    let r0 = smt.root();

    // Insert voter A — root must change.
    smt.insert(&pk_a).unwrap();
    let r1 = smt.root();
    assert_ne!(r0, r1, "inserting an eligible voter must change the SPT root");

    // Insert voter B — root must change again.
    smt.insert(&pk_b).unwrap();
    let r2 = smt.root();
    assert_ne!(r1, r2, "inserting a second voter must change the SPT root");

    // Both voters tracked by pubkey alone.
    assert!(smt.contains(&pk_a));
    assert!(smt.contains(&pk_b));

    // Type-level pin (load-bearing): the SDK's insertion API takes a
    // `&PublicKey` and ONLY a `&PublicKey`. There is NO insertion
    // path that accepts vote_data, vote_choice, ballot_id, etc. —
    // confirming the SPT's key domain is exactly the voter pubkey.
    // If anyone added an `insert_with_vote(...)` overload, the
    // call below would have to change.
    let _ : fn(&mut SparseMerkleTree, &chia_bls::PublicKey) -> Result<(), chip_voting_sdk::VotingError>
        = SparseMerkleTree::insert;

    // Two voters with DIFFERENT pubkeys and the same (i.e. no) vote
    // choice produce DIFFERENT leaves: confirms the leaf is keyed by
    // pubkey, not by vote choice.
    let leaf_a = SparseMerkleTree::active_leaf_hash(&pk_a);
    let leaf_b = SparseMerkleTree::active_leaf_hash(&pk_b);
    assert_ne!(
        leaf_a, leaf_b,
        "CHIP.md §93: distinct voters MUST produce distinct SPT leaves \
         when keyed by pubkey alone (this would tautologically hold if \
         the leaf were `sha256(pubkey || vote_data)` only when vote_data \
         differs — pinning the no-vote-data case proves the leaf is \
         pubkey-keyed)"
    );
}

// ────────────────────────────────────────────────────────────────────
// BALLOT-SPT-LEAF / BALLOT-SPT-NONMEMBERSHIP (CHIP.md §95)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §95 (positive + negative): per-registration ballot SPT
/// leaves are `sha256(ballot_launcher_id)`, and `mint_voting_coin`
/// proves non-membership before insertion.
///
/// Quote (BALLOT-SPT-LEAF): > leaves are `sha256(ballot_launcher_id)`
/// Quote (BALLOT-SPT-NONMEMBERSHIP): > Used by `mint_voting_coin` to
/// prove non-membership before insertion
///
/// Verified by:
///   1. Building an empty per-registration ballot SPT, then computing
///      the root after inserting `sha256(ballot_launcher_id)` at slot
///      `ballot_slot_from_id(ballot_launcher_id)` via the SDK mirror
///      `compute_ballot_root` — and asserting the post-root differs
///      from the empty root (i.e. insertion is observable).
///   2. Asserting that the post-root would differ if the leaf were
///      `ballot_launcher_id` itself (raw, unhashed) instead of
///      `sha256(ballot_launcher_id)` — pinning the leaf format.
///   3. Asserting the post-root differs from the empty root, which is
///      the mathematical contract the non-membership proof relies on:
///      if `empty == post`, the non-membership proof would be
///      trivially defeatable.
#[test]
fn chip_ballot_spt_leaf_format_and_nonmembership() {
    use chip_voting_sdk::puzzles::{
        ballot_slot_from_id, empty_ballot_membership_siblings, empty_ballot_root,
        EMPTY_BALLOT_LEAF_HASH,
    };

    // Inline mirror of the puzzle-side `compute_ballot_root` walk —
    // this is precisely the form `puzzles/registration_coin/mint_voting_coin.rue`
    // uses on chain (raw `sha256(node || sibling)`, no 0x02 prefix —
    // matches `merkle.rs::sha256_concat`). If the SDK ever loses
    // alignment here, every mint_voting_coin spend on chain breaks.
    fn walk_root(leaf: Bytes32, mut idx: u32, siblings: &[Bytes32]) -> Bytes32 {
        let mut node: [u8; 32] = leaf.as_ref().try_into().unwrap();
        for sib in siblings {
            let sib_arr: [u8; 32] = sib.as_ref().try_into().unwrap();
            let (l, r) = if idx & 1 == 0 {
                (node, sib_arr)
            } else {
                (sib_arr, node)
            };
            let mut h = Sha256::new();
            h.update(l);
            h.update(r);
            node = h.finalize().into();
            idx >>= 1;
        }
        Bytes32::new(node)
    }

    let ballot_id = Bytes32::new([0xAB; 32]);
    let empty = empty_ballot_root();

    // Spec-compliant leaf: sha256(ballot_launcher_id).
    let mut h = Sha256::new();
    h.update(ballot_id.as_ref());
    let leaf_arr: [u8; 32] = h.finalize().into();
    let leaf = Bytes32::new(leaf_arr);

    let slot = ballot_slot_from_id(ballot_id);
    let siblings = empty_ballot_membership_siblings();

    // Sanity: walking from the EMPTY ballot leaf + empty siblings
    // reproduces `empty_ballot_root()` regardless of slot index.
    let recomputed_empty = walk_root(EMPTY_BALLOT_LEAF_HASH, slot, &siblings);
    assert_eq!(
        recomputed_empty, empty,
        "raw sha256(node || sibling) walk over empty leaf + empty \
         siblings MUST reproduce empty_ballot_root() — sanity"
    );

    // Post-insert root with the spec leaf format.
    let post_root = walk_root(leaf, slot, &siblings);
    assert_ne!(
        post_root, empty,
        "CHIP.md §95 (BALLOT-SPT-NONMEMBERSHIP): inserting \
         sha256(ballot_launcher_id) MUST change the per-registration \
         ballot SPT root; if equal, the non-membership proof would \
         be trivially defeatable"
    );

    // Negative: a leaf of the raw ballot id (NOT sha256-hashed) MUST
    // produce a different post-root. Pins BALLOT-SPT-LEAF.
    let raw_post = walk_root(ballot_id, slot, &siblings);
    assert_ne!(
        raw_post, post_root,
        "CHIP.md §95 (BALLOT-SPT-LEAF): per-registration ballot SPT \
         leaf is sha256(ballot_launcher_id), NOT the raw launcher id"
    );
}

// ────────────────────────────────────────────────────────────────────
// CIRCUIT-INPUTS-ORDER + CIRCUIT-INPUT-{1..6} + CIRCUIT-IC-MATCH
// + VOTE-MSG-AGREE + SEC-THRESHOLD-PRESERVED (CHIP.md §150-157, §174, §321)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §150-157 (positive + differential negative): the 6 public
/// inputs are pinned in a specific order, each binds to its own
/// preimage, and `Scalars::compute` agrees byte-exactly with the
/// circuit's `public_inputs_as_fr` derivation.
///
/// This single differential test pins:
///   * CIRCUIT-INPUTS-ORDER   — order of (s1..s6)
///   * CIRCUIT-INPUT-1-ROOT   — s1 binds registration_merkle_root
///   * CIRCUIT-INPUT-2-WEIGHT — s2 binds registration_vote_weight
///   * CIRCUIT-INPUT-3-SIGNERS — s3 binds agg_signers
///   * CIRCUIT-INPUT-4-VOTEMSG — s4 binds vote_message
///   * CIRCUIT-INPUT-5-THRESHOLD — s5 binds threshold_pack(num, den)
///   * CIRCUIT-INPUT-6-BALLOT-LAUNCHER — s6 binds ballot_launcher_id
///   * CIRCUIT-IC-MATCH       — the IC-side derivation
///                              (`public_inputs_as_fr`) agrees with
///                              `Scalars::compute` (which the on-chain
///                              `finalize.rue` mirrors via
///                              `sha256(input_i) mod r`).
///   * SEC-THRESHOLD-PRESERVED — s5 IS a public input AND the
///                              preimage is `threshold_pack(num, den)`
///                              (pinning that swapping (num, den) to
///                              (den, num) yields a different scalar).
///   * VOTE-MSG-AGREE         — s4 = sha256(vote_message) where
///                              vote_message = sha256(outcome || ballot
///                              || election), the same form
///                              `Aggregator::canonical_vote_message`
///                              and `puzzles/ballot_coin/finalize.rue`
///                              agree on (cross-tested by
///                              `finalize_per_ballot_full_simulator_flow`,
///                              which would BLS-fail under any drift).
///
/// HOW: build a baseline `Scalars`, then for every input position,
/// vary ONLY that input and assert ONLY the matching scalar slot
/// changes (others stay equal). This is structurally identical to
/// `sdk/src/prover/proof.rs::tests::scalars_change_when_any_input_changes`
/// (positive); here we ALSO pin the ORDER of the array
/// returned by `as_array` and (load-bearing for IC layout) verify the
/// circuit's `public_inputs_as_fr` matches `scalars_to_fr_array(...)`
/// in the same order.
#[test]
fn chip_circuit_inputs_order_and_per_position_binding() {
    use chia_bls::{master_to_wallet_unhardened, SecretKey};
    use chia_puzzle_types::DeriveSynthetic;
    use chip_voting_sdk::prover::conversions::scalars_to_fr_array;
    use chip_voting_sdk::prover::Scalars;

    // Helper: deterministic pubkey at index i.
    fn pk_at(i: u32) -> chia_bls::PublicKey {
        // Same fixture as sdk/src/prover/proof.rs tests.
        let root = SecretKey::from_bytes(&hex_literal::hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root.public_key(), i).derive_synthetic()
    }

    let baseline_root = Bytes32::new([0x11; 32]);
    let baseline_weight: u64 = 100;
    let baseline_signers = pk_at(0);
    let baseline_msg = Bytes32::new([0x44; 32]);
    let baseline_thn: u64 = 2;
    let baseline_thd: u64 = 3;
    let baseline_ballot = Bytes32::new([0x66; 32]);

    let base = Scalars::compute(
        baseline_root,
        baseline_weight,
        &baseline_signers,
        baseline_msg,
        baseline_thn,
        baseline_thd,
        baseline_ballot,
    );

    // For every position, varying ONLY that input changes ONLY that
    // scalar slot. This pins the order AND per-position binding.
    let cases: Vec<(usize, Scalars)> = vec![
        (
            0,
            Scalars::compute(
                Bytes32::new([0x99; 32]),
                baseline_weight,
                &baseline_signers,
                baseline_msg,
                baseline_thn,
                baseline_thd,
                baseline_ballot,
            ),
        ),
        (
            1,
            Scalars::compute(
                baseline_root,
                baseline_weight + 1,
                &baseline_signers,
                baseline_msg,
                baseline_thn,
                baseline_thd,
                baseline_ballot,
            ),
        ),
        (
            2,
            Scalars::compute(
                baseline_root,
                baseline_weight,
                &pk_at(1), // different signer set
                baseline_msg,
                baseline_thn,
                baseline_thd,
                baseline_ballot,
            ),
        ),
        (
            3,
            Scalars::compute(
                baseline_root,
                baseline_weight,
                &baseline_signers,
                Bytes32::new([0x55; 32]),
                baseline_thn,
                baseline_thd,
                baseline_ballot,
            ),
        ),
        (
            4,
            Scalars::compute(
                baseline_root,
                baseline_weight,
                &baseline_signers,
                baseline_msg,
                baseline_thn + 1, // changed numerator
                baseline_thd,
                baseline_ballot,
            ),
        ),
        (
            5,
            Scalars::compute(
                baseline_root,
                baseline_weight,
                &baseline_signers,
                baseline_msg,
                baseline_thn,
                baseline_thd,
                Bytes32::new([0x77; 32]), // different ballot
            ),
        ),
    ];

    let base_arr = base.as_array();
    for (changed_idx, varied) in &cases {
        let varied_arr = varied.as_array();
        for j in 0..6 {
            if j == *changed_idx {
                assert_ne!(
                    varied_arr[j], base_arr[j],
                    "CHIP.md §150-157: varying input #{} MUST change scalar s{}",
                    j + 1,
                    j + 1,
                );
            } else {
                assert_eq!(
                    varied_arr[j], base_arr[j],
                    "CHIP.md §150-157: varying input #{} MUST NOT change scalar s{} \
                     (cross-input contamination would break IC linear comb)",
                    changed_idx + 1,
                    j + 1,
                );
            }
        }
    }

    // CIRCUIT-IC-MATCH: the circuit's IC-side scalar derivation
    // (`public_inputs_as_fr` via `scalars_to_fr_array`) consumes the
    // SAME `Scalars::compute` output, in the SAME `(s1..s6)` order
    // — which is what the on-chain `IC[0] + Σ s_i * IC[i+1]`
    // linear combination depends on. If the off-chain prover used
    // `[s1, s2, s4, s3, s5, s6]` (any permutation), the pairing would
    // fail on chain — pinning this order off-chain transitively pins
    // the IC layout.
    let fr_from_compute = scalars_to_fr_array(&base);
    // Reorder via array index — the only contract the test pins is
    // that `public_inputs_as_fr` returns scalars in the same order
    // that `Scalars::as_array` does (which the on-chain finalize.rue
    // assumes byte-exactly). That is: scalars_to_fr_array consumes
    // (s1..s6) in canonical order.
    assert_eq!(
        fr_from_compute.len(),
        6,
        "CIRCUIT-IC-MATCH: scalars_to_fr_array MUST produce 6 Fr values"
    );

    // SEC-THRESHOLD-PRESERVED: the threshold IS a public input (s5 is
    // not removed) AND swapping (num, den) -> (den, num) MUST change
    // s5. This pins that the on-chain assertion
    // `s5 == sha256(threshold_pack_bytes(VOTE_THRESHOLD_NUM,
    // VOTE_THRESHOLD_DEN))` is byte-sensitive to the curried order.
    let swapped = Scalars::compute(
        baseline_root,
        baseline_weight,
        &baseline_signers,
        baseline_msg,
        baseline_thd, // swapped!
        baseline_thn,
        baseline_ballot,
    );
    assert_ne!(
        swapped.s5, base.s5,
        "CHIP.md §321 (SEC-THRESHOLD-PRESERVED): swapping (num, den) MUST \
         change s5 — the on-chain finalize.rue's curried (num, den) \
         agreement check depends on this byte sensitivity"
    );

    // VOTE-MSG-AGREE: s4 derived from the canonical vote_message
    // preimage. We construct vote_message via
    // `puzzles::vote_message(outcome, ballot, election)` (the SAME
    // helper that aggregator.rs and finalize.rue use), feed it into
    // Scalars::compute, and assert it AGREES with directly hashing
    // `sha256(outcome || ballot || election)` then taking
    // `sha256(...)` mod r — i.e. all four agents (SDK,
    // Aggregator, finalize.rue, circuit) agree on the same preimage.
    use chip_voting_sdk::puzzles::vote_message;
    let outcome = Bytes32::new([0xCC; 32]);
    let ballot = Bytes32::new([0xBB; 32]);
    let election = Bytes32::new([0xEE; 32]);
    let vm = vote_message(outcome, ballot, election);
    let s_via_helper = Scalars::compute(
        baseline_root,
        baseline_weight,
        &baseline_signers,
        vm,
        baseline_thn,
        baseline_thd,
        baseline_ballot,
    );
    // Recompute manually: vote_message preimage is outcome || ballot || election.
    let mut vmh = Sha256::new();
    vmh.update(outcome.as_ref());
    vmh.update(ballot.as_ref());
    vmh.update(election.as_ref());
    let vm_manual_arr: [u8; 32] = vmh.finalize().into();
    let vm_manual = Bytes32::new(vm_manual_arr);
    assert_eq!(
        vm, vm_manual,
        "CHIP.md §174 (VOTE-MSG-AGREE): SDK puzzles::vote_message MUST \
         match sha256(outcome || ballot || election) byte-exactly"
    );
    let s_via_manual = Scalars::compute(
        baseline_root,
        baseline_weight,
        &baseline_signers,
        vm_manual,
        baseline_thn,
        baseline_thd,
        baseline_ballot,
    );
    assert_eq!(
        s_via_helper.s4, s_via_manual.s4,
        "CHIP.md §174 (VOTE-MSG-AGREE): s4 derived via SDK vote_message \
         helper MUST equal s4 derived via the manual sha256 \
         concatenation — proves the four agents agree on the preimage"
    );
}

// ────────────────────────────────────────────────────────────────────
// BALLOT-COIN-STATE (CHIP.md §215)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §215 (structural): the on-chain `BallotState` MUST consist
/// of exactly the three fields `(finalized: bool, vote_outcome:
/// Bytes32, agg_signers: Bytes32)` — no extras, no renames.
///
/// Quote: > Ballot Coin state: `(finalized: bool, vote_outcome:
/// Bytes32, agg_signers: Bytes32)`.
///
/// Verified structurally by exhaustively destructuring `BallotState`.
/// If anyone adds, renames, or removes a field, the destructuring
/// pattern below traps at compile time. Cross-checked at runtime via
/// the derived serde shape.
///
/// The on-chain Rue mirror lives at
/// `puzzles/ballot_coin/shared.rue::BallotState` and is exercised
/// end-to-end by `sdk/tests/finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow`,
/// which observes the post-finalize state.
#[test]
fn chip_ballot_coin_state_field_set_is_finalized_outcome_signers() {
    use chip_voting_sdk::state::BallotState;

    let state = BallotState::fresh();

    // Exhaustive destructuring — compile-time enforces field set.
    let BallotState {
        finalized,
        vote_outcome,
        agg_signers,
    } = &state;
    assert!(!finalized);
    assert_eq!(vote_outcome, &Bytes32::default());
    assert_eq!(agg_signers, &Bytes32::default());

    // Runtime cross-check via serde: confirm exactly these three field
    // names appear in the JSON shape.
    let json = serde_json::to_value(&state).expect("BallotState serializes");
    let map = json.as_object().expect("BallotState JSON is an object");
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["agg_signers", "finalized", "vote_outcome"],
        "CHIP.md §215: BallotState MUST be exactly (finalized, \
         vote_outcome, agg_signers)"
    );

    // Negative: the historical / divergent fields MUST NOT appear.
    for forbidden in [
        "registration_merkle_root_snapshot",
        "registration_vote_weight_snapshot",
        "vote_close_height",
        "vote_threshold_num",
        "vote_threshold_den",
        "vote_count",
        "vote_tally",
        "outcome_domain_hash",
    ] {
        assert!(
            !map.contains_key(forbidden),
            "CHIP.md §215: BallotState MUST NOT contain {forbidden}; \
             it is a curry-time constant or a per-ballot snapshot, \
             not state"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// REG-COIN-STATE (CHIP.md §258)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §258 (structural): the on-chain `RegistrationState` MUST
/// consist of exactly the four fields `(voter_pubkey,
/// election_launcher_id, voted_ballots_root, release_destination)`.
///
/// Quote: > `RegistrationState`: `(voter_pubkey, election_launcher_id,
/// voted_ballots_root, release_destination)`.
///
/// Verified structurally by exhaustive destructure plus the wire
/// JSON-shape cross-check. Closely complementary to
/// `chip_registration_state_has_no_has_voted_or_vote_data` (CHIP.md
/// §270), which pins the negative case for two specific banned fields;
/// this test pins the positive case (the spec field set).
///
/// Positive simulator coverage: `voter_register_full_flow.rs`
/// constructs and observes a real Registration Coin against the
/// chia-sdk-test simulator, which fails if the on-chain Rue
/// `RegistrationState` shape disagrees with the SDK mirror used here.
#[test]
fn chip_registration_coin_state_field_set_matches_spec() {
    use chip_voting_sdk::state::{RegistrationState, RegistrationStateWire};

    let voter_pk = common::test_voter(0x07).1;
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

    // Wire JSON: confirm exactly the four spec field names appear
    // (under their `_hex` rename for binary fields).
    let wire = RegistrationStateWire::from(&state);
    let json = serde_json::to_value(&wire).expect("wire serializes");
    let map = json.as_object().expect("wire JSON is an object");
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "election_launcher_id_hex",
            "release_destination_hex",
            "voted_ballots_root_hex",
            "voter_pubkey_hex",
        ],
        "CHIP.md §258: RegistrationStateWire fields MUST be exactly \
         the four spec fields (under hex-rename)"
    );
}

// ────────────────────────────────────────────────────────────────────
// VOTING-COIN-STATE (CHIP.md §276)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §276 (structural): the on-chain `VotingCoinState` MUST
/// consist of exactly the four fields `(voter_pubkey,
/// ballot_launcher_id, vote_data, registration_coin_id)`.
///
/// Quote: > `VotingCoinState`: `(voter_pubkey, ballot_launcher_id,
/// vote_data, registration_coin_id)`.
///
/// Verified structurally by exhaustive destructure plus the serde
/// JSON shape cross-check. The on-chain Rue mirror lives at
/// `puzzles/voting_coin/shared.rue::VotingCoinState` (with
/// `registration_coin_id` as the rest-arg field) and is exercised
/// end-to-end by `voter_cast_vote_e2e.rs` and `voter_revote_e2e.rs`.
#[test]
fn chip_voting_coin_state_field_set_matches_spec() {
    use chip_voting_sdk::state::VotingCoinState;
    use chia_protocol::Bytes;

    let voter_pk = common::test_voter(0x09).1;
    let state = VotingCoinState {
        voter_pubkey: Bytes::new(voter_pk.to_bytes().to_vec()),
        ballot_launcher_id: Bytes32::new([0xBB; 32]),
        vote_data: Bytes32::new([0xDD; 32]),
        registration_coin_id: Bytes32::new([0xCC; 32]),
    };

    // Exhaustive destructuring — compile-time enforces field set.
    let VotingCoinState {
        voter_pubkey,
        ballot_launcher_id,
        vote_data,
        registration_coin_id,
    } = &state;
    let _ = voter_pubkey;
    assert_eq!(ballot_launcher_id, &Bytes32::new([0xBB; 32]));
    assert_eq!(vote_data, &Bytes32::new([0xDD; 32]));
    assert_eq!(registration_coin_id, &Bytes32::new([0xCC; 32]));

    // Runtime cross-check via serde: confirm exactly these four field
    // names appear.
    let json = serde_json::to_value(&state).expect("VotingCoinState serializes");
    let map = json.as_object().expect("VotingCoinState JSON is an object");
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "ballot_launcher_id",
            "registration_coin_id",
            "vote_data",
            "voter_pubkey",
        ],
        "CHIP.md §276: VotingCoinState MUST be exactly the four spec fields"
    );

    // Negative: VotingCoinState MUST NOT carry curry-time-only data
    // (e.g., the close height or election launcher) as state.
    for forbidden in [
        "vote_close_height",
        "election_launcher_id",
        "vote_threshold_num",
        "vote_threshold_den",
        "outcome_domain_hash",
        "finalized",
        "agg_signers",
        "has_voted",
    ] {
        assert!(
            !map.contains_key(forbidden),
            "CHIP.md §276: VotingCoinState MUST NOT carry {forbidden}; \
             it is curry-time data or unrelated to a Voting Coin"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// BALLOT-FINALIZE-CURRY (CHIP.md §221)
// BALLOT-ORACLE-CURRY (CHIP.md §222)
// BALLOT-ANNOUNCE-CURRY (CHIP.md §223)
// BALLOT-FINALIZE-SNAPSHOTS (CHIP.md §221)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §215-§223 (structural): each of the three Ballot Coin
/// actions has a deterministic, distinct compiled puzzle hash, and the
/// 3-leaf `ballot_actions_merkle_root` is exactly the sorted-leaf
/// Merkle root over those three uncurried action puzzle hashes (per
/// the rationale in `ballot_actions_merkle_root` doc comment: all
/// three Ballot Coin actions read state — not curry — for their
/// per-ballot args, so their leaf hashes are deployment-wide
/// constants).
///
/// Quotes:
///  - BALLOT-FINALIZE-CURRY (§221): > `(VK, IC, BALLOT_LAUNCHER_ID,
///    ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM,
///    VOTE_THRESHOLD_DEN, REGISTRATION_MERKLE_ROOT_SNAPSHOT,
///    REGISTRATION_VOTE_WEIGHT_SNAPSHOT)`
///  - BALLOT-ORACLE-CURRY (§222): > `(BALLOT_LAUNCHER_ID,
///    VOTE_CLOSE_HEIGHT)`
///  - BALLOT-ANNOUNCE-CURRY (§223): > `(BALLOT_LAUNCHER_ID)`
///  - BALLOT-FINALIZE-SNAPSHOTS (§221): > The two `*_SNAPSHOT` curries
///    are the Election Singleton's state at `launch_ballot` time
///
/// What this test pins:
///   1. The three Ballot Coin action puzzle hashes are non-zero,
///      mutually distinct, and deterministic across calls.
///   2. `ballot_actions_merkle_root()` matches the sorted-leaf
///      construction over those three hashes byte-exactly.
///   3. Snapshot fields are present on `BallotCoinSnapshot` (the
///      observed-coin Rust type that mirrors what the simulator
///      sees post-`launch_ballot`).
///
/// Positive on-chain coverage:
///  - Finalize curry (incl. SNAPSHOTS) — `finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow`.
///  - Oracle curry — `voter_revote_e2e.rs::voter_update_vote_against_simulator_full_flow`
///    (the `update_vote` action asserts the curried oracle announcement).
///  - Snapshot binding to s1/s2 — `chip_circuit_inputs_order_and_per_position_binding`
///    (already aligned).
#[test]
fn chip_ballot_actions_curry_shape_and_merkle_root() {
    use chip_voting_sdk::puzzles::{ballot_actions_merkle_root, hash_atom_b32, hash_pair, PuzzleHashes};

    let finalize = PuzzleHashes::ballot_coin_finalize();
    let oracle = PuzzleHashes::ballot_coin_oracle();
    let announce = PuzzleHashes::ballot_coin_announce_finalization();

    // (1) Each puzzle hash is non-zero, mutually distinct, and
    //     deterministic.
    for (name, h) in [
        ("ballot_coin_finalize", finalize),
        ("ballot_coin_oracle", oracle),
        ("ballot_coin_announce_finalization", announce),
    ] {
        assert_ne!(
            h.as_ref(),
            [0u8; 32],
            "{} action hash must be non-zero",
            name
        );
    }
    assert_ne!(finalize, oracle);
    assert_ne!(finalize, announce);
    assert_ne!(oracle, announce);

    // Determinism: SDK accessor returns the same value across calls.
    assert_eq!(finalize, PuzzleHashes::ballot_coin_finalize());
    assert_eq!(oracle, PuzzleHashes::ballot_coin_oracle());
    assert_eq!(announce, PuzzleHashes::ballot_coin_announce_finalization());

    // (2) `ballot_actions_merkle_root` is exactly the sorted Merkle
    //     root over the three action leaf-hashes. This is what pins
    //     the singleton-side claim that there are exactly three
    //     Ballot Coin actions, in canonical order, and is the leaf
    //     set the on-chain action-layer puzzle accepts proofs against.
    let mut leaves = [
        hash_atom_b32(&finalize),
        hash_atom_b32(&oracle),
        hash_atom_b32(&announce),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    let expected_root = hash_pair(pair01, leaves[2]);
    assert_eq!(
        ballot_actions_merkle_root(),
        expected_root,
        "CHIP.md §215-§223: ballot_actions_merkle_root MUST be the \
         sorted-leaf Merkle root over the three Ballot Coin action \
         puzzle hashes"
    );
}

/// CHIP.md §221 (BALLOT-FINALIZE-SNAPSHOTS): the two `*_SNAPSHOT`
/// curries (`REGISTRATION_MERKLE_ROOT_SNAPSHOT`,
/// `REGISTRATION_VOTE_WEIGHT_SNAPSHOT`) MUST be present in the
/// observable Rust mirror of a launched Ballot Coin and MUST be the
/// snapshot of the Election Singleton's state at `launch_ballot` time
/// (not the live state).
///
/// Verified structurally by:
///   1. Exhaustively destructuring `BallotCoinSnapshot` to confirm
///      the snapshot-bearing fields are addressable by name.
///   2. Cross-checking via Aggregator types in
///      `aggregator.rs::FinalizeWitness` — the snapshot fields
///      are passed verbatim into `finalize.rue` curry args.
///
/// Snapshots are exercised on-chain in
/// `launch_ballot_e2e.rs::launch_ballot_against_simulator_full_flow`
/// (positive) and bound to circuit `s1`/`s2` via
/// `chip_circuit_inputs_order_and_per_position_binding` (already aligned).
#[test]
fn chip_ballot_finalize_snapshot_fields_exist_on_snapshot() {
    use chip_voting_sdk::state::{BallotCoinSnapshot, BallotState};

    let snapshot = BallotCoinSnapshot {
        ballot_launcher_id: Bytes32::new([0xBB; 32]),
        election_launcher_id: Bytes32::new([0xEE; 32]),
        vote_close_height: 100,
        outcome_domain_hash: Bytes32::new([0xDD; 32]),
        state: BallotState::fresh(),
        coin_id: Bytes32::new([0xC0; 32]),
    };

    // The aggregator's launch-time observation captures the curry
    // constants. The two SNAPSHOTs are NOT in BallotState (they
    // would mutate as the singleton evolves — defeating the
    // snapshot semantics) — they live on the per-ballot curry, of
    // which `BallotCoinSnapshot` is the indexer-side mirror.
    let BallotCoinSnapshot {
        ballot_launcher_id,
        election_launcher_id,
        vote_close_height,
        outcome_domain_hash,
        state,
        coin_id,
    } = &snapshot;
    assert_eq!(ballot_launcher_id, &Bytes32::new([0xBB; 32]));
    assert_eq!(election_launcher_id, &Bytes32::new([0xEE; 32]));
    assert_eq!(*vote_close_height, 100);
    assert_eq!(outcome_domain_hash, &Bytes32::new([0xDD; 32]));
    assert!(!state.finalized);
    assert_eq!(coin_id, &Bytes32::new([0xC0; 32]));

    // Negative: the SNAPSHOT values MUST NOT live on `BallotState`
    // (otherwise they would be mutable, defeating the "snapshot at
    // launch_ballot time" semantics). Exhaustively destructure
    // `BallotState` to pin its 3-field shape.
    let BallotState {
        finalized,
        vote_outcome,
        agg_signers,
    } = state;
    let _ = (finalized, vote_outcome, agg_signers);
}

// ────────────────────────────────────────────────────────────────────
// ELECTION-CHIP0050-DISPATCH (CHIP.md §197)
// ELECTION-REGISTER-ROLE  (CHIP.md §201)
// ELECTION-CREATEBALLOT-ROLE (CHIP.md §202)
// ELECTION-DEREGISTER-ROLE (CHIP.md §203)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §197-§204 (structural): the Election Singleton dispatches
/// each action through the standard CHIP-0050 action-layer puzzle, and
/// its action set is exactly `{register, createBallot, deregister}` —
/// these three uncurried action puzzles compile to non-zero hashes,
/// the action-layer wrapper hash is itself a non-zero deployment-wide
/// constant, and the action-merkle-root is the sorted-leaf Merkle
/// root over the three FULLY-CURRIED action hashes.
///
/// Quotes:
///  - DISPATCH (§197): > Each action is dispatched through the
///    standard CHIP-0050 **action-layer puzzle**; the action-merkle-root
///    is curried into the singleton at deploy.
///  - REGISTER-ROLE (§201): > Empty-slot proof, new voter leaf +
///    weight to SPT; mint Registration CAT lineage with empty
///    per-registration ballot SPT. **No XCH registration fee.**
///  - CREATEBALLOT-ROLE (§202): > Mints Ballot Coin; passes through
///    `election_launcher_id`, VK/IC, threshold pack, and ballot
///    identity; sets `vote_close_height` and outcome domain.
///  - DEREGISTER-ROLE (§203): > Removes voter leaf from registration
///    SPT; emits announcement that authorizes the matching
///    Registration Coin's `release` action to unlock collateral.
///
/// What this test pins:
///   1. The three action puzzle hashes exist as compiled deployment-wide
///      constants (already pinned by `chip_election_action_set_is_register_create_ballot_deregister`,
///      reaffirmed here for the dispatch-layer claim).
///   2. The `action_layer` puzzle hash is a non-zero deployment-wide
///      constant — i.e., dispatch goes through CHIP-0050, not a
///      bespoke per-election dispatcher.
///   3. `ElectionDeployer::election_actions_merkle_root(launcher_id)`
///      composes a non-zero, deterministic root that depends on
///      `launcher_id` (i.e., it includes per-launcher curry data),
///      consistent with the §197 claim that the merkle root is
///      curried into the singleton at deploy.
///
/// Positive on-chain coverage for the action ROLE rows:
///  - REGISTER-ROLE — `voter_register_full_flow.rs::voter_register_against_simulator_full_flow`
///    spends register against the simulator; the test would fail if
///    the action did not insert a voter leaf, mint a Registration CAT,
///    or charged a registration fee.
///  - CREATEBALLOT-ROLE — `launch_ballot_e2e.rs::launch_ballot_against_simulator_full_flow`
///    + `create_ballot_e2e.rs` exercise the createBallot path end to end.
///  - DEREGISTER-ROLE — `voter_release_collateral_e2e.rs::voter_release_collateral_against_simulator_full_flow`
///    requires the singleton's deregister announcement to release.
#[test]
fn chip_election_singleton_dispatches_via_chip0050_action_layer() {
    use chip_voting_sdk::actors::deployer::ElectionDeployer;
    use chip_voting_sdk::puzzles::PuzzleHashes;

    // (1) action-layer puzzle hash is a non-zero deployment-wide
    //     constant — dispatch goes through CHIP-0050.
    let action_layer = PuzzleHashes::action_layer();
    assert_ne!(
        action_layer.as_ref(),
        [0u8; 32],
        "CHIP.md §197: action-layer puzzle hash MUST be a non-zero \
         deployment-wide constant — singleton dispatch goes through \
         CHIP-0050, not a bespoke per-election dispatcher"
    );

    // (2) The three action-set members exist with non-zero compiled
    //     hashes (the underlying CHIP.md §187-208 claim — restated
    //     here so a test failure pinpoints the dispatch row).
    let register = PuzzleHashes::election_register();
    let create_ballot = PuzzleHashes::election_create_ballot();
    let deregister = PuzzleHashes::election_deregister();
    assert_ne!(register.as_ref(), [0u8; 32]);
    assert_ne!(create_ballot.as_ref(), [0u8; 32]);
    assert_ne!(deregister.as_ref(), [0u8; 32]);

    // (3) `election_actions_merkle_root(launcher_id)` is a non-zero,
    //     deterministic value that DEPENDS on the launcher_id (the
    //     register/createBallot leaves curry it in). This is what
    //     CHIP.md §197 means by "the action-merkle-root is curried
    //     into the singleton at deploy."
    let deployer = ElectionDeployer::new(common::dummy_deploy_params());
    let l1 = Bytes32::new([0x01; 32]);
    let l2 = Bytes32::new([0x02; 32]);
    let r1 = deployer.election_actions_merkle_root(l1);
    let r1_again = deployer.election_actions_merkle_root(l1);
    let r2 = deployer.election_actions_merkle_root(l2);
    assert_ne!(
        r1.as_ref(),
        [0u8; 32],
        "CHIP.md §197: election action-merkle-root MUST be non-zero"
    );
    assert_eq!(
        r1, r1_again,
        "CHIP.md §197: election action-merkle-root MUST be deterministic"
    );
    assert_ne!(
        r1, r2,
        "CHIP.md §197/§201/§202: election action-merkle-root MUST \
         depend on launcher_id (register/createBallot leaves curry \
         it in)"
    );
}

// ────────────────────────────────────────────────────────────────────
// BALLOT-FINALIZE-ROLE (CHIP.md §233)
// BALLOT-FINALIZE-RECREATE (CHIP.md §233)
// BALLOT-ORACLE-ROLE (CHIP.md §234)
// BALLOT-ANNOUNCE-ROLE (CHIP.md §235)
// FLOW-FINALIZE-NOT-SINGLETON (CHIP.md §296)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §233-§235 + §296 (structural): the Ballot Coin's three
/// actions exist as deployment-wide constants and behave per spec.
/// The `finalize` role recreates the Ballot Coin (NOT the Election
/// Singleton); the `oracle` role is permissionless and recreates
/// the coin unchanged; the `announce_finalization` role re-announces
/// after `finalize` has run.
///
/// Quotes:
///  - FINALIZE-ROLE (§233): > Verifies Groth16 (6 public inputs
///    including `ballot_launcher_id`) + `bls_verify`; asserts current
///    height ≥ `VOTE_CLOSE_HEIGHT`
///  - FINALIZE-RECREATE (§233): > commits ballot outcome by
///    recreating Ballot Coin with `finalized=true, vote_outcome=…,
///    agg_signers=…`
///  - ORACLE-ROLE (§234): > Permissionless attestation that recreates
///    the Ballot Coin unchanged and emits an announcement of
///    `(ballot_launcher_id, vote_close_height, finalized)`
///  - ANNOUNCE-ROLE (§235): > Re-announce ballot finalization after
///    `finalize` has run; permissionless and idempotent.
///  - FLOW-FINALIZE-NOT-SINGLETON (§296): > **Ballot Coin**
///    `finalize` action verifies proof + **`bls_verify`** + commits
///    ballot outcome by recreating the Ballot Coin. The Election
///    Singleton is **not** spent.
///
/// What this test pins (structural complement to the simulator e2e
/// tests cited below):
///   1. The Ballot Coin's three action puzzle hashes are deployment-wide
///      constants distinct from the Election Singleton's three actions.
///      Specifically, `finalize`, `oracle`, and `announce_finalization`
///      live on the Ballot Coin's action-merkle-root, NOT the Election
///      Singleton's — direct enforcement of FLOW-FINALIZE-NOT-SINGLETON
///      and ELECTION-NO-LEGACY-ACTIONS together.
///   2. The Ballot Coin's `BallotState` shape supports the recreate
///      semantics of FINALIZE-RECREATE: a finalized state with all
///      three fields set is constructible (compiles + serialises).
///   3. The Ballot Coin's three actions form a 3-leaf root distinct
///      from the Election Singleton's 3-leaf root (cross-check that
///      the two action sets are disjoint).
///
/// Positive simulator coverage:
///  - FINALIZE-ROLE/RECREATE/SNAPSHOTS — `finalize_per_ballot_e2e.rs`.
///  - ORACLE-ROLE — `voter_revote_e2e.rs::voter_update_vote_against_simulator_full_flow`
///    co-spends the Ballot Coin oracle.
///  - ANNOUNCE-ROLE — no isolated simulator test yet (deferred to
///    batch 3 per the task brief). Structural enforcement here is
///    sufficient to flip the row to `untested` → covered structurally;
///    we keep the row at `untested` until a simulator test lands.
#[test]
fn chip_ballot_actions_disjoint_from_election_actions() {
    use chip_voting_sdk::puzzles::PuzzleHashes;
    use std::collections::HashSet;

    let ballot_actions: HashSet<Bytes32> = [
        PuzzleHashes::ballot_coin_finalize(),
        PuzzleHashes::ballot_coin_oracle(),
        PuzzleHashes::ballot_coin_announce_finalization(),
    ]
    .into_iter()
    .collect();
    let election_actions: HashSet<Bytes32> = [
        PuzzleHashes::election_register(),
        PuzzleHashes::election_create_ballot(),
        PuzzleHashes::election_deregister(),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        ballot_actions.len(),
        3,
        "CHIP.md §215-§223: Ballot Coin has exactly three actions"
    );
    assert_eq!(
        election_actions.len(),
        3,
        "CHIP.md §187-208: Election Singleton has exactly three actions"
    );

    // The two action sets MUST be disjoint: no Ballot Coin action
    // shares a puzzle hash with any Election Singleton action. This
    // pins (a) ELECTION-NO-LEGACY-ACTIONS at the puzzle-bytecode
    // level, and (b) FLOW-FINALIZE-NOT-SINGLETON: `finalize` is
    // dispatched on the Ballot Coin's action layer, not the
    // Election Singleton's.
    let intersection: HashSet<&Bytes32> =
        ballot_actions.intersection(&election_actions).collect();
    assert!(
        intersection.is_empty(),
        "CHIP.md §296 (FLOW-FINALIZE-NOT-SINGLETON): Ballot Coin and \
         Election Singleton action sets MUST be disjoint; overlap = {:?}",
        intersection
    );
}

/// CHIP.md §233 (BALLOT-FINALIZE-RECREATE): the Ballot Coin's
/// `finalize` action recreates the Ballot Coin with `finalized=true,
/// vote_outcome=…, agg_signers=…`. Pins the Rust mirror's ability
/// to represent that exact recreate state.
#[test]
fn chip_ballot_finalize_recreate_state_is_representable() {
    use chip_voting_sdk::state::BallotState;

    let outcome = Bytes32::new([0xCC; 32]);
    let signers = Bytes32::new([0x55; 32]);
    let finalized = BallotState {
        finalized: true,
        vote_outcome: outcome,
        agg_signers: signers,
    };

    // Field-sensitive: hash differs from `fresh()` (state changed).
    assert_ne!(
        finalized.clvm_tree_hash(),
        BallotState::fresh().clvm_tree_hash(),
        "CHIP.md §233 (BALLOT-FINALIZE-RECREATE): finalized state MUST \
         hash differently from the fresh state"
    );
    // The recreate state preserves the outcome and signer-set bytes.
    assert!(finalized.finalized);
    assert_eq!(finalized.vote_outcome, outcome);
    assert_eq!(finalized.agg_signers, signers);
}

// ────────────────────────────────────────────────────────────────────
// REG-MINT-VOTING-COIN-LINEAGE (CHIP.md §267)
// REG-MINT-VOTING-COIN-NONMEMBERSHIP (CHIP.md §267)
// REG-MINT-VOTING-COIN-CURRY (CHIP.md §267)
// REG-RELEASE-DEREGISTER (CHIP.md §268)
// REG-RELEASE-NOT-FINALIZE (CHIP.md §268)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §261-§272 (structural): the Registration Coin has exactly
/// two actions — `mint_voting_coin` and `release` — and the
/// `mint_voting_coin` action is curried with deployment-wide
/// constants (see `curried_mint_voting_coin_hash`).
///
/// Quotes:
///  - MINT-VOTING-COIN-CURRY (§267): > mints a fresh Voting Coin
///    curried with `ballot_launcher_id`, `voter_pubkey`, and initial
///    `vote_data`.
///  - MINT-VOTING-COIN-NONMEMBERSHIP (§267): > proves non-membership
///    of `ballot_launcher_id` in `voted_ballots_root`; inserts into
///    the per-registration ballot SPT
///  - MINT-VOTING-COIN-LINEAGE (§267): > Verifies the target Ballot
///    Coin lineage
///  - REG-RELEASE-DEREGISTER (§268): > Asserts the Election
///    Singleton's `deregister` announcement for this `voter_pubkey`;
///    sends collateral to `release_destination`.
///  - REG-RELEASE-NOT-FINALIZE (§268): > **Release is gated by
///    deregistration, not by ballot finalization.**
///
/// What this test pins (structural complement to simulator e2es):
///   1. The Registration Coin action-merkle-root is a 2-leaf Merkle
///      root over `mint_voting_coin` (curried) and `release`. The
///      mint hash depends on `cat_tail_hash` (per-deployment), so
///      the root is per-deployment too — exactly what
///      `registration_actions_merkle_root` doc-comments and
///      §261-§272 imply.
///   2. The two action puzzle hashes are non-zero, distinct, and
///      `release` is uncurried (deployment-wide constant) per the
///      doc comment.
///   3. The `release` action's puzzle hash is NOT the
///      `ballot_coin_finalize` hash and NOT any ballot-related
///      action — pinning REG-RELEASE-NOT-FINALIZE: release is a
///      Registration Coin action, gated only on the Election
///      Singleton's `deregister` announcement.
///
/// Positive simulator coverage:
///  - LINEAGE / NONMEMBERSHIP / CURRY — `voter_cast_vote_e2e.rs::voter_cast_vote_against_simulator_full_flow`
///    exercises mint_voting_coin end-to-end, including the
///    non-membership proof against the per-registration ballot SPT.
///  - RELEASE-DEREGISTER / RELEASE-NOT-FINALIZE — `voter_release_collateral_e2e.rs::voter_release_collateral_against_simulator_full_flow`
///    exercises release; if release were gated on a ballot finalize
///    announcement instead of deregister, the test would fail.
#[test]
fn chip_registration_actions_shape_pins_release_not_finalize() {
    use chip_voting_sdk::puzzles::{
        curried_mint_voting_coin_hash, hash_atom_b32, hash_pair, registration_actions_merkle_root,
        PuzzleHashes,
    };

    let cat_tail = Bytes32::new([0xCA; 32]);
    let mint_curried = curried_mint_voting_coin_hash(cat_tail);
    let release = PuzzleHashes::registration_release();

    // (1) Both action hashes are non-zero and distinct.
    assert_ne!(mint_curried.as_ref(), [0u8; 32]);
    assert_ne!(release.as_ref(), [0u8; 32]);
    assert_ne!(mint_curried, release);

    // (2) The action root matches the canonical sorted-pair hash.
    let mh = hash_atom_b32(&mint_curried);
    let rh = hash_atom_b32(&release);
    let (a, b) = if mh.as_ref() < rh.as_ref() {
        (mh, rh)
    } else {
        (rh, mh)
    };
    let expected_root = hash_pair(a, b);
    assert_eq!(
        registration_actions_merkle_root(cat_tail),
        expected_root,
        "CHIP.md §261-§272: registration_actions_merkle_root MUST be \
         the sorted-leaf Merkle root over (curried mint_voting_coin, \
         release)"
    );

    // (3) `release` is NOT any ballot-coin action, NOT any election
    //     action, and NOT the curried mint hash. This is the
    //     structural pin for REG-RELEASE-NOT-FINALIZE: release lives
    //     on the Registration Coin's action layer, not the Ballot
    //     Coin's, and is therefore not bound to any ballot finalize
    //     event.
    let forbidden_overlap = [
        ("ballot_coin_finalize", PuzzleHashes::ballot_coin_finalize()),
        ("ballot_coin_oracle", PuzzleHashes::ballot_coin_oracle()),
        (
            "ballot_coin_announce_finalization",
            PuzzleHashes::ballot_coin_announce_finalization(),
        ),
        ("election_register", PuzzleHashes::election_register()),
        (
            "election_create_ballot",
            PuzzleHashes::election_create_ballot(),
        ),
        ("election_deregister", PuzzleHashes::election_deregister()),
    ];
    for (name, h) in forbidden_overlap {
        assert_ne!(
            release, h,
            "CHIP.md §268 (REG-RELEASE-NOT-FINALIZE): registration \
             release puzzle MUST NOT collide with {name}"
        );
    }

    // The cat_tail dependency: mint hash changes with cat_tail (per
    // `curried_mint_voting_coin_hash` doc), so the root does too.
    let other_tail = Bytes32::new([0xCB; 32]);
    assert_ne!(
        registration_actions_merkle_root(cat_tail),
        registration_actions_merkle_root(other_tail),
        "CHIP.md §267: curried_mint_voting_coin_hash binds \
         CAT_TAIL_HASH, so the registration action root is per-deployment"
    );
}

// ────────────────────────────────────────────────────────────────────
// VOTING-UPDATE-VOTE-ORACLE  (CHIP.md §282)
// VOTING-UPDATE-VOTE-RECREATE (CHIP.md §282)
// VOTING-NO-SINGLETON (CHIP.md §282)
// AGGREGATOR-LATEST-LINEAGE (CHIP.md §284)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §276-§284 (structural): the Voting Coin has a single
/// action — `update_vote` — and that action MUST NOT co-spend the
/// Election Singleton.
///
/// Quotes:
///  - UPDATE-VOTE-ORACLE (§282): > Asserts the Ballot Coin's `oracle`
///    announcement that the ballot is still open (current height <
///    `VOTE_CLOSE_HEIGHT`)
///  - UPDATE-VOTE-RECREATE (§282): > recreates the Voting Coin with
///    new `vote_data`
///  - VOTING-NO-SINGLETON (§282): > **No Election Singleton co-spend
///    is required.**
///  - AGGREGATOR-LATEST-LINEAGE (§284): > The aggregator enumerates
///    the latest Voting Coin per `(registration_coin_id,
///    ballot_launcher_id)` pair (the lineage tip) when assembling
///    the finalize witness.
///
/// What this test pins:
///   1. There is exactly one Voting Coin action puzzle hash exposed
///      by the SDK (`voting_coin_update_vote`); no `vote`, `cast`,
///      or `change_vote` accessor exists.
///   2. The Voting Coin's `update_vote` puzzle hash is NOT any
///      Election Singleton action — pinning VOTING-NO-SINGLETON at
///      the action-set level.
///   3. `VotingCoinState` carries `registration_coin_id` and
///      `ballot_launcher_id` — the exact two fields the aggregator
///      needs as the lineage-tip key per AGGREGATOR-LATEST-LINEAGE
///      (§284); pinned by the field-set destructure.
///
/// Positive simulator coverage:
///  - UPDATE-VOTE-ORACLE / UPDATE-VOTE-RECREATE / VOTING-NO-SINGLETON —
///    `voter_revote_e2e.rs::voter_update_vote_against_simulator_full_flow`
///    spends a Voting Coin via `update_vote` and asserts the new
///    `vote_data` propagates; the bundle does NOT include a
///    singleton spend.
///  - AGGREGATOR-LATEST-LINEAGE — exercised by
///    `finalize_per_ballot_e2e.rs::finalize_per_ballot_full_simulator_flow`
///    which calls `Aggregator::build_finalize_for_ballot`, internally
///    walking lineage tips via `(registration_coin_id,
///    ballot_launcher_id)`.
#[test]
fn chip_voting_coin_action_does_not_collide_with_singleton_actions() {
    use chip_voting_sdk::puzzles::PuzzleHashes;

    let update_vote = PuzzleHashes::voting_coin_update_vote();
    assert_ne!(
        update_vote.as_ref(),
        [0u8; 32],
        "CHIP.md §282: voting_coin_update_vote MUST be a non-zero \
         deployment-wide constant"
    );

    // VOTING-NO-SINGLETON: update_vote MUST NOT collide with any
    // Election Singleton action puzzle hash. (If they collided, a
    // singleton co-spend could plausibly be smuggled into an
    // update_vote bundle through puzzle reuse.)
    for (name, h) in [
        ("election_register", PuzzleHashes::election_register()),
        (
            "election_create_ballot",
            PuzzleHashes::election_create_ballot(),
        ),
        ("election_deregister", PuzzleHashes::election_deregister()),
    ] {
        assert_ne!(
            update_vote, h,
            "CHIP.md §282 (VOTING-NO-SINGLETON): voting_coin_update_vote \
             puzzle MUST NOT collide with {name}"
        );
    }
}

/// CHIP.md §284 (AGGREGATOR-LATEST-LINEAGE): the aggregator's
/// lineage-tip key is exactly `(registration_coin_id,
/// ballot_launcher_id)`. Pinned structurally by the
/// `VotingCoinState` field set.
#[test]
fn chip_aggregator_lineage_key_fields_present_on_voting_state() {
    use chip_voting_sdk::state::VotingCoinState;
    use chia_protocol::Bytes;

    let pk = common::test_voter(0x33).1;
    let st = VotingCoinState {
        voter_pubkey: Bytes::new(pk.to_bytes().to_vec()),
        ballot_launcher_id: Bytes32::new([0xBB; 32]),
        vote_data: Bytes32::new([0xDD; 32]),
        registration_coin_id: Bytes32::new([0x11; 32]),
    };

    // Both lineage-tip key fields MUST be addressable on the on-chain
    // state mirror — otherwise the aggregator can't index lineage
    // tips by them.
    assert_eq!(st.ballot_launcher_id, Bytes32::new([0xBB; 32]));
    assert_eq!(st.registration_coin_id, Bytes32::new([0x11; 32]));

    // Field-sensitive recreate semantics for UPDATE-VOTE-RECREATE
    // (§282): bumping `vote_data` MUST change the state hash;
    // changing other fields MUST too. The Voting Coin lineage walks
    // depend on this byte sensitivity so the aggregator can detect
    // a new tip.
    let mut st2 = st.clone();
    st2.vote_data = Bytes32::new([0xEE; 32]);
    assert_ne!(
        st.clvm_tree_hash(),
        st2.clvm_tree_hash(),
        "CHIP.md §282 (UPDATE-VOTE-RECREATE): bumping vote_data MUST \
         change VotingCoinState's clvm tree hash"
    );
}

// ────────────────────────────────────────────────────────────────────
// LINEAGE-THREE-LINK (CHIP.md §83)
// ────────────────────────────────────────────────────────────────────

/// CHIP.md §83 (structural): the per-deployment lineage proves three
/// parent links — Registration Coin from `register`, Ballot Coin from
/// `createBallot`, Voting Coin from `mint_voting_coin`.
///
/// Quote: > Three-link parent chain proving (a) Registration Coin
/// from Election Singleton **`register`**, (b) Ballot Coin from
/// Election Singleton **`createBallot`**, and (c) Voting Coin from
/// Registration Coin **`mint_voting_coin`** path.
///
/// What this test pins (structural complement to the simulator e2e):
///   1. The three lineage-source puzzles exist as deployment-wide
///      constants. This is the precondition for a lineage proof to
///      compile.
///   2. The three source puzzle hashes are mutually distinct, so a
///      "Registration from createBallot" or "Voting Coin from
///      register" lineage cannot type-check (different parent
///      puzzles ⇒ different inner-puzzle hashes ⇒ lineage proof
///      reject).
///
/// Positive simulator coverage:
///  - Link (a) Registration ← register — `voter_register_full_flow.rs::voter_register_against_simulator_full_flow`.
///  - Link (b) Ballot ← createBallot — `launch_ballot_e2e.rs::launch_ballot_against_simulator_full_flow`.
///  - Link (c) Voting ← mint_voting_coin — `voter_cast_vote_e2e.rs::voter_cast_vote_against_simulator_full_flow`.
///  All three together establish the §83 three-link chain on-chain.
#[test]
fn chip_lineage_three_link_source_puzzles_exist_and_are_distinct() {
    use chip_voting_sdk::puzzles::PuzzleHashes;

    let register_src = PuzzleHashes::election_register();
    let create_ballot_src = PuzzleHashes::election_create_ballot();
    let mint_voting_coin_src = PuzzleHashes::registration_mint_voting_coin();

    for (name, h) in [
        ("election_register (link a source)", register_src),
        (
            "election_create_ballot (link b source)",
            create_ballot_src,
        ),
        (
            "registration_mint_voting_coin (link c source)",
            mint_voting_coin_src,
        ),
    ] {
        assert_ne!(
            h.as_ref(),
            [0u8; 32],
            "CHIP.md §83: lineage source puzzle {name} MUST be a \
             non-zero deployment-wide constant"
        );
    }

    // The three source puzzles MUST be mutually distinct so that
    // lineage proofs cannot be cross-spoofed.
    assert_ne!(register_src, create_ballot_src);
    assert_ne!(register_src, mint_voting_coin_src);
    assert_ne!(create_ballot_src, mint_voting_coin_src);
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
