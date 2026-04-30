// ============================================================================
// puzzles.rs — compiled puzzle bytecode + tree-hash arithmetic
// ============================================================================
//
// MODULE: puzzles
// PURPOSE: Embed Rue-compiled CLVM bytecode for the voting CHIP puzzles
//          and expose helper functions that compute curried puzzle
//          hashes the same way the on-chain Rue code does.
//
// DESIGN:
//   * .hex / .hash files are emitted by `./build.ps1` from
//     `puzzles/*.rue` and embedded via `include_str!` so the SDK
//     always ships the canonical bytecode.
//   * All tree-hash arithmetic is delegated to upstream
//     `clvm_utils::CurriedProgram + tree_hash_atom + tree_hash_pair`
//     and `chia_puzzle_types::{cat::CatArgs, singleton::SingletonArgs}`
//     so we never hand-roll hashes.
//   * Standard puzzle constants (CAT outer mod hash, singleton launcher
//     hash) come from `chia_puzzles` so versions stay in sync.
//
// CRATES USED:
//   * chia_puzzles               — CAT_PUZZLE_HASH (CAT v2 outer)
//   * chia_puzzle_types::cat     — CatArgs::curry_tree_hash
//   * chia_puzzle_types::singleton — SingletonArgs::curry_tree_hash
//   * clvm_utils                 — CurriedProgram, tree_hash_atom, tree_hash_pair, ToTreeHash, TreeHash
//   * chia_bls                   — PublicKey
//   * chia_protocol              — Bytes32
//   * sha2                       — for the per-voter hint (not a CLVM tree hash)
// ============================================================================

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_puzzle_types::cat::CatArgs;
use chia_puzzle_types::singleton::SingletonArgs;
use chia_puzzles::CAT_PUZZLE_HASH;
use clvm_utils::{tree_hash_atom, tree_hash_pair, TreeHash};
use sha2::{Digest, Sha256};

// ── Embedded puzzle bytecode + tree hashes ────────────────────────────
//
// CONVENTION: each puzzle X has a `*_HEX` constant (CLVM bytecode in
// hex, used for puzzle reveals at spend time) and a `*_HASH_HEX`
// constant (tree hash of the uncurried puzzle, used for currying).

/// Action layer dispatcher. CHIP-0050 inner puzzle that:
///   * verifies each selected action's hash is in `MERKLE_ROOT`
///   * runs them in sequence, threading `StateTruth` between them
///   * hands the final state + accumulated conditions to `FINALIZER`
pub const ACTION_LAYER_HEX: &str =
    include_str!("../../puzzles/compiled/action.rue.hex");
pub const ACTION_LAYER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/action.rue.hash");

/// Election Singleton custom finalizer — recreates the singleton with
/// `amount = 1 + accumulated_fees`.
pub const ELECTION_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalizer.rue.hex");
pub const ELECTION_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalizer.rue.hash");

/// Election Singleton `register` action — verifies SPT + asserts the
/// CAT-creation announcement + recreates state.
pub const ELECTION_REGISTER_HEX: &str =
    include_str!("../../puzzles/compiled/election/register.rue.hex");
pub const ELECTION_REGISTER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/register.rue.hash");

/// Election Singleton `finalize` action — Groth16 + BLS + height lock +
/// commits vote outcome + pays accumulated_fees to the finalizer.
pub const ELECTION_FINALIZE_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalize.rue.hex");
pub const ELECTION_FINALIZE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalize.rue.hash");

/// Election Singleton `announce_finalization` action — re-emits the
/// finalization announcement post-finalization.
pub const ELECTION_ANNOUNCE_FINALIZATION_HEX: &str =
    include_str!("../../puzzles/compiled/election/announce_finalization.rue.hex");
pub const ELECTION_ANNOUNCE_FINALIZATION_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/announce_finalization.rue.hash");

/// Election Singleton `oracle` action — emits a vote-result
/// CreateCoinAnnouncement that any external puzzle can assert
/// against in the same spend bundle. Valid in BOTH finalized and
/// unfinalized states; the announcement message uses distinct
/// `"oracle_finalized"` / `"oracle_unfinalized"` prefixes so the
/// two variants can never be confused. State is unchanged.
pub const ELECTION_ORACLE_HEX: &str =
    include_str!("../../puzzles/compiled/election/oracle.rue.hex");
pub const ELECTION_ORACLE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/oracle.rue.hash");

/// Registration Coin custom finalizer — recreates the CAT-wrapped coin
/// OR sends CAT to destination depending on `release_destination`.
pub const REGISTRATION_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/finalizer.rue.hex");
pub const REGISTRATION_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/finalizer.rue.hash");

/// Registration Coin `vote` action — emits AggSigUnsafe + recreates
/// with has_voted=true and vote_data committed to state.
pub const REGISTRATION_VOTE_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/vote.rue.hex");
pub const REGISTRATION_VOTE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/vote.rue.hash");

/// Registration Coin `release` action — asserts finalization, AggSigMe
/// destination, sends CAT.
pub const REGISTRATION_RELEASE_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/release.rue.hex");
pub const REGISTRATION_RELEASE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/release.rue.hash");

/// FN: decode_hash
/// WHAT: parses an embedded `.rue.hash` constant into a `Bytes32`.
/// WHY:  Rue's `--hash` output is hex (with optional `0x` prefix); this
///       gives us a typed handle without each call site repeating the
///       hex-decode + length check.
/// PANICS: only on a build-time bug (the embedded constant not being
///         exactly 64 hex chars). Safe to call without checking.
pub fn decode_hash(hex_str: &str) -> Bytes32 {
    let trimmed = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).expect("embedded puzzle hash must be valid hex");
    let arr: [u8; 32] = bytes.try_into().expect("embedded puzzle hash must be 32 bytes");
    Bytes32::new(arr)
}

/// STRUCT: PuzzleHashes
/// PURPOSE: Cheap typed accessors for every puzzle's tree hash. Each
///          method does the hex-decode of its `*_HASH_HEX` constant.
/// USE FROM: drivers that compute curried puzzle hashes — `Bytes32` is
///           the canonical form for those upstream APIs.
pub struct PuzzleHashes;

impl PuzzleHashes {
    pub fn action_layer() -> Bytes32 { decode_hash(ACTION_LAYER_HASH_HEX) }
    pub fn election_finalizer() -> Bytes32 { decode_hash(ELECTION_FINALIZER_HASH_HEX) }
    pub fn election_register() -> Bytes32 { decode_hash(ELECTION_REGISTER_HASH_HEX) }
    pub fn election_finalize() -> Bytes32 { decode_hash(ELECTION_FINALIZE_HASH_HEX) }
    pub fn election_announce_finalization() -> Bytes32 {
        decode_hash(ELECTION_ANNOUNCE_FINALIZATION_HASH_HEX)
    }
    pub fn election_oracle() -> Bytes32 { decode_hash(ELECTION_ORACLE_HASH_HEX) }
    pub fn registration_finalizer() -> Bytes32 { decode_hash(REGISTRATION_FINALIZER_HASH_HEX) }
    pub fn registration_vote() -> Bytes32 { decode_hash(REGISTRATION_VOTE_HASH_HEX) }
    pub fn registration_release() -> Bytes32 { decode_hash(REGISTRATION_RELEASE_HASH_HEX) }

    /// Standard CAT v2 outer puzzle tree hash. Sourced from
    /// `chia_puzzles::CAT_PUZZLE_HASH` so version drift between our
    /// SDK and the rest of the Chia ecosystem is impossible.
    pub fn cat_outer() -> Bytes32 { Bytes32::new(CAT_PUZZLE_HASH) }
}

// ── CLVM tree-hash primitives (thin wrappers over clvm_utils) ─────────
//
// CLVM tree hash convention:
//   * atom  A → sha256(0x01 || A.bytes)
//   * pair (X,Y) → sha256(0x02 || tree_hash(X) || tree_hash(Y))
// Each helper here just re-types the upstream `clvm_utils` result back
// into `Bytes32` for ergonomic passing into `chia_protocol` APIs.

/// FN: hash_atom
/// WHAT: tree hash of a raw byte atom.
/// IMPL: delegates to `clvm_utils::tree_hash_atom`.
pub fn hash_atom(bytes: &[u8]) -> Bytes32 {
    Bytes32::new(tree_hash_atom(bytes).to_bytes())
}

/// FN: hash_atom_b32
/// WHAT: tree hash of a 32-byte hash treated as an atom — the form
///       needed when supplying a hash as a `CurriedProgram` arg.
pub fn hash_atom_b32(b: &Bytes32) -> Bytes32 {
    Bytes32::new(tree_hash_atom(b.as_ref()).to_bytes())
}

/// FN: hash_pair
/// WHAT: tree hash of a pair, given the tree hashes of its halves.
pub fn hash_pair(left: Bytes32, right: Bytes32) -> Bytes32 {
    let l = TreeHash::new(left.to_bytes());
    let r = TreeHash::new(right.to_bytes());
    Bytes32::new(tree_hash_pair(l, r).to_bytes())
}

/// FN: curry_tree_hash
/// WHAT: tree hash of `(curry mod_hash arg_1 ... arg_n)`.
/// USAGE: `arg_hashes[i]` is the tree hash of the i-th curried argument.
///        For a `Bytes32` atom argument, pass `hash_atom_b32(&value)`.
/// IMPL: thin wrapper around `clvm_utils::curry_tree_hash` (the
///       canonical Chia helper). It builds the standard curry
///       envelope `(a (q . PROGRAM) (c (q . ARG1) (c (q . ARG2)
///       ... (q . 1))))` and tree-hashes it without materialising
///       any CLVM tree.
///
/// HISTORICAL NOTE: an earlier version built
///   `CurriedProgram { program: TreeHash, args: Vec<TreeHash> }
///       .tree_hash()`
/// which is WRONG — `Vec<T>` serialises as a plain `(T1 . (T2
/// . NIL))` list, not the curry envelope. That bug made every
/// curried puzzle hash diverge from the on-chain reality. Pinned
/// by the deployer↔spender equivalence test.
/// EXAMPLE:
/// ```text
/// let inner_ph = curry_tree_hash(
///     mod_hash,
///     &[hash_atom_b32(&voter_pubkey_b32), hash_atom_b32(&launcher_id)],
/// );
/// ```
pub fn curry_tree_hash(mod_hash: Bytes32, arg_hashes: &[Bytes32]) -> Bytes32 {
    let mod_th = TreeHash::new(mod_hash.to_bytes());
    let args_th: Vec<TreeHash> = arg_hashes
        .iter()
        .map(|h| TreeHash::new(h.to_bytes()))
        .collect();
    Bytes32::new(clvm_utils::curry_tree_hash(mod_th, &args_th).to_bytes())
}

// ── High-level puzzle-hash computations ───────────────────────────────

/// Domain-separated preimage prefix for [`voter_hint`]. Must match
/// `puzzles/election/register.rue` byte-for-byte.
pub const VOTER_HINT_DOMAIN_V1: &[u8] = b"CHIP/onchain/voter_hint/v1/";

/// FN: voter_hint
/// WHAT: per-voter coin-state lookup key for this election CAT.
/// FORMULA:
///   `sha256(VOTER_HINT_DOMAIN_V1 ||
///           election_launcher_id ||
///           cat_tail_hash ||
///           voter_pubkey)`.
/// WHY: binds launcher, CAT tail, and voter (no cross-election /
///      cross-asset collisions); stable across the registration coin
///      lineage so indexers use one `get_coin_records_by_hint` key.
/// MIRROR: identical formula appears in
///         `puzzles/election/register.rue::fresh_registration_coin_puzzle_hash`
///         (hint baked into curry) + memos written by `finalizer.rue`.
pub fn voter_hint(
    election_launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
    voter_pubkey: &PublicKey,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(VOTER_HINT_DOMAIN_V1);
    h.update(election_launcher_id.as_ref());
    h.update(cat_tail_hash.as_ref());
    h.update(voter_pubkey.to_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: fresh_registration_state_tree_hash
/// WHAT: tree hash of the genesis `RegistrationState` for a freshly-
///       registered voter (HAS_VOTED=false, vote_data=0,
///       release_destination=nil).
/// SHAPE: mirrors the Rue struct field order
///        `(voter_pubkey . (election_launcher_id . (has_voted . (vote_data . release_destination))))`
/// WHY: the registration coin's action layer is curried with this
///      state, so its tree hash is part of the coin's puzzle hash.
pub fn fresh_registration_state_tree_hash(
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
) -> Bytes32 {
    let pk_hash = hash_atom(&voter_pubkey.to_bytes());
    let el_hash = hash_atom_b32(&election_launcher_id);
    let hv_hash = hash_atom(&[]);                      // false → nil → empty atom
    let vd_hash = hash_atom_b32(&Bytes32::default());
    let rd_hash = hash_atom(&[]);                      // None → nil

    let pair = hash_pair(vd_hash, rd_hash);
    let pair = hash_pair(hv_hash, pair);
    let pair = hash_pair(el_hash, pair);
    hash_pair(pk_hash, pair)
}

/// FN: fresh_registration_inner_hash
/// WHAT: action-layer inner puzzle hash for a Registration Coin (the
///       puzzle hash *inside* the CAT outer wrap).
/// USAGE: rarely needed standalone — callers usually want
///        `fresh_registration_coin_puzzle_hash`. Exposed for indexers
///        that want to compare against the inner puzzle hash directly.
pub fn fresh_registration_inner_hash(
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
) -> Bytes32 {
    let action_layer_mod_hash = PuzzleHashes::action_layer();
    let registration_finalizer_mod_hash = PuzzleHashes::registration_finalizer();
    let registration_merkle_root = registration_actions_merkle_root();

    let hint = voter_hint(election_launcher_id, cat_tail_hash, voter_pubkey);
    let initial_state_hash =
        fresh_registration_state_tree_hash(voter_pubkey, election_launcher_id);

    // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT)
    let finalizer_first = curry_tree_hash(
        registration_finalizer_mod_hash,
        &[hash_atom_b32(&action_layer_mod_hash), hash_atom_b32(&hint)],
    );
    // Finalizer 2nd curry: bind self-hash (CHIP-0050 finalizer pattern).
    // `finalizer_first` is the *atom* the puzzle curries in (the hash
    // value, not the program), so wrap it with `hash_atom_b32`.
    let finalizer_full =
        curry_tree_hash(finalizer_first, &[hash_atom_b32(&finalizer_first)]);

    // Action layer curry: (FINALIZER, MERKLE_ROOT, STATE)
    //
    // Curry-arg convention (matches yakuhito's slot-machine and the
    // mirrored Rue helper in `election/register.rue`):
    //   * Atom values   → wrap with `hash_atom_b32(...)`.
    //   * Tree-hashed   → pass as `Bytes32` directly. `finalizer_full`
    //                     is a `curry_tree_hash` result so it already
    //                     represents `tree_hash(finalizer_program)`.
    //                     Pre-wrapping would double-hash.
    curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            hash_atom_b32(&registration_merkle_root),
            initial_state_hash,
        ],
    )
}

/// FN: fresh_registration_coin_puzzle_hash
/// WHAT: full CAT-wrapped puzzle hash for a fresh Registration Coin —
///       the puzzle hash that appears on-chain.
/// USAGE: predict where a voter's registration coin will land BEFORE
///        they spend their CAT into it. Lets indexers + aggregators
///        watch for the coin without needing the puzzle reveal.
/// UPSTREAM: delegates the CAT outer wrap to
///           `chia_puzzle_types::cat::CatArgs::curry_tree_hash` so the
///           arithmetic is identical to every other CAT in Chia.
/// MIRROR: matches on-chain `fresh_registration_coin_puzzle_hash` in
///         `puzzles/election/register.rue`.
pub fn fresh_registration_coin_puzzle_hash(
    cat_tail_hash: Bytes32,
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
) -> Bytes32 {
    let inner = fresh_registration_inner_hash(voter_pubkey, election_launcher_id, cat_tail_hash);
    let inner_th = TreeHash::new(inner.to_bytes());
    let curried = CatArgs::curry_tree_hash(cat_tail_hash, inner_th);
    Bytes32::new(curried.to_bytes())
}

// ── Oracle action helpers ─────────────────────────────────────────────
//
// These mirror the byte-form of the announcement messages emitted by
// `puzzles/election/oracle.rue`. Centralising them here lets external
// consumers — both inside this SDK (`actors::oracle::Oracle`) and
// downstream puzzles that want to assert against the oracle —
// recompute the exact `AssertCoinAnnouncement` arguments without
// re-running the CLVM puzzle.

/// FN: oracle_finalized_message
/// WHAT: byte-form of the message emitted by the `oracle` action when
///       `State.finalized == true`.
/// FORMULA: `sha256("oracle_finalized" || vote_outcome ||
///                   count_be8 || merkle_root)`
/// MIRROR: `puzzles/election/shared.rue::oracle_finalized_announcement_msg`.
pub fn oracle_finalized_message(
    vote_outcome: Bytes32,
    registration_count: u64,
    registration_merkle_root: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"oracle_finalized");
    h.update(vote_outcome.as_ref());
    h.update(registration_count.to_be_bytes());
    h.update(registration_merkle_root.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: oracle_unfinalized_message
/// WHAT: byte-form of the message emitted by the `oracle` action
///       when `State.finalized == false`.
/// FORMULA: `sha256("oracle_unfinalized" || count_be8 ||
///                   merkle_root)`
/// PREFIX SAFETY: the distinct ASCII prefix from
/// `oracle_finalized_message` guarantees external puzzles can
/// pattern-match on the variant via the preimage prefix bytes —
/// and consensus's `AssertCoinAnnouncement` opcode never collides
/// the two variants because the resulting sha256 outputs differ.
/// MIRROR: `puzzles/election/shared.rue::oracle_unfinalized_announcement_msg`.
pub fn oracle_unfinalized_message(
    registration_count: u64,
    registration_merkle_root: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"oracle_unfinalized");
    h.update(registration_count.to_be_bytes());
    h.update(registration_merkle_root.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: oracle_announcement_id
/// WHAT: the FULL `AssertCoinAnnouncement` argument id consumers must
///       emit to assert the oracle's announcement.
/// FORMULA: `sha256(announcer_coin_id || message)` — exactly the form
///          consensus's `AssertCoinAnnouncement` opcode expects.
/// USAGE: pass `singleton_coin_id` = the Election Singleton's CURRENT
///        coin id (which is what the `oracle` action's spend uses as
///        its coin), and `message` = one of `oracle_finalized_message`
///        / `oracle_unfinalized_message` (whichever variant matches
///        the singleton's state). The result goes directly into a
///        downstream puzzle's `AssertCoinAnnouncement.id` argument.
pub fn oracle_announcement_id(
    singleton_coin_id: Bytes32,
    message: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(singleton_coin_id.as_ref());
    h.update(message.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: election_singleton_puzzle_hash
/// WHAT: full Election Singleton puzzle hash, given its action-layer
///       inner puzzle hash.
/// USAGE: predict the on-chain puzzle hash of the Election Singleton —
///        used by `Aggregator::sync` to query its coin record.
/// UPSTREAM: delegates to
///           `chia_puzzle_types::singleton::SingletonArgs::curry_tree_hash`.
pub fn election_singleton_puzzle_hash(
    election_launcher_id: Bytes32,
    inner_puzzle_hash: Bytes32,
) -> Bytes32 {
    let inner_th = TreeHash::new(inner_puzzle_hash.to_bytes());
    let curried = SingletonArgs::curry_tree_hash(election_launcher_id, inner_th);
    Bytes32::new(curried.to_bytes())
}

/// FN: registration_actions_merkle_root
/// WHAT: 2-leaf Merkle root over the registration coin's allowed
///       actions (vote, release).
/// WHY: the action layer asserts every selected action's puzzle hash
///      is in this tree. Because both actions read voter info from
///      state (not curry), their puzzle hashes are deployment-wide
///      constants — so this root is a constant too, computable
///      offline.
/// LEAF ORDER: `min(vote_hash, release_hash) || max(...)` — sorted to
///             give a canonical root regardless of declaration order.
pub fn registration_actions_merkle_root() -> Bytes32 {
    let vote = hash_atom_b32(&PuzzleHashes::registration_vote());
    let release = hash_atom_b32(&PuzzleHashes::registration_release());
    let (a, b) = if vote.as_ref() < release.as_ref() {
        (vote, release)
    } else {
        (release, vote)
    };
    hash_pair(a, b)
}

/// FN: registration_action_root_leaves
/// WHAT: leaf SET (sorted) for the Registration Coin's actions
///       Merkle tree. Pass this directly to
///       `chia_sdk_types::MerkleTree::new(&leaves)` to construct a
///       tree whose root matches `registration_actions_merkle_root`
///       and whose `.proof(leaf)` returns the proof selectors that
///       the on-chain `simplify_merkle_proof` accepts.
/// SORT: by `tree_hash_atom(puzzle_hash)` ascending — the same
///       ordering `registration_actions_merkle_root` uses internally.
pub fn registration_action_root_leaves() -> Vec<Bytes32> {
    let vote_ph = PuzzleHashes::registration_vote();
    let release_ph = PuzzleHashes::registration_release();
    let vote_h = hash_atom_b32(&vote_ph);
    let release_h = hash_atom_b32(&release_ph);
    if vote_h.as_ref() < release_h.as_ref() {
        vec![vote_ph, release_ph]
    } else {
        vec![release_ph, vote_ph]
    }
}

/// FN: election_actions_merkle_root
/// WHAT: 4-leaf Merkle root over the Election Singleton's allowed
///       actions (register, finalize, announce_finalization, oracle),
///       each already curried with election-wide constants by the
///       caller (TREE_DEPTH, EMPTY_LEAF_HASH, CAT_TAIL_HASH,
///       COLLATERAL_AMOUNT, etc.).
/// LEAF ORDER: sorted ascending — caller doesn't need to maintain a
///             specific declaration order. The sort key is the
///             `hash_atom_b32`-wrapped leaf, mirroring the wrapping
///             `chia_sdk_types::MerkleTree::new` applies internally
///             (sha256(0x01 || leaf_bytes)) so this manual
///             arithmetic stays byte-for-byte equivalent.
/// SHAPE: with 4 leaves the upstream
///        `chia_sdk_types::MerkleTree::list_to_binary_tree` splits
///        at midpoint = `(4+1) >> 1 = 2`, producing the perfectly
///        balanced binary tree
///          root = sha256(0x02 ||
///                        sha256(0x02 || L0 || L1) ||
///                        sha256(0x02 || L2 || L3))
///        which is exactly `hash_pair(hash_pair(L0,L1),
///        hash_pair(L2,L3))`. Pinned by
///        `election_actions_merkle_root_matches_merkletree`.
pub fn election_actions_merkle_root(
    register_full_hash: Bytes32,
    finalize_full_hash: Bytes32,
    announce_finalization_full_hash: Bytes32,
    oracle_full_hash: Bytes32,
) -> Bytes32 {
    let mut leaves = [
        hash_atom_b32(&register_full_hash),
        hash_atom_b32(&finalize_full_hash),
        hash_atom_b32(&announce_finalization_full_hash),
        hash_atom_b32(&oracle_full_hash),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    let pair23 = hash_pair(leaves[2], leaves[3]);
    hash_pair(pair01, pair23)
}

// ============================================================================
// Tests
// ============================================================================
//
// CONVENTION: every test below carries a `WHAT / HOW / WHY` block:
//   * WHAT — the single invariant the test proves
//   * HOW  — how the test mechanically establishes that invariant
//             (inputs, the operation under test, the assertion)
//   * WHY  — why this invariant matters for the SDK (what breaks if
//             it ever stops holding)
//
// Test strategy (TDD-style):
//   * Each pure helper has a unit test asserting its byte-exact output.
//   * `decode_hash` is exercised via `PuzzleHashes::*` accessors —
//     they panic if any embedded `.hash` file is malformed.
//   * Curry helpers are tested against `chia_puzzle_types`'s own
//     curry helpers for parity (CAT + singleton).
//   * `voter_hint` is tested against a hand-computed sha256.
//   * Merkle-root helpers are tested for canonical leaf ordering.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{SecretKey, master_to_wallet_unhardened};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;

    /// Deterministic test pubkey (shared with chia_sdk_signer test data).
    fn test_pubkey() -> PublicKey {
        let root_sk = SecretKey::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root_sk.public_key(), 0).derive_synthetic()
    }

    fn b32(byte: u8) -> Bytes32 { Bytes32::new([byte; 32]) }

    /// WHAT: every embedded `.rue.hash` artefact is well-formed
    ///       (exactly 32 bytes of valid hex).
    /// HOW:  call every `PuzzleHashes::*` accessor; each one runs
    ///       `decode_hash` on its embedded constant and panics on
    ///       malformed input. Reaching the end of the function = pass.
    /// WHY:  if a build script ever ships a truncated or malformed
    ///       hash file, every downstream puzzle-hash computation in
    ///       the SDK silently uses garbage. Catching it here turns a
    ///       runtime mystery into a build-time test failure.
    #[test]
    fn embedded_puzzle_hashes_are_decodable() {
        let _ = PuzzleHashes::action_layer();
        let _ = PuzzleHashes::election_finalizer();
        let _ = PuzzleHashes::election_register();
        let _ = PuzzleHashes::election_finalize();
        let _ = PuzzleHashes::election_announce_finalization();
        let _ = PuzzleHashes::election_oracle();
        let _ = PuzzleHashes::registration_finalizer();
        let _ = PuzzleHashes::registration_vote();
        let _ = PuzzleHashes::registration_release();
    }

    /// WHAT: `PuzzleHashes::cat_outer()` returns the canonical
    ///       `chia_puzzles::CAT_PUZZLE_HASH` constant.
    /// HOW:  direct equality assertion against `CAT_PUZZLE_HASH`.
    /// WHY:  the SDK's CAT-wrapping arithmetic must use the same
    ///       outer puzzle as every other Chia tool. If `chia-puzzles`
    ///       ever updates `CAT_PUZZLE_HASH` (CAT v3, etc.), this test
    ///       breaks loudly so we notice and update everything in
    ///       lock-step.
    #[test]
    fn cat_outer_matches_upstream_constant() {
        assert_eq!(PuzzleHashes::cat_outer(), Bytes32::new(CAT_PUZZLE_HASH));
    }

    /// WHAT: our `hash_atom` returns byte-identical output to
    ///       `clvm_utils::tree_hash_atom`.
    /// HOW:  hash a fixed 16-byte buffer through both helpers and
    ///       compare the resulting `Bytes32`.
    /// WHY:  `hash_atom` is just a thin re-type wrapper; this test
    ///       guards against accidental drift if someone "optimises"
    ///       the wrapper without re-checking parity with upstream.
    #[test]
    fn hash_atom_matches_upstream() {
        let payload = [0xAA; 16];
        assert_eq!(
            hash_atom(&payload),
            Bytes32::new(tree_hash_atom(&payload).to_bytes()),
        );
    }

    /// WHAT: our `hash_pair` produces byte-identical output to
    ///       `clvm_utils::tree_hash_pair`.
    /// HOW:  build two `Bytes32` halves, hash through both functions,
    ///       compare the result.
    /// WHY:  same rationale as `hash_atom_matches_upstream`; together
    ///       they pin the entire CLVM tree-hash convention to its
    ///       upstream definition.
    #[test]
    fn hash_pair_matches_upstream() {
        let l = b32(1);
        let r = b32(2);
        let lt = TreeHash::new(l.to_bytes());
        let rt = TreeHash::new(r.to_bytes());
        assert_eq!(hash_pair(l, r), Bytes32::new(tree_hash_pair(lt, rt).to_bytes()));
    }

    /// WHAT: our `curry_tree_hash` matches the upstream
    ///       `clvm_utils::curry_tree_hash` standalone helper AND
    ///       the actual tree hash of a materialised
    ///       `CurriedProgram` CLVM tree.
    /// HOW:  curry an atom argument into a fake mod hash via THREE
    ///       paths and assert all three agree byte-for-byte:
    ///         1. our `curry_tree_hash`
    ///         2. `clvm_utils::curry_tree_hash`
    ///         3. `tree_hash(CurriedProgram { program, args }
    ///            .to_clvm())` — the fully materialised tree
    /// WHY:  `curry_tree_hash` is the workhorse for every action /
    ///       finalizer / state hash in the SDK. Any drift from the
    ///       upstream curry envelope `(a (q . PROGRAM) (c (q . arg1)
    ///       ... (q . 1)))` arithmetic would silently produce
    ///       non-spendable puzzle hashes everywhere — the live
    ///       integration test on mainnet surfaced exactly this bug
    ///       before this assertion was added.
    #[test]
    fn curry_tree_hash_matches_upstream() {
        use clvm_traits::clvm_curried_args;
        use clvmr::Allocator;

        // Use atom-hashes as INPUTS to curry_tree_hash so the
        // materialised path (which puts atoms in the allocator and
        // takes their tree hash) produces the SAME inputs.
        let mod_atom = b32(0x42);
        let arg_atom = b32(0x99);
        let mod_hash = hash_atom_b32(&mod_atom); // tree hash of the program-atom
        let arg_hash = hash_atom_b32(&arg_atom); // tree hash of the arg-atom

        let ours = curry_tree_hash(mod_hash, &[arg_hash]);

        let mod_th = TreeHash::new(mod_hash.to_bytes());
        let arg_th = TreeHash::new(arg_hash.to_bytes());
        let upstream = clvm_utils::curry_tree_hash(mod_th, &[arg_th]);
        assert_eq!(ours, Bytes32::new(upstream.to_bytes()));

        // Materialise the curry envelope through the regular
        // `to_clvm` path and tree-hash the resulting tree. The
        // program and arg are atoms here, so their tree hashes
        // equal `hash_atom_b32` of their bytes — matching the
        // inputs we passed above.
        use clvm_traits::ToClvm;
        use clvm_utils::CurriedProgram;
        let mut a = Allocator::new();
        let prog_node = a.new_atom(mod_atom.as_ref()).unwrap();
        let arg_node = a.new_atom(arg_atom.as_ref()).unwrap();
        let curry_node: clvmr::NodePtr = CurriedProgram {
            program: prog_node,
            args: clvm_curried_args!(arg_node),
        }
        .to_clvm(&mut a)
        .unwrap();
        let materialised = clvm_utils::tree_hash(&a, curry_node);
        assert_eq!(ours, Bytes32::new(materialised.to_bytes()));
    }

    /// WHAT: `voter_hint` matches the v1 preimage
    ///       `sha256(DOMAIN||election||tail||pk_bytes)` byte-exact.
    /// HOW:  recompute the sha256 inline against a fixed pk +
    ///       election id + CAT tail and assert equality.
    /// WHY:  the on-chain Rue puzzle and every off-chain indexer must
    ///       compute the SAME hint or coin-state queries return
    ///       nothing. Pinning the formula to a hand-computed value
    ///       prevents accidental change of the input order or
    ///       prefix bytes.
    #[test]
    fn voter_hint_is_sha256_of_concatenation() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail = b32(0xAA);

        let mut expected = Sha256::new();
        expected.update(VOTER_HINT_DOMAIN_V1);
        expected.update(election_id.as_ref());
        expected.update(tail.as_ref());
        expected.update(pk.to_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&expected.finalize());

        assert_eq!(voter_hint(election_id, tail, &pk), Bytes32::new(arr));
    }

    /// WHAT: `voter_hint` is deterministic (idempotent) for the same
    ///       (pubkey, election, CAT tail) triple.
    /// HOW:  call twice with identical inputs, assert equal output.
    /// WHY:  indexers cache the hint per voter; if it ever changed
    ///       between calls the cache would silently desynchronise
    ///       from the chain.
    #[test]
    fn voter_hint_is_stable_per_voter() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail = b32(0xAA);
        assert_eq!(
            voter_hint(election_id, tail, &pk),
            voter_hint(election_id, tail, &pk),
        );
    }

    /// WHAT: the same voter pubkey under two different elections
    ///       produces two different hints.
    /// HOW:  hold pubkey constant, vary election_id, assert
    ///       inequality.
    /// WHY:  cross-election replay safety — a voter's coins in
    ///       election A must never match an `get_coin_records_by_hint`
    ///       query for election B.
    #[test]
    fn voter_hint_differs_per_election() {
        let pk = test_pubkey();
        let tail = b32(0xAA);
        assert_ne!(
            voter_hint(b32(0x11), tail, &pk),
            voter_hint(b32(0x22), tail, &pk),
        );
    }

    #[test]
    fn voter_hint_differs_per_cat_tail() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        assert_ne!(
            voter_hint(election_id, b32(0xAA), &pk),
            voter_hint(election_id, b32(0xBB), &pk),
        );
    }

    /// WHAT: `registration_actions_merkle_root()` is deterministic
    ///       (it returns the same value across calls).
    /// HOW:  call twice, assert equality. Internally the function
    ///       sorts its leaves before hashing, so the output is
    ///       independent of the underlying compiled-puzzle ordering.
    /// WHY:  the root is curried into every Registration Coin's
    ///       puzzle hash. Non-determinism would yield non-spendable
    ///       coins.
    #[test]
    fn registration_actions_merkle_root_is_sorted_canonical() {
        let r1 = registration_actions_merkle_root();
        let r2 = registration_actions_merkle_root();
        assert_eq!(r1, r2);
    }

    /// WHAT: `election_actions_merkle_root` is permutation-invariant
    ///       — feeding it the same SET of leaves in any order
    ///       produces the same root.
    /// HOW:  call with several permutations of `(a, b, c, d)` and
    ///       assert all roots are equal.
    /// WHY:  callers shouldn't have to remember an arbitrary
    ///       declaration order; the canonical-sort behaviour is part
    ///       of the public contract and must not regress.
    #[test]
    fn election_actions_merkle_root_is_order_independent() {
        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);
        let d = b32(0xD4);

        let r1 = election_actions_merkle_root(a, b, c, d);
        let r2 = election_actions_merkle_root(b, a, c, d);
        let r3 = election_actions_merkle_root(c, b, a, d);
        let r4 = election_actions_merkle_root(d, c, b, a);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert_eq!(r3, r4);
    }

    /// WHAT: our hand-rolled `election_actions_merkle_root` agrees
    ///       byte-for-byte with `chia_sdk_types::MerkleTree::new`
    ///       on the SORTED leaf set.
    /// HOW:  build the same 4 leaves, sort them by `hash_atom_b32`
    ///       (the same key our manual code uses), pass to
    ///       `MerkleTree::new`, compare its `.root()` with the
    ///       output of our helper.
    /// WHY:  the on-chain action layer's merkle proofs are produced
    ///       by `chia_sdk_types::MerkleTree`. If our deployer-side
    ///       root computation diverged from the spend-side proof
    ///       generator, every spend would fail at the merkle check.
    #[test]
    fn election_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);
        let d = b32(0xD4);

        let mut leaves = vec![a, b, c, d];
        leaves.sort_by(|x, y| {
            hash_atom_b32(x)
                .as_ref()
                .cmp(hash_atom_b32(y).as_ref())
        });
        let upstream_root = MerkleTree::new(&leaves).root();

        let our_root = election_actions_merkle_root(a, b, c, d);
        assert_eq!(our_root, upstream_root);
    }

    /// WHAT: `fresh_registration_coin_puzzle_hash` equals
    ///       `chia_puzzle_types::cat::CatArgs::curry_tree_hash(tail,
    ///       inner_th)`.
    /// HOW:  compute the inner hash via our helper, then curry it
    ///       through `CatArgs` directly and compare.
    /// WHY:  any wallet / indexer that knows about CATs assumes this
    ///       exact wrapping. If our SDK diverges, third-party
    ///       tooling cannot find or recognise our coins.
    #[test]
    fn fresh_registration_coin_puzzle_hash_matches_catargs() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail_hash = b32(0x22);

        let inner = fresh_registration_inner_hash(&pk, election_id, tail_hash);
        let inner_th = TreeHash::new(inner.to_bytes());
        let expected = Bytes32::new(
            CatArgs::curry_tree_hash(tail_hash, inner_th).to_bytes(),
        );

        assert_eq!(
            fresh_registration_coin_puzzle_hash(tail_hash, &pk, election_id),
            expected,
        );
    }

    /// WHAT: two distinct voters under the same election produce
    ///       distinct registration-coin inner puzzle hashes.
    /// HOW:  derive two synthetic pubkeys at indexes 0 and 1 from
    ///       the test seed, assert the pubkeys differ (sanity), then
    ///       assert the inner hashes differ.
    /// WHY:  `voter_pubkey` is part of `RegistrationState`; if two
    ///       voters mapped to the same coin puzzle hash they would
    ///       collide on-chain.
    #[test]
    fn fresh_registration_inner_hash_is_per_voter() {
        let election_id = b32(0x11);
        let pk1 = test_pubkey();
        let pk2 = {
            let root_sk = SecretKey::from_bytes(&hex!(
                "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
            ))
            .unwrap();
            master_to_wallet_unhardened(&root_sk.public_key(), 1).derive_synthetic()
        };
        assert_ne!(pk1, pk2, "test setup: pubkeys must differ");
        let tail = b32(0x22);
        assert_ne!(
            fresh_registration_inner_hash(&pk1, election_id, tail),
            fresh_registration_inner_hash(&pk2, election_id, tail),
        );
    }

    /// WHAT: the SAME voter under two different elections produces
    ///       two different registration-coin inner puzzle hashes.
    /// HOW:  hold pubkey constant, vary election_id, assert hashes
    ///       differ.
    /// WHY:  `election_launcher_id` is part of `RegistrationState`;
    ///       this binding prevents a coin minted for election A
    ///       from being recognised as valid for election B.
    #[test]
    fn fresh_registration_inner_hash_is_per_election() {
        let pk = test_pubkey();
        let tail = b32(0x22);
        assert_ne!(
            fresh_registration_inner_hash(&pk, b32(0x11), tail),
            fresh_registration_inner_hash(&pk, b32(0x22), tail),
        );
    }

    /// WHAT: `oracle_finalized_message` returns
    ///       `sha256("oracle_finalized" || vote_outcome ||
    ///                count_be8 || merkle_root)` byte-exact.
    /// HOW:  recompute the sha256 inline against fixed inputs and
    ///       assert equality.
    /// WHY:  the on-chain `oracle` action's preimage is the
    ///       contract every external puzzle that asserts against
    ///       the oracle relies on. Drift here would silently
    ///       invalidate every consumer's `AssertCoinAnnouncement`.
    #[test]
    fn oracle_finalized_message_is_canonical_sha256() {
        let outcome = b32(0x42);
        let count: u64 = 7;
        let root = b32(0x11);

        let mut h = Sha256::new();
        h.update(b"oracle_finalized");
        h.update(outcome.as_ref());
        h.update(count.to_be_bytes());
        h.update(root.as_ref());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(oracle_finalized_message(outcome, count, root), Bytes32::new(expected));
    }

    /// WHAT: `oracle_unfinalized_message` returns
    ///       `sha256("oracle_unfinalized" || count_be8 ||
    ///                merkle_root)` byte-exact.
    /// HOW:  recompute the sha256 inline against fixed inputs and
    ///       assert equality. Notably the unfinalized variant
    ///       OMITS `vote_outcome` (since it's zero pre-finalization
    ///       and would only add noise to the preimage).
    /// WHY:  same rationale as the finalized variant — pin the
    ///       byte-exact preimage so external consumers stay
    ///       compatible.
    #[test]
    fn oracle_unfinalized_message_is_canonical_sha256() {
        let count: u64 = 13;
        let root = b32(0x55);

        let mut h = Sha256::new();
        h.update(b"oracle_unfinalized");
        h.update(count.to_be_bytes());
        h.update(root.as_ref());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(oracle_unfinalized_message(count, root), Bytes32::new(expected));
    }

    /// WHAT: `oracle_finalized_message` and
    ///       `oracle_unfinalized_message` over the SAME (count,
    ///       root) values are byte-distinct.
    /// HOW:  call both with identical (count, root) and a zero
    ///       vote_outcome; assert inequality.
    /// WHY:  domain separation is the WHOLE reason there are two
    ///       variants — without it, an attacker could trick a
    ///       downstream puzzle into believing an unfinalized
    ///       reading was a finalized one. Pin it as a property.
    #[test]
    fn oracle_finalized_and_unfinalized_messages_diverge() {
        let count: u64 = 4;
        let root = b32(0xAA);
        let outcome = Bytes32::default();

        let m_fin = oracle_finalized_message(outcome, count, root);
        let m_un = oracle_unfinalized_message(count, root);
        assert_ne!(m_fin, m_un, "oracle finalized vs unfinalized messages must NEVER collide");
    }

    /// WHAT: `oracle_announcement_id(coin_id, message)` equals
    ///       `sha256(coin_id || message)` byte-exact (matches the
    ///       consensus `AssertCoinAnnouncement` formula).
    /// HOW:  recompute via sha2 inline, assert equality.
    /// WHY:  every downstream puzzle pairs `AssertCoinAnnouncement`
    ///       with this exact id form. Diverging here would mean
    ///       valid oracle spends can't be asserted against.
    #[test]
    fn oracle_announcement_id_is_sha256_of_coin_id_and_message() {
        let singleton_id = b32(0x42);
        let msg = b32(0x99);

        let mut h = Sha256::new();
        h.update(singleton_id.as_ref());
        h.update(msg.as_ref());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h.finalize());

        assert_eq!(oracle_announcement_id(singleton_id, msg), Bytes32::new(expected));
    }

    /// WHAT: `election_singleton_puzzle_hash` equals
    ///       `chia_puzzle_types::singleton::SingletonArgs::curry_tree_hash(launcher_id, inner_th)`.
    /// HOW:  compute via our helper, also via `SingletonArgs`
    ///       directly, assert equality.
    /// WHY:  same rationale as the CatArgs parity test —
    ///       singleton-aware tooling assumes this exact wrapping.
    #[test]
    fn election_singleton_puzzle_hash_matches_singletonargs() {
        let launcher_id = b32(0xAB);
        let inner_ph = b32(0xCD);
        let inner_th = TreeHash::new(inner_ph.to_bytes());
        let expected = Bytes32::new(
            SingletonArgs::curry_tree_hash(launcher_id, inner_th).to_bytes(),
        );
        assert_eq!(
            election_singleton_puzzle_hash(launcher_id, inner_ph),
            expected,
        );
    }
}
