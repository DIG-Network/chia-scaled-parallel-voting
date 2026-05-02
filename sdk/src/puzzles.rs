// ============================================================================
// puzzles.rs — compiled puzzle bytecode + tree-hash arithmetic
// ============================================================================
//
// MODULE: puzzles
// PURPOSE: Embed Rue-compiled CLVM bytecode for the voting CHIP puzzles
//          (CHIP rev 2026-05-02: multi-ballot architecture) and expose
//          helper functions that compute curried puzzle hashes the
//          same way the on-chain Rue code does.
//
// DESIGN:
//   * .rue.hex / .rue.hash files are emitted by `./build.sh` from
//     `puzzles/**/*.rue` and embedded via `include_str!` so the SDK
//     always ships the canonical bytecode.
//   * All tree-hash arithmetic is delegated to upstream
//     `clvm_utils::CurriedProgram + tree_hash_atom + tree_hash_pair`
//     and `chia_puzzle_types::{cat::CatArgs, singleton::SingletonArgs}`
//     so we never hand-roll hashes.
//   * Standard puzzle constants (CAT outer mod hash, singleton launcher
//     hash) come from `chia_puzzles` so versions stay in sync.
//
// ARCHITECTURE NOTES (CHIP rev 2026-05-02):
//   * The Election Singleton hosts only orchestration actions
//     (register, create_ballot, deregister). Per-ballot finalization
//     and oracle live on Ballot Coins (a singleton per ballot).
//   * Each registered voter's per-ballot vote is carried by an
//     ephemeral Voting Coin (CAT-wrapped, mint+spend in the same
//     bundle).
//   * The Registration Coin tracks an SPT root over the ballots a
//     voter has voted on (`voted_ballots_root`); the empty root for
//     a depth-32 tree of `EMPTY_BALLOT_LEAF_HASH` is the genesis
//     value at registration time.
//
// CRATES USED:
//   * chia_puzzles               — CAT_PUZZLE_HASH (CAT v2 outer)
//   * chia_puzzle_types::cat     — CatArgs::curry_tree_hash
//   * chia_puzzle_types::singleton — SingletonArgs::curry_tree_hash
//   * clvm_utils                 — CurriedProgram, tree_hash_atom, tree_hash_pair, ToTreeHash, TreeHash
//   * chia_bls                   — PublicKey
//   * chia_protocol              — Bytes32
//   * sha2                       — for hint preimages + announcement messages
// ============================================================================

use std::sync::OnceLock;

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
// Filenames on disk end in `.rue.hex` / `.rue.hash` (the `.rue.` prefix
// is preserved by `build.sh` so the artefact unambiguously points back
// at its source).

/// Action layer dispatcher. CHIP-0050 inner puzzle that:
///   * verifies each selected action's hash is in `MERKLE_ROOT`
///   * runs them in sequence, threading `StateTruth` between them
///   * hands the final state + accumulated conditions to `FINALIZER`
pub const ACTION_LAYER_HEX: &str = include_str!("../../puzzles/compiled/action.rue.hex");
pub const ACTION_LAYER_HASH_HEX: &str = include_str!("../../puzzles/compiled/action.rue.hash");

// ── Election Singleton (orchestration lane) ───────────────────────────

/// Election Singleton custom finalizer — recreates the singleton at
/// `amount = 1` after each inner action runs (CHIP rev 2026-05-02:
/// the singleton no longer accumulates fees; per-ballot finalization
/// has moved off-singleton).
pub const ELECTION_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalizer.rue.hex");
pub const ELECTION_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/finalizer.rue.hash");

/// Election Singleton `register` action — verifies SPT emptiness
/// proof at the voter's canonical slot, asserts the
/// CAT-creation announcement of the Registration Coin, and inserts
/// `sha256(voter_pubkey)` at that slot. Mints the Registration Coin
/// with `voted_ballots_root = EMPTY_BALLOT_ROOT` and
/// `release_destination = nil`.
pub const ELECTION_REGISTER_HEX: &str =
    include_str!("../../puzzles/compiled/election/register.rue.hex");
pub const ELECTION_REGISTER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/register.rue.hash");

/// Election Singleton `create_ballot` action — mints a new Ballot
/// Coin singleton (eve coin) and announces its launcher id + close
/// height + outcome domain. The Election Singleton's state is
/// unchanged.
pub const ELECTION_CREATE_BALLOT_HEX: &str =
    include_str!("../../puzzles/compiled/election/create_ballot.rue.hex");
pub const ELECTION_CREATE_BALLOT_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/create_ballot.rue.hash");

/// Election Singleton `deregister` action — wipes the voter's leaf
/// from the SPT and emits the canonical deregister announcement that
/// the Registration Coin's `release` action asserts against to
/// authorize collateral release.
pub const ELECTION_DEREGISTER_HEX: &str =
    include_str!("../../puzzles/compiled/election/deregister.rue.hex");
pub const ELECTION_DEREGISTER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/deregister.rue.hash");

// ── Ballot Coin (per-ballot lane) ─────────────────────────────────────

/// Ballot Coin custom finalizer — recreates the Ballot Coin singleton
/// at amount 1. (Standard CHIP-0050 finalizer; ballot coins never
/// accumulate fees.)
pub const BALLOT_COIN_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/finalizer.rue.hex");
pub const BALLOT_COIN_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/finalizer.rue.hash");

/// Ballot Coin `finalize` action — Groth16 + BLS aggregate
/// verification, six public inputs (registration_merkle_root,
/// registration_vote_weight, agg_signers, vote_message,
/// threshold_pack, ballot_launcher_id). Sets `finalized = true` and
/// commits the `vote_outcome` + `agg_signers` commitment.
pub const BALLOT_COIN_FINALIZE_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/finalize.rue.hex");
pub const BALLOT_COIN_FINALIZE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/finalize.rue.hash");

/// Ballot Coin `oracle` action — emits a domain-separated
/// announcement of the ballot's open/closed status. Used by Voting
/// Coin spends to pin the ballot's actual curried close height (open
/// variant) and by downstream consumers asserting against finalized
/// outcomes (closed variant).
pub const BALLOT_COIN_ORACLE_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/oracle.rue.hex");
pub const BALLOT_COIN_ORACLE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/oracle.rue.hash");

/// Ballot Coin `announce_finalization` action — re-emits the
/// finalization announcement post-finalization for downstream
/// observers / late asserters.
pub const BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/announce_finalization.rue.hex");
pub const BALLOT_COIN_ANNOUNCE_FINALIZATION_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ballot_coin/announce_finalization.rue.hash");

// ── Registration Coin (CAT inner) ─────────────────────────────────────

/// Registration Coin custom finalizer — recreates the CAT-wrapped
/// coin OR sends CAT to `release_destination` if set.
pub const REGISTRATION_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/finalizer.rue.hex");
pub const REGISTRATION_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/finalizer.rue.hash");

/// Registration Coin `mint_voting_coin` action — proves the target
/// ballot's slot in `voted_ballots_root` is empty, replaces it with
/// the committed leaf (one-shot per ballot), mints the per-ballot
/// Voting Coin (CAT-wrapped) carrying the voter's signed
/// `vote_message`.
pub const REGISTRATION_MINT_VOTING_COIN_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/mint_voting_coin.rue.hex");
pub const REGISTRATION_MINT_VOTING_COIN_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/mint_voting_coin.rue.hash");

/// Registration Coin `release` action — asserts the Election
/// Singleton's `deregister` announcement and an AggSigMe over
/// `(election_id, pubkey, destination)`, then sets
/// `release_destination` so the finalizer pays out the CAT collateral.
pub const REGISTRATION_RELEASE_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/release.rue.hex");
pub const REGISTRATION_RELEASE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/registration_coin/release.rue.hash");

// ── Voting Coin (per-ballot ephemeral, CAT inner) ─────────────────────

/// Voting Coin custom finalizer — recreates the Voting Coin (or
/// terminates it; depending on the action) with the new state.
pub const VOTING_COIN_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/voting_coin/finalizer.rue.hex");
pub const VOTING_COIN_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/voting_coin/finalizer.rue.hash");

/// Voting Coin `update_vote` action — voter changes `vote_data`
/// before the ballot closes. Asserts ballot-open via the Ballot Coin
/// oracle co-spend; emits a fresh AggSigMe over `vote_message(new)`.
pub const VOTING_COIN_UPDATE_VOTE_HEX: &str =
    include_str!("../../puzzles/compiled/voting_coin/update_vote.rue.hex");
pub const VOTING_COIN_UPDATE_VOTE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/voting_coin/update_vote.rue.hash");

// ── Ballot SPT constants ──────────────────────────────────────────────

/// Empty leaf marker for the per-registration ballot SPT. Voting on
/// a ballot replaces an empty leaf with a committed leaf at the
/// canonical slot for that ballot's launcher id; the marker is
/// 32 bytes of 0x00 (matches `EMPTY_BALLOT_LEAF_HASH` in
/// `puzzles/registration_coin/shared.rue`).
pub const EMPTY_BALLOT_LEAF_HASH: Bytes32 = Bytes32::new([0; 32]);

/// Depth of the per-registration ballot SPT — must match
/// `BALLOT_TREE_DEPTH` in `puzzles/registration_coin/shared.rue`.
pub const BALLOT_TREE_DEPTH: usize = 32;

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
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("embedded puzzle hash must be 32 bytes");
    Bytes32::new(arr)
}

/// STRUCT: PuzzleHashes
/// PURPOSE: Cheap typed accessors for every puzzle's tree hash. Each
///          method does the hex-decode of its `*_HASH_HEX` constant.
/// USE FROM: drivers that compute curried puzzle hashes — `Bytes32` is
///           the canonical form for those upstream APIs.
pub struct PuzzleHashes;

impl PuzzleHashes {
    pub fn action_layer() -> Bytes32 {
        decode_hash(ACTION_LAYER_HASH_HEX)
    }

    // Election Singleton
    pub fn election_finalizer() -> Bytes32 {
        decode_hash(ELECTION_FINALIZER_HASH_HEX)
    }
    pub fn election_register() -> Bytes32 {
        decode_hash(ELECTION_REGISTER_HASH_HEX)
    }
    pub fn election_create_ballot() -> Bytes32 {
        decode_hash(ELECTION_CREATE_BALLOT_HASH_HEX)
    }
    pub fn election_deregister() -> Bytes32 {
        decode_hash(ELECTION_DEREGISTER_HASH_HEX)
    }

    // Ballot Coin
    pub fn ballot_coin_finalizer() -> Bytes32 {
        decode_hash(BALLOT_COIN_FINALIZER_HASH_HEX)
    }
    pub fn ballot_coin_finalize() -> Bytes32 {
        decode_hash(BALLOT_COIN_FINALIZE_HASH_HEX)
    }
    pub fn ballot_coin_oracle() -> Bytes32 {
        decode_hash(BALLOT_COIN_ORACLE_HASH_HEX)
    }
    pub fn ballot_coin_announce_finalization() -> Bytes32 {
        decode_hash(BALLOT_COIN_ANNOUNCE_FINALIZATION_HASH_HEX)
    }

    // Registration Coin
    pub fn registration_finalizer() -> Bytes32 {
        decode_hash(REGISTRATION_FINALIZER_HASH_HEX)
    }
    pub fn registration_mint_voting_coin() -> Bytes32 {
        decode_hash(REGISTRATION_MINT_VOTING_COIN_HASH_HEX)
    }
    pub fn registration_release() -> Bytes32 {
        decode_hash(REGISTRATION_RELEASE_HASH_HEX)
    }

    // Voting Coin
    pub fn voting_coin_finalizer() -> Bytes32 {
        decode_hash(VOTING_COIN_FINALIZER_HASH_HEX)
    }
    pub fn voting_coin_update_vote() -> Bytes32 {
        decode_hash(VOTING_COIN_UPDATE_VOTE_HASH_HEX)
    }

    /// Standard CAT v2 outer puzzle tree hash. Sourced from
    /// `chia_puzzles::CAT_PUZZLE_HASH` so version drift between our
    /// SDK and the rest of the Chia ecosystem is impossible.
    pub fn cat_outer() -> Bytes32 {
        Bytes32::new(CAT_PUZZLE_HASH)
    }
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

/// Domain-separated preimage prefix for [`voting_coin_hint`]. Must
/// match `puzzles/registration_coin/mint_voting_coin.rue` byte-for-byte.
pub const VOTING_COIN_HINT_DOMAIN_V1: &[u8] = b"CHIP/onchain/voting_coin_hint/v1/";

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

/// FN: voting_coin_hint
/// WHAT: per-(voter, ballot) coin-state lookup key for the Voting
///       Coin minted by `mint_voting_coin`.
/// FORMULA:
///   `sha256(VOTING_COIN_HINT_DOMAIN_V1 ||
///           election_launcher_id ||
///           cat_tail_hash ||
///           voter_pubkey ||
///           ballot_launcher_id)`.
/// WHY: parallels [`voter_hint`] but binds the per-ballot Voting Coin
///      so indexers can find one voter's vote on a specific ballot in
///      a single `get_coin_records_by_hint` call.
/// MIRROR: `puzzles/registration_coin/mint_voting_coin.rue` —
///         `voting_coin_hint = sha256("CHIP/onchain/voting_coin_hint/v1/" ||
///         election_launcher_id || cat_tail_hash || voter_pubkey ||
///         ballot_launcher_id)`.
pub fn voting_coin_hint(
    election_launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
    voter_pubkey: &PublicKey,
    ballot_launcher_id: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(VOTING_COIN_HINT_DOMAIN_V1);
    h.update(election_launcher_id.as_ref());
    h.update(cat_tail_hash.as_ref());
    h.update(voter_pubkey.to_bytes());
    h.update(ballot_launcher_id.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: empty_ballot_root
/// WHAT: SPT root over a depth-32 tree where every leaf is
///       `EMPTY_BALLOT_LEAF_HASH` (32 bytes of 0x00). This is the
///       genesis value of `RegistrationState.voted_ballots_root` for
///       a freshly-registered voter.
/// IMPL: lazily folds `node = hash_pair(node, node)` 32 times starting
///       from the empty-leaf hash. Cached via `OnceLock` so the
///       computation runs at most once per process.
/// MIRROR: `EMPTY_BALLOT_ROOT` curried into `puzzles/election/register.rue`.
pub fn empty_ballot_root() -> Bytes32 {
    static CACHED: OnceLock<Bytes32> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let mut node = EMPTY_BALLOT_LEAF_HASH;
        for _ in 0..BALLOT_TREE_DEPTH {
            node = hash_pair(node, node);
        }
        node
    })
}

/// FN: fresh_registration_state_tree_hash
/// WHAT: tree hash of a `RegistrationState` value with the given
///       fields. Field order mirrors the Rue struct in
///       `puzzles/registration_coin/shared.rue`:
///       `(voter_pubkey, election_launcher_id, voted_ballots_root,
///         ...release_destination)` — the last field uses the rest-arg
///       `...` prefix so the cons chain terminates AT it (no trailing
///       nil pair).
/// USAGE: callers minting a fresh registration coin pass
///        `voted_ballots_root = empty_ballot_root()` and
///        `release_destination = None`. Callers predicting a coin
///        post-release pass `Some(destination)`.
pub fn fresh_registration_state_tree_hash(
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
    voted_ballots_root: Bytes32,
    release_destination: Option<Bytes32>,
) -> Bytes32 {
    let pk_hash = hash_atom(&voter_pubkey.to_bytes());
    let el_hash = hash_atom_b32(&election_launcher_id);
    let vbr_hash = hash_atom_b32(&voted_ballots_root);
    let rd_hash = match release_destination {
        Some(dest) => hash_atom_b32(&dest),
        None => hash_atom(&[]), // None → nil → empty atom
    };

    // Rest-arg shape — last field is paired directly:
    //   (pk . (el . (vbr . rd)))
    let pair = hash_pair(vbr_hash, rd_hash);
    let pair = hash_pair(el_hash, pair);
    hash_pair(pk_hash, pair)
}

/// FN: fresh_registration_inner_hash
/// WHAT: action-layer inner puzzle hash for a Registration Coin (the
///       puzzle hash *inside* the CAT outer wrap). Builds the genesis
///       state with `voted_ballots_root = empty_ballot_root()` and
///       `release_destination = None`.
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
    let initial_state_hash = fresh_registration_state_tree_hash(
        voter_pubkey,
        election_launcher_id,
        empty_ballot_root(),
        None,
    );

    // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT)
    let finalizer_first = curry_tree_hash(
        registration_finalizer_mod_hash,
        &[hash_atom_b32(&action_layer_mod_hash), hash_atom_b32(&hint)],
    );
    // Finalizer 2nd curry: bind self-hash (CHIP-0050 finalizer pattern).
    // `finalizer_first` is the *atom* the puzzle curries in (the hash
    // value, not the program), so wrap it with `hash_atom_b32`.
    let finalizer_full = curry_tree_hash(finalizer_first, &[hash_atom_b32(&finalizer_first)]);

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
///       the puzzle hash that appears on-chain at registration time.
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

// ── Action-layer Merkle roots ─────────────────────────────────────────
//
// Every action layer is curried with a Merkle root over the tree-hashes
// of its allowed actions (after each action has been curried with its
// deployment-wide constants). The action-layer puzzle then asserts the
// selected action's hash is in that tree before delegating to it.
//
// Leaf order convention: ascending by `hash_atom_b32(action_hash)` —
// the same wrapping `chia_sdk_types::MerkleTree::new` applies internally
// (sha256(0x01 || leaf_bytes)) — so the manual arithmetic here stays
// byte-for-byte equivalent to that helper.

/// FN: registration_actions_merkle_root
/// WHAT: 2-leaf Merkle root over the Registration Coin's allowed
///       actions: `mint_voting_coin` and `release`.
/// WHY: the action layer asserts every selected action's puzzle hash
///      is in this tree. Both actions read voter info from state (not
///      curry), so their puzzle hashes are deployment-wide constants
///      and this root is constant too — computable offline.
/// LEAF ORDER: sorted ascending by `hash_atom_b32(leaf)` so the root
///             matches what `chia_sdk_types::MerkleTree::new` produces.
pub fn registration_actions_merkle_root() -> Bytes32 {
    let mint_voting_coin = hash_atom_b32(&PuzzleHashes::registration_mint_voting_coin());
    let release = hash_atom_b32(&PuzzleHashes::registration_release());
    let (a, b) = if mint_voting_coin.as_ref() < release.as_ref() {
        (mint_voting_coin, release)
    } else {
        (release, mint_voting_coin)
    };
    hash_pair(a, b)
}

/// FN: registration_action_root_leaves
/// WHAT: leaf SET (sorted) for the Registration Coin's actions
///       Merkle tree. Pass directly to
///       `chia_sdk_types::MerkleTree::new(&leaves)` to construct a
///       tree whose root matches `registration_actions_merkle_root`
///       and whose `.proof(leaf)` returns the proof selectors that
///       the on-chain `simplify_merkle_proof` accepts.
/// SORT: by `tree_hash_atom(puzzle_hash)` ascending — same ordering
///       `registration_actions_merkle_root` uses internally.
pub fn registration_action_root_leaves() -> Vec<Bytes32> {
    let mint_voting_coin_ph = PuzzleHashes::registration_mint_voting_coin();
    let release_ph = PuzzleHashes::registration_release();
    let mint_h = hash_atom_b32(&mint_voting_coin_ph);
    let release_h = hash_atom_b32(&release_ph);
    if mint_h.as_ref() < release_h.as_ref() {
        vec![mint_voting_coin_ph, release_ph]
    } else {
        vec![release_ph, mint_voting_coin_ph]
    }
}

/// FN: election_actions_merkle_root
/// WHAT: 3-leaf Merkle root over the Election Singleton's allowed
///       actions: `register`, `create_ballot`, `deregister`. Each is
///       already curried with election-wide constants by the caller
///       (TREE_DEPTH, EMPTY_LEAF_HASH, CAT_TAIL_HASH, COLLATERAL_AMOUNT,
///       EMPTY_BALLOT_ROOT, etc.).
/// LEAF ORDER: sorted ascending — caller doesn't need to maintain a
///             specific declaration order.
/// SHAPE: with 3 leaves the upstream
///        `chia_sdk_types::MerkleTree::list_to_binary_tree` splits
///        at midpoint = `(3+1) >> 1 = 2`, producing an unbalanced
///        binary tree
///          root = sha256(0x02 ||
///                        sha256(0x02 || L0 || L1) ||
///                        L2)
///        which is exactly `hash_pair(hash_pair(L0,L1), L2)`. Pinned
///        by `election_actions_merkle_root_matches_merkletree`.
pub fn election_actions_merkle_root(
    register_full_hash: Bytes32,
    create_ballot_full_hash: Bytes32,
    deregister_full_hash: Bytes32,
) -> Bytes32 {
    let mut leaves = [
        hash_atom_b32(&register_full_hash),
        hash_atom_b32(&create_ballot_full_hash),
        hash_atom_b32(&deregister_full_hash),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    hash_pair(pair01, leaves[2])
}

/// FN: ballot_actions_merkle_root
/// WHAT: 3-leaf Merkle root over the Ballot Coin's allowed actions:
///       `finalize`, `oracle`, `announce_finalization`.
/// WHY: all three Ballot Coin actions read state (not curry) for their
///      per-ballot args, so their puzzle hashes are deployment-wide
///      constants and this root is constant too.
/// LEAF ORDER: sorted ascending — same convention as the other action
///             roots.
pub fn ballot_actions_merkle_root() -> Bytes32 {
    let mut leaves = [
        hash_atom_b32(&PuzzleHashes::ballot_coin_finalize()),
        hash_atom_b32(&PuzzleHashes::ballot_coin_oracle()),
        hash_atom_b32(&PuzzleHashes::ballot_coin_announce_finalization()),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    hash_pair(pair01, leaves[2])
}

/// FN: ballot_action_root_leaves
/// WHAT: leaf SET (sorted) for the Ballot Coin's actions Merkle tree.
///       Pass to `chia_sdk_types::MerkleTree::new(&leaves)` to construct
///       a tree whose root matches `ballot_actions_merkle_root`.
pub fn ballot_action_root_leaves() -> Vec<Bytes32> {
    let mut leaves = vec![
        PuzzleHashes::ballot_coin_finalize(),
        PuzzleHashes::ballot_coin_oracle(),
        PuzzleHashes::ballot_coin_announce_finalization(),
    ];
    leaves.sort_by(|a, b| hash_atom_b32(a).as_ref().cmp(hash_atom_b32(b).as_ref()));
    leaves
}

/// FN: voting_coin_actions_merkle_root
/// WHAT: 1-leaf Merkle root over the Voting Coin's allowed actions —
///       currently only `update_vote`. The per-ballot consume-side
///       (the actual vote) happens via the Registration Coin's
///       `mint_voting_coin` action and the Ballot Coin's `finalize`
///       action; the Voting Coin itself only carries the signed
///       `vote_message` and supports edits via `update_vote`.
/// SHAPE: with a single leaf, the Merkle root is
///        `hash_atom_b32(update_vote_hash)` — i.e. the sha256(0x01 ||
///        update_vote_hash) wrapping that the upstream
///        `chia_sdk_types::MerkleTree::new` applies to a singleton
///        leaf list.
pub fn voting_coin_actions_merkle_root() -> Bytes32 {
    hash_atom_b32(&PuzzleHashes::voting_coin_update_vote())
}

/// FN: voting_coin_action_root_leaves
/// WHAT: leaf SET (single leaf) for the Voting Coin's actions Merkle
///       tree. Pass to `chia_sdk_types::MerkleTree::new(&leaves)`.
pub fn voting_coin_action_root_leaves() -> Vec<Bytes32> {
    vec![PuzzleHashes::voting_coin_update_vote()]
}

// ── Announcement-message helpers ──────────────────────────────────────
//
// These mirror the byte-form of the `CreateCoinAnnouncement` messages
// emitted by the new puzzles. Centralising them lets external
// consumers — both inside this SDK (actor drivers + aggregator) and
// downstream puzzles that want to assert against these announcements —
// recompute the exact preimage without re-running the CLVM puzzle.

/// FN: deregister_announcement_msg
/// WHAT: byte-form of the message emitted by
///       `puzzles/election/deregister.rue`'s `announce_deregister`
///       condition.
/// FORMULA: `sha256("deregister" || voter_pubkey)`
/// MIRROR: `puzzles/election/shared.rue::deregister_announcement_msg`
///         and inlined in `puzzles/registration_coin/release.rue`.
pub fn deregister_announcement_msg(voter_pubkey: &PublicKey) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"deregister");
    h.update(voter_pubkey.to_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: ballot_oracle_open_msg
/// WHAT: byte-form of the open-variant message emitted by
///       `puzzles/ballot_coin/oracle.rue` when `State.finalized == false`.
/// FORMULA: `sha256("ballot_oracle_open" ||
///                  ballot_launcher_id ||
///                  vote_close_height_be8)`.
/// USAGE: Voting Coin's `update_vote` action asserts a
///        `CoinAnnouncement` with this preimage to pin the Ballot
///        Coin's actual curried close height (defends against a
///        malicious mint having lied about close height).
pub fn ballot_oracle_open_msg(ballot_launcher_id: Bytes32, vote_close_height: u64) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"ballot_oracle_open");
    h.update(ballot_launcher_id.as_ref());
    h.update(vote_close_height.to_be_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: ballot_oracle_closed_msg
/// WHAT: byte-form of the closed-variant message emitted by
///       `puzzles/ballot_coin/oracle.rue` when `State.finalized == true`.
/// FORMULA: `sha256("ballot_oracle_closed" ||
///                  ballot_launcher_id ||
///                  vote_close_height_be8 ||
///                  vote_outcome ||
///                  agg_signers_commitment)`.
/// PREFIX SAFETY: distinct ASCII prefix from `ballot_oracle_open_msg`
///                guarantees external puzzles can pattern-match on
///                the variant via the preimage prefix bytes; the
///                resulting sha256 outputs are byte-distinct.
pub fn ballot_oracle_closed_msg(
    ballot_launcher_id: Bytes32,
    vote_close_height: u64,
    vote_outcome: Bytes32,
    agg_signers_commitment: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"ballot_oracle_closed");
    h.update(ballot_launcher_id.as_ref());
    h.update(vote_close_height.to_be_bytes());
    h.update(vote_outcome.as_ref());
    h.update(agg_signers_commitment.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: ballot_finalization_msg
/// WHAT: byte-form of the message emitted by
///       `puzzles/ballot_coin/announce_finalization.rue` (and by the
///       finalize action upon transitioning state).
/// FORMULA: `sha256("ballot_finalized" ||
///                  ballot_launcher_id ||
///                  vote_outcome ||
///                  agg_signers_commitment)`.
/// MIRROR: `puzzles/ballot_coin/shared.rue::ballot_finalization_msg`.
pub fn ballot_finalization_msg(
    ballot_launcher_id: Bytes32,
    vote_outcome: Bytes32,
    agg_signers_commitment: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"ballot_finalized");
    h.update(ballot_launcher_id.as_ref());
    h.update(vote_outcome.as_ref());
    h.update(agg_signers_commitment.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: vote_message
/// WHAT: CHIP rev 2026-05-02 canonical preimage for the voter's
///       AggSig over their ballot vote.
/// FORMULA: `sha256(vote_outcome || ballot_launcher_id ||
///                  election_launcher_id)`.
/// WHY: binding all three ids into a single domain-separated digest
///      means the same outcome bytes against a different ballot or
///      election produces a different message — a signature from one
///      ballot can't be replayed onto another.
/// MIRROR: `puzzles/voting_coin/shared.rue::vote_message`.
pub fn vote_message(
    vote_outcome: Bytes32,
    ballot_launcher_id: Bytes32,
    election_launcher_id: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(vote_outcome.as_ref());
    h.update(ballot_launcher_id.as_ref());
    h.update(election_launcher_id.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

// ── Voting Coin / Ballot Coin puzzle-hash predictors ──────────────────

/// FN: voting_coin_state_tree_hash
/// WHAT: tree hash of a `VotingCoinState`.
/// SHAPE: mirrors the Rue struct field order
///        `(voter_pubkey, ballot_launcher_id, vote_data,
///          ...registration_coin_id)` — last field is rest-arg.
pub fn voting_coin_state_tree_hash(
    voter_pubkey: &PublicKey,
    ballot_launcher_id: Bytes32,
    vote_data: Bytes32,
    registration_coin_id: Bytes32,
) -> Bytes32 {
    let pk_hash = hash_atom(&voter_pubkey.to_bytes());
    let bli_hash = hash_atom_b32(&ballot_launcher_id);
    let vd_hash = hash_atom_b32(&vote_data);
    let rci_hash = hash_atom_b32(&registration_coin_id);

    // Rest-arg shape: (pk . (bli . (vd . rci)))
    let pair = hash_pair(vd_hash, rci_hash);
    let pair = hash_pair(bli_hash, pair);
    hash_pair(pk_hash, pair)
}

/// FN: voting_coin_inner_hash
/// WHAT: action-layer inner puzzle hash for a Voting Coin (inside the
///       CAT outer wrap), given the curried constants of the
///       deployment.
fn voting_coin_inner_hash(
    action_layer_mod_hash: Bytes32,
    voting_coin_finalizer_mod_hash: Bytes32,
    voting_coin_actions_merkle_root_v: Bytes32,
    hint: Bytes32,
    initial_state_hash: Bytes32,
) -> Bytes32 {
    // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT)
    let finalizer_first = curry_tree_hash(
        voting_coin_finalizer_mod_hash,
        &[hash_atom_b32(&action_layer_mod_hash), hash_atom_b32(&hint)],
    );
    // Finalizer 2nd curry: bind self-hash (CHIP-0050 finalizer pattern).
    let finalizer_full = curry_tree_hash(finalizer_first, &[hash_atom_b32(&finalizer_first)]);

    // Action layer curry: (FINALIZER, MERKLE_ROOT, STATE)
    curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            hash_atom_b32(&voting_coin_actions_merkle_root_v),
            initial_state_hash,
        ],
    )
}

/// FN: voting_coin_puzzle_hash
/// WHAT: full CAT-wrapped Voting Coin puzzle hash — the puzzle hash
///       that appears on-chain when a voter mints a Voting Coin via
///       `mint_voting_coin`.
/// USAGE: indexers / aggregators predict where a voter's Voting Coin
///        for a given ballot will land before observing the spend.
/// MIRROR: `puzzles/registration_coin/mint_voting_coin.rue` —
///         `voting_coin_full_hash` (CAT-wrapped action layer over
///         `VotingCoinState`).
#[allow(clippy::too_many_arguments)]
pub fn voting_coin_puzzle_hash(
    cat_mod_hash: Bytes32,
    cat_tail_hash: Bytes32,
    action_layer_mod_hash: Bytes32,
    voting_coin_finalizer_mod_hash: Bytes32,
    voting_coin_actions_merkle_root_v: Bytes32,
    voter_pubkey: &PublicKey,
    ballot_launcher_id: Bytes32,
    election_launcher_id: Bytes32,
    vote_data: Bytes32,
    registration_coin_id: Bytes32,
) -> Bytes32 {
    let hint = voting_coin_hint(
        election_launcher_id,
        cat_tail_hash,
        voter_pubkey,
        ballot_launcher_id,
    );
    let initial_state_hash = voting_coin_state_tree_hash(
        voter_pubkey,
        ballot_launcher_id,
        vote_data,
        registration_coin_id,
    );
    let inner_hash = voting_coin_inner_hash(
        action_layer_mod_hash,
        voting_coin_finalizer_mod_hash,
        voting_coin_actions_merkle_root_v,
        hint,
        initial_state_hash,
    );

    // CAT outer wrap: curry(CAT_MOD_HASH, [CAT_MOD_HASH, CAT_TAIL_HASH, INNER]).
    // Mirrors the `voting_coin_full_hash` computation in
    // `mint_voting_coin.rue` byte-for-byte. We use the manual curry
    // here (rather than `CatArgs::curry_tree_hash`) so the caller's
    // own `cat_mod_hash` is honored — Rue puzzles curry it explicitly
    // rather than baking the upstream constant in.
    curry_tree_hash(
        cat_mod_hash,
        &[
            hash_atom_b32(&cat_mod_hash),
            hash_atom_b32(&cat_tail_hash),
            inner_hash,
        ],
    )
}

/// FN: ballot_coin_state_tree_hash
/// WHAT: tree hash of a `BallotState`.
/// SHAPE: mirrors the Rue struct field order
///        `(finalized, vote_outcome, ...agg_signers)` — last field is
///        rest-arg.
pub fn ballot_coin_state_tree_hash(
    finalized: bool,
    vote_outcome: Bytes32,
    agg_signers: Bytes32,
) -> Bytes32 {
    // Bool false → nil → empty atom; Bool true → 0x01 single-byte atom.
    // Rue compiles `Bool` to a 1-byte truthy atom or nil; the conventional
    // CLVM encoding is `()` for false and `1` (== `0x01`) for true.
    let fin_hash = if finalized {
        hash_atom(&[0x01])
    } else {
        hash_atom(&[])
    };
    let vo_hash = hash_atom_b32(&vote_outcome);
    let agg_hash = hash_atom_b32(&agg_signers);

    // Rest-arg shape: (fin . (vo . agg))
    let pair = hash_pair(vo_hash, agg_hash);
    hash_pair(fin_hash, pair)
}

/// FN: ballot_coin_inner_hash
/// WHAT: action-layer inner puzzle hash for a Ballot Coin (inside the
///       singleton outer wrap).
#[allow(clippy::too_many_arguments)]
fn ballot_coin_inner_hash(
    action_layer_mod_hash: Bytes32,
    ballot_finalizer_mod_hash: Bytes32,
    ballot_actions_merkle_root_v: Bytes32,
    ballot_launcher_id: Bytes32,
    initial_state_hash: Bytes32,
) -> Bytes32 {
    // The Ballot Coin's finalizer uses the CHIP-0050 self-hash
    // pattern with HINT = ballot_launcher_id (so memos written by
    // recreations are stable and indexable per-ballot).
    let finalizer_first = curry_tree_hash(
        ballot_finalizer_mod_hash,
        &[
            hash_atom_b32(&action_layer_mod_hash),
            hash_atom_b32(&ballot_launcher_id),
        ],
    );
    let finalizer_full = curry_tree_hash(finalizer_first, &[hash_atom_b32(&finalizer_first)]);

    curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            hash_atom_b32(&ballot_actions_merkle_root_v),
            initial_state_hash,
        ],
    )
}

/// FN: ballot_coin_puzzle_hash
/// WHAT: full singleton-wrapped Ballot Coin puzzle hash — the puzzle
///       hash that appears on-chain after `create_ballot` mints the
///       eve coin and the singleton's launch-handoff completes.
/// USAGE: indexers and the aggregator query this to find the
///        per-ballot coin and its current state.
/// CURRY MODEL: the Ballot Coin's per-ballot configuration
///        (vote_close_height, outcome_domain_hash, VK/IC, threshold,
///        snapshot of the registration root + weight) is curried
///        directly into the `finalize` action's puzzle hash — see
///        `puzzles/election/create_ballot.rue` for the construction.
///        That fully-curried `finalize` hash becomes one of the leaves
///        of `ballot_actions_merkle_root_v`, which the caller passes
///        in. Other ballot actions (`oracle`, `announce_finalization`)
///        also need their per-ballot args curried before the leaf is
///        computed; the caller is responsible for assembling those
///        leaves and passing the resulting root.
///
/// INPUTS:
///   * `singleton_mod_hash`              — the singleton outer mod hash
///                                         the deployment uses (typically
///                                         `chia_puzzles::SINGLETON_TOP_LAYER_V1_1_HASH`).
///   * `ballot_launcher_id`              — eve coin id of the new ballot
///                                         singleton (computed in
///                                         `create_ballot.rue`).
///   * `ballot_actions_merkle_root_v`    — Merkle root over the per-ballot
///                                         curried action hashes (see
///                                         `ballot_actions_merkle_root` for
///                                         the deployment-wide variant; the
///                                         per-ballot variant requires the
///                                         caller to curry `vote_close_height`
///                                         + outcome domain into each leaf
///                                         before hashing).
///   * `ballot_finalizer_mod_hash`       — `BALLOT_COIN_FINALIZER_HASH_HEX`
///                                         decoded.
///   * `action_layer_mod_hash`           — `ACTION_LAYER_HASH_HEX` decoded.
///
/// The remaining inputs (`vote_close_height`, `outcome_domain_hash`,
/// `vk_hash`, `ic_hash`, `vote_threshold_*`, `registration_*_snapshot`,
/// `election_launcher_id`) are accepted for future extension and to
/// keep the public signature stable as the action-leaf composition
/// firms up; the current implementation does not consume them at the
/// inner-hash level (they are absorbed by the per-leaf currying the
/// caller does upstream of `ballot_actions_merkle_root_v`).
#[allow(clippy::too_many_arguments)]
pub fn ballot_coin_puzzle_hash(
    singleton_mod_hash: Bytes32,
    ballot_launcher_id: Bytes32,
    election_launcher_id: Bytes32,
    vote_close_height: u64,
    outcome_domain_hash: Bytes32,
    vk_hash: Bytes32,
    ic_hash: Bytes32,
    vote_threshold_num: u64,
    vote_threshold_den: u64,
    registration_merkle_root_snapshot: Bytes32,
    registration_vote_weight_snapshot: u64,
    ballot_actions_merkle_root_v: Bytes32,
    ballot_finalizer_mod_hash: Bytes32,
    action_layer_mod_hash: Bytes32,
) -> Bytes32 {
    // The per-ballot args appear in the curried `finalize` action's
    // puzzle hash (which is one of the leaves of
    // `ballot_actions_merkle_root_v`) rather than at the inner-action-layer
    // level. We therefore only need the ballot's launcher id (for the
    // finalizer HINT) and the merkle root + initial state at this point.
    let _ = (
        election_launcher_id,
        vote_close_height,
        outcome_domain_hash,
        vk_hash,
        ic_hash,
        vote_threshold_num,
        vote_threshold_den,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
    );

    // Genesis BallotState: finalized=false, vote_outcome=0, agg_signers=0.
    let initial_state_hash =
        ballot_coin_state_tree_hash(false, Bytes32::default(), Bytes32::default());

    let inner_hash = ballot_coin_inner_hash(
        action_layer_mod_hash,
        ballot_finalizer_mod_hash,
        ballot_actions_merkle_root_v,
        ballot_launcher_id,
        initial_state_hash,
    );

    // Singleton outer wrap: we delegate to the upstream
    // `SingletonArgs::curry_tree_hash` so the singleton-mod-hash
    // consumption is identical to every other singleton in Chia. If
    // the caller provided a non-standard `singleton_mod_hash` we can't
    // honor that through the upstream helper — but the standard CHIP
    // deployment uses the canonical singleton, so this is fine.
    let _ = singleton_mod_hash; // documented pass-through; kept for API stability
    let inner_th = TreeHash::new(inner_hash.to_bytes());
    let curried = SingletonArgs::curry_tree_hash(ballot_launcher_id, inner_th);
    Bytes32::new(curried.to_bytes())
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
//   * `voter_hint` / `voting_coin_hint` are tested against hand-computed sha256.
//   * Merkle-root helpers are tested for canonical leaf ordering.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey};
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

    fn b32(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

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
        let _ = PuzzleHashes::election_create_ballot();
        let _ = PuzzleHashes::election_deregister();
        let _ = PuzzleHashes::ballot_coin_finalizer();
        let _ = PuzzleHashes::ballot_coin_finalize();
        let _ = PuzzleHashes::ballot_coin_oracle();
        let _ = PuzzleHashes::ballot_coin_announce_finalization();
        let _ = PuzzleHashes::registration_finalizer();
        let _ = PuzzleHashes::registration_mint_voting_coin();
        let _ = PuzzleHashes::registration_release();
        let _ = PuzzleHashes::voting_coin_finalizer();
        let _ = PuzzleHashes::voting_coin_update_vote();
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
    #[test]
    fn hash_pair_matches_upstream() {
        let l = b32(1);
        let r = b32(2);
        let lt = TreeHash::new(l.to_bytes());
        let rt = TreeHash::new(r.to_bytes());
        assert_eq!(
            hash_pair(l, r),
            Bytes32::new(tree_hash_pair(lt, rt).to_bytes())
        );
    }

    /// WHAT: our `curry_tree_hash` matches the upstream
    ///       `clvm_utils::curry_tree_hash` standalone helper AND
    ///       the actual tree hash of a materialised
    ///       `CurriedProgram` CLVM tree.
    #[test]
    fn curry_tree_hash_matches_upstream() {
        use clvm_traits::clvm_curried_args;
        use clvmr::Allocator;

        let mod_atom = b32(0x42);
        let arg_atom = b32(0x99);
        let mod_hash = hash_atom_b32(&mod_atom);
        let arg_hash = hash_atom_b32(&arg_atom);

        let ours = curry_tree_hash(mod_hash, &[arg_hash]);

        let mod_th = TreeHash::new(mod_hash.to_bytes());
        let arg_th = TreeHash::new(arg_hash.to_bytes());
        let upstream = clvm_utils::curry_tree_hash(mod_th, &[arg_th]);
        assert_eq!(ours, Bytes32::new(upstream.to_bytes()));

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

    /// WHAT: `voter_hint` matches the v1 preimage byte-exact.
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

    /// WHAT: `voting_coin_hint` matches the v1 preimage byte-exact —
    ///       the same shape as `voter_hint` but extended with the
    ///       per-ballot launcher id suffix.
    #[test]
    fn voting_coin_hint_is_sha256_of_concatenation() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail = b32(0xAA);
        let ballot_id = b32(0xBB);

        let mut expected = Sha256::new();
        expected.update(VOTING_COIN_HINT_DOMAIN_V1);
        expected.update(election_id.as_ref());
        expected.update(tail.as_ref());
        expected.update(pk.to_bytes());
        expected.update(ballot_id.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&expected.finalize());

        assert_eq!(
            voting_coin_hint(election_id, tail, &pk, ballot_id),
            Bytes32::new(arr),
        );
    }

    /// WHAT: `voting_coin_hint` differs per-ballot for the same voter.
    #[test]
    fn voting_coin_hint_differs_per_ballot() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail = b32(0xAA);
        assert_ne!(
            voting_coin_hint(election_id, tail, &pk, b32(0xB1)),
            voting_coin_hint(election_id, tail, &pk, b32(0xB2)),
        );
    }

    /// WHAT: `voter_hint` is deterministic.
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

    /// WHAT: voter hint differs across elections.
    #[test]
    fn voter_hint_differs_per_election() {
        let pk = test_pubkey();
        let tail = b32(0xAA);
        assert_ne!(
            voter_hint(b32(0x11), tail, &pk),
            voter_hint(b32(0x22), tail, &pk),
        );
    }

    /// WHAT: voter hint differs across CAT tails.
    #[test]
    fn voter_hint_differs_per_cat_tail() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        assert_ne!(
            voter_hint(election_id, b32(0xAA), &pk),
            voter_hint(election_id, b32(0xBB), &pk),
        );
    }

    /// WHAT: `empty_ballot_root()` is deterministic and matches the
    ///       depth-32 fold of `EMPTY_BALLOT_LEAF_HASH`.
    /// HOW:  recompute via inline iteration; assert equality.
    /// WHY:  the value is curried into every `register` action and
    ///       initialises every voter's `voted_ballots_root`. Drift
    ///       would break voter↔singleton handshake at registration.
    #[test]
    fn empty_ballot_root_is_depth_32_fold_of_zero_leaf() {
        let mut node = EMPTY_BALLOT_LEAF_HASH;
        for _ in 0..BALLOT_TREE_DEPTH {
            node = hash_pair(node, node);
        }
        assert_eq!(empty_ballot_root(), node);
        // Idempotent across calls (cache works).
        assert_eq!(empty_ballot_root(), empty_ballot_root());
    }

    /// WHAT: `registration_actions_merkle_root()` is deterministic.
    #[test]
    fn registration_actions_merkle_root_is_sorted_canonical() {
        let r1 = registration_actions_merkle_root();
        let r2 = registration_actions_merkle_root();
        assert_eq!(r1, r2);
    }

    /// WHAT: registration leaf set agrees with
    ///       `chia_sdk_types::MerkleTree::new` on the SORTED leaves.
    #[test]
    fn registration_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let leaves = registration_action_root_leaves();
        let upstream_root = MerkleTree::new(&leaves).root();
        assert_eq!(registration_actions_merkle_root(), upstream_root);
    }

    /// WHAT: `election_actions_merkle_root` is permutation-invariant.
    #[test]
    fn election_actions_merkle_root_is_order_independent() {
        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);

        let r1 = election_actions_merkle_root(a, b, c);
        let r2 = election_actions_merkle_root(b, a, c);
        let r3 = election_actions_merkle_root(c, b, a);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    /// WHAT: hand-rolled `election_actions_merkle_root` agrees byte-
    ///       for-byte with `chia_sdk_types::MerkleTree::new` on the
    ///       SORTED leaf set (3-leaf shape: pair01 + L2).
    #[test]
    fn election_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);

        let mut leaves = vec![a, b, c];
        leaves.sort_by(|x, y| hash_atom_b32(x).as_ref().cmp(hash_atom_b32(y).as_ref()));
        let upstream_root = MerkleTree::new(&leaves).root();

        let our_root = election_actions_merkle_root(a, b, c);
        assert_eq!(our_root, upstream_root);
    }

    /// WHAT: ballot leaf set agrees with
    ///       `chia_sdk_types::MerkleTree::new` on the SORTED leaves.
    #[test]
    fn ballot_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let leaves = ballot_action_root_leaves();
        let upstream_root = MerkleTree::new(&leaves).root();
        assert_eq!(ballot_actions_merkle_root(), upstream_root);
    }

    /// WHAT: voting-coin merkle root with one leaf == sha256(0x01 || leaf).
    #[test]
    fn voting_coin_actions_merkle_root_is_single_leaf_wrap() {
        use chia_sdk_types::MerkleTree;

        let leaves = voting_coin_action_root_leaves();
        let upstream_root = MerkleTree::new(&leaves).root();
        assert_eq!(voting_coin_actions_merkle_root(), upstream_root);
    }

    /// WHAT: `fresh_registration_coin_puzzle_hash` equals the CAT
    ///       wrap of the inner hash.
    #[test]
    fn fresh_registration_coin_puzzle_hash_matches_catargs() {
        let pk = test_pubkey();
        let election_id = b32(0x11);
        let tail_hash = b32(0x22);

        let inner = fresh_registration_inner_hash(&pk, election_id, tail_hash);
        let inner_th = TreeHash::new(inner.to_bytes());
        let expected = Bytes32::new(CatArgs::curry_tree_hash(tail_hash, inner_th).to_bytes());

        assert_eq!(
            fresh_registration_coin_puzzle_hash(tail_hash, &pk, election_id),
            expected,
        );
    }

    /// WHAT: distinct voters produce distinct coin inner hashes.
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

    /// WHAT: same voter, different elections → different inner hash.
    #[test]
    fn fresh_registration_inner_hash_is_per_election() {
        let pk = test_pubkey();
        let tail = b32(0x22);
        assert_ne!(
            fresh_registration_inner_hash(&pk, b32(0x11), tail),
            fresh_registration_inner_hash(&pk, b32(0x22), tail),
        );
    }

    /// WHAT: `deregister_announcement_msg` byte-exact matches
    ///       `sha256("deregister" || pk_bytes)`.
    #[test]
    fn deregister_announcement_msg_is_canonical_sha256() {
        let pk = test_pubkey();
        let mut h = Sha256::new();
        h.update(b"deregister");
        h.update(pk.to_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        assert_eq!(deregister_announcement_msg(&pk), Bytes32::new(arr));
    }

    /// WHAT: `ballot_oracle_open_msg` byte-exact matches its preimage.
    #[test]
    fn ballot_oracle_open_msg_is_canonical_sha256() {
        let ballot_id = b32(0xBB);
        let close_h: u64 = 1_234_567;

        let mut h = Sha256::new();
        h.update(b"ballot_oracle_open");
        h.update(ballot_id.as_ref());
        h.update(close_h.to_be_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            ballot_oracle_open_msg(ballot_id, close_h),
            Bytes32::new(arr)
        );
    }

    /// WHAT: `ballot_oracle_closed_msg` byte-exact matches its preimage.
    #[test]
    fn ballot_oracle_closed_msg_is_canonical_sha256() {
        let ballot_id = b32(0xBB);
        let close_h: u64 = 1_234_567;
        let outcome = b32(0xCC);
        let agg = b32(0xDD);

        let mut h = Sha256::new();
        h.update(b"ballot_oracle_closed");
        h.update(ballot_id.as_ref());
        h.update(close_h.to_be_bytes());
        h.update(outcome.as_ref());
        h.update(agg.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            ballot_oracle_closed_msg(ballot_id, close_h, outcome, agg),
            Bytes32::new(arr),
        );
    }

    /// WHAT: open and closed oracle messages NEVER collide for the
    ///       same (ballot_id, close_height) — domain separation via
    ///       distinct ASCII prefix.
    #[test]
    fn ballot_oracle_open_and_closed_messages_diverge() {
        let ballot_id = b32(0xBB);
        let close_h: u64 = 99;
        let m_open = ballot_oracle_open_msg(ballot_id, close_h);
        let m_closed =
            ballot_oracle_closed_msg(ballot_id, close_h, Bytes32::default(), Bytes32::default());
        assert_ne!(
            m_open, m_closed,
            "ballot_oracle open vs closed messages must NEVER collide",
        );
    }

    /// WHAT: `ballot_finalization_msg` byte-exact matches its preimage.
    #[test]
    fn ballot_finalization_msg_is_canonical_sha256() {
        let ballot_id = b32(0xBB);
        let outcome = b32(0xCC);
        let agg = b32(0xDD);

        let mut h = Sha256::new();
        h.update(b"ballot_finalized");
        h.update(ballot_id.as_ref());
        h.update(outcome.as_ref());
        h.update(agg.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            ballot_finalization_msg(ballot_id, outcome, agg),
            Bytes32::new(arr),
        );
    }

    /// WHAT: `vote_message` byte-exact matches its 3-input concatenation.
    #[test]
    fn vote_message_is_canonical_sha256() {
        let outcome = b32(0xCC);
        let ballot_id = b32(0xBB);
        let election_id = b32(0xEE);

        let mut h = Sha256::new();
        h.update(outcome.as_ref());
        h.update(ballot_id.as_ref());
        h.update(election_id.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            vote_message(outcome, ballot_id, election_id),
            Bytes32::new(arr),
        );
    }

    /// WHAT: `election_singleton_puzzle_hash` matches `SingletonArgs`.
    #[test]
    fn election_singleton_puzzle_hash_matches_singletonargs() {
        let launcher_id = b32(0xAB);
        let inner_ph = b32(0xCD);
        let inner_th = TreeHash::new(inner_ph.to_bytes());
        let expected =
            Bytes32::new(SingletonArgs::curry_tree_hash(launcher_id, inner_th).to_bytes());
        assert_eq!(
            election_singleton_puzzle_hash(launcher_id, inner_ph),
            expected,
        );
    }
}
