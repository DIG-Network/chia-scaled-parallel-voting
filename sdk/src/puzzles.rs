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

/// SEC-F3+F5: Election Singleton `attest_ballot` action — a READ-ONLY action
/// (state unchanged) that emits a CHIP-0025 SEND_MESSAGE carrying the canonical
/// ballot-binding tuple from the election's unforgeable state, paired in-bundle
/// with the Ballot Coin's `finalize` RECEIVE_MESSAGE. Binds the ballot's curried
/// VK/snapshots/vote-options-root to the genuine election.
pub const ELECTION_ATTEST_BALLOT_HEX: &str =
    include_str!("../../puzzles/compiled/election/attest_ballot.rue.hex");
pub const ELECTION_ATTEST_BALLOT_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/election/attest_ballot.rue.hash");

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

// ── Ceremony Coin (per-contribution marker) ───────────────────────────

/// CeremonyCoin marker puzzle — a coin per Groth16 ceremony
/// contribution. Curry binds (CEREMONY_LAUNCHER_ID, PARTICIPANT_PK,
/// CONTRIBUTION_HASH, PREV_CONTRIBUTION_HASH); puzzle body returns
/// no conditions (pure marker, effectively unspendable but
/// chain-discoverable via hint=CEREMONY_LAUNCHER_ID).
pub const CEREMONY_COIN_MARKER_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_coin/marker.rue.hex");
pub const CEREMONY_COIN_MARKER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_coin/marker.rue.hash");

// ── Ceremony Singleton (multi-participant trusted setup) ──────────────

/// Ceremony Singleton custom finalizer — recreates the singleton at
/// amount=1 carrying the advanced CeremonyState (count+1,
/// last_contribution_hash <- new contribution hash).
pub const CEREMONY_SINGLETON_FINALIZER_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/finalizer.rue.hex");
pub const CEREMONY_SINGLETON_FINALIZER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/finalizer.rue.hash");

/// Ceremony Singleton `contribute` action — permissionless. Validates
/// height bounds, lineage (prev_contribution_hash matches singleton
/// state), and an UNAUGMENTED participant signature; emits a marker
/// CeremonyCoin (hinted with launcher) plus an announcement carrying
/// the contribution hash. Full PoK + parameters payload travels in
/// the spend's solution and is recovered off-chain by the dApp.
pub const CEREMONY_SINGLETON_CONTRIBUTE_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/contribute.rue.hex");
pub const CEREMONY_SINGLETON_CONTRIBUTE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/contribute.rue.hash");

/// `finalize` action puzzle (post-D3): sealed by anyone once the
/// window has closed and the threshold has been reached. Emits a
/// marker coin with vk_hash + marker_root + full vk_bytes in memos
/// and advances the singleton's curried state to `finalized=1`,
/// blocking further contribute spends.
pub const CEREMONY_SINGLETON_FINALIZE_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/finalize.rue.hex");
pub const CEREMONY_SINGLETON_FINALIZE_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/finalize.rue.hash");

/// Voucher coin spawned by the Ceremony Singleton's `finalize` action.
/// Anyone-can-spend, re-spendable indefinitely. Emits a canonical
/// CreateCoinAnnouncement(sha256("chip:ceremony:voucher" || vk_hash ||
/// max_voters_be8 || ceremony_launcher_id)) on every spend, plus a
/// CreateCoin recreating itself at the same puzzle hash. ElectionDeployer
/// co-spends one of these in the same SpendBundle as the launcher and
/// asserts the announcement to bind the deployed election to the
/// finalized ceremony.
pub const CEREMONY_VOUCHER_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/ceremony_voucher.rue.hex");
pub const CEREMONY_VOUCHER_HASH_HEX: &str =
    include_str!("../../puzzles/compiled/ceremony_singleton/ceremony_voucher.rue.hash");

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
    pub fn election_attest_ballot() -> Bytes32 {
        decode_hash(ELECTION_ATTEST_BALLOT_HASH_HEX)
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

    // Ceremony Coin (per-contribution marker)
    pub fn ceremony_coin_marker() -> Bytes32 {
        decode_hash(CEREMONY_COIN_MARKER_HASH_HEX)
    }

    // Ceremony Singleton (multi-participant trusted setup)
    pub fn ceremony_singleton_finalizer() -> Bytes32 {
        decode_hash(CEREMONY_SINGLETON_FINALIZER_HASH_HEX)
    }
    pub fn ceremony_singleton_contribute() -> Bytes32 {
        decode_hash(CEREMONY_SINGLETON_CONTRIBUTE_HASH_HEX)
    }
    pub fn ceremony_singleton_finalize() -> Bytes32 {
        decode_hash(CEREMONY_SINGLETON_FINALIZE_HASH_HEX)
    }
    pub fn ceremony_voucher() -> Bytes32 {
        decode_hash(CEREMONY_VOUCHER_HASH_HEX)
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
/// IMPL: lazily folds `node = sha256(node || node)` 32 times starting
///       from the empty-leaf hash. Cached via `OnceLock` so the
///       computation runs at most once per process.
/// HASH CONVENTION: PLAIN sha256, NOT the CLVM `tree_hash_pair`
///       (which prepends `0x02`). The on-chain
///       `puzzles/registration_coin/mint_voting_coin.rue`
///       `compute_ballot_root` uses raw `sha256(node_b + sibling_b)`
///       — same convention as the registration SPT in
///       `merkle.rs::sha256_concat`. An earlier draft of this helper
///       used `hash_pair` (the 0x02-prefixed variant), producing a
///       byte-distinct root that broke every mint_voting_coin spend
///       even though the SDK was internally self-consistent.
/// MIRROR: `EMPTY_BALLOT_ROOT` curried into `puzzles/election/register.rue`.
pub fn empty_ballot_root() -> Bytes32 {
    static CACHED: OnceLock<Bytes32> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let mut node = EMPTY_BALLOT_LEAF_HASH;
        for _ in 0..BALLOT_TREE_DEPTH {
            node = sha256_concat_b32(&node, &node);
        }
        node
    })
}

/// FN: sha256_concat_b32 (file-private)
/// WHAT: plain `sha256(a || b)` over two 32-byte inputs as a
///       `Bytes32`. Mirrors the on-chain `sha256(node_b + sibling_b)`
///       used by both the registration SPT (`merkle.rs`) and the
///       per-registration ballot SPT
///       (`registration_coin/mint_voting_coin.rue`).
fn sha256_concat_b32(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(a.as_ref());
    h.update(b.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: empty_ballot_membership_siblings
/// WHAT: 32-element sibling list for the EMPTY per-registration
///       ballot SPT. Suitable for `BallotMembership.siblings` in
///       `mint_voting_coin`'s solution when the voter has not yet
///       voted on any ballot (`voted_ballots_root` ==
///       `empty_ballot_root()`).
/// SHAPE: `siblings[i]` is the level-`i` sibling — at level 0 the
///        empty leaf, at higher levels the i-fold of
///        `sha256(prev || prev)`. The on-chain `compute_ballot_root`
///        with starting node `EMPTY_BALLOT_LEAF_HASH` and these
///        siblings produces `empty_ballot_root()` regardless of the
///        slot index (every level's sibling matches the node, so
///        the order swap the puzzle does on odd indices is a no-op).
pub fn empty_ballot_membership_siblings() -> Vec<Bytes32> {
    let mut out = Vec::with_capacity(BALLOT_TREE_DEPTH);
    let mut node = EMPTY_BALLOT_LEAF_HASH;
    for _ in 0..BALLOT_TREE_DEPTH {
        out.push(node);
        node = sha256_concat_b32(&node, &node);
    }
    out
}

/// FN: ballot_slot_from_id
/// WHAT: per-registration ballot SPT slot for `ballot_launcher_id`.
/// FORMULA: `u32::from_be_bytes(sha256(ballot_launcher_id)[0..4])`.
///       Mirrors `ballot_slot_from_id` in
///       `puzzles/registration_coin/mint_voting_coin.rue`. The puzzle
///       prefixes the 4 bytes with `0x00` to coerce signedness; in
///       Rust we just use `u32` directly (always non-negative).
pub fn ballot_slot_from_id(ballot_launcher_id: Bytes32) -> u32 {
    let mut h = Sha256::new();
    h.update(ballot_launcher_id.as_ref());
    let digest = h.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// FN: voted_ballots_root_after_inserts
/// WHAT: compute the per-registration ballot SPT root after inserting
///       each `ballot_launcher_id` at its `ballot_slot_from_id` slot,
///       starting from the all-empty (`empty_ballot_root()`) state.
/// USAGE: post-cast Registration Coin's `voted_ballots_root`. For an
///        empty input, returns `empty_ballot_root()`.
/// IMPL: builds a sparse map slot → leaf (where leaf for an inserted
///       ballot is `sha256(ballot_launcher_id)`, mirroring the
///       `occupied_leaf` line in `mint_voting_coin.rue`), then folds
///       up `BALLOT_TREE_DEPTH` levels using `sha256_concat_b32`. At
///       each level, missing nodes default to the level-`i` empty
///       node from `empty_ballot_membership_siblings()`.
pub fn voted_ballots_root_after_inserts(ballot_launcher_ids: &[Bytes32]) -> Bytes32 {
    if ballot_launcher_ids.is_empty() {
        return empty_ballot_root();
    }

    // Empty-node-per-level cache (level 0 = empty leaf, level i =
    // sha256(level i-1 || level i-1)). Used to fill missing siblings.
    let empty_per_level = empty_ballot_membership_siblings();

    // Sparse current-level map: slot → node hash. At level 0 keys are
    // ballot slots; values are the per-ballot leaf hashes.
    use std::collections::BTreeMap;
    let mut current: BTreeMap<u32, Bytes32> = BTreeMap::new();
    for ballot_launcher_id in ballot_launcher_ids {
        let slot = ballot_slot_from_id(*ballot_launcher_id);
        let leaf = {
            let mut h = Sha256::new();
            h.update(ballot_launcher_id.as_ref());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.finalize());
            Bytes32::new(arr)
        };
        current.insert(slot, leaf);
    }

    // Fold up the tree level-by-level. At each level the slot index
    // halves (right-shift) and pairs of siblings hash together. Bit
    // 0 of the OLD slot determines left/right ordering for the NEW
    // node; the puzzle does the same `index % 2 == 0 ?
    // sha256(node_b + sibling_b) : sha256(sibling_b + node_b)`.
    for level in 0..BALLOT_TREE_DEPTH {
        let mut next: BTreeMap<u32, Bytes32> = BTreeMap::new();
        let level_empty = empty_per_level[level];
        let mut iter = current.into_iter().peekable();
        while let Some((slot, node)) = iter.next() {
            let parent_slot = slot >> 1;
            let is_left = slot & 1 == 0;
            // Pair with sibling at `slot ^ 1` if present, else with
            // the level-`level` empty node.
            let sibling = if is_left
                && iter.peek().map(|(s, _)| *s == slot ^ 1).unwrap_or(false)
            {
                let (_, n) = iter.next().expect("peeked sibling");
                n
            } else {
                level_empty
            };
            let parent = if is_left {
                sha256_concat_b32(&node, &sibling)
            } else {
                sha256_concat_b32(&sibling, &node)
            };
            // Multiple inserts may collide at the parent slot
            // (different children on the same parent's two slots).
            // BTreeMap iteration is sorted, so this only happens
            // when two siblings both have explicit nodes — handled
            // by the peek+consume above. Subsequent inserts at the
            // same parent_slot would overwrite, which is incorrect
            // for the rare case where two different sub-paths reach
            // the same parent — guard against it explicitly.
            //
            // BUG-AVOIDANCE: this branch is unreachable for a single
            // insert pass when input slots are distinct (they
            // always are — each ballot has its own slot). For
            // multi-ballot input the peek+consume already handles
            // adjacent siblings.
            assert!(
                !next.contains_key(&parent_slot),
                "voted_ballots_root_after_inserts: duplicate parent slot {} at level {}",
                parent_slot,
                level,
            );
            next.insert(parent_slot, parent);
        }
        current = next;
    }

    // After folding `BALLOT_TREE_DEPTH` levels, exactly one node
    // remains at slot 0 — the SPT root.
    let (_slot, root) = current
        .into_iter()
        .next()
        .expect("voted_ballots_root_after_inserts: post-fold map must have exactly one entry");
    root
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
/// Tree hash of a `u64` as a canonical CLVM int atom (minimal big-endian,
/// sign-extended so the MSB stays clear) — matches how Rue hashes an `Int`
/// field. Used for `RegistrationState.locked_weight` (SEC-F2).
pub fn uint_atom_hash(n: u64) -> Bytes32 {
    if n == 0 {
        return hash_atom(&[]);
    }
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let mut payload = bytes[first..].to_vec();
    if !payload.is_empty() && payload[0] & 0x80 != 0 {
        payload.insert(0, 0);
    }
    hash_atom(&payload)
}

pub fn fresh_registration_state_tree_hash(
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
    voted_ballots_root: Bytes32,
    locked_weight: u64,
    release_destination: Option<Bytes32>,
) -> Bytes32 {
    let pk_hash = hash_atom(&voter_pubkey.to_bytes());
    let el_hash = hash_atom_b32(&election_launcher_id);
    let vbr_hash = hash_atom_b32(&voted_ballots_root);
    let lw_hash = uint_atom_hash(locked_weight);
    let rd_hash = match release_destination {
        Some(dest) => hash_atom_b32(&dest),
        None => hash_atom(&[]), // None → nil → empty atom
    };

    // SEC-F2 layout — `locked_weight` is a regular Int field BEFORE the
    // rest-arg `release_destination`:
    //   (pk . (el . (vbr . (locked_weight . rd))))
    let pair = hash_pair(lw_hash, rd_hash);
    let pair = hash_pair(vbr_hash, pair);
    let pair = hash_pair(el_hash, pair);
    hash_pair(pk_hash, pair)
}

/// FN: registration_inner_hash_for_state
/// WHAT: action-layer inner puzzle hash for a Registration Coin at an
///       ARBITRARY (`voted_ballots_root`, `release_destination`) state.
///       Generalises `fresh_registration_inner_hash` so callers can
///       predict the on-chain ph for a Registration Coin recreated
///       post-cast (with `voted_ballots_root` updated) or post-
///       release (with `release_destination = Some(_)`).
/// USAGE: `Voter::release_collateral` walks the registration coin's
///        CAT lineage to recover the post-cast `voted_ballots_root`
///        and predicts the on-chain ph via this helper.
pub fn registration_inner_hash_for_state(
    voter_pubkey: &PublicKey,
    election_launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
    voted_ballots_root: Bytes32,
    locked_weight: u64,
    release_destination: Option<Bytes32>,
) -> Bytes32 {
    let action_layer_mod_hash = PuzzleHashes::action_layer();
    let registration_finalizer_mod_hash = PuzzleHashes::registration_finalizer();
    let registration_merkle_root = registration_actions_merkle_root(cat_tail_hash);

    let hint = voter_hint(election_launcher_id, cat_tail_hash, voter_pubkey);
    let state_hash = fresh_registration_state_tree_hash(
        voter_pubkey,
        election_launcher_id,
        voted_ballots_root,
        locked_weight,
        release_destination,
    );

    // Finalizer 1st curry: (ACTION_LAYER_MOD_HASH, HINT)
    let finalizer_first = curry_tree_hash(
        registration_finalizer_mod_hash,
        &[hash_atom_b32(&action_layer_mod_hash), hash_atom_b32(&hint)],
    );
    // Finalizer 2nd curry: bind self-hash (CHIP-0050 finalizer pattern).
    let finalizer_full = curry_tree_hash(finalizer_first, &[hash_atom_b32(&finalizer_first)]);

    // Action layer curry: (FINALIZER, MERKLE_ROOT, STATE)
    curry_tree_hash(
        action_layer_mod_hash,
        &[
            finalizer_full,
            hash_atom_b32(&registration_merkle_root),
            state_hash,
        ],
    )
}

/// FN: cat_outer_for_inner_hash
/// WHAT: CAT-wrapped puzzle hash for an arbitrary inner puzzle hash —
///       the on-chain ph that appears for a CAT coin whose inner ph
///       is `inner_ph`. Mirrors the CAT outer's curry composition
///       (`CatArgs::curry_tree_hash`).
/// USAGE: paired with `registration_inner_hash_for_state` to predict
///        the post-cast Registration Coin's on-chain ph.
pub fn cat_outer_for_inner_hash(cat_tail_hash: Bytes32, inner_ph: Bytes32) -> Bytes32 {
    use chia_puzzle_types::cat::CatArgs;
    use clvm_utils::TreeHash;
    let inner_th = TreeHash::new(inner_ph.to_bytes());
    let curried = CatArgs::curry_tree_hash(cat_tail_hash, inner_th);
    Bytes32::new(curried.to_bytes())
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
    locked_weight: u64,
) -> Bytes32 {
    registration_inner_hash_for_state(
        voter_pubkey,
        election_launcher_id,
        cat_tail_hash,
        empty_ballot_root(),
        locked_weight,
        None,
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
    locked_weight: u64,
) -> Bytes32 {
    let inner =
        fresh_registration_inner_hash(voter_pubkey, election_launcher_id, cat_tail_hash, locked_weight);
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

/// FN: curried_mint_voting_coin_hash
/// WHAT: tree hash of the FULLY-CURRIED `mint_voting_coin` action
///       puzzle. The action's 5 curried params (per
///       `puzzles/registration_coin/mint_voting_coin.rue`) are all
///       deployment-wide constants — only `CAT_TAIL_HASH` varies per
///       election.
/// CURRY ORDER: `(CAT_MOD_HASH, CAT_TAIL_HASH, ACTION_LAYER_MOD_HASH,
///   VOTING_COIN_FINALIZER_MOD_HASH, VOTING_COIN_ACTIONS_MERKLE_ROOT)`.
/// USAGE: drives [`registration_actions_merkle_root`] (the action root
///   curried into the Registration Coin's action layer) and is what
///   the on-chain `action.rue` checks against via
///   `simplify_merkle_proof(tree_hash(curried_mint_voting_coin),
///   proof)`.
/// CHIP rev 2026-05-02 NOTE: this fix addresses a bug where the
/// previous implementation hashed the UNCURRIED `mint_voting_coin`,
/// breaking the on-chain merkle proof. The Voting Coin's
/// `update_vote` action no longer carries per-ballot curry args (per
/// the matching CHIP rev), so `VOTING_COIN_ACTIONS_MERKLE_ROOT` is
/// now genuinely deployment-wide and the curried mint hash is too.
pub fn curried_mint_voting_coin_hash(cat_tail_hash: Bytes32) -> Bytes32 {
    curry_tree_hash(
        PuzzleHashes::registration_mint_voting_coin(),
        &[
            hash_atom_b32(&PuzzleHashes::cat_outer()),
            hash_atom_b32(&cat_tail_hash),
            hash_atom_b32(&PuzzleHashes::action_layer()),
            hash_atom_b32(&PuzzleHashes::voting_coin_finalizer()),
            hash_atom_b32(&voting_coin_actions_merkle_root()),
        ],
    )
}

/// FN: registration_actions_merkle_root
/// WHAT: 2-leaf Merkle root over the Registration Coin's allowed
///       actions: `mint_voting_coin` (curried with deployment-wide
///       constants — see [`curried_mint_voting_coin_hash`]) and
///       `release` (no curry args).
/// WHY: the on-chain action layer (`puzzles/action.rue`) verifies
///      `simplify_merkle_proof(tree_hash(SELECTED_PUZZLE), proof) ==
///      MERKLE_ROOT`, where `tree_hash(SELECTED_PUZZLE)` is the
///      tree hash of the FULLY-CURRIED action puzzle. Leaves here
///      must therefore use curried hashes.
/// LEAF ORDER: sorted ascending by `hash_atom_b32(leaf)` so the root
///             matches what `chia_sdk_types::MerkleTree::new` produces.
pub fn registration_actions_merkle_root(cat_tail_hash: Bytes32) -> Bytes32 {
    let mint_voting_coin = hash_atom_b32(&curried_mint_voting_coin_hash(cat_tail_hash));
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
///       tree whose root matches
///       [`registration_actions_merkle_root`] and whose
///       `.proof(leaf)` returns the proof selectors that the on-chain
///       `simplify_merkle_proof` accepts.
/// SORT: by `tree_hash_atom(puzzle_hash)` ascending — same ordering
///       `registration_actions_merkle_root` uses internally.
pub fn registration_action_root_leaves(cat_tail_hash: Bytes32) -> Vec<Bytes32> {
    let mint_voting_coin_ph = curried_mint_voting_coin_hash(cat_tail_hash);
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
/// WHAT: 4-leaf Merkle root over the Election Singleton's allowed
///       actions: `register`, `create_ballot`, `deregister`, and
///       `attest_ballot` (SEC-F3+F5 — the read-only action that attests
///       the ballot-binding tuple). Each leaf is already curried with
///       election-wide constants by the caller.
/// LEAF ORDER: sorted ascending — caller doesn't need to maintain a
///             specific declaration order.
/// SHAPE: with 4 leaves the upstream
///        `chia_sdk_types::MerkleTree::list_to_binary_tree` splits at
///        midpoint = `(4+1) >> 1 = 2`, producing a BALANCED binary tree
///          root = sha256(0x02 ||
///                        sha256(0x02 || L0 || L1) ||
///                        sha256(0x02 || L2 || L3))
///        = `hash_pair(hash_pair(L0,L1), hash_pair(L2,L3))`. Pinned by
///        `election_actions_merkle_root_matches_merkletree`.
pub fn election_actions_merkle_root(
    register_full_hash: Bytes32,
    create_ballot_full_hash: Bytes32,
    deregister_full_hash: Bytes32,
    attest_ballot_full_hash: Bytes32,
) -> Bytes32 {
    let mut leaves = [
        hash_atom_b32(&register_full_hash),
        hash_atom_b32(&create_ballot_full_hash),
        hash_atom_b32(&deregister_full_hash),
        hash_atom_b32(&attest_ballot_full_hash),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    let pair23 = hash_pair(leaves[2], leaves[3]);
    hash_pair(pair01, pair23)
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

/// FN: per_ballot_actions_merkle_root
/// WHAT: 3-leaf Merkle root over a SPECIFIC Ballot Coin's
///       fully-curried action puzzle hashes (`finalize`, `oracle`,
///       `announce_finalization`). All three Ballot Coin actions
///       carry per-ballot curry args (vote_close_height,
///       outcome_domain_hash, BALLOT_LAUNCHER_ID, VK/IC, threshold,
///       registration snapshot), so each Ballot Coin has its own
///       merkle root. Caller pre-curries each action with its
///       per-ballot args and supplies the resulting `*_full_hash`es.
/// LEAF ORDER: sorted ascending by `hash_atom_b32(leaf)` — same
///             ordering [`ballot_actions_merkle_root`] uses.
pub fn per_ballot_actions_merkle_root(
    finalize_full_hash: Bytes32,
    oracle_full_hash: Bytes32,
    announce_finalization_full_hash: Bytes32,
) -> Bytes32 {
    let mut leaves = [
        hash_atom_b32(&finalize_full_hash),
        hash_atom_b32(&oracle_full_hash),
        hash_atom_b32(&announce_finalization_full_hash),
    ];
    leaves.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let pair01 = hash_pair(leaves[0], leaves[1]);
    hash_pair(pair01, leaves[2])
}

/// FN: per_ballot_action_root_leaves
/// WHAT: leaf SET (sorted) for a per-ballot actions Merkle tree.
///       Pass to `chia_sdk_types::MerkleTree::new(&leaves)` to
///       construct a tree whose root matches
///       [`per_ballot_actions_merkle_root`] and whose `.proof(leaf)`
///       returns the proof selectors the action layer accepts.
pub fn per_ballot_action_root_leaves(
    finalize_full_hash: Bytes32,
    oracle_full_hash: Bytes32,
    announce_finalization_full_hash: Bytes32,
) -> Vec<Bytes32> {
    let mut leaves = vec![
        finalize_full_hash,
        oracle_full_hash,
        announce_finalization_full_hash,
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
/// FORMULA (M4-revised, 3-field preimage): `sha256("ballot_oracle_open" ||
///                  ballot_launcher_id ||
///                  vote_close_height_be8 ||
///                  vote_options_root)`.
/// USAGE: Voting Coin's `update_vote` action asserts a
///        `CoinAnnouncement` with this preimage to pin the Ballot
///        Coin's actual curried close height + curried vote_options_root
///        (defends against a malicious mint having lied about either).
/// SENTINEL: pass `Bytes32::default()` (= 0x00…00) for `vote_options_root`
///        when the ballot is Mode1Free (no vote-mode lock).
pub fn ballot_oracle_open_msg(
    ballot_launcher_id: Bytes32,
    vote_close_height: u64,
    vote_options_root: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"ballot_oracle_open");
    h.update(ballot_launcher_id.as_ref());
    h.update(vote_close_height.to_be_bytes());
    h.update(vote_options_root.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

/// FN: ballot_oracle_closed_msg
/// WHAT: byte-form of the closed-variant message emitted by
///       `puzzles/ballot_coin/oracle.rue` when `State.finalized == true`.
/// FORMULA (M4-revised, 5-field preimage): `sha256("ballot_oracle_closed" ||
///                  ballot_launcher_id ||
///                  vote_close_height_be8 ||
///                  vote_options_root ||
///                  vote_outcome ||
///                  agg_signers_commitment)`.
/// PREFIX SAFETY: distinct ASCII prefix from `ballot_oracle_open_msg`
///                guarantees external puzzles can pattern-match on
///                the variant via the preimage prefix bytes; the
///                resulting sha256 outputs are byte-distinct.
pub fn ballot_oracle_closed_msg(
    ballot_launcher_id: Bytes32,
    vote_close_height: u64,
    vote_options_root: Bytes32,
    vote_outcome: Bytes32,
    agg_signers_commitment: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"ballot_oracle_closed");
    h.update(ballot_launcher_id.as_ref());
    h.update(vote_close_height.to_be_bytes());
    h.update(vote_options_root.as_ref());
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
// Ceremony voucher helpers (V-series Option 1)
// ============================================================================

/// Domain-separation prefix committed into every voucher coin's
/// canonical announcement message. MUST stay byte-identical to the
/// literal in `puzzles/ceremony_singleton/ceremony_voucher.rue`.
pub const CEREMONY_VOUCHER_DOMAIN: &[u8] = b"chip:ceremony:voucher";

/// Compute the canonical announcement message a voucher coin emits
/// on every spend. Pre-supplied to the puzzle as a 1st-curry arg so
/// the rue puzzle never has to re-hash the variable-length CLVM
/// representation of `max_voters`.
///
/// FORMULA: `sha256(CEREMONY_VOUCHER_DOMAIN || vk_hash ||
///           max_voters_be8 || ceremony_launcher_id)`.
pub fn ceremony_voucher_canonical_msg(
    vk_hash: Bytes32,
    max_voters: u64,
    ceremony_launcher_id: Bytes32,
) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(CEREMONY_VOUCHER_DOMAIN);
    h.update(vk_hash.to_bytes().as_slice());
    h.update(&max_voters.to_be_bytes());
    h.update(ceremony_launcher_id.to_bytes().as_slice());
    let digest: [u8; 32] = h.finalize().into();
    Bytes32::new(digest)
}

/// Predict the puzzle hash of a curried `ceremony_voucher` coin.
///
/// CURRY LAYOUT (mirrors `puzzles/ceremony_singleton/ceremony_voucher.rue`):
///   1st curry: `(MOD_HASH, CANONICAL_MSG, CEREMONY_LAUNCHER_ID)`
///   2nd curry: `(SELF_HASH = curry_tree_hash(MOD_HASH,
///               [hash_atom(MOD_HASH), hash_atom(CANONICAL_MSG),
///                hash_atom(CEREMONY_LAUNCHER_ID)]))`
/// Final puzzle hash = `curry_tree_hash(SELF_HASH, [hash_atom(SELF_HASH)])`.
pub fn ceremony_voucher_puzzle_hash(
    vk_hash: Bytes32,
    max_voters: u64,
    ceremony_launcher_id: Bytes32,
) -> Bytes32 {
    let mod_hash = PuzzleHashes::ceremony_voucher();
    let canonical_msg =
        ceremony_voucher_canonical_msg(vk_hash, max_voters, ceremony_launcher_id);
    let first_curry = curry_tree_hash(
        mod_hash,
        &[
            hash_atom_b32(&mod_hash),
            hash_atom_b32(&canonical_msg),
            hash_atom_b32(&ceremony_launcher_id),
        ],
    );
    curry_tree_hash(first_curry, &[hash_atom_b32(&first_curry)])
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
    ///       depth-32 fold of `EMPTY_BALLOT_LEAF_HASH` under PLAIN
    ///       sha256 (no 0x02 CLVM tree-hash prefix). The on-chain
    ///       per-registration ballot SPT in
    ///       `mint_voting_coin.rue::compute_ballot_root` uses
    ///       `sha256(node || sibling)` directly, same as the
    ///       registration SPT in `merkle.rs`.
    /// HOW:  recompute via inline iteration with raw sha256; assert
    ///       equality.
    /// WHY:  the value is curried into every `register` action and
    ///       initialises every voter's `voted_ballots_root`. Drift
    ///       (e.g. accidental use of `hash_pair` / `tree_hash_pair`)
    ///       would break voter↔Registration Coin handshake at
    ///       mint_voting_coin time even though register itself
    ///       wouldn't notice.
    #[test]
    fn empty_ballot_root_is_depth_32_fold_of_zero_leaf() {
        use sha2::{Digest as _, Sha256 as _Sha256};
        let mut node = EMPTY_BALLOT_LEAF_HASH;
        for _ in 0..BALLOT_TREE_DEPTH {
            let mut h = _Sha256::new();
            h.update(node.as_ref());
            h.update(node.as_ref());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.finalize());
            node = Bytes32::new(arr);
        }
        assert_eq!(empty_ballot_root(), node);
        // Idempotent across calls (cache works).
        assert_eq!(empty_ballot_root(), empty_ballot_root());
    }

    /// WHAT: `voted_ballots_root_after_inserts(&[])` equals
    ///       `empty_ballot_root()` (vacuous).
    #[test]
    fn voted_ballots_root_after_inserts_empty_is_empty_root() {
        assert_eq!(
            voted_ballots_root_after_inserts(&[]),
            empty_ballot_root(),
        );
    }

    /// WHAT: `voted_ballots_root_after_inserts(&[ballot_id])` agrees
    ///       byte-for-byte with the on-chain `mint_voting_coin.rue`
    ///       `compute_ballot_root` over the empty SPT siblings, using
    ///       `sha256(ballot_id)` as the inserted leaf and
    ///       `ballot_slot_from_id(ballot_id)` as the slot.
    /// WHY:  this is the load-bearing identity for the Gap (3) fix in
    ///       `Voter::release_collateral` — the SDK must reproduce the
    ///       on-chain post-cast `voted_ballots_root` so the predicted
    ///       Registration Coin puzzle hash matches the actual
    ///       on-chain ph.
    #[test]
    fn voted_ballots_root_after_single_insert_matches_compute_ballot_root() {
        use sha2::{Digest as _, Sha256 as _Sha256};
        let ballot_id = b32(0xCC);

        // Reference path: mirror the puzzle's
        // `compute_ballot_root(occupied_leaf, slot, siblings, depth)`
        // exactly, with `siblings = empty_ballot_membership_siblings()`.
        let mut h = _Sha256::new();
        h.update(ballot_id.as_ref());
        let mut leaf_arr = [0u8; 32];
        leaf_arr.copy_from_slice(&h.finalize());
        let occupied_leaf = Bytes32::new(leaf_arr);

        let siblings = empty_ballot_membership_siblings();
        let mut node = occupied_leaf;
        let mut idx = ballot_slot_from_id(ballot_id);
        for sibling in &siblings {
            let mut hh = _Sha256::new();
            if idx & 1 == 0 {
                hh.update(node.as_ref());
                hh.update(sibling.as_ref());
            } else {
                hh.update(sibling.as_ref());
                hh.update(node.as_ref());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hh.finalize());
            node = Bytes32::new(arr);
            idx >>= 1;
        }
        let expected = node;

        assert_eq!(
            voted_ballots_root_after_inserts(&[ballot_id]),
            expected,
            "single-insert post-cast voted_ballots_root must match \
             on-chain compute_ballot_root output byte-for-byte",
        );
    }

    /// WHAT: `empty_ballot_membership_siblings()` produces a 32-element
    ///       sibling list whose `compute_ballot_root` (plain-sha256
    ///       fold) at any slot index yields `empty_ballot_root()`.
    /// HOW:  fold the empty leaf upward using each sibling at level
    ///       i; the result must equal `empty_ballot_root()` (and is
    ///       slot-independent because every sibling matches the node).
    /// WHY:  this is what the SDK passes for the
    ///       `BallotMembership.siblings` field of `mint_voting_coin`'s
    ///       solution when the voter has no prior votes; if the list
    ///       were wrong the on-chain non-membership proof would fail
    ///       and the spend would be rejected.
    #[test]
    fn empty_ballot_membership_siblings_round_trips_to_empty_ballot_root() {
        use sha2::{Digest as _, Sha256 as _Sha256};
        let siblings = empty_ballot_membership_siblings();
        assert_eq!(siblings.len(), BALLOT_TREE_DEPTH);

        let slot: u32 = 0xDEAD_BEEF; // arbitrary; should not affect result
        let mut node = EMPTY_BALLOT_LEAF_HASH;
        let mut idx = slot;
        for sibling in &siblings {
            let mut h = _Sha256::new();
            if idx & 1 == 0 {
                h.update(node.as_ref());
                h.update(sibling.as_ref());
            } else {
                h.update(sibling.as_ref());
                h.update(node.as_ref());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.finalize());
            node = Bytes32::new(arr);
            idx >>= 1;
        }
        assert_eq!(node, empty_ballot_root());
    }

    /// WHAT: `registration_actions_merkle_root(cat_tail_hash)` is
    ///       deterministic given a fixed `cat_tail_hash`.
    #[test]
    fn registration_actions_merkle_root_is_sorted_canonical() {
        let tail = b32(0x77);
        let r1 = registration_actions_merkle_root(tail);
        let r2 = registration_actions_merkle_root(tail);
        assert_eq!(r1, r2);
    }

    /// WHAT: registration leaf set agrees with
    ///       `chia_sdk_types::MerkleTree::new` on the SORTED leaves.
    #[test]
    fn registration_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let tail = b32(0x77);
        let leaves = registration_action_root_leaves(tail);
        let upstream_root = MerkleTree::new(&leaves).root();
        assert_eq!(registration_actions_merkle_root(tail), upstream_root);
    }

    /// WHAT: `election_actions_merkle_root` is permutation-invariant.
    #[test]
    fn election_actions_merkle_root_is_order_independent() {
        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);
        let d = b32(0xD4);

        let r1 = election_actions_merkle_root(a, b, c, d);
        let r2 = election_actions_merkle_root(b, a, d, c);
        let r3 = election_actions_merkle_root(d, c, b, a);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    /// WHAT: hand-rolled `election_actions_merkle_root` agrees byte-
    ///       for-byte with `chia_sdk_types::MerkleTree::new` on the
    ///       SORTED leaf set (SEC-F3+F5 4-leaf balanced shape:
    ///       pair(pair(L0,L1), pair(L2,L3))). This is load-bearing: the
    ///       aggregator builds action-inclusion proofs via the same
    ///       `MerkleTree`, so the root must match or proofs fail on-chain.
    #[test]
    fn election_actions_merkle_root_matches_merkletree() {
        use chia_sdk_types::MerkleTree;

        let a = b32(0xA1);
        let b = b32(0xB2);
        let c = b32(0xC3);
        let d = b32(0xD4);

        let mut leaves = vec![a, b, c, d];
        leaves.sort_by(|x, y| hash_atom_b32(x).as_ref().cmp(hash_atom_b32(y).as_ref()));
        let upstream_root = MerkleTree::new(&leaves).root();

        let our_root = election_actions_merkle_root(a, b, c, d);
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

        let inner = fresh_registration_inner_hash(&pk, election_id, tail_hash, 1_000);
        let inner_th = TreeHash::new(inner.to_bytes());
        let expected = Bytes32::new(CatArgs::curry_tree_hash(tail_hash, inner_th).to_bytes());

        assert_eq!(
            fresh_registration_coin_puzzle_hash(tail_hash, &pk, election_id, 1_000),
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
            fresh_registration_inner_hash(&pk1, election_id, tail, 1_000),
            fresh_registration_inner_hash(&pk2, election_id, tail, 1_000),
        );
    }

    /// WHAT: same voter, different elections → different inner hash.
    #[test]
    fn fresh_registration_inner_hash_is_per_election() {
        let pk = test_pubkey();
        let tail = b32(0x22);
        assert_ne!(
            fresh_registration_inner_hash(&pk, b32(0x11), tail, 1_000),
            fresh_registration_inner_hash(&pk, b32(0x22), tail, 1_000),
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

    /// WHAT: `ballot_oracle_open_msg` byte-exact matches its
    ///       3-field preimage (M4-revised: vote_options_root added).
    #[test]
    fn ballot_oracle_open_msg_is_canonical_sha256() {
        let ballot_id = b32(0xBB);
        let close_h: u64 = 1_234_567;
        let options_root = b32(0xEE);

        let mut h = Sha256::new();
        h.update(b"ballot_oracle_open");
        h.update(ballot_id.as_ref());
        h.update(close_h.to_be_bytes());
        h.update(options_root.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            ballot_oracle_open_msg(ballot_id, close_h, options_root),
            Bytes32::new(arr)
        );
    }

    /// WHAT: `ballot_oracle_closed_msg` byte-exact matches its
    ///       5-field preimage (M4-revised: vote_options_root added).
    #[test]
    fn ballot_oracle_closed_msg_is_canonical_sha256() {
        let ballot_id = b32(0xBB);
        let close_h: u64 = 1_234_567;
        let options_root = b32(0xEE);
        let outcome = b32(0xCC);
        let agg = b32(0xDD);

        let mut h = Sha256::new();
        h.update(b"ballot_oracle_closed");
        h.update(ballot_id.as_ref());
        h.update(close_h.to_be_bytes());
        h.update(options_root.as_ref());
        h.update(outcome.as_ref());
        h.update(agg.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());

        assert_eq!(
            ballot_oracle_closed_msg(ballot_id, close_h, options_root, outcome, agg),
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
        let options_root = Bytes32::default();
        let m_open = ballot_oracle_open_msg(ballot_id, close_h, options_root);
        let m_closed = ballot_oracle_closed_msg(
            ballot_id,
            close_h,
            options_root,
            Bytes32::default(),
            Bytes32::default(),
        );
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

    // ── Cat A: focused unit tests for new helpers (`voted_ballots_root_after_inserts`
    //          multi-insert, `registration_inner_hash_for_state`,
    //          `cat_outer_for_inner_hash`). The single-insert case is already
    //          covered by `voted_ballots_root_after_single_insert_matches_compute_ballot_root`;
    //          here we add the multi-insert correctness identities.

    /// WHAT: `voted_ballots_root_after_inserts(&[a, b])` matches a
    ///       fold computed by inserting a then b independently into
    ///       a sparse SPT and recomputing the root via the stock
    ///       `compute_ballot_root` reference path on each leaf.
    /// HOW:  build a 2^32-sparse map manually for two ballots whose
    ///       slots differ; fold up depth-32 mirroring the helper's
    ///       BTreeMap pair logic. Assert the helper's output equals
    ///       this independent reference.
    /// WHY:  guards the post-cast `voted_ballots_root` for any voter
    ///       who has cast in 2+ ballots — the load-bearing identity
    ///       for `Voter::release_collateral` after multiple casts.
    #[test]
    fn voted_ballots_root_after_inserts_two_ballots_matches_manual_fold() {
        use sha2::{Digest as _, Sha256 as _Sha256};
        use std::collections::BTreeMap;

        let b_a = b32(0x11);
        let b_b = b32(0x22);
        // Sanity: ballot slot derivation must produce distinct slots
        // for two distinct ballot ids (otherwise the test is vacuous).
        let slot_a = ballot_slot_from_id(b_a);
        let slot_b = ballot_slot_from_id(b_b);
        assert_ne!(slot_a, slot_b);

        // Reference fold path — independent reimplementation that
        // does NOT call `voted_ballots_root_after_inserts` internally.
        fn leaf_for(id: Bytes32) -> Bytes32 {
            let mut h = _Sha256::new();
            h.update(id.as_ref());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.finalize());
            Bytes32::new(arr)
        }
        let mut current: BTreeMap<u32, Bytes32> = BTreeMap::new();
        current.insert(slot_a, leaf_for(b_a));
        current.insert(slot_b, leaf_for(b_b));

        let empty_per_level = empty_ballot_membership_siblings();
        for level in 0..BALLOT_TREE_DEPTH {
            let mut next: BTreeMap<u32, Bytes32> = BTreeMap::new();
            let level_empty = empty_per_level[level];
            let mut iter = current.into_iter().peekable();
            while let Some((slot, node)) = iter.next() {
                let parent_slot = slot >> 1;
                let is_left = slot & 1 == 0;
                let sibling = if is_left
                    && iter.peek().map(|(s, _)| *s == slot ^ 1).unwrap_or(false)
                {
                    iter.next().expect("peeked sibling").1
                } else {
                    level_empty
                };
                let mut h = _Sha256::new();
                if is_left {
                    h.update(node.as_ref());
                    h.update(sibling.as_ref());
                } else {
                    h.update(sibling.as_ref());
                    h.update(node.as_ref());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h.finalize());
                next.insert(parent_slot, Bytes32::new(arr));
            }
            current = next;
        }
        let expected = current.into_iter().next().expect("one root").1;

        assert_eq!(
            voted_ballots_root_after_inserts(&[b_a, b_b]),
            expected,
            "two-insert root must match independent reference fold",
        );
    }

    /// WHAT: `voted_ballots_root_after_inserts` is order-independent
    ///       across the input ballot id list — the same set of
    ///       ballots produces the same root regardless of the input
    ///       ordering.
    /// HOW:  hand-built three-ballot input; permute the order and
    ///       assert all permutations yield the same root, and that
    ///       root differs from any 2-element subset's root.
    /// WHY:  the SPT is order-free at the slot level (the mapping is
    ///       slot → leaf), so the SDK lineage walker MUST be free to
    ///       discover ballot ids in any order. If a future refactor
    ///       accidentally introduced order-dependence, this test
    ///       would surface it.
    #[test]
    fn voted_ballots_root_after_inserts_three_ballots_is_order_independent() {
        let b1 = b32(0x31);
        let b2 = b32(0x32);
        let b3 = b32(0x33);

        let r_123 = voted_ballots_root_after_inserts(&[b1, b2, b3]);
        let r_321 = voted_ballots_root_after_inserts(&[b3, b2, b1]);
        let r_213 = voted_ballots_root_after_inserts(&[b2, b1, b3]);

        assert_eq!(r_123, r_321, "set-equal inputs must produce equal roots");
        assert_eq!(r_123, r_213, "set-equal inputs must produce equal roots");

        // Strict subset must produce a different root (the third
        // ballot's leaf actually changes the SPT — guards against an
        // accidental no-op insertion path).
        let r_12 = voted_ballots_root_after_inserts(&[b1, b2]);
        assert_ne!(
            r_123, r_12,
            "adding a third distinct ballot MUST change the SPT root",
        );
        // And neither of those equals the empty root.
        assert_ne!(r_123, empty_ballot_root());
        assert_ne!(r_12, empty_ballot_root());
    }

    /// WHAT: `registration_inner_hash_for_state` with the fresh-
    ///       state arguments (`empty_ballot_root()`, `None`) equals
    ///       `fresh_registration_inner_hash` — the original helper
    ///       it generalises.
    /// HOW:  compute both and assert byte-for-byte equality.
    /// WHY:  if the generalised helper ever drifted from the fresh-
    ///       state helper, on-chain ph predictions for newly-minted
    ///       Registration Coins would fail. Pinning the identity
    ///       here means callers can safely use either helper for
    ///       fresh state without a behaviour split.
    #[test]
    fn registration_inner_hash_for_state_matches_fresh_helper() {
        let pk = test_pubkey();
        let election_id = b32(0xEE);
        let cat_tail = b32(0x77);

        let fresh = fresh_registration_inner_hash(&pk, election_id, cat_tail, 1_000);
        let general = registration_inner_hash_for_state(
            &pk,
            election_id,
            cat_tail,
            empty_ballot_root(),
            1_000,
            None,
        );

        assert_eq!(
            fresh, general,
            "fresh-state inputs must produce identical inner ph",
        );
    }

    /// WHAT: `registration_inner_hash_for_state` produces a DIFFERENT
    ///       inner ph for distinct `voted_ballots_root` values, and
    ///       again for distinct `release_destination` values.
    /// HOW:  hold every other curry input fixed, vary one field at a
    ///       time, assert the resulting inner ph differs.
    /// WHY:  if the helper ever stopped binding a field into the
    ///       state hash, post-cast or post-release Registration Coin
    ///       ph predictions would silently fall back to the fresh
    ///       state. This test pins both fields as load-bearing.
    #[test]
    fn registration_inner_hash_for_state_distinguishes_state_fields() {
        let pk = test_pubkey();
        let election_id = b32(0xEE);
        let cat_tail = b32(0x77);

        let fresh = registration_inner_hash_for_state(
            &pk, election_id, cat_tail, empty_ballot_root(), 1_000, None,
        );
        let with_vbr = registration_inner_hash_for_state(
            &pk, election_id, cat_tail, b32(0xCC), 1_000, None,
        );
        let with_dest = registration_inner_hash_for_state(
            &pk, election_id, cat_tail, empty_ballot_root(), 1_000, Some(b32(0xDD)),
        );

        assert_ne!(
            fresh, with_vbr,
            "voted_ballots_root MUST be bound into the state hash",
        );
        assert_ne!(
            fresh, with_dest,
            "release_destination MUST be bound into the state hash",
        );
        assert_ne!(
            with_vbr, with_dest,
            "vbr-bumped state and dest-bumped state MUST be distinct",
        );
    }

    /// WHAT: `cat_outer_for_inner_hash(tail, inner)` matches
    ///       `chia_puzzle_types::cat::CatArgs::curry_tree_hash` on
    ///       the same inputs (the canonical CAT outer wrap).
    /// HOW:  delegate to `CatArgs::curry_tree_hash` directly and
    ///       compare bytes.
    /// WHY:  the helper is a single-argument convenience over the
    ///       upstream curry call; if it ever drifted, every post-cast
    ///       Registration Coin ph prediction in `release_collateral`
    ///       would be wrong.
    #[test]
    fn cat_outer_for_inner_hash_matches_catargs() {
        use chia_puzzle_types::cat::CatArgs;
        let cat_tail = b32(0x77);
        let inner_ph = b32(0xCD);
        let inner_th = TreeHash::new(inner_ph.to_bytes());
        let expected = Bytes32::new(CatArgs::curry_tree_hash(cat_tail, inner_th).to_bytes());
        assert_eq!(cat_outer_for_inner_hash(cat_tail, inner_ph), expected);
    }

    /// WHAT: composing `registration_inner_hash_for_state` with
    ///       `cat_outer_for_inner_hash` for fresh-state inputs
    ///       reproduces `fresh_registration_coin_puzzle_hash`.
    /// HOW:  build inner via the generalised helper at fresh state,
    ///       wrap via `cat_outer_for_inner_hash`, compare to the
    ///       fresh-state ph helper.
    /// WHY:  callers in `Voter::release_collateral` use this
    ///       composition to predict the post-cast Registration Coin
    ///       ph. Pinning the composition equals the fresh-state
    ///       helper when run at fresh state guards the entire chain.
    #[test]
    fn cat_outer_compose_with_inner_state_matches_fresh_full_ph() {
        let pk = test_pubkey();
        let election_id = b32(0xEE);
        let cat_tail = b32(0x77);

        let inner = registration_inner_hash_for_state(
            &pk, election_id, cat_tail, empty_ballot_root(), 1_000, None,
        );
        let outer = cat_outer_for_inner_hash(cat_tail, inner);
        let fresh_full = fresh_registration_coin_puzzle_hash(cat_tail, &pk, election_id, 1_000);

        assert_eq!(
            outer, fresh_full,
            "compose(inner_state, cat_outer) at fresh state MUST equal \
             fresh_registration_coin_puzzle_hash",
        );
    }

    /// WHAT: `ceremony_voucher_canonical_msg` is byte-exact `sha256(
    ///       "chip:ceremony:voucher" || vk_hash || max_voters_be8 ||
    ///       ceremony_launcher_id)`.
    /// HOW:  hand-recompute the same sha256 from the same inputs;
    ///       compare to the helper's output.
    /// WHY:  this hash is curried into every voucher coin AND
    ///       reproduced inside `puzzles/ceremony_singleton/
    ///       ceremony_voucher.rue`. Any drift between the SDK helper
    ///       and the rue puzzle would make every election deploy fail
    ///       its AssertCoinAnnouncement.
    #[test]
    fn ceremony_voucher_canonical_msg_matches_handwritten_sha256() {
        let vk_hash = b32(0xAA);
        let max_voters: u64 = 20_000;
        let launcher = b32(0xBB);

        let mut h = Sha256::new();
        h.update(b"chip:ceremony:voucher");
        h.update(vk_hash.to_bytes().as_slice());
        h.update(&max_voters.to_be_bytes());
        h.update(launcher.to_bytes().as_slice());
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(
            ceremony_voucher_canonical_msg(vk_hash, max_voters, launcher),
            Bytes32::new(expected),
        );
    }

    /// WHAT: `ceremony_voucher_puzzle_hash` composes the standard
    ///       two-curry self-hash pattern matching `ceremony_voucher.rue`.
    /// HOW:  rebuild the curry chain manually using the same primitives
    ///       (`PuzzleHashes::ceremony_voucher`, `curry_tree_hash`,
    ///       `hash_atom_b32`) and compare. Then mutate one input byte
    ///       and assert the puzzle hash changes (sensitivity).
    /// WHY:  the on-chain link guarantee (election asserts voucher's
    ///       announcement) only works if every consumer agrees on the
    ///       voucher's puzzle hash for a given (vk_hash, max_voters,
    ///       launcher) triple. This test pins the composition and
    ///       proves all three inputs are committed.
    #[test]
    fn ceremony_voucher_puzzle_hash_composes_two_curry_self_hash() {
        let vk_hash = b32(0xCC);
        let max_voters: u64 = 20_000;
        let launcher = b32(0xDD);

        let mod_hash = PuzzleHashes::ceremony_voucher();
        let canonical = ceremony_voucher_canonical_msg(vk_hash, max_voters, launcher);
        let first = curry_tree_hash(
            mod_hash,
            &[
                hash_atom_b32(&mod_hash),
                hash_atom_b32(&canonical),
                hash_atom_b32(&launcher),
            ],
        );
        let expected = curry_tree_hash(first, &[hash_atom_b32(&first)]);

        assert_eq!(
            ceremony_voucher_puzzle_hash(vk_hash, max_voters, launcher),
            expected,
        );

        // Sensitivity: every input must be committed.
        let with_diff_vk = ceremony_voucher_puzzle_hash(b32(0xCD), max_voters, launcher);
        let with_diff_max = ceremony_voucher_puzzle_hash(vk_hash, 19_999, launcher);
        let with_diff_launcher = ceremony_voucher_puzzle_hash(vk_hash, max_voters, b32(0xDE));
        assert_ne!(expected, with_diff_vk);
        assert_ne!(expected, with_diff_max);
        assert_ne!(expected, with_diff_launcher);
    }
}
