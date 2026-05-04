// ============================================================================
// merkle.rs — Sparse Merkle Tree (depth 32) for the registered voter set
// ============================================================================
//
// MODULE: merkle
// PURPOSE: Off-chain mirror of the on-chain SPT that the Election
//          Singleton maintains. Used by:
//            - Voter::register      → builds an emptiness proof for
//                                     the new voter's slot
//            - Aggregator::sync     → rebuilds the tree from on-chain
//                                     coins to verify root match
//            - Aggregator::build_finalize → builds inclusion proofs
//                                     for each signing voter
//
// DESIGN:
//   * Depth 32 (matches the curried `TREE_DEPTH` in
//     `puzzles/election/register.rue` and the Groth16 circuit).
//   * Each voter occupies a deterministic slot derived from their
//     pubkey (canonical slot rule lives in `slot_for_pubkey`).
//   * Sparse representation: only non-empty leaves are stored;
//     empty subtrees are answered from a precomputed table.
//   * Internal node hash is `sha256(left || right)` (raw concat) to
//     match the on-chain `compute_root` Rue helper — NOT the CLVM
//     tree-hash convention.
//   * Occupied leaf hash is `sha256(pubkey)` per CHIP.md §88-91 —
//     uniform per-voter weight is tracked on Election Singleton state
//     (`registration_vote_weight`), NOT encoded into the leaf.
//
// CORRESPONDENCE TO RUE:
//   `compute_root(node, index, siblings, depth)` in
//   `puzzles/election/register.rue` walks leaf → root, hashing
//   sibling at each level using `index & 1` to decide ordering. This
//   module's `verify_proof` mirrors that walk byte-for-byte.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::config::{EMPTY_LEAF_HASH, TREE_DEPTH};

/// TYPE: MerkleProof
/// SHAPE: TREE_DEPTH sibling hashes, ordered from leaf level upward.
/// USAGE: pass into `verify_proof` along with the leaf hash and slot
///        index to reconstruct the root.
pub type MerkleProof = Vec<Bytes32>;

/// STRUCT: SparseMerkleTree
/// PURPOSE: in-memory SPT that stores only registered voters; empty
///          subtree hashes are reused from a precomputed table.
///
/// CONSTRUCTION COST: `new()` precomputes 33 empty-subtree hashes (one
///                    per level). All subsequent operations are O(log n)
///                    in the depth.
///
/// THREAD SAFETY: not Send/Sync via interior mutability. Wrap in your
///                own `Mutex<SparseMerkleTree>` if you need to share
///                across tasks.
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    /// Slot index → 48-byte voter pubkey bytes. BTreeMap so range
    /// queries (used by `subtree_hash` for sparsity short-circuit)
    /// are O(log n).
    leaves: BTreeMap<u32, [u8; 48]>,

    /// Precomputed empty-subtree hashes. `empty_subtree[L]` is the
    /// hash of an all-empty subtree spanning `2^L` leaves.
    /// `empty_subtree[0] = EMPTY_LEAF_HASH`. Build cost is O(depth).
    empty_subtree: Vec<Bytes32>,
}

impl SparseMerkleTree {
    /// FN: new
    /// WHAT: empty SPT. Root equals `empty_subtree[TREE_DEPTH]`.
    /// USAGE: every caller (deployer genesis, voter register, aggregator
    ///        sync, indexer rebuild) constructs via this. Per CHIP.md
    ///        §88-91 the occupied leaf is `sha256(pubkey)` — uniform
    ///        per-voter weight is tracked on Election Singleton state
    ///        (`registration_vote_weight`), NOT in the leaf — so the
    ///        SMT needs no extra parameters.
    /// COST: precomputes the empty-subtree table. ~33 sha256 calls.
    pub fn new() -> Self {
        let mut empty_subtree = Vec::with_capacity(TREE_DEPTH as usize + 1);
        empty_subtree.push(Bytes32::new(EMPTY_LEAF_HASH));
        for level in 0..TREE_DEPTH {
            let prev = empty_subtree[level as usize];
            let next = sha256_concat(prev.as_ref(), prev.as_ref());
            empty_subtree.push(next);
        }
        Self {
            leaves: BTreeMap::new(),
            empty_subtree,
        }
    }

    /// FN: slot_for_pubkey
    /// WHAT: canonical SPT slot for a voter pubkey.
    /// FORMULA: `u32::from_be_bytes(sha256(pubkey)[0..4])`.
    /// MIRRORS: `slot_from_pubkey` in
    ///          `puzzles/election/register.rue` — bit-exact agreement
    ///          is required for any empty-slot proof to verify
    ///          on-chain.
    /// WHY u32: the puzzle takes the first 4 bytes of sha256 (low 32
    ///          bits after `mod 2^32`); padding to 5 bytes with `0x00`
    ///          gives an unsigned interpretation in CLVM.
    pub fn slot_for_pubkey(pubkey: &PublicKey) -> u32 {
        let pk_bytes = pubkey.to_bytes();
        let h = Sha256::digest(pk_bytes);
        u32::from_be_bytes(h[0..4].try_into().unwrap())
    }

    /// FN: active_leaf_hash
    /// WHAT: leaf hash for a registered voter — per CHIP.md §88-91
    ///       `sha256(pubkey)`. Per-voter weight is tracked on the
    ///       Election Singleton state (`registration_vote_weight +=
    ///       COLLATERAL_AMOUNT` per `register` action) rather than
    ///       encoded in the leaf, since this revision uses a uniform
    ///       per-registration `COLLATERAL_AMOUNT`.
    /// MIRRORS: `puzzles/election/register.rue` (and `deregister.rue`)
    ///          which compute the same hash via `sha256(pk_b)`.
    pub fn active_leaf_hash(pubkey: &PublicKey) -> Bytes32 {
        let pk_bytes = pubkey.to_bytes();
        active_leaf_hash_bytes(&pk_bytes)
    }

    /// FN: insert
    /// WHAT: add a voter to the tree.
    /// IDEMPOTENT: re-inserting the same pubkey is a no-op.
    /// ERRORS: `SlotCollision` if two distinct pubkeys hash to the
    ///         same SPT slot. Vanishingly unlikely (birthday-bound
    ///         on 2^32 slots) but checked anyway — a collision in
    ///         production would corrupt the on-chain state otherwise.
    pub fn insert(&mut self, pubkey: &PublicKey) -> Result<(), crate::VotingError> {
        let slot = Self::slot_for_pubkey(pubkey);
        let pk_bytes = pubkey.to_bytes();
        if let Some(existing) = self.leaves.get(&slot) {
            if existing != &pk_bytes {
                return Err(crate::VotingError::SlotCollision { slot: slot as u64 });
            }
            return Ok(());
        }
        self.leaves.insert(slot, pk_bytes);
        Ok(())
    }

    /// FN: contains
    /// WHAT: true iff a voter pubkey is registered (occupies its
    ///       canonical slot).
    pub fn contains(&self, pubkey: &PublicKey) -> bool {
        let slot = Self::slot_for_pubkey(pubkey);
        self.leaves
            .get(&slot)
            .map(|stored| stored == &pubkey.to_bytes())
            .unwrap_or(false)
    }

    /// FN: len
    /// WHAT: number of registered voters.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// FN: root
    /// WHAT: current SPT root. Matches the on-chain
    ///       `STATE.registration_merkle_root` after every register
    ///       spend.
    /// COST: O(non-empty leaves * log n).
    pub fn root(&self) -> Bytes32 {
        // Top of tree spans the full slot space [0, 2^32). u64 used
        // throughout to avoid u32 overflow at the upper bound.
        self.subtree_hash(0, 1u64 << TREE_DEPTH, TREE_DEPTH)
    }

    /// FN: subtree_hash (private)
    /// WHAT: hash of the subtree spanning slots `[lo, hi)` at the
    ///       given remaining `level`.
    /// CONTRACT: caller guarantees `hi - lo == 2^level`.
    /// SHORT-CIRCUIT: if no leaves in range, return precomputed empty
    ///                hash for that level. This is what makes the tree
    ///                sparse-friendly.
    /// OVERFLOW SAFETY: uses u64 throughout so the level=32 case
    ///                  (lo=0, hi=2^32) doesn't overflow u32.
    fn subtree_hash(&self, lo: u64, hi: u64, level: u32) -> Bytes32 {
        if level == 0 {
            return match self.leaves.get(&(lo as u32)) {
                Some(pk) => active_leaf_hash_bytes(pk),
                None => Bytes32::new(EMPTY_LEAF_HASH),
            };
        }
        if !self.range_has_any(lo, hi) {
            return self.empty_subtree[level as usize];
        }
        let mid = lo + ((hi - lo) >> 1);
        let left = self.subtree_hash(lo, mid, level - 1);
        let right = self.subtree_hash(mid, hi, level - 1);
        sha256_concat(left.as_ref(), right.as_ref())
    }

    /// FN: range_has_any (private)
    /// WHAT: true iff any inserted leaf has slot in [lo, hi).
    /// COST: O(log n) via BTreeMap range query.
    fn range_has_any(&self, lo: u64, hi: u64) -> bool {
        // Clamp to u32 — leaf slots are u32. `hi` may equal 2^32 at
        // the top level, which we treat as "no upper bound" for the
        // BTreeMap range.
        let lo32 = lo as u32;
        if hi > u32::MAX as u64 {
            self.leaves.range(lo32..).next().is_some()
        } else {
            let hi32 = hi as u32;
            if hi32 <= lo32 {
                return false;
            }
            self.leaves.range(lo32..hi32).next().is_some()
        }
    }

    /// FN: prove
    /// WHAT: build a Merkle proof for the slot at `index`.
    /// RETURNS: `TREE_DEPTH` sibling hashes from leaf to root.
    /// USAGE: pair with `verify_proof` to validate against a known
    ///        root. The same proof is also passed verbatim into the
    ///        on-chain `register` action's solution.
    pub fn prove(&self, index: u32) -> MerkleProof {
        let mut siblings = Vec::with_capacity(TREE_DEPTH as usize);
        for level in 0..TREE_DEPTH {
            // At level L the parent index is `index >> L`. Its sibling
            // is the parent index XOR 1. Convert sibling parent index
            // back to slot range [sibling_lo, sibling_hi) at this level.
            let sibling_parent = (index as u64 >> level) ^ 1;
            let span = 1u64 << level;
            let sibling_lo = sibling_parent * span;
            let sibling_hi = sibling_lo + span;
            siblings.push(self.subtree_hash(sibling_lo, sibling_hi, level));
        }
        siblings
    }
}

/// FN: active_leaf_hash_bytes (file-private)
/// WHAT: leaf hash from raw 48-byte pubkey buffer (skip the typed
///       PublicKey roundtrip — used inside SPT recursion). Per
///       CHIP.md §88-91: `sha256(pubkey)`.
fn active_leaf_hash_bytes(pk_bytes: &[u8; 48]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(pk_bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// FN: verify_proof
/// WHAT: independent proof verifier. Walks `leaf` up `siblings` using
///       `index & 1` to decide left/right ordering at each level,
///       returns true iff the resulting root matches `expected_root`.
/// USAGE: callers verify proofs received from untrusted peers (e.g.,
///        an aggregator validating a voter-supplied empty-slot proof
///        before including it in a finalize spend).
/// MIRROR: byte-for-byte equivalent to `compute_root` in
///         `puzzles/election/register.rue` — passing `verify_proof`
///         is necessary AND sufficient for the on-chain check.
pub fn verify_proof(
    leaf: Bytes32,
    index: u32,
    siblings: &[Bytes32],
    expected_root: Bytes32,
) -> bool {
    if siblings.len() != TREE_DEPTH as usize {
        return false;
    }
    let mut node = leaf;
    let mut idx = index;
    for sibling in siblings {
        node = if idx & 1 == 0 {
            sha256_concat(node.as_ref(), sibling.as_ref())
        } else {
            sha256_concat(sibling.as_ref(), node.as_ref())
        };
        idx >>= 1;
    }
    node == expected_root
}

fn sha256_concat(a: &[u8], b: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;

    fn pk_at(index: u32) -> PublicKey {
        let root_sk = SecretKey::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root_sk.public_key(), index).derive_synthetic()
    }

    /// WHAT: two freshly-constructed empty SPTs return the same root.
    /// HOW:  build two `SparseMerkleTree::new()` instances and
    ///       compare their `root()`.
    /// WHY:  the empty-tree root is the genesis state of every
    ///       election; non-determinism here would mean the deployer
    ///       and aggregator computed different starting states.
    #[test]
    fn empty_tree_root_is_deterministic() {
        let t1 = SparseMerkleTree::new();
        let t2 = SparseMerkleTree::new();
        assert_eq!(t1.root(), t2.root());
    }

    /// WHAT: an empty-tree proof at slot 0 verifies for the
    ///       empty-leaf hash AND has the protocol-fixed length of
    ///       `TREE_DEPTH` siblings.
    /// HOW:  build an empty tree, prove(0), assert proof length == 32,
    ///       and `verify_proof(empty_leaf, 0, &proof, root)`.
    /// WHY:  this is the very first SPT operation any voter performs
    ///       at registration time; it must succeed against an empty
    ///       election.
    #[test]
    fn empty_tree_proof_roundtrip_at_slot_zero() {
        let tree = SparseMerkleTree::new();
        let root = tree.root();
        let empty_leaf = Bytes32::new(EMPTY_LEAF_HASH);
        let proof = tree.prove(0);
        assert_eq!(proof.len(), TREE_DEPTH as usize);
        assert!(verify_proof(empty_leaf, 0, &proof, root));
    }

    /// WHAT: proofs work at the upper boundary slot `u32::MAX`
    ///       without arithmetic overflow.
    /// HOW:  build an empty tree, prove for slot `u32::MAX`, verify
    ///       against the empty leaf and the empty root.
    /// WHY:  the SPT internally uses u64 to avoid u32 overflow when
    ///       computing range bounds at the top level. This test
    ///       caught a real overflow bug during development; pinning
    ///       the boundary case prevents regression.
    #[test]
    fn empty_tree_proof_roundtrip_at_max_slot() {
        let tree = SparseMerkleTree::new();
        let root = tree.root();
        let empty_leaf = Bytes32::new(EMPTY_LEAF_HASH);
        let proof = tree.prove(u32::MAX);
        assert!(verify_proof(empty_leaf, u32::MAX, &proof, root));
    }

    /// WHAT: inserting a voter changes the root.
    /// HOW:  capture root before/after a single insert and assert
    ///       inequality.
    /// WHY:  the singleton's `registration_merkle_root` field is the
    ///       only on-chain witness that the voter set changed. If
    ///       insertion didn't update the root, `register` actions
    ///       would silently leave the root constant and registrations
    ///       would not be observable.
    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let r0 = tree.root();
        tree.insert(&pk_at(0)).unwrap();
        let r1 = tree.root();
        assert_ne!(r0, r1, "root must change after inserting a voter");
    }

    /// WHAT: re-inserting the same voter is a no-op.
    /// HOW:  insert pk, capture root, insert pk again, assert root
    ///       unchanged.
    /// WHY:  callers (especially `Aggregator::sync` rebuilding from
    ///       a chain replay) may legitimately encounter the same
    ///       voter multiple times. Idempotency means they don't have
    ///       to deduplicate explicitly.
    #[test]
    fn insert_is_idempotent() {
        let mut t1 = SparseMerkleTree::new();
        t1.insert(&pk_at(0)).unwrap();
        let r_after_first = t1.root();
        t1.insert(&pk_at(0)).unwrap();
        assert_eq!(t1.root(), r_after_first);
    }

    /// WHAT: a proof for a freshly-inserted voter verifies against
    ///       the new root with the voter's `active_leaf_hash`.
    /// HOW:  insert pk, prove at its slot, verify against the active
    ///       leaf hash and the new root.
    /// WHY:  this is the round-trip the on-chain register action
    ///       performs against the new (post-insert) root. If our
    ///       off-chain `prove()` and the on-chain `compute_root()`
    ///       didn't agree byte-for-byte, the register spend would
    ///       always reject.
    #[test]
    fn proof_for_inserted_voter_verifies() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        tree.insert(&pk).unwrap();
        let slot = SparseMerkleTree::slot_for_pubkey(&pk);
        let leaf = SparseMerkleTree::active_leaf_hash(&pk);
        let proof = tree.prove(slot);
        let root = tree.root();
        assert!(verify_proof(leaf, slot, &proof, root));
    }

    /// WHAT: a proof for an *empty* slot in a partially-populated
    ///       tree verifies with the empty leaf.
    /// HOW:  insert one voter; query a slot that another voter
    ///       (un-registered) would map to; verify the proof against
    ///       the empty leaf and the current root.
    /// WHY:  this mirrors the on-chain register action's *pre-check*
    ///       — before inserting a new voter, it verifies the slot is
    ///       currently empty. Failing this would either let two
    ///       voters claim the same slot or refuse legitimate
    ///       registrations.
    #[test]
    fn proof_for_empty_slot_verifies_with_empty_leaf() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(&pk_at(0)).unwrap(); // someone else
        let unregistered_slot = SparseMerkleTree::slot_for_pubkey(&pk_at(99));
        let proof = tree.prove(unregistered_slot);
        let root = tree.root();
        let empty_leaf = Bytes32::new(EMPTY_LEAF_HASH);
        assert!(verify_proof(empty_leaf, unregistered_slot, &proof, root));
    }

    /// WHAT: a proof for an empty slot does NOT verify against an
    ///       arbitrary wrong leaf.
    /// HOW:  build an empty tree, generate a proof for slot 42,
    ///       attempt to verify it against a 0xFF...FF leaf.
    /// WHY:  baseline forgery resistance — anyone could try to
    ///       substitute a fake leaf, and the proof must reject.
    #[test]
    fn wrong_leaf_fails_verification() {
        let tree = SparseMerkleTree::new();
        let proof = tree.prove(42);
        let wrong_leaf = Bytes32::new([0xFF; 32]);
        assert!(!verify_proof(wrong_leaf, 42, &proof, tree.root()));
    }

    /// WHAT: a populated voter's proof verifies with their active
    ///       leaf hash but NOT with the empty leaf hash.
    /// HOW:  insert pk; build a proof at pk's slot; verify against
    ///       both leaves. Only the active leaf passes.
    /// WHY:  forgery resistance against the most realistic attack —
    ///       an attacker tries to convince the on-chain register
    ///       action that a slot is empty when it's actually
    ///       occupied (which would let them overwrite the voter).
    #[test]
    fn populated_voter_proof_only_verifies_with_active_leaf() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        tree.insert(&pk).unwrap();
        let slot = SparseMerkleTree::slot_for_pubkey(&pk);
        let proof = tree.prove(slot);
        let root = tree.root();

        let active_leaf = SparseMerkleTree::active_leaf_hash(&pk);
        let empty_leaf = Bytes32::new(EMPTY_LEAF_HASH);

        assert!(verify_proof(active_leaf, slot, &proof, root));
        assert!(!verify_proof(empty_leaf, slot, &proof, root));
    }

    /// WHAT: trees with different voter counts produce different roots.
    /// HOW:  build two trees, one with {pk0}, one with {pk0, pk1};
    ///       compare roots.
    /// WHY:  a registration that didn't update the root would create
    ///       a silent state divergence between voter and indexer.
    ///       This pins "n+1 voters → different root" as a basic
    ///       invariant.
    #[test]
    fn root_changes_when_voter_count_changes() {
        let mut t1 = SparseMerkleTree::new();
        t1.insert(&pk_at(0)).unwrap();
        let r1 = t1.root();

        let mut t2 = SparseMerkleTree::new();
        t2.insert(&pk_at(0)).unwrap();
        t2.insert(&pk_at(1)).unwrap();
        let r2 = t2.root();

        assert_ne!(r1, r2);
    }

    /// WHAT: insertion order doesn't affect the final root.
    /// HOW:  insert {pk0..pk4} in ascending order into one tree, in
    ///       descending order into another, compare roots.
    /// WHY:  `Aggregator::sync` walks the chain in time order and
    ///       inserts as voters arrive; an `Indexer` may rebuild from
    ///       cached data in arbitrary order. Both must reach the
    ///       same root or chain validation fails.
    #[test]
    fn rebuild_from_pubkey_set_yields_same_root() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();

        for i in 0..5u32 {
            t1.insert(&pk_at(i)).unwrap();
        }
        for i in (0..5u32).rev() {
            t2.insert(&pk_at(i)).unwrap();
        }
        assert_eq!(t1.root(), t2.root());
    }

    /// WHAT: a proof with the wrong number of siblings (≠ TREE_DEPTH)
    ///       is rejected outright.
    /// HOW:  pass a 10-element sibling vec to `verify_proof` and
    ///       assert it returns false.
    /// WHY:  defensive — a malformed proof from an attacker should
    ///       fail in O(1) without doing any hashing. Also catches
    ///       any future drift between TREE_DEPTH and the proof
    ///       generator.
    #[test]
    fn proof_with_wrong_length_rejected() {
        let tree = SparseMerkleTree::new();
        let leaf = Bytes32::new(EMPTY_LEAF_HASH);
        let too_short = vec![Bytes32::default(); 10];
        assert!(!verify_proof(leaf, 0, &too_short, tree.root()));
    }

    /// WHAT: `slot_for_pubkey` is a pure function (deterministic).
    /// HOW:  call it twice on the same pubkey; assert equal output.
    /// WHY:  the slot is what every other SPT operation indexes on;
    ///       non-determinism would corrupt the entire tree.
    #[test]
    fn slot_for_pubkey_is_deterministic() {
        let pk = pk_at(0);
        assert_eq!(
            SparseMerkleTree::slot_for_pubkey(&pk),
            SparseMerkleTree::slot_for_pubkey(&pk),
        );
    }

    /// WHAT: `contains` + `len` correctly track insertions.
    /// HOW:  on a fresh tree assert `!contains` and `is_empty`,
    ///       insert, then assert `contains` and `len() == 1`.
    /// WHY:  these helpers are used by the higher-level Aggregator /
    ///       Indexer to answer "is this voter registered?" without
    ///       a full chain query.
    #[test]
    fn contains_and_len_track_inserts() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        assert!(!tree.contains(&pk));
        assert!(tree.is_empty());
        tree.insert(&pk).unwrap();
        assert!(tree.contains(&pk));
        assert_eq!(tree.len(), 1);
    }
}
