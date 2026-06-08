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
//   * Occupied leaf hash is `sha256(pubkey || locked_amount_be8)` —
//     each voter's weight (= the CAT mojos they locked at register
//     time) is bound into their leaf so the on-chain register /
//     deregister actions can verify it without trusting the
//     `registration_vote_weight` total. The aggregator sums real
//     per-voter amounts when building the finalize witness.
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

/// FN: merkle_root_of_sorted_coin_ids
/// WHAT: SHA-256 binary-tree merkle root over the sorted set of marker
///       coin ids that contributed to a Ceremony Singleton. Used by
///       the finalize action to commit to the contribution set.
/// CONVENTION:
///   * Sort the input ascending (lexicographic on raw 32-byte ids).
///     The on-chain finalize action recomputes the same root from the
///     supplied list, so the dApp / SDK and the puzzle MUST agree on
///     ordering.
///   * Build a balanced binary tree bottom-up. At each level, if the
///     count is odd, the last node is duplicated (paired with itself)
///     before pairing — same convention as the action_layer's
///     actions_merkle_root and many other Chia merkle constructions.
///   * Internal node hash = `sha256(left || right)` raw concat (NOT
///     CLVM tree-hash). Single-leaf trees return the leaf hash
///     directly. Empty input returns `Bytes32::default()`.
/// EDGE CASES:
///   * Empty: returns `0x0000…00`.
///   * Single id: the leaf is hashed once (`sha256(id)`) and returned
///     as the root — matches "tree of height 0" semantics.
pub fn merkle_root_of_sorted_coin_ids(ids: &[Bytes32]) -> Bytes32 {
    if ids.is_empty() {
        return Bytes32::default();
    }
    let mut sorted: Vec<Bytes32> = ids.to_vec();
    sorted.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
    // Hash leaves: sha256(id_bytes).
    let mut level: Vec<Bytes32> = sorted
        .into_iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_ref());
            Bytes32::new(h.finalize().into())
        })
        .collect();
    // Bottom-up pairing.
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            // Pad odd level by duplicating the last node.
            let last = level[level.len() - 1];
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks_exact(2) {
            let mut h = Sha256::new();
            h.update(chunk[0].as_ref());
            h.update(chunk[1].as_ref());
            next.push(Bytes32::new(h.finalize().into()));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod merkle_root_of_sorted_coin_ids_tests {
    use super::*;

    fn b32(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

    /// Empty input yields the zero hash sentinel.
    #[test]
    fn empty_input_is_zero() {
        assert_eq!(merkle_root_of_sorted_coin_ids(&[]), Bytes32::default());
    }

    /// Single-leaf root equals `sha256(leaf)`.
    #[test]
    fn single_leaf_is_sha256_of_leaf() {
        let id = b32(0x42);
        let root = merkle_root_of_sorted_coin_ids(&[id]);
        let mut h = Sha256::new();
        h.update(id.as_ref());
        let expected = Bytes32::new(h.finalize().into());
        assert_eq!(root, expected);
    }

    /// Two-leaf tree: root = sha256(sha256(min) || sha256(max)).
    /// Sort matters: passing in reversed order must give the same root.
    #[test]
    fn two_leaves_sorted() {
        let a = b32(0x01);
        let b = b32(0xFF);
        let root_in_order = merkle_root_of_sorted_coin_ids(&[a, b]);
        let root_reversed = merkle_root_of_sorted_coin_ids(&[b, a]);
        assert_eq!(root_in_order, root_reversed);

        // Manual recomputation.
        let mut h_a = Sha256::new();
        h_a.update(a.as_ref());
        let leaf_a = h_a.finalize();
        let mut h_b = Sha256::new();
        h_b.update(b.as_ref());
        let leaf_b = h_b.finalize();
        let mut h_root = Sha256::new();
        h_root.update(leaf_a);
        h_root.update(leaf_b);
        let expected = Bytes32::new(h_root.finalize().into());
        assert_eq!(root_in_order, expected);
    }

    /// Odd-count level: 3 leaves → pair (0,1) at level 0, level 1 has
    /// {pair01, leaf2}; pad with leaf2 to {pair01, leaf2, leaf2,
    /// leaf2}? No — level 1 has only 2 entries (pair01 + leaf2), so
    /// level 1 already has even count. Trace: level 0 = [a, b, c] →
    /// pad to [a, b, c, c] → level 1 = [hash(a,b), hash(c,c)] → root
    /// = hash(hash(a,b), hash(c,c)).
    #[test]
    fn three_leaves_pads_last() {
        let a = b32(0x01);
        let b = b32(0x02);
        let c = b32(0x03);
        let root = merkle_root_of_sorted_coin_ids(&[c, a, b]); // unsorted

        let leaf = |id: &Bytes32| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(id.as_ref());
            h.finalize().into()
        };
        let pair = |l: [u8; 32], r: [u8; 32]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(l);
            h.update(r);
            h.finalize().into()
        };
        let la = leaf(&a);
        let lb = leaf(&b);
        let lc = leaf(&c);
        let expected = Bytes32::new(pair(pair(la, lb), pair(lc, lc)));
        assert_eq!(root, expected);
    }

    /// Determinism: same input twice → same root.
    #[test]
    fn deterministic() {
        let ids: Vec<Bytes32> = (0u8..7).map(b32).collect();
        let r1 = merkle_root_of_sorted_coin_ids(&ids);
        let r2 = merkle_root_of_sorted_coin_ids(&ids);
        assert_eq!(r1, r2);
    }
}

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
    /// Slot index → (48-byte voter pubkey, locked CAT mojos). BTreeMap
    /// so range queries (used by `subtree_hash` for sparsity
    /// short-circuit) are O(log n). The locked amount is part of the
    /// leaf preimage, so two voters with the same pubkey but
    /// different lock amounts produce different leaves (and would also
    /// be rejected by the singleton's anti-double-register check).
    leaves: BTreeMap<u32, ([u8; 48], u64)>,

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
    /// WHAT: leaf hash for a registered voter — `sha256(pubkey ||
    ///       locked_amount_be8)`. The 8-byte big-endian encoding of the
    ///       locked CAT mojos is fixed-width so concatenation is
    ///       collision-resistant.
    /// MIRRORS: `puzzles/election/register.rue` (and `deregister.rue`)
    ///          which compute the same hash via
    ///          `sha256(pk_b + int_to_8_bytes_be(locked_cat_mojos))`.
    pub fn active_leaf_hash(pubkey: &PublicKey, locked_amount: u64) -> Bytes32 {
        let pk_bytes = pubkey.to_bytes();
        active_leaf_hash_bytes(&pk_bytes, locked_amount)
    }

    /// FN: insert
    /// WHAT: add a voter to the tree at their canonical slot, binding
    ///       their locked CAT mojos into the leaf preimage.
    /// IDEMPOTENT: re-inserting the same `(pubkey, locked_amount)` is
    ///             a no-op. Re-inserting the same pubkey with a
    ///             different `locked_amount` is rejected as a
    ///             `SlotCollision` — the on-chain singleton would
    ///             reject it too (a voter can't change their lockup
    ///             without first deregistering).
    /// ERRORS: `SlotCollision` if (a) two distinct pubkeys hash to the
    ///         same slot (vanishingly unlikely — birthday-bound on 2^32
    ///         slots), or (b) the same pubkey is re-inserted with a
    ///         changed `locked_amount`.
    pub fn insert(
        &mut self,
        pubkey: &PublicKey,
        locked_amount: u64,
    ) -> Result<(), crate::VotingError> {
        let slot = Self::slot_for_pubkey(pubkey);
        let pk_bytes = pubkey.to_bytes();
        if let Some((existing_pk, existing_amount)) = self.leaves.get(&slot) {
            if existing_pk != &pk_bytes || *existing_amount != locked_amount {
                return Err(crate::VotingError::SlotCollision { slot: slot as u64 });
            }
            return Ok(());
        }
        self.leaves.insert(slot, (pk_bytes, locked_amount));
        Ok(())
    }

    /// FN: remove
    /// WHAT: wipe a voter's leaf back to `EMPTY_LEAF_HASH` —
    ///       mirrors `puzzles/election/deregister.rue`'s SPT
    ///       transition (`active_leaf` → empty leaf at the same
    ///       slot).
    /// IDEMPOTENT: removing a non-registered (or wrong-pubkey)
    ///             pubkey is a no-op so callers walking
    ///             apply_singleton_spend re-application can be safe
    ///             across repeated syncs.
    /// USAGE: `Aggregator::sync` calls this when it detects a
    ///        `deregister` CreateCoinAnnouncement on the Election
    ///        Singleton (per `deregister_announcement_msg`).
    pub fn remove(&mut self, pubkey: &PublicKey) -> bool {
        let slot = Self::slot_for_pubkey(pubkey);
        let pk_bytes = pubkey.to_bytes();
        match self.leaves.get(&slot) {
            Some((stored_pk, _)) if stored_pk == &pk_bytes => {
                self.leaves.remove(&slot);
                true
            }
            _ => false,
        }
    }

    /// FN: contains
    /// WHAT: true iff a voter pubkey is registered (occupies its
    ///       canonical slot).
    pub fn contains(&self, pubkey: &PublicKey) -> bool {
        let slot = Self::slot_for_pubkey(pubkey);
        self.leaves
            .get(&slot)
            .map(|(stored_pk, _)| stored_pk == &pubkey.to_bytes())
            .unwrap_or(false)
    }

    /// FN: locked_amount
    /// WHAT: the CAT mojos a registered voter locked at register time,
    ///       or `None` if the voter isn't registered.
    /// USAGE: aggregator's finalize witness builder reads each signer's
    ///        weight from here; deregister flow reads it to construct
    ///        the puzzle solution.
    pub fn locked_amount(&self, pubkey: &PublicKey) -> Option<u64> {
        let slot = Self::slot_for_pubkey(pubkey);
        let pk_bytes = pubkey.to_bytes();
        self.leaves
            .get(&slot)
            .filter(|(stored_pk, _)| stored_pk == &pk_bytes)
            .map(|(_, amount)| *amount)
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
                Some((pk, amount)) => active_leaf_hash_bytes(pk, *amount),
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
/// WHAT: leaf hash from raw 48-byte pubkey buffer + locked CAT mojos
///       (skip the typed PublicKey roundtrip — used inside SPT
///       recursion). Encoding: `sha256(pubkey || locked_amount_be8)`.
///       The fixed 8-byte big-endian width is collision-resistant and
///       mirrors `int_to_8_bytes_be` in the on-chain RUE puzzles.
fn active_leaf_hash_bytes(pk_bytes: &[u8; 48], locked_amount: u64) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(pk_bytes);
    h.update(locked_amount.to_be_bytes());
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
// PoseidonSmt — SNARK-friendly registration accumulator (F1 step 4)
// ============================================================================
//
// Off-chain mirror of the Poseidon-over-Fr registration tree the F1 redesign
// uses: leaf = Poseidon `hash_leaf(jubjub_px, jubjub_py, weight)`, node =
// Poseidon `hash2(left, right)`, depth `TREE_DEPTH`. This is the SAME tree the
// in-circuit membership proof (`prover::circuit_v2`) and the on-chain
// `puzzles/poseidon.rue` verify against — `poseidon_perm` is the shared
// primitive, so a proof produced here verifies in the circuit (pinned by
// `poseidon_smt_proof_verifies_in_circuit`).
//
// Identity: a voter is keyed by their JUBJUB signing key (the key the circuit
// checks the Schnorr signature for). The slot is derived from that key. The
// root serialises as the 32-byte big-endian form of the Fr root (field
// elements are < P < 2^255 so this is canonical and matches the integer the
// circuit consumes as a public input).
//
// Built ALONGSIDE the live SHA256 `SparseMerkleTree`; wiring it into
// register/deregister + the aggregator is the atomic on-chain migration that
// follows (see docs/F1-finalize-redesign.md step 4).

use crate::prover::poseidon_perm::{cfg as poseidon_cfg, hash2, hash_leaf};
use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::EdwardsAffine as JubAffine;
use ark_ff::{BigInteger, PrimeField};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

/// Serialise an Fr as a 32-byte big-endian array (zero-padded).
pub fn fr_to_be32(f: Fr) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

/// Poseidon membership proof: `TREE_DEPTH` sibling field elements (leaf→root)
/// plus the direction bits (true ⇒ this node is the right child).
pub struct PoseidonProof {
    pub siblings: Vec<Fr>,
    pub bits: Vec<bool>,
}

/// Sparse Poseidon Merkle tree over Jubjub-keyed registration leaves.
pub struct PoseidonSmt {
    cfg: PoseidonConfig<Fr>,
    depth: usize,
    /// `empties[i]` = root of an all-empty subtree of height `i`
    /// (`empties[0]` = empty leaf = 0).
    empties: Vec<Fr>,
    /// slot → leaf hash.
    leaves: BTreeMap<u32, Fr>,
}

impl PoseidonSmt {
    pub fn new() -> Self {
        Self::with_depth(TREE_DEPTH as usize)
    }

    pub fn with_depth(depth: usize) -> Self {
        let cfg = poseidon_cfg();
        let mut empties = vec![Fr::from(0u64)];
        for i in 0..depth {
            let p = empties[i];
            empties.push(hash2(&cfg, p, p));
        }
        Self {
            cfg,
            depth,
            empties,
            leaves: BTreeMap::new(),
        }
    }

    /// Canonical slot for a Jubjub key: first 4 bytes of
    /// `sha256(px_be32 || py_be32)`, big-endian — masked to `depth` bits.
    pub fn slot_for_jubjub(px: Fr, py: Fr) -> u32 {
        let mut h = Sha256::new();
        h.update(fr_to_be32(px));
        h.update(fr_to_be32(py));
        let d = h.finalize();
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    fn slot_masked(&self, px: Fr, py: Fr) -> u32 {
        let raw = Self::slot_for_jubjub(px, py);
        if self.depth >= 32 {
            raw
        } else {
            raw & ((1u32 << self.depth) - 1)
        }
    }

    /// The registration leaf for a Jubjub key + weight.
    pub fn leaf_hash(&self, px: Fr, py: Fr, weight: u64) -> Fr {
        hash_leaf(&self.cfg, px, py, weight)
    }

    pub fn insert(&mut self, pubkey: JubAffine, weight: u64) {
        let slot = self.slot_masked(pubkey.x, pubkey.y);
        let leaf = self.leaf_hash(pubkey.x, pubkey.y, weight);
        self.leaves.insert(slot, leaf);
    }

    /// Wipe a voter's leaf back to empty (the on-chain `deregister` action's
    /// SPT update). Returns whether a leaf was present. Idempotent.
    pub fn remove(&mut self, pubkey: JubAffine) -> bool {
        let slot = self.slot_masked(pubkey.x, pubkey.y);
        self.leaves.remove(&slot).is_some()
    }

    /// True iff this Jubjub key currently occupies its slot.
    pub fn contains(&self, pubkey: JubAffine) -> bool {
        let slot = self.slot_masked(pubkey.x, pubkey.y);
        self.leaves.contains_key(&slot)
    }

    /// Hash of the subtree spanning slots `[lo, hi)` at remaining `level`
    /// (caller guarantees `hi - lo == 2^level`). u64 bounds avoid u32
    /// overflow at the top level (lo=0, hi=2^32). Mirrors the SHA256
    /// `SparseMerkleTree::subtree_hash`.
    fn subtree_hash(&self, lo: u64, hi: u64, level: usize) -> Fr {
        if level == 0 {
            return *self.leaves.get(&(lo as u32)).unwrap_or(&self.empties[0]);
        }
        if !self.range_has_any(lo, hi) {
            return self.empties[level];
        }
        let mid = lo + ((hi - lo) >> 1);
        let l = self.subtree_hash(lo, mid, level - 1);
        let r = self.subtree_hash(mid, hi, level - 1);
        hash2(&self.cfg, l, r)
    }

    fn range_has_any(&self, lo: u64, hi: u64) -> bool {
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

    pub fn root(&self) -> Fr {
        self.subtree_hash(0, 1u64 << self.depth, self.depth)
    }

    /// Root serialised for on-chain state / circuit public input.
    pub fn root_be32(&self) -> [u8; 32] {
        fr_to_be32(self.root())
    }

    /// Membership / emptiness proof for a slot: `depth` sibling hashes
    /// (leaf→root) + direction bits (true ⇒ node is the right child).
    pub fn prove(&self, index: u32) -> PoseidonProof {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut bits = Vec::with_capacity(self.depth);
        for level in 0..self.depth {
            let sibling_parent = ((index as u64) >> level) ^ 1;
            let span = 1u64 << level;
            let sibling_lo = sibling_parent * span;
            let sibling_hi = sibling_lo + span;
            siblings.push(self.subtree_hash(sibling_lo, sibling_hi, level));
            bits.push(((index as u64) >> level) & 1 == 1);
        }
        PoseidonProof { siblings, bits }
    }

    pub fn prove_jubjub(&self, px: Fr, py: Fr) -> PoseidonProof {
        self.prove(self.slot_masked(px, py))
    }
}

impl Default for PoseidonSmt {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod poseidon_smt_tests {
    use super::*;
    use crate::prover::circuit_v2::{keygen, schnorr_sign, SignerV2, VotingCircuitV2};
    use ark_ed_on_bls12_381::Fr as JubScalar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    /// A single-leaf Poseidon tree's membership proof reconstructs the root.
    #[test]
    fn poseidon_smt_proof_reconstructs_root() {
        let cfg = poseidon_cfg();
        let mut tree = PoseidonSmt::with_depth(16);
        let p = keygen(JubScalar::from(9u64));
        tree.insert(p, 1_000);
        let slot = {
            let raw = PoseidonSmt::slot_for_jubjub(p.x, p.y);
            raw & ((1u32 << 16) - 1)
        };
        let proof = tree.prove(slot);
        // Reconstruct: leaf, then fold siblings per direction bits.
        let mut node = tree.leaf_hash(p.x, p.y, 1_000);
        for (sib, &is_right) in proof.siblings.iter().zip(proof.bits.iter()) {
            node = if is_right {
                hash2(&cfg, *sib, node)
            } else {
                hash2(&cfg, node, *sib)
            };
        }
        assert_eq!(node, tree.root(), "proof must reconstruct the root");
    }

    /// `remove` wipes a leaf so the root returns to the empty-tree root
    /// (the on-chain `deregister` SPT update).
    #[test]
    fn poseidon_smt_remove_restores_empty_root() {
        let mut tree = PoseidonSmt::with_depth(16);
        let empty_root = tree.root();
        let p = keygen(JubScalar::from(123u64));
        tree.insert(p, 1_000);
        assert!(tree.contains(p));
        assert_ne!(tree.root(), empty_root, "insert must change the root");
        assert!(tree.remove(p), "remove returns true when present");
        assert!(!tree.contains(p));
        assert_eq!(tree.root(), empty_root, "remove must restore the empty root");
        assert!(!tree.remove(p), "remove is idempotent (false when absent)");
    }

    /// LOAD-BEARING: a PoseidonSmt membership proof satisfies the in-circuit
    /// membership constraint of `circuit_v2` — i.e. the off-chain accumulator
    /// and the Groth16 circuit agree on the SAME tree. (Combined with the Rue
    /// parity test, all three layers share one accumulator.)
    #[test]
    fn poseidon_smt_proof_verifies_in_circuit() {
        let depth = 20usize;
        let cfg = poseidon_cfg();
        let mut tree = PoseidonSmt::with_depth(depth);
        let x = JubScalar::from(42u64);
        let p = keygen(x);
        let weight = 1_000u64;
        tree.insert(p, weight);
        let proof = tree.prove_jubjub(p.x, p.y);
        let root = tree.root();

        let vote_message = Fr::from(0xABCDEFu64);
        let (r, s) = schnorr_sign(&cfg, x, JubScalar::from(7u64), vote_message);
        let signer = SignerV2 {
            pubkey: p,
            weight,
            path: proof.siblings,
            path_bits: proof.bits,
            sig_r: r,
            sig_s: s,
            present: true,
        };
        let circuit = VotingCircuitV2 {
            registration_root: root,
            vote_message,
            registration_vote_weight: weight,
            vote_threshold_num: 1,
            vote_threshold_den: 2,
            depth,
            max_signers: 1,
            signers: vec![signer],
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "PoseidonSmt proof must satisfy circuit_v2 membership"
        );
    }
}

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
        tree.insert(&pk_at(0), 1).unwrap();
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
        t1.insert(&pk_at(0), 1).unwrap();
        let r_after_first = t1.root();
        t1.insert(&pk_at(0), 1).unwrap();
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
        tree.insert(&pk, 1).unwrap();
        let slot = SparseMerkleTree::slot_for_pubkey(&pk);
        let leaf = SparseMerkleTree::active_leaf_hash(&pk, 1);
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
        tree.insert(&pk_at(0), 1).unwrap(); // someone else
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
        tree.insert(&pk, 1).unwrap();
        let slot = SparseMerkleTree::slot_for_pubkey(&pk);
        let proof = tree.prove(slot);
        let root = tree.root();

        let active_leaf = SparseMerkleTree::active_leaf_hash(&pk, 1);
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
        t1.insert(&pk_at(0), 1).unwrap();
        let r1 = t1.root();

        let mut t2 = SparseMerkleTree::new();
        t2.insert(&pk_at(0), 1).unwrap();
        t2.insert(&pk_at(1), 1).unwrap();
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
            t1.insert(&pk_at(i), 1).unwrap();
        }
        for i in (0..5u32).rev() {
            t2.insert(&pk_at(i), 1).unwrap();
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
        tree.insert(&pk, 1).unwrap();
        assert!(tree.contains(&pk));
        assert_eq!(tree.len(), 1);
    }

    /// WHAT: voters with different `locked_amount` produce different
    ///       leaf hashes and therefore different roots.
    /// HOW:  insert pk into two trees with different amounts; assert
    ///       roots differ AND leaf hashes differ.
    /// WHY:  weighted voting requires the locked amount to be bound
    ///       into the leaf preimage so the on-chain register /
    ///       deregister actions can verify it without trusting the
    ///       running `registration_vote_weight` total.
    #[test]
    fn leaf_binds_locked_amount() {
        let pk = pk_at(0);
        let mut t_a = SparseMerkleTree::new();
        let mut t_b = SparseMerkleTree::new();
        t_a.insert(&pk, 1_000).unwrap();
        t_b.insert(&pk, 5_000).unwrap();
        assert_ne!(t_a.root(), t_b.root());
        assert_ne!(
            SparseMerkleTree::active_leaf_hash(&pk, 1_000),
            SparseMerkleTree::active_leaf_hash(&pk, 5_000),
        );
    }

    /// WHAT: re-inserting the same pubkey with a CHANGED locked amount
    ///       is rejected as a slot collision.
    /// WHY:  on chain, a voter cannot mutate their lockup without
    ///       first deregistering — the SMT must surface the same
    ///       constraint or a chain replay would build a divergent
    ///       state.
    #[test]
    fn changing_locked_amount_rejected_as_slot_collision() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        tree.insert(&pk, 1_000).unwrap();
        let err = tree.insert(&pk, 2_000).unwrap_err();
        match err {
            crate::VotingError::SlotCollision { .. } => {}
            other => panic!("expected SlotCollision, got {other:?}"),
        }
    }

    /// WHAT: a proof for a weighted leaf verifies against the new root
    ///       AND a proof using the WRONG amount is rejected.
    /// WHY:  this is the round-trip the on-chain register action
    ///       performs: it computes `sha256(pk || amount_be8)` and
    ///       walks the proof up to the curried merkle root. Forgery
    ///       resistance requires that swapping in a different amount
    ///       — even by 1 mojo — breaks verification.
    #[test]
    fn weighted_proof_roundtrip_and_forgery_resistance() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        let lock = 1_234_567u64;
        tree.insert(&pk, lock).unwrap();
        let slot = SparseMerkleTree::slot_for_pubkey(&pk);
        let proof = tree.prove(slot);
        let root = tree.root();

        let real_leaf = SparseMerkleTree::active_leaf_hash(&pk, lock);
        let wrong_leaf = SparseMerkleTree::active_leaf_hash(&pk, lock + 1);

        assert!(verify_proof(real_leaf, slot, &proof, root));
        assert!(!verify_proof(wrong_leaf, slot, &proof, root));
        assert_eq!(tree.locked_amount(&pk), Some(lock));
    }

    /// WHAT: `locked_amount(pk)` round-trips for inserted voters and
    ///       returns `None` for un-registered ones.
    #[test]
    fn locked_amount_lookup() {
        let mut tree = SparseMerkleTree::new();
        let pk = pk_at(0);
        let other = pk_at(1);
        tree.insert(&pk, 9_999).unwrap();
        assert_eq!(tree.locked_amount(&pk), Some(9_999));
        assert_eq!(tree.locked_amount(&other), None);
    }
}
