// ============================================================================
// vote_mode.rs — per-ballot voting mode + election-level lock
// ============================================================================
//
// MODULE: vote_mode
// PURPOSE: typed mirrors of the on-chain vote-mode commitments. Each
//          ballot commits a `vote_options_root` in its curry; the
//          election can OPTIONALLY commit a `vote_mode_lock` in
//          `ElectionState` that constrains every ballot's mode.
//
// SEMANTICS:
//   * Mode 1 (Free): vote_options_root = 0x00…00. cast_vote /
//     update_vote skip the merkle inclusion proof. Any vote value is
//     accepted.
//   * Mode 2 (Restricted): vote_options_root = sorted-merkle-root over
//     a set of allowed option-hashes. cast_vote / update_vote MUST
//     verify a merkle inclusion proof of `sha256(vote_value)` against
//     the root. Up to 64 options per ballot.
//   * Election lock: ElectionState.vote_mode_lock. Sentinel
//     `0xFF…FF` (= VOTE_MODE_LOCK_NONE) means "no lock — each ballot
//     picks its own mode at create_ballot time". Any other value
//     forces every ballot to commit that exact vote_options_root.
//
// SENTINEL SPLIT: the all-ones (no-lock) and all-zeros (lock-to-Free)
// sentinels are deliberately distinct so a deployer can lock the
// election to Mode1Free explicitly without that being confused with
// the absence of a lock.

use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};

/// Sentinel `vote_mode_lock` value meaning "election does NOT lock
/// the per-ballot mode — each ballot creator is free to commit any
/// `vote_options_root`". MUST stay byte-identical to the rue-side
/// sentinel pinned in `puzzles/election/create_ballot.rue`.
pub const VOTE_MODE_LOCK_NONE: Bytes32 = Bytes32::new([0xFF; 32]);

/// Sentinel `vote_options_root` value meaning "this ballot is
/// Mode1Free — cast_vote / update_vote skip merkle gating". Equal to
/// `Bytes32::default()`.
pub const VOTE_OPTIONS_ROOT_FREE: Bytes32 = Bytes32::new([0x00; 32]);

/// Maximum number of allowed options per Mode2Restricted ballot.
/// Bounded so on-chain merkle proofs stay cheap (depth ≤ 6 ⇒ ≤ 6
/// sibling hashes per cast_vote).
pub const MAX_VOTE_OPTIONS: usize = 64;

/// ENUM: BallotVoteMode
/// PURPOSE: deployer-side / dApp-side typed wrapper. Converts to the
///          on-chain `vote_options_root: Bytes32` commitment via
///          [`vote_options_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BallotVoteMode {
    /// Any vote value accepted. On-chain commitment = all-zeros.
    Free,
    /// Only votes whose `sha256(vote_value)` is in `options` are
    /// accepted. On-chain commitment = sorted-merkle-root over
    /// `options`.
    Restricted { options: Vec<Bytes32> },
}

impl BallotVoteMode {
    /// FN: vote_options_root
    /// WHAT: on-chain commitment for this mode.
    pub fn vote_options_root(&self) -> Bytes32 {
        match self {
            Self::Free => VOTE_OPTIONS_ROOT_FREE,
            Self::Restricted { options } => sorted_merkle_root(options),
        }
    }

    /// FN: validate
    /// CHECKS:
    ///   * Free: always Ok.
    ///   * Restricted: 1..=MAX_VOTE_OPTIONS options, all distinct.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Free => Ok(()),
            Self::Restricted { options } => {
                if options.is_empty() {
                    return Err("BallotVoteMode::Restricted requires at least 1 option");
                }
                if options.len() > MAX_VOTE_OPTIONS {
                    return Err("BallotVoteMode::Restricted exceeds MAX_VOTE_OPTIONS");
                }
                let mut sorted = options.clone();
                sorted.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
                for w in sorted.windows(2) {
                    if w[0] == w[1] {
                        return Err("BallotVoteMode::Restricted has duplicate options");
                    }
                }
                Ok(())
            }
        }
    }

    /// FN: merkle_proof_for_option
    /// WHAT: produce the inclusion proof for `option_hash` against
    ///       `self.vote_options_root()`. Returns `None` if the mode
    ///       is `Free` or if `option_hash` is not in the option set.
    /// PROOF SHAPE: a `Vec<Bytes32>` of sibling node hashes from the
    ///              option's leaf upward to the root, in level order.
    ///              The cast_vote rue puzzle consumes this as a
    ///              `HashCons` (head = first sibling, tail = the rest).
    pub fn merkle_proof_for_option(
        &self,
        option_hash: Bytes32,
    ) -> Option<(usize, Vec<Bytes32>)> {
        let options = match self {
            Self::Free => return None,
            Self::Restricted { options } => options,
        };
        let mut sorted = options.clone();
        sorted.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        let original_idx = sorted.iter().position(|o| *o == option_hash)?;
        let mut idx = original_idx;
        // Hash leaves first.
        let mut level: Vec<Bytes32> =
            sorted.into_iter().map(|id| sha256_of(id.as_ref())).collect();
        let mut proof: Vec<Bytes32> = Vec::new();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = level[level.len() - 1];
                level.push(last);
            }
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proof.push(level[sibling_idx]);
            // Move up.
            let mut next = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks_exact(2) {
                let mut h = Sha256::new();
                h.update(chunk[0].as_ref());
                h.update(chunk[1].as_ref());
                next.push(Bytes32::new(h.finalize().into()));
            }
            level = next;
            idx /= 2;
        }
        Some((original_idx, proof))
    }
}

/// FN: verify_merkle_inclusion
/// WHAT: index-aware verifier matching `merkle_proof_for_option`'s
///       output. Mirrors the cast_vote.rue puzzle's gate exactly.
/// FORMULA: leaf = sha256(option_hash); for each (sibling, bit) in
///          (proof, leaf_index_bits_low_to_high):
///              parent = if bit == 0 { sha256(leaf || sibling) }
///                       else        { sha256(sibling || leaf) }
pub fn verify_merkle_inclusion(
    option_hash: Bytes32,
    leaf_index: usize,
    proof: &[Bytes32],
    expected_root: Bytes32,
) -> bool {
    let mut node = sha256_of(option_hash.as_ref());
    let mut idx = leaf_index;
    for sib in proof {
        let mut h = Sha256::new();
        if idx % 2 == 0 {
            h.update(node.as_ref());
            h.update(sib.as_ref());
        } else {
            h.update(sib.as_ref());
            h.update(node.as_ref());
        }
        node = Bytes32::new(h.finalize().into());
        idx /= 2;
    }
    node == expected_root
}

/// FN: verify_merkle_inclusion
/// WHAT: independent verifier — given a leaf option-hash, its sibling
///       proof, and the root, recompute the root from the proof and
///       compare. Mirrors what the rue cast_vote puzzle does
///       on-chain. Returns `true` iff `option_hash` is committed in
///       the tree whose root is `expected_root`.
/// FORMULA: leaf_hash = sha256(option_hash);
///          for each sibling in proof:
///              parent = if leaf < sibling { sha256(leaf || sibling) }
///                       else              { sha256(sibling || leaf) }
///          (sort-by-content pairing — symmetric, no leaf-index needed)
/// NOTE: this verifier is sort-aware, but `merkle_proof_for_option`
///       above produces an INDEX-aware proof (matches
///       `merkle_root_of_sorted_coin_ids`). Both verifiers below
///       (sort-aware + index-aware) are kept so the rue puzzle can
///       pick whichever is cheaper to encode in CLVM.
pub fn verify_merkle_inclusion_sort(
    option_hash: Bytes32,
    proof: &[Bytes32],
    expected_root: Bytes32,
) -> bool {
    let mut node = sha256_of(option_hash.as_ref());
    for sib in proof {
        let mut h = Sha256::new();
        if node.as_ref() < sib.as_ref() {
            h.update(node.as_ref());
            h.update(sib.as_ref());
        } else {
            h.update(sib.as_ref());
            h.update(node.as_ref());
        }
        node = Bytes32::new(h.finalize().into());
    }
    node == expected_root
}

/// FN: sorted_merkle_root
/// WHAT: byte-identical root of `options` to what
///       `merkle_root_of_sorted_coin_ids` produces — kept here as a
///       file-private alias to make the dependency direction explicit
///       (vote_mode → merkle).
fn sorted_merkle_root(options: &[Bytes32]) -> Bytes32 {
    crate::merkle::merkle_root_of_sorted_coin_ids(options)
}

fn sha256_of(input: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(input);
    Bytes32::new(h.finalize().into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

    /// WHAT: Free mode commits to the all-zeros sentinel.
    /// HOW:  construct Free, call vote_options_root(), assert ==
    ///       VOTE_OPTIONS_ROOT_FREE.
    /// WHY:  cast_vote.rue's mode discrimination depends on this
    ///       exact sentinel byte-for-byte.
    #[test]
    fn free_mode_root_is_zero() {
        let m = BallotVoteMode::Free;
        assert_eq!(m.vote_options_root(), VOTE_OPTIONS_ROOT_FREE);
    }

    /// WHAT: Restricted mode commits to the sorted merkle root.
    /// HOW:  build a 3-option Restricted, compare to direct call of
    ///       merkle_root_of_sorted_coin_ids.
    #[test]
    fn restricted_mode_root_matches_sorted_merkle() {
        let m = BallotVoteMode::Restricted {
            options: vec![b32(0x03), b32(0x01), b32(0x02)],
        };
        let mut sorted = vec![b32(0x03), b32(0x01), b32(0x02)];
        sorted.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        assert_eq!(
            m.vote_options_root(),
            crate::merkle::merkle_root_of_sorted_coin_ids(&sorted),
        );
    }

    /// WHAT: validate rejects empty / oversized / duplicate option sets.
    #[test]
    fn validate_rejects_bad_inputs() {
        assert!(
            BallotVoteMode::Restricted { options: vec![] }
                .validate()
                .is_err()
        );
        let oversized: Vec<Bytes32> = (0..=MAX_VOTE_OPTIONS as u8).map(b32).collect();
        assert!(
            BallotVoteMode::Restricted { options: oversized }
                .validate()
                .is_err()
        );
        assert!(
            BallotVoteMode::Restricted {
                options: vec![b32(0x01), b32(0x02), b32(0x01)]
            }
            .validate()
            .is_err()
        );
    }

    /// WHAT: validate accepts Free and well-formed Restricted.
    #[test]
    fn validate_accepts_good_inputs() {
        BallotVoteMode::Free.validate().unwrap();
        BallotVoteMode::Restricted {
            options: vec![b32(0x01), b32(0x02), b32(0x03)],
        }
        .validate()
        .unwrap();
    }

    /// WHAT: merkle_proof_for_option round-trips through the
    ///       sort-aware verifier for every option in a Restricted set.
    /// HOW:  build a 4-option Restricted, derive its root, and for
    ///       each option compute a proof and verify it.
    /// WHY:  this is the core invariant cast_vote.rue relies on. The
    ///       SDK's proof builder MUST produce something the on-chain
    ///       verifier accepts.
    #[test]
    fn proof_for_each_option_round_trips() {
        let opts = vec![b32(0x01), b32(0x02), b32(0x03), b32(0x04)];
        let m = BallotVoteMode::Restricted { options: opts.clone() };
        let root = m.vote_options_root();
        for opt in &opts {
            let (idx, proof) = m
                .merkle_proof_for_option(*opt)
                .expect("proof for committed option");
            assert!(
                verify_merkle_inclusion(*opt, idx, &proof, root),
                "round-trip failed for option {:?}",
                opt,
            );
        }
    }

    /// WHAT: merkle_proof_for_option returns None for a non-committed
    ///       option AND for the Free variant.
    #[test]
    fn proof_returns_none_for_unknown_or_free() {
        let m = BallotVoteMode::Restricted {
            options: vec![b32(0x01), b32(0x02)],
        };
        assert!(m.merkle_proof_for_option(b32(0xff)).is_none());
        assert!(BallotVoteMode::Free.merkle_proof_for_option(b32(0x01)).is_none());
    }

    /// WHAT: VOTE_MODE_LOCK_NONE is exactly 0xFF…FF.
    #[test]
    fn vote_mode_lock_none_is_all_ones() {
        assert_eq!(VOTE_MODE_LOCK_NONE, Bytes32::new([0xFF; 32]));
    }
}
