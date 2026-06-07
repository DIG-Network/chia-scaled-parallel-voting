// ============================================================================
// prover/circuit_v2.rs — F1 redesign: in-circuit signer-set membership (WIP)
// ============================================================================
//
// STATUS: research-grade WORK IN PROGRESS toward closing finding F1
// (finalize forgery — see docs/F1-finalize-redesign.md). This module is
// built ALONGSIDE the live `circuit.rs`/`finalize.rue` path and is NOT yet
// wired into finalization, so the existing test suite stays green.
//
// WHAT THIS PROVES (the shared foundation both redesign options need):
//   * G2 — per-signer MEMBERSHIP: each present signer's leaf
//     `Poseidon(pubkey_id, weight)` is verified, IN-CIRCUIT, against a
//     depth-`DEPTH` Poseidon Merkle root that is a public input. A signer
//     who is not actually in the tree CANNOT produce a satisfying witness.
//   * G1 — WEIGHT/threshold: the summed VERIFIED weight meets the curried
//     quorum threshold (`signed * den >= num * total`), so the numerator is
//     the real registered weight, not a free witness.
//
// WHY POSEIDON (not the production SHA256 SPT): in-circuit SHA256 is
// ~1M constraints per depth-32 membership proof — infeasible at scale.
// Poseidon is ~8–10k constraints per proof. The production redesign
// migrates the registration accumulator to Poseidon on-chain too
// (register/deregister) — see the design doc.
//
// WHAT IS NOT DONE HERE (the remaining F1 work):
//   * G3 — binding `agg_signers` to the proven set. In-circuit BLS12-381
//     G1 addition over an `Fr` constraint system is structurally absent in
//     arkworks 0.4 (verified). The recommended resolution (design doc
//     Option B) is to drop the BLS aggregate and have each signer sign
//     `vote_message` with a SNARK-friendly signature verified in-circuit.
//     This module does not yet verify signatures.
//   * Real pubkey encoding (a 48-byte G1 key → multiple Fr limbs) — here a
//     single `pubkey_id: Fr` stands in for the voter identity.
//   * A range proof on the threshold `slack` (currently mirrors the
//     existing circuit's slack-identity; a bit-decomposition range check is
//     required for full soundness).
//   * Matching the on-chain finalize.rue public-input encoding / VK.
//
// The unit tests below pin the load-bearing property: a forged signer set
// (a member with a tampered leaf, or a non-member with a bogus path)
// fails to satisfy the constraints — which is exactly what closes F1's
// "fabricated weight / unregistered signer" forgery at the circuit level.

use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Canonical 2-to-1 Poseidon parameters over BLS12-381 `Fr`.
///
/// NOTE: `find_poseidon_ark_and_mds` deterministically derives the round
/// constants + MDS for the given (rounds, width). The round numbers here
/// are a reasonable width-3 set; a production deployment MUST pin an
/// audited parameter set (and the SAME set is used on-chain in the
/// Poseidon-in-Rue register verifier and in `sdk/src/merkle.rs`).
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8usize;
    let partial_rounds = 57usize;
    let alpha = 5u64;
    let rate = 2usize;
    let capacity = 1usize;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig::<Fr>::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

/// Off-circuit 2-to-1 Poseidon compression — MUST match the in-circuit
/// `TwoToOneCRHGadget::compress` so test witnesses reconstruct the same
/// root the circuit computes.
pub fn poseidon2(cfg: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::compress(cfg, left, right)
        .expect("poseidon compress")
}

/// A single signer's private membership witness (prototype encoding).
#[derive(Clone, Debug)]
pub struct SignerV2 {
    /// Field-element stand-in for the voter's identity (production: an
    /// Fr commitment to the 48-byte G1 pubkey).
    pub pubkey_id: Fr,
    /// The voter's registered weight (bound into the leaf).
    pub weight: u64,
    /// Sibling hashes leaf→root (length == DEPTH).
    pub path: Vec<Fr>,
    /// Direction bits leaf→root (true ⇒ this node is the RIGHT child).
    pub path_bits: Vec<bool>,
    /// Whether this fixed slot carries a real signer (false ⇒ padded).
    pub present: bool,
}

impl SignerV2 {
    /// The leaf value the tree commits: `Poseidon(pubkey_id, weight)`.
    pub fn leaf(&self, cfg: &PoseidonConfig<Fr>) -> Fr {
        poseidon2(cfg, self.pubkey_id, Fr::from(self.weight))
    }

    /// Reconstruct the root this witness implies (off-circuit; for tests).
    pub fn implied_root(&self, cfg: &PoseidonConfig<Fr>) -> Fr {
        let mut node = self.leaf(cfg);
        for (sib, &is_right) in self.path.iter().zip(self.path_bits.iter()) {
            node = if is_right {
                poseidon2(cfg, *sib, node)
            } else {
                poseidon2(cfg, node, *sib)
            };
        }
        node
    }

    fn padding(depth: usize) -> Self {
        Self {
            pubkey_id: Fr::from(0u64),
            weight: 0,
            path: vec![Fr::from(0u64); depth],
            path_bits: vec![false; depth],
            present: false,
        }
    }
}

/// F1-redesign membership+weight circuit (WIP — see module docs).
#[derive(Clone)]
pub struct VotingCircuitV2 {
    // ── Public inputs ──
    /// Poseidon registration-tree root snapshot.
    pub registration_root: Fr,
    /// Total registered weight (threshold denominator base).
    pub registration_vote_weight: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    // ── Fixed shape ──
    pub depth: usize,
    pub max_signers: usize,
    // ── Private witnesses ──
    pub signers: Vec<SignerV2>,
}

impl VotingCircuitV2 {
    /// Pad the signer set to the fixed `max_signers` shape so the QAP /
    /// VK is independent of the actual signer count.
    pub fn padded_signers(&self) -> Vec<SignerV2> {
        let mut s = self.signers.clone();
        while s.len() < self.max_signers {
            s.push(SignerV2::padding(self.depth));
        }
        s
    }

    /// Sum of present signers' weights (off-circuit helper).
    pub fn signed_weight(&self) -> u64 {
        self.signers
            .iter()
            .filter(|s| s.present)
            .map(|s| s.weight)
            .sum()
    }
}

impl ConstraintSynthesizer<Fr> for VotingCircuitV2 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cfg = poseidon_config();
        let params = CRHParametersVar::<Fr>::new_constant(cs.clone(), cfg)?;

        // Public inputs.
        let root_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.registration_root))?;
        let total_weight_var =
            FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.registration_vote_weight)))?;
        let num_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.vote_threshold_num)))?;
        let den_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.vote_threshold_den)))?;

        let signers = self.padded_signers();

        // Accumulate verified weight.
        let mut acc_weight = FpVar::<Fr>::zero();

        for s in &signers {
            // present flag (Boolean).
            let present = Boolean::new_witness(cs.clone(), || Ok(s.present))?;

            // leaf = Poseidon(pubkey_id, weight).
            let pubkey_id = FpVar::<Fr>::new_witness(cs.clone(), || Ok(s.pubkey_id))?;
            let weight = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(s.weight)))?;
            let leaf = TwoToOneCRHGadget::<Fr>::compress(&params, &pubkey_id, &weight)?;

            // Walk the Poseidon Merkle path to a computed root.
            let mut node = leaf;
            for level in 0..self.depth {
                let sib =
                    FpVar::<Fr>::new_witness(cs.clone(), || Ok(s.path[level]))?;
                let is_right =
                    Boolean::new_witness(cs.clone(), || Ok(s.path_bits[level]))?;
                // left  = is_right ? sib  : node
                // right = is_right ? node : sib
                let left = is_right.select(&sib, &node)?;
                let right = is_right.select(&node, &sib)?;
                node = TwoToOneCRHGadget::<Fr>::compress(&params, &left, &right)?;
            }

            // MEMBERSHIP (G2): for a PRESENT signer the reconstructed root
            // MUST equal the public registration root. Absent/padded slots
            // are exempt (their bogus path is ignored). `conditional_enforce_equal`
            // adds the constraint `node == root` gated on `present`.
            node.conditional_enforce_equal(&root_var, &present)?;

            // Accumulate present·weight.
            let contribution = present.select(&weight, &FpVar::<Fr>::zero())?;
            acc_weight += contribution;
        }

        // THRESHOLD (G1): acc_weight * den >= num * total_weight, encoded
        // via a slack witness identity (acc*den - num*total == slack).
        // NOTE (WIP): a bit-decomposition range proof on `slack` is still
        // required for full soundness — see module docs.
        let lhs = &acc_weight * &den_var;
        let rhs = &num_var * &total_weight_var;
        let slack_val = {
            let signed = self.signed_weight() as u128;
            let lhs_v = signed * self.vote_threshold_den as u128;
            let rhs_v = self.vote_threshold_num as u128 * self.registration_vote_weight as u128;
            if lhs_v < rhs_v {
                return Err(SynthesisError::Unsatisfiable);
            }
            Fr::from(lhs_v - rhs_v)
        };
        let slack = FpVar::<Fr>::new_witness(cs.clone(), || Ok(slack_val))?;
        (lhs - rhs).enforce_equal(&slack)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;
    use std::collections::BTreeMap;

    /// Run a circuit's constraints on a fresh CS and report satisfiability —
    /// the definitive unit-level test of the gadget logic.
    fn is_satisfied(c: VotingCircuitV2) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match c.generate_constraints(cs.clone()) {
            Ok(()) => cs.is_satisfied().unwrap_or(false),
            Err(_) => false, // e.g. below-threshold short-circuit
        }
    }

    /// Tiny off-circuit Poseidon Merkle tree for building test witnesses.
    struct TestTree {
        cfg: PoseidonConfig<Fr>,
        depth: usize,
        empty: Vec<Fr>, // empty subtree hash per level (0 = leaf)
        leaves: BTreeMap<u64, Fr>,
    }

    impl TestTree {
        fn new(depth: usize) -> Self {
            let cfg = poseidon_config();
            let mut empty = vec![Fr::from(0u64)];
            for i in 0..depth {
                let prev = empty[i];
                empty.push(poseidon2(&cfg, prev, prev));
            }
            Self {
                cfg,
                depth,
                empty,
                leaves: BTreeMap::new(),
            }
        }

        fn insert(&mut self, index: u64, leaf: Fr) {
            self.leaves.insert(index, leaf);
        }

        fn node(&self, level: usize, idx: u64) -> Fr {
            if level == 0 {
                return *self.leaves.get(&idx).unwrap_or(&self.empty[0]);
            }
            let span = 1u64 << level;
            // Does any leaf fall under [idx*span, (idx+1)*span)?
            let lo = idx * span;
            let hi = lo + span;
            if self.leaves.range(lo..hi).next().is_none() {
                return self.empty[level];
            }
            let l = self.node(level - 1, idx * 2);
            let r = self.node(level - 1, idx * 2 + 1);
            poseidon2(&self.cfg, l, r)
        }

        fn root(&self) -> Fr {
            self.node(self.depth, 0)
        }

        fn proof(&self, mut index: u64) -> (Vec<Fr>, Vec<bool>) {
            let mut path = Vec::with_capacity(self.depth);
            let mut bits = Vec::with_capacity(self.depth);
            for level in 0..self.depth {
                let sibling_idx = index ^ 1;
                path.push(self.node(level, sibling_idx));
                // is_right == current node is the right child == index odd
                bits.push(index & 1 == 1);
                index >>= 1;
            }
            (path, bits)
        }
    }

    fn build_signer(tree: &TestTree, index: u64, pubkey_id: Fr, weight: u64) -> SignerV2 {
        let (path, path_bits) = tree.proof(index);
        SignerV2 {
            pubkey_id,
            weight,
            path,
            path_bits,
            present: true,
        }
    }

    fn rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(0xF1_C0DE)
    }

    /// A small registration tree with two voters; a 2/3-quorum proof over
    /// BOTH of them verifies, and the SAME setup REJECTS a forged signer
    /// whose leaf is not in the tree.
    fn setup_tree() -> (TestTree, SignerV2, SignerV2, u64) {
        let depth = 8usize;
        let cfg = poseidon_config();
        let mut tree = TestTree::new(depth);
        let (pk_a, w_a) = (Fr::from(111u64), 1_000u64);
        let (pk_b, w_b) = (Fr::from(222u64), 2_000u64);
        let (idx_a, idx_b) = (5u64, 42u64);
        tree.insert(idx_a, poseidon2(&cfg, pk_a, Fr::from(w_a)));
        tree.insert(idx_b, poseidon2(&cfg, pk_b, Fr::from(w_b)));
        let total = w_a + w_b;
        let sa = build_signer(&tree, idx_a, pk_a, w_a);
        let sb = build_signer(&tree, idx_b, pk_b, w_b);
        (tree, sa, sb, total)
    }

    fn circuit(tree: &TestTree, signers: Vec<SignerV2>, total: u64) -> VotingCircuitV2 {
        VotingCircuitV2 {
            registration_root: tree.root(),
            registration_vote_weight: total,
            vote_threshold_num: 1,
            vote_threshold_den: 2,
            depth: tree.depth,
            max_signers: 3,
            signers,
        }
    }

    /// WHAT: a proof whose signers are genuine tree members and whose
    ///       verified weight meets quorum verifies.
    /// WHY:  the membership+weight circuit must accept the honest case.
    #[test]
    fn honest_membership_proof_verifies() {
        let (tree, sa, sb, total) = setup_tree();
        let c = circuit(&tree, vec![sa, sb], total);

        // Constraint-level: the honest witness satisfies the circuit.
        assert!(is_satisfied(c.clone()), "honest witness must satisfy constraints");

        // End-to-end Groth16: prove + verify.
        let public = vec![
            c.registration_root,
            Fr::from(c.registration_vote_weight),
            Fr::from(c.vote_threshold_num),
            Fr::from(c.vote_threshold_den),
        ];
        let mut r = rng();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c.clone(), &mut r).unwrap();
        let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut r).unwrap();
        assert!(
            Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap(),
            "honest membership+quorum proof must verify"
        );
    }

    /// WHAT (load-bearing, closes F1's core): a signer who is NOT in the
    ///       registration tree (forged leaf / bogus path) cannot produce a
    ///       satisfying witness — `prove` fails.
    /// WHY:  this is exactly the forgery `exploit_finalize_forgery_e2e.rs`
    ///       demonstrates against the LIVE circuit; the redesigned circuit
    ///       rejects it because membership is enforced in-circuit.
    #[test]
    fn forged_non_member_signer_is_rejected() {
        let (tree, sa, _sb, _total) = setup_tree();
        // Forge: an attacker key with a huge weight, NOT in the tree, using
        // sa's (valid-shaped but wrong) path. Claim it alone meets quorum.
        let mut forged = sa.clone();
        forged.pubkey_id = Fr::from(999_999u64); // unregistered identity
        forged.weight = 1_000_000; // fabricated weight
        let c = circuit(&tree, vec![forged], 2_000);
        assert!(
            !is_satisfied(c),
            "FORGERY: a non-member signer must NOT satisfy the constraints \
             (membership enforced in-circuit). It did — F1 membership \
             binding regressed."
        );
    }

    /// WHAT: tampering a real member's weight (claiming more than the leaf
    ///       commits) breaks membership and is rejected.
    #[test]
    fn tampered_weight_is_rejected() {
        let (tree, sa, _sb, _total) = setup_tree();
        let mut tampered = sa.clone();
        tampered.weight += 1; // leaf no longer matches the tree
        let c = circuit(&tree, vec![tampered], 2_000);
        assert!(
            !is_satisfied(c),
            "a signer claiming more weight than their leaf commits must be \
             rejected by the in-circuit membership check"
        );
    }
}
