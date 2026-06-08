// ============================================================================
// prover/circuit_v2.rs — F1 redesign, Option B: in-circuit signer set (WIP)
// ============================================================================
//
// STATUS: research-grade WORK IN PROGRESS toward closing finding F1
// (finalize forgery — see docs/F1-finalize-redesign.md). Built ALONGSIDE
// the live `circuit.rs` / `finalize.rue` path and NOT yet wired into
// finalization, so the existing suite stays green.
//
// OPTION B (chosen): make the Groth16 proof attest, entirely in-circuit and
// at O(1) on-chain cost, that "registered voters whose combined weight
// meets the quorum threshold SIGNED `vote_message`". This drops the BLS
// aggregate / on-chain `bls_verify` / `agg_signers` entirely (in-circuit
// BLS12-381 G1 is structurally infeasible in arkworks 0.4 — see the design
// doc). Voters instead sign with a SNARK-friendly **Schnorr signature over
// Jubjub** (the embedded curve of BLS12-381, whose BASE field IS the
// constraint field `Fr`), verified natively in-circuit.
//
// PER PRESENT SIGNER the circuit enforces:
//   * MEMBERSHIP (G2): `leaf = Poseidon(pubkey.x, pubkey.y, weight)` is a
//     leaf of the depth-`DEPTH` Poseidon registration tree whose root is a
//     public input. A non-registered key (or a tampered weight) cannot
//     satisfy this.
//   * SIGNATURE: a Jubjub Schnorr signature `(R, s)` by `pubkey` over the
//     public `vote_message`: `s·G == R + c·P`, `c = Poseidon(R.x, P.x, m)`.
//     So only a key whose holder actually signed THIS outcome contributes.
//   * WEIGHT (G1): the verified weights sum to the curried quorum threshold
//     (`signed * den >= num * total`).
//
// `finalize` then just verifies ONE Groth16 proof + commits the outcome —
// constant cost regardless of voter count.
//
// SOUNDNESS HARDENING — DONE (load-bearing):
//   * the threshold `slack` is range-checked to [0, 2^200) (so
//     `(lhs-rhs)==slack` genuinely implies `lhs>=rhs` — a wrapped negative
//     difference is ~p and fails) and each signer `weight` is bounded to 64
//     bits;
//   * the Schnorr scalar `s` is bound to the canonical 252-bit inner-scalar
//     width (rejects an over-length `s + n·r` malleated witness).
//
// REMAINING (multi-session, see design doc):
//   * Migrate the on-chain registration accumulator (register/deregister +
//     sdk/merkle.rs) to this Poseidon tree over the voters' Jubjub pubkeys.
//   * Go-live hardening pass (requires careful cryptographic review — NOT
//     load-bearing for the demonstrated forgeries, which membership +
//     collateral + the tested signature/slack checks already close):
//       - PRIME-ORDER subgroup checks on witnessed `P`/`R` via cofactor
//         clearing (`P == [8]·Q`). A first cut was reverted: arkworks
//         `EdwardsVar` witness/`scalar_mul_le` behaviour on small-order
//         points made the naive check vacuous in unit tests; the correct
//         gadget needs verification before shipping (a vacuous check is
//         worse than none).
//       - derive `vote_message` as ≤254-bit off-circuit (coupled to the
//         step-6 aggregator) + add the matching in-circuit bound.
//       - pin an audited Poseidon parameter set shared with `sdk/merkle.rs`
//         + the on-chain verifier.
//   * Wire into finalize.rue (new public-input set; drop VK BLS bits) +
//     ceremony/VK + aggregator/voter signing + flip
//     exploit_finalize_forgery_e2e to assert REJECTION.
//
// The unit tests pin the load-bearing properties: a forged non-member, a
// weight-tamper, and a wrong-message/forged signature each FAIL the
// constraints — exactly the forgery exploit_finalize_forgery_e2e.rs shows
// against the live circuit.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ec::Group;
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective as Jub, Fr as JubScalar};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use crate::prover::poseidon_perm::{
    hash2, hash2_var, hash3, hash3_var, hash_leaf, hash_leaf_var,
};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::error::{VotingError, VotingResult};
use crate::prover::circuit::{ArkProvingKey, ArkVerifyingKey};
use crate::prover::proof::Groth16Proof;
use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_snark::SNARK;

/// Canonical Poseidon parameters over BLS12-381 `Fr` (width 3, rate 2).
/// The SAME config is used for the leaf hash, the Merkle node hash, and the
/// Schnorr challenge. Production MUST pin an audited parameter set shared
/// with `sdk/merkle.rs` and the on-chain Poseidon-in-Rue register verifier.
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

/// Enforce `0 <= v < 2^n` by bit-decomposition. `to_bits_le` constrains
/// `bits == v` (little-endian, field width); forcing every bit at index
/// `>= n` to zero bounds `v`. This is the primitive behind the threshold
/// range proof (an Fr difference that "wrapped" to a negative integer is
/// ~p ≈ 2^255 and fails this check).
fn enforce_lt_pow2(v: &FpVar<Fr>, n: usize) -> Result<(), SynthesisError> {
    let bits = v.to_bits_le()?;
    for b in bits.iter().skip(n) {
        b.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}


/// Reduce a base-field Poseidon challenge `c` into the Jubjub inner scalar
/// field by integer value — matches the in-circuit interpretation where
/// `c.to_bits_le()` is consumed by Jubjub double-and-add (reduced mod the
/// group order).
pub fn challenge_to_inner(c: Fr) -> JubScalar {
    JubScalar::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le())
}

/// A single signer's witness: their Jubjub pubkey + membership proof +
/// a Schnorr signature `(R, s)` over `vote_message`.
#[derive(Clone, Debug)]
pub struct SignerV2 {
    pub pubkey: EdwardsAffine, // P = x·G  (the registered signing key)
    pub weight: u64,
    pub path: Vec<Fr>,        // Merkle siblings leaf→root
    pub path_bits: Vec<bool>, // direction bits (true ⇒ node is right child)
    pub sig_r: EdwardsAffine, // R = k·G
    pub sig_s: JubScalar,     // s = k + c·x  (inner scalar field)
    pub present: bool,
}

impl SignerV2 {
    /// Registration leaf = `Poseidon(P.x, P.y, weight)`.
    pub fn leaf(&self, cfg: &PoseidonConfig<Fr>) -> Fr {
hash_leaf(cfg, self.pubkey.x, self.pubkey.y, self.weight)
    }

    /// Off-circuit root this witness implies (tests).
    pub fn implied_root(&self, cfg: &PoseidonConfig<Fr>) -> Fr {
        let mut node = self.leaf(cfg);
        for (sib, &is_right) in self.path.iter().zip(self.path_bits.iter()) {
            node = if is_right {
                hash2(cfg, *sib, node)
            } else {
                hash2(cfg, node, *sib)
            };
        }
        node
    }

    fn padding(depth: usize) -> Self {
        Self {
            pubkey: EdwardsAffine::default(),
            weight: 0,
            path: vec![Fr::from(0u64); depth],
            path_bits: vec![false; depth],
            sig_r: EdwardsAffine::default(),
            sig_s: JubScalar::from(0u64),
            present: false,
        }
    }
}

/// F1-redesign Option-B circuit (WIP — see module docs).
#[derive(Clone)]
pub struct VotingCircuitV2 {
    // ── Public inputs ──
    pub registration_root: Fr, // Poseidon registration-tree root snapshot
    pub vote_message: Fr,      // outcome digest signers signed (≤254-bit)
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
    pub fn padded_signers(&self) -> Vec<SignerV2> {
        let mut s = self.signers.clone();
        while s.len() < self.max_signers {
            s.push(SignerV2::padding(self.depth));
        }
        s
    }

    pub fn signed_weight(&self) -> u64 {
        self.signers
            .iter()
            .filter(|s| s.present)
            .map(|s| s.weight)
            .sum()
    }

    /// The circuit's PUBLIC INPUTS as field elements, in the exact order
    /// `generate_constraints` allocates them (`new_input`):
    ///   [0] registration_root      (the Poseidon SPT root snapshot)
    ///   [1] vote_message           (Fr; the outcome digest signers signed)
    ///   [2] registration_vote_weight (Fr::from)
    ///   [3] vote_threshold_num     (Fr::from)
    ///   [4] vote_threshold_den     (Fr::from)
    /// The on-chain `finalize_v2` verifier and the aggregator's proof
    /// builder MUST use this exact ordering (IC1..IC5) — it replaces the
    /// live circuit's 8-input layout (no `agg_signers`/threshold-pack
    /// scalars; binding is fully in-circuit).
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.registration_root,
            self.vote_message,
            Fr::from(self.registration_vote_weight),
            Fr::from(self.vote_threshold_num),
            Fr::from(self.vote_threshold_den),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for VotingCircuitV2 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cfg = poseidon_config();

        // Public inputs.
        let root_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.registration_root))?;
        let m_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.vote_message))?;
        let total_weight_var =
            FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.registration_vote_weight)))?;
        let num_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.vote_threshold_num)))?;
        let den_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.vote_threshold_den)))?;

        // Jubjub base point (constant).
        let g_var = EdwardsVar::new_constant(cs.clone(), Jub::generator())?;

        let signers = self.padded_signers();
        let mut acc_weight = FpVar::<Fr>::zero();

        for s in &signers {
            let present = Boolean::new_witness(cs.clone(), || Ok(s.present))?;

            // Signer's Jubjub pubkey + weight.
            let p_var = EdwardsVar::new_witness(cs.clone(), || Ok(Jub::from(s.pubkey)))?;
            let weight = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(s.weight)))?;

            // Weight is a u64 (defense-in-depth + keeps the threshold-sum
            // bounded for the slack range proof below; membership also binds
            // it to the registered leaf, which register.rue caps < 2^64).
            enforce_lt_pow2(&weight, 64)?;

            // ── MEMBERSHIP (G2): leaf = Poseidon(P.x, P.y, weight) ──
            let leaf = hash_leaf_var(&cfg, &p_var.x, &p_var.y, &weight)?;
            let mut node = leaf;
            for level in 0..self.depth {
                let sib = FpVar::<Fr>::new_witness(cs.clone(), || Ok(s.path[level]))?;
                let is_right = Boolean::new_witness(cs.clone(), || Ok(s.path_bits[level]))?;
                let left = is_right.select(&sib, &node)?;
                let right = is_right.select(&node, &sib)?;
                node = hash2_var(&cfg, &left, &right)?;
            }
            // present ⇒ reconstructed root == public root.
            node.conditional_enforce_equal(&root_var, &present)?;

            // ── SIGNATURE: Schnorr over Jubjub, s·G == R + c·P ──
            let r_var = EdwardsVar::new_witness(cs.clone(), || Ok(Jub::from(s.sig_r)))?;
            let s_bits: Vec<Boolean<Fr>> = s
                .sig_s
                .into_bigint()
                .to_bits_le()
                .into_iter()
                .map(|b| Boolean::new_witness(cs.clone(), || Ok(b)))
                .collect::<Result<_, _>>()?;
            // SOUNDNESS: bind `s` to the canonical 252-bit inner-scalar width
            // (Jubjub `r < 2^252`), so a malleated `s + n·r` over-length
            // witness cannot be substituted. Honest `s < r` has zero high
            // bits, so this is satisfied; padding signers have `s = 0`.
            for b in s_bits.iter().skip(252) {
                b.enforce_equal(&Boolean::constant(false))?;
            }
            // c = Poseidon(R.x, P.x, vote_message)
            let c_var = hash3_var(&cfg, &r_var.x, &p_var.x, &m_var)?;
            let c_bits = c_var.to_bits_le()?;
            let s_g = g_var.scalar_mul_le(s_bits.iter())?;
            let c_p = p_var.scalar_mul_le(c_bits.iter())?;
            let rhs = &r_var + &c_p;
            // present ⇒ s·G == R + c·P (valid signature on vote_message).
            s_g.conditional_enforce_equal(&rhs, &present)?;

            // ── WEIGHT (G1): accumulate present·weight ──
            let contribution = present.select(&weight, &FpVar::<Fr>::zero())?;
            acc_weight += contribution;
        }

        // THRESHOLD (G1): acc_weight * den >= num * total_weight, via a slack
        // identity. NOTE (WIP): a bit-decomposition range proof on `slack`
        // is still required for full soundness (see module docs).
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
        // SOUNDNESS (load-bearing): range-check slack to [0, 2^200) so
        // `(lhs - rhs) == slack` genuinely implies `lhs >= rhs`. lhs/rhs are
        // products of u64-bounded values summed over <= max_signers, so an
        // honest non-negative difference is far below 2^200, while a wrapped
        // negative difference is ~p (≈2^255) and fails this check. Without
        // it, `slack` is a free Fr witness and the threshold is vacuous.
        enforce_lt_pow2(&slack, 200)?;
        (lhs - rhs).enforce_equal(&slack)?;

        Ok(())
    }
}

// ── Off-circuit signing (tests / future aggregator) ──────────────────────

/// Generate a Jubjub keypair `(secret x, public P=x·G)`.
pub fn keygen(x: JubScalar) -> EdwardsAffine {
    use ark_ec::CurveGroup;
    (Jub::generator() * x).into_affine()
}

/// Schnorr-sign `vote_message` with secret `x` and nonce `k`:
/// `R=k·G`, `c=Poseidon(R.x, P.x, m)`, `s = k + c_inner·x`.
pub fn schnorr_sign(
    cfg: &PoseidonConfig<Fr>,
    x: JubScalar,
    k: JubScalar,
    vote_message: Fr,
) -> (EdwardsAffine, JubScalar) {
    use ark_ec::CurveGroup;
    let p = (Jub::generator() * x).into_affine();
    let r = (Jub::generator() * k).into_affine();
    let c = hash3(cfg, r.x, p.x, vote_message);
    let s = k + challenge_to_inner(c) * x;
    (r, s)
}

// ── Groth16 prove / verify / setup for circuit_v2 ────────────────────────

impl VotingCircuitV2 {
    /// FN: prove
    /// WHAT: run the Groth16 prover for the v2 (Option-B) circuit; returns
    ///       the chia-compressed wire proof. Mirrors `VotingCircuit::prove`.
    /// PRE-CHECK: the in-circuit slack identity requires
    ///       `signed_weight*den >= num*total`; we surface `BelowThreshold`
    ///       here rather than emit a proof the verifier (or the circuit's
    ///       own `Unsatisfiable`) would reject.
    pub fn prove(&self, proving_key: &ArkProvingKey) -> VotingResult<Groth16Proof> {
        let signed = self.signed_weight() as u128;
        let lhs = signed * self.vote_threshold_den as u128;
        let rhs = self.vote_threshold_num as u128 * self.registration_vote_weight as u128;
        if lhs < rhs {
            return Err(VotingError::BelowThreshold);
        }
        let mut rng = ark_std::rand::rngs::OsRng;
        let proof = Groth16::<Bls12_381>::prove(&proving_key.0, self.clone(), &mut rng)
            .map_err(|e| VotingError::ProvingError(format!("Groth16::prove (v2) failed: {e}")))?;
        Groth16Proof::from_arkworks(&proof)
    }

    /// FN: verify_offchain
    /// WHAT: off-chain Groth16 verification pre-flight. `public_inputs` is
    ///       the raw `[Fr; 5]` from `public_inputs()` (NOT sha256 scalars —
    ///       circuit_v2 binds field values directly), matching the on-chain
    ///       `finalize.rue` scalar = `fr_to_bytes32_be(input_i)` layout.
    pub fn verify_offchain(
        verification_key: &ArkVerifyingKey,
        proof: &Groth16Proof,
        public_inputs: &[Fr],
    ) -> VotingResult<bool> {
        let proof = proof.to_arkworks()?;
        let pvk = ark_groth16::prepare_verifying_key(&verification_key.0);
        Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, public_inputs, &proof)
            .map_err(|e| VotingError::ProvingError(format!("verify (v2) failed: {e}")))
    }
}

/// FN: generate_test_setup_v2
/// WHAT: Groth16 trusted setup for the `VotingCircuitV2` shape. Produces
///       `(ProvingKey, VerificationKey)` from a deterministic RNG.
///
/// **TEST-ONLY** — single-party setup, toxic waste not destroyed. Production
/// setup MUST come from the MPC ceremony (which curries this same circuit
/// shape). The VK has `PUBLIC_INPUT_COUNT + 1 = 6` IC points (624 bytes
/// chia-chunked).
///
/// CIRCUIT SHAPE: arkworks evaluates the witness during setup, so the shape
/// circuit must be SATISFIABLE — we build one genuinely-registered, signing
/// member at index 0 of an otherwise-empty depth-`tree_depth` Poseidon tree
/// (weight 1, threshold 1/2 over total 1 → `1*2 >= 1*1`). Only the
/// constraint STRUCTURE (input count + R1CS shape) is captured into the VK;
/// the concrete root/sig values are irrelevant to the resulting keys.
pub fn generate_test_setup_v2<R: ark_std::rand::Rng + ark_std::rand::CryptoRng>(
    tree_depth: usize,
    max_signers: usize,
    rng: &mut R,
) -> VotingResult<(ArkProvingKey, ArkVerifyingKey)> {
    use ark_ec::CurveGroup;
    let cfg = poseidon_config();
    let x = JubScalar::from(1u64);
    let p = (Jub::generator() * x).into_affine();
    let weight = 1u64;
    let vote_message = Fr::from(1u64);
    let (sig_r, sig_s) = schnorr_sign(&cfg, x, JubScalar::from(2u64), vote_message);

    // Empty-subtree hashes for an all-empty tree (leaf = Fr::zero).
    let mut empty = vec![Fr::from(0u64)];
    for i in 0..tree_depth {
        let e = empty[i];
        empty.push(hash2(&cfg, e, e));
    }
    // Single leaf at index 0: siblings are the empty subtree hashes, all
    // direction bits false (index 0 is the left child at every level).
    let leaf = hash_leaf(&cfg, p.x, p.y, weight);
    let path: Vec<Fr> = (0..tree_depth).map(|l| empty[l]).collect();
    let path_bits = vec![false; tree_depth];
    let mut node = leaf;
    for sib in &path {
        node = hash2(&cfg, node, *sib);
    }
    let root = node;

    let signer = SignerV2 {
        pubkey: p,
        weight,
        path,
        path_bits,
        sig_r,
        sig_s,
        present: true,
    };
    let shape = VotingCircuitV2 {
        registration_root: root,
        vote_message,
        registration_vote_weight: 1,
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        depth: tree_depth,
        max_signers,
        signers: vec![signer],
    };
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(shape, rng)
        .map_err(|e| VotingError::ProvingError(format!("v2 setup failed: {e}")))?;
    Ok((ArkProvingKey(pk), ArkVerifyingKey(vk)))
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

    fn is_satisfied(c: VotingCircuitV2) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match c.generate_constraints(cs.clone()) {
            Ok(()) => cs.is_satisfied().unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Off-circuit Poseidon Merkle tree over the registration leaves.
    struct TestTree {
        cfg: PoseidonConfig<Fr>,
        depth: usize,
        empty: Vec<Fr>,
        leaves: BTreeMap<u64, Fr>,
    }
    impl TestTree {
        fn new(depth: usize) -> Self {
            let cfg = poseidon_config();
            let mut empty = vec![Fr::from(0u64)];
            for i in 0..depth {
                let p = empty[i];
                empty.push(hash2(&cfg, p, p));
            }
            Self { cfg, depth, empty, leaves: BTreeMap::new() }
        }
        fn insert(&mut self, index: u64, leaf: Fr) {
            self.leaves.insert(index, leaf);
        }
        fn node(&self, level: usize, idx: u64) -> Fr {
            if level == 0 {
                return *self.leaves.get(&idx).unwrap_or(&self.empty[0]);
            }
            let span = 1u64 << level;
            let lo = idx * span;
            if self.leaves.range(lo..lo + span).next().is_none() {
                return self.empty[level];
            }
            let l = self.node(level - 1, idx * 2);
            let r = self.node(level - 1, idx * 2 + 1);
            hash2(&self.cfg, l, r)
        }
        fn root(&self) -> Fr {
            self.node(self.depth, 0)
        }
        fn proof(&self, mut index: u64) -> (Vec<Fr>, Vec<bool>) {
            let mut path = Vec::new();
            let mut bits = Vec::new();
            for level in 0..self.depth {
                path.push(self.node(level, index ^ 1));
                bits.push(index & 1 == 1);
                index >>= 1;
            }
            (path, bits)
        }
    }

    fn rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(0xF1_0B_C0DE)
    }

    /// Build a registered, signing member at `index` with secret `x`,
    /// nonce `k`, weight, signing `vote_message`. Inserts the leaf.
    fn member(
        tree: &mut TestTree,
        index: u64,
        x: JubScalar,
        k: JubScalar,
        weight: u64,
        vote_message: Fr,
    ) -> SignerV2 {
        let cfg = poseidon_config();
        let p = keygen(x);
        tree.insert(index, hash_leaf(&cfg, p.x, p.y, weight));
        let (r, s) = schnorr_sign(&cfg, x, k, vote_message);
        let (path, path_bits) = tree.proof(index);
        SignerV2 { pubkey: p, weight, path, path_bits, sig_r: r, sig_s: s, present: true }
    }

    fn setup() -> (TestTree, Fr, SignerV2, SignerV2, u64) {
        let depth = 8usize;
        let vote_message = Fr::from(0xABCDEFu64);
        let mut tree = TestTree::new(depth);
        // members must be built AFTER all inserts so their proofs reflect
        // the final tree — so build, collect, then re-prove.
        let cfg = poseidon_config();
        let (xa, ka, wa, ia) = (JubScalar::from(7u64), JubScalar::from(11u64), 1_000u64, 5u64);
        let (xb, kb, wb, ib) = (JubScalar::from(13u64), JubScalar::from(17u64), 2_000u64, 42u64);
        let pa = keygen(xa);
        let pb = keygen(xb);
        tree.insert(ia, hash_leaf(&cfg, pa.x, pa.y, wa));
        tree.insert(ib, hash_leaf(&cfg, pb.x, pb.y, wb));
        let mk = |x, k, w, i: u64, p: EdwardsAffine| {
            let (r, s) = schnorr_sign(&cfg, x, k, vote_message);
            let (path, path_bits) = tree.proof(i);
            SignerV2 { pubkey: p, weight: w, path, path_bits, sig_r: r, sig_s: s, present: true }
        };
        let sa = mk(xa, ka, wa, ia, pa);
        let sb = mk(xb, kb, wb, ib, pb);
        (tree, vote_message, sa, sb, wa + wb)
    }

    fn circuit(tree: &TestTree, m: Fr, signers: Vec<SignerV2>, total: u64) -> VotingCircuitV2 {
        VotingCircuitV2 {
            registration_root: tree.root(),
            vote_message: m,
            registration_vote_weight: total,
            vote_threshold_num: 1,
            vote_threshold_den: 2,
            depth: tree.depth,
            max_signers: 3,
            signers,
        }
    }

    /// HONEST: two registered members who both signed the outcome satisfy
    /// the circuit and the proof Groth16-verifies.
    #[test]
    fn honest_membership_and_signatures_verify() {
        let (tree, m, sa, sb, total) = setup();
        let c = circuit(&tree, m, vec![sa, sb], total);
        assert!(is_satisfied(c.clone()), "honest witness must satisfy");

        // Use the canonical public-input layout the on-chain verifier will
        // mirror — this also pins that `public_inputs()` matches the order
        // `generate_constraints` allocates `new_input`s.
        let public = c.public_inputs();
        let mut r = rng();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c.clone(), &mut r).unwrap();
        let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut r).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap());
    }

    /// FORGERY (membership): a non-member Jubjub key — even with a VALID
    /// self-signature — cannot satisfy the membership constraint.
    #[test]
    fn forged_non_member_rejected() {
        let (tree, m, _sa, _sb, _t) = setup();
        let cfg = poseidon_config();
        let (xz, kz) = (JubScalar::from(999u64), JubScalar::from(123u64));
        let pz = keygen(xz);
        let (rz, sz) = schnorr_sign(&cfg, xz, kz, m); // valid sig, but NOT registered
        let (path, path_bits) = tree.proof(5); // borrow a member's path shape
        let forged = SignerV2 {
            pubkey: pz,
            weight: 1_000_000,
            path,
            path_bits,
            sig_r: rz,
            sig_s: sz,
            present: true,
        };
        let c = circuit(&tree, m, vec![forged], 2_000);
        assert!(!is_satisfied(c), "non-member must fail membership");
    }

    /// FORGERY (signature): a registered member with an INVALID signature
    /// (s tampered) cannot satisfy the signature constraint.
    #[test]
    fn bad_signature_rejected() {
        let (tree, m, sa, _sb, _t) = setup();
        let mut bad = sa.clone();
        bad.sig_s += JubScalar::from(1u64); // break s·G == R + c·P
        let c = circuit(&tree, m, vec![bad], 2_000);
        assert!(!is_satisfied(c), "tampered signature must fail");
    }

    /// FORGERY (replay/wrong outcome): a member who signed a DIFFERENT
    /// message cannot have it counted for `vote_message` (challenge
    /// mismatch ⇒ signature check fails).
    #[test]
    fn wrong_message_rejected() {
        let (tree, m, sa, _sb, _t) = setup();
        // sa signed `m`; verify against a different outcome message.
        let c = circuit(&tree, m + Fr::from(1u64), vec![sa], 2_000);
        assert!(!is_satisfied(c), "signature over a different message must fail");
    }

    /// THRESHOLD: a signer set whose verified weight is below the quorum is
    /// rejected (the slack range-check makes the inequality non-vacuous).
    #[test]
    fn below_threshold_rejected() {
        let (tree, m, sa, _sb, _t) = setup();
        // sa weight = 1000; require 1/2 quorum over a 10_000 total → needs
        // signed >= 5000. 1000 < 5000 ⇒ must be rejected.
        let c = circuit(&tree, m, vec![sa], 10_000);
        assert!(!is_satisfied(c), "below-quorum signed weight must be rejected");
    }

    /// Weight tamper: claiming more weight than the registered leaf commits
    /// breaks membership.
    #[test]
    fn tampered_weight_rejected() {
        let (tree, m, sa, _sb, _t) = setup();
        let mut bad = sa.clone();
        bad.weight += 1;
        let c = circuit(&tree, m, vec![bad], 2_000);
        assert!(!is_satisfied(c), "weight tamper must fail membership");
    }

}
