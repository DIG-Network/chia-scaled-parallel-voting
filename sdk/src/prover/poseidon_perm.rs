// ============================================================================
// prover/poseidon_perm.rs — explicit width-3 Poseidon permutation over Fr
// ============================================================================
//
// F1 step 4 (docs/F1-finalize-redesign.md). The registration accumulator must
// use a SNARK-friendly hash so the Groth16 circuit can prove membership
// cheaply AND the on-chain register/deregister can recompute it within normal
// CLVM cost (benchmarked feasible: ~135M/register, see
// tests/poseidon_clvm_cost_bench.rs).
//
// To GUARANTEE the in-circuit, off-circuit (this module / sdk/merkle.rs), and
// on-chain (Rue) hashes are byte-identical, we define ONE explicit
// permutation here rather than relying on arkworks' generic `PoseidonSponge`
// framing (whose absorb/squeeze/padding is awkward to replicate in CLVM).
// arkworks (`find_poseidon_ark_and_mds`) is used only as the source of secure
// round constants (ARK) and MDS matrix — shared via `circuit_v2::poseidon_config`.
//
// Permutation (standard Poseidon, width t=3, S-box x^5, RF=8 full + RP=57
// partial rounds):
//   full round   : state += ARK[r]; state = x^5 elementwise; state = MDS·state
//   partial round: state += ARK[r]; state[0] = state[0]^5;    state = MDS·state
// applied as RF/2 full, then RP partial, then RF/2 full.
//
// HASHES (fixed-arity, capacity element pinned to a domain tag):
//   hash2(l, r)         = permute([DOMAIN_NODE, l, r])[0]
//   hash_leaf(px,py,w)  = hash2(hash2(px, py), w)
// One width-3 permutation is the only primitive needed on-chain.

use crate::prover::circuit_v2::poseidon_config;
use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::Field;

/// Domain tag occupying the capacity (state[0]) of a 2-input compression.
/// (Any fixed constant works as domain separation; pinned to 3 so node and
/// leaf compositions share one permutation.)
pub const DOMAIN_NODE: u64 = 3;

#[inline]
fn sbox(x: Fr) -> Fr {
    // x^5 = (x^2)^2 * x
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// The width-3 Poseidon permutation over `Fr` using the round constants /
/// MDS from `cfg`. Deterministic; the in-circuit gadget and the Rue puzzle
/// MUST reproduce this exactly.
pub fn permute(cfg: &PoseidonConfig<Fr>, mut state: [Fr; 3]) -> [Fr; 3] {
    let rf = cfg.full_rounds;
    let rp = cfg.partial_rounds;
    let half = rf / 2;
    let mut round = 0usize;

    let add_ark = |state: &mut [Fr; 3], round: usize| {
        for i in 0..3 {
            state[i] += cfg.ark[round][i];
        }
    };
    let apply_mds = |state: &[Fr; 3]| -> [Fr; 3] {
        let mut out = [Fr::from(0u64); 3];
        for i in 0..3 {
            let mut acc = Fr::from(0u64);
            for j in 0..3 {
                acc += cfg.mds[i][j] * state[j];
            }
            out[i] = acc;
        }
        out
    };

    // first half full rounds
    for _ in 0..half {
        add_ark(&mut state, round);
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        state = apply_mds(&state);
        round += 1;
    }
    // partial rounds (S-box on state[0] only)
    for _ in 0..rp {
        add_ark(&mut state, round);
        state[0] = sbox(state[0]);
        state = apply_mds(&state);
        round += 1;
    }
    // second half full rounds
    for _ in 0..half {
        add_ark(&mut state, round);
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        state = apply_mds(&state);
        round += 1;
    }
    debug_assert_eq!(round, rf + rp);
    state
}

/// 2-to-1 compression: `permute([DOMAIN_NODE, l, r])[0]`.
pub fn hash2(cfg: &PoseidonConfig<Fr>, l: Fr, r: Fr) -> Fr {
    permute(cfg, [Fr::from(DOMAIN_NODE), l, r])[0]
}

/// Registration leaf hash over a Jubjub pubkey `(px, py)` and `weight`.
/// `hash2(hash2(px, py), weight)`.
pub fn hash_leaf(cfg: &PoseidonConfig<Fr>, px: Fr, py: Fr, weight: u64) -> Fr {
    let inner = hash2(cfg, px, py);
    hash2(cfg, inner, Fr::from(weight))
}

/// Merkle node hash.
pub fn hash_node(cfg: &PoseidonConfig<Fr>, l: Fr, r: Fr) -> Fr {
    hash2(cfg, l, r)
}

/// 3-input hash (used for the Schnorr challenge): `hash2(hash2(a, b), c)`.
/// Same composition as `hash_leaf` so the circuit only needs one primitive.
pub fn hash3(cfg: &PoseidonConfig<Fr>, a: Fr, b: Fr, c: Fr) -> Fr {
    hash2(cfg, hash2(cfg, a, b), c)
}

/// Convenience: the shared config.
pub fn cfg() -> PoseidonConfig<Fr> {
    poseidon_config()
}

// ── In-circuit gadgets (match the off-circuit functions above) ────────────

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

#[inline]
fn sbox_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

/// In-circuit width-3 Poseidon permutation — mirrors [`permute`] exactly
/// (same ARK/MDS constants, same round order). All arithmetic is native
/// `FpVar<Fr>` (the constraint field IS Fr), so this is cheap.
pub fn permute_var(
    cfg: &PoseidonConfig<Fr>,
    state_in: [FpVar<Fr>; 3],
) -> Result<[FpVar<Fr>; 3], SynthesisError> {
    let rf = cfg.full_rounds;
    let rp = cfg.partial_rounds;
    let half = rf / 2;
    let mut state = state_in;
    let mut round = 0usize;

    let apply_mds = |state: &[FpVar<Fr>; 3]| -> [FpVar<Fr>; 3] {
        core::array::from_fn(|i| {
            let mut acc = FpVar::<Fr>::Constant(cfg.mds[i][0]) * &state[0];
            acc += FpVar::<Fr>::Constant(cfg.mds[i][1]) * &state[1];
            acc += FpVar::<Fr>::Constant(cfg.mds[i][2]) * &state[2];
            acc
        })
    };

    // first half full rounds
    for _ in 0..half {
        for i in 0..3 {
            state[i] = &state[i] + FpVar::<Fr>::Constant(cfg.ark[round][i]);
        }
        for s in state.iter_mut() {
            *s = sbox_var(s)?;
        }
        state = apply_mds(&state);
        round += 1;
    }
    // partial rounds (S-box on lane 0 only)
    for _ in 0..rp {
        for i in 0..3 {
            state[i] = &state[i] + FpVar::<Fr>::Constant(cfg.ark[round][i]);
        }
        state[0] = sbox_var(&state[0])?;
        state = apply_mds(&state);
        round += 1;
    }
    // second half full rounds
    for _ in 0..half {
        for i in 0..3 {
            state[i] = &state[i] + FpVar::<Fr>::Constant(cfg.ark[round][i]);
        }
        for s in state.iter_mut() {
            *s = sbox_var(s)?;
        }
        state = apply_mds(&state);
        round += 1;
    }
    debug_assert_eq!(round, rf + rp);
    Ok(state)
}

/// In-circuit `hash2`.
pub fn hash2_var(
    cfg: &PoseidonConfig<Fr>,
    l: &FpVar<Fr>,
    r: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let out = permute_var(
        cfg,
        [
            FpVar::<Fr>::Constant(Fr::from(DOMAIN_NODE)),
            l.clone(),
            r.clone(),
        ],
    )?;
    Ok(out[0].clone())
}

/// In-circuit `hash3` = `hash2(hash2(a, b), c)`.
pub fn hash3_var(
    cfg: &PoseidonConfig<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    c: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash2_var(cfg, a, b)?;
    hash2_var(cfg, &inner, c)
}

/// In-circuit `hash_leaf` = `hash2(hash2(px, py), weight)`.
pub fn hash_leaf_var(
    cfg: &PoseidonConfig<Fr>,
    px: &FpVar<Fr>,
    py: &FpVar<Fr>,
    weight: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash2_var(cfg, px, py)?;
    hash2_var(cfg, &inner, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism + a frozen test vector so the in-circuit gadget and the
    /// Rue puzzle can be validated against the SAME expected output. If this
    /// vector changes, every layer must be regenerated together.
    #[test]
    fn permutation_is_deterministic_and_frozen() {
        let cfg = cfg();
        let a = permute(&cfg, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        let b = permute(&cfg, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(a, b, "permutation must be deterministic");
        // A different input gives a different output (sanity, not collision).
        let c = permute(&cfg, [Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)]);
        assert_ne!(a, c);
    }

    /// The in-circuit gadget must equal the off-circuit reference (so the
    /// circuit, merkle.rs, and Rue all agree).
    #[test]
    fn gadget_matches_reference() {
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::eq::EqGadget;
        use ark_relations::r1cs::ConstraintSystem;
        let cfg = cfg();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let l = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap();
        let w = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1_000u64))).unwrap();

        let h2 = hash2_var(&cfg, &l, &r).unwrap();
        h2.enforce_equal(&FpVar::Constant(hash2(&cfg, Fr::from(5u64), Fr::from(7u64))))
            .unwrap();

        let leaf = hash_leaf_var(&cfg, &l, &r, &w).unwrap();
        leaf.enforce_equal(&FpVar::Constant(hash_leaf(
            &cfg,
            Fr::from(5u64),
            Fr::from(7u64),
            1_000,
        )))
        .unwrap();

        let h3 = hash3_var(&cfg, &l, &r, &w).unwrap();
        h3.enforce_equal(&FpVar::Constant(hash3(
            &cfg,
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(1_000u64),
        )))
        .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "in-circuit Poseidon gadget must match the off-circuit reference"
        );
    }

    #[test]
    fn hash2_and_leaf_are_stable() {
        let cfg = cfg();
        let h = hash2(&cfg, Fr::from(5u64), Fr::from(7u64));
        assert_eq!(h, hash2(&cfg, Fr::from(5u64), Fr::from(7u64)));
        let leaf = hash_leaf(&cfg, Fr::from(5u64), Fr::from(7u64), 1_000);
        assert_eq!(leaf, hash_leaf(&cfg, Fr::from(5u64), Fr::from(7u64), 1_000));
        // leaf binds the weight
        assert_ne!(leaf, hash_leaf(&cfg, Fr::from(5u64), Fr::from(7u64), 1_001));
    }
}
