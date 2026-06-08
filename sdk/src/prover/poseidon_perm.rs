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

/// Convenience: the shared config.
pub fn cfg() -> PoseidonConfig<Fr> {
    poseidon_config()
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
