// ============================================================================
// tests/finalize_v2_groth16_e2e.rs — F1 step 5: on-chain Groth16 verify of
// VotingCircuitV2 via puzzles/finalize_v2_probe.rue.
// ============================================================================
//
// Validates that a REAL arkworks Groth16 proof for `VotingCircuitV2` (the
// Option-B finalize circuit: in-circuit Poseidon membership + Jubjub Schnorr +
// weight threshold, 5 public inputs, NO BLS aggregate) verifies on-chain
// through the Rue pairing verifier `finalize_v2_probe.rue`, and that a forged
// proof / tampered public input is REJECTED (the puzzle raises).
//
// This de-risks the `ballot_coin/finalize.rue` rewrite (step 5): the pairing +
// IC layout for circuit_v2 is sound on-chain. The membership/signature/weight
// binding is proven IN-circuit (circuit_v2 tests); this test proves the
// on-chain side accepts a valid proof and rejects an invalid one.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as JubScalar;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use chia_protocol::Bytes;
use chip_voting_sdk::merkle::PoseidonSmt;
use chip_voting_sdk::prover::circuit::ArkVerifyingKey;
use chip_voting_sdk::prover::circuit_v2::{
    keygen, poseidon_config, schnorr_sign, SignerV2, VotingCircuitV2,
};
use chip_voting_sdk::prover::conversions::{
    fr_to_bytes32_be, g1_compressed_bytes, g2_compressed_bytes,
};
use clvm_traits::ToClvm;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, ChiaDialect};

/// Build an honest circuit_v2 instance (1 registered, signing member).
fn honest_circuit() -> VotingCircuitV2 {
    let depth = 20usize;
    let cfg = poseidon_config();
    let mut tree = PoseidonSmt::with_depth(depth);
    let x = JubScalar::from(42u64);
    let p = keygen(x);
    let weight = 1_000u64;
    tree.insert(p, weight);
    let proof = tree.prove_jubjub(p.x, p.y);
    let root = tree.root();
    let vote_message = Fr::from(0xABCD_EFu64);
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
    VotingCircuitV2 {
        registration_root: root,
        vote_message,
        registration_vote_weight: weight,
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        depth,
        max_signers: 1,
        signers: vec![signer],
    }
}

fn probe_hex() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../puzzles/compiled/finalize_v2_probe.rue.hex"
    );
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read probe hex: {e}"));
    hex::decode(s.trim().trim_start_matches("0x")).expect("probe hex decodes")
}

/// Build the 18-element solution list and run the probe; returns whether it
/// verified (Ok) or was rejected (Err = pairing raise).
fn run_probe(vk_bytes: &[u8], proof_abc: (&[u8], &[u8], &[u8]), scalars: &[[u8; 32]; 5]) -> bool {
    // VK layout (chia_chunked_bytes): alpha(48) beta(96) gamma(96) delta(96)
    // then IC0..IC5 (48 each) — 336 + 6*48 = 624 bytes.
    assert_eq!(vk_bytes.len(), 624, "circuit_v2 VK must be 624 bytes (6 ICs)");
    let mut env: Vec<Bytes> = Vec::with_capacity(18);
    env.push(Bytes::new(vk_bytes[0..48].to_vec())); // alpha
    env.push(Bytes::new(vk_bytes[48..144].to_vec())); // beta
    env.push(Bytes::new(vk_bytes[144..240].to_vec())); // gamma
    env.push(Bytes::new(vk_bytes[240..336].to_vec())); // delta
    for i in 0..6 {
        let o = 336 + i * 48;
        env.push(Bytes::new(vk_bytes[o..o + 48].to_vec())); // ic_i
    }
    env.push(Bytes::new(proof_abc.0.to_vec())); // a
    env.push(Bytes::new(proof_abc.1.to_vec())); // b
    env.push(Bytes::new(proof_abc.2.to_vec())); // c
    for s in scalars {
        env.push(Bytes::new(s.to_vec()));
    }

    let mut a = Allocator::new();
    let puzzle = node_from_bytes(&mut a, &probe_hex()).expect("probe parses");
    let env_node = env.to_clvm(&mut a).expect("env serialises");
    let dialect = ChiaDialect::new(0);
    clvmr::run_program(&mut a, &dialect, puzzle, env_node, 11_000_000_000).is_ok()
}

#[test]
fn circuit_v2_proof_verifies_onchain_and_forgery_rejected() {
    let circuit = honest_circuit();
    let public = circuit.public_inputs();
    assert_eq!(public.len(), 5);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xF1_5A_1E);
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");
    // Sanity: the VK has exactly 6 IC points (5 public inputs + 1).
    assert_eq!(vk.gamma_abc_g1.len(), 6, "circuit_v2 must have 5 public inputs");
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("prove");
    // Off-chain sanity.
    assert!(
        Groth16::<Bls12_381>::verify(&vk, &public, &proof).unwrap(),
        "off-chain verify must pass"
    );

    let vk_bytes = ArkVerifyingKey(vk).chia_chunked_bytes().expect("vk bytes");
    let a = g1_compressed_bytes(&proof.a).expect("a");
    let b = g2_compressed_bytes(&proof.b).expect("b");
    let c = g1_compressed_bytes(&proof.c).expect("c");
    let scalars: [[u8; 32]; 5] = [
        fr_to_bytes32_be(&public[0]),
        fr_to_bytes32_be(&public[1]),
        fr_to_bytes32_be(&public[2]),
        fr_to_bytes32_be(&public[3]),
        fr_to_bytes32_be(&public[4]),
    ];

    // (1) Honest proof verifies on-chain.
    assert!(
        run_probe(&vk_bytes, (&a, &b, &c), &scalars),
        "SEC-F1: a valid circuit_v2 Groth16 proof MUST verify through finalize_v2_probe.rue"
    );

    // (2) Tamper a public input (registration_root) — pairing MUST fail.
    let mut forged = scalars;
    forged[0][31] ^= 0x01;
    assert!(
        !run_probe(&vk_bytes, (&a, &b, &c), &forged),
        "SEC-F1: a tampered public input MUST be rejected by the on-chain pairing"
    );

    // (3) Tamper the proof's A point — pairing MUST fail.
    let mut bad_a = a;
    bad_a[10] ^= 0x01;
    // A corrupted compressed point may be unparseable (Err) or parse to a
    // different point (pairing fails) — either way run_probe returns false.
    assert!(
        !run_probe(&vk_bytes, (&bad_a, &b, &c), &scalars),
        "SEC-F1: a tampered proof MUST be rejected by the on-chain pairing"
    );
}
