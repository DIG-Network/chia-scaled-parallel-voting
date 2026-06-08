// ============================================================================
// tests/int32_be_parity_e2e.rs — SEC-F1: validate `int_to_32_bytes_be` (Rue).
// ============================================================================
//
// The Poseidon registration accumulator stores its root + Jubjub pubkey
// coordinates as 32-byte big-endian field elements. The on-chain
// register/deregister puzzles encode them with `int_to_32_bytes_be` (Rue,
// common_types). This test runs it (via puzzles/int32_probe.rue) and asserts
// byte-for-byte parity with `fr_to_bytes32_be` for several values, including
// 0, small, and near-modulus — so the on-chain slot/root hashing matches
// merkle.rs::PoseidonSmt (which uses 32-byte BE).

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use chip_voting_sdk::prover::conversions::fr_to_bytes32_be;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, ChiaDialect};

fn probe_hex() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../puzzles/compiled/int32_probe.rue.hex"
    );
    let s = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read int32 probe: {e}"));
    hex::decode(s.trim().trim_start_matches("0x")).expect("hex")
}

/// Run int32_probe(n) where `n` is the canonical (leading-zero-stripped)
/// big-endian atom for the field element; return the 32-byte output.
fn run_int32(fr: Fr) -> Vec<u8> {
    // Pass the full 32-byte BE. Fr < P < 2^255 ⇒ MSB byte < 0x80, so CLVM
    // reads it as the correct POSITIVE integer; `int_to_32_bytes_be` derives
    // its output from that integer value (re-padding to 32 bytes), so the
    // input atom length is irrelevant — this still exercises the padding.
    let be = fr_to_bytes32_be(&fr);

    let mut a = Allocator::new();
    let puzzle = node_from_bytes(&mut a, &probe_hex()).expect("probe parses");
    let n = a.new_atom(&be).unwrap();
    let nil = a.nil();
    let env = a.new_pair(n, nil).unwrap();
    let dialect = ChiaDialect::new(0);
    let out = clvmr::run_program(&mut a, &dialect, puzzle, env, 11_000_000_000)
        .expect("int32 probe runs")
        .1;
    a.atom(out).as_ref().to_vec()
}

#[test]
fn int_to_32_bytes_be_matches_fr_to_bytes32_be() {
    let cases = [
        Fr::from(0u64),
        Fr::from(5u64),
        Fr::from(255u64),
        Fr::from(256u64),
        Fr::from(u64::MAX),
        // a near-modulus value (top byte 0x73, well-exercised padding)
        -Fr::from(2u64), // = P - 2
        -Fr::from(1u64), // = P - 1
    ];
    for fr in cases {
        let got = run_int32(fr);
        let expected = fr_to_bytes32_be(&fr);
        assert_eq!(
            got,
            expected.to_vec(),
            "int_to_32_bytes_be mismatch for {}",
            hex::encode(fr.into_bigint().to_bytes_be())
        );
        assert_eq!(got.len(), 32, "must be exactly 32 bytes");
    }
}
