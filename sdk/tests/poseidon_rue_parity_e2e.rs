// ============================================================================
// tests/poseidon_rue_parity_e2e.rs — F1 step 4 parity gate.
// ============================================================================
//
// Proves the on-chain Rue Poseidon (`puzzles/poseidon.rue`, exercised via the
// `puzzles/poseidon_probe.rue` entry point) reproduces the off-circuit Rust
// reference (`sdk/src/prover/poseidon_perm.rs`) BYTE-FOR-BYTE for the
// registration-accumulator hashes. If these ever diverge, on-chain
// register/deregister membership and the in-circuit proof would disagree and
// every finalize would break — so this parity is load-bearing for F1.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use chip_voting_sdk::prover::poseidon_perm::{cfg, hash2, hash_leaf, hash_node};
use clvmr::reduction::Reduction;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, ChiaDialect, NodePtr};

fn fr_to_be32(f: Fr) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

fn probe_hex() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../puzzles/compiled/poseidon_probe.rue.hex"
    );
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read probe hex ({path}): {e}"))
}

/// Run poseidon_probe with `(sel, a, b, c)` and return the result as Fr.
fn run_probe(sel: u8, a: Fr, b: Fr, c: Fr) -> Fr {
    let mut al = Allocator::new();
    let bytes = hex::decode(probe_hex().trim().trim_start_matches("0x")).expect("hex");
    let puzzle = node_from_bytes(&mut al, &bytes).expect("probe parses");

    let nil = al.nil();
    let sel_atom = if sel == 0 {
        nil
    } else {
        al.new_atom(&[sel]).unwrap()
    };
    let a_atom = al.new_atom(&fr_to_be32(a)).unwrap();
    let b_atom = al.new_atom(&fr_to_be32(b)).unwrap();
    let c_atom = al.new_atom(&fr_to_be32(c)).unwrap();
    // env = (sel a b c) = (sel . (a . (b . (c . nil))))
    let e = al.new_pair(c_atom, nil).unwrap();
    let e = al.new_pair(b_atom, e).unwrap();
    let e = al.new_pair(a_atom, e).unwrap();
    let env = al.new_pair(sel_atom, e).unwrap();

    let dialect = ChiaDialect::new(0);
    let Reduction(_cost, out): Reduction =
        clvmr::run_program(&mut al, &dialect, puzzle, env, 11_000_000_000).expect("probe runs");
    let out_bytes = al.atom(out);
    Fr::from_be_bytes_mod_order(out_bytes.as_ref())
}

#[test]
fn rue_poseidon_matches_rust_reference() {
    let cfg = cfg();
    let cases = [
        (Fr::from(0u64), Fr::from(0u64), 0u64),
        (Fr::from(5u64), Fr::from(7u64), 1_000u64),
        (Fr::from(1u64), Fr::from(2u64), 3u64),
        (
            Fr::from(123456789u64),
            Fr::from(987654321u64),
            18_446_744_073_709_551_615u64, // u64::MAX
        ),
    ];

    for (i, &(a, b, w)) in cases.iter().enumerate() {
        // hash2 (sel 0)
        let rue = run_probe(0, a, b, Fr::from(0u64));
        let rust = hash2(&cfg, a, b);
        assert_eq!(rue, rust, "hash2 parity case {i}");

        // hash_node (sel 2) — same as hash2
        let rue_n = run_probe(2, a, b, Fr::from(0u64));
        assert_eq!(rue_n, hash_node(&cfg, a, b), "hash_node parity case {i}");

        // hash_leaf (sel 1) — (px, py, weight)
        let rue_leaf = run_probe(1, a, b, Fr::from(w));
        let rust_leaf = hash_leaf(&cfg, a, b, w);
        assert_eq!(rue_leaf, rust_leaf, "hash_leaf parity case {i}");
    }
}
