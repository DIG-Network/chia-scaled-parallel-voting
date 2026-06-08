// ============================================================================
// tests/poseidon_clvm_cost_bench.rs — F1 step 4 feasibility gate.
// ============================================================================
//
// F1 (docs/F1-finalize-redesign.md) step 4 migrates the on-chain registration
// accumulator to a Poseidon-over-Fr tree so the Groth16 circuit can prove
// membership cheaply. Poseidon has NO CLVM builtin, so register.rue /
// deregister.rue would compute it in Rue via modular arithmetic over the
// BLS12-381 scalar field Fr. The HARD PROCESS RULE is "every on-chain change
// within normal CLVM cost". This bench measures the dominant primitive — a
// single modular multiply `(a*b) % P` over 32-byte operands — and extrapolates
// to a full register spend, to DECIDE whether step 4 proceeds as
// Poseidon-in-Rue or as the design-doc dual-commitment / documented residual.
//
// Permutation op-count (Poseidon width t=3, RF=8 full + RP=57 partial rounds,
// S-box x^5):
//   * full round   : 3 S-box (×4 modmul each = 12) + 9 MDS modmul        = 21 modmul
//   * partial round: 1 S-box (×4 = 4)              + 9 MDS modmul        = 13 modmul
//   ⇒ per permutation: 8*21 + 57*13 = 168 + 741                          = 909 modmul
// Per register spend (depth-32 membership): 1 leaf + 32 node hashes
//   ≈ 33 permutations ⇒ ~30_000 modmul (modadds are cheaper, ignored here as
//   a lower bound on the multiply term).

use clvmr::reduction::Reduction;
use clvmr::{Allocator, ChiaDialect, NodePtr};

/// BLS12-381 scalar field (Fr) modulus, 32 bytes big-endian.
const FR_MODULUS_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

fn atom(a: &mut Allocator, bytes: &[u8]) -> NodePtr {
    a.new_atom(bytes).unwrap()
}

/// Build `(r (divmod (* 2 5) (q . P)))`:
///   env path 2 = first arg `a`, path 5 = second arg `b`;
///   `(* 2 5)` = a*b; `(divmod a*b (q . P))` = (quotient . remainder);
///   `(r ...)` takes the remainder = (a*b) mod P.
fn build_modmul_program(a: &mut Allocator) -> NodePtr {
    let nil = a.nil();
    let two = atom(a, &[2]);
    let five = atom(a, &[5]);
    let mul_op = atom(a, &[18]); // *
    // (* 2 5)
    let mul_args = a.new_pair(five, nil).unwrap();
    let mul_args = a.new_pair(two, mul_args).unwrap();
    let mul = a.new_pair(mul_op, mul_args).unwrap();
    // (q . P)  — quote the modulus
    let q_op = atom(a, &[1]);
    let p_atom = atom(a, &FR_MODULUS_BE);
    let q_p = a.new_pair(q_op, p_atom).unwrap();
    // (divmod (* 2 5) (q . P))
    let divmod_op = atom(a, &[20]); // divmod
    let dm_args = a.new_pair(q_p, nil).unwrap();
    let dm_args = a.new_pair(mul, dm_args).unwrap();
    let divmod = a.new_pair(divmod_op, dm_args).unwrap();
    // (r (divmod ...))
    let r_op = atom(a, &[6]); // rest — divmod returns (quot . rem); rest = rem
    let r_args = a.new_pair(divmod, nil).unwrap();
    a.new_pair(r_op, r_args).unwrap()
}

#[test]
fn poseidon_in_rue_clvm_cost_feasibility() {
    let mut a = Allocator::new();
    let prog = build_modmul_program(&mut a);

    // env = (a . (b . nil)) with two worst-case 32-byte operands < P.
    let mut a_be = FR_MODULUS_BE;
    a_be[31] -= 1; // P-1 (after the 0x...01 low byte → 0x...00)... use P with low byte 0
    let mut b_be = FR_MODULUS_BE;
    b_be[0] = 0x70; // a distinct ~32-byte value < P
    let nil = a.nil();
    let a_atom = atom(&mut a, &a_be);
    let b_atom = atom(&mut a, &b_be);
    let env_rest = a.new_pair(b_atom, nil).unwrap();
    let env = a.new_pair(a_atom, env_rest).unwrap();

    let dialect = ChiaDialect::new(0);
    let Reduction(cost, _out) =
        clvmr::run_program(&mut a, &dialect, prog, env, 11_000_000_000).expect("modmul runs");

    // Extrapolate.
    const MODMUL_PER_PERM: u64 = 909;
    const PERM_PER_REGISTER: u64 = 33;
    let per_perm = cost * MODMUL_PER_PERM;
    let per_register = per_perm * PERM_PER_REGISTER;
    // Chia's per-block cost ceiling is 11_000_000_000. A single spend may use a
    // large fraction; treat "well under the block cap with headroom for the
    // rest of the register spend" as the feasibility bar.
    const BLOCK_COST_CAP: u64 = 11_000_000_000;

    println!("=== F1 step-4 Poseidon-in-Rue CLVM cost benchmark ===");
    println!("single 32-byte modmul (a*b % P) cost   : {cost}");
    println!("per Poseidon permutation (×{MODMUL_PER_PERM} modmul): {per_perm}");
    println!("per register spend (×{PERM_PER_REGISTER} perms)     : {per_register}");
    println!(
        "fraction of block cost cap ({BLOCK_COST_CAP}): {:.2}%",
        (per_register as f64 / BLOCK_COST_CAP as f64) * 100.0
    );
    println!(
        "VERDICT: {}",
        if per_register < BLOCK_COST_CAP / 4 {
            "FEASIBLE — Poseidon-in-Rue register fits with headroom"
        } else if per_register < BLOCK_COST_CAP {
            "TIGHT — fits a block but little headroom; consider batching/dual-commitment"
        } else {
            "INFEASIBLE — exceeds block cost; use dual-commitment + document residual"
        }
    );

    // The bench always 'passes'; it exists to print the cost decision. The
    // single modmul must at least execute.
    assert!(cost > 0, "modmul must consume cost");
}
