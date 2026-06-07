// ============================================================================
// prover/ — Groth16 proving infrastructure for the voting circuit
// ============================================================================
//
// MODULE: prover
// PURPOSE: Off-chain Groth16 proof generation + verification, with
//          byte-exact compatibility for the on-chain CLVM verifier
//          (`puzzles/election/finalize.rue`).
//
// ── Submodules ──────────────────────────────────────────────────────
//
//   * `circuit`      — `VotingCircuit` (R1CS), `prove`, `verify_offchain`,
//                       `generate_test_setup`, VK newtype wrappers.
//   * `proof`        — `Groth16Proof` wire type (hex-encoded compressed
//                       points) + `Scalars` pre-computed sha256 hashes
//                       of the public inputs. Both round-trip to/from
//                       arkworks types via dedicated methods.
//   * `conversions`  — chia_bls ↔ arkworks BLS12-381 byte-encoding
//                       bridge; scalar conversions; G1 aggregation.
//
// ── Public-input convention (matches puzzles/ballot_coin/finalize.rue) ──
//
// The Groth16 verifier consumes 6 BLS12-381 Fr scalars as public
// inputs (CHIP rev 2026-05-02). Each scalar is
// `bytes32_to_fr(sha256(input_i) mod r)` — the big-endian-mod-r
// interpretation of the sha256 of the i-th input:
//
//   1. s1 = sha256(registration_merkle_root)             (32 bytes)
//   2. s2 = sha256(registration_vote_weight_be8)         (8-byte weight)
//   3. s3 = sha256(agg_signers_g1_compressed_48)         (48-byte G1)
//   4. s4 = sha256(vote_message)                         (32 bytes;
//                                                        `sha256(outcome ||
//                                                         ballot_launcher_id ||
//                                                         election_launcher_id)`
//                                                        per ballot_coin/finalize.rue)
//   5. s5 = sha256(threshold_pack(num, den))             (16 bytes;
//                                                        `int_to_8_bytes_be(num) ||
//                                                         int_to_8_bytes_be(den)`)
//   6. s6 = sha256(ballot_launcher_id)                   (32 bytes)
//
// The on-chain `ballot_coin/finalize.rue`:
//   1. Asserts `s_i == sha256(input_i) mod r` for each i.
//   2. Computes `vk_input = IC[0] + Σ s_i * IC[i+1]` (i = 1..=6).
//   3. Verifies the Groth16 pairing identity over `vk_input`.
//
// The off-chain `VotingCircuit::public_inputs_as_fr` returns the
// SAME `[Fr; 6]` (via `Scalars::compute → scalars_to_fr_array`) so
// the prover commits to the same IC values.
//
// ── Private witnesses (per signer, k of n where 2k > n) ─────────────
//
//   * Each signer's pubkey (48-byte BLS12-381 G1).
//   * Each signer's SPT slot index (u32).
//   * Each signer's SPT inclusion proof (32 sibling hashes, depth 32).
//
// ── Constraints encoded in-circuit ──────────────────────────────────
//
//   A. STRICT MAJORITY: `2 * signer_count > registration_count`,
//      enforced via `(2k - n - 1 - slack) * 1 == 0` with
//      `slack >= 0`. Bound to a private witness `raw_count`.
//
// ── Constraints DEFERRED to on-chain validation (by design) ─────────
//
//   B. `raw_count ↔ s2` binding — pinned by `finalize.rue`'s
//      `assert modpow(sha256(int_to_8_bytes_be(State.registration_count)), 1, r) == s2`
//      assertion (avoids a ~25k-constraint in-circuit sha256
//      gadget).
//   C. Per-signer SPT membership — pinned by every
//      `election/register.rue` spend's empty-slot SPT proof
//      verification at registration time (so the on-chain voter
//      set is provably the only set the aggregator can pull
//      pubkeys from).
//   D. `agg_signers = G1 sum of signer pubkeys` — pinned by the
//      on-chain `bls_verify(agg_sig, agg_signers, vote_message)`
//      opcode. Sound iff `agg_sig` is the BLS aggregate over
//      `vote_message` from the individual pubkeys whose G1 sum
//      is `agg_signers`.
//
// The combination (in-circuit threshold + on-chain bls_verify +
// scalar-binding assertions) pins every property a fully
// in-circuit verifier would, while keeping the trusted-setup
// circuit small enough for sub-second proving. See
// `prover/circuit.rs::generate_constraints` doc-comment for the
// per-constraint analysis.
//
// ── Trusted-setup model ────────────────────────────────────────────
//
//   * `generate_test_setup(rng)` — runs the Groth16 trusted setup
//     against a single deterministic RNG. **TEST-ONLY**; production
//     setup MUST come from a multi-party MPC ceremony (see
//     `crate::ceremony`).
//   * The resulting `ArkVerifyingKey` serialises to the exact
//     672-byte layout `ElectionConfig::verification_key_hex`
//     validates against (`alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖
//     IC[0..6]`, 7 IC points × 48 bytes) via
//     `ArkVerifyingKey::chia_chunked_bytes`.

pub mod circuit;
// F1 redesign (WIP — docs/F1-finalize-redesign.md): in-circuit Poseidon-SPT
// signer membership + weight binding, built alongside the live `circuit`
// path. Not yet wired into finalization.
pub mod circuit_v2;
pub mod conversions;
pub mod proof;

pub use circuit::VotingCircuit;
pub use proof::{threshold_pack_bytes, Groth16Proof, Scalars};
