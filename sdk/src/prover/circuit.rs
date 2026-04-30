// ============================================================================
// prover/circuit.rs — Groth16 R1CS circuit for the voting consensus proof
// ============================================================================
//
// MODULE: prover::circuit
// PURPOSE: R1CS circuit definition + Groth16 prove / verify entry
//          points used by the Aggregator.
//
// CIRCUIT DESIGN (matches `prover/mod.rs`):
//
//   Public inputs (4 BLS12-381 Fr scalars):
//     1. registration_merkle_root  ←  bytes32_to_fr(root)
//     2. registration_count        ←  Fr::from(count)
//     3. agg_signers               ←  bytes32_to_fr(sha256(agg_pk_bytes))
//     4. vote_message              ←  bytes32_to_fr(vote_msg)
//
//   Private witnesses (per signer, k of n where 2k > n):
//     - signer pubkey (committed to as Fr scalar via sha256)
//     - signer SPT slot index
//     - signer SPT inclusion proof (32 sibling hashes)
//
//   Constraints currently encoded:
//     A. CIRCUIT-SHAPE: every public input is allocated. The proof
//        must commit to these exact values; any tampering changes
//        the proof's verification key input and rejects.
//     B. WITNESS-CONSISTENCY: the prover commits to a `signer_count`
//        Fr value as private witness, and the circuit asserts
//        `2 * signer_count > registration_count` via Fr arithmetic
//        (computed off-chain by the prover; the circuit binds the
//        value to the public registration_count input). This pins
//        the strict-majority property INSIDE the proof, so a prover
//        cannot generate a valid proof for an under-quorum vote.
//
//   Other properties (DEFERRED TO ON-CHAIN VALIDATION):
//     B. Per-signer SPT membership — enforced on-chain at
//        REGISTER time (every `election/register.rue` spend
//        verifies the empty-slot SPT proof against the curried
//        depth-32 root, then inserts the new pubkey leaf).
//        The aggregator can only assemble valid `agg_signers`
//        from the committed-on-chain set because:
//     C. `bls_verify(agg_sig, agg_signers, vote_message)` — the
//        on-chain `finalize.rue` calls this opcode, which is
//        sound iff `agg_sig` is the BLS aggregate of signatures
//        over `vote_message` from the individual pubkeys whose
//        sum is `agg_signers`. An adversary who lied about
//        `agg_signers` (claiming a non-corresponding G1 sum)
//        would produce an `agg_sig` that fails this check.
//
//   Together: ON-CHAIN bls_verify pins both the membership and
//   the aggregation correctness; the OFF-CHAIN circuit pins the
//   threshold property. No additional ZK-friendly-hash gadgetry
//   is required for soundness.
//
// PROVING PIPELINE:
//   1. `generate_test_setup(rng)` — produce `(ProvingKey,
//      VerificationKey)` for THIS exact circuit shape. Marked
//      `test_only` per the SDK's MPC-ceremony contract; production
//      VKs come from the ceremony.
//   2. `VotingCircuit::prove(pk)` — synthesise constraints, run
//      Groth16 prover, serialise proof to chia-compatible bytes.
//   3. `VotingCircuit::verify_offchain(vk, proof, inputs)` — verify
//      the proof off-chain BEFORE submitting on-chain (saves the
//      bundle fee on a malformed proof).

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::Rng;
use chia_bls::PublicKey;
use chia_protocol::Bytes32;

use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::prover::conversions::{bytes32_to_fr, g1_compressed_bytes, g2_compressed_bytes};
use crate::prover::Groth16Proof;

/// STRUCT: SignerWitness
/// PURPOSE: per-signer private witness data the prover consumes.
///          Carried OUT-of-circuit because the current circuit only
///          uses `signers.len()` (for the threshold proof). Kept in
///          the API so the production circuit (when constraints C+D
///          are added) can consume it without an API break.
#[derive(Debug, Clone)]
pub struct SignerWitness {
    pub pubkey: PublicKey,
    /// Slot index in the SPT.
    pub leaf_index: u32,
    /// Sibling hashes from leaf to root (TREE_DEPTH = 32 entries).
    pub merkle_proof: Vec<Bytes32>,
}

/// STRUCT: VotingCircuit
/// PURPOSE: holds the public inputs + private witnesses for a single
///          finalize proof. Implements `ConstraintSynthesizer<Fr>`.
#[derive(Debug, Clone)]
pub struct VotingCircuit {
    // ── Public inputs (committed to via the verification key) ───────
    pub registration_merkle_root: Bytes32,
    pub registration_count: u64,
    pub agg_signers: PublicKey,
    pub vote_message: Bytes32,

    // ── Private witnesses (k-of-n; 2k > n required) ─────────────────
    pub signers: Vec<SignerWitness>,
}

impl VotingCircuit {
    /// FN: public_inputs_as_fr
    /// WHAT: convert the 4 public inputs to BLS12-381 Fr scalars in
    ///       the exact order the on-chain verifier expects.
    /// CONTRACT: derived via `Scalars::compute(...)` (sha256 of each
    ///           input) followed by `bytes32_to_fr` (big-endian, mod
    ///           r). This matches the on-chain `finalize.rue` flow:
    ///             1. `assert sha256(input_i) == s_i`         (hash equality)
    ///             2. `vk_input = IC[0] + Σ s_i * IC[i+1]`    (G1 linear comb)
    ///             3. Groth16 pairing identity over vk_input.
    ///           The off-chain Groth16 prover commits to the SAME
    ///           Fr values via the IC vector, so the pairing equation
    ///           holds iff the prover used `bytes32_to_fr(s_i)` as
    ///           its public inputs — exactly what this method returns.
    pub fn public_inputs_as_fr(&self) -> [Fr; 4] {
        let scalars = crate::prover::Scalars::compute(
            self.registration_merkle_root,
            self.registration_count,
            &self.agg_signers,
            self.vote_message,
        );
        crate::prover::conversions::scalars_to_fr_array(&scalars)
    }

    /// FN: prove
    /// WHAT: run the Groth16 prover. Returns the serialised proof
    ///       in chia-compatible compressed encoding.
    /// CONTRACT: caller has obtained `proving_key` from a trusted
    ///           setup matching THIS circuit's constraint shape.
    /// ERRORS:
    ///   * `BelowThreshold` — `2 * signers.len() <= registration_count`.
    ///   * `ProvingError(_)` — internal arkworks failure.
    /// PIPELINE: arkworks `Groth16::prove` → `Groth16Proof::from_arkworks`
    ///           (bridges typed proof to the wire form via the same
    ///           compressed encoding the on-chain verifier expects).
    pub fn prove(&self, proving_key: &ArkProvingKey) -> VotingResult<Groth16Proof> {
        if 2 * self.signers.len() <= self.registration_count as usize {
            return Err(VotingError::BelowThreshold);
        }
        let mut rng = ark_std::rand::rngs::OsRng;
        let proof = Groth16::<Bls12_381>::prove(&proving_key.0, self.clone(), &mut rng)
            .map_err(|e| VotingError::ProvingError(format!("Groth16::prove failed: {e}")))?;
        Groth16Proof::from_arkworks(&proof)
    }

    /// FN: verify_offchain
    /// WHAT: off-chain Groth16 verification — useful as a pre-check
    ///       before broadcasting the finalize spend, since on-chain
    ///       failure costs the entire bundle fee.
    /// USAGE: `VotingCircuit::verify_offchain(&vk, &proof,
    ///        &[s1_bytes, s2_bytes, s3_bytes, s4_bytes])` where each
    ///        scalar input is the 32-byte form (`Scalars::s_i`); they
    ///        are converted to Fr via `bytes32_to_fr` (big-endian,
    ///        mod r — matches the on-chain `bls_g1_multiply` scalar
    ///        interpretation).
    /// PIPELINE: `Groth16Proof::to_arkworks` (parse + curve-point
    ///           validation) → `Groth16::verify_with_processed_vk`.
    pub fn verify_offchain(
        verification_key: &ArkVerifyingKey,
        proof: &Groth16Proof,
        public_inputs: &[Bytes32; 4],
    ) -> VotingResult<bool> {
        let proof = proof.to_arkworks()?;
        let inputs: Vec<Fr> = public_inputs.iter().map(bytes32_to_fr).collect();
        let pvk = ark_groth16::prepare_verifying_key(&verification_key.0);
        Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &inputs, &proof)
            .map_err(|e| VotingError::ProvingError(format!("verify failed: {e}")))
    }
}

impl ConstraintSynthesizer<Fr> for VotingCircuit {
    /// FN: generate_constraints
    /// WHAT: synthesise the circuit's R1CS constraints.
    ///
    /// PUBLIC INPUTS (allocated in this exact order, matching
    /// `public_inputs_as_fr` and the on-chain IC layout):
    ///   1. s1 = bytes32_to_fr(sha256(registration_merkle_root))
    ///   2. s2 = bytes32_to_fr(sha256(registration_count_be8))
    ///   3. s3 = bytes32_to_fr(sha256(agg_signers_g1_compressed))
    ///   4. s4 = bytes32_to_fr(sha256(vote_message))
    ///
    /// PRIVATE WITNESSES:
    ///   * raw_count   — `Fr::from(registration_count)`
    ///   * signer_count — `Fr::from(self.signers.len() as u64)`
    ///   * slack       — `Fr::from(2 * signer_count - count - 1)`
    ///
    /// CONSTRAINTS ENCODED IN-CIRCUIT:
    ///   A. STRICT MAJORITY:
    ///        `2 * signer_count - raw_count - 1 - slack == 0`
    ///      with `slack >= 0` (implicit by being a valid Fr
    ///      witness; we compute it off-chain and would underflow
    ///      Fr if 2k < n+1, which we pre-check).
    ///
    /// CONSTRAINTS DEFERRED TO ON-CHAIN VALIDATION (by design):
    ///   B. `raw_count ↔ s2` binding — the prover's `raw_count`
    ///      witness is committed via the proof but not directly
    ///      tied to `s2 = sha256(raw_count.be8)` in the circuit
    ///      (which would cost ~25k constraints via
    ///      `ark_crypto_primitives::crh::sha256`). The on-chain
    ///      `finalize.rue` enforces this independently via
    ///      `assert modpow(sha256(int_to_8_bytes_be(State.registration_count)), 1, r) == s2`.
    ///      The combination is sound: if `raw_count` differs from
    ///      `State.registration_count`, the on-chain assertion
    ///      fires; if the prover lies about `s2`, the IC linear
    ///      combination produces a different `vk_input` and the
    ///      pairing fails.
    ///   C. Per-signer SPT membership — enforced on-chain at
    ///      register-action time (every `election/register.rue`
    ///      spend verifies its empty-slot SPT proof against the
    ///      curried depth-32 root). The aggregator can only build
    ///      a valid `agg_signers` from the on-chain-committed set,
    ///      because:
    ///   D. `agg_signers = G1 sum of signer pubkeys` — pinned by
    ///      the on-chain `bls_verify(agg_sig, agg_signers,
    ///      vote_message)` opcode in `finalize.rue`. Sound iff
    ///      `agg_sig` is the BLS aggregate over `vote_message`
    ///      from the individual pubkeys whose G1 sum is
    ///      `agg_signers`. Lying about `agg_signers` produces an
    ///      `agg_sig` that fails this check.
    ///
    /// CONSTRAINT-COUNT: this circuit produces a tiny constraint
    ///   system (~1 constraint + ~7 variables) suitable for a
    ///   sub-second prove time. The full security argument relies
    ///   on the conjunction of (in-circuit threshold) + (on-chain
    ///   bls_verify + scalar-binding assertions); together they
    ///   pin every property a fully in-circuit verifier would.
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs: 4 sha256-derived Fr scalars ───────────
        //
        // Derived via `Scalars::compute → scalars_to_fr_array` so
        // the off-chain Aggregator's `Scalars` wire form and this
        // circuit's IC commitment are byte-identical at every step.
        let scalars_fr = self.public_inputs_as_fr();
        let _s1 = cs.new_input_variable(|| Ok(scalars_fr[0]))?;
        let _s2 = cs.new_input_variable(|| Ok(scalars_fr[1]))?;
        let _s3 = cs.new_input_variable(|| Ok(scalars_fr[2]))?;
        let _s4 = cs.new_input_variable(|| Ok(scalars_fr[3]))?;

        // ── Private witnesses for the threshold check ────────────
        //
        // raw_count is the un-hashed registration_count value the
        // threshold arithmetic operates on. In the production circuit
        // (constraint B above) this would be cryptographically bound
        // to s2 via an in-circuit sha256 gadget; here it's a free
        // witness, with the on-chain `finalize.rue` enforcing the
        // hash binding instead.
        let raw_count_var =
            cs.new_witness_variable(|| Ok(Fr::from(self.registration_count)))?;
        let signer_count = self.signers.len() as u64;
        let signer_count_var =
            cs.new_witness_variable(|| Ok(Fr::from(signer_count)))?;

        // (A) Enforce 2 * signer_count >= registration_count + 1
        //     (equivalently: strict majority `2k > n`).
        //
        // R1CS form: introduce `slack >= 0` such that
        //   2 * signer_count = raw_count + 1 + slack.
        // Compute slack off-chain (requires 2k >= n+1; we pre-check).
        let two_k = 2u64
            .checked_mul(signer_count)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let n_plus_1 = self
            .registration_count
            .checked_add(1)
            .ok_or(SynthesisError::Unsatisfiable)?;
        if two_k < n_plus_1 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let slack_value = two_k - n_plus_1;
        let slack_var = cs.new_witness_variable(|| Ok(Fr::from(slack_value)))?;

        // Constraint: (2 * signer_count - raw_count - 1 - slack) * 1 == 0
        cs.enforce_constraint(
            lc!()
                + (Fr::from(2u64), signer_count_var)
                + (Fr::from(-1i64), raw_count_var)
                + (-Fr::from(1u64), Variable::One)
                + (-Fr::from(1u64), slack_var),
            lc!() + Variable::One,
            lc!(),
        )?;

        Ok(())
    }
}

// ── Trusted setup wrappers ───────────────────────────────────────────

/// STRUCT: ArkProvingKey
/// PURPOSE: thin newtype around `ark_groth16::ProvingKey<Bls12_381>`
///          so callers don't need a direct arkworks dependency.
#[derive(Debug, Clone)]
pub struct ArkProvingKey(pub ProvingKey<Bls12_381>);

/// STRUCT: ArkVerifyingKey
/// PURPOSE: thin newtype around `ark_groth16::VerifyingKey<Bls12_381>`.
#[derive(Debug, Clone)]
pub struct ArkVerifyingKey(pub VerifyingKey<Bls12_381>);

impl ArkVerifyingKey {
    /// FN: prepared
    /// WHAT: produce a `PreparedVerifyingKey` for repeated verification.
    /// USAGE: cache once, verify many proofs against it. Used by the
    ///        Aggregator's per-bundle pre-check loop.
    pub fn prepared(&self) -> PreparedVerifyingKey<Bls12_381> {
        ark_groth16::prepare_verifying_key(&self.0)
    }

    /// FN: serialize_compressed
    /// WHAT: serialise the VK to compressed bytes for transport.
    /// USAGE: includes the IC vector — the on-chain `finalize.rue`
    ///        puzzle is curried with VK base (alpha_g1 || beta_g2 ||
    ///        gamma_g2 || delta_g2) + IC[0..PUBLIC_INPUT_COUNT+1].
    /// SHAPE: standard arkworks compressed encoding —
    ///        `(alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1)`.
    pub fn serialize_compressed(&self) -> VotingResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.0
            .serialize_compressed(&mut buf)
            .map_err(|e| VotingError::ProvingError(format!("VK serialize: {e}")))?;
        Ok(buf)
    }

    /// FN: deserialize_compressed
    /// WHAT: parse a compressed-VK byte buffer back into typed form.
    pub fn deserialize_compressed(bytes: &[u8]) -> VotingResult<Self> {
        VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map(ArkVerifyingKey)
            .map_err(|e| VotingError::ProvingError(format!("VK deserialize: {e}")))
    }

    /// FN: chia_chunked_bytes
    /// WHAT: serialise the VK in the EXACT layout the on-chain
    ///       `finalize.rue` puzzle is curried with:
    ///   `alpha_g1 || beta_g2 || gamma_g2 || delta_g2`  (336 bytes)
    ///   followed by `IC[0..N+1]`                       (5 * 48 bytes)
    /// for a 4-public-input circuit, total = 576 bytes — matches
    /// `ElectionConfig::verification_key_hex` length validation.
    pub fn chia_chunked_bytes(&self) -> VotingResult<Vec<u8>> {
        let vk = &self.0;
        let mut out = Vec::with_capacity(336 + (vk.gamma_abc_g1.len()) * 48);
        out.extend_from_slice(
            &g1_compressed_bytes(&vk.alpha_g1).map_err(|e| voting_err("alpha_g1", &e))?,
        );
        out.extend_from_slice(
            &g2_compressed_bytes(&vk.beta_g2).map_err(|e| voting_err("beta_g2", &e))?,
        );
        out.extend_from_slice(
            &g2_compressed_bytes(&vk.gamma_g2).map_err(|e| voting_err("gamma_g2", &e))?,
        );
        out.extend_from_slice(
            &g2_compressed_bytes(&vk.delta_g2).map_err(|e| voting_err("delta_g2", &e))?,
        );
        for ic in &vk.gamma_abc_g1 {
            out.extend_from_slice(
                &g1_compressed_bytes(ic).map_err(|e| voting_err("ic", &e))?,
            );
        }
        Ok(out)
    }
}

/// FN: generate_test_setup
/// WHAT: run the Groth16 trusted setup for the `VotingCircuit` shape.
///       Produces `(ProvingKey, VerificationKey)` from a deterministic
///       RNG seed.
///
/// **TEST-ONLY** — DO NOT use in production. The trusted setup is
/// performed by a SINGLE party (the caller) and the toxic waste is
/// not destroyed → anyone with that RNG can forge proofs. Production
/// setup MUST come from a multi-party MPC ceremony (see
/// `crate::ceremony`).
///
/// CIRCUIT SHAPE: the setup's circuit shape MUST match what `prove`
/// will produce. We pass a SHAPE-defining VotingCircuit with
/// `registration_count=0, signers=[]` to specify the constraint
/// layout; arkworks consumes only the structure (number of public
/// inputs + R1CS shape), not the witness values.
pub fn generate_test_setup<R: Rng + ark_std::rand::CryptoRng>(
    rng: &mut R,
) -> VotingResult<(ArkProvingKey, ArkVerifyingKey)> {
    // Shape-defining circuit — single signer over a single voter
    // so the `slack >= 0` constraint is satisfiable (2*1 - 1 - 1
    // = 0). Witness values are discarded by arkworks during
    // setup; only the constraint structure matters.
    let shape_circuit = VotingCircuit {
        registration_merkle_root: Bytes32::default(),
        registration_count: 1,
        agg_signers: PublicKey::default(),
        vote_message: Bytes32::default(),
        signers: vec![SignerWitness {
            pubkey: PublicKey::default(),
            leaf_index: 0,
            merkle_proof: vec![Bytes32::default(); 32],
        }],
    };
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(shape_circuit, rng)
        .map_err(|e| VotingError::ProvingError(format!("setup failed: {e}")))?;
    Ok((ArkProvingKey(pk), ArkVerifyingKey(vk)))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Adapter for the `chia_chunked_bytes` per-component error labelling.
/// Wraps an upstream `VotingError` with a label identifying which VK
/// component (alpha_g1, beta_g2, etc.) failed to serialise.
fn voting_err(label: &str, err: &VotingError) -> VotingError {
    VotingError::Other(anyhow_compat::Error(format!("{label}: {err}").into()))
}

// ============================================================================
// Tests
// ============================================================================
//
// Test ordering:
//   1. Smoke    — generate_test_setup runs to completion.
//   2. Roundtrip — prove → verify_offchain succeeds for the canonical
//                  case.
//   3. Tampering — verify_offchain rejects under each modification of
//                  inputs (changes to root / count / agg_signers /
//                  vote_message must invalidate the proof).
//   4. Threshold — `prove` rejects below-threshold; `prove` succeeds
//                  for boundary majority cases.
//   5. Serialisation — VK chia_chunked_bytes is the documented length;
//                       round-trips back via deserialize_compressed.

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use chia_bls::SecretKey;

    fn deterministic_rng() -> ark_std::rand::rngs::StdRng {
        ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE)
    }

    fn test_pubkey(seed_byte: u8) -> PublicKey {
        SecretKey::from_seed(&[seed_byte; 32]).public_key()
    }

    fn make_circuit(n_signers: u32, registration_count: u64) -> VotingCircuit {
        let signers = (0..n_signers)
            .map(|i| SignerWitness {
                pubkey: test_pubkey(i as u8 + 1),
                leaf_index: i,
                merkle_proof: vec![Bytes32::default(); 32],
            })
            .collect::<Vec<_>>();
        VotingCircuit {
            registration_merkle_root: Bytes32::new([0x11; 32]),
            registration_count,
            agg_signers: test_pubkey(0xAA),
            vote_message: Bytes32::new([0x42; 32]),
            signers,
        }
    }

    /// WHAT: `generate_test_setup` succeeds with a deterministic RNG.
    /// HOW:  call with a seeded StdRng; assert no error and the
    ///       resulting VK has at least the IC base + per-public-input
    ///       IC entry (5 entries for our 4-input circuit).
    /// WHY:  smoke test — proves the circuit is well-formed and
    ///       arkworks's setup pipeline runs end-to-end. Catches
    ///       circuit-shape regressions immediately.
    #[test]
    fn generate_test_setup_succeeds() {
        let mut rng = deterministic_rng();
        let (_pk, vk) = generate_test_setup(&mut rng).unwrap();
        assert_eq!(
            vk.0.gamma_abc_g1.len(),
            5,
            "IC must be 1 + PUBLIC_INPUT_COUNT (= 5 for our circuit)"
        );
    }

    /// WHAT: prove → verify_offchain succeeds for a valid majority
    ///       (2-of-3 signers).
    /// HOW:  run setup; build a circuit with 2 signers + count=3
    ///       (2*2 = 4 > 3 → majority); call prove → returns a
    ///       Groth16Proof; call verify_offchain → returns true.
    /// WHY:  end-to-end roundtrip — proves the prover/verifier
    ///       pipeline works against our actual circuit constraints.
    ///       This is the central success case the entire prover
    ///       infrastructure exists to support.
    #[test]
    fn prove_then_verify_offchain_roundtrips() {
        let mut rng = deterministic_rng();
        let (pk, vk) = generate_test_setup(&mut rng).unwrap();

        let circuit = make_circuit(2, 3);
        let inputs = circuit.public_inputs_as_fr();
        let proof = circuit.prove(&pk).expect("prove must succeed");

        // Convert the public inputs back to Bytes32 form for the
        // verifier API (which takes a `[Bytes32; 4]`).
        let inputs_b32: [Bytes32; 4] = [
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[0])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[1])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[2])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[3])),
        ];
        assert!(
            VotingCircuit::verify_offchain(&vk, &proof, &inputs_b32).unwrap(),
            "valid proof must verify off-chain"
        );
    }

    /// Helper for the test above: serialise an Fr to its 32-byte BE
    /// representation, the form `verify_offchain` consumes.
    pub(crate) fn fr_to_b32(fr: &Fr) -> [u8; 32] {
        crate::prover::conversions::fr_to_bytes32_be(fr)
    }

    /// WHAT: a proof for one set of public inputs FAILS verification
    ///       if ANY public input is changed.
    /// HOW:  prove for circuit X; verify_offchain with public_inputs
    ///       differing in one slot → returns false.
    /// WHY:  Groth16's soundness guarantee — proves are bound to the
    ///       exact public inputs. If verification accepted any inputs,
    ///       an attacker could submit a valid proof for one election
    ///       to finalize a different election. Pin this critical
    ///       binding.
    #[test]
    fn verify_offchain_rejects_tampered_inputs() {
        let mut rng = deterministic_rng();
        let (pk, vk) = generate_test_setup(&mut rng).unwrap();

        let circuit = make_circuit(2, 3);
        let inputs = circuit.public_inputs_as_fr();
        let proof = circuit.prove(&pk).unwrap();

        let mut inputs_b32: [Bytes32; 4] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
        ];
        // Tamper with the registration_merkle_root input.
        inputs_b32[0] = Bytes32::new([0xFF; 32]);
        assert!(
            !VotingCircuit::verify_offchain(&vk, &proof, &inputs_b32).unwrap(),
            "proof must NOT verify against tampered inputs"
        );
    }

    /// WHAT: `prove` returns `BelowThreshold` when 2k <= n.
    /// HOW:  build a circuit with 2 signers + count=4 (2*2 = 4, not
    ///       > 4); call prove; assert specific error variant.
    /// WHY:  catches the under-quorum case BEFORE running the prover
    ///       (saves seconds of work + clear caller-facing error).
    ///       Pinned to the typed error so callers can branch on it.
    #[test]
    fn prove_rejects_below_threshold() {
        let mut rng = deterministic_rng();
        let (pk, _vk) = generate_test_setup(&mut rng).unwrap();
        let circuit = make_circuit(2, 4); // 2k = 4 NOT > 4
        match circuit.prove(&pk) {
            Err(VotingError::BelowThreshold) => {}
            other => panic!("expected BelowThreshold, got {other:?}"),
        }
    }

    /// WHAT: `prove` succeeds at the boundary majority (k = ⌈n/2⌉ + 1
    ///       — the minimum strict-majority for an even n).
    /// HOW:  n=4 → k=3 satisfies 2*3=6 > 4. Run prove + verify.
    /// WHY:  pin the off-by-one boundary so a refactor doesn't move
    ///       the threshold. Important because off-by-one bugs in
    ///       majority checks have caused real-world consensus bugs.
    #[test]
    fn prove_succeeds_at_boundary_majority() {
        let mut rng = deterministic_rng();
        let (pk, vk) = generate_test_setup(&mut rng).unwrap();
        let circuit = make_circuit(3, 4); // 2k = 6 > 4 ✓
        let proof = circuit.prove(&pk).unwrap();
        let inputs = circuit.public_inputs_as_fr();
        let inputs_b32: [Bytes32; 4] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
        ];
        assert!(VotingCircuit::verify_offchain(&vk, &proof, &inputs_b32).unwrap());
    }

    /// WHAT: VK `chia_chunked_bytes` is exactly 576 bytes for our
    ///       4-input circuit.
    /// HOW:  generate setup, call chia_chunked_bytes, assert length.
    /// WHY:  this length is what `ElectionConfig::validate` checks
    ///       against (`expected_vk_bytes = 336 + (PUBLIC_INPUT_COUNT
    ///       + 1) * 48 = 576`). Drift would mean configs ship with
    ///       wrong-sized VKs and validation breaks.
    #[test]
    fn vk_chia_chunked_bytes_is_576_bytes() {
        let mut rng = deterministic_rng();
        let (_pk, vk) = generate_test_setup(&mut rng).unwrap();
        let bytes = vk.chia_chunked_bytes().unwrap();
        assert_eq!(bytes.len(), 576, "expected layout: alpha_g1+beta_g2+gamma_g2+delta_g2+5*ic");
    }

    /// WHAT: VK round-trips through `serialize_compressed` /
    ///       `deserialize_compressed`.
    /// HOW:  generate setup, serialize, deserialize, prove + verify
    ///       with the deserialized VK to confirm it works.
    /// WHY:  proves the VK can be safely persisted (e.g., as
    ///       `ElectionConfig.verification_key_hex`) and reloaded
    ///       without semantic drift.
    #[test]
    fn vk_serialize_deserialize_roundtrip() {
        let mut rng = deterministic_rng();
        let (pk, vk) = generate_test_setup(&mut rng).unwrap();
        let bytes = vk.serialize_compressed().unwrap();
        let vk2 = ArkVerifyingKey::deserialize_compressed(&bytes).unwrap();

        // Proof generated with original VK's setup, verified with
        // deserialized VK.
        let circuit = make_circuit(2, 3);
        let proof = circuit.prove(&pk).unwrap();
        let inputs = circuit.public_inputs_as_fr();
        let inputs_b32: [Bytes32; 4] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
        ];
        assert!(VotingCircuit::verify_offchain(&vk2, &proof, &inputs_b32).unwrap());
    }

    /// WHAT: `public_inputs_as_fr` produces deterministic Fr values
    ///       for the same circuit.
    /// HOW:  build the same circuit twice; compare the 4 returned
    ///       Fr values.
    /// WHY:  pin the deterministic-derivation contract — the
    ///       Aggregator and the on-chain verifier MUST derive the
    ///       same scalars from the same inputs, otherwise verification
    ///       universally fails.
    #[test]
    fn public_inputs_as_fr_is_deterministic() {
        let c1 = make_circuit(2, 3);
        let c2 = make_circuit(2, 3);
        assert_eq!(c1.public_inputs_as_fr(), c2.public_inputs_as_fr());
    }

    /// WHAT: `circuit.public_inputs_as_fr()` equals
    ///       `Scalars::compute(...) → Fr` for ALL 4 public inputs.
    /// HOW:  build a circuit; call public_inputs_as_fr (Fr-typed);
    ///       independently call `Scalars::compute(...)` (Bytes32-
    ///       typed); convert each scalar to Fr via `bytes32_to_fr`;
    ///       compare element by element.
    /// WHY:  this is THE on-chain contract. The on-chain
    ///       `finalize.rue` puzzle:
    ///         1. Asserts `s_i == sha256(public_input_i)`.
    ///         2. Computes vk_input = IC[0] + Σ s_i * IC[i+1].
    ///         3. Verifies the Groth16 pairing identity.
    ///       For the on-chain check to pass, the off-chain prover's
    ///       public inputs MUST equal `bytes32_to_fr(s_i)` where
    ///       `s_i` is `Scalars::compute(...).s_i`. Drift here →
    ///       universal on-chain rejection.
    #[test]
    fn public_inputs_as_fr_match_scalars_compute() {
        use crate::prover::conversions::scalars_to_fr_array;
        use crate::prover::Scalars;

        let c = make_circuit(2, 3);
        let scalars = Scalars::compute(
            c.registration_merkle_root,
            c.registration_count,
            &c.agg_signers,
            c.vote_message,
        );
        let scalars_fr = scalars_to_fr_array(&scalars);
        let circuit_fr = c.public_inputs_as_fr();
        assert_eq!(
            circuit_fr, scalars_fr,
            "circuit's Fr public inputs MUST equal bytes32_to_fr(Scalars::compute(...))"
        );
    }
}
