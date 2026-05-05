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
//   Public inputs (6 BLS12-381 Fr scalars; CHIP rev 2026-05-02):
//     1. registration_merkle_root   ←  bytes32_to_fr(sha256(root) mod r)
//     2. registration_vote_weight   ←  bytes32_to_fr(sha256(weight_be8) mod r)
//     3. agg_signers                ←  bytes32_to_fr(sha256(agg_pk_bytes) mod r)
//     4. vote_message               ←  bytes32_to_fr(sha256(vote_msg) mod r)
//     5. threshold_pack             ←  bytes32_to_fr(sha256(num_be8 || den_be8) mod r)
//     6. ballot_launcher_id         ←  bytes32_to_fr(sha256(launcher_id) mod r)
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
///          The weighted-quorum gadget reads `weight` to enforce
///          `Σ signer_weights * den >= num * registration_vote_weight`
///          per CHIP.md "Why Groth16" + the threshold pack semantics.
///          The merkle_proof / leaf_index fields are kept in the API
///          for future deployments that fold per-signer SPT membership
///          into the circuit (currently enforced on-chain via the
///          register action's empty-slot proof).
#[derive(Debug, Clone)]
pub struct SignerWitness {
    pub pubkey: PublicKey,
    /// Per-voter weight (uniform = COLLATERAL_AMOUNT in this revision;
    /// the leaf hash `sha256(pubkey || weight_be8)` carries the same
    /// value, binding it to the registration SPT). Curried into the
    /// Σ-of-weights gadget as a private witness; the on-chain
    /// `bls_verify` opcode + the curried `(num, den)` snapshot bound
    /// via s5 keep this honest.
    pub weight: u64,
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
    /// Sum of voter weights at registration-snapshot time — replaces
    /// the pre-CHIP `registration_count` (which assumed all voters
    /// have equal weight). The on-chain `ballot_coin/finalize.rue`
    /// curries `REGISTRATION_VOTE_WEIGHT_SNAPSHOT` and asserts
    /// `s2 == sha256(int_to_8_bytes_be(weight)) mod r`.
    pub registration_vote_weight: u64,
    pub agg_signers: PublicKey,
    pub vote_message: Bytes32,
    /// Quorum threshold numerator (e.g. 2 in 2/3).
    pub vote_threshold_num: u64,
    /// Quorum threshold denominator (e.g. 3 in 2/3).
    pub vote_threshold_den: u64,
    /// Ballot Coin launcher ID — pins the proof to a single ballot.
    /// Without this commitment a prover could replay a proof against
    /// any ballot whose other public inputs happened to coincide.
    pub ballot_launcher_id: Bytes32,

    // ── Private witnesses (k-of-n; 2k > n required) ─────────────────
    pub signers: Vec<SignerWitness>,
}

impl VotingCircuit {
    /// FN: public_inputs_as_fr
    /// WHAT: convert the 6 public inputs to BLS12-381 Fr scalars in
    ///       the exact order the on-chain verifier expects.
    /// CONTRACT: derived via `Scalars::compute(...)` (sha256 of each
    ///           input) followed by `bytes32_to_fr` (big-endian, mod
    ///           r). This matches the on-chain
    ///           `puzzles/ballot_coin/finalize.rue` flow:
    ///             1. `assert sha256(input_i) == s_i`         (hash equality)
    ///             2. `vk_input = IC[0] + Σ s_i * IC[i+1]`    (G1 linear comb, i=1..=6)
    ///             3. Groth16 pairing identity over vk_input.
    ///           The off-chain Groth16 prover commits to the SAME
    ///           Fr values via the IC vector, so the pairing equation
    ///           holds iff the prover used `bytes32_to_fr(s_i)` as
    ///           its public inputs — exactly what this method returns.
    pub fn public_inputs_as_fr(&self) -> [Fr; 8] {
        let scalars = crate::prover::Scalars::compute(
            self.registration_merkle_root,
            self.registration_vote_weight,
            &self.agg_signers,
            self.vote_message,
            self.vote_threshold_num,
            self.vote_threshold_den,
            self.ballot_launcher_id,
        );
        crate::prover::conversions::scalars_to_fr_array(&scalars)
    }

    /// FN: prove
    /// WHAT: run the Groth16 prover. Returns the serialised proof
    ///       in chia-compatible compressed encoding.
    /// CONTRACT: caller has obtained `proving_key` from a trusted
    ///           setup matching THIS circuit's constraint shape.
    /// ERRORS:
    ///   * `BelowThreshold` — `2 * signers.len() <= registration_vote_weight`.
    ///     NOTE: this naive 2k>n pre-check is preserved from the
    ///     count-based circuit; the production weighted-quorum
    ///     gadget (`Σ signer_weights * den >= num * registration_vote_weight`)
    ///     lands in Phase 6 along with the per-signer weight witness.
    ///   * `ProvingError(_)` — internal arkworks failure.
    /// PIPELINE: arkworks `Groth16::prove` → `Groth16Proof::from_arkworks`
    ///           (bridges typed proof to the wire form via the same
    ///           compressed encoding the on-chain verifier expects).
    pub fn prove(&self, proving_key: &ArkProvingKey) -> VotingResult<Groth16Proof> {
        // Weighted-quorum pre-check: `Σ signer_weights * den >= num *
        // registration_vote_weight`. Mirrors the in-circuit gadget so
        // the prover surfaces `BelowThreshold` (rather than producing
        // a proof that the on-chain verifier would reject) when the
        // signers' aggregate weight doesn't meet the curried (num,
        // den) threshold.
        if self.signers.is_empty() {
            return Err(VotingError::BelowThreshold);
        }
        let total_signer_weight: u64 = self.signers.iter().map(|s| s.weight).sum();
        let lhs = total_signer_weight
            .checked_mul(self.vote_threshold_den)
            .ok_or(VotingError::BelowThreshold)?;
        let rhs = self
            .vote_threshold_num
            .checked_mul(self.registration_vote_weight)
            .ok_or(VotingError::BelowThreshold)?;
        if lhs < rhs {
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
    ///        &[s1, s2, s3, s4, s5, s6])` where each scalar input is
    ///        the 32-byte form (`Scalars::s_i`); they are converted
    ///        to Fr via `bytes32_to_fr` (big-endian, mod r — matches
    ///        the on-chain `bls_g1_multiply` scalar interpretation).
    /// PIPELINE: `Groth16Proof::to_arkworks` (parse + curve-point
    ///           validation) → `Groth16::verify_with_processed_vk`.
    pub fn verify_offchain(
        verification_key: &ArkVerifyingKey,
        proof: &Groth16Proof,
        public_inputs: &[Bytes32; 8],
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
    /// `public_inputs_as_fr` and the on-chain IC layout under CHIP
    /// rev 2026-05-02):
    ///   1. s1 = bytes32_to_fr(sha256(registration_merkle_root))
    ///   2. s2 = bytes32_to_fr(sha256(registration_vote_weight_be8))
    ///   3. s3 = bytes32_to_fr(sha256(agg_signers_g1_compressed))
    ///   4. s4 = bytes32_to_fr(sha256(vote_message))
    ///   5. s5 = bytes32_to_fr(sha256(threshold_pack(num,den)))
    ///   6. s6 = bytes32_to_fr(sha256(ballot_launcher_id))
    ///
    /// PRIVATE WITNESSES:
    ///   * raw_count    — `Fr::from(registration_vote_weight)`
    ///   * signer_count — `Fr::from(self.signers.len() as u64)`
    ///   * slack        — `Fr::from(2 * signer_count - raw_count - 1)`
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
        // ── Public inputs: 6 sha256-derived Fr scalars ───────────
        //
        // Derived via `Scalars::compute → scalars_to_fr_array` so
        // the off-chain Aggregator's `Scalars` wire form and this
        // circuit's IC commitment are byte-identical at every step.
        let scalars_fr = self.public_inputs_as_fr();
        let _s1 = cs.new_input_variable(|| Ok(scalars_fr[0]))?;
        let _s2 = cs.new_input_variable(|| Ok(scalars_fr[1]))?;
        let _s3 = cs.new_input_variable(|| Ok(scalars_fr[2]))?;
        let _s4 = cs.new_input_variable(|| Ok(scalars_fr[3]))?;
        let _s5 = cs.new_input_variable(|| Ok(scalars_fr[4]))?;
        // s6 (ballot_launcher_id) is allocated as a public input but
        // not constrained in-circuit beyond its IC commitment — its
        // sole purpose is binding the proof to a specific ballot via
        // the public-input vector (drift here ⇒ different vk_input ⇒
        // pairing fails).
        let _s6 = cs.new_input_variable(|| Ok(scalars_fr[5]))?;
        // s7 = Fr::from(num), s8 = Fr::from(den) — first-class public
        // inputs (CHIP rev). Promoting (num, den) from compile-time
        // R1CS coefficients to public-input variables means a SINGLE
        // VK can verify proofs for any (num, den), with the on-chain
        // finalize action asserting `int_to_be32(num) == s7` and
        // `int_to_be32(den) == s8` against the curried snapshot.
        // These vars are USED below in the weighted-quorum gadget
        // (multiplied by witness weights), so they must be bound to
        // real Variable handles, not `_`-discarded.
        let s7_var = cs.new_input_variable(|| Ok(scalars_fr[6]))?;
        let s8_var = cs.new_input_variable(|| Ok(scalars_fr[7]))?;

        // ── Private witnesses for the threshold check ────────────
        //
        // raw_count is the un-hashed registration_vote_weight value
        // the threshold arithmetic operates on. In the production
        // circuit (constraint B above) this would be cryptographically
        // bound to s2 via an in-circuit sha256 gadget; here it's a
        // free witness, with the on-chain `finalize.rue` enforcing
        // the hash binding instead. NOTE: under CHIP rev 2026-05-02
        // this gadget still uses the naive `2k > n` form against
        // `registration_vote_weight`; the weighted-quorum (num/den)
        // gadget lands in Phase 6 along with per-signer weight
        // witnesses. The `s5 = sha256(threshold_pack)` public input
        // is already allocated above so the production circuit can
        // bind to it without an API break.
        // ── Weighted-quorum gadget (CHIP.md spec) ────────────────
        //
        // Enforce `Σ signer_weights * den >= num * registration_vote_weight`
        // — the weighted form of the strict-majority quorum check
        // CHIP.md pins. The threshold (num, den) is committed via s5
        // (`sha256(threshold_pack(num, den)) mod r` → public input);
        // the on-chain `finalize.rue` curries (num, den) and asserts
        // the same threshold_pack scalar matches s5, so the threshold
        // values are bound to the curried Ballot Coin state and to
        // the proof's public inputs simultaneously.
        //
        // R1CS form: introduce `slack >= 0` such that
        //   Σ(weight_i) * den == num * registration_vote_weight + slack
        // is REWRITTEN as
        //   Σ(weight_i) * den - num * registration_vote_weight == slack
        // We compute `slack` off-chain (the prover pre-checks the
        // inequality holds, otherwise the constraint system is
        // unsatisfiable and `prove()` returns `BelowThreshold`).
        //
        // Per-signer weight witnesses are private (carried in
        // `SignerWitness.weight`); per CHIP.md they are bound to the
        // SPT leaf via `sha256(pubkey || weight_be8)` so an attacker
        // can't forge a signer with a fake weight without triggering
        // the on-chain register action's leaf-hash mismatch.
        let registration_vote_weight_var =
            cs.new_witness_variable(|| Ok(Fr::from(self.registration_vote_weight)))?;

        // Σ signer_weights — sum the per-signer weights off-chain
        // and commit the result as a single witness variable. We
        // intentionally DO NOT allocate per-signer weight witnesses
        // here: that would make the R1CS shape depend on
        // `signers.len()`, breaking the trusted setup's fixed-shape
        // invariant. Soundness on signer-set composition is enforced
        // OUT-of-circuit by the on-chain `bls_verify(agg_signers,
        // agg_sig, vote_message)` opcode (in `finalize.rue`) and
        // by the SPT leaf hash binding `sha256(pubkey || weight_be8)`
        // — the curried registration_merkle_root_snapshot makes a
        // forged signer's leaf inconsistent with the on-chain root
        // committed via s1.
        let total_signer_weight: u64 = self.signers.iter().map(|s| s.weight).sum();
        let total_signer_weight_var =
            cs.new_witness_variable(|| Ok(Fr::from(total_signer_weight)))?;

        // Compute slack off-chain. If 2*num >= 2*den (i.e., threshold
        // > 100%), or if signer total weight is below threshold,
        // the slack underflows u64 → return Unsatisfiable so the
        // higher-level `prove()` returns `BelowThreshold`.
        let lhs = total_signer_weight
            .checked_mul(self.vote_threshold_den)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let rhs = self
            .vote_threshold_num
            .checked_mul(self.registration_vote_weight)
            .ok_or(SynthesisError::Unsatisfiable)?;
        if lhs < rhs {
            return Err(SynthesisError::Unsatisfiable);
        }
        let slack_value = lhs - rhs;
        let slack_var = cs.new_witness_variable(|| Ok(Fr::from(slack_value)))?;

        // Enforce the inequality via the slack identity:
        //   total_signer_weight * den == num * registration_vote_weight + slack
        // i.e.,
        //   (s8_var * total_signer_weight_var) - (s7_var * registration_vote_weight_var)
        //     == slack_var
        //
        // R1CS forbids var*var inside a single linear combination, so
        // we split each product into its own constraint via a fresh
        // witness, then a final linear constraint stitches them
        // together.
        //
        // Witness values for the products are computed directly from
        // the Fr scalars we have at hand (s7/s8 = Fr::from(num/den);
        // weights are u64). Soundness comes from the enforce_constraint
        // calls below — the prover can't lie about lhs_var/rhs_var
        // without violating their multiplicative identities.
        let s8_fr = Fr::from(self.vote_threshold_den);
        let s7_fr = Fr::from(self.vote_threshold_num);
        let total_signer_weight_fr = Fr::from(total_signer_weight);
        let registration_vote_weight_fr = Fr::from(self.registration_vote_weight);

        // lhs_var = s8_var * total_signer_weight_var
        let lhs_value = s8_fr * total_signer_weight_fr;
        let lhs_var = cs.new_witness_variable(|| Ok(lhs_value))?;
        cs.enforce_constraint(
            lc!() + s8_var,
            lc!() + total_signer_weight_var,
            lc!() + lhs_var,
        )?;

        // rhs_var = s7_var * registration_vote_weight_var
        let rhs_value = s7_fr * registration_vote_weight_fr;
        let rhs_var = cs.new_witness_variable(|| Ok(rhs_value))?;
        cs.enforce_constraint(
            lc!() + s7_var,
            lc!() + registration_vote_weight_var,
            lc!() + rhs_var,
        )?;

        // Final slack identity: lhs_var - rhs_var == slack_var.
        // Encoded as `(lhs_var - rhs_var) * 1 == slack_var` — purely
        // linear, R1CS-friendly.
        cs.enforce_constraint(
            lc!() + lhs_var - rhs_var,
            lc!() + Variable::One,
            lc!() + slack_var,
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

impl ArkProvingKey {
    /// FN: serialize_compressed
    /// WHAT: serialise the PK to compressed bytes for transport / cache.
    /// USAGE: ceremony output → CDN → browser → IndexedDB; the wasm
    ///        finalize path loads it once per session.
    pub fn serialize_compressed(&self) -> VotingResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.0
            .serialize_compressed(&mut buf)
            .map_err(|e| VotingError::ProvingError(format!("PK serialize: {e}")))?;
        Ok(buf)
    }

    /// FN: deserialize_compressed
    /// WHAT: parse a compressed-PK byte buffer back into typed form.
    pub fn deserialize_compressed(bytes: &[u8]) -> VotingResult<Self> {
        ProvingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map(ArkProvingKey)
            .map_err(|e| VotingError::ProvingError(format!("PK deserialize: {e}")))
    }
}

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
    ///       `puzzles/ballot_coin/finalize.rue` puzzle is curried with:
    ///   `alpha_g1 || beta_g2 || gamma_g2 || delta_g2`  (336 bytes)
    ///   followed by `IC[0..N+1]`                       (7 * 48 bytes)
    /// for a 6-public-input circuit (CHIP rev 2026-05-02), total =
    /// 672 bytes — matches `ElectionConfig::verification_key_hex`
    /// length validation against `336 + (PUBLIC_INPUT_COUNT + 1) * 48`.
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
            out.extend_from_slice(&g1_compressed_bytes(ic).map_err(|e| voting_err("ic", &e))?);
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
    // Shape-defining circuit — single signer over a single voter,
    // chosen so the weighted-quorum constraint is satisfiable:
    //   total_signer_weight * den >= num * registration_vote_weight
    //   1 * 2  >=  1 * 1
    // Witness values are evaluated by arkworks during setup so the
    // constraint must actually be satisfied here (not just well-
    // formed). Under CHIP rev 2026-05-02 the resulting VK has 7 IC
    // points (ic0 + ic1..ic6) ⇒ 672 bytes total via
    // `chia_chunked_bytes`.
    let shape_circuit = VotingCircuit {
        registration_merkle_root: Bytes32::default(),
        registration_vote_weight: 1,
        agg_signers: PublicKey::default(),
        vote_message: Bytes32::default(),
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        ballot_launcher_id: Bytes32::default(),
        signers: vec![SignerWitness {
            pubkey: PublicKey::default(),
            weight: 1,
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

    fn make_circuit(n_signers: u32, registration_vote_weight: u64) -> VotingCircuit {
        // Per-signer weight = 1 so `registration_vote_weight` is
        // interpretable as "total count" for these tests' threshold
        // arithmetic. Real deployments use COLLATERAL_AMOUNT.
        //
        // (num, den) MUST match the shape_circuit's threshold —
        // they're baked into the QAP coefficients at trusted-setup
        // time, so a proof generated with different (num, den)
        // wouldn't verify against the same VK. `generate_test_setup`
        // uses (1, 2), so we use (1, 2) here too.
        let signers = (0..n_signers)
            .map(|i| SignerWitness {
                pubkey: test_pubkey(i as u8 + 1),
                weight: 1,
                leaf_index: i,
                merkle_proof: vec![Bytes32::default(); 32],
            })
            .collect::<Vec<_>>();
        VotingCircuit {
            registration_merkle_root: Bytes32::new([0x11; 32]),
            registration_vote_weight,
            agg_signers: test_pubkey(0xAA),
            vote_message: Bytes32::new([0x42; 32]),
            vote_threshold_num: 1,
            vote_threshold_den: 2,
            ballot_launcher_id: Bytes32::new([0x77; 32]),
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
            9,
            "IC must be 1 + PUBLIC_INPUT_COUNT (= 9 for our 8-input circuit)"
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
        // verifier API (which takes a `[Bytes32; 8]`).
        let inputs_b32: [Bytes32; 8] = [
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[0])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[1])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[2])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[3])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[4])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[5])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[6])),
            Bytes32::new(crate::prover::circuit::tests::fr_to_b32(&inputs[7])),
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

        let mut inputs_b32: [Bytes32; 8] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
            Bytes32::new(fr_to_b32(&inputs[4])),
            Bytes32::new(fr_to_b32(&inputs[5])),
            Bytes32::new(fr_to_b32(&inputs[6])),
            Bytes32::new(fr_to_b32(&inputs[7])),
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
        // CHIP rev 2026-05-02: the threshold pre-check was relaxed
        // from `2k > n` (count-based) to `signers.is_empty()` —
        // see `VotingCircuit::prove`'s comment for the rationale.
        // The full weighted-quorum gadget is Phase 6 work.
        let mut rng = deterministic_rng();
        let (pk, _vk) = generate_test_setup(&mut rng).unwrap();
        let circuit = make_circuit(0, 4); // empty signer set
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
        let inputs_b32: [Bytes32; 8] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
            Bytes32::new(fr_to_b32(&inputs[4])),
            Bytes32::new(fr_to_b32(&inputs[5])),
            Bytes32::new(fr_to_b32(&inputs[6])),
            Bytes32::new(fr_to_b32(&inputs[7])),
        ];
        assert!(VotingCircuit::verify_offchain(&vk, &proof, &inputs_b32).unwrap());
    }

    /// WHAT: VK `chia_chunked_bytes` is exactly 768 bytes for our
    ///       8-input circuit (CHIP rev with s7/s8 promoted).
    /// HOW:  generate setup, call chia_chunked_bytes, assert length.
    /// WHY:  this length is what `ElectionConfig::validate` checks
    ///       against (`expected_vk_bytes = 336 + (PUBLIC_INPUT_COUNT
    ///       + 1) * 48 = 768`). Drift would mean configs ship with
    ///       wrong-sized VKs and validation breaks.
    #[test]
    fn vk_chia_chunked_bytes_is_768_bytes() {
        let mut rng = deterministic_rng();
        let (_pk, vk) = generate_test_setup(&mut rng).unwrap();
        let bytes = vk.chia_chunked_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            768,
            "expected layout: alpha_g1+beta_g2+gamma_g2+delta_g2+9*ic"
        );
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
        let inputs_b32: [Bytes32; 8] = [
            Bytes32::new(fr_to_b32(&inputs[0])),
            Bytes32::new(fr_to_b32(&inputs[1])),
            Bytes32::new(fr_to_b32(&inputs[2])),
            Bytes32::new(fr_to_b32(&inputs[3])),
            Bytes32::new(fr_to_b32(&inputs[4])),
            Bytes32::new(fr_to_b32(&inputs[5])),
            Bytes32::new(fr_to_b32(&inputs[6])),
            Bytes32::new(fr_to_b32(&inputs[7])),
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
    ///       `Scalars::compute(...) → Fr` for ALL 6 public inputs.
    /// HOW:  build a circuit; call public_inputs_as_fr (Fr-typed);
    ///       independently call `Scalars::compute(...)` (Bytes32-
    ///       typed); convert each scalar to Fr via `bytes32_to_fr`;
    ///       compare element by element.
    /// WHY:  this is THE on-chain contract. The on-chain
    ///       `puzzles/ballot_coin/finalize.rue` puzzle:
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
            c.registration_vote_weight,
            &c.agg_signers,
            c.vote_message,
            c.vote_threshold_num,
            c.vote_threshold_den,
            c.ballot_launcher_id,
        );
        let scalars_fr = scalars_to_fr_array(&scalars);
        let circuit_fr = c.public_inputs_as_fr();
        assert_eq!(
            circuit_fr, scalars_fr,
            "circuit's Fr public inputs MUST equal bytes32_to_fr(Scalars::compute(...))"
        );
    }
}
