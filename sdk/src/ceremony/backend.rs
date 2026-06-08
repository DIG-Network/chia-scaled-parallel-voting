// ============================================================================
// ceremony/backend.rs — pluggable MPC cryptography backend trait
// ============================================================================
//
// MODULE: ceremony::backend
// PURPOSE: Abstract trait separating ceremony ORCHESTRATION (who
//          contributes when, transcript chain validation, attestation
//          publishing) from the underlying MPC CRYPTOGRAPHY (how a
//          contribution actually mixes entropy into the transcript).
//
// DESIGN: integrators plug their preferred MPC implementation here:
//   * `phase2` (Sean Bowe's classic Groth16 phase-2 MPC, BLS12-381)
//   * `arkworks-rs/snark-mpc` (matches our ark-groth16 stack)
//   * Custom in-house implementations
//
// `MpcBackend` must provide:
//   * `initial_transcript` — genesis transcript for a fresh circuit
//   * `contribute` — mix a participant's 32 bytes of entropy in
//   * `verify` — verify a completed transcript chain is sound
//   * `extract_keys` — extract `(ProvingKey, VerificationKey)`
//
// `SimulatedBackend` is provided as a TEST-ONLY backend that
// exercises the orchestration layer using a deterministic single-
// party trusted setup (real Groth16 keys; reconstructible from
// the public transcript). MUST NEVER be used in production —
// substitute a real MPC backend (`phase2`, `arkworks-snark-mpc`).

use crate::error::VotingResult;

use super::transcript::Transcript;
use super::verification::{ProvingKey, VerificationKey};

#[async_trait::async_trait]
pub trait MpcBackend: Send + Sync {
    /// Stable identifier for this backend, e.g., `"phase2"` or
    /// `"arkworks-snark-mpc"`. Embedded in the transcript so the
    /// verifier can pick the right backend.
    fn backend_id(&self) -> &'static str;

    /// Build the initial transcript for our circuit. Typically takes
    /// a Powers-of-Tau parameter file as the entropy seed.
    fn initial_transcript(&self) -> VotingResult<Transcript>;

    /// Mix in a participant's fresh randomness, producing the next
    /// transcript. `entropy` MUST be uniformly random and securely
    /// erased after the call returns.
    fn contribute(
        &self,
        previous: &Transcript,
        participant_name: String,
        entropy: [u8; 32],
        message: Option<String>,
    ) -> VotingResult<Transcript>;

    /// Verify that a transcript chain is well-formed and that all
    /// attestations link consistently.
    fn verify(&self, transcript: &Transcript) -> VotingResult<()>;

    /// Extract the final keys after the ceremony is complete.
    fn extract_keys(&self, transcript: &Transcript) -> VotingResult<(ProvingKey, VerificationKey)>;
}

/// **DO NOT USE IN PRODUCTION.** A test backend for the ceremony
/// orchestration that uses `generate_test_setup` to produce
/// FUNCTIONAL (cryptographically-correct) Groth16 keys for the
/// `VotingCircuit` shape, but DERIVES the trusted setup from the
/// transcript's contributed entropy via a deterministic seed —
/// short-circuiting the multi-party-toxic-waste-destruction
/// guarantee. ANYONE who knows the contributed entropy can forge
/// proofs. Acceptable ONLY for testing the orchestration layer
/// (transcript chain, attestation flow, key extraction shape);
/// production deployments MUST use a real MPC backend (`phase2`,
/// `arkworks-snark-mpc`).
///
/// # tree_depth
/// SPT depth used by the Groth16 circuit. Bound at construction so
/// that contribute / extract_keys produce a (PK, VK) for the right
/// circuit shape. Default 32 — matches the historical
/// `crate::config::TREE_DEPTH` for backwards compat with existing
/// tests. Production callers (E2 onwards) derive this from
/// `CeremonyParams.max_voters` via `ceil(log2(max_voters))`.
#[derive(Debug, Clone)]
pub struct SimulatedBackend {
    pub tree_depth: usize,
    /// SEC-F1: the `VotingCircuitV2` signer-slot count baked into the VK
    /// shape. The aggregator MUST pad its signer set to this when proving
    /// (circuit_v2 `padded_signers`), so it is a protocol parameter shared
    /// by ceremony + finalize. Defaults to 1 for the simulated backend (the
    /// VK byte length — 624 — is independent of this; only setup/proving
    /// cost scales with it).
    pub max_signers: usize,
}

impl Default for SimulatedBackend {
    fn default() -> Self {
        Self { tree_depth: 32, max_signers: 1 }
    }
}

impl SimulatedBackend {
    /// Construct with an explicit tree depth — typically
    /// `ceil(log2(ceremony_params.max_voters))`.
    pub fn with_tree_depth(tree_depth: usize) -> Self {
        Self { tree_depth, max_signers: 1 }
    }
}

#[async_trait::async_trait]
impl MpcBackend for SimulatedBackend {
    fn backend_id(&self) -> &'static str {
        "simulated"
    }

    fn initial_transcript(&self) -> VotingResult<Transcript> {
        Ok(Transcript {
            circuit_id: "chip-voting-v1".into(),
            public_input_count: crate::config::PUBLIC_INPUT_COUNT,
            constraint_count: 0,
            raw_transcript_hex: hex::encode([0u8; 64]),
            attestations: Vec::new(),
        })
    }

    fn contribute(
        &self,
        previous: &Transcript,
        participant_name: String,
        entropy: [u8; 32],
        message: Option<String>,
    ) -> VotingResult<Transcript> {
        use sha2::{Digest, Sha256};
        let raw = hex::decode(&previous.raw_transcript_hex).expect("hex");
        let mut h = Sha256::new();
        h.update(&raw);
        h.update(entropy);
        let out = h.finalize();
        let new_raw = [&raw[..], &out[..]].concat();
        let new_raw_hex = hex::encode(&new_raw);
        let new_hash_hex = {
            let out = Sha256::digest(&new_raw);
            hex::encode(out)
        };
        let prev_hash_hex = previous.hash_hex();
        let mut next = previous.clone();
        next.raw_transcript_hex = new_raw_hex;
        next.attestations
            .push(super::transcript::ContributionAttestation {
                index: (previous.attestations.len() as u32) + 1,
                participant_name,
                transcript_hash_hex: new_hash_hex,
                previous_transcript_hash_hex: prev_hash_hex,
                message,
            });
        Ok(next)
    }

    fn verify(&self, transcript: &Transcript) -> VotingResult<()> {
        // Verify attestation chain hashes link.
        use sha2::{Digest, Sha256};
        let initial_hash = {
            let initial_raw = [0u8; 64];
            let out = Sha256::digest(initial_raw);
            hex::encode(out)
        };
        let mut prev_hash = initial_hash;
        for att in &transcript.attestations {
            if att.previous_transcript_hash_hex != prev_hash {
                return Err(crate::VotingError::CeremonyTranscriptCorrupt);
            }
            prev_hash = att.transcript_hash_hex.clone();
        }
        Ok(())
    }

    fn extract_keys(&self, transcript: &Transcript) -> VotingResult<(ProvingKey, VerificationKey)> {
        // Derive a deterministic RNG seed from the transcript's
        // raw contributed entropy. EVERY participant's contribution
        // mixes into raw_transcript_hex; hashing it gives a fixed
        // 32-byte seed that uniquely identifies the (public)
        // ceremony state.
        //
        // Production semantics: the participant's secret randomness
        // is irrecoverable post-erasure. Here it's recomputable
        // from the public transcript, which is FINE for testing
        // (the goal is to validate the orchestration code path)
        // but UNSAFE for real elections.
        use ark_serialize::CanonicalSerialize;
        use ark_std::rand::SeedableRng;
        use sha2::{Digest, Sha256};

        let raw = hex::decode(&transcript.raw_transcript_hex).map_err(|e| {
            crate::VotingError::Other(crate::error::anyhow_compat::Error(
                format!("transcript raw hex: {e}").into(),
            ))
        })?;
        let mut h = Sha256::new();
        h.update(b"chip-voting-simulated-backend-seed");
        h.update(transcript.circuit_id.as_bytes());
        h.update(&raw);
        let seed = h.finalize();
        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed);
        let mut rng = ark_std::rand::rngs::StdRng::from_seed(rng_seed);

        // SEC-F1: run the VotingCircuitV2 (Option-B) setup to produce real,
        // verification-correct (PK, VK) — 5 public inputs / 6 IC points
        // (624-byte chia-chunked VK). tree_depth + max_signers fix the R1CS
        // shape the election singleton curries and the aggregator proves
        // against.
        let (ark_pk, ark_vk) = crate::prover::circuit_v2::generate_test_setup_v2(
            self.tree_depth,
            self.max_signers,
            &mut rng,
        )?;

        // Serialise both keys to opaque byte buffers for the
        // backend-agnostic ProvingKey / VerificationKey wrappers.
        // Production backends use their own encodings; for
        // SimulatedBackend we use arkworks compressed form.
        let mut pk_bytes = Vec::new();
        ark_pk
            .0
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| crate::VotingError::ProvingError(format!("serialize PK: {e}")))?;
        let vk_bytes = ark_vk.chia_chunked_bytes()?;

        Ok((
            ProvingKey {
                raw_bytes: pk_bytes,
            },
            VerificationKey {
                raw_bytes: vk_bytes,
            },
        ))
    }
}
