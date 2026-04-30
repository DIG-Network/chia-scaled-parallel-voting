// ============================================================================
// ceremony/verification.rs — independent ceremony auditor
// ============================================================================
//
// MODULE: ceremony::verification
// PURPOSE: Anyone-can-audit verification of a completed MPC
//          transcript. Decoupled from the coordinator so a third
//          party can replay the chain offline given just the
//          published transcript + the chosen `MpcBackend`.
//
// DESIGN:
//   * `VerificationKey` and `ProvingKey` are intentionally opaque
//     byte buffers at this layer — the byte format is determined by
//     the chosen MPC backend (`phase2`, `arkworks-snark-mpc`, etc.).
//   * Concrete `ark-groth16` types live in `crate::prover` (via
//     `ArkVerifyingKey::deserialize_compressed`); the backend's
//     `extract_keys` impl is what bridges between this opaque form
//     and the typed prover.
//
// AUDIT GUARANTEE: `verify_transcript(t, &backend)` returns `Ok(())`
//   iff the transcript chain is sound. Failure modes are detailed in
//   the function's doc-comment.

use serde::{Deserialize, Serialize};

use crate::error::VotingResult;

use super::backend::MpcBackend;
use super::transcript::Transcript;

/// Final Groth16 verification key in raw serialised form. Hex-encoded
/// into `ElectionConfig.verification_key_hex` for on-chain currying.
///
/// Layout for our circuit:
///   alpha_g1 (48) || beta_g2 (96) || gamma_g2 (96) || delta_g2 (96) ||
///   ic_0 (48) || ic_1 (48) || ic_2 (48) || ic_3 (48) || ic_4 (48)
/// = 576 bytes total (5 IC points = `PUBLIC_INPUT_COUNT + 1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub raw_bytes: Vec<u8>,
}

impl VerificationKey {
    pub fn serialize(&self) -> Vec<u8> {
        self.raw_bytes.clone()
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        Ok(Self { raw_bytes: hex::decode(hex_str)? })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.raw_bytes)
    }
}

/// Final Groth16 proving key. Held only by aggregators (which need it
/// to produce proofs); never goes on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingKey {
    pub raw_bytes: Vec<u8>,
}

/// Full independent verification of a completed ceremony.
///
/// Anyone can call this to re-verify the chain WITHOUT trusting the
/// coordinator — they only need the published transcript and the
/// backend implementation. Returns `Ok(())` if the chain is sound.
///
/// What is verified:
///   1. Each attestation's `previous_transcript_hash` matches the
///      previous attestation's `transcript_hash`.
///   2. Each attestation's `transcript_hash` actually hashes to the
///      raw transcript bytes at that point in the chain.
///   3. The backend-specific cryptographic verification of every
///      contribution (e.g., that each participant's update is a valid
///      knowledge-of-toxic-waste proof).
pub fn verify_transcript(transcript: &Transcript, backend: &dyn MpcBackend) -> VotingResult<()> {
    backend.verify(transcript)
}
