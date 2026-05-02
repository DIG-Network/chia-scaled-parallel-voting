// ============================================================================
// ceremony/participant.rs — single contributor's local view of the ceremony
// ============================================================================
//
// MODULE: ceremony::participant
// PURPOSE: One participant's local-machine view of an MPC ceremony
//          contribution. Stateless wrapper around the chosen
//          `MpcBackend`'s `contribute` method.
//
// SECURITY:
//   * Entropy MUST be generated on an air-gapped machine using a
//     hardware RNG (NOT a stdlib PRNG).
//   * Entropy MUST be securely erased after `contribute` returns —
//     the SDK zeroises its own buffers but cannot reach the caller's
//     entropy buffer.
//   * Each participant publishes their attestation (the transcript
//     hash they output) on a public channel so anyone can later
//     replay the chain and verify their contribution.
//
//! Ceremony participant — runs locally on each contributor's machine.
//!
//! ```text
//! use chip_voting_sdk::ceremony::{CeremonyParticipant, SimulatedBackend};
//!
//! // 1. Receive the current transcript from the coordinator (offline,
//! //    air-gapped — copy via USB, QR codes, etc.)
//! let input = read_transcript_from_file("input.transcript.json")?;
//!
//! // 2. Generate STRONG entropy locally and run the participant.
//! //    DO NOT use stdlib RNGs in production — use a hardware RNG,
//! //    /dev/random, or a multi-source mixer.
//! let mut entropy = [0u8; 32];
//! getrandom::getrandom(&mut entropy)?;
//!
//! let participant = CeremonyParticipant::new(
//!     Box::new(SimulatedBackend),
//!     "alice".into(),
//!     Some("Contributed at chia-eve 2026, Alice".into()),
//! );
//!
//! let output = participant.contribute(&input, entropy)?;
//!
//! // 3. SECURELY ERASE entropy. Zeroise all intermediate memory.
//! //    The SDK does its best with `zeroize` on its own buffers but
//! //    YOUR caller is responsible for the raw entropy you generated.
//!
//! // 4. Send `output.transcript` back to the coordinator and publish
//! //    `output.attestation` (e.g., on Twitter or GitHub).
//! ```

use crate::error::VotingResult;

use super::backend::MpcBackend;
use super::transcript::{ContributionAttestation, Transcript};

/// Output of a single participant's contribution.
pub struct ContributionOutput {
    /// The new transcript to send back to the coordinator.
    pub transcript: Transcript,
    /// The participant's public attestation, suitable for publishing.
    /// (This is a copy of the last entry in `transcript.attestations`.)
    pub attestation: ContributionAttestation,
}

/// A single participant's local view of the ceremony. Stateless —
/// holds the chosen backend and the participant's chosen public name.
pub struct CeremonyParticipant {
    backend: Box<dyn MpcBackend>,
    name: String,
    message: Option<String>,
}

impl CeremonyParticipant {
    pub fn new(backend: Box<dyn MpcBackend>, name: String, message: Option<String>) -> Self {
        Self {
            backend,
            name,
            message,
        }
    }

    /// Mix this participant's entropy into the previous transcript and
    /// produce the next one. The participant MUST securely erase
    /// `entropy` after this call returns.
    pub fn contribute(
        &self,
        previous: &Transcript,
        entropy: [u8; 32],
    ) -> VotingResult<ContributionOutput> {
        let next =
            self.backend
                .contribute(previous, self.name.clone(), entropy, self.message.clone())?;
        let attestation = next
            .attestations
            .last()
            .cloned()
            .expect("contribute always appends an attestation");
        Ok(ContributionOutput {
            transcript: next,
            attestation,
        })
    }
}
