// ============================================================================
// ceremony/transcript.rs — public ceremony artefact
// ============================================================================
//
// MODULE: ceremony::transcript
// PURPOSE: types for the artefact passed between MPC participants and
//          published for independent verification.
//
// SECURITY MODEL:
//   * Transcripts are PUBLIC. They contain only commitments —
//     never the secret entropy itself.
//   * Each participant publishes a `ContributionAttestation` (their
//     index, name, output transcript hash, input transcript hash) so
//     anyone can replay the chain offline.

use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

/// FN: parse_bytes32 (file-private)
/// WHAT: hex string → `Bytes32`. Panics on bad input — only used on
///       fields that the type system guarantees are well-formed
///       (because they came from `hash_hex`).
fn parse_bytes32(s: &str) -> Bytes32 {
    let bytes = hex::decode(s.trim()).expect("transcript hash hex");
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    Bytes32::new(arr)
}

/// One participant's public attestation to their contribution. Posted
/// to a public channel (Twitter / GitHub / Discord / a web page) so
/// anyone can later verify the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionAttestation {
    /// Sequential index of this contribution (1-based, ceremony-wide).
    pub index: u32,

    /// Free-form name / handle the participant chose to publish under.
    pub participant_name: String,

    /// SHA-256 hash of the OUTPUT transcript bytes after this
    /// participant's contribution. Hex-encoded — anyone can recompute
    /// and compare.
    pub transcript_hash_hex: String,

    /// SHA-256 hash of the INPUT transcript this participant consumed.
    /// Hex-encoded. Lets verifiers chain attestations: this
    /// contribution's `previous_transcript_hash` MUST equal the
    /// previous contribution's `transcript_hash`.
    pub previous_transcript_hash_hex: String,

    /// Optional message the participant chose to include in their
    /// attestation (e.g., randomness sources used, BIP-340 signature
    /// over the transcript hash by a publicly-known key, etc.).
    #[serde(default)]
    pub message: Option<String>,
}

impl ContributionAttestation {
    pub fn transcript_hash(&self) -> Bytes32 {
        parse_bytes32(&self.transcript_hash_hex)
    }

    pub fn previous_transcript_hash(&self) -> Bytes32 {
        parse_bytes32(&self.previous_transcript_hash_hex)
    }
}

/// The full ceremony transcript — circuit-specific cryptographic
/// material plus an audit trail of attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transcript {
    /// Circuit identifier (e.g., "chip-voting-v1") — included so
    /// transcripts from different circuits can't be mixed up.
    pub circuit_id: String,

    /// Total number of public inputs to the circuit
    /// (`PUBLIC_INPUT_COUNT = 6` for our voting CHIP rev
    /// 2026-05-02 — `registration_merkle_root`,
    /// `registration_vote_weight`, `agg_signers`, `vote_message`,
    /// `threshold_pack`, `ballot_launcher_id`).
    pub public_input_count: usize,

    /// Total number of constraints in the R1CS (informational).
    pub constraint_count: usize,

    /// Backend-specific raw transcript bytes (the cryptographic state
    /// produced by the underlying MPC implementation, e.g., bellman's
    /// `phase2::MPCParameters`). Serialised with whatever encoding
    /// the chosen backend uses.
    ///
    /// In hex form for JSON portability — typically several MB.
    pub raw_transcript_hex: String,

    /// Append-only chain of public attestations, one per participant.
    pub attestations: Vec<ContributionAttestation>,
}

impl Transcript {
    /// Compute the SHA-256 hash of the raw transcript bytes — used to
    /// link attestations and to publish a compact "I contributed"
    /// fingerprint.
    pub fn hash(&self) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let raw = hex::decode(&self.raw_transcript_hex).expect("transcript hex is valid");
        let out = Sha256::digest(raw);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Bytes32::new(arr)
    }

    /// Hex-encoded form of [`hash`].
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Number of contributions so far.
    pub fn contribution_count(&self) -> usize {
        self.attestations.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_transcript() -> Transcript {
        Transcript {
            circuit_id: "chip-voting-v1".into(),
            public_input_count: 4,
            constraint_count: 100,
            raw_transcript_hex: hex::encode([0u8; 64]),
            attestations: vec![],
        }
    }

    /// WHAT: `Transcript::hash` is deterministic.
    /// HOW:  call `hash` twice on the same transcript, assert
    ///       equality.
    /// WHY:  attestations chain by hash; non-determinism would
    ///       break every chain-link verification.
    #[test]
    fn hash_is_deterministic() {
        let t = empty_transcript();
        assert_eq!(t.hash(), t.hash());
    }

    /// WHAT: `Transcript::hash` is sensitive to `raw_transcript_hex`
    ///       — different raw bytes → different hashes.
    /// HOW:  construct two transcripts with different raw bytes
    ///       (`[1; 64]` vs `[2; 64]`) and assert hashes differ in
    ///       both directions.
    /// WHY:  the hash is the only commitment to the underlying
    ///       cryptographic state; if it weren't sensitive to that
    ///       state, an adversary could swap raw bytes without
    ///       detection.
    #[test]
    fn hash_changes_with_raw_transcript() {
        let mut a = empty_transcript();
        let b = {
            let mut x = a.clone();
            x.raw_transcript_hex = hex::encode([1u8; 64]);
            x
        };
        assert_ne!(a.hash(), b.hash());
        a.raw_transcript_hex = hex::encode([2u8; 64]);
        assert_ne!(a.hash(), b.hash());
    }

    /// WHAT: `Transcript::hash` is INDEPENDENT of the attestations
    ///       vector.
    /// HOW:  take an empty transcript's hash, push an attestation,
    ///       assert the hash is unchanged.
    /// WHY:  attestations chain prior states by their hash, so the
    ///       current transcript's hash must NOT include attestations
    ///       (otherwise the chain link would be self-referential).
    ///       This test pins that subtle invariant.
    #[test]
    fn hash_does_not_depend_on_attestations() {
        let a = empty_transcript();
        let mut b = a.clone();
        b.attestations.push(ContributionAttestation {
            index: 1,
            participant_name: "alice".into(),
            transcript_hash_hex: a.hash_hex(),
            previous_transcript_hash_hex: a.hash_hex(),
            message: None,
        });
        assert_eq!(a.hash(), b.hash());
    }

    /// WHAT: `hash_hex` followed by `parse_bytes32` recovers the
    ///       original `Bytes32` exactly.
    /// HOW:  serialise hash to hex, parse, compare to original.
    /// WHY:  the chain-link verification reads
    ///       `previous_transcript_hash_hex` and parses it via
    ///       `parse_bytes32`; this round-trip must be lossless.
    #[test]
    fn hash_hex_roundtrips_through_parse_bytes32() {
        let t = empty_transcript();
        let hex_form = t.hash_hex();
        assert_eq!(t.hash(), parse_bytes32(&hex_form));
    }

    /// WHAT: `contribution_count` equals `attestations.len()`.
    /// HOW:  start with empty transcript (count = 0), push one
    ///       attestation, assert count = 1.
    /// WHY:  callers (UIs, audit dashboards) rely on this trivial
    ///       accessor for participant counts; pin it so refactors
    ///       can't accidentally change the meaning.
    #[test]
    fn contribution_count_tracks_attestation_vec() {
        let mut t = empty_transcript();
        assert_eq!(t.contribution_count(), 0);
        t.attestations.push(ContributionAttestation {
            index: 1,
            participant_name: "x".into(),
            transcript_hash_hex: t.hash_hex(),
            previous_transcript_hash_hex: t.hash_hex(),
            message: None,
        });
        assert_eq!(t.contribution_count(), 1);
    }
}
