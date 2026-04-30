// ============================================================================
// ceremony/coordinator.rs — sequential contribution driver
// ============================================================================
//
// MODULE: ceremony::coordinator
// PURPOSE: Stateful orchestrator that hands the current transcript to
//          the next participant and validates each returned contribution.
// THREAD-MODEL: single-threaded; single ceremony per coordinator.
// SECURITY: validates per-contribution chain hashes BEFORE accepting
//           — a corrupted contribution can never overwrite the current
//           transcript.
//!
//! ```text
//! use chip_voting_sdk::ceremony::{CeremonyCoordinator, MpcBackend, SimulatedBackend};
//!
//! // Production: use a real backend like phase2 or arkworks-rs/snark-mpc.
//! let backend = Box::new(SimulatedBackend);
//! let mut coord = CeremonyCoordinator::new(backend);
//!
//! coord.start("chip-voting-v1".into())?;
//!
//! // Send `coord.current_transcript()` to participant 1 (off-line,
//! // air-gapped). They run a CeremonyParticipant locally and return
//! // the next transcript + attestation.
//! coord.accept_contribution(participant1_transcript)?;
//!
//! // Repeat for each participant…
//! coord.accept_contribution(participant2_transcript)?;
//!
//! // After at least one contribution, finalise.
//! let vk = coord.finalize()?;
//!
//! // `vk` goes into `ElectionConfig.verification_key_hex` for deployment.
//! ```

use crate::error::{VotingError, VotingResult};

use super::backend::MpcBackend;
use super::transcript::Transcript;
use super::verification::VerificationKey;

pub struct CeremonyCoordinator {
    backend: Box<dyn MpcBackend>,
    transcript: Option<Transcript>,
    finalized: bool,
}

impl CeremonyCoordinator {
    pub fn new(backend: Box<dyn MpcBackend>) -> Self {
        Self {
            backend,
            transcript: None,
            finalized: false,
        }
    }

    /// Initialise the ceremony with the genesis transcript.
    pub fn start(&mut self, _circuit_id: String) -> VotingResult<()> {
        if self.transcript.is_some() {
            return Err(VotingError::Other(crate::error::anyhow_compat::Error(
                "CeremonyCoordinator: already started".into(),
            )));
        }
        self.transcript = Some(self.backend.initial_transcript()?);
        Ok(())
    }

    /// Resume coordination from a previously-known-good transcript
    /// (loaded from disk by the CLI between participant rounds).
    /// Verifies the transcript with the backend before adopting it,
    /// so a tampered transcript can never quietly become the
    /// coordinator's "current" state.
    ///
    /// CALLER CONTRACT: the caller must have stored the transcript
    /// from a previous `accept_contribution` (or the genesis
    /// transcript from `start` + `current_transcript`). Resuming
    /// from a transcript the coordinator never produced is allowed
    /// (e.g. the CLI use case) AS LONG AS `backend.verify` passes
    /// — that's the only soundness check needed because every
    /// later `accept_contribution` will chain-validate against
    /// this transcript's hash.
    pub fn resume(&mut self, transcript: Transcript) -> VotingResult<()> {
        if self.transcript.is_some() {
            return Err(VotingError::Other(crate::error::anyhow_compat::Error(
                "CeremonyCoordinator: already started".into(),
            )));
        }
        self.backend.verify(&transcript)?;
        self.transcript = Some(transcript);
        Ok(())
    }

    /// Get the current transcript — send this to the next participant.
    pub fn current_transcript(&self) -> VotingResult<&Transcript> {
        self.transcript
            .as_ref()
            .ok_or_else(|| VotingError::Other(crate::error::anyhow_compat::Error(
                "CeremonyCoordinator: not started".into(),
            )))
    }

    /// Accept a participant's contribution. The new transcript replaces
    /// the current one. The backend verifies the chain consistency.
    pub fn accept_contribution(&mut self, contributed: Transcript) -> VotingResult<()> {
        if self.finalized {
            return Err(VotingError::CeremonyFinalized);
        }
        let current = self.current_transcript()?;
        if contributed.attestations.len() != current.attestations.len() + 1 {
            return Err(VotingError::CeremonyTranscriptCorrupt);
        }
        let last = contributed.attestations.last().expect("just checked");
        if last.previous_transcript_hash_hex != current.hash_hex() {
            return Err(VotingError::CeremonyTranscriptCorrupt);
        }
        if last.transcript_hash_hex != contributed.hash_hex() {
            return Err(VotingError::CeremonyTranscriptCorrupt);
        }
        self.backend.verify(&contributed)?;
        self.transcript = Some(contributed);
        Ok(())
    }

    /// Number of contributions accepted so far.
    pub fn contribution_count(&self) -> usize {
        self.transcript
            .as_ref()
            .map(|t| t.contribution_count())
            .unwrap_or(0)
    }

    /// Extract the final VerificationKey. Refuses if no participants
    /// have contributed (single-party setup is unsafe per the CHIP).
    pub fn finalize(&mut self) -> VotingResult<VerificationKey> {
        let transcript = self.current_transcript()?;
        if transcript.attestations.is_empty() {
            return Err(VotingError::UnsafeSingleParty);
        }
        let (_pk, vk) = self.backend.extract_keys(transcript)?;
        self.finalized = true;
        Ok(vk)
    }

    /// Get a snapshot of the published audit chain for posting to
    /// GitHub / a website.
    pub fn published_attestations(&self) -> VotingResult<Vec<super::transcript::ContributionAttestation>> {
        Ok(self.current_transcript()?.attestations.clone())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::backend::SimulatedBackend;
    use crate::ceremony::participant::CeremonyParticipant;
    use crate::error::VotingError;

    fn coord() -> CeremonyCoordinator {
        CeremonyCoordinator::new(Box::new(SimulatedBackend))
    }

    /// WHAT: `current_transcript()` errors before `start()` is
    ///       called.
    /// HOW:  build a coordinator, immediately call
    ///       `current_transcript()`, assert error.
    /// WHY:  enforces the lifecycle — accidentally accepting
    ///       contributions before genesis is constructed would
    ///       silently corrupt the chain.
    #[test]
    fn cannot_get_transcript_before_start() {
        let c = coord();
        assert!(c.current_transcript().is_err());
    }

    /// WHAT: calling `start()` twice on the same coordinator errors.
    /// HOW:  start once successfully, start again, assert second
    ///       call returns `Err`.
    /// WHY:  prevents an accidental restart from wiping the in-
    ///       progress chain (would silently lose all attestations).
    #[test]
    fn double_start_is_rejected() {
        let mut c = coord();
        c.start("chip-voting-v1".into()).unwrap();
        assert!(c.start("chip-voting-v1".into()).is_err());
    }

    /// WHAT: finalising a ceremony with zero contributions returns
    ///       `VotingError::UnsafeSingleParty`.
    /// HOW:  start coordinator, immediately call `finalize`, match
    ///       the specific error variant.
    /// WHY:  zero-party / single-party setups defeat the whole point
    ///       of the MPC — the toxic-waste secret would be recoverable.
    ///       Pin the specific error so callers can branch on it.
    #[test]
    fn finalize_with_zero_contributions_is_unsafe() {
        let mut c = coord();
        c.start("chip-voting-v1".into()).unwrap();
        match c.finalize() {
            Err(VotingError::UnsafeSingleParty) => {}
            other => panic!("expected UnsafeSingleParty, got {:?}", other),
        }
    }

    /// WHAT: a full coordinator → 2 participants → coordinator.finalize
    ///       cycle succeeds and produces a non-empty VK.
    /// HOW:  drive the full happy path: start, accept Alice's
    ///       contribution, accept Bob's contribution, finalize. Assert
    ///       contribution_count = 2 and vk has bytes.
    /// WHY:  end-to-end coverage of the orchestrator state machine —
    ///       the only way to know all the per-step assertions
    ///       compose into a working flow.
    #[test]
    fn happy_path_two_participants() {
        let mut c = coord();
        c.start("chip-voting-v1".into()).unwrap();

        let alice = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "alice".into(),
            None,
        );
        let bob = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "bob".into(),
            None,
        );

        let t1 = c.current_transcript().unwrap().clone();
        let alice_out = alice.contribute(&t1, [0xAAu8; 32]).unwrap();
        c.accept_contribution(alice_out.transcript).unwrap();

        let t2 = c.current_transcript().unwrap().clone();
        let bob_out = bob.contribute(&t2, [0xBBu8; 32]).unwrap();
        c.accept_contribution(bob_out.transcript).unwrap();

        assert_eq!(c.contribution_count(), 2);

        let vk = c.finalize().unwrap();
        assert!(!vk.raw_bytes.is_empty());
    }

    /// WHAT: a contribution whose `previous_transcript_hash_hex`
    ///       doesn't match the current transcript hash is rejected
    ///       with `CeremonyTranscriptCorrupt`.
    /// HOW:  produce a real contribution from Alice, mutate her
    ///       attestation's previous-hash field to `0xFF...FF`, submit.
    /// WHY:  this is the chain-link integrity check — without it an
    ///       attacker could inject a contribution that branches off
    ///       a forged earlier state.
    #[test]
    fn rejects_contribution_with_wrong_chain_link() {
        let mut c = coord();
        c.start("chip-voting-v1".into()).unwrap();

        let alice = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "alice".into(),
            None,
        );
        let t = c.current_transcript().unwrap().clone();
        let mut out = alice.contribute(&t, [0xAAu8; 32]).unwrap();
        // Tamper with the chain link.
        out.transcript.attestations[0].previous_transcript_hash_hex = "ff".repeat(32);
        match c.accept_contribution(out.transcript) {
            Err(VotingError::CeremonyTranscriptCorrupt) => {}
            other => panic!("expected CeremonyTranscriptCorrupt, got {:?}", other),
        }
    }

    /// WHAT: `resume` adopts a previously-known transcript and
    ///       allows further `accept_contribution`s to chain from it.
    /// HOW:  drive coord_a through 1 contribution, snapshot its
    ///       transcript, build a fresh coord_b, `resume` it from
    ///       the snapshot, then accept a 2nd contribution.
    /// WHY:  models the CLI's between-participant-round persistence:
    ///       coordinator is loaded fresh each invocation, so
    ///       `resume` MUST faithfully reconstruct enough state to
    ///       accept the next chained contribution.
    #[test]
    fn resume_round_trips_through_disk_persistence() {
        let mut a = coord();
        a.start("chip-voting-v1".into()).unwrap();
        let alice = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "alice".into(),
            None,
        );
        let t1 = a.current_transcript().unwrap().clone();
        let alice_out = alice.contribute(&t1, [0xAAu8; 32]).unwrap();
        a.accept_contribution(alice_out.transcript).unwrap();
        let snapshot = a.current_transcript().unwrap().clone();

        // Fresh coordinator, no in-memory state — exactly what the
        // CLI looks like on the next invocation.
        let mut b = coord();
        b.resume(snapshot).unwrap();
        assert_eq!(b.contribution_count(), 1);

        let bob = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "bob".into(),
            None,
        );
        let t2 = b.current_transcript().unwrap().clone();
        let bob_out = bob.contribute(&t2, [0xBBu8; 32]).unwrap();
        b.accept_contribution(bob_out.transcript).unwrap();
        assert_eq!(b.contribution_count(), 2);

        let vk = b.finalize().unwrap();
        assert!(!vk.raw_bytes.is_empty());
    }

    /// WHAT: `resume` rejects a transcript that fails backend
    ///       verification.
    /// HOW:  build a real transcript, mutate one attestation's hash
    ///       so the chain breaks, `resume`. Expect
    ///       `CeremonyTranscriptCorrupt`.
    /// WHY:  resume is the trust boundary between persisted state
    ///       and live coordination — a tampered file MUST be
    ///       rejected at adoption time, not silently treated as
    ///       authoritative.
    #[test]
    fn resume_rejects_tampered_transcript() {
        let mut a = coord();
        a.start("chip-voting-v1".into()).unwrap();
        let alice = CeremonyParticipant::new(
            Box::new(SimulatedBackend),
            "alice".into(),
            None,
        );
        let t1 = a.current_transcript().unwrap().clone();
        let alice_out = alice.contribute(&t1, [0xAAu8; 32]).unwrap();
        a.accept_contribution(alice_out.transcript).unwrap();
        let mut tampered = a.current_transcript().unwrap().clone();
        tampered.attestations[0].previous_transcript_hash_hex = "00".repeat(32);

        let mut b = coord();
        match b.resume(tampered) {
            Err(VotingError::CeremonyTranscriptCorrupt) => {}
            other => panic!("expected CeremonyTranscriptCorrupt, got {:?}", other),
        }
    }

    /// WHAT: a contribution whose `attestations.len()` doesn't equal
    ///       `current.attestations.len() + 1` is rejected with
    ///       `CeremonyTranscriptCorrupt`.
    /// HOW:  clone the current transcript with attestations cleared,
    ///       submit as a "contribution".
    /// WHY:  the participant must append exactly ONE new attestation
    ///       per contribution — submitting more (or fewer) would
    ///       mean the chain is being silently re-written. Pin the
    ///       exact error variant so downstream code can match on it.
    #[test]
    fn rejects_contribution_with_wrong_attestation_count() {
        let mut c = coord();
        c.start("chip-voting-v1".into()).unwrap();

        let mut forged = c.current_transcript().unwrap().clone();
        forged.attestations.clear();
        match c.accept_contribution(forged) {
            Err(VotingError::CeremonyTranscriptCorrupt) => {}
            other => panic!("expected CeremonyTranscriptCorrupt, got {:?}", other),
        }
    }
}
