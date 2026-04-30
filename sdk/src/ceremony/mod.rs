// ============================================================================
// ceremony/ — Multi-Party Computation (MPC) trusted-setup orchestration
// ============================================================================
//
// MODULE: ceremony
// PURPOSE: Orchestrate a Groth16 trusted-setup ceremony for the
//          voting circuit, producing a `(ProvingKey, VerificationKey)`
//          pair where the toxic waste is destroyed by ≥1 honest party.
//
// SECURITY MODEL: Groth16 requires circuit-specific structured
//   reference strings. If a single party knows the secret randomness
//   ("toxic waste"), they can forge proofs. The MPC fix: many
//   participants each contribute randomness, mixing it into the
//   running transcript. As long as ONE participant honestly discards
//   their contribution, the final keys are sound — even if every
//   other participant is malicious.
//
//! Multi-Party Computation (MPC) ceremony for the Groth16 trusted setup.
//!
//! Groth16 requires a circuit-specific trusted setup that produces a
//! `(ProvingKey, VerificationKey)` pair. The setup involves secret
//! "toxic waste" that, if any single participant leaks it, lets that
//! participant forge proofs. The MPC ceremony fixes this: every
//! participant contributes randomness, and as long as **at least one**
//! participant is honest and discards their contribution, the final
//! keys are sound.
//!
//! This module exposes:
//!
//! * [`CeremonyCoordinator`] — assembles the ceremony, drives the
//!   sequence of participant contributions, and finalises the keys.
//! * [`CeremonyParticipant`] — a single participant's local view; takes
//!   the previous transcript, mixes in fresh randomness, and produces
//!   the next transcript.
//! * [`Transcript`] — the public artefact passed between participants;
//!   contains every previous contribution's public attestation.
//! * [`VerificationKey`] — the final on-chain VK, ready to be hex-
//!   encoded and curried into the Election Singleton's `finalize`
//!   action.
//! * [`verify_transcript`] — independent verifier; anyone can audit a
//!   completed transcript without trusting the coordinator.
//!
//! ## Workflow
//!
//! ```text
//!  ┌────────┐  initial transcript  ┌────────────┐  next transcript  ┌────────────┐
//!  │ Coord. │ ─────────────────►  │ Participant│ ────────────────►│ Participant│ ─►  …
//!  │        │                      │     1      │                    │     2      │
//!  └────────┘                      └────────────┘                    └────────────┘
//!                                                                         │
//!                                                       final transcript ▼
//!                                                              ┌────────────────┐
//!                                                              │ verify + finalise│
//!                                                              │     → VK         │
//!                                                              └────────────────┘
//! ```
//!
//! ## Security
//!
//! * Each participant **MUST** generate their randomness on an
//!   air-gapped machine and securely erase it (and any intermediate
//!   memory) immediately after producing their attestation.
//! * Participants **MUST** publicly attest to their contribution —
//!   typically by tweeting / publishing on GitHub the hash of the new
//!   transcript so anyone can later recompute and verify.
//! * The coordinator **MUST** publish every intermediate transcript so
//!   independent verifiers can replay the chain.
//! * A single-party setup (zero participants) is rejected by
//!   `CeremonyCoordinator::finalize` with `VotingError::UnsafeSingleParty`.
//!
//! ## Interop
//!
//! This API does NOT implement the cryptographic protocol itself —
//! that's delegated to a backing implementation (an `MpcBackend`) which
//! integrators can swap out. Recommended backends:
//!
//! * [`phase2`](https://github.com/ebfull/phase2) — Sean Bowe's classic
//!   Groth16 phase-2 implementation (BLS12-381).
//! * [`arkworks/snark-mpc`](https://github.com/arkworks-rs) — pure-ark
//!   implementation matching our `ark-groth16` proving stack.
//!
//! A reference [`SimulatedBackend`](backend::SimulatedBackend) is
//! included for testing — **NEVER use it in production**.

pub mod backend;
pub mod coordinator;
pub mod participant;
pub mod transcript;
pub mod verification;

pub use backend::{MpcBackend, SimulatedBackend};
pub use coordinator::CeremonyCoordinator;
pub use participant::CeremonyParticipant;
pub use transcript::{Transcript, ContributionAttestation};
pub use verification::{verify_transcript, VerificationKey, ProvingKey};
