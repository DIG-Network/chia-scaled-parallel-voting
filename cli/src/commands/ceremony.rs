// ============================================================================
// commands/ceremony.rs — MPC trusted-setup orchestration
// ============================================================================
//
// VERB: chip-voting ceremony
// PURPOSE: Drive the multi-party Groth16 trusted setup that produces
//          the verification key for an election deployment.
//
// FLOW (typical):
//   1. Coordinator runs `ceremony init --output transcript.json`.
//   2. Coordinator hands transcript.json to participant 1 (offline,
//      air-gapped).
//   3. Participant 1 runs `ceremony contribute --input
//      transcript.json --output transcript.1.json` on their offline
//      machine. They publish their attestation to a public channel
//      (Twitter, GitHub, etc.).
//   4. Coordinator runs `ceremony accept --input transcript.1.json`
//      to absorb the contribution.
//   5. Repeat steps 2-4 for every participant.
//   6. Anyone can run `ceremony verify --input transcript.N.json`
//      to independently audit the chain.
//   7. Coordinator runs `ceremony finalize --input transcript.N.json
//      --vk-output vk.json` to extract the verification key for
//      `chip-voting deployer deploy --vk-file vk.json`.
//
// SECURITY:
//   * The CLI uses `getrandom` for entropy by default. For
//     PRODUCTION, supply your own entropy via `--entropy-file`
//     (sourced from a hardware RNG / multi-source mixer).
//   * Each participant MUST run their `contribute` step on an
//     air-gapped machine. The CLI does NOT prevent network
//     activity; participants are responsible for their machine
//     hygiene.
//   * The `SimulatedBackend` is the ONLY backend currently shipped.
//     It produces FUNCTIONAL Groth16 keys (suitable for end-to-end
//     orchestration testing AND for running the full proving
//     pipeline on a Simulator) BUT derives the trusted setup
//     deterministically from the public transcript — anyone can
//     reconstruct the toxic waste. For PRODUCTION, plug in a real
//     MPC backend (`phase2`, `arkworks-snark-mpc`) by extending
//     `chip-voting-sdk::ceremony::MpcBackend` and re-building.

use anyhow::{Context as _, Result};
use chip_voting_sdk::ceremony::{
    verify_transcript, CeremonyCoordinator, CeremonyParticipant, SimulatedBackend, Transcript,
    VerificationKey,
};
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;

#[derive(Debug, Subcommand)]
pub enum CeremonyCmd {
    /// Initialise a new ceremony — emit the genesis transcript.
    Init {
        /// Free-form circuit identifier (typically `chip-voting-v1`).
        /// Recorded in the transcript so transcripts from different
        /// circuits can't be mixed up.
        #[arg(long, default_value = "chip-voting-v1")]
        circuit_id: String,

        /// Where to write the genesis transcript.
        #[arg(long)]
        output: PathBuf,

        #[arg(long)]
        overwrite: bool,
    },

    /// Run one participant's contribution. Reads the input
    /// transcript, mixes in fresh entropy, writes the output
    /// transcript + the attestation. The participant publishes the
    /// attestation to a public channel.
    ///
    /// SECURITY: run on an AIR-GAPPED machine in production.
    Contribute {
        /// Input transcript (received from the coordinator).
        #[arg(long)]
        input: PathBuf,

        /// Where to write the new transcript (send to the
        /// coordinator).
        #[arg(long)]
        output: PathBuf,

        /// Free-form participant name / handle (recorded in the
        /// attestation).
        #[arg(long)]
        participant_name: String,

        /// Optional message to include in the attestation
        /// (e.g., randomness sources used, BIP-340 sig, etc.).
        #[arg(long)]
        message: Option<String>,

        /// Path to a 32-byte file of fresh entropy (HARDWARE RNG
        /// recommended for production). If omitted, the CLI uses
        /// `getrandom` — acceptable for testing only.
        #[arg(long)]
        entropy_file: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,
    },

    /// Coordinator-side: accept a participant's returned transcript
    /// (validate the chain link + cryptographic verification) and
    /// write the new ceremony state.
    Accept {
        /// Current ceremony state (the transcript we sent to the
        /// participant).
        #[arg(long)]
        current: PathBuf,

        /// Returned transcript from the participant.
        #[arg(long)]
        contribution: PathBuf,

        /// Where to write the updated ceremony state.
        #[arg(long)]
        output: PathBuf,

        #[arg(long)]
        overwrite: bool,
    },

    /// Independently verify a transcript. Anyone can run this with
    /// just the published transcript; no coordinator state needed.
    Verify {
        #[arg(long)]
        input: PathBuf,
    },

    /// Extract the final VerificationKey from a completed transcript.
    /// Refuses transcripts with zero contributions.
    Finalize {
        #[arg(long)]
        input: PathBuf,

        /// Where to write the VK JSON (consumed by `deployer
        /// deploy --vk-file`).
        #[arg(long)]
        vk_output: PathBuf,

        #[arg(long)]
        overwrite: bool,
    },
}

pub async fn run(cmd: CeremonyCmd, ctx: &Context) -> Result<()> {
    match cmd {
        CeremonyCmd::Init {
            circuit_id,
            output,
            overwrite,
        } => init(circuit_id, output, overwrite, ctx),
        CeremonyCmd::Contribute {
            input,
            output,
            participant_name,
            message,
            entropy_file,
            overwrite,
        } => contribute(
            input,
            output,
            participant_name,
            message,
            entropy_file,
            overwrite,
            ctx,
        ),
        CeremonyCmd::Accept {
            current,
            contribution,
            output,
            overwrite,
        } => accept(current, contribution, output, overwrite, ctx),
        CeremonyCmd::Verify { input } => verify(input, ctx),
        CeremonyCmd::Finalize {
            input,
            vk_output,
            overwrite,
        } => finalize(input, vk_output, overwrite, ctx),
    }
}

fn init(
    circuit_id: String,
    output: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord
        .start(circuit_id.clone())
        .map_err(|e| anyhow::anyhow!("start: {e:?}"))?;
    let transcript = coord
        .current_transcript()
        .map_err(|e| anyhow::anyhow!("current_transcript: {e:?}"))?;
    config_file::save_json(&output, transcript, overwrite)?;
    ctx.print(&serde_json::json!({
        "wrote":          output.display().to_string(),
        "circuit_id":     circuit_id,
        "transcript_hash": transcript.hash_hex(),
        "contributions":  0,
    }))
}

fn contribute(
    input: PathBuf,
    output: PathBuf,
    participant_name: String,
    message: Option<String>,
    entropy_file: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let previous: Transcript = config_file::load_json(&input)?;
    let entropy = load_entropy(entropy_file.as_ref())?;
    let participant =
        CeremonyParticipant::new(Box::new(SimulatedBackend), participant_name.clone(), message);
    let output_data = participant
        .contribute(&previous, entropy)
        .map_err(|e| anyhow::anyhow!("contribute: {e:?}"))?;
    config_file::save_json(&output, &output_data.transcript, overwrite)?;
    ctx.print(&serde_json::json!({
        "wrote":             output.display().to_string(),
        "participant_name":  participant_name,
        "attestation_index": output_data.attestation.index,
        "transcript_hash":   output_data.attestation.transcript_hash_hex,
        "previous_hash":     output_data.attestation.previous_transcript_hash_hex,
    }))
}

fn accept(
    current: PathBuf,
    contribution: PathBuf,
    output: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    // Coordinator round between participants: load the previously-
    // signed transcript via `resume` (which calls
    // `backend.verify` to reject tampering), then absorb the new
    // contribution via `accept_contribution` (which chain-validates
    // attestation count + previous-hash + current-hash + backend
    // verify on the new transcript).
    let current_t: Transcript = config_file::load_json(&current)?;
    let contribution_t: Transcript = config_file::load_json(&contribution)?;
    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord
        .resume(current_t)
        .map_err(|e| anyhow::anyhow!("resume current transcript: {e:?}"))?;
    coord
        .accept_contribution(contribution_t.clone())
        .map_err(|e| anyhow::anyhow!("accept_contribution: {e:?}"))?;
    let new_t = coord
        .current_transcript()
        .map_err(|e| anyhow::anyhow!("current_transcript: {e:?}"))?;
    config_file::save_json(&output, new_t, overwrite)?;
    ctx.print(&serde_json::json!({
        "wrote":              output.display().to_string(),
        "contribution_index": contribution_t.attestations.last().map(|a| a.index).unwrap_or(0),
        "transcript_hash":    new_t.hash_hex(),
        "contributions":      coord.contribution_count(),
    }))
}

fn verify(input: PathBuf, ctx: &Context) -> Result<()> {
    let transcript: Transcript = config_file::load_json(&input)?;
    verify_transcript(&transcript, &SimulatedBackend)
        .map_err(|e| anyhow::anyhow!("verify_transcript: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "verified":         true,
        "circuit_id":       transcript.circuit_id,
        "contributions":    transcript.attestations.len(),
        "transcript_hash":  transcript.hash_hex(),
        "attestations": transcript.attestations.iter().map(|a| serde_json::json!({
            "index":            a.index,
            "participant":      a.participant_name,
            "transcript_hash":  a.transcript_hash_hex,
            "previous_hash":    a.previous_transcript_hash_hex,
            "message":          a.message,
        })).collect::<Vec<_>>(),
    }))
}

fn finalize(
    input: PathBuf,
    vk_output: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let transcript: Transcript = config_file::load_json(&input)?;
    if transcript.attestations.is_empty() {
        anyhow::bail!(
            "transcript has zero contributions — single-party (or zero-party) setup is unsafe"
        );
    }
    // Resume the coordinator from the persisted transcript (which
    // chain-verifies it via `backend.verify`), then call
    // `coordinator.finalize` — the production-correct path that
    // also enforces the no-zero-contributions invariant.
    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord
        .resume(transcript.clone())
        .map_err(|e| anyhow::anyhow!("resume: {e:?}"))?;
    let vk: VerificationKey = coord
        .finalize()
        .map_err(|e| anyhow::anyhow!("finalize: {e:?}"))?;

    let vk_json = serde_json::json!({
        "raw_bytes_hex": format!("0x{}", vk.to_hex()),
        "byte_length":   vk.raw_bytes.len(),
    });
    config_file::save_json(&vk_output, &vk_json, overwrite)?;
    ctx.print(&serde_json::json!({
        "wrote":          vk_output.display().to_string(),
        "byte_length":    vk.raw_bytes.len(),
        "contributions":  transcript.attestations.len(),
    }))
}

fn load_entropy(path: Option<&std::path::PathBuf>) -> Result<[u8; 32]> {
    match path {
        Some(p) => {
            let raw = std::fs::read(p)
                .with_context(|| format!("reading entropy from {}", p.display()))?;
            anyhow::ensure!(
                raw.len() == 32,
                "entropy file must be EXACTLY 32 bytes (got {})",
                raw.len()
            );
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            Ok(out)
        }
        None => {
            tracing::warn!(
                "no --entropy-file supplied; using getrandom (acceptable for testing only)"
            );
            let mut out = [0u8; 32];
            getrandom::getrandom(&mut out).context("getrandom failed")?;
            Ok(out)
        }
    }
}
