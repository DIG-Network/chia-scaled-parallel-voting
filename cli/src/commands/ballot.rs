// ============================================================================
// commands/ballot.rs — Ballot Coin actions (CHIP rev 2026-05-02)
// ============================================================================
//
// VERB: chip-voting ballot
// PURPOSE: per-ballot lane introduced by CHIP rev 2026-05-02. The
//          Election Singleton minted a Ballot Coin via `create_ballot`,
//          and from there each ballot has its own oracle / finalize
//          actions. The CLI surface mirrors the SDK's `BallotIssuer` /
//          `BallotReader` actors.
//
// STATUS: STUB. The SDK actors are stubbed pending Phase 6 (issuer +
//         reader bring-up). Each subcommand parses cleanly and
//         prints a TODO message; nothing touches the chain yet.

use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

use crate::output::Context;

#[derive(Debug, Subcommand)]
pub enum BallotCmd {
    /// Mint a fresh Ballot Coin lineage by driving the Election
    /// Singleton's `create_ballot` action. (STUB pending Phase 6.)
    Create {
        /// Path to the shared `election-config.json`.
        #[arg(long)]
        election_config: PathBuf,

        /// 32-byte hex ballot seed (uniqueness salt baked into the
        /// ballot's launcher id).
        #[arg(long)]
        ballot_seed: String,

        /// Block height at which voting on this ballot closes.
        #[arg(long)]
        vote_close_height: u64,

        /// 32-byte hex outcome-domain hash (commits to the
        /// off-chain vote-option schema).
        #[arg(long)]
        outcome_domain_hash: String,
    },

    /// List every Ballot Coin minted under this election. (STUB
    /// pending Phase 6.)
    List {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print the current `BallotState` for a single Ballot Coin.
    /// (STUB pending Phase 6.)
    State {
        #[arg(long)]
        election_config: PathBuf,

        /// 32-byte hex Ballot Coin launcher id.
        #[arg(long)]
        ballot_launcher_id: String,
    },
}

pub async fn run(cmd: BallotCmd, ctx: &Context) -> Result<()> {
    match cmd {
        BallotCmd::Create { .. } => {
            ctx.print(&serde_json::json!({
                "status": "stub",
                "todo":   "ballot create — pending Phase 6 (BallotIssuer::create_ballot)",
            }))
        }
        BallotCmd::List { .. } => {
            ctx.print(&serde_json::json!({
                "status": "stub",
                "todo":   "ballot list — pending Phase 6 (BallotReader::list_ballots)",
            }))
        }
        BallotCmd::State { .. } => {
            ctx.print(&serde_json::json!({
                "status": "stub",
                "todo":   "ballot state — pending Phase 6 (BallotReader::get_ballot)",
            }))
        }
    }
}
