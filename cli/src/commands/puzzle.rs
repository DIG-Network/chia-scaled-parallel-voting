// ============================================================================
// commands/puzzle.rs — puzzle introspection (no chain access)
// ============================================================================
//
// VERB: chip-voting puzzle
// PURPOSE: dump the compiled puzzle hashes + Merkle roots embedded
//          in the SDK. Useful for:
//            * verifying the SDK is using the same puzzle bytecode
//              you expect (vs a stale compile);
//            * pasting hashes into off-chain tooling (block
//              explorers, indexer schemas, etc.);
//            * sanity-checking a freshly-built CLI binary.
// CHAIN: none — entirely offline.

use clap::Subcommand;
use chip_voting_sdk::puzzles::{self, PuzzleHashes};

use crate::output::Context;

#[derive(Debug, Subcommand)]
pub enum PuzzleCmd {
    /// Dump every embedded puzzle tree hash + the action-layer
    /// Merkle roots derived from them.
    Hashes,
}

pub async fn run(cmd: PuzzleCmd, ctx: &Context) -> anyhow::Result<()> {
    match cmd {
        PuzzleCmd::Hashes => {
            let value = serde_json::json!({
                "action_layer":              hex_str(PuzzleHashes::action_layer()),
                "election_finalizer":        hex_str(PuzzleHashes::election_finalizer()),
                "election_register":         hex_str(PuzzleHashes::election_register()),
                "election_finalize":         hex_str(PuzzleHashes::election_finalize()),
                "election_announce_finalization": hex_str(PuzzleHashes::election_announce_finalization()),
                "registration_finalizer":    hex_str(PuzzleHashes::registration_finalizer()),
                "registration_vote":         hex_str(PuzzleHashes::registration_vote()),
                "registration_release":      hex_str(PuzzleHashes::registration_release()),
                "cat_outer":                 hex_str(PuzzleHashes::cat_outer()),
                "registration_actions_merkle_root": hex_str(puzzles::registration_actions_merkle_root()),
                "note": "election_actions_merkle_root is per-deployment (depends on curried election constants); see `chip-voting deployer predict-puzzle-hash`",
            });
            ctx.print(&value)?;
        }
    }
    Ok(())
}

fn hex_str(b: chia_protocol::Bytes32) -> String {
    format!("0x{}", hex::encode(b))
}
