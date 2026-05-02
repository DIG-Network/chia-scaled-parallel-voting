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
            // CHIP rev 2026-05-02: the singleton's `finalize` and
            // `announce_finalization` actions, and the registration
            // coin's `vote` action, were all deleted (per-ballot lane
            // moved to the Ballot Coin / Voting Coin). The hashes
            // below mirror the new action surface.
            let value = serde_json::json!({
                "action_layer":              hex_str(PuzzleHashes::action_layer()),
                "election_finalizer":        hex_str(PuzzleHashes::election_finalizer()),
                "election_register":         hex_str(PuzzleHashes::election_register()),
                "election_create_ballot":    hex_str(PuzzleHashes::election_create_ballot()),
                "election_deregister":       hex_str(PuzzleHashes::election_deregister()),
                "ballot_coin_finalizer":     hex_str(PuzzleHashes::ballot_coin_finalizer()),
                "ballot_coin_finalize":      hex_str(PuzzleHashes::ballot_coin_finalize()),
                "ballot_coin_oracle":        hex_str(PuzzleHashes::ballot_coin_oracle()),
                "ballot_coin_announce_finalization": hex_str(PuzzleHashes::ballot_coin_announce_finalization()),
                "registration_finalizer":    hex_str(PuzzleHashes::registration_finalizer()),
                "registration_mint_voting_coin": hex_str(PuzzleHashes::registration_mint_voting_coin()),
                "registration_release":      hex_str(PuzzleHashes::registration_release()),
                "voting_coin_finalizer":     hex_str(PuzzleHashes::voting_coin_finalizer()),
                "voting_coin_update_vote":   hex_str(PuzzleHashes::voting_coin_update_vote()),
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
