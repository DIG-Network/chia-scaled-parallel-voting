// ============================================================================
// commands/indexer.rs — read-only chain queries
// ============================================================================
//
// VERB: chip-voting indexer
// PURPOSE: Headless monitoring of an election's on-chain state.
//          Used by block explorers, status pages, custodians who
//          need to know if an election is finalized before honouring
//          a withdrawal of the underlying CAT.
//
// CHAIN: every subcommand connects to ChiaQuery.

use anyhow::Result;
use chip_voting_sdk::Indexer;
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;
use crate::wallet as wallet_helpers;

#[derive(Debug, Subcommand)]
pub enum IndexerCmd {
    /// Print the current ElectionState — registration count,
    /// accumulated fees, finalization status, vote outcome (if
    /// finalized), and the SPT root.
    Status {
        /// Path to the shared `election-config.json`.
        #[arg(long)]
        election_config: PathBuf,
    },

    /// List all registered voters' BLS public keys + their SPT slot.
    /// Output is JSON-friendly: `{ voters: [{pubkey_hex, slot}, …] }`.
    Voters {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// List every cast vote (one record per voter who has voted).
    /// Each record contains the voter's pubkey, the vote_data (32
    /// bytes), and the BLS signature.
    Votes {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print the puzzle hash of the Election Singleton + the per-
    /// voter Registration Coin puzzle hash for a given voter pubkey.
    /// Useful for off-chain explorers without re-implementing the
    /// puzzle math.
    PuzzleHashes {
        #[arg(long)]
        election_config: PathBuf,

        /// Optional voter BLS public key — when set, also prints
        /// that voter's expected Registration Coin puzzle hash and
        /// hint.
        #[arg(long)]
        voter_pubkey: Option<String>,
    },

    /// Print whether the election has been finalized. Mirrors
    /// `Indexer::is_finalized`.
    IsFinalized {
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Print whether a given voter pubkey is in the registered
    /// voter set. Mirrors `Indexer::is_registered`.
    IsRegistered {
        #[arg(long)]
        election_config: PathBuf,
        #[arg(long)]
        voter_pubkey: String,
    },

    /// Print the current SPT root + every populated leaf slot.
    /// Mirrors `Indexer::merkle_tree`.
    MerkleTree {
        #[arg(long)]
        election_config: PathBuf,
    },
}

pub async fn run(cmd: IndexerCmd, ctx: &Context) -> Result<()> {
    match cmd {
        IndexerCmd::Status { election_config } => status(election_config, ctx).await,
        IndexerCmd::Voters { election_config } => voters(election_config, ctx).await,
        IndexerCmd::Votes { election_config } => votes(election_config, ctx).await,
        IndexerCmd::PuzzleHashes {
            election_config,
            voter_pubkey,
        } => puzzle_hashes(election_config, voter_pubkey, ctx).await,
        IndexerCmd::IsFinalized { election_config } => {
            is_finalized_cmd(election_config, ctx).await
        }
        IndexerCmd::IsRegistered {
            election_config,
            voter_pubkey,
        } => is_registered_cmd(election_config, voter_pubkey, ctx).await,
        IndexerCmd::MerkleTree { election_config } => merkle_tree_cmd(election_config, ctx).await,
    }
}

async fn make_indexer(config_path: PathBuf, ctx: &Context) -> Result<Indexer> {
    let config = config_file::load_election_config(&config_path)?;
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    Ok(Indexer::new(config, chain))
}

async fn status(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut indexer = make_indexer(config_path, ctx).await?;
    indexer
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("indexer sync: {e:?}"))?;
    let state = indexer
        .state()
        .map_err(|e| anyhow::anyhow!("state: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "election_launcher_id":     indexer.config.election_launcher_id_hex,
        "registration_count":       state.registration_count,
        "accumulated_fees":         state.accumulated_fees,
        "finalized":                state.finalized,
        "vote_outcome":             format!("0x{}", hex::encode(state.vote_outcome)),
        "registration_merkle_root": format!("0x{}", hex::encode(state.registration_merkle_root)),
    }))
}

async fn voters(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut indexer = make_indexer(config_path, ctx).await?;
    indexer
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("indexer sync: {e:?}"))?;
    let set = indexer
        .voter_set()
        .map_err(|e| anyhow::anyhow!("voter_set: {e:?}"))?;
    let entries: Vec<_> = set
        .voters
        .iter()
        .map(|pk| {
            let slot = chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(pk);
            serde_json::json!({
                "voter_pubkey_hex": format!("0x{}", hex::encode(pk.to_bytes())),
                "slot":             slot,
            })
        })
        .collect();
    ctx.print(&serde_json::json!({
        "registration_count": set.voters.len(),
        "voters":             entries,
    }))
}

async fn votes(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let indexer = make_indexer(config_path, ctx).await?;
    let records = indexer
        .vote_records()
        .await
        .map_err(|e| anyhow::anyhow!("vote_records: {e:?}"))?;
    let entries: Vec<_> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "voter_pubkey_hex":     format!("0x{}", hex::encode(r.voter_pubkey.to_bytes())),
                "vote_data_hex":        format!("0x{}", hex::encode(r.vote_data)),
                "vote_signature_hex":   format!("0x{}", r.vote_signature_hex.trim_start_matches("0x")),
                "registration_coin_id": format!("0x{}", hex::encode(r.registration_coin_id)),
            })
        })
        .collect();
    ctx.print(&serde_json::json!({
        "votes_cast": records.len(),
        "votes":      entries,
    }))
}

async fn puzzle_hashes(
    config_path: PathBuf,
    voter_pubkey: Option<String>,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let launcher_id = config
        .election_launcher_id()
        .map_err(|e| anyhow::anyhow!("election_launcher_id: {e}"))?;
    // Without a fully-synced state we don't know the inner puzzle
    // hash exactly (it changes as state evolves), but we CAN print
    // the genesis singleton puzzle hash.
    let mut value = serde_json::json!({
        "election_launcher_id": format!("0x{}", hex::encode(launcher_id)),
    });

    if let Some(pk_hex) = voter_pubkey {
        let pk = parse_pk(&pk_hex)?;
        let cat_tail_hash = config
            .cat_tail_hash()
            .map_err(|e| anyhow::anyhow!("cat_tail_hash: {e}"))?;
        let reg_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &pk,
            launcher_id,
        );
        let hint = chip_voting_sdk::puzzles::voter_hint(launcher_id, cat_tail_hash, &pk);
        value["voter"] = serde_json::json!({
            "voter_pubkey_hex":             format!("0x{}", hex::encode(pk.to_bytes())),
            "fresh_registration_puzzle_hash": format!("0x{}", hex::encode(reg_ph)),
            "voter_hint":                   format!("0x{}", hex::encode(hint)),
            "slot":                          chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(&pk),
        });
    }
    ctx.print(&value)
}

async fn is_finalized_cmd(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut indexer = make_indexer(config_path, ctx).await?;
    indexer
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("indexer sync: {e:?}"))?;
    let finalized = indexer
        .is_finalized()
        .map_err(|e| anyhow::anyhow!("is_finalized: {e:?}"))?;
    let outcome = indexer
        .vote_outcome()
        .map_err(|e| anyhow::anyhow!("vote_outcome: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "finalized": finalized,
        "vote_outcome": format!("0x{}", hex::encode(outcome)),
    }))
}

async fn is_registered_cmd(
    config_path: PathBuf,
    voter_pubkey: String,
    ctx: &Context,
) -> Result<()> {
    let mut indexer = make_indexer(config_path, ctx).await?;
    indexer
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("indexer sync: {e:?}"))?;
    let pk = parse_pk(&voter_pubkey)?;
    let is_reg = indexer
        .is_registered(&pk)
        .map_err(|e| anyhow::anyhow!("is_registered: {e:?}"))?;
    ctx.print(&serde_json::json!({
        "voter_pubkey":  format!("0x{}", hex::encode(pk.to_bytes())),
        "is_registered": is_reg,
    }))
}

async fn merkle_tree_cmd(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let mut indexer = make_indexer(config_path, ctx).await?;
    indexer
        .sync()
        .await
        .map_err(|e| anyhow::anyhow!("indexer sync: {e:?}"))?;
    let smt = indexer
        .merkle_tree()
        .map_err(|e| anyhow::anyhow!("merkle_tree: {e:?}"))?;
    let voter_set = indexer
        .voter_set()
        .map_err(|e| anyhow::anyhow!("voter_set: {e:?}"))?;
    let leaves: Vec<_> = voter_set
        .voters
        .iter()
        .map(|pk| {
            serde_json::json!({
                "pubkey_hex": format!("0x{}", hex::encode(pk.to_bytes())),
                "slot":       chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(pk),
            })
        })
        .collect();
    ctx.print(&serde_json::json!({
        "root":   format!("0x{}", hex::encode(smt.root())),
        "depth":  chip_voting_sdk::config::TREE_DEPTH,
        "leaves": leaves,
    }))
}

fn parse_pk(s: &str) -> Result<chia_bls::PublicKey> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("voter_pubkey: must be hex"))?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("voter_pubkey: must be exactly 48 bytes"))?;
    chia_bls::PublicKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("voter_pubkey: {e:?}"))
}
