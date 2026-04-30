// ============================================================================
// commands/voter.rs — voter actions (register / vote / release / status)
// ============================================================================
//
// VERB: chip-voting voter
// PURPOSE: Per-voter operations on a deployed election. Each
//          subcommand drives a single signed multi-coin spend bundle.
//
// REQUIREMENTS for any of register / vote / release:
//   * the voter's BLS secret key (passed via --voter-secret-* flags)
//   * a funded XCH wallet (`dig-l1-wallet` keystore) for fees + the
//     registration fee
//   * for register: a CAT wallet holding ≥COLLATERAL_AMOUNT of the
//     governance asset
//   * `--election-config` (the shared JSON the deployer published)
//
// SAFETY:
//   * Bundles are shown for confirmation before broadcast unless
//     --yes is set.
//   * Voter BLS secrets are NEVER persisted by the CLI. Pass via
//     `--voter-secret-env` / `--voter-secret-file` in production
//     (NOT `--voter-secret-hex`, which exposes via shell history).

use anyhow::Result;
use chia_protocol::Bytes32;
use chip_voting_sdk::actors::voter::VoterKeys;
use chip_voting_sdk::Voter;
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;
use crate::rpc;
use crate::wallet as wallet_helpers;

/// Shared --voter-secret group used by every flow.
#[derive(Debug, clap::Args)]
pub struct VoterSecretArgs {
    /// Voter's BLS secret as hex (32 bytes). Use --voter-secret-env
    /// in production.
    #[arg(long, group = "voter_secret")]
    voter_secret_hex: Option<String>,

    /// Env var holding the voter's BLS secret hex.
    #[arg(long, group = "voter_secret")]
    voter_secret_env: Option<String>,

    /// File holding the voter's BLS secret (hex on a single line).
    #[arg(long, group = "voter_secret")]
    voter_secret_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum VoterCmd {
    /// Print this voter's registration coin puzzle hash + slot for a
    /// given election. No chain access required.
    Status {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,
    },

    /// Register the voter on-chain. Pairs a caller-supplied
    /// CAT-issuance spend (which creates the CAT-wrapped
    /// Registration Coin at the predicted puzzle hash + emits the
    /// `create_reg` CreateCoinAnnouncement) with the singleton
    /// register-action spend the actor builds. The voter's
    /// AggSigMe over the registration message is signed with the
    /// voter's BLS key. The CAT spend's own signatures must
    /// already be embedded in the supplied JSON.
    Register {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// Path to a JSON file containing the pre-built CAT
        /// issuance spend (CoinSpend shape: `{"coin": {...},
        /// "puzzle_reveal_hex": "...", "solution_hex": "..."}`).
        /// In production the operator's CAT-issuance pipeline
        /// constructs this; for the simulator end-to-end test a
        /// helper builder lives at
        /// `chip_voting_sdk::cat_test::build_synthetic_cat_spend`.
        #[arg(long)]
        cat_parent_spend_file: PathBuf,

        /// If set, write the signed bundle here (for archival).
        #[arg(long)]
        bundle_output: Option<PathBuf>,

        /// Allow overwriting an existing bundle output.
        #[arg(long)]
        overwrite: bool,
    },

    /// Cast a vote: re-spend the voter's registration coin via the
    /// `vote` action. The vote_data is a 32-byte payload; the voter
    /// authenticates with an UNAUGMENTED BLS signature
    /// (`AggSigUnsafe` on-chain).
    Vote {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex payload the voter is committing to. Typically
        /// `sha256(ballot_options)` or similar.
        #[arg(long)]
        vote_data: String,

        #[arg(long)]
        bundle_output: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,
    },

    /// Print the canonical vote message (`sha256("vote" ||
    /// election_id || pubkey || vote_data)`) the voter must sign
    /// for a vote action. Mirrors `Voter::vote_message`. Pure
    /// offline computation.
    VoteMessage {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex vote payload.
        #[arg(long)]
        vote_data: String,
    },

    /// Print the canonical release message (`sha256("release" ||
    /// election_id || pubkey || destination)`) the voter signs to
    /// authorise a collateral release. Mirrors
    /// `Voter::release_message`.
    ReleaseMessage {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// Puzzle hash that will receive the released CAT
        /// collateral. 32-byte hex.
        #[arg(long)]
        destination: String,
    },

    /// Release the voter's CAT collateral after the election has
    /// been finalized. Builds a paired bundle:
    ///   * Election Singleton: announce_finalization action
    ///   * Registration Coin:  release action
    Release {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// Puzzle hash that will receive the released CAT
        /// collateral. 32-byte hex.
        #[arg(long)]
        destination: String,

        #[arg(long)]
        bundle_output: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,
    },
}

pub async fn run(cmd: VoterCmd, ctx: &Context) -> Result<()> {
    match cmd {
        VoterCmd::Status {
            election_config,
            secret,
        } => status(election_config, secret, ctx),
        VoterCmd::Register {
            election_config,
            secret,
            cat_parent_spend_file,
            bundle_output,
            overwrite,
        } => {
            register(
                election_config,
                secret,
                cat_parent_spend_file,
                bundle_output,
                overwrite,
                ctx,
            )
            .await
        }
        VoterCmd::Vote {
            election_config,
            secret,
            vote_data,
            bundle_output,
            overwrite,
        } => vote(election_config, secret, vote_data, bundle_output, overwrite, ctx).await,
        VoterCmd::VoteMessage {
            election_config,
            secret,
            vote_data,
        } => vote_message_cmd(election_config, secret, vote_data, ctx),
        VoterCmd::ReleaseMessage {
            election_config,
            secret,
            destination,
        } => release_message_cmd(election_config, secret, destination, ctx),
        VoterCmd::Release {
            election_config,
            secret,
            destination,
            bundle_output,
            overwrite,
        } => release(election_config, secret, destination, bundle_output, overwrite, ctx).await,
    }
}

fn build_voter_keys(secret: &VoterSecretArgs) -> Result<VoterKeys> {
    let sk = wallet_helpers::load_secret_key(
        secret.voter_secret_hex.as_deref(),
        secret.voter_secret_env.as_deref(),
        secret.voter_secret_file.as_ref(),
    )?;
    Ok(VoterKeys::new(sk))
}

fn status(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let pk_hex = format!("0x{}", hex::encode(keys.pubkey.to_bytes()));
    let cat_tail_hash = config
        .cat_tail_hash()
        .map_err(|e| anyhow::anyhow!("cat_tail_hash: {e}"))?;
    let election_id = config
        .election_launcher_id()
        .map_err(|e| anyhow::anyhow!("election_launcher_id: {e}"))?;
    let reg_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &keys.pubkey,
        election_id,
    );
    let hint = chip_voting_sdk::puzzles::voter_hint(election_id, cat_tail_hash, &keys.pubkey);
    let slot = chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(&keys.pubkey);
    ctx.print(&serde_json::json!({
        "voter_pubkey":                 pk_hex,
        "election_launcher_id":         config.election_launcher_id_hex,
        "fresh_registration_puzzle_hash": format!("0x{}", hex::encode(reg_ph)),
        "voter_hint":                   format!("0x{}", hex::encode(hint)),
        "slot":                         slot,
    }))
}

fn vote_message_cmd(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    vote_data: String,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let voter = Voter::new(config, keys, ctx.network);
    let vd = parse_b32(&vote_data, "vote_data")?;
    let msg = voter.vote_message(vd);
    ctx.print(&serde_json::json!({
        "vote_message": format!("0x{}", hex::encode(msg)),
    }))
}

fn release_message_cmd(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    destination: String,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let voter = Voter::new(config, keys, ctx.network);
    let dest = parse_b32(&destination, "destination")?;
    let msg = voter.release_message(dest);
    ctx.print(&serde_json::json!({
        "release_message": format!("0x{}", hex::encode(msg)),
    }))
}

async fn register(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    cat_parent_spend_file: PathBuf,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let cat_parent_spend = load_coin_spend(&cat_parent_spend_file)?;
    let voter = Voter::new(config, keys, ctx.network);

    // Sync to recover the latest SPT (so the register action can
    // produce the correct empty-slot Merkle proof).
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let mut agg = chip_voting_sdk::Aggregator::new(
        voter.config.clone(),
        chain,
        ctx.network,
    );
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync (for SPT): {e:?}"))?;
    let smt = agg
        .merkle_tree()
        .map_err(|e| anyhow::anyhow!("merkle_tree: {e:?}"))?
        .clone();

    // Independent chain client for the build_bundle path.
    let chain2 = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let bundle = voter
        .register(&smt, cat_parent_spend, &chain2)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::register: {e:?}"))?;

    finalize_voter_action("register", bundle, bundle_output, overwrite, ctx).await
}

/// Load a `chia_protocol::CoinSpend` from a JSON file shaped like
/// `{"coin": {"parent_coin_info": "0x...", "puzzle_hash": "0x...",
///   "amount": <u64>}, "puzzle_reveal_hex": "0x...",
///   "solution_hex": "0x..."}`.
fn load_coin_spend(path: &std::path::Path) -> Result<chia_protocol::CoinSpend> {
    #[derive(serde::Deserialize)]
    struct WireCoin {
        parent_coin_info: String,
        puzzle_hash: String,
        amount: u64,
    }
    #[derive(serde::Deserialize)]
    struct Wire {
        coin: WireCoin,
        puzzle_reveal_hex: String,
        solution_hex: String,
    }
    let wire: Wire = config_file::load_json(path)?;
    let parent = parse_b32_str(&wire.coin.parent_coin_info, "coin.parent_coin_info")?;
    let ph = parse_b32_str(&wire.coin.puzzle_hash, "coin.puzzle_hash")?;
    let coin = chia_protocol::Coin::new(parent, ph, wire.coin.amount);
    let puzzle = chia_protocol::Program::from(
        hex::decode(wire.puzzle_reveal_hex.trim().trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("puzzle_reveal_hex: {e}"))?,
    );
    let solution = chia_protocol::Program::from(
        hex::decode(wire.solution_hex.trim().trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("solution_hex: {e}"))?,
    );
    Ok(chia_protocol::CoinSpend::new(coin, puzzle, solution))
}

fn parse_b32_str(s: &str, name: &str) -> Result<chia_protocol::Bytes32> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name}: must be exactly 32 bytes"))?;
    Ok(chia_protocol::Bytes32::new(arr))
}

async fn vote(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    vote_data: String,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let vd = parse_b32(&vote_data, "vote_data")?;
    let voter = Voter::new(config, keys, ctx.network);
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let bundle = voter
        .vote(vd, &chain)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::vote: {e:?}"))?;
    finalize_voter_action("vote", bundle, bundle_output, overwrite, ctx).await
}

async fn release(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    destination: String,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let dest = parse_b32(&destination, "destination")?;
    let voter = Voter::new(config, keys, ctx.network);
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let bundle = voter
        .release_collateral(dest, &chain)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::release_collateral: {e:?}"))?;
    finalize_voter_action("release", bundle, bundle_output, overwrite, ctx).await
}

async fn finalize_voter_action(
    label: &str,
    bundle: chia_protocol::SpendBundle,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let bundle_json = spend_bundle_to_json(&bundle);
    if let Some(path) = &bundle_output {
        config_file::save_json(path, &bundle_json, overwrite)?;
    }
    if !ctx.confirm(&format!("Broadcast the {label} bundle?"))? {
        ctx.print(&serde_json::json!({
            "broadcast":   "skipped (user declined)",
            "bundle_file": bundle_output.map(|p| p.display().to_string()),
        }))?;
        return Ok(());
    }
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let push = rpc::broadcast(&chain, &bundle).await?;
    ctx.print(&serde_json::json!({
        "broadcast":   push,
        "bundle_file": bundle_output.map(|p| p.display().to_string()),
    }))
}

fn parse_b32(s: &str, name: &str) -> Result<Bytes32> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("{name}: must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name}: must be exactly 32 bytes"))?;
    Ok(Bytes32::new(arr))
}

fn spend_bundle_to_json(b: &chia_protocol::SpendBundle) -> serde_json::Value {
    serde_json::json!({
        "coin_spends": b.coin_spends.iter().map(|cs| serde_json::json!({
            "coin": {
                "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                "puzzle_hash":      format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                "amount":           cs.coin.amount,
            },
            "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
            "solution_hex":      format!("0x{}", hex::encode(cs.solution.as_ref())),
        })).collect::<Vec<_>>(),
        "aggregated_signature": format!("0x{}", hex::encode(b.aggregated_signature.to_bytes())),
    })
}
