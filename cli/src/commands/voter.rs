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

    /// Cast a vote on a specific Ballot Coin (CHIP rev 2026-05-02).
    /// Mints a fresh Voting Coin off the voter's Registration Coin.
    CastVote {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex Ballot Coin launcher id this vote targets.
        #[arg(long)]
        ballot_launcher_id: String,

        /// 32-byte hex payload the voter is committing to. Typically
        /// `sha256(ballot_options)` or similar.
        #[arg(long)]
        vote_data: String,

        /// Block height at which the ballot stops accepting vote
        /// edits. Must match what `BallotIssuer::launch_ballot` curried
        /// into the on-chain Ballot Coin's oracle / finalize actions.
        #[arg(long)]
        vote_close_height: u64,

        /// Per-ballot quorum threshold numerator. Curried into the
        /// Ballot Coin's `finalize` action.
        #[arg(long)]
        vote_threshold_num: u64,

        /// Per-ballot quorum threshold denominator.
        #[arg(long)]
        vote_threshold_den: u64,

        /// 32-byte hex `registration_merkle_root` snapshot the
        /// BallotIssuer captured at `launch_ballot` time. Curried into
        /// the Ballot Coin's `finalize` action.
        #[arg(long)]
        registration_merkle_root_snapshot: String,

        /// `registration_vote_weight` snapshot the BallotIssuer
        /// captured at `launch_ballot` time.
        #[arg(long)]
        registration_vote_weight_snapshot: u64,

        /// CAT mojos to mint into the new Voting Coin. The CAT outer
        /// enforces conservation, so the recreated Registration Coin
        /// gets `collateral_amount - voting_coin_amount`.
        #[arg(long, default_value_t = 1)]
        voting_coin_amount: u64,

        #[arg(long)]
        bundle_output: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,
    },

    /// Update an existing vote by re-spending the voter's Voting
    /// Coin via its `update_vote` action. (STUB — `Voter::update_vote`
    /// is stubbed pending Phase 6.)
    UpdateVote {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex coin id of the voter's existing Voting Coin.
        #[arg(long)]
        voting_coin_id: String,

        /// New 32-byte hex vote payload.
        #[arg(long)]
        new_vote_data: String,

        #[arg(long)]
        bundle_output: Option<PathBuf>,

        #[arg(long)]
        overwrite: bool,
    },

    /// Print the canonical vote message
    /// (`sha256(vote_data || ballot_launcher_id || election_id)`)
    /// the voter must sign for a `cast_vote` / `update_vote` action.
    /// Mirrors `puzzles::vote_message`. Pure offline computation.
    VoteMessage {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex Ballot Coin launcher id.
        #[arg(long)]
        ballot_launcher_id: String,

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

    /// Release the voter's CAT collateral. Per CHIP rev 2026-05-02
    /// this is gated on the singleton's `deregister` action — the
    /// finalize / announce_finalization actions moved off the
    /// singleton, so release no longer needs paired finalize.
    /// (STUB — `Voter::release_collateral` is stubbed pending Phase 6.)
    Release {
        #[arg(long)]
        election_config: PathBuf,

        #[command(flatten)]
        secret: VoterSecretArgs,

        /// 32-byte hex coin id of the voter's Registration Coin.
        #[arg(long)]
        registration_coin_id: String,

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
        VoterCmd::CastVote {
            election_config,
            secret,
            ballot_launcher_id,
            vote_data,
            vote_close_height,
            vote_threshold_num,
            vote_threshold_den,
            registration_merkle_root_snapshot,
            registration_vote_weight_snapshot,
            voting_coin_amount,
            bundle_output,
            overwrite,
        } => {
            cast_vote(
                election_config,
                secret,
                ballot_launcher_id,
                vote_data,
                vote_close_height,
                vote_threshold_num,
                vote_threshold_den,
                registration_merkle_root_snapshot,
                registration_vote_weight_snapshot,
                voting_coin_amount,
                bundle_output,
                overwrite,
                ctx,
            )
            .await
        }
        VoterCmd::UpdateVote {
            election_config,
            secret,
            voting_coin_id,
            new_vote_data,
            bundle_output,
            overwrite,
        } => {
            update_vote(
                election_config,
                secret,
                voting_coin_id,
                new_vote_data,
                bundle_output,
                overwrite,
                ctx,
            )
            .await
        }
        VoterCmd::VoteMessage {
            election_config,
            secret,
            ballot_launcher_id,
            vote_data,
        } => vote_message_cmd(election_config, secret, ballot_launcher_id, vote_data, ctx),
        VoterCmd::ReleaseMessage {
            election_config,
            secret,
            destination,
        } => release_message_cmd(election_config, secret, destination, ctx),
        VoterCmd::Release {
            election_config,
            secret,
            registration_coin_id,
            destination,
            bundle_output,
            overwrite,
        } => {
            release(
                election_config,
                secret,
                registration_coin_id,
                destination,
                bundle_output,
                overwrite,
                ctx,
            )
            .await
        }
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

fn status(config_path: PathBuf, secret: VoterSecretArgs, ctx: &Context) -> Result<()> {
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
    _secret: VoterSecretArgs,
    ballot_launcher_id: String,
    vote_data: String,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let election_id = config
        .election_launcher_id()
        .map_err(|e| anyhow::anyhow!("election_launcher_id: {e}"))?;
    let blid = parse_b32(&ballot_launcher_id, "ballot_launcher_id")?;
    let vd = parse_b32(&vote_data, "vote_data")?;
    // Per CHIP rev 2026-05-02 the canonical vote message lives in
    // `puzzles::vote_message` (mirrored by
    // `puzzles/voting_coin/shared.rue::vote_message`); the per-voter
    // wrapper that used to live on `Voter` was deleted along with the
    // singleton-side vote action.
    let msg = chip_voting_sdk::puzzles::vote_message(vd, blid, election_id);
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
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    let mut agg = chip_voting_sdk::Aggregator::new(voter.config.clone(), chain, ctx.network);
    agg.sync()
        .await
        .map_err(|e| anyhow::anyhow!("sync (for SPT): {e:?}"))?;
    let smt = agg
        .merkle_tree()
        .map_err(|e| anyhow::anyhow!("merkle_tree: {e:?}"))?
        .clone();

    // Independent chain client for the build_bundle path.
    let chain2 =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
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

#[allow(clippy::too_many_arguments)]
async fn cast_vote(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    ballot_launcher_id: String,
    vote_data: String,
    vote_close_height: u64,
    vote_threshold_num: u64,
    vote_threshold_den: u64,
    registration_merkle_root_snapshot: String,
    registration_vote_weight_snapshot: u64,
    voting_coin_amount: u64,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let blid = parse_b32(&ballot_launcher_id, "ballot_launcher_id")?;
    let vd = parse_b32(&vote_data, "vote_data")?;
    let reg_root_snapshot = parse_b32(
        &registration_merkle_root_snapshot,
        "registration_merkle_root_snapshot",
    )?;
    let voter = Voter::new(config, keys, ctx.network);
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    let params = chip_voting_sdk::actors::voter::CastVoteParams {
        ballot_launcher_id: blid,
        vote_data: vd,
        vote_close_height,
        vote_threshold_num,
        vote_threshold_den,
        registration_merkle_root_snapshot: reg_root_snapshot,
        registration_vote_weight_snapshot,
        voting_coin_amount,
    };
    let result = voter
        .cast_vote(&chain, params)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::cast_vote: {e:?}"))?;
    finalize_voter_action(
        "cast_vote",
        result.spend_bundle,
        bundle_output,
        overwrite,
        ctx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn update_vote(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    voting_coin_id: String,
    new_vote_data: String,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let vc_id = parse_b32(&voting_coin_id, "voting_coin_id")?;
    let new_vd = parse_b32(&new_vote_data, "new_vote_data")?;
    let voter = Voter::new(config, keys, ctx.network);
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    // STUB: `Voter::update_vote` is stubbed pending Phase 6. Same
    // shape as cast_vote — we propagate the SDK's stubbed error.
    let bundle = voter
        .update_vote(&chain, vc_id, new_vd)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::update_vote: {e:?}"))?;
    finalize_voter_action("update_vote", bundle, bundle_output, overwrite, ctx).await
}

#[allow(clippy::too_many_arguments)]
async fn release(
    config_path: PathBuf,
    secret: VoterSecretArgs,
    registration_coin_id: String,
    destination: String,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let config = config_file::load_election_config(&config_path)?;
    let keys = build_voter_keys(&secret)?;
    let reg_id = parse_b32(&registration_coin_id, "registration_coin_id")?;
    let dest = parse_b32(&destination, "destination")?;
    let voter = Voter::new(config, keys, ctx.network);
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
    // Sync the SMT from chain so the deregister action's membership
    // proof can be constructed (release_collateral asserts it
    // matches the on-chain singleton state).
    let current = chip_voting_sdk::actors::aggregator::find_current_singleton(
        &chain,
        &voter.config,
        0,
    )
    .await
    .map_err(|e| anyhow::anyhow!("find_current_singleton: {e:?}"))?;
    let bundle = voter
        .release_collateral(&chain, &current.smt, reg_id, dest)
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
    let chain =
        wallet_helpers::make_independent_chain(ctx.network, ctx.rpc_override.as_deref()).await?;
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
