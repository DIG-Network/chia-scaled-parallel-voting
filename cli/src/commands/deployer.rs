// ============================================================================
// commands/deployer.rs — election bootstrap CLI
// ============================================================================
//
// VERB: chip-voting deployer
// PURPOSE: Build and broadcast the genesis spend that creates the
//          Election Singleton.
//
// SUBCOMMANDS:
//   * predict-puzzle-hash — offline; given DeployParams + a parent
//                          coin id, print the inner_puzzle_hash and
//                          full singleton puzzle hash that will land
//                          on-chain. Use to pre-fund a CAT TAIL or
//                          for off-chain audits.
//   * dry-run             — offline; build the unsigned coin spends
//                          + the resulting ElectionConfig but DON'T
//                          submit. Output is JSON ready to feed into
//                          a separate signer / cold-storage flow.
//   * deploy              — full path: build, sign, broadcast.
//                          Requires `--rpc` and the parent coin's
//                          synthetic secret key (loaded from env or
//                          file — never on the command line in
//                          production).
//
// SECURITY:
//   * VK input must be the FINAL output of a completed MPC ceremony
//     (`chip-voting ceremony finalize`). The CLI re-validates length
//     (must equal `336 + (PUBLIC_INPUT_COUNT + 1) * 48` = 672 bytes
//     for the 6-public-input voting circuit) before attempting deploy.
//   * Bundle is shown for confirmation before broadcast unless
//     `--yes` is set.

use anyhow::{Context as _, Result};
use chia_protocol::{Bytes32, Coin};
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::{DeployParams, ElectionDeployer};
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;
use crate::rpc;
use crate::wallet as wallet_helpers;

/// Shared --params group reused by predict / dry-run / deploy.
#[derive(Debug, clap::Args)]
pub struct DeployParamsArgs {
    /// CAT TAIL hash of the governance token (32-byte hex).
    #[arg(long)]
    cat_tail_hash: String,

    /// Collateral each voter locks at registration, in CAT mojos.
    #[arg(long)]
    collateral_amount: u64,

    /// L1 block height the election was launched at. Stored in the
    /// genesis `ElectionState` (per CHIP rev 2026-05-02) so per-ballot
    /// epochs / timing windows can be derived against a stable
    /// on-chain anchor. Defaults to 0 if unset; pass the current peak
    /// height for any real deploy.
    #[arg(long, default_value_t = 0)]
    election_start_height: u64,

    /// Path to a JSON file with the Groth16 verification key produced
    /// by the MPC ceremony (`chip-voting ceremony finalize`). The
    /// file must contain `{"raw_bytes_hex": "0x..."}` matching the
    /// `VerificationKey` shape.
    #[arg(long)]
    vk_file: PathBuf,

    /// Optional human-readable label.
    #[arg(long)]
    label: Option<String>,
}

/// Shared --parent-coin group for dry-run / deploy.
#[derive(Debug, clap::Args)]
pub struct ParentCoinArgs {
    /// Parent XCH coin's id (32-byte hex). Becomes the launcher
    /// coin's parent.
    #[arg(long)]
    parent_coin_id: String,

    /// Parent coin's puzzle hash (32-byte hex).
    #[arg(long)]
    parent_puzzle_hash: String,

    /// Parent coin's amount (in mojos).
    #[arg(long)]
    parent_amount: u64,

    /// Synthetic public key (BLS G1) controlling the parent coin's
    /// standard p2 layer. 48-byte hex.
    #[arg(long)]
    parent_synthetic_pubkey: String,
}

#[derive(Debug, Subcommand)]
pub enum DeployerCmd {
    /// Predict the on-chain Election Singleton puzzle hash for a
    /// given parent XCH coin (offline). Use to pre-compute the
    /// singleton's address before broadcasting.
    PredictPuzzleHash {
        #[command(flatten)]
        params: DeployParamsArgs,

        /// Parent XCH coin's id (32-byte hex).
        #[arg(long)]
        parent_coin_id: String,
    },

    /// Print the curried action-set Merkle root for a given
    /// (params, launcher_id) pair. Mirrors
    /// `ElectionDeployer::election_actions_merkle_root`.
    ActionsMerkleRoot {
        #[command(flatten)]
        params: DeployParamsArgs,

        #[arg(long)]
        launcher_id: String,
    },

    /// Build the unsigned deploy spend bundle + emit the resulting
    /// `ElectionConfig`. No chain access required.
    DryRun {
        #[command(flatten)]
        params: DeployParamsArgs,

        #[command(flatten)]
        parent: ParentCoinArgs,

        /// Where to write the unsigned coin spends + ElectionConfig
        /// JSON.
        #[arg(long)]
        output_file: PathBuf,

        /// Allow overwriting an existing output file.
        #[arg(long)]
        overwrite: bool,
    },

    /// Full deploy: build + sign + broadcast. Caller supplies the
    /// parent coin info + the parent's synthetic secret key (via
    /// env or file). The CLI signs with that key and pushes the
    /// bundle to the network.
    Deploy {
        #[command(flatten)]
        params: DeployParamsArgs,

        #[command(flatten)]
        parent: ParentCoinArgs,

        /// Hex-encoded parent SYNTHETIC secret key (32 bytes). Use
        /// `--parent-secret-env` or `--parent-secret-file` in
        /// production — `--parent-secret-hex` is for testing only.
        #[arg(long, group = "parent_secret")]
        parent_secret_hex: Option<String>,

        /// Env var name holding the parent's synthetic secret key.
        #[arg(long, group = "parent_secret")]
        parent_secret_env: Option<String>,

        /// File containing the parent's synthetic secret key (hex,
        /// single line).
        #[arg(long, group = "parent_secret")]
        parent_secret_file: Option<PathBuf>,

        /// Where to save the resulting ElectionConfig JSON.
        #[arg(long, default_value = "election-config.json")]
        config_output: PathBuf,

        /// Optional path to also archive the broadcast spend bundle
        /// JSON (for audit / replay).
        #[arg(long)]
        bundle_output: Option<PathBuf>,

        /// Allow overwriting existing output files.
        #[arg(long)]
        overwrite: bool,
    },
}

pub async fn run(cmd: DeployerCmd, ctx: &Context) -> Result<()> {
    match cmd {
        DeployerCmd::PredictPuzzleHash {
            params,
            parent_coin_id,
        } => predict(params, parent_coin_id, ctx),
        DeployerCmd::ActionsMerkleRoot {
            params,
            launcher_id,
        } => actions_merkle_root_cmd(params, launcher_id, ctx),
        DeployerCmd::DryRun {
            params,
            parent,
            output_file,
            overwrite,
        } => dry_run(params, parent, output_file, overwrite, ctx),
        DeployerCmd::Deploy {
            params,
            parent,
            parent_secret_hex,
            parent_secret_env,
            parent_secret_file,
            config_output,
            bundle_output,
            overwrite,
        } => {
            deploy(
                params,
                parent,
                parent_secret_hex,
                parent_secret_env,
                parent_secret_file,
                config_output,
                bundle_output,
                overwrite,
                ctx,
            )
            .await
        }
    }
}

fn build_deployer(args: &DeployParamsArgs) -> Result<ElectionDeployer> {
    let cat_tail_hash = parse_b32(&args.cat_tail_hash, "cat_tail_hash")?;
    let vk = load_vk(&args.vk_file)?;
    Ok(ElectionDeployer::new(DeployParams {
        verification_key: vk,
        cat_tail_hash,
        collateral_amount: args.collateral_amount,
        election_start_height: args.election_start_height,
        label: args.label.clone(),
    }))
}

fn predict(
    params: DeployParamsArgs,
    parent_coin_id: String,
    ctx: &Context,
) -> Result<()> {
    let deployer = build_deployer(&params)?;
    let parent_id = parse_b32(&parent_coin_id, "parent_coin_id")?;
    let launcher_id = chip_voting_sdk::actors::deployer::derive_launcher_id(parent_id, 1);
    let inner_ph = deployer.genesis_inner_puzzle_hash(launcher_id);
    let singleton_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, inner_ph);
    ctx.print(&serde_json::json!({
        "launcher_id":            hex_b32(launcher_id),
        "inner_puzzle_hash":      hex_b32(inner_ph),
        "singleton_puzzle_hash":  hex_b32(singleton_ph),
    }))
}

fn actions_merkle_root_cmd(
    params: DeployParamsArgs,
    launcher_id: String,
    ctx: &Context,
) -> Result<()> {
    let deployer = build_deployer(&params)?;
    let l_id = parse_b32(&launcher_id, "launcher_id")?;
    let root = deployer.election_actions_merkle_root(l_id);
    ctx.print(&serde_json::json!({
        "launcher_id":                 hex_b32(l_id),
        "election_actions_merkle_root": hex_b32(root),
    }))
}

fn dry_run(
    params: DeployParamsArgs,
    parent: ParentCoinArgs,
    output_file: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let deployer = build_deployer(&params)?;
    let parent_coin = build_parent_coin(&parent)?;
    let parent_pk = parse_pk(&parent.parent_synthetic_pubkey)?;
    let (coin_spends, config) = deployer
        .build_deploy_bundle(parent_coin, parent_pk)
        .map_err(|e| anyhow::anyhow!("build_deploy_bundle failed: {e:?}"))?;
    let json = serde_json::json!({
        "election_config": serde_json::from_str::<serde_json::Value>(&config.to_json())?,
        "unsigned_coin_spends_count": coin_spends.len(),
        "unsigned_coin_spends": coin_spends
            .iter()
            .map(coin_spend_to_json)
            .collect::<Vec<_>>(),
    });
    config_file::save_json(&output_file, &json, overwrite)?;
    tracing::info!(path = %output_file.display(), "wrote unsigned bundle + config");
    ctx.print(&serde_json::json!({
        "wrote": output_file.display().to_string(),
        "election_launcher_id": config.election_launcher_id_hex,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn deploy(
    params: DeployParamsArgs,
    parent: ParentCoinArgs,
    secret_hex: Option<String>,
    secret_env: Option<String>,
    secret_file: Option<PathBuf>,
    config_output: PathBuf,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let deployer = build_deployer(&params)?;
    let parent_coin = build_parent_coin(&parent)?;
    let parent_pk = parse_pk(&parent.parent_synthetic_pubkey)?;
    let parent_sk = wallet_helpers::load_secret_key(
        secret_hex.as_deref(),
        secret_env.as_deref(),
        secret_file.as_ref(),
    )?;

    // Sanity check: the supplied secret must match the supplied pubkey.
    anyhow::ensure!(
        parent_sk.public_key() == parent_pk,
        "supplied parent_secret does NOT derive --parent-synthetic-pubkey — refusing to sign with the wrong key"
    );

    let artifacts = deployer
        .deploy_signed(parent_coin, parent_pk, &[parent_sk], ctx.network)
        .map_err(|e| anyhow::anyhow!("deploy_signed: {e:?}"))?;

    // Show the bundle summary + ask for confirmation.
    let summary = serde_json::json!({
        "election_launcher_id":    artifacts.config.election_launcher_id_hex,
        "coin_spends":             artifacts.spend_bundle.coin_spends.len(),
        "election_start_height":   params.election_start_height,
        "collateral_amount":       params.collateral_amount,
        "label":                   params.label,
    });
    ctx.print(&summary)?;
    if !ctx.confirm("Broadcast this deploy bundle to the network?")? {
        anyhow::bail!("user declined broadcast");
    }

    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let push_result = rpc::broadcast(&chain, &artifacts.spend_bundle).await?;

    config_file::save_election_config(&config_output, &artifacts.config, overwrite)?;
    if let Some(bundle_path) = bundle_output {
        config_file::save_json(
            &bundle_path,
            &serde_json::json!({
                "election_launcher_id": artifacts.config.election_launcher_id_hex,
                "spend_bundle": spend_bundle_to_json(&artifacts.spend_bundle),
            }),
            overwrite,
        )?;
    }

    ctx.print(&serde_json::json!({
        "broadcast":         push_result,
        "election_config":   config_output.display().to_string(),
    }))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn build_parent_coin(p: &ParentCoinArgs) -> Result<Coin> {
    let parent_id = parse_b32(&p.parent_coin_id, "parent_coin_id")?;
    let parent_ph = parse_b32(&p.parent_puzzle_hash, "parent_puzzle_hash")?;
    Ok(Coin::new(parent_id, parent_ph, p.parent_amount))
}

fn load_vk(path: &std::path::Path) -> Result<VerificationKey> {
    #[derive(serde::Deserialize)]
    struct Wire {
        raw_bytes_hex: String,
    }
    let wire: Wire = config_file::load_json(path)?;
    let bytes = hex::decode(wire.raw_bytes_hex.trim().trim_start_matches("0x"))
        .context("vk_file: raw_bytes_hex must be hex")?;
    let expected = 336 + (PUBLIC_INPUT_COUNT + 1) * 48;
    anyhow::ensure!(
        bytes.len() == expected,
        "verification key wrong length: got {}, expected {}",
        bytes.len(),
        expected
    );
    Ok(VerificationKey { raw_bytes: bytes })
}

fn parse_b32(s: &str, name: &str) -> Result<Bytes32> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .with_context(|| format!("{name}: must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name}: must be exactly 32 bytes"))?;
    Ok(Bytes32::new(arr))
}

fn parse_pk(s: &str) -> Result<chia_bls::PublicKey> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .context("public key: must be hex")?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key: must be exactly 48 bytes"))?;
    chia_bls::PublicKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("public key parse: {e:?}"))
}

fn hex_b32(b: Bytes32) -> String {
    format!("0x{}", hex::encode(b))
}

fn coin_spend_to_json(cs: &chia_protocol::CoinSpend) -> serde_json::Value {
    serde_json::json!({
        "coin": {
            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
            "puzzle_hash":      format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
            "amount":           cs.coin.amount,
        },
        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
        "solution_hex":      format!("0x{}", hex::encode(cs.solution.as_ref())),
    })
}

fn spend_bundle_to_json(b: &chia_protocol::SpendBundle) -> serde_json::Value {
    serde_json::json!({
        "coin_spends": b.coin_spends.iter().map(coin_spend_to_json).collect::<Vec<_>>(),
        "aggregated_signature": format!("0x{}", hex::encode(b.aggregated_signature.to_bytes())),
    })
}
