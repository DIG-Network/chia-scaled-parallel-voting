// ============================================================================
// commands/oracle.rs — permissionless oracle-action spend production
// ============================================================================
//
// VERB: chip-voting oracle
// PURPOSE: Anyone-can-call helper that exposes the Election Singleton's
//          `oracle` action over the CLI. Three flows:
//
//    * `predict`     — read-only preview of which announcement (and
//                       message bytes) the next oracle spend WOULD
//                       emit. Useful for downstream-puzzle authors
//                       who need to bake the expected
//                       `AssertCoinAnnouncement.id` into their
//                       solution / curry.
//
//    * `build-spend` — emit the SINGLE coin-spend JSON (no
//                       broadcast). Pair this in your own bundle
//                       alongside the spend(s) that assert the
//                       announcement.
//
//    * `bundle`      — emit a fully-formed standalone SpendBundle
//                       JSON. Use when you want the announcement
//                       on-chain on its own (e.g., to notarise a
//                       finalized result).
//
//    * `broadcast`   — `bundle` + push the result to the network
//                       after a confirmation prompt.
//
// SIGNING: the oracle action emits NO `AggSig*` conditions. None of
// these subcommands ever ask the user for a secret key — the
// produced bundle's aggregated signature is the BLS identity.

use anyhow::Result;
use chia_protocol::Bytes32;
use chip_voting_sdk::{Oracle, OracleAnnouncement};
use clap::Subcommand;
use std::path::PathBuf;

use crate::config_file;
use crate::output::Context;
use crate::rpc;
use crate::wallet as wallet_helpers;

#[derive(Debug, Subcommand)]
pub enum OracleCmd {
    /// Read the chain and show which announcement the oracle would
    /// emit RIGHT NOW (variant + bare message bytes + the
    /// `AssertCoinAnnouncement.id` downstream puzzles must use).
    /// Read-only — no spend produced.
    Predict {
        /// Path to the shared `election-config.json`.
        #[arg(long)]
        election_config: PathBuf,
    },

    /// Build the oracle action's SINGLE `CoinSpend` and emit it as
    /// JSON for inclusion in your own spend bundle. Also reports
    /// the singleton's coin id and the `announcement_id` so the
    /// caller can wire downstream `AssertCoinAnnouncement` arguments
    /// before assembling the bundle.
    BuildSpend {
        #[arg(long)]
        election_config: PathBuf,

        /// Where to write the coin spend JSON (one CoinSpend +
        /// metadata).
        #[arg(long)]
        output_file: PathBuf,

        /// Allow overwriting an existing output file.
        #[arg(long)]
        overwrite: bool,
    },

    /// Build a standalone fully-formed `SpendBundle` carrying ONLY
    /// the oracle action. Useful when you want to publish the
    /// announcement on-chain on its own — no caller secrets needed
    /// (the oracle action emits no AggSig conditions).
    Bundle {
        #[arg(long)]
        election_config: PathBuf,

        /// Where to write the signed spend bundle JSON.
        #[arg(long)]
        output_file: PathBuf,

        /// Allow overwriting an existing output file.
        #[arg(long)]
        overwrite: bool,
    },

    /// Build the standalone oracle bundle AND broadcast it after a
    /// confirmation prompt. Equivalent to `bundle` + manual
    /// `chia_query::ChiaQuery::push_tx`.
    Broadcast {
        #[arg(long)]
        election_config: PathBuf,

        /// If set, also archive the (signed) bundle to this path
        /// before broadcasting.
        #[arg(long)]
        bundle_output: Option<PathBuf>,

        /// Allow overwriting an existing bundle output file.
        #[arg(long)]
        overwrite: bool,
    },
}

pub async fn run(cmd: OracleCmd, ctx: &Context) -> Result<()> {
    match cmd {
        OracleCmd::Predict { election_config } => predict(election_config, ctx).await,
        OracleCmd::BuildSpend {
            election_config,
            output_file,
            overwrite,
        } => build_spend(election_config, output_file, overwrite, ctx).await,
        OracleCmd::Bundle {
            election_config,
            output_file,
            overwrite,
        } => bundle_cmd(election_config, output_file, overwrite, ctx).await,
        OracleCmd::Broadcast {
            election_config,
            bundle_output,
            overwrite,
        } => broadcast_cmd(election_config, bundle_output, overwrite, ctx).await,
    }
}

/// Construct the Oracle actor wired to the live `chia_query::ChiaQuery`
/// chain reader. Mirrors `commands::aggregator::make_aggregator` so
/// every actor's CLI bootstrap path looks identical.
async fn make_oracle(config_path: PathBuf, ctx: &Context) -> Result<Oracle> {
    let config = config_file::load_election_config(&config_path)?;
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    Ok(Oracle::new(config, chain, ctx.network))
}

async fn predict(config_path: PathBuf, ctx: &Context) -> Result<()> {
    let oracle = make_oracle(config_path, ctx).await?;
    let ann = oracle
        .predict_announcement()
        .await
        .map_err(|e| anyhow::anyhow!("oracle predict_announcement: {e:?}"))?;
    ctx.print(&announcement_to_json(&ann, /* announcement_id = */ None))
}

async fn build_spend(
    config_path: PathBuf,
    output_file: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let oracle = make_oracle(config_path, ctx).await?;
    let spend = oracle
        .build_oracle_spend()
        .await
        .map_err(|e| anyhow::anyhow!("oracle build_oracle_spend: {e:?}"))?;

    let singleton_coin_id = spend.singleton_coin_id();
    let json = serde_json::json!({
        "election_launcher_id": oracle.config.election_launcher_id_hex,
        "singleton_coin": coin_to_json(&spend.singleton_coin),
        "singleton_coin_id":     hex_b32(singleton_coin_id),
        "announcement_id":       hex_b32(spend.announcement_id),
        "announcement":          announcement_to_json(&spend.announcement, Some(spend.announcement_id)),
        "coin_spend":            coin_spend_to_json(&spend.coin_spend),
    });
    config_file::save_json(&output_file, &json, overwrite)?;
    tracing::info!(path = %output_file.display(), "wrote oracle coin spend");
    ctx.print(&serde_json::json!({
        "wrote": output_file.display().to_string(),
        "singleton_coin_id": hex_b32(singleton_coin_id),
        "announcement_id":   hex_b32(spend.announcement_id),
        "variant":           variant_label(&spend.announcement),
    }))
}

async fn bundle_cmd(
    config_path: PathBuf,
    output_file: PathBuf,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let oracle = make_oracle(config_path, ctx).await?;
    // Build twice: once for metadata via `build_oracle_spend`, once
    // for the assembled bundle. The chain walk is cheap and gives
    // us byte-identical metadata (same call path).
    let metadata = oracle
        .build_oracle_spend()
        .await
        .map_err(|e| anyhow::anyhow!("oracle build_oracle_spend: {e:?}"))?;
    let bundle = oracle
        .build_oracle_bundle()
        .await
        .map_err(|e| anyhow::anyhow!("oracle build_oracle_bundle: {e:?}"))?;

    let json = serde_json::json!({
        "election_launcher_id": oracle.config.election_launcher_id_hex,
        "singleton_coin_id":     hex_b32(metadata.singleton_coin_id()),
        "announcement_id":       hex_b32(metadata.announcement_id),
        "announcement":          announcement_to_json(&metadata.announcement, Some(metadata.announcement_id)),
        "spend_bundle":          spend_bundle_to_json(&bundle),
    });
    config_file::save_json(&output_file, &json, overwrite)?;
    tracing::info!(path = %output_file.display(), "wrote oracle spend bundle");
    ctx.print(&serde_json::json!({
        "wrote":             output_file.display().to_string(),
        "singleton_coin_id": hex_b32(metadata.singleton_coin_id()),
        "announcement_id":   hex_b32(metadata.announcement_id),
        "variant":           variant_label(&metadata.announcement),
        "coin_spends":       bundle.coin_spends.len(),
    }))
}

async fn broadcast_cmd(
    config_path: PathBuf,
    bundle_output: Option<PathBuf>,
    overwrite: bool,
    ctx: &Context,
) -> Result<()> {
    let oracle = make_oracle(config_path, ctx).await?;
    let metadata = oracle
        .build_oracle_spend()
        .await
        .map_err(|e| anyhow::anyhow!("oracle build_oracle_spend: {e:?}"))?;
    let bundle = oracle
        .build_oracle_bundle()
        .await
        .map_err(|e| anyhow::anyhow!("oracle build_oracle_bundle: {e:?}"))?;

    if let Some(path) = &bundle_output {
        let json = serde_json::json!({
            "election_launcher_id": oracle.config.election_launcher_id_hex,
            "singleton_coin_id":     hex_b32(metadata.singleton_coin_id()),
            "announcement_id":       hex_b32(metadata.announcement_id),
            "announcement":          announcement_to_json(&metadata.announcement, Some(metadata.announcement_id)),
            "spend_bundle":          spend_bundle_to_json(&bundle),
        });
        config_file::save_json(path, &json, overwrite)?;
        tracing::info!(path = %path.display(), "archived oracle bundle pre-broadcast");
    }

    if !ctx.confirm("Broadcast the oracle spend bundle?")? {
        anyhow::bail!("user declined broadcast");
    }
    let chain = wallet_helpers::make_independent_chain(
        ctx.network,
        ctx.rpc_override.as_deref(),
    )
    .await?;
    let push = rpc::broadcast(&chain, &bundle).await?;
    ctx.print(&serde_json::json!({
        "broadcast":         push,
        "bundle_file":       bundle_output.map(|p| p.display().to_string()),
        "singleton_coin_id": hex_b32(metadata.singleton_coin_id()),
        "announcement_id":   hex_b32(metadata.announcement_id),
        "variant":           variant_label(&metadata.announcement),
    }))
}

/// Render an `OracleAnnouncement` as a JSON object. `announcement_id`
/// is included only when the caller has the singleton coin id (i.e.,
/// for spend-producing flows) — `predict` omits it because predicting
/// the id requires the future spend's coin id.
fn announcement_to_json(
    ann: &OracleAnnouncement,
    announcement_id: Option<Bytes32>,
) -> serde_json::Value {
    let (variant, message, count, root, outcome) = match ann {
        OracleAnnouncement::Finalized {
            message,
            vote_outcome,
            registration_count,
            registration_merkle_root,
        } => (
            "finalized",
            *message,
            *registration_count,
            *registration_merkle_root,
            Some(*vote_outcome),
        ),
        OracleAnnouncement::Unfinalized {
            message,
            registration_count,
            registration_merkle_root,
        } => (
            "unfinalized",
            *message,
            *registration_count,
            *registration_merkle_root,
            None,
        ),
    };
    let mut obj = serde_json::json!({
        "variant":                  variant,
        "message":                  hex_b32(message),
        "registration_count":       count,
        "registration_merkle_root": hex_b32(root),
    });
    if let Some(o) = outcome {
        obj["vote_outcome"] = serde_json::Value::String(hex_b32(o));
    }
    if let Some(id) = announcement_id {
        obj["announcement_id"] = serde_json::Value::String(hex_b32(id));
    }
    obj
}

fn variant_label(ann: &OracleAnnouncement) -> &'static str {
    match ann {
        OracleAnnouncement::Finalized { .. } => "finalized",
        OracleAnnouncement::Unfinalized { .. } => "unfinalized",
    }
}

fn hex_b32(b: Bytes32) -> String {
    format!("0x{}", hex::encode(b))
}

fn coin_to_json(c: &chia_protocol::Coin) -> serde_json::Value {
    serde_json::json!({
        "parent_coin_info": format!("0x{}", hex::encode(c.parent_coin_info)),
        "puzzle_hash":      format!("0x{}", hex::encode(c.puzzle_hash)),
        "amount":           c.amount,
    })
}

fn coin_spend_to_json(cs: &chia_protocol::CoinSpend) -> serde_json::Value {
    serde_json::json!({
        "coin": coin_to_json(&cs.coin),
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

