// ============================================================================
// config_file.rs — Election configuration file load/save helpers
// ============================================================================
//
// MODULE: config_file
// PURPOSE: Read/write `chip_voting_sdk::ElectionConfig` from a JSON
//          file on disk. Used by virtually every subcommand —
//          everyone (deployer, voter, aggregator, indexer) needs the
//          same config to derive puzzle hashes consistently.
//
// PORTABILITY: a config file is the canonical "election identity" —
// it's safe to publish (no secrets), and every participant should
// download THE SAME bytes from a trusted source (e.g., the election's
// website).

use anyhow::{Context as _, Result};
use chip_voting_sdk::ElectionConfig;
use std::path::Path;

/// Load an `ElectionConfig` from a JSON file.
///
/// `path` is interpreted relative to the current working directory.
/// Errors carry the path + a human-readable parse error.
pub fn load_election_config(path: &Path) -> Result<ElectionConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading election config from {}", path.display()))?;
    let cfg: ElectionConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parsing election config JSON from {}", path.display()))?;
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("election config failed self-validation: {e}"))?;
    Ok(cfg)
}

/// Save an `ElectionConfig` to a JSON file. Creates parent dirs as
/// needed; refuses to overwrite an existing file unless `overwrite`
/// is true.
pub fn save_election_config(path: &Path, cfg: &ElectionConfig, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        anyhow::bail!(
            "refusing to overwrite existing config at {} — pass --overwrite to replace",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory for {}", path.display()))?;
    }
    let json = cfg.to_json();
    std::fs::write(path, json)
        .with_context(|| format!("writing election config to {}", path.display()))?;
    Ok(())
}

/// Save an arbitrary JSON-serialisable artefact (spend bundle, ceremony
/// transcript, …). Same overwrite semantics as `save_election_config`.
pub fn save_json<T: serde::Serialize>(path: &Path, value: &T, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        anyhow::bail!(
            "refusing to overwrite existing file at {} — pass --overwrite to replace",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory for {}", path.display()))?;
    }
    let pretty = serde_json::to_string_pretty(value)?;
    std::fs::write(path, pretty).with_context(|| format!("writing JSON to {}", path.display()))?;
    Ok(())
}

/// Load arbitrary JSON-serialisable artefact.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading JSON from {}", path.display()))?;
    let v: T = serde_json::from_str(&raw)
        .with_context(|| format!("parsing JSON from {}", path.display()))?;
    Ok(v)
}
