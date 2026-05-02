// ============================================================================
// wallet.rs — BLS key-loading + chain-client helpers
// ============================================================================
//
// MODULE: wallet (CLI internal — distinct from the `commands::wallet`
//          subcommand module).
// PURPOSE: helpers shared by every actor command that needs to load
//          a BLS secret key from disk/env/cli, or open a network
//          chain client.
//
// SAFETY: every secret-key load path here is operator-controlled.
// The CLI does NOT use a hosted wallet — voters/operators sign
// with raw BLS keys supplied via `--voter-secret-{hex,env,file}`.
// This keeps the actor flow trivially testable in a Simulator
// (no network round-trip required to load a key).

use anyhow::{Context as _, Result};
use chia_bls::SecretKey;
use chia_query::ChiaQuery;
use dig_l1_wallet::NetworkType;
use std::path::PathBuf;

/// Load a 32-byte BLS secret from a CLI-supplied source.
///
/// Resolution order:
///   1. `secret_hex` — hex string (possibly `0x`-prefixed) directly
///      on the command line. CONVENIENT for testing; AVOID in
///      production (shell history exposure).
///   2. `secret_env` — env var name. Caller exports the secret in
///      that env var. SAFER than `--secret-hex` because the secret
///      doesn't appear in `ps`/`history` output.
///   3. `secret_file` — file containing nothing but the hex. Same
///      caveats as `secret_env` plus filesystem ACL exposure.
///
/// Exactly one source must be provided.
pub fn load_secret_key(
    secret_hex: Option<&str>,
    secret_env: Option<&str>,
    secret_file: Option<&PathBuf>,
) -> Result<SecretKey> {
    let raw = match (secret_hex, secret_env, secret_file) {
        (Some(s), None, None) => s.to_string(),
        (None, Some(env), None) => {
            std::env::var(env).with_context(|| format!("reading secret from env var ${env}"))?
        }
        (None, None, Some(p)) => std::fs::read_to_string(p)
            .with_context(|| format!("reading secret from {}", p.display()))?
            .trim()
            .to_string(),
        (None, None, None) => anyhow::bail!(
            "no BLS secret source — pass one of --secret-hex / --secret-env / --secret-file"
        ),
        _ => anyhow::bail!(
            "ambiguous BLS secret — pass exactly one of --secret-hex / --secret-env / --secret-file"
        ),
    };

    let bytes = hex::decode(raw.trim().trim_start_matches("0x"))
        .context("BLS secret must be hex (32 bytes)")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("BLS secret must be exactly 32 bytes"))?;
    SecretKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("not a valid BLS secret key: {e:?}"))
}

/// Generate a fresh BLS key from `getrandom`. ONLY for the
/// `wallet generate-key` subcommand — never used implicitly.
pub fn generate_random_secret() -> Result<SecretKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).context("getrandom failed")?;
    Ok(SecretKey::from_seed(&seed))
}

/// Pretty-print a secret + derived pubkey as JSON (for `wallet
/// generate-key` output).
pub fn keypair_json(sk: &SecretKey) -> serde_json::Value {
    let pk = sk.public_key();
    serde_json::json!({
        "secret_key_hex": format!("0x{}", hex::encode(sk.to_bytes())),
        "public_key_hex": format!("0x{}", hex::encode(pk.to_bytes())),
    })
}

/// Independent ChiaQuery — use when you DON'T need a wallet (indexer,
/// aggregator chain reads, etc.) and want to keep the L1Wallet's
/// embedded client out of the picture.
pub async fn make_independent_chain(
    network: NetworkType,
    rpc_override: Option<&str>,
) -> Result<ChiaQuery> {
    crate::rpc::make_chain_client(network, rpc_override).await
}
