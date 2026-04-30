// ============================================================================
// commands/wallet.rs — BLS keygen + wallet inspection
// ============================================================================
//
// VERB: chip-voting wallet
// PURPOSE: helper subcommands for managing BLS keys + inspecting
//          dig-l1-wallet keystores. Voters and aggregators need a
//          BLS keypair (separate from their XCH p2/synthetic key);
//          this verb produces and prints them.
// CHAIN: only the `balance` subcommand touches the chain.

use clap::Subcommand;
use std::path::PathBuf;

use crate::output::Context;
use crate::wallet as wallet_helpers;

#[derive(Debug, Subcommand)]
pub enum WalletCmd {
    /// Generate a fresh BLS keypair (32-byte secret + 48-byte
    /// pubkey). Output is printed to stdout (or written to
    /// `--output-file`). NEVER prints to a terminal that's being
    /// recorded — use `--output-file` for production rotations.
    GenerateKey {
        /// If set, write the JSON keypair here instead of stdout.
        /// File is created mode 0600 on Unix; on Windows the OS ACL
        /// applies.
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// Derive + print the public key for a given BLS secret.
    /// Useful for sharing the pubkey (e.g., to register with an
    /// election deployer) without re-running keygen.
    Pubkey {
        /// BLS secret as hex (use --secret-env or --secret-file in
        /// production).
        #[arg(long, group = "secret_src")]
        secret_hex: Option<String>,
        /// Read the BLS secret from this env var.
        #[arg(long, group = "secret_src")]
        secret_env: Option<String>,
        /// Read the BLS secret from this file (hex-encoded, single
        /// line).
        #[arg(long, group = "secret_src")]
        secret_file: Option<PathBuf>,
    },
}

pub async fn run(cmd: WalletCmd, ctx: &Context) -> anyhow::Result<()> {
    match cmd {
        WalletCmd::GenerateKey { output_file } => {
            let sk = wallet_helpers::generate_random_secret()?;
            let json = wallet_helpers::keypair_json(&sk);
            if let Some(path) = output_file {
                crate::config_file::save_json(&path, &json, /*overwrite=*/ false)?;
                tracing::info!(path = %path.display(), "wrote keypair");
                ctx.print(&serde_json::json!({
                    "wrote": path.display().to_string(),
                    "public_key_hex": json["public_key_hex"],
                }))?;
            } else {
                ctx.print(&json)?;
            }
        }
        WalletCmd::Pubkey {
            secret_hex,
            secret_env,
            secret_file,
        } => {
            let sk = wallet_helpers::load_secret_key(
                secret_hex.as_deref(),
                secret_env.as_deref(),
                secret_file.as_ref(),
            )?;
            ctx.print(&wallet_helpers::keypair_json(&sk))?;
        }
    }
    Ok(())
}
