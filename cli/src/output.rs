// ============================================================================
// output.rs — shared CLI execution context + dual JSON/human formatter
// ============================================================================
//
// MODULE: output
// PURPOSE: Centralise the global flags (network, json, yes) and the
//          `print` helper that renders either a serde_json::Value or
//          a human-friendly key=value layout based on `ctx.json`.
//
// PHILOSOPHY: every command handler builds a single `serde_json::Value`
// and hands it to `Context::print`. Keeping the structured shape
// canonical means `--json` output is always parseable and the
// human-readable view is just a fallback rendering of the same
// data.

use clap::ValueEnum;
use dig_l1_wallet::NetworkType;
use serde::Serialize;
use std::io::Write;

/// Runtime context propagated to every command handler.
///
/// Built once in `main()` from the global CLI flags. Cheap to clone;
/// passed by reference everywhere.
#[derive(Debug, Clone)]
pub struct Context {
    pub network: NetworkType,
    pub rpc_override: Option<String>,
    pub json: bool,
    pub assume_yes: bool,
}

impl Context {
    /// Render `value` to stdout. JSON mode emits pretty-printed JSON.
    /// Human mode emits a flattened key=value layout (one field per
    /// line, indenting nested objects). Errors writing to stdout are
    /// fatal — the OS will report them.
    pub fn print<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        let v = serde_json::to_value(value)?;
        let mut out = std::io::stdout().lock();
        if self.json {
            serde_json::to_writer_pretty(&mut out, &v)?;
            writeln!(out)?;
        } else {
            render_human(&mut out, &v, 0)?;
        }
        Ok(())
    }

    /// Prompt the user for confirmation. Returns true if `--yes` was
    /// passed OR the user typed `y` / `yes`. Anything else returns
    /// false. Prompt + answer go through stderr so stdout stays clean
    /// for `--json` consumers.
    pub fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        if self.assume_yes {
            return Ok(true);
        }
        use std::io::{stderr, stdin, BufRead};
        let mut err = stderr().lock();
        write!(err, "{prompt} [y/N]: ")?;
        err.flush()?;
        let mut line = String::new();
        stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim().to_ascii_lowercase();
        Ok(matches!(trimmed.as_str(), "y" | "yes"))
    }
}

/// Recursive human-readable renderer for `serde_json::Value`. Keeps
/// objects aligned by indent level; arrays render with `- ` prefixes;
/// scalars render inline.
fn render_human<W: Write>(
    w: &mut W,
    v: &serde_json::Value,
    depth: usize,
) -> anyhow::Result<()> {
    let pad = "  ".repeat(depth);
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if val.is_object() || val.is_array() {
                    writeln!(w, "{pad}{k}:")?;
                    render_human(w, val, depth + 1)?;
                } else {
                    writeln!(w, "{pad}{k} = {}", scalar_str(val))?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                if item.is_object() || item.is_array() {
                    writeln!(w, "{pad}- [{i}]")?;
                    render_human(w, item, depth + 1)?;
                } else {
                    writeln!(w, "{pad}- {}", scalar_str(item))?;
                }
            }
        }
        scalar => writeln!(w, "{pad}{}", scalar_str(scalar))?,
    }
    Ok(())
}

fn scalar_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Network selector mirroring `dig_l1_wallet::NetworkType` but with a
/// `simulator` variant for local testing. Only the network NAME
/// differs between mainnet and testnet11 — both share the same
/// puzzle hash arithmetic; only AGG_SIG additional data and the
/// peer-discovery seed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet11,
}

impl From<NetworkArg> for NetworkType {
    fn from(arg: NetworkArg) -> NetworkType {
        match arg {
            NetworkArg::Mainnet => NetworkType::Mainnet,
            NetworkArg::Testnet11 => NetworkType::Testnet11,
        }
    }
}
