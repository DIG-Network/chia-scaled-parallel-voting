// ============================================================================
// chip-voting CLI — entry point
// ============================================================================
//
// PURPOSE: production command-line interface for the Chia voting CHIP.
//          Drives every actor (Deployer, Voter, Aggregator, Indexer)
//          plus the MPC trusted-setup ceremony from the shell.
//
// ARCHITECTURE:
//   * Pure orchestration — every on-chain operation delegates to
//     `chip-voting-sdk`. The CLI does NOT re-implement puzzle math,
//     coin selection, or signing.
//   * Stateless per-invocation — the only state on disk is what the
//     user explicitly persists: election config (JSON), ceremony
//     transcripts (JSON), and exported spend bundles (JSON).
//   * Network-agnostic — `--network` (mainnet | testnet11 | simulator)
//     selects between mainnet, the public testnet11, or a local
//     simulator endpoint via `chia-query`. Defaults to mainnet.
//   * Output — `--json` prints structured machine-parseable output to
//     stdout; without it the output is human-friendly. Logs always go
//     to stderr.
//
// EXIT CODES:
//   0  success
//   1  user / configuration error (bad args, missing file)
//   2  chain / network error (RPC unreachable, bundle rejected)
//   3  cryptographic error (signature verification failed, bad VK)
//
// SAFETY POSTURE:
//   * The CLI never persists raw secret keys in plain text. Wallet
//     keys are loaded from `dig_l1_wallet`'s encrypted keystore;
//     voter BLS secrets are loaded from a path you decrypt yourself
//     OR from an env var (CLI flag `--voter-secret-env`).
//   * Every spend bundle is presented for a confirmation prompt
//     before broadcast unless `--yes` is passed (CI-friendly).

#![deny(rust_2018_idioms)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod commands;
mod config_file;
mod output;
mod rpc;
mod wallet;

use clap::{Parser, Subcommand};

/// chip-voting — production CLI for the Chia voting CHIP.
///
/// Drives every actor (Deployer, Voter, Aggregator, Indexer) and the
/// MPC trusted-setup ceremony. See the per-subcommand `--help` for
/// flags and examples.
#[derive(Debug, Parser)]
#[command(
    name = "chip-voting",
    version,
    about = "CLI for the Chia voting CHIP (Election Singleton + Registration Coin + Groth16 finalization)",
    long_about = None,
)]
struct Cli {
    /// Network to talk to. Affects AGG_SIG additional data and the
    /// peer-discovery seed used by `chia-query`.
    #[arg(long, value_enum, default_value_t = output::NetworkArg::Mainnet, global = true)]
    network: output::NetworkArg,

    /// Optional `chia-query` endpoint URL override. Bypasses peer
    /// discovery — useful when pointing at a local node or a CDN
    /// fallback. If set, `--network` still controls AGG_SIG signing.
    #[arg(long, global = true)]
    rpc: Option<String>,

    /// Print structured JSON to stdout instead of human-readable
    /// text. Logs still go to stderr.
    #[arg(long, global = true)]
    json: bool,

    /// Skip the "broadcast this bundle?" confirmation prompts. Use
    /// for CI / scripting. Has no effect on non-mutating commands.
    #[arg(short = 'y', long = "yes", global = true)]
    assume_yes: bool,

    /// Verbose logging (info → debug).
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// Trace-level logging (debug → trace). Implies --verbose.
    #[arg(long, global = true)]
    trace: bool,

    #[command(subcommand)]
    cmd: Command,
}

/// Top-level subcommand verbs. Each maps to one actor (or shared
/// utilities). Sub-subcommands live in `commands::<actor>`.
#[derive(Debug, Subcommand)]
enum Command {
    /// One-time election bootstrap: deploy the Election Singleton.
    #[command(subcommand)]
    Deployer(commands::deployer::DeployerCmd),

    /// Per-voter actions: register, vote, release collateral, status.
    #[command(subcommand)]
    Voter(commands::voter::VoterCmd),

    /// Aggregator actions: sync, collect votes, finalize.
    #[command(subcommand)]
    Aggregator(commands::aggregator::AggregatorCmd),

    /// Indexer actions (read-only): status, voters, votes.
    #[command(subcommand)]
    Indexer(commands::indexer::IndexerCmd),

    /// Ballot Coin actions (CHIP rev 2026-05-02). Subcommands are
    /// stub placeholders pending Phase 6 — they parse cleanly but
    /// each prints a TODO message until the per-ballot SDK actors
    /// land.
    #[command(subcommand)]
    Ballot(commands::ballot::BallotCmd),

    /// MPC trusted-setup ceremony commands.
    #[command(subcommand)]
    Ceremony(commands::ceremony::CeremonyCmd),

    /// Wallet helpers (BLS keygen, address, balance).
    #[command(subcommand)]
    Wallet(commands::wallet::WalletCmd),

    /// Puzzle introspection (compiled hashes, action layer hashes).
    #[command(subcommand)]
    Puzzle(commands::puzzle::PuzzleCmd),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.trace);

    let ctx = output::Context {
        network: cli.network.into(),
        rpc_override: cli.rpc.clone(),
        json: cli.json,
        assume_yes: cli.assume_yes,
    };

    match cli.cmd {
        Command::Deployer(c) => commands::deployer::run(c, &ctx).await?,
        Command::Voter(c) => commands::voter::run(c, &ctx).await?,
        Command::Aggregator(c) => commands::aggregator::run(c, &ctx).await?,
        Command::Indexer(c) => commands::indexer::run(c, &ctx).await?,
        Command::Ballot(c) => commands::ballot::run(c, &ctx).await?,
        Command::Ceremony(c) => commands::ceremony::run(c, &ctx).await?,
        Command::Wallet(c) => commands::wallet::run(c, &ctx).await?,
        Command::Puzzle(c) => commands::puzzle::run(c, &ctx).await?,
    }
    Ok(())
}

/// Configure `tracing-subscriber` based on CLI verbosity flags.
///
/// Default level is `info`. `--verbose` lifts to `debug`; `--trace`
/// lifts to `trace`. The user's `RUST_LOG` env var, if set, takes
/// precedence over both flags.
fn init_logging(verbose: bool, trace: bool) {
    use tracing_subscriber::{fmt, EnvFilter};
    let default_level = if trace {
        "trace"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_env_filter(filter)
        .init();
}
