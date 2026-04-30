// ============================================================================
// commands/ — per-actor subcommand handlers
// ============================================================================
//
// MODULE: commands
// LAYOUT: one module per top-level verb. Each module exposes a
//   `<Verb>Cmd` enum (clap subcommands) and an `async fn run(cmd,
//   &Context)` dispatcher. main.rs match's the verb and calls the
//   corresponding `run`.
//
// CONVENTION: handlers
//   1. Parse + validate inputs (return user-error early on bad args).
//   2. Build the SDK actor / orchestrate the operation.
//   3. Render the result via `Context::print` (JSON or human).
//   4. NEVER write to stdout directly — use `ctx.print(...)`.
//   5. NEVER persist secret material to disk in plain text.

pub mod aggregator;
pub mod ceremony;
pub mod deployer;
pub mod indexer;
pub mod oracle;
pub mod puzzle;
pub mod voter;
pub mod wallet;
