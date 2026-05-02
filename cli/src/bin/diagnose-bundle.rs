// ============================================================================
// chip-voting-diagnose-bundle — surface the actual rejection reason for a
// SpendBundle that mainnet returned `status=FAILED` for.
// ============================================================================
//
// USAGE:
//   cargo run --release -p chip-voting-cli --bin chip-voting-diagnose-bundle \
//       -- <path-to-dump.json> [--height N]
//
// The dump file is the JSON produced by `live_integration_test::push_tx`'s
// failure path (`CHIP_VOTING_DUMP_DIR=./dump cargo run ...`). It contains
// `coin_spends` and `aggregated_signature` in the same shape `chia_query`
// uses.
//
// We rebuild a `chia_protocol::SpendBundle` from those fields and run it
// through `chip_voting_sdk::validate_bundle_for_consensus`, which calls
// the SAME `chia_consensus::validate_clvm_and_signature` mempool admission
// path full nodes use. A typed `ErrorCode` on rejection tells us exactly
// which consensus rule fired (e.g. `AssertHeightRelativeFailed`,
// `BadAggregateSignature`, `CostExceeded`, `GeneratorRuntimeError`).

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use chip_voting_sdk::{validate_bundle_for_consensus, Bytes32, Coin, CoinSpend, SpendBundle};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "chip-voting-diagnose-bundle")]
struct Args {
    /// Path to a `push-tx-failed-*.json` dump produced by the live test.
    dump: PathBuf,

    /// Chain peak height to validate the bundle against. Defaults to a
    /// far-future height so `ASSERT_HEIGHT_RELATIVE` / `ASSERT_HEIGHT_ABSOLUTE`
    /// don't fire spuriously — pass the actual peak from the time of
    /// rejection if you suspect a height-relative trap.
    #[arg(long, default_value_t = 100_000_000)]
    height: u32,
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim().trim_start_matches("0x");
    Ok(hex::decode(trimmed)?)
}

fn parse_b32(s: &str) -> Result<Bytes32> {
    let bytes = parse_hex(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes for {s}"))?;
    Ok(Bytes32::new(arr))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let raw = std::fs::read_to_string(&args.dump)
        .with_context(|| format!("read {}", args.dump.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw).context("dump file is not JSON")?;

    let label = json["label"].as_str().unwrap_or("(unknown)");
    let status = json["status"].as_str().unwrap_or("(unknown)");
    println!(
        "loaded {} (label={label}, status={status})",
        args.dump.display()
    );

    let coin_spends_json = json["coin_spends"]
        .as_array()
        .ok_or_else(|| anyhow!("dump missing coin_spends array"))?;

    let mut coin_spends: Vec<CoinSpend> = Vec::with_capacity(coin_spends_json.len());
    for (i, cs_json) in coin_spends_json.iter().enumerate() {
        let coin_json = &cs_json["coin"];
        let coin = Coin::new(
            parse_b32(coin_json["parent_coin_info"].as_str().unwrap())?,
            parse_b32(coin_json["puzzle_hash"].as_str().unwrap())?,
            coin_json["amount"]
                .as_u64()
                .ok_or_else(|| anyhow!("coin[{i}].amount not a u64"))?,
        );
        let puzzle_reveal = chia_protocol::Program::from(parse_hex(
            cs_json["puzzle_reveal_hex"].as_str().unwrap(),
        )?);
        let solution =
            chia_protocol::Program::from(parse_hex(cs_json["solution_hex"].as_str().unwrap())?);
        coin_spends.push(CoinSpend::new(coin, puzzle_reveal, solution));
    }

    let agg_sig_bytes = parse_hex(
        json["aggregated_signature"]
            .as_str()
            .ok_or_else(|| anyhow!("dump missing aggregated_signature"))?,
    )?;
    let arr: [u8; 96] = agg_sig_bytes
        .try_into()
        .map_err(|_| anyhow!("aggregated_signature must be 96 bytes"))?;
    let agg_sig = chia_bls::Signature::from_bytes(&arr)
        .map_err(|e| anyhow!("aggregated_signature parse: {e:?}"))?;

    let bundle = SpendBundle::new(coin_spends, agg_sig);

    println!(
        "bundle has {} coin_spend(s); validating at height {}…",
        bundle.coin_spends.len(),
        args.height,
    );
    for (i, cs) in bundle.coin_spends.iter().enumerate() {
        println!(
            "  spend[{i}] coin_id={} puzzle_hash={} amount={}",
            hex::encode(cs.coin.coin_id()),
            hex::encode(cs.coin.puzzle_hash),
            cs.coin.amount,
        );
    }

    match validate_bundle_for_consensus(&bundle, args.height) {
        Ok(cost) => {
            println!(
                "✓ bundle PASSES consensus validation at height {} (cost={cost})",
                args.height
            );
            println!(
                "  the node-side `status=FAILED` was likely caused by something OUTSIDE the \
                 deterministic consensus path — e.g. the singleton coin was already spent, the \
                 fee was below the local farmer's policy threshold, or the bundle expired waiting \
                 for an `ASSERT_HEIGHT_RELATIVE` it can no longer satisfy."
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ consensus rejected: {e}");
            bail!("consensus rejection (see above)");
        }
    }
}
