// ============================================================================
// rpc.rs — ChiaQuery client construction + broadcast helpers
// ============================================================================
//
// MODULE: rpc
// PURPOSE: Build a `chia_query::ChiaQuery` from CLI flags. ChiaQuery
//          is the SDK's preferred chain reader/broadcaster — it
//          discovers peers via DNS, falls back to coinset.org HTTP
//          when peers are slow, and exposes `push_tx`.
//
// CERT POLICY: by default we use the chia node's TLS cert at the
// network's standard path (~/.chia/<network>/config/ssl/wallet/...).
// Users running headless (no chia install) can pass `--cert-path` /
// `--key-path` to the relevant subcommands.

use anyhow::{Context as _, Result};
use chia_query::{ChiaQuery, ChiaQueryConfig};
use chia_protocol::SpendBundle;
use dig_l1_wallet::NetworkType;

/// Construct a `ChiaQuery` for the given network.
///
/// `rpc_override` is reserved for a future "named endpoint" feature
/// (e.g., pointing at a private relay); for now it's logged but not
/// used because ChiaQuery does its own peer discovery and coinset.org
/// fallback. Pass `None` for default behaviour.
pub async fn make_chain_client(
    network: NetworkType,
    rpc_override: Option<&str>,
) -> Result<ChiaQuery> {
    let mut cfg = ChiaQueryConfig {
        network,
        ..Default::default()
    };
    // Override the coinset base URL if the user provided one. ChiaQuery
    // also uses the peer pool, so this URL is just the HTTP fallback.
    if let Some(url) = rpc_override {
        tracing::info!(rpc = url, "using user-supplied coinset URL");
        cfg.coinset_base_url = url.to_string();
    }
    ChiaQuery::new(cfg)
        .await
        .with_context(|| {
            format!(
                "constructing ChiaQuery for {:?} (peer discovery + TLS init)",
                network
            )
        })
}

/// Broadcast a spend bundle and return a JSON summary of the result.
///
/// chia-query has its own `SpendBundle` shape (hex-string encoded
/// fields for HTTP JSON portability), distinct from
/// `chia_protocol::SpendBundle` (binary). We convert at the boundary.
///
/// On success returns the `status` string from the node ("SUCCESS",
/// "PENDING", "FAILED") plus the bundle's coin spends. Callers
/// typically print this through `Context::print`.
pub async fn broadcast(
    chain: &ChiaQuery,
    bundle: &SpendBundle,
) -> Result<serde_json::Value> {
    let wire = to_query_bundle(bundle);
    let status = chain
        .push_tx(&wire)
        .await
        .with_context(|| "submitting spend bundle to network")?;
    Ok(serde_json::json!({
        "status":      status.status,
        "coin_spends": bundle.coin_spends.len(),
        "aggregated_signature": format!("0x{}", hex::encode(bundle.aggregated_signature.to_bytes())),
    }))
}

/// Convert a `chia_protocol::SpendBundle` into the hex-encoded
/// JSON-portable shape `chia_query` expects for `push_tx`.
fn to_query_bundle(b: &SpendBundle) -> chia_query::SpendBundle {
    chia_query::SpendBundle {
        coin_spends: b
            .coin_spends
            .iter()
            .map(|cs| chia_query::CoinSpend {
                coin: chia_query::Coin {
                    parent_coin_info: format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                    puzzle_hash: format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                    amount: cs.coin.amount,
                },
                puzzle_reveal: format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                solution: format!("0x{}", hex::encode(cs.solution.as_ref())),
            })
            .collect(),
        aggregated_signature: format!("0x{}", hex::encode(b.aggregated_signature.to_bytes())),
    }
}
