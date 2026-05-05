// ============================================================================
// push.mjs — broadcast SpendBundle bytes + poll for confirmation
// ============================================================================
//
// Mirrors `cli/src/bin/live_integration_test.rs::push_and_wait`:
// converts the wasm-side Streamable SpendBundle bytes (output of
// `wasm.assembleSpendBundle`) into a chia-wallet-sdk-wasm
// `SpendBundle` object, hands it to `CoinsetClient.pushTx()`, and
// polls `getCoinRecordByName(coinId)` until the bundle's expected
// output coin appears with `confirmedBlockIndex > 0`.
//
// Why we go via chia-wallet-sdk-wasm: coinset.org's `/push_tx`
// endpoint expects a JSON SpendBundle in chia full-node format
// (coin_spends with `puzzle_reveal` / `solution` as 0x-hex; aggregated_signature
// as 0x-hex). Hand-building that JSON is fiddly. The wallet SDK's
// `CoinsetClient.pushTx(SpendBundle)` does the conversion + POST in
// one call.

import { SpendBundle, CoinsetClient } from "chia-wallet-sdk-wasm";
import { coinRecordByName } from "./coinset.mjs";

/**
 * Decode wasm-bindgen Streamable bytes into a chia-wallet-sdk-wasm
 * SpendBundle. Same wire format on both sides (chia_protocol).
 */
export function spendBundleFromStreamableBytes(bytes) {
  return SpendBundle.fromBytes(bytes);
}

/** Pick mainnet vs. testnet11 client per the wallet's network. */
export function clientForNetwork(network) {
  if (network === "mainnet") return CoinsetClient.mainnet();
  if (network === "testnet11") return CoinsetClient.testnet11();
  throw new Error(`clientForNetwork: unknown network ${network}`);
}

/**
 * Push a Streamable-bytes-encoded SpendBundle and return the
 * `pushTx` response (`{ status, error? }` shape per coinset.org).
 *
 * Tries chia-wallet-sdk-wasm's `CoinsetClient.pushTx` first (handles
 * the JSON shape conversion); falls back to manual JSON-shape
 * construction + direct fetch if the SDK's reqwest layer chokes on
 * the response decode (occasionally happens for large bundles).
 */
export async function pushSpendBundleBytes(bundleBytes, { network = "mainnet" } = {}) {
  // chia-wallet-sdk-wasm's CoinsetClient.pushTx works for small
  // bundles but its reqwest response-decoder chokes on coinset.org's
  // larger responses (e.g. 7996-byte register bundles return a
  // response whose JSON shape the SDK can't parse). Always go the
  // manual route — convert SpendBundle → coinset.org's JSON shape
  // via chia-wallet-sdk-wasm accessors, then POST directly.
  const bundle = spendBundleFromStreamableBytes(bundleBytes);
  const baseUrl =
    network === "mainnet"
      ? "https://api.coinset.org"
      : "https://api-testnet11.coinset.org";
  const json = bundleToJson(bundle);
  const r = await fetch(`${baseUrl}/push_tx`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ spend_bundle: json }),
  });
  const text = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(
      `pushSpendBundleBytes: non-JSON response from /push_tx: ${text.slice(0, 200)}`
    );
  }
  return parsed;
}

function bytesToHex(bytes) {
  return (
    "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")
  );
}

/** chia-wallet-sdk-wasm SpendBundle → coinset.org push_tx JSON shape. */
function bundleToJson(bundle) {
  return {
    coin_spends: bundle.coinSpends.map((cs) => ({
      coin: {
        parent_coin_info: bytesToHex(cs.coin.parentCoinInfo),
        puzzle_hash: bytesToHex(cs.coin.puzzleHash),
        amount: Number(cs.coin.amount),
      },
      puzzle_reveal: bytesToHex(cs.puzzleReveal),
      solution: bytesToHex(cs.solution),
    })),
    aggregated_signature: bytesToHex(bundle.aggregatedSignature.toBytes()),
  };
}

/**
 * Poll `coinRecordByName(coinIdHex)` until `confirmedHeight > 0`,
 * `spentHeight > 0`, or `timeoutMs` elapsed.
 *
 * Returns the coin record on success. Throws with elapsed-time
 * context on timeout (most useful when chasing peer-pool propagation
 * lag — the rust test's same logic surfaces "peers stuck" cleanly).
 *
 * `pollIntervalMs` defaults to 30_000 (mainnet block target ~52s;
 * tighter just hammers the RPC). `timeoutMs` defaults to 600_000
 * (10 minutes — covers normal block production + farmer queue jitter).
 */
export async function pollUntilConfirmed(
  coinIdHex,
  {
    label = "coin",
    pollIntervalMs = 30_000,
    timeoutMs = 600_000,
    requireSpent = false,
  } = {}
) {
  const started = Date.now();
  let attempts = 0;
  while (true) {
    attempts++;
    let rec = null;
    try {
      rec = await coinRecordByName(coinIdHex);
    } catch (e) {
      // Transient RPC failure — log and retry.
      console.warn(`pollUntilConfirmed[${label}] attempt ${attempts}: RPC error: ${e.message}`);
    }
    if (rec) {
      const ready = requireSpent ? rec.spentHeight > 0 : rec.confirmedHeight > 0;
      if (ready) return rec;
    }
    const elapsed = Date.now() - started;
    if (elapsed >= timeoutMs) {
      throw new Error(
        `pollUntilConfirmed[${label}]: ${coinIdHex} not ${requireSpent ? "spent" : "confirmed"} ` +
          `after ${(elapsed / 1000) | 0}s (${attempts} attempts). ` +
          (rec
            ? `last seen with confirmed=${rec.confirmedHeight} spent=${rec.spentHeight}.`
            : `coin never showed up — push may have failed silently.`)
      );
    }
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }
}
