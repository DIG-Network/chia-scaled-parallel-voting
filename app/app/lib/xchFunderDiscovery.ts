// ============================================================================
// xchFunderDiscovery.ts — find an XCH funder coin across Sage synthetic keys
// ============================================================================
//
// Mirrors `catCollateralDiscovery.ts`'s pattern but for XCH (standard p2)
// puzzle hashes. The connected receive address is only one of many synthetic
// keys Sage manages; XCH funds for ballot launchers / fees can live on any
// of them, so we page chip0002_getPublicKeys until we find an unspent coin
// big enough to fund the launcher (need ≥ 3 mojos so change > 0; we require
// ≥ 100 for a sane minimum).

import walletConnect from "./walletConnectInstance";
import { coinRecordsByPuzzleHash, type CoinRecord } from "./coinset";
import { standardPuzzleHashHexFromSyntheticPubkeyHex } from "./chiaAddress";

const PAGE_SIZE = 100;
const MAX_SAFETY_KEY_LOOKUPS = 50_000;
const COINSET_KEY_SCAN_GAP_MS = 80;

export type XchFunderProgress =
  | { phase: "receive_key" }
  | { phase: "synthetic_keys"; keysChecked: number; sageOffset: number };

export type XchFunderResult = {
  /** Synthetic pubkey hex (`0x` + 96 lowercase hex) that owns the chosen XCH coin. */
  syntheticPkHex: string;
  xchCoin: CoinRecord;
};

function normalizePk(hex: string): string {
  const raw = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(raw)) {
    throw new Error("Expected 96 hex chars for a G1 synthetic pubkey");
  }
  return `0x${raw}`;
}

async function tryXchAt(
  pkHex: string,
  minMojos: bigint
): Promise<CoinRecord | null> {
  const ph = await standardPuzzleHashHexFromSyntheticPubkeyHex(pkHex);
  const coins = await coinRecordsByPuzzleHash(ph, false);
  // Pick the smallest unspent coin that's big enough — leaves larger coins
  // available for other flows and minimizes wasted change-coin creation.
  const candidates = coins
    .filter((c) => c.spentHeight === 0 && BigInt(c.amount) >= minMojos)
    .sort((a, b) => Number(BigInt(a.amount) - BigInt(b.amount)));
  return candidates[0] ?? null;
}

/**
 * Find an unspent XCH coin worth at least `minMojos`:
 * - Tries `preferredSyntheticPkHex` first (typically the connected
 *   receive address's synthetic key).
 * - Then pages `chip0002_getPublicKeys` until a match, Sage returns
 *   no more keys, or `MAX_SAFETY_KEY_LOOKUPS` is hit.
 */
export async function discoverXchFunder(opts: {
  minMojos: bigint;
  preferredSyntheticPkHex?: string | null;
  onProgress?: (p: XchFunderProgress) => void;
}): Promise<XchFunderResult> {
  await walletConnect.waitForInit();

  const examined = new Set<string>();
  let preferredNorm: string | null = null;
  if (opts.preferredSyntheticPkHex?.trim()) {
    try {
      preferredNorm = normalizePk(opts.preferredSyntheticPkHex);
    } catch {
      preferredNorm = null;
    }
  }

  if (preferredNorm) {
    examined.add(preferredNorm);
    opts.onProgress?.({ phase: "receive_key" });
    const hit = await tryXchAt(preferredNorm, opts.minMojos);
    if (hit) return { syntheticPkHex: preferredNorm, xchCoin: hit };
  }

  let walletQueries = 0;
  let sageOffset = 0;

  for (;;) {
    if (walletQueries >= MAX_SAFETY_KEY_LOOKUPS) {
      throw new Error(
        `No XCH funder coin found after ${MAX_SAFETY_KEY_LOOKUPS.toLocaleString()} ` +
          `synthetic key lookups (safety limit).`
      );
    }
    const keys = await walletConnect.getPublicKeys(PAGE_SIZE, sageOffset);
    if (!keys || keys.length === 0) break;
    sageOffset += keys.length;

    for (const k of keys) {
      let norm: string;
      try {
        norm = normalizePk(k);
      } catch {
        continue;
      }
      if (examined.has(norm)) continue;
      examined.add(norm);
      walletQueries += 1;
      opts.onProgress?.({
        phase: "synthetic_keys",
        keysChecked: walletQueries,
        sageOffset,
      });
      const hit = await tryXchAt(norm, opts.minMojos);
      if (hit) return { syntheticPkHex: norm, xchCoin: hit };
      if (COINSET_KEY_SCAN_GAP_MS > 0) {
        await new Promise((r) => setTimeout(r, COINSET_KEY_SCAN_GAP_MS));
      }
    }

    if (keys.length < PAGE_SIZE) break;
  }

  throw new Error(
    `No spendable XCH coin (≥${opts.minMojos.toString()} mojos) found across ` +
      `${(preferredNorm ? "your receive-address key plus " : "") + walletQueries} ` +
      `Sage synthetic keys (paged until the wallet returned no more keys). ` +
      `Top up the wallet, consolidate XCH, or split a larger coin.`
  );
}
