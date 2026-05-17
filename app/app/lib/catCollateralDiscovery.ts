// ============================================================================
// catCollateralDiscovery.ts — CAT collateral lookup across Sage synthetic keys
// ============================================================================
//
// Paginates chip0002_getPublicKeys, derives CAT outer hashes via chia-sdk,
// and queries coinset until collateral is found or Sage has no more keys.
//
// There is no WalletConnect RPC in CHIP's Sage session listing that answers
// "which synthetic pubkey holds CAT tail X?" — WC only declares chia_send,
// getAddress, chip0002_* (see WalletConnect.ts). Until Sage exposes balances
// or coins by CAT + key, derivation-index scan remains the portable approach.

import walletConnect from "./walletConnectInstance";
import { coinRecordsByPuzzleHash, stripHex, type CoinRecord } from "./coinset";
import { catOuterPuzzleHashHexFromSyntheticPubkeyHex } from "./chiaAddress";
import { formatCat, normalizeHex32, truncHex } from "./units";

const PAGE_SIZE = 100;

/** Abort runaway loops if a wallet reports an extreme number of keys. */
const MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS = 50_000;

const PROGRESS_THROTTLE_MS = 120;

/** Small pause between unsuccessful coinset lookups while scanning Sage keys (reduces bursts). */
const COINSET_KEY_SCAN_GAP_MS = 120;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Fingerprint CAT UTXOs for retry / exclusion (parent + puzzle hash + amount). */
export function catCollateralDedupeKey(c: CoinRecord): string {
  return `${stripHex(c.parentCoinInfo)}|${stripHex(c.puzzleHash)}|${c.amount}`;
}

export type CatCollateralDiscoveryResult = {
  /** Synthetic pubkey hex (`0x` + lowercase) that owns the chosen CAT coin */
  voterPk: string;
  catCoin: CoinRecord;
  allCatCoinsAtOuter: CoinRecord[];
};

/** Live progress for registration UI (receive key, then paged synthetics). */
export type CollateralScanProgress =
  | { phase: "receive_key" }
  | { phase: "synthetic_keys"; keysChecked: number; sageOffset: number };

/** Normalize Sage-style synthetic pubkey hex for comparison/dedupe. */
function normalizeSyntheticPkHex(hex: string): string {
  const raw = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(raw)) {
    throw new Error("Expected 96 hex chars for a G1 synthetic pubkey");
  }
  return `0x${raw}`;
}

function reportProgress(
  onProgress: ((p: CollateralScanProgress) => void) | undefined,
  payload: CollateralScanProgress,
  throttle: { last: number; pending: CollateralScanProgress | null }
): void {
  if (!onProgress) return;
  const now = typeof performance !== "undefined" ? performance.now() : Date.now();
  throttle.pending = payload;
  if (now - throttle.last < PROGRESS_THROTTLE_MS) return;
  throttle.last = now;
  const p = throttle.pending;
  throttle.pending = null;
  onProgress(p);
}

function flushProgress(
  onProgress: ((p: CollateralScanProgress) => void) | undefined,
  throttle: { last: number; pending: CollateralScanProgress | null }
): void {
  if (!onProgress || !throttle.pending) return;
  onProgress(throttle.pending);
  throttle.pending = null;
}

async function tryCollateralAtSyntheticPk(
  voterPkNormalized: string,
  tailBare64: string,
  collateralAmount: bigint,
  excludeDedupeKeys: ReadonlySet<string> | undefined
): Promise<{ catCoin: CoinRecord; all: CoinRecord[] } | null> {
  const outer = await catOuterPuzzleHashHexFromSyntheticPubkeyHex(
    voterPkNormalized,
    tailBare64
  );
  const digCoins = await coinRecordsByPuzzleHash(outer, false);
  const catCoin = digCoins.find(
    (c) =>
      BigInt(c.amount) >= collateralAmount &&
      !excludeDedupeKeys?.has(catCollateralDedupeKey(c))
  );
  if (!catCoin) return null;
  return { catCoin, all: digCoins };
}

/**
 * Find unspent CAT collateral. Phase 1 (fast path): use Sage's
 * `chip0002_getAssetCoins({ type: 'cat', assetId: tail })` to get
 * spendable CAT coins with their puzzle reveals pre-included; uncurry
 * to extract synthetic_pk per coin. Phase 2 (legacy fallback): if
 * getAssetCoins isn't available or returns empty, fall back to the
 * `chip0002_getPublicKeys` pagination + coinset.org puzzle-hash
 * lookup pattern (slow but works on older Sage builds).
 */
export async function discoverCatCollateralForRegistration(opts: {
  catTailHashHex: string;
  collateralAmountMojos: bigint;
  preferredSyntheticPkHex: string | null | undefined;
  onProgress?: (p: CollateralScanProgress) => void;
  /**
   * Dedupe keys from {@link catCollateralDedupeKey} — CAT coins to skip (e.g. prior
   * `push_tx` MINTING_COIN mempool conflicts).
   */
  excludeDedupeKeys?: ReadonlySet<string>;
}): Promise<CatCollateralDiscoveryResult> {
  const tailBareEarly = normalizeHex32(String(opts.catTailHashHex ?? ""));
  if (!/^[0-9a-f]{64}$/.test(tailBareEarly)) {
    throw new Error("Invalid CAT tail in election config.");
  }
  // Fast path: Sage owns the CATs — ask it directly. No key scan, no
  // coinset hop. The puzzle reveal in the response uncurries to give
  // us synthetic_pk per coin.
  try {
    const { listCatCoinsWithKeys } = await import("./sageAssetCoins");
    const sageCats = await listCatCoinsWithKeys(tailBareEarly, {
      minAmount: opts.collateralAmountMojos,
      includeLocked: false,
      limit: 200,
    });
    const excluded = opts.excludeDedupeKeys;
    for (const entry of sageCats) {
      const cr: CoinRecord = {
        parentCoinInfo: entry.coin.parent_coin_info.startsWith("0x")
          ? entry.coin.parent_coin_info
          : `0x${entry.coin.parent_coin_info}`,
        puzzleHash: entry.coin.puzzle_hash.startsWith("0x")
          ? entry.coin.puzzle_hash
          : `0x${entry.coin.puzzle_hash}`,
        amount: entry.coin.amount,
        spentHeight: 0,
        confirmedHeight: 0,
      };
      if (excluded?.has(catCollateralDedupeKey(cr))) continue;
      return {
        voterPk: entry.syntheticPkHex,
        catCoin: cr,
        // Sage gave us this single coin; the legacy field
        // `allCatCoinsAtOuter` is downgraded to a 1-element list.
        allCatCoinsAtOuter: [cr],
      };
    }
  } catch (e) {
    console.warn(
      "[catCollateralDiscovery] getAssetCoins fast-path failed, falling back to key scan:",
      e
    );
  }
  // Legacy fallback below — kept verbatim for older Sage builds and
  // edge cases (e.g. CAT held under a key Sage isn't tracking as
  // owned). Will be removed once getAssetCoins is reliable everywhere.
  const tailBare = normalizeHex32(String(opts.catTailHashHex ?? ""));
  if (!/^[0-9a-f]{64}$/.test(tailBare)) {
    throw new Error("Invalid CAT tail in election config.");
  }

  const tailDisplay = truncHex(`0x${tailBare}`, 8, 4);

  const examinedPk = new Set<string>();
  let preferredNorm: string | null = null;
  if (opts.preferredSyntheticPkHex?.trim()) {
    try {
      preferredNorm = normalizeSyntheticPkHex(opts.preferredSyntheticPkHex);
    } catch {
      preferredNorm = null;
    }
  }

  const throttle = { last: 0, pending: null as CollateralScanProgress | null };
  const onProgress = opts.onProgress;
  const excluded = opts.excludeDedupeKeys;

  await walletConnect.waitForInit();

  if (preferredNorm) {
    reportProgress(onProgress, { phase: "receive_key" }, throttle);
    examinedPk.add(preferredNorm);
    const hit = await tryCollateralAtSyntheticPk(
      preferredNorm,
      tailBare,
      opts.collateralAmountMojos,
      excluded
    );
    if (hit) {
      flushProgress(onProgress, throttle);
      return {
        voterPk: preferredNorm,
        catCoin: hit.catCoin,
        allCatCoinsAtOuter: hit.all,
      };
    }
  }

  let walletQueries = 0;
  let sageOffset = 0;

  for (;;) {
    if (walletQueries >= MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS) {
      flushProgress(onProgress, throttle);
      throw new Error(
        `No CAT collateral found after ${MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS.toLocaleString()} ` +
          `synthetic key lookups — safety limit. If your funds are on a very high derivation ` +
          `index, contact support. Asset ${tailDisplay}, need ≥ ${formatCat(
            opts.collateralAmountMojos
          )} in one coin (mainnet coinset / testnet NEXT_PUBLIC_COINSET_BASE_URL).`
      );
    }

    const keys = await walletConnect.getPublicKeys(PAGE_SIZE, sageOffset);
    if (!keys || keys.length === 0) {
      break;
    }

    sageOffset += keys.length;

    for (const k of keys) {
      const bare = k.trim().replace(/^0x/i, "");
      if (bare.length !== 96 || !/^[0-9a-fA-F]+$/.test(bare)) continue;

      let norm: string;
      try {
        norm = normalizeSyntheticPkHex(k.trim());
      } catch {
        continue;
      }

      if (examinedPk.has(norm)) continue;
      examinedPk.add(norm);
      walletQueries += 1;

      reportProgress(
        onProgress,
        { phase: "synthetic_keys", keysChecked: walletQueries, sageOffset },
        throttle
      );

      const hit = await tryCollateralAtSyntheticPk(
        norm,
        tailBare,
        opts.collateralAmountMojos,
        excluded
      );
      if (hit) {
        flushProgress(onProgress, throttle);
        return {
          voterPk: norm,
          catCoin: hit.catCoin,
          allCatCoinsAtOuter: hit.all,
        };
      }

      if (COINSET_KEY_SCAN_GAP_MS > 0) {
        await sleep(COINSET_KEY_SCAN_GAP_MS);
      }

      if (walletQueries >= MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS) {
        flushProgress(onProgress, throttle);
        throw new Error(
          `No CAT collateral found after ${MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS.toLocaleString()} ` +
            `synthetic key lookups (safety limit).`
        );
      }
    }

    if (keys.length < PAGE_SIZE) {
      break;
    }
  }

  flushProgress(onProgress, throttle);
  throw new Error(
    `No unspent CAT for asset ${tailDisplay} with one coin holding at least ` +
      `${formatCat(opts.collateralAmountMojos)} after checking ` +
      (preferredNorm ? "your receive-address key and " : "") +
      `${walletQueries} additional Sage synthetic keys (scanned until the wallet ` +
      `returned no more keys). Mainnet uses api.coinset.org — on testnet set ` +
      `NEXT_PUBLIC_COINSET_BASE_URL and rebuild.`
  );
}
