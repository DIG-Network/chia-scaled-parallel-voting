// ============================================================================
// registrationFeeDiscovery.ts — XCH registration fee across Sage synthetic keys
// ============================================================================
//
// Registration fee must be spent from standard_p2(synthetic_pk). That pk need
// not match the CAT collateral key: WalletConnect signs every CoinSpend in the
// bundle with whichever HD-derived keys own each input.

import walletConnect from "./walletConnectInstance";
import { coinRecordsByPuzzleHash, stripHex, type CoinRecord } from "./coinset";
import { standardPuzzleHashHexFromSyntheticPubkeyHex } from "./chiaAddress";
import { formatXch } from "./units";

const PAGE_SIZE = 100;
const MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS = 50_000;
const COINSET_KEY_SCAN_GAP_MS = 120;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function normalizeSyntheticPkHex(hex: string): string {
  const raw = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(raw)) {
    throw new Error("Expected 96 hex chars for a G1 synthetic pubkey");
  }
  return `0x${raw}`;
}

export type RegistrationFeeScanProgress =
  | { phase: "priority_keys"; keysChecked: number }
  | { phase: "synthetic_keys"; keysChecked: number; sageOffset: number };

/** Fingerprint standard XCH UTXOs for exclusion (same coin cannot fund two spends). */
export function xchCoinDedupeKey(c: CoinRecord): string {
  return `${stripHex(c.parentCoinInfo)}|${stripHex(c.puzzleHash)}|${c.amount}`;
}

async function tryXchAtSyntheticPk(
  pkNorm: string,
  minMojos: bigint,
  excludeDedupeKeys: ReadonlySet<string>
): Promise<CoinRecord | null> {
  const ph = await standardPuzzleHashHexFromSyntheticPubkeyHex(pkNorm);
  const recs = await coinRecordsByPuzzleHash(ph, false);
  return (
    recs.find(
      (c) =>
        BigInt(c.amount) >= minMojos &&
        !excludeDedupeKeys.has(xchCoinDedupeKey(c))
    ) ?? null
  );
}

export type DiscoverStandardXchOpts = {
  minMojos: bigint;
  /** UTXOs that must not be selected (e.g. already used as registration_fee input). */
  excludeCoins: CoinRecord[];
  prioritizePkHexes: (string | null | undefined)[];
  onProgress?: (p: RegistrationFeeScanProgress) => void;
};

/**
 * Find unspent standard XCH ≥ `minMojos`, optionally excluding coins already
 * used elsewhere in the same transaction bundle.
 */
export async function discoverStandardXchUtxo(
  opts: DiscoverStandardXchOpts
): Promise<{ feePayerPk: string; xchCoin: CoinRecord }> {
  if (opts.minMojos <= 0n) {
    throw new Error("discoverStandardXchUtxo: minMojos must be > 0");
  }

  const excludeDedupeKeys = new Set(
    opts.excludeCoins.map((c) => xchCoinDedupeKey(c))
  );

  const examinedPk = new Set<string>();
  const priorityNorm: string[] = [];
  for (const raw of opts.prioritizePkHexes) {
    if (!raw?.trim()) continue;
    let norm: string;
    try {
      norm = normalizeSyntheticPkHex(raw);
    } catch {
      continue;
    }
    if (examinedPk.has(norm)) continue;
    examinedPk.add(norm);
    priorityNorm.push(norm);
  }

  await walletConnect.waitForInit();

  let keysChecked = 0;
  const onProgress = opts.onProgress;

  for (const norm of priorityNorm) {
    keysChecked += 1;
    onProgress?.({ phase: "priority_keys", keysChecked });
    const coin = await tryXchAtSyntheticPk(norm, opts.minMojos, excludeDedupeKeys);
    if (coin) return { feePayerPk: norm, xchCoin: coin };
    if (COINSET_KEY_SCAN_GAP_MS > 0) await sleep(COINSET_KEY_SCAN_GAP_MS);
  }

  let walletQueries = priorityNorm.length;
  let sageOffset = 0;

  for (;;) {
    if (walletQueries >= MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS) {
      throw new Error(
        `No unspent XCH ≥ ${opts.minMojos.toString()} mojos (${formatXch(
          opts.minMojos
        )} XCH) after ${MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS.toLocaleString()} synthetic key lookups.`
      );
    }

    const keys = await walletConnect.getPublicKeys(PAGE_SIZE, sageOffset);
    if (!keys || keys.length === 0) break;
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

      onProgress?.({
        phase: "synthetic_keys",
        keysChecked: walletQueries,
        sageOffset,
      });

      const coin = await tryXchAtSyntheticPk(norm, opts.minMojos, excludeDedupeKeys);
      if (coin) return { feePayerPk: norm, xchCoin: coin };

      if (COINSET_KEY_SCAN_GAP_MS > 0) await sleep(COINSET_KEY_SCAN_GAP_MS);

      if (walletQueries >= MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS) {
        throw new Error(
          `No unspent XCH fee coin found after ${MAX_SAFETY_SYNTHETIC_KEY_LOOKUPS.toLocaleString()} lookups (safety limit).`
        );
      }
    }

    if (keys.length < PAGE_SIZE) break;
  }

  const feeDisp = `${formatXch(opts.minMojos)} XCH (${opts.minMojos.toLocaleString()} mojos)`;
  throw new Error(
    `No unspent standard XCH coin ≥ ${feeDisp} on any Sage synthetic key checked (${walletQueries} keys). ` +
      `Fund this wallet's receive address(es) so some derivation holds both the CAT collateral and fee XCH under coinset-visible standard puzzle hashes.`
  );
}

/**
 * Find unspent XCH ≥ `regFeeMojos` at `standard_puzzle_hash(pk)` for some
 * Sage synthetic key. Tries `prioritizePkHexes` first (deduped), then pages
 * `chip0002_getPublicKeys` like CAT collateral discovery.
 */
export async function discoverRegistrationFeeXch(opts: {
  regFeeMojos: bigint;
  prioritizePkHexes: (string | null | undefined)[];
  onProgress?: (p: RegistrationFeeScanProgress) => void;
}): Promise<{ feePayerPk: string; xchCoin: CoinRecord }> {
  if (opts.regFeeMojos <= 0n) {
    throw new Error("discoverRegistrationFeeXch: regFeeMojos must be > 0");
  }
  return discoverStandardXchUtxo({
    minMojos: opts.regFeeMojos,
    excludeCoins: [],
    prioritizePkHexes: opts.prioritizePkHexes,
    onProgress: opts.onProgress,
  });
}

/**
 * Second XCH UTXO for `RESERVE_FEE` — must differ from `excludeCoins` when
 * those inputs are already consumed in the same bundle.
 */
export async function discoverMempoolFeeXch(opts: {
  feeMojos: bigint;
  excludeCoins: CoinRecord[];
  prioritizePkHexes: (string | null | undefined)[];
  onProgress?: (p: RegistrationFeeScanProgress) => void;
}): Promise<{ feePayerPk: string; xchCoin: CoinRecord }> {
  if (opts.feeMojos <= 0n) {
    throw new Error("discoverMempoolFeeXch: feeMojos must be > 0");
  }
  return discoverStandardXchUtxo({
    minMojos: opts.feeMojos,
    excludeCoins: opts.excludeCoins,
    prioritizePkHexes: opts.prioritizePkHexes,
    onProgress: opts.onProgress,
  });
}
