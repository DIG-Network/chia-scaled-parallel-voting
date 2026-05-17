// ============================================================================
// sageAssetCoins.ts — fast coin selection via chip0002_getAssetCoins
// ============================================================================
//
// Replaces the brute-force pattern of paginating chip0002_getPublicKeys
// + computing standardPuzzleHash(pk) for every key looking for a match
// against a coinset.org coin record (~57s on wallets with many derived
// keys). chip0002_getAssetCoins returns coins Sage already knows it
// owns, INCLUDING the puzzle reveal — uncurrying the standard p2
// puzzle gives the synthetic_pk directly. No scanning.
//
// Returns a list of `{ coin, syntheticPkHex, lineageProof? }` entries
// suitable for funder-coin selection (deploy / register / etc.) or
// CAT collateral selection (register).

import walletConnect from "./walletConnectInstance";
import type { SageAssetCoin } from "./WalletConnect";

export interface SageCoinWithKey {
  coin: {
    parent_coin_info: string;
    puzzle_hash: string;
    amount: number;
  };
  /** 0x-prefixed synthetic pubkey hex (48 bytes), uncurried from the puzzle reveal. */
  syntheticPkHex: string;
  /** Raw puzzle reveal hex from Sage, if downstream wants to skip re-currying. */
  puzzleRevealHex?: string;
  lineageProof?: SageAssetCoin["lineageProof"];
  locked?: boolean;
}

/**
 * Extract the curried synthetic_pk from a standard p2 puzzle reveal.
 * The standard p2 puzzle is curried with exactly ONE arg
 * (synthetic_pk, 48-byte BLS G1). Returns null when:
 *   * the puzzle isn't a CurriedProgram (not standard shape)
 *   * the first curried arg isn't a 48-byte atom
 *
 * For CATs the wrapper around the standard p2 needs an extra unwrap;
 * that path is handled in `extractCatInnerSyntheticPk` below.
 */
function extractStandardSyntheticPk(
  clvm: { deserialize: (bytes: Uint8Array) => { uncurry: () => { args: { toAtom: () => Uint8Array | undefined }[] } | undefined } },
  puzzleBytes: Uint8Array
): string | null {
  const program = clvm.deserialize(puzzleBytes);
  const curried = program.uncurry();
  if (!curried) return null;
  const args = curried.args;
  if (!args || args.length === 0) return null;
  const pkAtom = args[0].toAtom();
  if (!pkAtom || pkAtom.length !== 48) return null;
  let s = "0x";
  for (let i = 0; i < pkAtom.length; i++) {
    s += pkAtom[i].toString(16).padStart(2, "0");
  }
  return s.toLowerCase();
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * List the wallet's spendable XCH coins with their derived
 * synthetic_pk pre-extracted. Filters out locked coins by default
 * (clawback / option / etc.) since we can't sign for those without
 * special handling.
 */
export async function listXchCoinsWithKeys(
  opts: { minAmount?: number; includeLocked?: boolean; limit?: number } = {}
): Promise<SageCoinWithKey[]> {
  const limit = opts.limit ?? 200;
  const includeLocked = opts.includeLocked ?? false;
  const minAmount = opts.minAmount ?? 0;
  // chip0002 spec: type=null means XCH (NOT the string "xch", which Sage rejects).
  const raw = await walletConnect.getAssetCoins(null, null, includeLocked, 0, limit);
  if (!raw || raw.length === 0) return [];

  const chia = await import("chia-wallet-sdk-wasm");
  const Clvm = chia.Clvm;
  const clvm = new Clvm();
  const out: SageCoinWithKey[] = [];
  for (const entry of raw) {
    if (!entry?.coin) continue;
    if (Number(entry.coin.amount) < minAmount) continue;
    if (!includeLocked && entry.locked) continue;
    if (!entry.puzzle) continue;
    let pk: string | null = null;
    try {
      const puzzleBytes = hexToBytes(entry.puzzle);
      pk = extractStandardSyntheticPk(clvm as never, puzzleBytes);
    } catch {
      pk = null;
    }
    if (!pk) continue;
    out.push({
      coin: {
        parent_coin_info: entry.coin.parent_coin_info,
        puzzle_hash: entry.coin.puzzle_hash,
        amount: Number(entry.coin.amount),
      },
      syntheticPkHex: pk,
      puzzleRevealHex: entry.puzzle,
      lineageProof: entry.lineageProof,
      locked: entry.locked,
    });
  }
  return out;
}

/**
 * Convenience: find a single XCH coin matching `puzzleHashHex` and
 * return its synthetic_pk. Replaces
 * `findSyntheticPkMatchingCoinPuzzleHashHex`'s brute-force scan.
 *
 * Returns null when Sage doesn't own a coin at that puzzle hash.
 */
export async function syntheticPkForOwnedXchPuzzleHash(
  puzzleHashHex: string
): Promise<string | null> {
  const target = puzzleHashHex.replace(/^0x/i, "").toLowerCase();
  const list = await listXchCoinsWithKeys({ includeLocked: false });
  for (const entry of list) {
    const ph = entry.coin.puzzle_hash.replace(/^0x/i, "").toLowerCase();
    if (ph === target) return entry.syntheticPkHex;
  }
  return null;
}

/**
 * Extract the synthetic_pk from a CAT-wrapped puzzle reveal. CAT
 * puzzle is curried with `(MOD_HASH, TAIL_HASH, INNER_PUZZLE)` —
 * uncurry, take the third arg (the inner puzzle which is standard
 * p2), uncurry that, take its first arg (the synthetic_pk atom).
 */
function extractCatInnerSyntheticPk(
  clvm: { deserialize: (bytes: Uint8Array) => { uncurry: () => { args: { uncurry: () => { args: { toAtom: () => Uint8Array | undefined }[] } | undefined }[] } | undefined } },
  puzzleBytes: Uint8Array
): string | null {
  const outer = clvm.deserialize(puzzleBytes).uncurry();
  if (!outer || !outer.args || outer.args.length < 3) return null;
  const inner = outer.args[2].uncurry();
  if (!inner || !inner.args || inner.args.length === 0) return null;
  const pkAtom = inner.args[0].toAtom();
  if (!pkAtom || pkAtom.length !== 48) return null;
  let s = "0x";
  for (let i = 0; i < pkAtom.length; i++) {
    s += pkAtom[i].toString(16).padStart(2, "0");
  }
  return s.toLowerCase();
}

/**
 * List the wallet's spendable CAT coins (for the given TAIL hash)
 * with their synthetic_pk pre-extracted from the CAT-wrapped puzzle
 * reveal. Replaces the brute-force `chip0002_getPublicKeys` scan +
 * coinset.org lookup pattern in `catCollateralDiscovery.ts`.
 *
 * `tailHashHex` is the 32-byte CAT TAIL hash (with or without 0x).
 */
export async function listCatCoinsWithKeys(
  tailHashHex: string,
  opts: { minAmount?: bigint; includeLocked?: boolean; limit?: number } = {}
): Promise<SageCoinWithKey[]> {
  const limit = opts.limit ?? 200;
  const includeLocked = opts.includeLocked ?? false;
  const minAmount = opts.minAmount ?? BigInt(0);
  // Sage wants BARE hex for the assetId (TAIL hash) — no `0x` prefix.
  const tail = tailHashHex.replace(/^0x/i, "").toLowerCase();
  const raw = await walletConnect.getAssetCoins(
    "cat",
    tail,
    includeLocked,
    0,
    limit
  );
  if (!raw || raw.length === 0) return [];

  const chia = await import("chia-wallet-sdk-wasm");
  const Clvm = chia.Clvm;
  const clvm = new Clvm();
  const out: SageCoinWithKey[] = [];
  for (const entry of raw) {
    if (!entry?.coin) continue;
    if (BigInt(entry.coin.amount) < minAmount) continue;
    if (!includeLocked && entry.locked) continue;
    if (!entry.puzzle) continue;
    let pk: string | null = null;
    try {
      const puzzleBytes = hexToBytes(entry.puzzle);
      pk = extractCatInnerSyntheticPk(clvm as never, puzzleBytes);
    } catch {
      pk = null;
    }
    if (!pk) continue;
    out.push({
      coin: {
        parent_coin_info: entry.coin.parent_coin_info,
        puzzle_hash: entry.coin.puzzle_hash,
        amount: Number(entry.coin.amount),
      },
      syntheticPkHex: pk,
      puzzleRevealHex: entry.puzzle,
      lineageProof: entry.lineageProof,
      locked: entry.locked,
    });
  }
  return out;
}
