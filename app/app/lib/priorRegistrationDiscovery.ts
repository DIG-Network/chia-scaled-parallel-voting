// ============================================================================
// priorRegistrationDiscovery.ts — find this Sage wallet's existing registration
// ============================================================================
//
// On a fresh browser / refresh / freshly imported share bundle the dApp doesn't
// know which of the user's synthetic keys (if any) already registered for
// this election. The chain knows: every register spend tags the new
// registration coin with `voter_hint = sha256(election_launcher || cat_tail
// || voter_pk)`. We page Sage's synthetic keys, compute each candidate's
// voter_hint, and query coinset's `get_coin_records_by_hint`. Any record
// (spent or unspent) means that pubkey already registered for this election.

import * as wasm from "chip-voting-wasm";
import walletConnect from "./walletConnectInstance";
import { coinRecordsByHint } from "./coinset";

const PAGE_SIZE = 100;
const MAX_SAFETY_KEY_LOOKUPS = 50_000;
const SCAN_GAP_MS = 80;

export type PriorRegistrationProgress =
  | { phase: "receive_key" }
  | { phase: "synthetic_keys"; keysChecked: number; sageOffset: number };

export type PriorRegistration = {
  /** Synthetic pubkey hex (`0x` + 96 lowercase hex). */
  syntheticPkHex: string;
  /** Voter hint that matched on-chain. */
  voterHintHex: string;
};

function normalizePk(hex: string): string | null {
  const raw = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(raw)) return null;
  return `0x${raw}`;
}

async function checkRegistration(
  pkHex: string,
  electionLauncherIdHex: string,
  catTailHashHex: string
): Promise<PriorRegistration | null> {
  const hintHex = wasm.voterHint(electionLauncherIdHex, catTailHashHex, pkHex);
  const records = await coinRecordsByHint(hintHex, true);
  if (records.length === 0) return null;
  return { syntheticPkHex: pkHex, voterHintHex: hintHex };
}

/**
 * Find the synthetic pubkey (if any) this Sage wallet has already used to
 * register for the given election. Returns `null` if no registration exists
 * across the keys Sage exposed (paged until exhaustion or safety cap).
 *
 * Returns ALL discovered registrations — wallets with multiple registrations
 * (e.g. accidental re-registration) get them all so the caller can decide.
 */
export async function discoverPriorRegistrations(opts: {
  electionLauncherIdHex: string;
  catTailHashHex: string;
  /** Try this key first (typically the connected receive address's synthetic pk). */
  preferredSyntheticPkHex?: string | null;
  /** Stop after the first hit. Default true. */
  stopOnFirst?: boolean;
  onProgress?: (p: PriorRegistrationProgress) => void;
}): Promise<PriorRegistration[]> {
  await walletConnect.waitForInit();

  const stopOnFirst = opts.stopOnFirst ?? true;
  const examined = new Set<string>();
  const found: PriorRegistration[] = [];

  if (opts.preferredSyntheticPkHex) {
    const pre = normalizePk(opts.preferredSyntheticPkHex);
    if (pre) {
      examined.add(pre);
      opts.onProgress?.({ phase: "receive_key" });
      const hit = await checkRegistration(
        pre,
        opts.electionLauncherIdHex,
        opts.catTailHashHex
      );
      if (hit) {
        found.push(hit);
        if (stopOnFirst) return found;
      }
    }
  }

  let walletQueries = 0;
  let sageOffset = 0;

  for (;;) {
    if (walletQueries >= MAX_SAFETY_KEY_LOOKUPS) break;
    const keys = await walletConnect.getPublicKeys(PAGE_SIZE, sageOffset);
    if (!keys || keys.length === 0) break;
    sageOffset += keys.length;

    for (const k of keys) {
      const norm = normalizePk(k);
      if (!norm || examined.has(norm)) continue;
      examined.add(norm);
      walletQueries += 1;
      opts.onProgress?.({
        phase: "synthetic_keys",
        keysChecked: walletQueries,
        sageOffset,
      });

      const hit = await checkRegistration(
        norm,
        opts.electionLauncherIdHex,
        opts.catTailHashHex
      );
      if (hit) {
        found.push(hit);
        if (stopOnFirst) return found;
      }
      if (SCAN_GAP_MS > 0) {
        await new Promise((r) => setTimeout(r, SCAN_GAP_MS));
      }
    }

    if (keys.length < PAGE_SIZE) break;
  }

  return found;
}
