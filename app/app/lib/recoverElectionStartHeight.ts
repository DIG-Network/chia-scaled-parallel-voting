// ----------------------------------------------------------------------------
// recoverElectionStartHeight.ts — chain-derive electionStartHeight + persist
// ----------------------------------------------------------------------------
//
// Mirrors live_integration.mjs:recoverElectionStartHeightOrFail. The dApp
// uses this in place of trusting `bootstrap.electionStartHeight` directly:
// the bootstrap becomes a write-cache for the chain-derived value, never a
// source-of-truth read. wasm.recoverElectionStartHeight walks a ±60 block
// window of candidate heights against the launcher's confirmed eve_ph, so
// the bootstrap value is no longer load-bearing once the launcher is on
// chain.
//
// Returns the verified height as a number, or null when the launcher
// isn't yet confirmed (call again later) or no candidate matches in the
// window (likely SDK / puzzle revision mismatch — surface to operator).
//
// Side effect: when the chain-derived value differs from the cached
// bootstrap value, the bootstrap is rewritten so all downstream readers
// pick up the corrected value automatically.

import { getWasm } from "./sdk";
import { createChainBackend } from "./chainBackend";
import {
  type ElectionBootstrap,
  readElectionBootstrap,
  writeElectionBootstrap,
} from "./electionBootstrap";

export async function recoverAndPersistElectionStartHeight(
  launcherIdHex: string,
  configJson: string,
  windowBlocks = 60
): Promise<number | null> {
  const wasm = await getWasm();
  let recovered: unknown;
  try {
    recovered = await wasm.recoverElectionStartHeight(
      createChainBackend() as never,
      configJson,
      windowBlocks
    );
  } catch {
    return null;
  }
  if (recovered == null) return null;
  const num = typeof recovered === "number" ? recovered : Number(recovered);
  if (!Number.isFinite(num) || num <= 0) return null;
  const cur = readElectionBootstrap(launcherIdHex);
  if (cur && cur.electionStartHeight !== num) {
    const merged: ElectionBootstrap = { ...cur, electionStartHeight: num };
    writeElectionBootstrap(merged);
  }
  return num;
}
