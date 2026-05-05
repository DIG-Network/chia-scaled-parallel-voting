// ============================================================================
// chainBackend.ts — JsChainBackend wired to coinset.org HTTP
// ============================================================================
//
// MODULE: lib/chainBackend
// PURPOSE: Build the JS object the wasm module's `JsChainBackend`
//          interface expects. All six methods proxy to the
//          existing `coinset.ts` HTTP client.
//
// USAGE:
//   const backend = createChainBackend();
//   const wasm = await getWasm();
//   const result = await wasm.findCurrentSingleton(backend, configJson);

import {
  coinRecordsByPuzzleHash,
  coinRecordsByHint,
  coinRecordByName,
  coinRecordsByParentIds,
  puzzleAndSolution,
  peakHeight,
  CoinRecord,
} from "./coinset";

/**
 * Shape of the JS object the wasm `JsChainBackend` extern type
 * expects. Method names and signatures must match the
 * `#[wasm_bindgen(method, js_name = "...")]` attributes on the
 * Rust side (see `wasm/src/lib.rs`, "SECTION 2 — Chain backend
 * interface").
 */
export interface ChainBackend {
  coinRecordsByPuzzleHash(phHex: string): Promise<JsCoinRecord[]>;
  coinRecordsByHint(hintHex: string): Promise<JsCoinRecord[]>;
  puzzleAndSolution(coinIdHex: string): Promise<JsPuzzleSolution | null>;
  coinRecordsByParentIds(parentIdsHex: string[]): Promise<JsCoinRecord[]>;
  coinRecordByName(coinIdHex: string): Promise<JsCoinRecord | null>;
  peakHeight(): Promise<number | null>;
}

/** What the wasm side decodes via `serde_wasm_bindgen` — camelCase. */
export interface JsCoinRecord {
  parentCoinInfo: string;
  puzzleHash: string;
  amount: number;
  spentHeight: number;
  confirmedHeight: number;
}

export interface JsPuzzleSolution {
  puzzleHex: string;
  solutionHex: string;
}

function mapRecord(r: CoinRecord): JsCoinRecord {
  return {
    parentCoinInfo: r.parentCoinInfo,
    puzzleHash: r.puzzleHash,
    amount: r.amount,
    spentHeight: r.spentHeight,
    confirmedHeight: r.confirmedHeight,
  };
}

/** Build a ChainBackend that proxies to coinset.org. */
export function createChainBackend(): ChainBackend {
  return {
    coinRecordsByPuzzleHash: async (phHex) =>
      (await coinRecordsByPuzzleHash(phHex, false)).map(mapRecord),
    coinRecordsByHint: async (hintHex) =>
      (await coinRecordsByHint(hintHex, true)).map(mapRecord),
    puzzleAndSolution: async (coinIdHex) => {
      const r = await puzzleAndSolution(coinIdHex);
      return r ? { puzzleHex: r.puzzleHex, solutionHex: r.solutionHex } : null;
    },
    coinRecordsByParentIds: async (parentIdsHex) =>
      (await coinRecordsByParentIds(parentIdsHex)).map(mapRecord),
    coinRecordByName: async (coinIdHex) => {
      const r = await coinRecordByName(coinIdHex);
      return r ? mapRecord(r) : null;
    },
    peakHeight: async () => await peakHeight(),
  };
}
