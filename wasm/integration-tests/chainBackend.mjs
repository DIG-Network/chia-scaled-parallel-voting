// ============================================================================
// chainBackend.mjs — implements `JsChainBackend` for Node.js + coinset.org
// ============================================================================
//
// The wasm crate's `JsChainReader` extern type expects a JS object
// exposing six methods (each returning a Promise). This file builds
// one against `coinset.mjs`. Mirrors `app/app/lib/chainBackend.ts`
// 1:1 — same shape, different transport (node fetch vs browser
// fetch, identical Promise contract).

import {
  coinRecordsByPuzzleHash,
  coinRecordsByHint,
  coinRecordByName,
  coinRecordsByParentIds,
  puzzleAndSolution,
  peakHeight,
} from "./coinset.mjs";

/**
 * Build a ChainBackend that proxies to coinset.org. Pass the
 * returned object directly into wasm exports that take a
 * `JsChainBackend` parameter.
 *
 * The wasm side calls each method via wasm-bindgen's extern-class
 * `method` import — the names below MUST match the
 * `#[wasm_bindgen(method, js_name = "..."]` attributes in
 * `wasm/src/lib.rs::SECTION 3`.
 */
export function createChainBackend({ verbose = false } = {}) {
  const log = verbose
    ? (op, ...args) => console.log(`[chainBackend] ${op}`, ...args)
    : () => {};

  return {
    async coinRecordsByPuzzleHash(phHex) {
      log("coinRecordsByPuzzleHash", phHex);
      const recs = await coinRecordsByPuzzleHash(phHex, false);
      log("→", recs.length, "records");
      return recs;
    },
    async coinRecordsByHint(hintHex) {
      log("coinRecordsByHint", hintHex);
      const recs = await coinRecordsByHint(hintHex, true);
      log("→", recs.length, "records");
      return recs;
    },
    async puzzleAndSolution(coinIdHex) {
      log("puzzleAndSolution", coinIdHex);
      const ps = await puzzleAndSolution(coinIdHex);
      log("→", ps ? "yes" : "null");
      return ps;
    },
    async coinRecordsByParentIds(parentIdsHex) {
      log("coinRecordsByParentIds", parentIdsHex.length, "ids");
      const recs = await coinRecordsByParentIds(parentIdsHex);
      log("→", recs.length, "records");
      return recs;
    },
    async coinRecordByName(coinIdHex) {
      log("coinRecordByName", coinIdHex);
      const rec = await coinRecordByName(coinIdHex);
      log("→", rec ? "found" : "null");
      return rec;
    },
    async peakHeight() {
      const h = await peakHeight();
      log("peakHeight →", h);
      return h;
    },
  };
}
