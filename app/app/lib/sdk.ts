// ============================================================================
// sdk.ts — lazy WASM loader + typed wrappers for `chip-voting-wasm`
// ============================================================================
//
// MODULE: lib/sdk
// PURPOSE: Centralise the dynamic-import pattern that loads the
//          `chip-voting-wasm` package, plus expose typed wrappers
//          around the chain-walking exports so call-sites don't
//          re-implement JSON marshalling.
//
// WHY LAZY: Next.js prerenders pages on the server. Importing the
// wasm package at module-top-level crashes the prerender pass with
// "WebAssembly.instantiate" / "ReferenceError: window is not
// defined" depending on the bundling stage. A `'use client'`
// directive plus a dynamic `await import(...)` inside an effect
// (or inside a `dynamic(..., {ssr: false})` factory) is the
// supported workflow.
//
// USAGE FROM A COMPONENT (preferred):
//
//   export default dynamic(
//     async function DynamicElem() {
//       const wasm = await getWasm();
//       return function MyComponent() { /* ... */ };
//     },
//     { ssr: false, loading: () => <Spinner /> }
//   );

import { createChainBackend } from "./chainBackend";

let cached: typeof import("chip-voting-wasm") | null = null;
let loading: Promise<typeof import("chip-voting-wasm")> | null = null;

/**
 * Lazily load (or return the cached) `chip-voting-wasm` module.
 * Safe to call from anywhere on the client; throws on the server
 * (you should be inside `'use client'` + an effect / handler).
 */
export async function getWasm(): Promise<typeof import("chip-voting-wasm")> {
  if (cached) return cached;
  if (loading) return loading;
  loading = (async () => {
    const wasm = await import("chip-voting-wasm");
    // `--target web`: `default()` async-instantiates `.wasm` before exports work.
    // `--target bundler` (our `wasm-pack build` default): WASM starts in the glue
    // entry — there is no `default` export.
    const d = wasm as { default?: unknown };
    if (typeof d.default === "function") {
      await (d.default as () => Promise<unknown>)();
    }
    wasm.init();
    cached = wasm;
    return wasm;
  })();
  return loading;
}

/** Re-export the WasmNetwork enum for convenient typed access. */
export type WasmModule = typeof import("chip-voting-wasm");

// ============================================================================
// Typed read-side wrappers
// ============================================================================
//
// All chain-walking exports return JSON-stringified data; these
// helpers parse to typed shapes so call-sites don't repeat
// `JSON.parse(...) as Foo`. Each wraps the chain backend in a
// fresh JsChainReader (the wasm side stores the JsChainBackend
// handle internally).

/**
 * BallotState carried inside a [`BallotCoinSnapshot`]. Mirrors
 * `chip_voting_sdk::state::BallotState`.
 *
 * - `finalized`: 0 = not finalized, 1 = finalized.
 * - `vote_outcome`: the canonical 32-byte outcome (only meaningful
 *   post-finalize; pre-finalize this is the zero hash).
 * - `agg_signers`: SHA-256 of the aggregated voter pubkey set
 *   (post-finalize; zero pre-finalize).
 */
export interface BallotState {
  finalized: number;
  vote_outcome: string;
  agg_signers: string;
}

/**
 * BallotCoinSnapshot returned by `listBallots` / `getBallot`.
 * Hex strings are 0x-prefixed (chia-protocol Bytes32 serde
 * convention).
 */
export interface BallotCoinSnapshot {
  ballot_launcher_id: string;
  election_launcher_id: string;
  vote_close_height: number;
  outcome_domain_hash: string;
  state: BallotState;
  coin_id: string;
}

/**
 * VoteRecordWire from `collectVotesForBallot`. Mirrors
 * `chip_voting_sdk::state::VoteRecordWire`.
 */
export interface VoteRecordWire {
  voter_pubkey_hex: string;
  vote_data_hex: string;
  vote_signature_hex: string;
  registration_coin_id_hex: string;
  ballot_launcher_id_hex: string;
  voting_coin_id_hex: string;
}

/** Walk the Election Singleton lineage and list every Ballot Coin. */
export async function listBallots(
  configJson: string
): Promise<BallotCoinSnapshot[]> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = await wasm.listBallots(backend as unknown as object, configJson);
  return JSON.parse(json) as BallotCoinSnapshot[];
}

/** Look up a single Ballot Coin by its launcher id; null if not found. */
export async function getBallot(
  configJson: string,
  ballotLauncherIdHex: string
): Promise<BallotCoinSnapshot | null> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = await wasm.getBallot(
    backend as unknown as object,
    configJson,
    ballotLauncherIdHex
  );
  const parsed = JSON.parse(json) as BallotCoinSnapshot | null;
  return parsed;
}

/** Collect every Voting Coin targeting `ballotLauncherIdHex`. */
export async function collectVotesForBallot(
  configJson: string,
  ballotLauncherIdHex: string,
  voterPubkeysHex: string[]
): Promise<VoteRecordWire[]> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = await wasm.collectVotesForBallot(
    backend as unknown as object,
    configJson,
    ballotLauncherIdHex,
    JSON.stringify(voterPubkeysHex)
  );
  return JSON.parse(json) as VoteRecordWire[];
}
