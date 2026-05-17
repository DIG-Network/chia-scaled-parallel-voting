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
 *
 * Curry fields (vote_threshold_num/den, registration_*_snapshot) are
 * recovered from the launcher second-spend's BallotLauncherMemo
 * (Option A — chain-readable curry). They are `null` for legacy
 * ballots minted before the memo was added (pre-CHIP rev
 * 2026-05-07); cross-browser observers should fall back to the
 * sessionStorage bootstrap in that case.
 */
export interface BallotCoinSnapshot {
  ballot_launcher_id: string;
  election_launcher_id: string;
  vote_close_height: number;
  outcome_domain_hash: string;
  state: BallotState;
  coin_id: string;
  vote_threshold_num: number | null;
  vote_threshold_den: number | null;
  registration_merkle_root_snapshot: string | null;
  registration_vote_weight_snapshot: number | null;
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

// ============================================================================
// Ceremony wrappers
// ============================================================================
//
// The Ceremony Singleton API replaces `runSingleParticipantCeremony`
// with a multi-participant on-chain trusted setup. /create deploys
// the ceremony; /ceremony lets anyone contribute; once the window
// closes and `min_participants` is met, /create's "Deploy election"
// step derives the VK from the chain-walked contributions.

/** Per-ceremony deployment params (shape mirrors the wasm export). */
export interface CeremonyParams {
  startBlockHeight: number;
  ceremonyLengthBlocks: number;
  minParticipants: number;
  /**
   * Maximum voters this ceremony's circuit / VK supports. Determines
   * `tree_depth = ceil(log2(maxVoters))` for the Groth16 circuit and
   * for the election singleton's curry. Default 20_000.
   */
  maxVoters: number;
  vkSeedHex: string;
  label?: string;
}

/** Coin record shape passed to wasm — matches existing `JsCoinRecord`. */
export interface CoinRecordJs {
  parentCoinInfoHex: string;
  puzzleHashHex: string;
  amount: number;
}

/** Lineage proof — Eve for the singleton's first spend, Lineage thereafter. */
export type LineageProofJs =
  | {
      kind: "eve";
      parentParentCoinInfoHex: string;
      parentAmount: number;
    }
  | {
      kind: "lineage";
      parentParentCoinInfoHex: string;
      parentInnerPuzzleHashHex: string;
      parentAmount: number;
    };

/** Singleton tip + state needed for a contribute spend. */
export interface CeremonySingletonState {
  coin: CoinRecordJs;
  lineageProof: LineageProofJs;
  state: {
    contributionCount: number;
    lastContributionHashHex: string;
  };
}

/** Per-contribution input shape. */
export interface CeremonyContributionInput {
  participantPkHex: string;
  contributionHashHex: string;
  prevContributionHashHex: string;
  /**
   * Raw 32-byte τ entropy hex. Embedded in the marker coin's memos
   * (post-B1) so chain-walkers can recover the contribution directly
   * via `coin_records_by_hint(launcher_id)`.
   */
  entropyHex: string;
  payloadHex: string;
}

/** Build the Ceremony Singleton genesis spend bundle. */
export async function deployCeremonyBundle(
  params: CeremonyParams,
  parentCoin: CoinRecordJs,
  funderPkHex: string
): Promise<{ coinSpendsBytes: Uint8Array; launcherIdHex: string }> {
  const wasm = await getWasm();
  const result = wasm.deployCeremonyBundle(
    params as unknown as object,
    parentCoin as unknown as object,
    funderPkHex
  ) as { coinSpendsBytes: Uint8Array; launcherIdHex: string };
  return result;
}

/** Build the spend bundle for a single ceremony contribution. */
export async function contributeToCeremony(
  ceremony: CeremonyParams & { launcherIdHex: string },
  singleton: CeremonySingletonState,
  funderCoin: CoinRecordJs,
  funderPkHex: string,
  contribution: CeremonyContributionInput
): Promise<{
  coinSpendsBytes: Uint8Array;
  signatureMsgHex: string;
  markerCoinIdHex: string;
}> {
  const wasm = await getWasm();
  // `serde_wasm_bindgen::to_value` returns a JS `Map` for JSON
  // objects (not a plain object) — same shape gotcha as
  // `deployCeremonyBundle`. Normalize so callers can use dot-access.
  const raw = wasm.contributeToCeremony(
    ceremony as unknown as object,
    singleton as unknown as object,
    funderCoin as unknown as object,
    funderPkHex,
    contribution as unknown as object
  );
  const result = (
    raw instanceof Map ? Object.fromEntries(raw) : raw
  ) as {
    coinSpendsBytes: Uint8Array;
    signatureMsgHex: string;
    markerCoinIdHex: string;
  };
  return result;
}

/** Chain-walked contribution record — JS-collected, passed back to wasm gates. */
export interface CeremonyContributionRecord {
  participantPkHex: string;
  contributionHashHex: string;
  prevContributionHashHex: string;
  coinIdHex: string;
  blockHeight: number;
  entropyHex?: string;
  payloadHex?: string;
}

/**
 * Derive the BLS G1 public key (48-byte hex) from a 32-byte seed
 * (random bytes from `crypto.getRandomValues`). Used by ceremony
 * participants to populate the contribute action's curry args
 * locally; the matching SK stays in browser memory only.
 */
export async function publicKeyFromSecretKeyBytes(
  secretKeyHex: string
): Promise<string> {
  const wasm = await getWasm();
  return wasm.publicKeyFromSecretKeyBytes(secretKeyHex);
}

/**
 * BLS-sign an UNAUGMENTED 32-byte message with a JS-supplied 32-byte
 * secret key seed. Used by ceremony participants to satisfy the
 * contribute action's AGG_SIG_UNSAFE condition; the participant key
 * is generated locally per-contribution (not via Sage).
 */
export async function signParticipantUnsafe(
  secretKeyHex: string,
  messageHex: string
): Promise<string> {
  const wasm = await getWasm();
  return wasm.signParticipantUnsafe(secretKeyHex, messageHex);
}

/**
 * Aggregate N×96-byte BLS G2 signatures (concatenated hex) into a
 * single 96-byte signature. Wraps `chia_bls::aggregate`. Used to
 * combine the funder's Sage-signed AGG_SIG_ME with the participant's
 * locally-signed AGG_SIG_UNSAFE for the bundle signature.
 */
export async function aggregateSignaturesG2(
  sigsConcatHex: string
): Promise<string> {
  const wasm = await getWasm();
  return wasm.aggregateSignaturesG2(sigsConcatHex);
}

/**
 * Result of `findCurrentCeremonySingleton` — the unspent tip + the
 * lineage proof + curried state needed to build the next contribute
 * spend.
 */
export interface CeremonySingletonTip {
  launcherIdHex: string;
  coinIdHex: string;
  coin: { parentCoinInfoHex: string; puzzleHashHex: string; amount: number };
  lineageProof: LineageProofJs;
  state: {
    contributionCount: number;
    lastContributionHashHex: string;
    /** Post-D1 ceremony state finalize flag. */
    finalized: boolean;
    /** Post-D1: sha256 of derived VK bytes, set at finalize time. 0x00…00 pre-finalize. */
    vkHashHex: string;
    /** Post-D1: merkle root over sorted contribution marker coin ids, set at finalize. 0x00…00 pre-finalize. */
    markerRootHex: string;
  };
}

/** Chain-walk to the singleton's unspent tip, returning state + lineage proof. */
export async function findCurrentCeremonySingleton(
  launcherIdHex: string,
  vkSeedHex: string
): Promise<CeremonySingletonTip> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = await wasm.findCurrentCeremonySingleton(
    backend as unknown as object,
    launcherIdHex,
    vkSeedHex
  );
  return JSON.parse(json) as CeremonySingletonTip;
}

/**
 * Result of `recoverCeremonyBootstrap` — the ceremony's deploy-time
 * params recovered from chain (post-D6) so a fresh browser session
 * with no localStorage can populate /ceremony from the URL alone.
 * Returns `null` for legacy ceremonies deployed before D6 (the
 * launcher's `key_value_list` is empty for those).
 */
export interface CeremonyBootstrapFromChain {
  startBlockHeight: number;
  ceremonyLengthBlocks: number;
  minParticipants: number;
  maxVoters: number;
  vkSeedHex: string;
  label: string | null;
}

/** Cross-browser bootstrap recovery — reads the launcher's memo from chain. */
export async function recoverCeremonyBootstrap(
  launcherIdHex: string
): Promise<CeremonyBootstrapFromChain | null> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = (await wasm.recoverCeremonyBootstrap(
    backend as unknown as object,
    launcherIdHex
  )) as string | null;
  if (!json) return null;
  return JSON.parse(json) as CeremonyBootstrapFromChain;
}

/**
 * V10: locate the unspent voucher coin spawned by a finalized ceremony.
 * Returns the parent_coin_info + amount the dApp needs to thread into
 * `deployElectionBundle` for the V7 linked-deploy path. Returns `null`
 * when no unspent voucher exists at the predicted puzzle hash (ceremony
 * not yet finalized, or the voucher hasn't been re-created).
 */
export interface CeremonyVoucherCoin {
  parentCoinIdHex: string;
  amount: number;
}
export async function findCeremonyVoucherCoin(
  launcherIdHex: string,
  vkHashHex: string,
  maxVoters: number
): Promise<CeremonyVoucherCoin | null> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const raw = (await wasm.findCeremonyVoucherCoin(
    backend as unknown as object,
    launcherIdHex,
    vkHashHex,
    BigInt(maxVoters)
  )) as unknown;
  if (raw == null) return null;
  // serde_wasm_bindgen serializes JSON objects as JS Maps; normalize.
  const obj = (raw instanceof Map ? Object.fromEntries(raw) : raw) as {
    parentCoinIdHex: string;
    amount: number;
  };
  return {
    parentCoinIdHex: obj.parentCoinIdHex,
    amount: Number(obj.amount),
  };
}

/** Chain-walk every accepted contribution for the ceremony singleton at `launcherIdHex`. */
export async function listCeremonyContributions(
  launcherIdHex: string
): Promise<CeremonyContributionRecord[]> {
  const wasm = await getWasm();
  const backend = createChainBackend();
  const json = await wasm.listCeremonyContributions(
    backend as unknown as object,
    launcherIdHex
  );
  return JSON.parse(json) as CeremonyContributionRecord[];
}

/** Validate a chain-walked contribution sequence (lineage + threshold). */
export async function validateCeremonyContributions(
  contributions: CeremonyContributionRecord[],
  vkSeedHex: string,
  minParticipants: number
): Promise<{ ok: true; count: number }> {
  const wasm = await getWasm();
  const result = wasm.validateCeremonyContributions(
    contributions as unknown as object,
    vkSeedHex,
    BigInt(minParticipants)
  ) as { ok: true; count: number };
  return result;
}

/**
 * Derive the final VK from chain-walked contributions. Currently
 * surfaces a "bridge pending Phase 5" error after gates pass; the
 * dApp UI gates "Deploy election" on this throwing nothing.
 */
export async function deriveVkFromCeremony(
  contributions: CeremonyContributionRecord[],
  vkSeedHex: string,
  minParticipants: number
): Promise<{ rawBytes: Uint8Array }> {
  const wasm = await getWasm();
  const raw = wasm.deriveVkFromCeremony(
    contributions as unknown as object,
    vkSeedHex,
    BigInt(minParticipants)
  );
  // serde_wasm_bindgen::to_value serializes JSON objects as JS Maps;
  // normalize to a plain object so callers can use dot-access.
  // VK bytes arrive as `Array<number>` because Vec<u8> goes through
  // serde_json::Value::Array; coerce back to Uint8Array.
  const obj = (raw instanceof Map ? Object.fromEntries(raw) : raw) as {
    rawBytes: number[] | Uint8Array;
  };
  const rawBytes =
    obj.rawBytes instanceof Uint8Array
      ? obj.rawBytes
      : new Uint8Array(obj.rawBytes);
  return { rawBytes };
}
