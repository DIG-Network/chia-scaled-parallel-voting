// ============================================================================
// coinset.ts — JS-side chain access (HTTP fetch to api.coinset.org)
// ============================================================================
//
// MODULE: lib/coinset
// PURPOSE: The CHIP SDK is a hard boundary — it never opens a chain
//          client. The dApp does its own chain reads here, then
//          passes the resolved coins / records into wasm helpers
//          (`buildDeployBundle`, `signCoinSpends`, etc.) for
//          assembly + signing.
//
// TRANSPORT: `https://api.coinset.org` is the canonically-synced
// public Chia full-node REST endpoint maintained by the coinset.org
// team. Sage Wallet's WC interface does NOT expose chain-read RPCs
// (it's an "active-key wallet", not an explorer), so we fetch
// directly. dApps wanting a private mirror can override
// `COINSET_BASE_URL` with `NEXT_PUBLIC_COINSET_BASE_URL`.
//
// SHAPES: every record returned matches the `JsCoinRecord` /
// `JsPuzzleSolution` types the wasm `JsChainBackend` expects,
// so this module can be used directly to wire a `JsChainReader`
// in wasm if/when we add chain-touching wasm wrappers.

// `??` ONLY catches `undefined` / `null` — NOT empty strings.
// `.env.local` keys with no value (`NEXT_PUBLIC_COINSET_BASE_URL=`)
// surface as `""` here, which would silently turn every chain
// query into a request against the dApp's own origin (404 from
// the static-export server). Use `|| trim()` to fall back on
// any falsy / whitespace-only value.
const COINSET_BASE_URL =
  process.env.NEXT_PUBLIC_COINSET_BASE_URL?.trim() ||
  "https://api.coinset.org";

/**
 * TTL (ms) for **read-only** coinset POSTs (`get_coin_records_*`, peak, etc.).
 * Coalesces bursty callers (lifecycle tick + wallet bar + WASM sync) into
 * at most one in-flight request per cache key — same key within the window
 * returns the memoized result without another round-trip.
 * Set `NEXT_PUBLIC_COINSET_READ_CACHE_MS=0` to disable.
 */
const READ_CACHE_TTL_MS = Math.max(
  0,
  Number(process.env.NEXT_PUBLIC_COINSET_READ_CACHE_MS ?? "5000")
);

type CacheBucket<T> = { expiry: number; value: T };
const readValueCache = new Map<string, CacheBucket<unknown>>();
const readInflight = new Map<string, Promise<unknown>>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withReadDedupe<T>(
  key: string,
  producer: () => Promise<T>
): Promise<T> {
  if (READ_CACHE_TTL_MS <= 0) {
    return producer();
  }
  const now = Date.now();
  const stale = readValueCache.get(key);
  if (stale !== undefined && stale.expiry > now) {
    return stale.value as T;
  }

  const existing = readInflight.get(key) as Promise<T> | undefined;
  if (existing) {
    return existing;
  }

  const pending = producer()
    .then((value) => {
      readInflight.delete(key);
      readValueCache.set(key, {
        expiry: Date.now() + READ_CACHE_TTL_MS,
        value,
      });
      return value;
    })
    .catch((e) => {
      readInflight.delete(key);
      throw e;
    });
  readInflight.set(key, pending);
  return pending;
}

async function pacedProducer<T>(
  producer: () => Promise<T>
): Promise<T> {
  const gap = Math.max(
    0,
    Number(process.env.NEXT_PUBLIC_COINSET_MIN_GAP_MS ?? "0")
  );
  if (gap <= 0) {
    return producer();
  }
  await sleep(gap);
  return producer();
}

/**
 * Coin record matching the wasm `JsCoinRecord` shape (camelCase
 * over the wire because that's what `serde-wasm-bindgen` decodes).
 * Mojo amounts come back as strings from coinset.org but we coerce
 * to numbers (Chia mojos fit in u53 for any realistic amount).
 */
export interface CoinRecord {
  parentCoinInfo: string; // hex with `0x` prefix
  puzzleHash: string; // hex with `0x` prefix
  amount: number;
  spentHeight: number;
  confirmedHeight: number;
}

export interface PuzzleSolution {
  puzzleHex: string;
  solutionHex: string;
}

/** Strip `0x` prefix and lowercase. */
function stripHex(s: string): string {
  return s.toLowerCase().replace(/^0x/, "");
}

/** Add `0x` prefix if missing. */
function withPrefix(s: string): string {
  return s.startsWith("0x") ? s : "0x" + s;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${COINSET_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    throw new Error(`${path}: HTTP ${r.status}`);
  }
  return (await r.json()) as T;
}

async function postJsonUncachedReads<T>(
  path: string,
  body: unknown,
  dedupeKey: string | null
): Promise<T> {
  const run = () => postJson<T>(path, body);
  if (dedupeKey === null || READ_CACHE_TTL_MS <= 0) {
    return pacedProducer(run);
  }
  const key = `${path}\u0001${dedupeKey}`;
  return withReadDedupe(key, () => pacedProducer(run));
}

interface RawCoin {
  parent_coin_info: string;
  puzzle_hash: string;
  amount: number;
}
interface RawCoinRecord {
  coin: RawCoin;
  spent_block_index: number;
  confirmed_block_index: number;
  spent: boolean;
  coinbase: boolean;
  timestamp: number;
}

function adapt(r: RawCoinRecord): CoinRecord {
  return {
    parentCoinInfo: withPrefix(r.coin.parent_coin_info),
    puzzleHash: withPrefix(r.coin.puzzle_hash),
    amount: Number(r.coin.amount),
    spentHeight: r.spent_block_index,
    confirmedHeight: r.confirmed_block_index,
  };
}

/** Get all coin records (default unspent only) at a puzzle hash. */
export async function coinRecordsByPuzzleHash(
  puzzleHash: string,
  includeSpent = false
): Promise<CoinRecord[]> {
  const ph = withPrefix(puzzleHash);
  const dk = `${stripHex(ph)}|spent=${includeSpent ? "1" : "0"}`;
  const r = await postJsonUncachedReads<{ coin_records: RawCoinRecord[] }>(
    "/get_coin_records_by_puzzle_hash",
    { puzzle_hash: ph, include_spent_coins: includeSpent },
    dk
  );
  return (r.coin_records ?? []).map(adapt);
}

/** Get all coin records (spent + unspent) hinted by a 32-byte hint. */
export async function coinRecordsByHint(
  hint: string,
  includeSpent = true
): Promise<CoinRecord[]> {
  const h = withPrefix(hint);
  const dk = `${stripHex(h)}|spent=${includeSpent ? "1" : "0"}`;
  const r = await postJsonUncachedReads<{ coin_records: RawCoinRecord[] }>(
    "/get_coin_records_by_hint",
    { hint: h, include_spent_coins: includeSpent },
    dk
  );
  return (r.coin_records ?? []).map(adapt);
}

/** Get a single coin record by id. Returns null if not on-chain. */
export async function coinRecordByName(
  coinId: string
): Promise<CoinRecord | null> {
  try {
    const nm = withPrefix(coinId);
    const dk = stripHex(nm);
    const r = await postJsonUncachedReads<{
      coin_record: RawCoinRecord | null;
    }>("/get_coin_record_by_name", { name: nm }, dk);
    return r.coin_record ? adapt(r.coin_record) : null;
  } catch {
    return null;
  }
}

/** Get a coin's puzzle reveal + solution (only if spent). */
export async function puzzleAndSolution(
  coinId: string,
  height?: number
): Promise<PuzzleSolution | null> {
  try {
    const cid = withPrefix(coinId);
    const dk = `${stripHex(cid)}|h=${height ?? "null"}`;
    const r = await postJsonUncachedReads<{
      coin_solution: { puzzle_reveal: string; solution: string } | null;
    }>(
      "/get_puzzle_and_solution",
      {
        coin_id: cid,
        height: height ?? null,
      },
      dk
    );
    if (!r.coin_solution) return null;
    return {
      puzzleHex: withPrefix(r.coin_solution.puzzle_reveal),
      solutionHex: withPrefix(r.coin_solution.solution),
    };
  } catch {
    return null;
  }
}

/** Get every coin spawned by any of `parent_ids` (spent + unspent). */
export async function coinRecordsByParentIds(
  parentIds: string[]
): Promise<CoinRecord[]> {
  if (parentIds.length === 0) return [];
  const sorted = [...parentIds].sort();
  const ids = sorted.map(withPrefix);
  const dk = sorted.map(stripHex).join(",");
  const r = await postJsonUncachedReads<{ coin_records: RawCoinRecord[] }>(
    "/get_coin_records_by_parent_ids",
    {
      parent_ids: ids,
      include_spent_coins: true,
    },
    dk
  );
  return (r.coin_records ?? []).map(adapt);
}

/** Current chain peak height. */
export async function peakHeight(): Promise<number | null> {
  try {
    const r = await postJsonUncachedReads<{
      blockchain_state: { peak: { height: number } | null };
    }>("/get_blockchain_state", {}, "peak");
    return r.blockchain_state?.peak?.height ?? null;
  } catch {
    return null;
  }
}

/** JSON shape Sage / chia full-node `push_tx` expects. */
export interface SpendBundleJson {
  coin_spends: {
    coin: { parent_coin_info: string; puzzle_hash: string; amount: number };
    puzzle_reveal: string;
    solution: string;
  }[];
  aggregated_signature: string;
}

/** Coinset / chia full-node `/push_tx` response shape (after normalization). */
interface PushTxResponse {
  /** True iff the bundle was accepted into the mempool. */
  success: boolean;
  /** Human-readable error string when `success === false`. */
  error?: string;
  /** Structured error envelope (when present, more useful than `error`). */
  structuredError?: {
    code: string;
    data?: { error?: string; spend_name?: string };
    message: string;
  };
  /** Some forks of the API also return a chia-compat status string. */
  status?: string;
}

/** Map coinset/full-node `/push_tx` JSON (camelCase + snake_case) into our shape. */
function normalizePushTxPayload(rawUnknown: unknown): PushTxResponse {
  const raw =
    typeof rawUnknown === "object" && rawUnknown !== null && !Array.isArray(rawUnknown)
      ? (rawUnknown as Record<string, unknown>)
      : {};

  /** APIs sometimes omit `success` or send loosely-typed flags. Default false unless clearly true. */
  const inferredSuccess =
    raw.success === true ||
    raw.success === 1 ||
    String(raw.success).toLowerCase() === "true";

  let structuredError: PushTxResponse["structuredError"];
  const seCandidate = raw.structuredError ?? raw.structured_error;
  if (
    typeof seCandidate === "object" &&
    seCandidate !== null &&
    !Array.isArray(seCandidate)
  ) {
    const se = seCandidate as Record<string, unknown>;
    let dataObj: { error?: string; spend_name?: string } | undefined;
    const d = se.data;
    if (typeof d === "object" && d !== null && !Array.isArray(d)) {
      const dd = d as Record<string, unknown>;
      const innerErr =
        typeof dd.error === "string"
          ? dd.error
          : typeof dd.detail === "string"
            ? dd.detail
            : undefined;
      const innerSpend =
        typeof dd.spend_name === "string"
          ? dd.spend_name
          : typeof (dd as { spendName?: unknown }).spendName === "string"
            ? (dd as { spendName: string }).spendName
            : undefined;
      dataObj =
        innerErr || innerSpend
          ? {
              ...(innerErr ? { error: innerErr } : {}),
              ...(innerSpend ? { spend_name: innerSpend } : {}),
            }
          : undefined;
    }
    structuredError = {
      code: typeof se.code === "string" ? se.code : "UNKNOWN",
      message: typeof se.message === "string" ? se.message : "",
      ...(dataObj ? { data: dataObj } : {}),
    };
  }

  const error =
    typeof raw.error === "string"
      ? raw.error
      : typeof raw.detail === "string"
        ? raw.detail
        : undefined;
  const status = typeof raw.status === "string" ? raw.status : undefined;

  return {
    success: Boolean(inferredSuccess),
    ...(error ? { error } : {}),
    ...(structuredError ? { structuredError } : {}),
    ...(status ? { status } : {}),
  };
}

function transactionAlreadyQueued(
  r: PushTxResponse,
  fullSerializedUpper?: string
): boolean {
  const code = r.structuredError?.data?.error?.trim().toUpperCase();
  if (code === "ALREADY_INCLUDING_TRANSACTION") {
    return true;
  }
  const blob = `${r.error ?? ""} ${r.status ?? ""} ${r.structuredError?.message ?? ""} ${JSON.stringify(r.structuredError?.data ?? {})}`;
  if (blob.includes("ALREADY_INCLUDING_TRANSACTION")) {
    return true;
  }
  return (
    !!fullSerializedUpper &&
    fullSerializedUpper.includes("ALREADY_INCLUDING_TRANSACTION")
  );
}

/**
 * Coinset/Chia occasionally returns HTTP 200 with `success: true` while
 * `status` or `error` still describes mempool rejection — treat those as failures.
 */
function mempoolRejectDetailFromContradiction(r: PushTxResponse): string | null {
  const errTrim = (r.error ?? "").trim();
  const st = (r.status ?? "").trim().toUpperCase();
  const dataErr = r.structuredError?.data?.error?.trim() ?? "";

  if (dataErr.toUpperCase() === "ALREADY_INCLUDING_TRANSACTION") {
    return null;
  }

  const okStatuses = new Set(["SUCCESS", "PENDING", ""]);
  const statusContradicts =
    st.length > 0 &&
    !okStatuses.has(st) &&
    !st.includes("ALREADY_INCLUDING_TRANSACTION");

  if (errTrim.length > 0) {
    return dataErr ? `${dataErr}: ${errTrim}` : errTrim;
  }
  if (dataErr.length > 0) {
    return dataErr;
  }
  if (statusContradicts) {
    return r.status ?? null;
  }
  return null;
}

/**
 * Push a signed spend bundle to the mempool via coinset.org.
 *
 * Returns the resolved status string:
 *   * `SUCCESS` — bundle accepted
 *   * `ALREADY_INCLUDING_TRANSACTION` — duplicate submit; mempool
 *     already holds this bundle (not an error — same as chia CLI
 *     treating transient duplicate push as OK)
 *   * `PENDING` — accepted, waiting on something
 *
 * Other failures throw with `/push_tx rejected: …` so the caller can
 * surface detail. SpendBundle JSON must be `{coin_spends,
 * aggregated_signature}` — raw bytes / hex get INVALID_SPEND_BUNDLE.
 */
export async function pushTx(spendBundle: SpendBundleJson): Promise<string> {
  const rawUnknown = await postJson<unknown>("/push_tx", {
    spend_bundle: spendBundle,
  });

  const fullSerialized =
    typeof rawUnknown === "object" && rawUnknown !== null
      ? JSON.stringify(rawUnknown)
      : String(rawUnknown);
  const fullUpper = fullSerialized.toUpperCase();

  const r = normalizePushTxPayload(rawUnknown);

  if (transactionAlreadyQueued(r, fullUpper)) {
    return "ALREADY_INCLUDING_TRANSACTION";
  }

  if (r.success) {
    const contradiction = mempoolRejectDetailFromContradiction(r);
    const embeddedFail =
      fullUpper.includes("MINTING_COIN") ||
      fullUpper.includes("DOUBLE_SPEND") ||
      (/\bTRANSACTION_FAILED\b/.test(fullUpper) &&
        !fullUpper.includes("ALREADY_INCLUDING_TRANSACTION"));

    const hint =
      !contradiction && embeddedFail
        ? extractRejectHint(fullUpper, r)
        : null;
    const detail = contradiction ?? hint;

    if (detail && detail.trim().length > 0) {
      throw new Error(`/push_tx rejected: ${detail}`);
    }
    return r.status ?? "SUCCESS";
  }

  // Surface as much detail as the server gave us (success=false).
  const detail =
    r.structuredError?.data?.error ??
    r.error ??
    r.structuredError?.message ??
    extractRejectHint(fullUpper, r) ??
    "unknown error (server returned success=false with no detail)";
  throw new Error(`/push_tx rejected: ${detail}`);
}

/** Best-effort detail when failure markers only appear deep in the JSON (e.g. traceback). */
function extractRejectHint(fullUpper: string, r: PushTxResponse): string | null {
  const m = fullUpper.match(/MINTING_COIN|DOUBLE_SPEND|INVALID_SPEND_BUNDLE/);
  if (m?.[0]) return m[0];
  const st = r.status?.trim();
  if (st?.length) return st;
  return null;
}

/**
 * Mempool transient rejects — rebuild the bundle after a pause (alternate
 * launcher parents, CAT UTXOs, etc.). Wallet declines are not retryable.
 */
export function isConsensusRetriablePushError(err: unknown): boolean {
  const raw = String(err instanceof Error ? err.message : err);
  if (/wallet\s+declined|user\s+reject|prompt\s+(was\s+)?dismissed/i.test(raw)) {
    return false;
  }
  const m = raw.toUpperCase();
  return (
    m.includes("MINTING_COIN") ||
    m.includes("DOUBLE_SPEND") ||
    m.includes("MEMPOOL_CONFLICT") ||
    m.includes("CONCURRENT_SPEND") ||
    m.includes("ASSERT_CONCURRENT_SPEND") ||
    m.includes("ERR_OCCUPIED") ||
    m.includes("OCCUPIED")
  );
}

export { COINSET_BASE_URL, withPrefix, stripHex };
