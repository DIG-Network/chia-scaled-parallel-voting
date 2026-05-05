// ============================================================================
// coinset.mjs — minimal Node.js HTTP client for api.coinset.org
// ============================================================================
//
// Mirrors the Rust live test's chain access via chia_query, but
// targets coinset.org's REST API directly (same transport the
// browser dApp uses via app/lib/coinset.ts).
//
// Every helper returns shapes matching the wasm-side `JsCoinRecord`
// / `JsPuzzleSolution` so chainBackend.mjs can pass them straight
// through to wasm without re-shaping.

const COINSET_BASE_URL =
  process.env.COINSET_BASE_URL?.trim() || "https://api.coinset.org";

async function postJsonOnce(path, body) {
  const r = await fetch(`${COINSET_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "<no body>");
    throw new Error(`${path} ${r.status}: ${text}`);
  }
  return r.json();
}

/**
 * coinset.org's edge proxy occasionally returns a transport-level
 * `TypeError: fetch failed` — usually a TLS handshake reset or a
 * 502 from the upstream node. Retry up to 4 times with exponential
 * backoff (mirrors the rust live test's chia_query retry policy).
 */
async function postJson(path, body) {
  const MAX_ATTEMPTS = 4;
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      return await postJsonOnce(path, body);
    } catch (e) {
      lastErr = e;
      if (attempt === MAX_ATTEMPTS) break;
      const waitMs = 500 * 2 ** (attempt - 1); // 500, 1000, 2000
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
  throw new Error(`${path}: failed after ${MAX_ATTEMPTS} attempts: ${lastErr?.message ?? lastErr}`);
}

function stripHex(s) {
  if (typeof s !== "string") return s;
  return s.startsWith("0x") ? s.slice(2) : s;
}

function ensure0x(s) {
  if (typeof s !== "string") return s;
  return s.startsWith("0x") ? s : `0x${s}`;
}

/** Map a coinset.org `coin_record` JSON to the JsCoinRecord wire shape. */
function mapCoinRecord(rec) {
  return {
    parentCoinInfo: stripHex(rec.coin.parent_coin_info),
    puzzleHash: stripHex(rec.coin.puzzle_hash),
    amount: Number(rec.coin.amount),
    spentHeight: Number(rec.spent_block_index ?? 0),
    confirmedHeight: Number(rec.confirmed_block_index ?? 0),
  };
}

export async function coinRecordsByPuzzleHash(puzzleHashHex, includeSpent = false) {
  const body = await postJson("/get_coin_records_by_puzzle_hash", {
    puzzle_hash: ensure0x(puzzleHashHex),
    include_spent_coins: includeSpent,
  });
  if (!body.success) throw new Error(`coinRecordsByPuzzleHash failed: ${body.error}`);
  return (body.coin_records ?? []).map(mapCoinRecord);
}

export async function coinRecordsByHint(hintHex, includeSpent = true) {
  const body = await postJson("/get_coin_records_by_hint", {
    hint: ensure0x(hintHex),
    include_spent_coins: includeSpent,
  });
  if (!body.success) throw new Error(`coinRecordsByHint failed: ${body.error}`);
  return (body.coin_records ?? []).map(mapCoinRecord);
}

export async function coinRecordByName(coinIdHex) {
  const body = await postJson("/get_coin_record_by_name", {
    name: ensure0x(coinIdHex),
  });
  if (!body.success) {
    if (body.error?.includes("not found")) return null;
    throw new Error(`coinRecordByName failed: ${body.error}`);
  }
  if (!body.coin_record) return null;
  return mapCoinRecord(body.coin_record);
}

export async function coinRecordsByParentIds(parentIdsHex) {
  const body = await postJson("/get_coin_records_by_parent_ids", {
    parent_ids: parentIdsHex.map(ensure0x),
    include_spent_coins: true,
  });
  if (!body.success) throw new Error(`coinRecordsByParentIds failed: ${body.error}`);
  return (body.coin_records ?? []).map(mapCoinRecord);
}

export async function puzzleAndSolution(coinIdHex, height) {
  // coinset.org's get_puzzle_and_solution requires a height. If
  // the caller doesn't supply one, look it up via coinRecordByName
  // (the spent_block_index is the height we want).
  let h = height;
  if (h === undefined || h === null) {
    const rec = await coinRecordByName(coinIdHex);
    if (!rec || rec.spentHeight === 0) return null;
    h = rec.spentHeight;
  }
  const body = await postJson("/get_puzzle_and_solution", {
    coin_id: ensure0x(coinIdHex),
    height: h,
  });
  if (!body.success) {
    if (body.error?.includes("not found") || body.error?.includes("unspent")) {
      return null;
    }
    throw new Error(`puzzleAndSolution failed: ${body.error}`);
  }
  if (!body.coin_solution) return null;
  return {
    puzzleHex: stripHex(body.coin_solution.puzzle_reveal),
    solutionHex: stripHex(body.coin_solution.solution),
  };
}

export async function peakHeight() {
  const body = await postJson("/get_blockchain_state", {});
  if (!body.success) return null;
  return Number(body.blockchain_state?.peak?.height ?? 0);
}

export async function pushTx(spendBundleJson) {
  const body = await postJson("/push_tx", { spend_bundle: spendBundleJson });
  return body;
}
