import walletConnect from "./walletConnectInstance";

/**
 * Paginate Sage `chip0002_getPublicKeys` and return the first synthetic
 * pubkey whose chia-wallet-sdk standard P2 puzzle hash matches
 * `targetInnerPuzzleHash` (exact 32-byte inner hash bytes).
 *
 * WHY CHIA SDK FOR BOTH: `Address.decode` → inner bytes must agree with
 * `standardPuzzleHash(pubkey)`. Using `chip-voting-wasm::standardPuzzleHash`
 * for matching could diverge from the chia-wallet-sdk revision bundled in
 * the browser, yielding no matching key ("Resolving pubkey…") and wrong CAT
 * outers versus coinset/mainnet CATs built with canonical cat mod hash +
 * chia-sdk tree arithmetic.
 *
 * IMPORTANT: `standardPuzzleHash(pubkey)` consumes the `PublicKey`— do not
 * call `pubkey.free()` afterward.
 */
export async function findSyntheticPkMatchingInnerPuzzleHash(
  targetInnerPuzzleHash: Uint8Array
): Promise<string | null> {
  const chia = await import("chia-wallet-sdk-wasm");
  const PAGE = 100;
  const MAX_OFFSET = 100_000;
  for (let off = 0; off < MAX_OFFSET; off += PAGE) {
    const keys = await walletConnect.getPublicKeys(PAGE, off);
    if (!keys || keys.length === 0) break;
    for (const k of keys) {
      try {
        const raw = k.trim().replace(/^0x/i, "");
        if (raw.length !== 96) continue;
        const pk = chia.PublicKey.fromBytes(chia.fromHex(raw));
        const ph = chia.standardPuzzleHash(pk);
        if (chia.bytesEqual(ph, targetInnerPuzzleHash)) {
          return `0x${raw.toLowerCase()}`;
        }
      } catch {
        /* skip malformed */
      }
    }
  }
  return null;
}

/**
 * Match `chia_getAddress` puzzle hash bytes (`Address.decode` →
 * puzzleHash). Tries the fast `chip0002_getAssetCoins` path first
 * (Sage owns the coin at this address — the puzzle reveal uncurries
 * to the synthetic_pk directly); falls back to the slow synthetic-
 * key scan only when getAssetCoins doesn't return a coin at that
 * address (e.g., zero-balance address, older Sage build).
 */
export async function findSyntheticPkForWalletAddress(
  addr: string
): Promise<string | null> {
  const chia = await import("chia-wallet-sdk-wasm");
  let decoded: { puzzleHash: Uint8Array; free(): void } | null = null;
  try {
    decoded = chia.Address.decode(addr.trim());
    const inner = new Uint8Array(decoded.puzzleHash);
    // Fast path: Sage knows which key derived this puzzle hash.
    try {
      const { syntheticPkForOwnedXchPuzzleHash } = await import("./sageAssetCoins");
      let phHex = "";
      for (let i = 0; i < inner.length; i++) {
        phHex += inner[i].toString(16).padStart(2, "0");
      }
      const fast = await syntheticPkForOwnedXchPuzzleHash(phHex);
      if (fast) return fast;
    } catch {
      /* fall through to scan */
    }
    return await findSyntheticPkMatchingInnerPuzzleHash(inner);
  } catch {
    return null;
  } finally {
    decoded?.free();
  }
}

/**
 * Match puzzle hash hex from chain / coin records (e.g. XCH parent
 * coin). Same fast-path-then-fallback pattern as
 * `findSyntheticPkForWalletAddress`.
 */
export async function findSyntheticPkMatchingCoinPuzzleHashHex(
  puzzleHashHex: string
): Promise<string | null> {
  const chia = await import("chia-wallet-sdk-wasm");
  const clean = puzzleHashHex.replace(/^0x/i, "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) return null;
  // Fast path via Sage's getAssetCoins.
  try {
    const { syntheticPkForOwnedXchPuzzleHash } = await import("./sageAssetCoins");
    const fast = await syntheticPkForOwnedXchPuzzleHash(clean);
    if (fast) return fast;
  } catch {
    /* fall through to scan */
  }
  const target = chia.fromHex(clean);
  return findSyntheticPkMatchingInnerPuzzleHash(target);
}
