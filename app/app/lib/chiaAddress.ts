/**
 * Canonical Chia bech32m address handling via `chia-wallet-sdk-wasm`
 * (same stack as streaming-ui). Never hand-roll bech32 → puzzle hash.
 */

export async function puzzleHashBytesFromWalletAddress(
  addr: string
): Promise<Uint8Array | null> {
  const chia = await import("chia-wallet-sdk-wasm");
  let decoded: InstanceType<(typeof chia)["Address"]> | undefined;
  try {
    decoded = chia.Address.decode(addr.trim());
    return new Uint8Array(decoded.puzzleHash);
  } catch {
    return null;
  } finally {
    decoded?.free();
  }
}

/** `0x` + 64 lowercase hex (for coinset / display). */
export async function puzzleHashHexFromWalletAddress(
  addr: string
): Promise<string | null> {
  const chia = await import("chia-wallet-sdk-wasm");
  let h: string;
  let decoded: InstanceType<(typeof chia)["Address"]> | undefined;
  try {
    decoded = chia.Address.decode(addr.trim());
    h = chia.toHex(decoded.puzzleHash);
  } catch {
    return null;
  } finally {
    decoded?.free();
  }
  h = h.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) return null;
  return `0x${h}`;
}

/**
 * CAT outer puzzle hash for `(asset_id, inner_puzzle_hash)` where
 * `inner` is the **same** inner encoded in the wallet receive address.
 * Uses chia-sdk `catPuzzleHash` so coinset queries match on-chain CATs.
 */
export async function catOuterPuzzleHashHexForWalletAddress(
  addr: string,
  catTailHashHex: string
): Promise<string> {
  const chia = await import("chia-wallet-sdk-wasm");
  const tail = catTailHashHex.replace(/^0x/i, "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(tail)) {
    throw new Error("CAT tail must be 64 hex chars (32 bytes)");
  }
  let decoded: InstanceType<(typeof chia)["Address"]> | undefined;
  let inner: Uint8Array;
  try {
    decoded = chia.Address.decode(addr.trim());
    inner = new Uint8Array(decoded.puzzleHash);
  } finally {
    decoded?.free();
  }
  const assetId = chia.fromHex(tail);
  const outer = chia.catPuzzleHash(assetId, inner);
  let oh = chia.toHex(outer);
  oh = oh.replace(/^0x/i, "").toLowerCase();
  return `0x${oh}`;
}

type ChiaWasm = typeof import("chia-wallet-sdk-wasm");
type SyntheticPkWasm = ReturnType<ChiaWasm["PublicKey"]["fromBytes"]>;

/**
 * CAT outer puzzle hash for `(asset_id, standard_puzzle_hash(pubkey))`
 * — same derivation as Sage `chip0002_getPublicKeys` synthetic keys.
 *
 * IMPORTANT: `chia-wallet-sdk-wasm` `standardPuzzleHash` consumes the
 * `PublicKey` (`__destroy_into_raw`); never call `pk.free()` afterward.
 */
export async function catOuterPuzzleHashHexFromSyntheticPubkeyHex(
  syntheticPkHex: string,
  catTailHashHex: string
): Promise<string> {
  const chia = await import("chia-wallet-sdk-wasm");
  const rawPk = syntheticPkHex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(rawPk)) {
    throw new Error("Synthetic pubkey must be 48-byte G1 element (96 hex chars)");
  }
  const tail = catTailHashHex.replace(/^0x/i, "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(tail)) {
    throw new Error("CAT tail must be 64 hex chars (32 bytes)");
  }
  const pk: SyntheticPkWasm = chia.PublicKey.fromBytes(chia.fromHex(rawPk));
  const inner = new Uint8Array(chia.standardPuzzleHash(pk));
  const assetId = chia.fromHex(tail);
  const outer = chia.catPuzzleHash(assetId, inner);
  let oh = chia.toHex(outer);
  oh = oh.replace(/^0x/i, "").toLowerCase();
  return `0x${oh}`;
}

/**
 * Standard (p2) puzzle hash for a Sage `chip0002_getPublicKeys` synthetic G1
 * element — matches `chip-voting-wasm::standardPuzzleHash` / coinset XCH rows.
 */
export async function standardPuzzleHashHexFromSyntheticPubkeyHex(
  syntheticPkHex: string
): Promise<string> {
  const chia = await import("chia-wallet-sdk-wasm");
  const rawPk = syntheticPkHex.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(rawPk)) {
    throw new Error("Synthetic pubkey must be 48-byte G1 element (96 hex chars)");
  }
  const pk = chia.PublicKey.fromBytes(chia.fromHex(rawPk));
  const ph = chia.standardPuzzleHash(pk);
  let h = chia.toHex(ph);
  h = h.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error("Unexpected standard puzzle hash length");
  }
  return `0x${h}`;
}
