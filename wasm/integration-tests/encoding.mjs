// ============================================================================
// encoding.mjs — chia_protocol Streamable encoders (CoinSpend / list)
// ============================================================================
//
// `chip-voting-wasm` exports that take pre-built bundles
// (createBallotBundle's `funder_spend_bytes`, registerBuildSpends's
// `cat_parent_spend_bytes`, signCoinSpends's `coin_spends_bytes`)
// expect the chia_protocol Streamable encoding. chia-wallet-sdk-wasm
// doesn't expose CoinSpend.toBytes(), so we encode manually here.
// Same wire format both sides round-trip on, since both sides use
// chia_protocol::Streamable.
//
// Wire formats:
//   Coin:
//     parent_coin_info: 32 bytes
//     puzzle_hash:      32 bytes
//     amount:            8 bytes BE u64
//   CoinSpend:
//     coin:              72 bytes (above)
//     puzzle_reveal:     u32 BE length || bytes
//     solution:          u32 BE length || bytes
//   coin-spend list (length-prefixed, the shape chip-voting-wasm
//   exports use for `coin_spends_bytes`):
//     count:             u32 BE
//     each spend:        u32 BE length || streamable CoinSpend

function writeU32Be(buf, n) {
  buf.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function writeU64Be(buf, n) {
  const bn = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf.push(Number((bn >> BigInt(i * 8)) & 0xffn));
  }
}

/** Encode a chia-wallet-sdk-wasm Coin (or duck-typed
 *  `{ parentCoinInfo: Uint8Array(32), puzzleHash: Uint8Array(32), amount: bigint|number }`)
 *  as 72 streamable bytes. */
export function encodeCoinStreamable(coin) {
  if (coin.parentCoinInfo.length !== 32) throw new Error("parentCoinInfo must be 32 bytes");
  if (coin.puzzleHash.length !== 32) throw new Error("puzzleHash must be 32 bytes");
  const buf = [];
  for (const b of coin.parentCoinInfo) buf.push(b);
  for (const b of coin.puzzleHash) buf.push(b);
  writeU64Be(buf, coin.amount);
  return new Uint8Array(buf);
}

/** Encode a chia-wallet-sdk-wasm CoinSpend (or
 *  `{ coin, puzzleReveal: Uint8Array, solution: Uint8Array }`) as
 *  streamable bytes (`Coin || u32-len-puzzle || puzzle || u32-len-solution || solution`). */
export function encodeCoinSpendStreamable(cs) {
  const coinBytes = encodeCoinStreamable(cs.coin);
  const out = [];
  for (const b of coinBytes) out.push(b);
  writeU32Be(out, cs.puzzleReveal.length);
  for (const b of cs.puzzleReveal) out.push(b);
  writeU32Be(out, cs.solution.length);
  for (const b of cs.solution) out.push(b);
  return new Uint8Array(out);
}

/** Encode a list of CoinSpends as the length-prefixed format
 *  chip-voting-wasm's `signCoinSpends` / `assembleSpendBundle` /
 *  `decode_coin_spends` use. */
export function encodeCoinSpendListLengthPrefixed(coinSpends) {
  const out = [];
  writeU32Be(out, coinSpends.length);
  for (const cs of coinSpends) {
    const bytes = encodeCoinSpendStreamable(cs);
    writeU32Be(out, bytes.length);
    for (const b of bytes) out.push(b);
  }
  return new Uint8Array(out);
}
