// ============================================================================
// units.ts — mojo / CAT / XCH formatters
// ============================================================================
//
// Chia uses mojos as the smallest indivisible unit:
//   * 1 XCH = 1_000_000_000_000 mojos (1e12)
//   * 1 CAT token at 3-decimal precision = 1_000 mojos (1e3)
//
// Displays here truncate trailing zeros for readability and use a
// monospace font upstream (`.mono`) so column alignment stays clean.

const XCH_MOJOS = 1_000_000_000_000n;
const CAT_MOJOS = 1_000n;

function trimTrail(s: string): string {
  // Strip trailing zeros after a decimal point, but keep one zero if
  // the result would end with a dot.
  if (!s.includes(".")) return s;
  let out = s.replace(/0+$/, "");
  if (out.endsWith(".")) out += "0";
  return out;
}

/** Format an XCH amount (mojos) with the chia-canonical 12 decimals. */
export function formatXch(mojos: bigint | number): string {
  const m = typeof mojos === "bigint" ? mojos : BigInt(mojos);
  const whole = m / XCH_MOJOS;
  const frac = (m % XCH_MOJOS).toString().padStart(12, "0");
  return trimTrail(`${whole.toString()}.${frac}`);
}

/** Format a CAT amount (mojos) with the standard 3-decimal precision. */
export function formatCat(mojos: bigint | number): string {
  const m = typeof mojos === "bigint" ? mojos : BigInt(mojos);
  const whole = m / CAT_MOJOS;
  const frac = (m % CAT_MOJOS).toString().padStart(3, "0");
  return trimTrail(`${whole.toString()}.${frac}`);
}

/** Parse user-typed XCH (decimal) into mojos. Returns null if invalid. */
export function parseXch(input: string): bigint | null {
  if (!/^\d+(\.\d{0,12})?$/.test(input.trim())) return null;
  const [whole, frac = ""] = input.trim().split(".");
  const padded = (frac + "0".repeat(12)).slice(0, 12);
  return BigInt(whole) * XCH_MOJOS + BigInt(padded || "0");
}

/** Parse user-typed CAT (decimal) into mojos. */
export function parseCat(input: string): bigint | null {
  if (!/^\d+(\.\d{0,3})?$/.test(input.trim())) return null;
  const [whole, frac = ""] = input.trim().split(".");
  const padded = (frac + "0".repeat(3)).slice(0, 3);
  return BigInt(whole) * CAT_MOJOS + BigInt(padded || "0");
}

/** Truncate a hex/id for display: `0xab12...cd34`. */
export function truncHex(hex: string, head = 6, tail = 4): string {
  const h = hex.startsWith("0x") ? hex : "0x" + hex;
  if (h.length <= head + tail + 2) return h;
  return `${h.slice(0, head + 2)}…${h.slice(-tail)}`;
}

/** Lowercase hex, no `0x` prefix (CAT asset ids, puzzle hashes, etc.). */
export function normalizeHex32(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, "");
}

/** Dexie and many explorers identify a CAT by bare 64-char hex. */
export function dexieCatAssetUrl(catTailHex: string): string {
  const n = normalizeHex32(catTailHex);
  if (!/^[0-9a-f]{64}$/.test(n))
    return "https://dexie.space/";
  return `https://dexie.space/assets/${n}`;
}
