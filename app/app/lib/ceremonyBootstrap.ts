// ============================================================================
// lib/ceremonyBootstrap — local persistence for ceremony deploy params
// ============================================================================
//
// Each ceremony deployed from this browser writes its `CeremonyBootstrap`
// (the curried params + label) to localStorage so /ceremonies (the
// index) and /ceremony?id=... (the detail page) can render without
// re-fetching from chain.
//
// localStorage (not sessionStorage) so deployed ceremonies survive tab
// close. Keys are namespaced with `chipCeremonyBootstrap:<launcher>`
// so the index can scan them without a separate registry.

export const CEREMONY_BOOTSTRAP_KEY = "chipCeremonyBootstrap:";

export type CeremonyBootstrap = {
  launcherIdHex: string;
  startBlockHeight: number;
  ceremonyLengthBlocks: number;
  minParticipants: number;
  /**
   * Max voters this ceremony's circuit supports. Determines the
   * SPT depth. Optional for backwards compat with bootstraps written
   * before E4; consumers default to 20000 when missing.
   */
  maxVoters?: number;
  vkSeedHex: string;
  label?: string | null;
};

/**
 * Read a ceremony bootstrap by launcher id (with or without 0x prefix).
 * Returns null if no entry exists or the stored JSON is malformed.
 *
 * Reads from localStorage; older sessionStorage entries written before
 * this module existed are silently ignored (one-time migration is
 * unnecessary because deployed ceremonies are short-lived).
 */
export function readCeremonyBootstrap(
  launcherIdHex: string
): CeremonyBootstrap | null {
  if (typeof window === "undefined") return null;
  const id = launcherIdHex.startsWith("0x")
    ? launcherIdHex
    : `0x${launcherIdHex}`;
  const raw = window.localStorage.getItem(`${CEREMONY_BOOTSTRAP_KEY}${id}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CeremonyBootstrap;
  } catch {
    return null;
  }
}

/** Persist a ceremony bootstrap to localStorage. */
export function writeCeremonyBootstrap(b: CeremonyBootstrap): void {
  if (typeof window === "undefined") return;
  const id = b.launcherIdHex.startsWith("0x")
    ? b.launcherIdHex
    : `0x${b.launcherIdHex}`;
  window.localStorage.setItem(
    `${CEREMONY_BOOTSTRAP_KEY}${id}`,
    JSON.stringify(b)
  );
}

/** List every ceremony bootstrap known to this browser. */
export function listAllCeremonies(): CeremonyBootstrap[] {
  if (typeof window === "undefined") return [];
  const out: CeremonyBootstrap[] = [];
  for (let i = 0; i < window.localStorage.length; i++) {
    const key = window.localStorage.key(i);
    if (!key || !key.startsWith(CEREMONY_BOOTSTRAP_KEY)) continue;
    const raw = window.localStorage.getItem(key);
    if (!raw) continue;
    try {
      out.push(JSON.parse(raw) as CeremonyBootstrap);
    } catch {
      // skip malformed entries
    }
  }
  return out;
}
