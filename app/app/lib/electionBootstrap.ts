// ----------------------------------------------------------------------------
// Session bootstrap — election page reads ElectionConfig ONLY from here (+ URL),
// never from IndexedDB/local `chip.elections`. WalletConnect home list seeds
// this on navigation; create flow writes after deploy. Survives refresh.
// ----------------------------------------------------------------------------

import type { ElectionChoice, StoredElection } from "./elections";

export type ElectionBootstrap = {
  launcherIdHex: string;
  configJson: string;
  label: string;
  addedAt?: string;
  choices?: ElectionChoice[];
  eveCoinIdHex?: string;
  provingKeyBase64?: string;
  registeredPubkeysHex?: string[];
  /**
   * Block height the deployer used as `election_start_height` at
   * `wasm.buildDeployBundle` time. Required by every chain-walking
   * wasm export (`readElectionSingletonState`, `cast_vote`,
   * `register`, `release`) — the launcher walker uses this to
   * predict the eve singleton puzzle hash, and a wrong value means
   * find_current_singleton returns NotDeployed. The SDK's
   * ElectionConfig does NOT include this field; we persist it on
   * the bootstrap so it survives refresh + share-bundle round-trips.
   */
  electionStartHeight?: number;
};

export function normalizeLauncherForKey(launcherIdHex: string): string {
  return "0x" + launcherIdHex.trim().replace(/^0x/i, "").toLowerCase();
}

function sessionKey(launcherIdHex: string): string {
  return `chip-election-bootstrap:${normalizeLauncherForKey(launcherIdHex)}`;
}

export function readElectionBootstrap(
  launcherIdHex: string
): ElectionBootstrap | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(sessionKey(launcherIdHex));
    if (!raw) return null;
    const p = JSON.parse(raw) as ElectionBootstrap;
    if (
      typeof p.configJson !== "string" ||
      typeof p.launcherIdHex !== "string" ||
      typeof p.label !== "string"
    ) {
      return null;
    }
    return {
      ...p,
      launcherIdHex: normalizeLauncherForKey(p.launcherIdHex),
    };
  } catch {
    return null;
  }
}

export function writeElectionBootstrap(b: ElectionBootstrap): void {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.setItem(
      sessionKey(b.launcherIdHex),
      JSON.stringify({
        ...b,
        launcherIdHex: normalizeLauncherForKey(b.launcherIdHex),
      })
    );
  } catch {
    /* quota / privacy mode — page may require re-paste after refresh */
  }
}

/** Merge pubkey into bootstrap so registration hint survives refresh. */
export function mergeBootstrapPubkeyRegistered(
  launcherIdHex: string,
  pubkeyHex: string
): ElectionBootstrap | null {
  const cur = readElectionBootstrap(launcherIdHex);
  if (!cur) return null;
  const set = new Set([
    ...(cur.registeredPubkeysHex ?? []).map((x) => x.toLowerCase()),
    pubkeyHex.toLowerCase(),
  ]);
  const next: ElectionBootstrap = {
    ...cur,
    registeredPubkeysHex: Array.from(set),
  };
  writeElectionBootstrap(next);
  return next;
}

export function bootstrapFromStored(stored: StoredElection): ElectionBootstrap {
  return {
    launcherIdHex: normalizeLauncherForKey(stored.launcherIdHex),
    configJson: stored.configJson,
    label: stored.label,
    addedAt: stored.addedAt,
    choices: stored.choices,
    eveCoinIdHex: stored.eveCoinIdHex,
    provingKeyBase64: stored.provingKeyBase64,
    registeredPubkeysHex: stored.registeredPubkeysHex,
  };
}
