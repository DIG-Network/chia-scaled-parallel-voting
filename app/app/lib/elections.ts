// ============================================================================
// elections.ts — local persistence of known election configs
// ============================================================================

import { normalizeHex32 } from "./units";

// MODULE: lib/elections
// PURPOSE: Track every election the user has created, registered for,
//          or browsed, so the home page can show a list without
//          re-deriving everything from chain on every visit.
//
// STORAGE: localStorage key `chip.elections` holds an array of
//          `StoredElection` records (full ElectionConfig JSON +
//          UI metadata). The user can prune the list manually.
//
// CHAIN VERIFICATION: this module does NOT trust the local copy
// blindly — every page that displays an election re-fetches the
// current singleton state from coinset.org via `lib/coinset.ts`.
// The local copy is just an INDEX so the home page can list
// elections without scanning the chain.

const KEY = "chip.elections";

/**
 * A single option a voter can pick. The on-chain `vote_data` is
 * 32 raw bytes; the dApp surfaces a friendly `label` and stores
 * the SHA-256 the voter actually casts. This mapping is
 * UI-only — the protocol never sees `label`.
 *
 * SHARING: when one user shares an election with another, they
 * also need to ship the choices list so the second user sees
 * the same options (and can decode the eventual outcome). The
 * "Import config" form on `/election` accepts either a bare
 * `ElectionConfig` JSON (no choices) or a wrapped
 * `{ config, choices, label }` bundle.
 */
export interface ElectionChoice {
  /** Human-readable option name (e.g., "Approve", "Reject"). */
  label: string;
  /**
   * 32-byte hex (with `0x` prefix) the voter writes on-chain.
   * Defaults to `sha256("vote:" + label)` so two clients that
   * agree on the label set produce identical bytes; the
   * deployer can override per-choice for richer schemes
   * (e.g., embedding metadata into the bytes).
   */
  voteDataHex: string;
}

export interface StoredElection {
  /** Full ElectionConfig JSON (round-trips through SDK serde). */
  configJson: string;
  /** Election launcher_id, 0x-hex. Primary key. */
  launcherIdHex: string;
  /** UI label (defaults to launcher_id slice). */
  label: string;
  /** ISO timestamp of when we first saw this election. */
  addedAt: string;
  /** Pre-derived eve singleton id (for quick "is it confirmed yet?" UX). */
  eveCoinIdHex?: string;
  /**
   * Local hint that the connected wallet's voter pubkey has
   * registered. Display only — chain queries are still authoritative.
   */
  registeredPubkeysHex?: string[];
  /**
   * Stored proving key bytes (for the local Groth16 prover, used
   * at finalize time). Only the deployer keeps this. Big — base64.
   */
  provingKeyBase64?: string;
  /**
   * UI-curated voter options. The dApp displays these as radio
   * buttons; the on-chain `vote_data` is always
   * `choice.voteDataHex`. Optional — elections without choices
   * fall back to the freeform vote-data input.
   */
  choices?: ElectionChoice[];
}

/**
 * Deterministic vote-data derivation: `sha256("vote:" + label)`.
 * Two browsers that agree on the label set produce identical
 * `vote_data`, so the eventual on-chain outcome is decodable
 * by anyone with the labels.
 */
export async function deriveVoteData(label: string): Promise<string> {
  const enc = new TextEncoder().encode("vote:" + label);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return (
    "0x" +
    Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

/** Build choices from labels in one shot (UI helper). */
export async function makeChoices(labels: string[]): Promise<ElectionChoice[]> {
  const out: ElectionChoice[] = [];
  for (const label of labels) {
    const trimmed = label.trim();
    if (!trimmed) continue;
    out.push({ label: trimmed, voteDataHex: await deriveVoteData(trimmed) });
  }
  return out;
}

/**
 * A "shareable bundle" — what the deployer pastes into chat to
 * onboard another voter. Two-tier format, both accepted by
 * `parseShareablePayload`:
 *
 *   1. CHOICES-ONLY (preferred for onboarding existing voters /
 *      observers): launcher id + ballot, and the collateral CAT
 *      asset id (`catTailHashHex`) so clients can cross-check.
 *
 *      ```json
 *      { "launcherId": "0xabc…", "catTailHashHex": "0x…", "label": "DAO Q3", "choices": [...] }
 *      ```
 *
 *      Recipient must already have the full `ElectionConfig` JSON
 *      stored locally (e.g. they were the deployer, or imported a
 *      legacy full bundle once). Use this when sharing the ballot
 *      *after* the election is already known to participants.
 *
 *   2. LEGACY FULL BUNDLE (still accepted, used by the deployer
 *      when bootstrapping a brand-new voter who's never seen the
 *      election): wraps the entire `ElectionConfig` plus the UI
 *      metadata.
 *
 *      ```json
 *      { "config": {…ElectionConfig…}, "label": "…", "choices": [...] }
 *      ```
 *
 *   3. BARE `ElectionConfig` JSON (oldest legacy path) — also
 *      accepted; carries no UI metadata.
 */
export interface ShareableBundle {
  /** Election launcher_id (0x-hex). Primary key linking to the chain. */
  launcherId?: string;
  /** CAT asset id / TAIL puzzle hash — 64 hex chars (optional `0x`). */
  catTailHashHex?: string;
  /** Human label. */
  label?: string;
  /** UI ballot. */
  choices?: ElectionChoice[];
  /** Optional full ElectionConfig (legacy path 2). */
  config?: unknown;
}

/** Normalized 64-char lowercase CAT tail hex (no `0x`). */
export function normalizeCatTailHex(tailHex: string): string {
  return normalizeHex32(tailHex);
}

/** `0x` + validated 64-char lowercase CAT tail hex. */
export function canonicalCatTail0x(tailHex: string): string {
  const n = normalizeCatTailHex(tailHex);
  if (!/^[0-9a-f]{64}$/.test(n)) {
    throw new Error("CAT asset id must be exactly 64 hex chars (32 bytes)");
  }
  return `0x${n}`;
}

function pickCatTailFromObject(obj: Record<string, unknown>): string | undefined {
  const raw =
    typeof obj.catTailHashHex === "string"
      ? obj.catTailHashHex
      : typeof obj.cat_tail_hash_hex === "string"
        ? obj.cat_tail_hash_hex
        : undefined;
  if (!raw?.trim()) return undefined;
  const n = normalizeCatTailHex(raw);
  if (!/^[0-9a-f]{64}$/.test(n)) return undefined;
  return `0x${n}`;
}

/**
 * Parse a shareable JSON payload. Returns the structured fields
 * the import flow needs; the caller decides what to do when fields
 * are missing (e.g., choices-only payload received but no stored
 * config exists for that launcher_id).
 */
export function parseShareablePayload(json: string): {
  /** Full ElectionConfig JSON, if the payload included one. */
  configJson?: string;
  /** Election launcher id (0x-hex), if the payload included one. */
  launcherIdHex?: string;
  /** CAT asset id (0x-prefixed, canonical lowercase), when present and valid. */
  catTailHashHex?: string;
  /** Human label, if the payload included one. */
  label?: string;
  /** UI ballot, if the payload included one. */
  choices?: ElectionChoice[];
} {
  const parsed = JSON.parse(json);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("payload must be a JSON object");
  }

  // Path 3: bare ElectionConfig at the top level.
  if ("election_launcher_id_hex" in parsed) {
    const o = parsed as Record<string, unknown>;
    return {
      configJson: json,
      launcherIdHex:
        typeof o.election_launcher_id_hex === "string"
          ? "0x" +
            (o.election_launcher_id_hex as string)
              .toLowerCase()
              .replace(/^0x/, "")
          : undefined,
      catTailHashHex: pickCatTailFromObject(o),
    };
  }

  // Path 2: wrapped legacy bundle ({ config, label, choices }).
  if (
    "config" in parsed &&
    parsed.config &&
    typeof parsed.config === "object"
  ) {
    const cfg = parsed.config as { election_launcher_id_hex?: string };
    const top = parsed as Record<string, unknown>;
    const catFromConfig =
      typeof (parsed.config as any).cat_tail_hash_hex === "string"
        ? pickCatTailFromObject(parsed.config as Record<string, unknown>)
        : undefined;
    return {
      configJson: JSON.stringify(parsed.config),
      launcherIdHex:
        typeof cfg.election_launcher_id_hex === "string"
          ? "0x" + cfg.election_launcher_id_hex.toLowerCase().replace(/^0x/, "")
          : typeof (parsed as any).launcherId === "string"
            ? "0x" +
              (parsed as any).launcherId.toLowerCase().replace(/^0x/, "")
            : undefined,
      catTailHashHex: pickCatTailFromObject(top) ?? catFromConfig,
      label: typeof (parsed as any).label === "string" ? (parsed as any).label : undefined,
      choices: Array.isArray((parsed as any).choices)
        ? ((parsed as any).choices as ElectionChoice[])
        : undefined,
    };
  }

  // Path 1: choices-only bundle ({ launcherId, label?, choices }).
  if ("launcherId" in parsed && "choices" in parsed) {
    if (typeof (parsed as any).launcherId !== "string") {
      throw new Error("launcherId must be a 0x-hex string");
    }
    const po = parsed as Record<string, unknown>;
    return {
      launcherIdHex:
        "0x" +
        ((parsed as any).launcherId as string).toLowerCase().replace(/^0x/, ""),
      catTailHashHex: pickCatTailFromObject(po),
      label: typeof (parsed as any).label === "string" ? (parsed as any).label : undefined,
      choices: Array.isArray((parsed as any).choices)
        ? ((parsed as any).choices as ElectionChoice[])
        : undefined,
    };
  }

  throw new Error(
    "Unrecognised payload shape — expected one of:\n" +
      "  { launcherId, catTailHashHex?, label?, choices }   (choices-only bundle)\n" +
      "  { config, label?, choices? }                      (legacy full bundle)\n" +
      "  { election_launcher_id_hex, … }                   (bare ElectionConfig JSON)"
  );
}

export function loadElections(): StoredElection[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as StoredElection[];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function saveElections(list: StoredElection[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify(list));
}

export function upsertElection(e: StoredElection) {
  const list = loadElections();
  const idx = list.findIndex(
    (x) => x.launcherIdHex.toLowerCase() === e.launcherIdHex.toLowerCase()
  );
  if (idx >= 0) {
    list[idx] = { ...list[idx], ...e };
  } else {
    list.unshift(e);
  }
  saveElections(list);
}

export function getElection(launcherIdHex: string): StoredElection | null {
  return (
    loadElections().find(
      (x) => x.launcherIdHex.toLowerCase() === launcherIdHex.toLowerCase()
    ) ?? null
  );
}

export function removeElection(launcherIdHex: string) {
  const list = loadElections().filter(
    (x) => x.launcherIdHex.toLowerCase() !== launcherIdHex.toLowerCase()
  );
  saveElections(list);
}

export function recordRegistration(launcherIdHex: string, pubkeyHex: string) {
  const list = loadElections();
  const idx = list.findIndex(
    (x) => x.launcherIdHex.toLowerCase() === launcherIdHex.toLowerCase()
  );
  if (idx < 0) return;
  const set = new Set([
    ...(list[idx].registeredPubkeysHex ?? []),
    pubkeyHex.toLowerCase(),
  ]);
  list[idx].registeredPubkeysHex = Array.from(set);
  saveElections(list);
}
