// ----------------------------------------------------------------------------
// ballotBootstrap.ts — per-ballot session-storage helper
// ----------------------------------------------------------------------------
//
// Per-ballot data the dApp captures at `launchBallot` time and re-uses
// at cast_vote / finalize / release time. The on-chain `eve Ballot
// Coin` is curried with `(VK, IC, BALLOT_LAUNCHER_ID,
// ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM,
// VOTE_THRESHOLD_DEN, REGISTRATION_MERKLE_ROOT_SNAPSHOT,
// REGISTRATION_VOTE_WEIGHT_SNAPSHOT)` — every later actor MUST mirror
// those values exactly or the ballot's curried puzzle hash diverges
// from chain.
//
// Mirrors `electionBootstrap.ts`'s session-storage pattern (key
// `chip-ballot-bootstrap:<electionLauncher>:<ballotLauncher>`).
//
// The dApp doesn't try to enumerate ballots from chain (the
// `listBallots` walk works but is slow); it just remembers what it
// just minted, plus what it picks up from imported share bundles.

import { normalizeHex32 } from "./units";

export interface BallotBootstrap {
  /** Election the ballot belongs to. 0x-hex 32 bytes. */
  electionLauncherIdHex: string;
  /** Ballot's own launcher id. 0x-hex 32 bytes. Primary key. */
  ballotLauncherIdHex: string;
  /** Eve Ballot Coin id (= launcher's child at the predicted singleton-wrapped ph). */
  eveBallotCoinIdHex?: string;
  /** Eve Ballot Coin full puzzle hash (singleton-wrapped). */
  eveBallotPuzzleHashHex?: string;
  /** Block height at which the launcher second-spend confirmed. */
  launchedAtHeight?: number;
  /** Per-ballot vote close height — curried into finalize/oracle/announce_finalization. */
  voteCloseHeight: number;
  /** 32-byte commitment to the allowed outcome set (`outcome_domain_hash`). */
  outcomeDomainHashHex: string;
  /** Random per-ballot seed used at createBallot time. 0x-hex 32 bytes. */
  ballotSeedHex?: string;
  /** Threshold pack (numerator). */
  voteThresholdNum: number;
  /** Threshold pack (denominator). */
  voteThresholdDen: number;
  /** Election Singleton state snapshot at `launch_ballot` time. */
  registrationMerkleRootSnapshotHex: string;
  /** Vote weight snapshot — sum of locked CAT collateral at launch time. */
  registrationVoteWeightSnapshot: number;
  /** Voter count snapshot — diagnostic only; not curried into the ballot. */
  registrationCountSnapshot?: number;
  /** ISO timestamp of when this record was first written. */
  addedAt: string;
  /** UI label (defaults to ballotLauncherId slice). */
  label?: string;
}

function normKey(electionLauncherIdHex: string, ballotLauncherIdHex: string): string {
  const e = normalizeHex32(electionLauncherIdHex);
  const b = normalizeHex32(ballotLauncherIdHex);
  return `chip-ballot-bootstrap:${e}:${b}`;
}

function listKey(electionLauncherIdHex: string): string {
  const e = normalizeHex32(electionLauncherIdHex);
  return `chip-ballots-bootstrap-list:${e}`;
}

/**
 * Read a single ballot's bootstrap record. Returns `null` if no such
 * record (caller should fall back to chain-walk via `wasm.getBallot`).
 */
export function readBallotBootstrap(
  electionLauncherIdHex: string,
  ballotLauncherIdHex: string
): BallotBootstrap | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(normKey(electionLauncherIdHex, ballotLauncherIdHex));
    if (!raw) return null;
    const p = JSON.parse(raw) as BallotBootstrap;
    if (
      typeof p.electionLauncherIdHex !== "string" ||
      typeof p.ballotLauncherIdHex !== "string" ||
      typeof p.voteCloseHeight !== "number" ||
      typeof p.registrationMerkleRootSnapshotHex !== "string"
    ) {
      return null;
    }
    return p;
  } catch {
    return null;
  }
}

/** Persist a ballot bootstrap record (overwrites existing). Updates the per-election listing index. */
export function writeBallotBootstrap(b: BallotBootstrap): void {
  if (typeof window === "undefined") return;
  const electionKey = normalizeHex32(b.electionLauncherIdHex);
  const ballotKey = normalizeHex32(b.ballotLauncherIdHex);
  const norm: BallotBootstrap = {
    ...b,
    electionLauncherIdHex: electionKey,
    ballotLauncherIdHex: ballotKey,
    addedAt: b.addedAt ?? new Date().toISOString(),
  };
  try {
    sessionStorage.setItem(normKey(electionKey, ballotKey), JSON.stringify(norm));
    // Maintain a list of known ballot ids per election so the UI
    // can enumerate without scanning all sessionStorage keys.
    const listed = listBallotBootstraps(electionKey);
    if (!listed.some((x) => normalizeHex32(x.ballotLauncherIdHex) === ballotKey)) {
      const next = [...listed, norm];
      sessionStorage.setItem(listKey(electionKey), JSON.stringify(next));
    } else {
      const next = listed.map((x) =>
        normalizeHex32(x.ballotLauncherIdHex) === ballotKey ? norm : x
      );
      sessionStorage.setItem(listKey(electionKey), JSON.stringify(next));
    }
  } catch {
    /* quota / privacy mode — caller may need to re-launch on refresh */
  }
}

/** List every ballot bootstrap known for this election. Empty if none stored. */
export function listBallotBootstraps(electionLauncherIdHex: string): BallotBootstrap[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = sessionStorage.getItem(listKey(electionLauncherIdHex));
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter(
      (x): x is BallotBootstrap =>
        x &&
        typeof x.ballotLauncherIdHex === "string" &&
        typeof x.voteCloseHeight === "number" &&
        typeof x.registrationMerkleRootSnapshotHex === "string"
    );
  } catch {
    return [];
  }
}

/**
 * Pick the most-recently-launched OPEN ballot whose snapshot is
 * non-empty (i.e. was launched after at least one register confirmed).
 * Returns `null` when no ballot fits — caller should redirect to the
 * createBallot operator UI.
 */
export function pickOpenBallotForVoting(
  electionLauncherIdHex: string,
  currentPeak: number
): BallotBootstrap | null {
  const candidates = listBallotBootstraps(electionLauncherIdHex)
    .filter(
      (b) =>
        !!b.eveBallotCoinIdHex &&
        b.voteCloseHeight > currentPeak &&
        !!b.registrationMerkleRootSnapshotHex &&
        b.registrationVoteWeightSnapshot > 0
    )
    .sort((a, b) => (b.launchedAtHeight ?? 0) - (a.launchedAtHeight ?? 0));
  return candidates[0] ?? null;
}

/** Delete a ballot bootstrap (e.g. after release / on user action). */
export function deleteBallotBootstrap(
  electionLauncherIdHex: string,
  ballotLauncherIdHex: string
): void {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.removeItem(normKey(electionLauncherIdHex, ballotLauncherIdHex));
    const next = listBallotBootstraps(electionLauncherIdHex).filter(
      (x) => normalizeHex32(x.ballotLauncherIdHex) !== normalizeHex32(ballotLauncherIdHex)
    );
    sessionStorage.setItem(listKey(electionLauncherIdHex), JSON.stringify(next));
  } catch {
    /* */
  }
}
