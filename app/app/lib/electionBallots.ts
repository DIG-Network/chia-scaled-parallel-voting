// ----------------------------------------------------------------------------
// electionBallots.ts — chain-walk ballot list, merged with bootstrap metadata
// ----------------------------------------------------------------------------
//
// Mirrors live_integration.mjs's `wasm.listBallots(config)` chain walk.
// The dApp previously enumerated ballots from sessionStorage bootstrap
// only, missing ballots from other browsers / share-bundle imports and
// trusting cached `voteCloseHeight` / finalize fields. This helper makes
// the chain the source of truth, while keeping bootstrap as a cache for
// (a) dApp-only metadata (label, choices, voteThresholdNum/Den, the
// registration snapshots) and (b) "pending mint" rows whose eve
// singleton is too fresh to appear in the chain walk.
//
// Returns BallotBootstrap-shaped rows so the existing UI / iteration
// sites work unchanged. Where chain and boot disagree on a chain-
// derivable field (voteCloseHeight, outcomeDomainHashHex, finalized
// state, eveBallotCoinIdHex), CHAIN WINS and the bootstrap is rewritten
// to match — so the cache always reflects on-chain truth on the next
// read.
//
// `finalized` semantics: chain returns a u8 (0/1). The dApp's
// `finalizedAtHeight` is the block height at which finalize confirmed
// (set during the post-broadcast poll). When chain says finalized but
// the bootstrap doesn't have a height (different browser confirmed
// it), `finalized: true` is set without a height; display code falls
// back to "finalized" without the @height suffix.

import { listBallots, getBallot, type BallotCoinSnapshot } from "./sdk";
import {
  listBallotBootstraps,
  readBallotBootstrap,
  writeBallotBootstrap,
  type BallotBootstrap,
} from "./ballotBootstrap";
import { normalizeHex32 } from "./units";

const ZERO_BYTES32_HEX = "0x" + "0".repeat(64);

function isAllZerosBytes32(h: string | undefined | null): boolean {
  if (!h) return true;
  const norm = normalizeHex32(h);
  return norm === "0".repeat(64);
}

function chainSnapshotToBootstrap(
  c: BallotCoinSnapshot,
  boot: BallotBootstrap | undefined
): BallotBootstrap {
  const finalizedOnChain = (c.state?.finalized ?? 0) > 0;
  // Option A: prefer chain-recovered curry params (from launcher
  // memo) over the bootstrap. When chain returns null (legacy ballot
  // minted before the memo was added), fall back to bootstrap so
  // existing test ballots stay usable.
  const voteThresholdNum =
    c.vote_threshold_num != null
      ? Number(c.vote_threshold_num)
      : boot?.voteThresholdNum ?? 0;
  const voteThresholdDen =
    c.vote_threshold_den != null
      ? Number(c.vote_threshold_den)
      : boot?.voteThresholdDen ?? 0;
  const registrationMerkleRootSnapshotHex =
    c.registration_merkle_root_snapshot != null
      ? normalizeHex32(c.registration_merkle_root_snapshot)
      : boot?.registrationMerkleRootSnapshotHex ?? "";
  const registrationVoteWeightSnapshot =
    c.registration_vote_weight_snapshot != null
      ? Number(c.registration_vote_weight_snapshot)
      : boot?.registrationVoteWeightSnapshot ?? 0;
  return {
    electionLauncherIdHex: normalizeHex32(c.election_launcher_id),
    ballotLauncherIdHex: normalizeHex32(c.ballot_launcher_id),
    eveBallotCoinIdHex: c.coin_id,
    eveBallotPuzzleHashHex: boot?.eveBallotPuzzleHashHex,
    launchedAtHeight: boot?.launchedAtHeight,
    voteCloseHeight: c.vote_close_height,
    outcomeDomainHashHex: c.outcome_domain_hash,
    ballotSeedHex: boot?.ballotSeedHex,
    voteThresholdNum,
    voteThresholdDen,
    registrationMerkleRootSnapshotHex,
    registrationVoteWeightSnapshot,
    registrationCountSnapshot: boot?.registrationCountSnapshot,
    addedAt: boot?.addedAt ?? new Date(0).toISOString(),
    label: boot?.label,
    finalizedAtHeight: boot?.finalizedAtHeight,
    finalized: finalizedOnChain || !!boot?.finalized,
    // Phase: chain-authoritative vote_outcome. SDK extracts the
    // winning hash from the finalize spend's puzzle reveal (see
    // sdk/src/actors/ballot.rs:extract_finalize_outcome). Chain wins
    // when it returns a non-zero hash; bootstrap is the fallback for
    // ballots where the spend isn't yet observable (extractor missed,
    // legacy ballot, etc.). The chain-zero case can happen when the
    // ballot is finalized but the extractor couldn't parse the
    // solution shape — bootstrap then gives the local view from when
    // this browser broadcast finalize.
    voteOutcomeHex:
      finalizedOnChain && !isAllZerosBytes32(c.state?.vote_outcome)
        ? c.state.vote_outcome
        : boot?.voteOutcomeHex ??
          (finalizedOnChain ? ZERO_BYTES32_HEX : undefined),
    choices: boot?.choices,
  };
}

/**
 * Get the canonical ballot list for an election. Walks the chain via
 * wasm.listBallots, then enriches with sessionStorage bootstrap (label,
 * choices, voteThreshold, registration snapshots). Bootstrap-only
 * entries (pending mint, chain walk hasn't seen them yet) are appended.
 *
 * On chain-walk failure (network error, wasm panic), falls back to
 * bootstrap-only enumeration so the UI stays usable. Caller can detect
 * fallback by comparing the result to listBallotBootstraps directly if
 * needed, but most callers don't care.
 *
 * Side effect: when chain-derivable fields (voteCloseHeight, eve coin
 * id, finalize bit) differ from the cached bootstrap, the bootstrap is
 * rewritten to match chain. Keeps the local cache aligned with chain
 * for offline-fallback correctness.
 */
export async function getElectionBallotsMerged(
  configJson: string,
  electionLauncherIdHex: string
): Promise<BallotBootstrap[]> {
  const bootstraps = listBallotBootstraps(electionLauncherIdHex);
  let chainBallots: BallotCoinSnapshot[];
  try {
    chainBallots = await listBallots(configJson);
  } catch {
    return bootstraps;
  }
  const bootByLauncher = new Map(
    bootstraps.map((b) => [normalizeHex32(b.ballotLauncherIdHex), b])
  );
  const merged: BallotBootstrap[] = [];
  for (const c of chainBallots) {
    const launcher = normalizeHex32(c.ballot_launcher_id);
    const boot = bootByLauncher.get(launcher);
    bootByLauncher.delete(launcher);
    const row = chainSnapshotToBootstrap(c, boot);
    if (
      !boot ||
      boot.voteCloseHeight !== row.voteCloseHeight ||
      boot.eveBallotCoinIdHex !== row.eveBallotCoinIdHex ||
      !!boot.finalized !== !!row.finalized
    ) {
      writeBallotBootstrap(row);
    }
    merged.push(row);
  }
  for (const boot of bootByLauncher.values()) {
    merged.push(boot);
  }
  return merged;
}

/**
 * Get a single ballot's canonical state. Mirrors live_integration.mjs's
 * `wasm.getBallot(config, ballotId)` point lookup. Chain-derives
 * voteCloseHeight, eveBallotCoinIdHex, outcomeDomainHashHex, finalized
 * bit, and voteOutcomeHex; merges bootstrap for dApp-only metadata
 * (label, choices, voteThresholdNum/Den, registration snapshots).
 *
 * Returns null only when both chain and bootstrap miss — usually that
 * means a wrong ballot id or an election that never minted this ballot.
 * If the chain walk fails (network blip), falls back to bootstrap.
 *
 * Side effect: when chain values differ from bootstrap, the bootstrap
 * is rewritten to match (chain wins). Aligns the cache with chain truth.
 */
export async function getBallotMerged(
  configJson: string,
  electionLauncherIdHex: string,
  ballotLauncherIdHex: string
): Promise<BallotBootstrap | null> {
  const boot = readBallotBootstrap(electionLauncherIdHex, ballotLauncherIdHex);
  let chainBallot: BallotCoinSnapshot | null;
  try {
    chainBallot = await getBallot(configJson, ballotLauncherIdHex);
  } catch {
    return boot;
  }
  if (!chainBallot) return boot;
  const row = chainSnapshotToBootstrap(chainBallot, boot ?? undefined);
  if (
    !boot ||
    boot.voteCloseHeight !== row.voteCloseHeight ||
    boot.eveBallotCoinIdHex !== row.eveBallotCoinIdHex ||
    !!boot.finalized !== !!row.finalized ||
    boot.outcomeDomainHashHex !== row.outcomeDomainHashHex
  ) {
    writeBallotBootstrap(row);
  }
  return row;
}
