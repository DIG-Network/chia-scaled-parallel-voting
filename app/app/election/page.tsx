"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import {
  Suspense,
  useEffect,
  useState,
  useCallback,
  useMemo,
  useRef,
} from "react";
import { useSearchParams } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import {
  coinRecordByName,
  CoinRecord,
  isConsensusRetriablePushError,
  peakHeight,
  pushTx,
} from "../lib/coinset";
import type { SpendBundleJson } from "../lib/coinset";
import {
  upsertElection,
  parseShareablePayload,
  canonicalCatTail0x,
  makeChoices,
  type ElectionChoice,
} from "../lib/elections";
import {
  readElectionBootstrap,
  writeElectionBootstrap,
  mergeBootstrapPubkeyRegistered,
  type ElectionBootstrap,
} from "../lib/electionBootstrap";
import { recoverAndPersistElectionStartHeight } from "../lib/recoverElectionStartHeight";
import { getElectionBallotsMerged } from "../lib/electionBallots";
import {
  writeBallotBootstrap,
  readBallotBootstrap,
  pickOpenBallotForVoting,
  type BallotBootstrap,
} from "../lib/ballotBootstrap";
import {
  formatCat,
  formatXch,
  parseCat,
  truncHex,
  normalizeHex32,
} from "../lib/units";
import {
  discoverCatCollateralForRegistration,
  catCollateralDedupeKey,
  type CollateralScanProgress,
} from "../lib/catCollateralDiscovery";
import { findSyntheticPkForWalletAddress } from "../lib/sageSyntheticKey";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { createChainBackend } from "../lib/chainBackend";
import { walletConnect } from "../lib/walletConnectInstance";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { pollUntilConfirmed } from "../lib/pollUntil";
import { getWasm } from "../lib/sdk";

/** WASM `CollectVotesStage` (camelCase) from collectVotesWithProgress. */
type WasmCollectVotesStage =
  | "syncElectionSingleton"
  | "fetchHintCoins"
  | "fetchParentSpend"
  | "decodeBallot";

type FinalizeCollectPayload = {
  voterIndex: number;
  votersTotal: number;
  stage: WasmCollectVotesStage;
  ballotsCollected: number;
};

type ElectionFinalizeModalState = {
  title: string;
} & (
  | {
      phase: "collect";
      detail: string;
      collect?: FinalizeCollectPayload | null;
    }
  | { phase: "tally"; detail: string }
  | { phase: "prove"; detail: string; outcomeSummary?: string }
  | { phase: "verify"; detail: string }
  | { phase: "submit"; detail: string }
);

function finalizeCollectStageLabel(stage: WasmCollectVotesStage): string {
  switch (stage) {
    case "syncElectionSingleton":
      return "Syncing election singleton and voter registry";
    case "fetchHintCoins":
      return "Fetching hinted ballot coins (indexer)";
    case "fetchParentSpend":
      return "Loading parent registration spend";
    case "decodeBallot":
      return "Parsing ballot memos (CLVM)";
    default:
      return "Collecting ballots";
  }
}

/** Three coarse sub-steps per registrant for a progress bar approximation. */
function finalizeCollectSubstepWeight(stage: WasmCollectVotesStage): number {
  switch (stage) {
    case "fetchHintCoins":
      return 0;
    case "fetchParentSpend":
      return 1;
    case "decodeBallot":
      return 2;
    case "syncElectionSingleton":
      return 0;
    default:
      return 0;
  }
}

function finalizeCollectHarvestPct(collect: FinalizeCollectPayload): number {
  const n = collect.votersTotal;
  if (n <= 0) return collect.stage === "syncElectionSingleton" ? 0 : 0;
  const done =
    Math.min(n, collect.voterIndex) * 3 + finalizeCollectSubstepWeight(collect.stage);
  return Math.min(100, Math.round((done / (n * 3)) * 100));
}

// PURE-SPA ROUTING: the launcher id comes from a `?id=...` query
// string (set by the home page's `<Link href="/election/?id=...">`
// and by the create page's redirect). We can't use a dynamic
// segment (`[launcherId]/page.tsx`) because static export
// (`output: "export"`) requires a build-time `generateStaticParams`
// list — there's no such list for arbitrary launcher hashes.
//
// CRITICAL WASM IMPORT PATTERN: components that touch wasm MUST
// load via `dynamic(async () => { ... }, { ssr: false })`. Top-
// level `import "chip-voting-wasm"` crashes the prerender pass.
/**
 * Per-ballot listing under one election. Reads the ballot bootstrap
 * (populated by handleCreateAndLaunchBallot or share-bundle import),
 * renders one row per ballot with its status badge and a Select
 * button. Selection drives handleVote / handleChangeVote /
 * handleFinalize.
 *
 * Status pack:
 *   active    — vote_close_height > current peak. Open for voting.
 *   expired   — close passed, no finalize record yet.
 *   finalized — finalizedAtHeight set in bootstrap.
 */
function BallotsList(props: {
  electionLauncherIdHex: string;
  configJson: string;
  currentPeak: number;
  refreshKey: number;
}) {
  const [ballots, setBallots] = useState<
    import("../lib/ballotBootstrap").BallotBootstrap[]
  >([]);
  useEffect(() => {
    if (!props.configJson) return;
    let cancelled = false;
    void (async () => {
      const all = await getElectionBallotsMerged(
        props.configJson,
        props.electionLauncherIdHex
      );
      if (cancelled) return;
      // Sort: open ballots first (sorted by close-height ascending —
      // soonest-to-close at the top), then closed-not-finalized,
      // then finalized.
      const status = (b: typeof all[number]): number => {
        const finalized = !!b.finalized || !!b.finalizedAtHeight;
        const closed = b.voteCloseHeight <= props.currentPeak;
        if (finalized) return 2;
        if (closed) return 1;
        return 0;
      };
      all.sort((a, b) => {
        const sa = status(a);
        const sb = status(b);
        if (sa !== sb) return sa - sb;
        if (sa === 0) {
          return a.voteCloseHeight - b.voteCloseHeight;
        }
        return (b.launchedAtHeight ?? 0) - (a.launchedAtHeight ?? 0);
      });
      setBallots(all);
    })();
    return () => {
      cancelled = true;
    };
  }, [
    props.electionLauncherIdHex,
    props.configJson,
    props.refreshKey,
    props.currentPeak,
  ]);

  const electionIdParam = normalizeHex32(props.electionLauncherIdHex).replace(
    /^0x/,
    ""
  );

  if (ballots.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-bg)]/50 p-5">
        <h3 className="font-semibold mb-1">Ballots</h3>
        <p className="text-sm text-[var(--color-muted)]">
          No ballots in this session yet. The deployer can mint one above; voters
          can also import a share bundle that includes ballot bootstrap.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[var(--color-border)] p-5">
      <h3 className="font-semibold mb-3">Ballots ({ballots.length})</h3>
      <ul className="space-y-2">
        {ballots.map((b) => {
          const finalized = !!b.finalized || !!b.finalizedAtHeight;
          const closed = b.voteCloseHeight <= props.currentPeak;
          const blocksLeft = b.voteCloseHeight - props.currentPeak;
          const status = finalized ? "finalized" : closed ? "expired" : "active";
          const ballotIdParam = normalizeHex32(b.ballotLauncherIdHex).replace(
            /^0x/,
            ""
          );
          return (
            <li key={b.ballotLauncherIdHex}>
              <Link
                href={`/ballot?electionId=${electionIdParam}&ballotId=${ballotIdParam}`}
                className="block w-full text-left rounded-lg border border-[var(--color-border)] p-3 transition hover:border-[var(--color-accent)]/50 hover:bg-[var(--color-accent)]/[0.04]"
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mb-1">
                  <span
                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold ${
                      status === "active"
                        ? "bg-green-500/15 text-green-700 dark:text-green-400"
                        : status === "expired"
                          ? "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                          : "bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                    }`}
                  >
                    {status}
                  </span>
                  <span className="font-mono text-xs">
                    {truncHex(normalizeHex32(b.ballotLauncherIdHex), 10, 6)}
                  </span>
                  <span className="ml-auto text-[11px] text-[var(--color-muted)]">
                    Open ballot →
                  </span>
                </div>
                <div className="text-xs text-[var(--color-muted)] flex flex-wrap gap-x-4 gap-y-0.5">
                  <span>close height: {b.voteCloseHeight.toLocaleString()}</span>
                  {!closed && props.currentPeak > 0 ? (
                    <span>~{blocksLeft.toLocaleString()} blocks left</span>
                  ) : null}
                  {finalized ? (
                    <span>
                      {b.finalizedAtHeight && b.finalizedAtHeight > 0
                        ? `finalized @ ${b.finalizedAtHeight.toLocaleString()}`
                        : "finalized"}
                    </span>
                  ) : null}
                  {b.registrationVoteWeightSnapshot > 0 ? (
                    <span>
                      vote weight snapshot: {b.registrationVoteWeightSnapshot}
                    </span>
                  ) : null}
                </div>
              </Link>
            </li>
          );
        })}
      </ul>
      <p className="text-xs text-[var(--color-muted)] mt-3">
        Click a ballot to vote, change your vote, or finalize it.
        Active ballots accept votes; expired ones can be finalized by anyone
        holding the proving key (imported via share bundle).
      </p>
    </div>
  );
}

const ElectionPageInner = dynamic(
  async function DynamicElem() {
    const wasm = await getWasm();

    return function ElectionPage() {
      const searchParams = useSearchParams();
      const launcherIdRaw = searchParams?.get("id") ?? "";
      const launcherIdHex = launcherIdRaw
        ? "0x" + launcherIdRaw.replace(/^0x/, "").toLowerCase()
        : "";

      const { address } = useAppSelector((s) => s.wallet);
      /** Off-chain ElectionConfig bootstrap (sessionStorage). Chain is source of truth for tallies/sync. */
      const [session, setSession] = useState<ElectionBootstrap | null>(null);
      // STATES:
      //   "checking" — launcher lookup in flight OR polling coinset without
      //                a session bootstrap yet (cold permalink / indexer lag).
      //   "pending"  — session bootstrap exists but launcher coin not indexed
      //                yet (mempool UX). Poll until confirmed or timeout.
      //   "deployed" — launcher coin is on-chain.
      //   "not-found" — launcher still missing after the poll timeout.
      const [chainStatus, setChainStatus] = useState<
        "checking" | "pending" | "deployed" | "not-found"
      >("checking");
      // Polling tick — increments on each retry so the UI can show
      // "Confirmation poll #N (block ~52 s on mainnet)…".
      const [pendingPoll, setPendingPoll] = useState(0);

      // Live state.
      const [snapshot, setSnapshot] = useState<SyncSnapshotShape | null>(null);
      const [snapshotLoading, setSnapshotLoading] = useState(false);
      const [snapshotError, setSnapshotError] = useState<string | null>(null);

      /** Lifecycle ticker — Election Singleton is permanent (CHIP rev
       *  2026-05-02 doesn't have a per-election expiry; only ballots
       *  have vote_close_height). This tracks peak + ballotsCast +
       *  whether ANY tracked ballot has been finalized. Per-ballot
       *  expiry display lives in BallotsList. */
      const POLL_ELECTION_LC_MS = 32_000;
      type ElectionLifecycle =
        | { status: "idle" }
        | { status: "loading" }
        | { status: "error"; message: string }
        | {
            status: "ready";
            finalized: boolean;
            ballotsCast: number;
            peak: number;
          };

      const [electionLc, setElectionLc] = useState<ElectionLifecycle>({
        status: "idle",
      });
      const snapshotRef = useRef(snapshot);
      snapshotRef.current = snapshot;

      /**
       * On-chain vote payload for this voter (`collectVotes`). Refreshes with the
       * election lifecycle ticker and clears optimistic state once it matches.
       */
      const [indexedMyVoteDataHex, setIndexedMyVoteDataHex] = useState<
        string | null
      >(null);
      /** Shown immediately after mempool submit until coinset-backed reads pick up the ballot. */
      const [optimisticVoteDataHex, setOptimisticVoteDataHex] = useState<
        string | null
      >(null);
      /** Tally bars: refreshed with lifecycle ticks (same source as finalize). */
      const [onChainVoteTally, setOnChainVoteTally] = useState<
        { label: string; count: number; barKey: string }[]
      >([]);

      // VOTER IDENTITY (post-CHIP-bls-unify): the connected wallet's
      // FIRST synthetic pubkey is the voter identity. We fetch it
      // lazily — on first action that needs it — via
      // `chip0002_getPublicKeys`. No persistence needed: every flow
      // re-asks Sage so the Sage-managed key always matches what we
      // sign with. Cached in component state for the lifetime of
      // the page so the UI can render "registered as 0xab12…".
      const [voterPk, setVoterPk] = useState<string | null>(null);
      const [walletKeyNote, setWalletKeyNote] = useState<string | null>(null);
      const [pubkeyResolutionBusy, setPubkeyResolutionBusy] =
        useState(false);

      // UI state for actions.
      const [busy, setBusy] = useState<null | string>(null);
      const [txStatus, setTxStatus] = useState<string | null>(null);
      const [error, setError] = useState<string | null>(null);
      /** Full-screen registration progress (collateral scan + build + sign). */
      const [registrationModal, setRegistrationModal] = useState<null | {
        title: string;
        detail: string;
      }>(null);
      /** Full-screen mint-ballot progress (funder discovery + sign + launch). */
      const [mintBallotModal, setMintBallotModal] = useState<null | {
        title: string;
        detail: string;
      }>(null);
      /** Blocking overlay while polling coinset until on-chain confirms a submitted bundle. */
      const [broadcastAwait, setBroadcastAwait] = useState<null | {
        title: string;
        detail: string;
      }>(null);
      /** Finalize overlay: collect ballots → Groth16 → Sage mempool submit */
      const [finalizeModal, setFinalizeModal] =
        useState<ElectionFinalizeModalState | null>(null);

      /** Puzzle hash that receives registration-fee payout on successful finalize (decoded Sage address). */
      const [finalizePayoutPh, setFinalizePayoutPh] = useState<string | null>(
        null
      );

      /**
       * The ballot the voter / operator currently selected from the
       * Ballots list. CHIP rev 2026-05-02 model: an election has many
       * ballots; cast_vote / change_vote / finalize each act on ONE
       * specific ballot. When unset, handlers fall back to the
       * "newest open" / "newest closed" pickers so the existing
       * single-ballot flow keeps working for elections with one
       * active ballot.
       */
      const [selectedBallotId, setSelectedBallotId] = useState<string | null>(
        null
      );
      /**
       * Force re-render of ballots list when the bootstrap changes
       * (e.g., handleCreateAndLaunchBallot writes a new entry).
       */
      const [ballotsListEpoch, setBallotsListEpoch] = useState(0);

      /**
       * Synchronously-resolved bootstrap for the currently-selected
       * ballot. Drives the per-ballot choice rendering in the Step 2
       * vote / change-vote panels so radio buttons show the
       * SELECTED ballot's choices, not a stale election-wide list.
       */
      const selectedBallotData = useMemo<BallotBootstrap | null>(() => {
        if (!selectedBallotId) return null;
        return readBallotBootstrap(launcherIdHex, selectedBallotId);
      }, [selectedBallotId, launcherIdHex, ballotsListEpoch]);

      /**
       * Comma-separated voter choice labels for the next ballot mint.
       * Each label maps to vote_data = sha256("vote:" + label) at
       * cast time. CHIP rev 2026-05-02 makes choices per-ballot —
       * different ballots can pose different questions under the same
       * election.
       */
      const [mintBallotChoices, setMintBallotChoices] = useState("Yes,No");
      // M12: per-election vote-mode lock — null while we haven't read
      // the chain yet, "ff…ff" sentinel for "no lock" (operator picks
      // per-ballot), "00…00" for "lock to Mode1Free", any other 32-byte
      // hex for "lock to that exact sorted-options merkle root".
      const [electionVoteModeLockHex, setElectionVoteModeLockHex] =
        useState<string | null>(null);
      // M12: when election is locked-Restricted, surface the labels
      // (operator persisted them in localStorage at /create time —
      // see chipVoteOptionLabels:<root> from M11).
      const [lockedRestrictedLabels, setLockedRestrictedLabels] =
        useState<string[] | null>(null);
      /**
       * Operator input: how many blocks the new ballot stays open
       * for voting after launch. The on-chain `vote_close_height`
       * is set to `peak + mintBallotBlocks` at create-ballot time
       * and is curried into the eve Ballot Coin. Mainnet block
       * cadence is ~52s, so 50 blocks ≈ 25 min, 1500 blocks ≈ ~21h.
       */
      const [mintBallotBlocks, setMintBallotBlocks] = useState("50");

      /**
       * CAT amount (decimal string, 3 fractional digits) to lock when registering.
       * On-chain minimum is `ElectionConfig.collateral_amount`; voters may lock more for weight.
       */
      const [registrationLockCollateralCat, setRegistrationLockCollateralCat] =
        useState("");
      const regLockInitLauncherRef = useRef<string>("");

      // ── Session bootstrap + verify launcher coin on-chain ────────
      // ElectionConfig JSON is participant-distributed metadata (CHIP SDK model);
      // ballots, registrations, finalize lock, etc. all come from chain reads.
      // Bootstrap lives in sessionStorage so the election page never reads `chip.elections`.
      useEffect(() => {
        if (!launcherIdRaw) return;
        const boot = readElectionBootstrap(launcherIdHex);
        setSession(boot);

        let cancelled = false;
        const start = Date.now();
        const TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
        const POLL_MS = 6_000;

        const tick = async () => {
          if (cancelled) return;
          try {
            const launcher = await coinRecordByName(launcherIdHex);
            if (cancelled) return;
            if (launcher) {
              setChainStatus("deployed");
              return;
            }
          } catch {
            /* network blip — retry */
          }
          if (cancelled) return;
          const elapsed = Date.now() - start;
          const bootNow = readElectionBootstrap(launcherIdHex);

          // No launcher yet: keep polling (bootstrap or cold open) until timeout.
          if (elapsed >= TIMEOUT_MS) {
          setChainStatus("not-found");
          return;
        }
          setChainStatus(bootNow ? "pending" : "checking");
          setPendingPoll((n) => n + 1);
          setTimeout(tick, POLL_MS);
        };
        void tick();

        return () => {
          cancelled = true;
        };
      }, [launcherIdHex, launcherIdRaw]);

      // Default registration lock to this election's minimum when the launcher (or first session) appears.
      useEffect(() => {
        if (!launcherIdHex || !session?.configJson) return;
        if (regLockInitLauncherRef.current === launcherIdHex) return;
        regLockInitLauncherRef.current = launcherIdHex;
        try {
          const c = JSON.parse(session.configJson);
          const min = BigInt(String(c.collateral_amount ?? 0));
          if (min >= 1n) {
            setRegistrationLockCollateralCat(formatCat(min));
          }
        } catch {
          /* ignore */
        }
      }, [launcherIdHex, session?.configJson]);

      // ── Resolve voter pubkey from Sage ────────────────────────────
      // Use the SAME synthetic pubkey that owns `chia_getAddress`:
      // decode address → puzzle hash (chia-wallet-sdk), then paginate
      // chip0002_getPublicKeys until standardPuzzleHash(pubkey) matches.
      // Never blindly use getPublicKeys(1, 0): the user's active profile
      // may not be account offset 0, and naive bech32 decode is wrong on
      // Chia payloads (needs Address.decode).
      useEffect(() => {
        if (!address || !launcherIdHex) {
          setVoterPk(null);
          setWalletKeyNote(null);
          setPubkeyResolutionBusy(false);
          return;
        }
        let cancelled = false;
        setPubkeyResolutionBusy(true);
        setWalletKeyNote(null);
        (async () => {
          try {
            const pk = await findSyntheticPkForWalletAddress(address);
            if (cancelled) return;
            if (!pk) {
              setWalletKeyNote(
                "Could not match your receive address to a Sage synthetic " +
                  "key. Registration still scans every synthetic key Sage " +
                  "returns until collateral is found."
              );
              setVoterPk(null);
              return;
            }
            setWalletKeyNote(null);
            setVoterPk(pk);
          } catch (e: unknown) {
            const msg =
              e instanceof Error ? e.message : typeof e === "string" ? e : String(e);
            setError(`Resolving Sage voter key failed: ${msg}`);
            setVoterPk(null);
          } finally {
            if (!cancelled) setPubkeyResolutionBusy(false);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [address, launcherIdHex]);

      // ── Discover prior registrations for the connected Sage on-chain.
      //     If a fresh browser / share-bundle import has no registered pubkey
      //     in the bootstrap yet, scan Sage's synthetic keys and look up each
      //     candidate's voter_hint via coinset. Any match means that key
      //     already registered for this election — merge it back into the
      //     bootstrap so the UI immediately reflects "registered" state.
      const [priorRegScanBusy, setPriorRegScanBusy] = useState<string | null>(null);
      useEffect(() => {
        if (!address?.trim() || !session) return;
        // Already know at least one registered pubkey — don't re-scan.
        if ((session.registeredPubkeysHex ?? []).length > 0) return;
        const cfg = (() => {
          try { return JSON.parse(session.configJson); } catch { return null; }
        })();
        if (!cfg?.election_launcher_id_hex || !cfg?.cat_tail_hash_hex) return;

        let cancelled = false;
        (async () => {
          try {
            setPriorRegScanBusy("Checking on-chain for existing registrations…");
            const { discoverPriorRegistrations } = await import(
              "../lib/priorRegistrationDiscovery"
            );
            const preferredPk = await findSyntheticPkForWalletAddress(address);
            if (cancelled) return;
            const hits = await discoverPriorRegistrations({
              electionLauncherIdHex:
                "0x" + String(cfg.election_launcher_id_hex).replace(/^0x/, ""),
              catTailHashHex:
                "0x" + String(cfg.cat_tail_hash_hex).replace(/^0x/, ""),
              preferredSyntheticPkHex: preferredPk,
              stopOnFirst: true,
              onProgress: (p) => {
                if (cancelled) return;
                if (p.phase === "receive_key") {
                  setPriorRegScanBusy(
                    "Checking your receive-address synthetic key for an existing registration…"
                  );
                } else {
                  setPriorRegScanBusy(
                    `Scanning Sage synthetic keys for prior registration ` +
                      `(${p.keysChecked.toLocaleString()} checked)…`
                  );
                }
              },
            });
            if (cancelled) return;
            if (hits.length > 0) {
              const found = hits[0].syntheticPkHex;
              const merged = mergeBootstrapPubkeyRegistered(launcherIdHex, found);
              if (merged) {
                setSession(merged);
                setVoterPk(found);
              }
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            console.warn("[priorRegistrationDiscovery] failed:", msg);
          } finally {
            if (!cancelled) setPriorRegScanBusy(null);
          }
        })();

        return () => {
          cancelled = true;
        };
      }, [address, launcherIdHex, session]);

      // ── Finalize reward destination: standard PH for connected receive address.
      useEffect(() => {
        if (!address?.trim()) {
          setFinalizePayoutPh(null);
          return;
        }
        let cancelled = false;
        setFinalizePayoutPh(null);
        void (async () => {
          const ph = await puzzleHashHexFromWalletAddress(address.trim());
          if (!cancelled && ph) setFinalizePayoutPh(ph);
        })();
        return () => {
          cancelled = true;
        };
      }, [address]);

      // ── Sync snapshot from chain ──────────────────────────────────
      // CHIP rev 2026-05-02: the whole-election `syncSnapshot` walked
      // the chain to populate finalized + vote outcome + voter set in
      // one call. The new model splits that across the Election
      // Singleton (registration state only) and per-ballot bootstrap
      // (ballot finalize state). We synthesize the legacy
      // SyncSnapshotShape so the existing JSX consumers don't need
      // rewriting:
      //   * registrationCount / registrationMerkleRootHex / smtRootHex
      //     come from `wasm.readElectionSingletonState`.
      //   * votersHex falls back to `session.registeredPubkeysHex`
      //     (UI-tracked locally; accurate for voters this session
      //     observed register).
      //   * finalized / voteOutcomeHex aggregate the bootstrap's per-
      //     ballot finalize records — true iff at least one ballot
      //     has been finalized.
      //   * accumulatedFees is no longer surfaced in the new model
      //     (no on-chain fee accumulator); reported as 0.
      const syncSnapshot = useCallback(async () => {
        if (!session) return;
        setSnapshotLoading(true);
        setSnapshotError(null);
        try {
          const backend = createChainBackend();
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(
            session?.electionStartHeight ??
              cfg.election_start_height ??
              0
          );
          const stateJson = await wasm.readElectionSingletonState(
            backend as any,
            session.configJson,
            BigInt(electionStartHeight)
          );
          const state = JSON.parse(stateJson) as {
            coinIdHex: string;
            registrationMerkleRootHex: string;
            registrationCount: number;
            registrationVoteWeight: number;
            electionStartHeight: number;
            voteModeLockHex?: string;
          };
          // M12: capture the per-election ballot-mode lock so the
          // mint-ballot modal can render the right UI + reject mismatched
          // vote_options_root submissions. `null` until first sync.
          if (state.voteModeLockHex) {
            setElectionVoteModeLockHex(state.voteModeLockHex);
            // Hydrate locked-restricted labels from localStorage when
            // the lock is a non-sentinel root (M11 wrote them under
            // chipVoteOptionLabels:<root>).
            const lockHex = state.voteModeLockHex.replace(/^0x/, "");
            const NO_LOCK = "ff".repeat(32);
            const FREE_LOCK = "00".repeat(32);
            if (lockHex !== NO_LOCK && lockHex !== FREE_LOCK) {
              try {
                const raw = window.localStorage.getItem(
                  `chipVoteOptionLabels:${state.voteModeLockHex}`
                );
                if (raw) {
                  const parsed = JSON.parse(raw) as { labels?: string[] };
                  if (Array.isArray(parsed.labels) && parsed.labels.length > 0) {
                    setLockedRestrictedLabels(parsed.labels);
                  }
                }
              } catch {
                // labels aren't local — modal will fall back to showing
                // just the merkle root.
              }
            }
          }
          const ballots = await getElectionBallotsMerged(
            session.configJson,
            launcherIdHex
          );
          const finalizedBallot = ballots.find(
            (b) => b.finalized || !!b.finalizedAtHeight
          );
          const snap: SyncSnapshotShape = {
            registrationCount: state.registrationCount,
            registrationVoteWeight: state.registrationVoteWeight,
            registrationMerkleRootHex: state.registrationMerkleRootHex,
            finalized: !!finalizedBallot,
            voteOutcomeHex: finalizedBallot?.voteOutcomeHex ?? "0x" + "0".repeat(64),
            electionStartHeight: state.electionStartHeight,
            votersHex: session.registeredPubkeysHex ?? [],
            smtRootHex: state.registrationMerkleRootHex,
          };
          setSnapshot(snap);
          // Self-heal: when the sync recovers a non-zero
          // electionStartHeight from chain (post-launch /
          // post-register, where apply_singleton_spend evolved the
          // genesis state), persist it back to the bootstrap so
          // future voting / register / release flows have the right
          // value without needing the deployer's submission peak.
          if (
            state.electionStartHeight > 0 &&
            (session.electionStartHeight ?? 0) !== state.electionStartHeight
          ) {
            const merged: ElectionBootstrap = {
              ...session,
              electionStartHeight: state.electionStartHeight,
            };
            writeElectionBootstrap(merged);
            setSession(merged);
          }
        } catch (e: any) {
          setSnapshotError(e?.message ?? String(e));
        } finally {
          setSnapshotLoading(false);
        }
      }, [session, launcherIdHex]);

      // Chain-derive electionStartHeight once per launcher, BEFORE
      // syncSnapshot reads any singleton state. The bootstrap value
      // is set at deploy time (peak); the launcher confirms 1-N
      // blocks later, so the cached value can drift. Mirrors
      // live_integration.mjs:recoverElectionStartHeightOrFail —
      // every chain read should start from a chain-validated ESH,
      // not the cached deploy-peak hint. Helper persists the
      // recovered value back to the bootstrap so all downstream
      // session?.electionStartHeight reads pick it up.
      const eshVerifiedRef = useRef<string>("");
      useEffect(() => {
        if (chainStatus !== "deployed" || !session) return;
        const key = `${launcherIdHex}|${session.configJson.length}`;
        if (eshVerifiedRef.current === key) return;
        eshVerifiedRef.current = key;
        let cancelled = false;
        void (async () => {
          const recovered = await recoverAndPersistElectionStartHeight(
            launcherIdHex,
            session.configJson
          );
          if (cancelled) return;
          if (recovered != null && recovered !== session.electionStartHeight) {
            const fresh = readElectionBootstrap(launcherIdHex);
            if (fresh) setSession(fresh);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [chainStatus, launcherIdHex, session]);

      useEffect(() => {
        if (chainStatus === "deployed") {
          syncSnapshot();
        }
      }, [chainStatus, syncSnapshot]);

      useEffect(() => {
        if (chainStatus !== "deployed" || !session) {
          setElectionLc({ status: "idle" });
          return;
        }

        const configJson = session.configJson;

        let cancelled = false;

        async function tick(): Promise<void> {
          if (cancelled) return;

          try {
            if (!cancelled) {
              setElectionLc((prev) =>
                prev.status === "ready" ? prev : { status: "loading" }
              );
            }

            const backend = createChainBackend();
            // CHIP rev 2026-05-02: votes are per-ballot. Aggregate
            // ballot count across every ballot bootstrap we know
            // about; for each, query its on-chain Voting Coin
            // lineage via collectVotesForBallot.
            const allBallots = await getElectionBallotsMerged(
              configJson,
              launcherIdHex
            );
            const voterPubkeysJson = JSON.stringify(
              session?.registeredPubkeysHex ?? []
            );
            let ballotsCast = 0;
            for (const b of allBallots) {
              try {
                const rowsJson = (await wasm.collectVotesForBallot(
                  backend as any,
                  configJson,
                  b.ballotLauncherIdHex,
                  voterPubkeysJson
                )) as string;
                const rows = JSON.parse(rowsJson);
                if (Array.isArray(rows)) ballotsCast += rows.length;
              } catch {
                /* swallow per-ballot errors — a single missing ballot
                   shouldn't blank the lifecycle status. */
              }
            }

            // The Election Singleton itself doesn't carry a "finalized"
            // bit — that's a per-ballot state in the new model. We
            // treat the snapshot as finalized iff at least one tracked
            // ballot has a finalize confirmation in its bootstrap.
            const tipFinalized = allBallots.some(
              (b) => b.finalized || !!b.finalizedAtHeight
            );

            if (cancelled) return;

            const peak = await peakHeight();
            if (peak === null) {
              if (!cancelled) {
                setElectionLc({
                  status: "error",
                  message: "Peak height unavailable.",
                });
              }
              return;
            }

            if (!cancelled) {
              setElectionLc({
                status: "ready",
                finalized:
                  tipFinalized || snapshotRef.current?.finalized === true,
                ballotsCast,
                peak,
              });
            }
          } catch (e: unknown) {
            if (!cancelled) {
              const msg =
                e instanceof Error
                  ? e.message
                  : typeof e === "string"
                    ? e
                    : String(e);
              setElectionLc({ status: "error", message: msg });
            }
          }
        }

        void tick();
        const id = window.setInterval(() => void tick(), POLL_ELECTION_LC_MS);
        return () => {
          cancelled = true;
          window.clearInterval(id);
        };
      }, [chainStatus, session, wasm, snapshot]);

      const pullFreshSnapshot = useCallback(async (): Promise<SyncSnapshotShape | null> => {
        if (!session) return null;
        const backend = createChainBackend();
        const cfg = JSON.parse(session.configJson);
        const electionStartHeight = Number(
            session?.electionStartHeight ??
              cfg.election_start_height ??
              0
          );
        const stateJson = await wasm.readElectionSingletonState(
          backend as any,
          session.configJson,
          BigInt(electionStartHeight)
        );
        const state = JSON.parse(stateJson) as {
          coinIdHex: string;
          registrationMerkleRootHex: string;
          registrationCount: number;
          registrationVoteWeight: number;
          electionStartHeight: number;
        };
        const ballots = await getElectionBallotsMerged(
          session.configJson,
          launcherIdHex
        );
        const finalizedBallot = ballots.find(
          (b) => b.finalized || !!b.finalizedAtHeight
        );
        return {
          registrationCount: state.registrationCount,
          registrationVoteWeight: state.registrationVoteWeight,
          registrationMerkleRootHex: state.registrationMerkleRootHex,
          finalized: !!finalizedBallot,
          voteOutcomeHex: finalizedBallot?.voteOutcomeHex ?? "0x" + "0".repeat(64),
          electionStartHeight: state.electionStartHeight,
          votersHex: session.registeredPubkeysHex ?? [],
          smtRootHex: state.registrationMerkleRootHex,
        };
      }, [session, launcherIdHex]);

      const snapshotBrief = useCallback((s: SyncSnapshotShape | null | undefined) => {
        if (!s) return "";
        return [
          String(s.registrationCount),
          s.finalized ? "1" : "0",
          normalizeHex32(s.voteOutcomeHex),
          normalizeHex32(s.registrationMerkleRootHex),
          normalizeHex32(s.smtRootHex),
          String(s.electionStartHeight ?? 0),
          ...(s.votersHex ?? []).map((v) => normalizeHex32(v)).sort(),
        ].join("|");
      }, []);

      /** Local + wallet hints for which synthetic pubkey belongs to this user for this election. */
      const registrationCandidatePubkeys = useMemo(() => {
        const arr = [
          ...(session?.registeredPubkeysHex ?? []),
          ...(voterPk ? [voterPk] : []),
        ];
        return [...new Set(arr)];
      }, [session?.registeredPubkeysHex, voterPk]);

      /** The Sage pubkey listed on-chain (may differ from receive-address-derived `voterPk` when CAT lives on another synthetic key). */
      const registeredAsPk = useMemo(() => {
        const vh = snapshot?.votersHex;
        if (!vh?.length) return null;
        for (const pk of registrationCandidatePubkeys) {
          const want = normalizeHex32(pk);
          if (vh.some((hex) => normalizeHex32(hex) === want)) {
            return pk;
          }
        }
        return null;
      }, [snapshot?.votersHex, registrationCandidatePubkeys]);

      /** Key to pass into WASM for vote / collateral release — must match votersHex for registered users. */
      const effectiveVoterPk = useMemo(() => {
        const vh = snapshot?.votersHex;
        if (voterPk && vh?.length) {
          const want = normalizeHex32(voterPk);
          if (vh.some((hex) => normalizeHex32(hex) === want)) {
            return voterPk;
          }
        }
        return registeredAsPk ?? voterPk ?? null;
      }, [snapshot?.votersHex, voterPk, registeredAsPk]);

      const myReg = registeredAsPk !== null;

      // ── Per-voter locked amount lookup (your vote weight) ─────────
      // Drives the "Your weight" stat. The wasm export syncs the SMT
      // from chain (parsing real `locked_cat_mojos` from each register
      // CCA) and reads `smt.locked_amount(pk)`. Re-runs whenever the
      // chain snapshot mutates so register/release land update the
      // displayed weight without a manual refresh.
      const [myLockedAmount, setMyLockedAmount] = useState<bigint | null>(null);
      useEffect(() => {
        if (!session || !effectiveVoterPk || !myReg) {
          setMyLockedAmount(null);
          return;
        }
        const cfg = (() => {
          try {
            return JSON.parse(session.configJson);
          } catch {
            return null;
          }
        })();
        const electionStartHeight = Number(
          session?.electionStartHeight ?? cfg?.election_start_height ?? 0
        );
        if (!electionStartHeight) {
          setMyLockedAmount(null);
          return;
        }
        let cancelled = false;
        void (async () => {
          try {
            const backend = createChainBackend();
            const result = await wasm.getVoterLockedAmount(
              backend as any,
              session.configJson,
              effectiveVoterPk,
              wasm.WasmNetwork.Mainnet,
              BigInt(electionStartHeight)
            );
            if (cancelled) return;
            if (result == null || result === undefined) {
              setMyLockedAmount(null);
            } else {
              const n = typeof result === "number" ? result : Number(result);
              setMyLockedAmount(Number.isFinite(n) ? BigInt(Math.round(n)) : null);
            }
          } catch {
            if (!cancelled) setMyLockedAmount(null);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [
        session,
        effectiveVoterPk,
        myReg,
        snapshot?.registrationVoteWeight,
        snapshot?.registrationCount,
      ]);

      const lifecycleBallotsCast =
        electionLc.status === "ready" ? electionLc.ballotsCast : 0;

      useEffect(() => {
        setIndexedMyVoteDataHex(null);
        setOptimisticVoteDataHex(null);
        setOnChainVoteTally([]);
      }, [launcherIdHex]);

      useEffect(() => {
        if (
          chainStatus !== "deployed" ||
          !session?.configJson ||
          !effectiveVoterPk
        ) {
          setIndexedMyVoteDataHex(null);
          return;
        }
        let cancelled = false;
        void (async () => {
          try {
            const backend = createChainBackend();
            // Aggregate this voter's most-recent vote across all
            // ballots on chain (newest ballot wins if multiple).
            const allBallots = [
              ...(await getElectionBallotsMerged(
                session!.configJson,
                launcherIdHex
              )),
            ].sort(
              (a, b) => (b.launchedAtHeight ?? 0) - (a.launchedAtHeight ?? 0)
            );
            const pkWant = normalizeHex32(effectiveVoterPk);
            let found: string | null = null;
            for (const b of allBallots) {
              const rowsJson = (await wasm.collectVotesForBallot(
                backend as any,
                session!.configJson,
                b.ballotLauncherIdHex,
                JSON.stringify([effectiveVoterPk])
              )) as string;
              const rows = JSON.parse(rowsJson) as unknown[];
              for (const r of rows ?? []) {
                const row = r as Record<string, string | undefined>;
                const rk = normalizeHex32(
                  row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
                );
                if (rk !== pkWant) continue;
                const vd = row.vote_data_hex ?? row.voteDataHex ?? "";
                if (vd) {
                  const t = vd.trim();
                  found = t.startsWith("0x")
                    ? t.toLowerCase()
                    : `0x${normalizeHex32(t)}`;
                }
                break;
              }
              if (found) break;
            }
            if (!cancelled) {
              setIndexedMyVoteDataHex(found);
              setOptimisticVoteDataHex((prev) => {
                if (
                  !prev ||
                  !found ||
                  normalizeHex32(found) !== normalizeHex32(prev)
                ) {
                  return prev;
                }
                return null;
              });
            }
          } catch {
            if (!cancelled) setIndexedMyVoteDataHex(null);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [
        chainStatus,
        session?.configJson,
        effectiveVoterPk,
        wasm,
        lifecycleBallotsCast,
        optimisticVoteDataHex,
      ]);

      useEffect(() => {
        if (chainStatus !== "deployed" || !session?.configJson) {
          setOnChainVoteTally([]);
          return;
        }
        let cancelled = false;
        void (async () => {
          try {
            const backend = createChainBackend();
            // Tally aggregates votes across every ballot for this
            // election. Per-ballot model: each Voting Coin lineage
            // hangs off a specific ballot, so we walk each ballot
            // separately (chain-derived list) and union the rows.
            const allBallots = await getElectionBallotsMerged(
              session!.configJson,
              launcherIdHex
            );
            const voterPubkeysJson = JSON.stringify(
              session!.registeredPubkeysHex ?? []
            );
            const rows: { voteDataHex: string }[] = [];
            for (const b of allBallots) {
              try {
                const rawJson = (await wasm.collectVotesForBallot(
                  backend as any,
                  session!.configJson,
                  b.ballotLauncherIdHex,
                  voterPubkeysJson
                )) as string;
                if (cancelled) return;
                const raw = JSON.parse(rawJson) as unknown[];
                for (const r of raw ?? []) {
                  const row = r as Record<string, string | undefined>;
                  const vd = row.voteDataHex ?? row.vote_data_hex ?? "";
                  if (vd) rows.push({ voteDataHex: vd });
                }
              } catch {
                /* swallow per-ballot errors */
              }
            }
            if (cancelled) return;
            setOnChainVoteTally(
              computeOnChainVoteTallyFromWire(rows, session.choices)
            );
          } catch {
            if (!cancelled) setOnChainVoteTally([]);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [
        chainStatus,
        session?.configJson,
        wasm,
        lifecycleBallotsCast,
        optimisticVoteDataHex,
        launcherIdHex,
        session?.choices,
      ]);

      const resolvedMyVoteDataHex =
        indexedMyVoteDataHex ?? optimisticVoteDataHex;

      // CHIP rev 2026-05-02: "votes closed" is per-ballot. The
      // selected ballot drives whether voting / finalize buttons are
      // enabled — `votesClosed` here means "the SELECTED ballot's
      // vote_close_height has passed on chain, so cast/change-vote
      // would be rejected and finalize is now allowed."
      const votesClosed = useMemo<boolean>(() => {
        if (!selectedBallotData) return false;
        const peak =
          electionLc.status === "ready" ? electionLc.peak : 0;
        return peak > 0 && selectedBallotData.voteCloseHeight <= peak;
      }, [selectedBallotData, electionLc]);

      const waitBroadcastConfirm = useCallback(
        async (opts: {
          title: string;
          intro: string;
          predicate: () => Promise<boolean>;
        }): Promise<boolean> => {
          setBroadcastAwait({
            title: opts.title,
            detail: `${opts.intro}\n\nChecking chain…`,
          });
          const ok = await pollUntilConfirmed({
            predicate: opts.predicate,
            pollMs: 6000,
            timeoutMs: 5 * 60 * 1000,
            onAttempt: ({ attempt, elapsedMs }) => {
              setBroadcastAwait({
                title: opts.title,
                detail:
                  `${opts.intro}\n\n` +
                  `Poll #${attempt} — ${Math.round(
                    elapsedMs / 1000
                  )}s elapsed (mainnet ~52s/block).`,
              });
            },
          });
          setBroadcastAwait(null);
          await syncSnapshot();
          if (!ok) {
            setError(
              `${opts.title}: bundle was submitted but chain confirmation timed out after 5 min. ` +
                `Use Refresh state, or inspect coinset / your wallet's activity.`
            );
          }
          return ok;
        },
        [syncSnapshot, pullFreshSnapshot]
      );

      // ── CREATE + LAUNCH BALLOT FLOW (operator only) ──────────────
      //
      // Mints a Ballot Coin lineage under this election. Two on-chain
      // submissions:
      //   1. createBallotBundle — Sage signs the funder XCH coin
      //      (provides 2 mojos for the launcher coin), spends the
      //      Election Singleton's createBallot action.
      //   2. launchBallotBundle — second-spend of the launcher to
      //      mint the eve Ballot Coin (no AggSig — bundle's identity
      //      sig is sufficient).
      //
      // After both confirm, we capture the Election Singleton state
      // RIGHT BEFORE the launch and persist a per-ballot bootstrap so
      // every voter / finalizer / releaser sees the SAME snapshot the
      // ballot was minted with. Mirrors `phaseCreateBallot` +
      // `phaseLaunchBallot` from the integration test harness.
      const handleCreateAndLaunchBallot = async () => {
        if (!session?.provingKeyBase64) {
          setError("Only the deployer (holder of the Groth16 proving key) can mint a ballot.");
          return;
        }
        if (!address) {
          setError("Connect Sage Wallet first.");
          return;
        }
        const cfg = JSON.parse(session.configJson);
        let electionStartHeight = Number(
            session?.electionStartHeight ??
              cfg.election_start_height ??
              0
          );

        setError(null);
        setTxStatus(null);
        // Helper: keep the busy banner + the full-screen mint-ballot
        // modal in lockstep so each flow step shows up the same way
        // the other actions' modals do (deploy, register, finalize).
        const setMintStatus = (detail: string) => {
          setBusy(detail);
          setMintBallotModal({ title: "Mint a new ballot", detail });
        };
        setMintStatus("Creating ballot…");

        try {
          await walletConnect.waitForInit();

          // Belt-and-suspenders: re-validate ESH against chain right
          // before a write spend. The session-bootstrap effect above
          // pre-warms this on launcher confirm, but a long-lived tab
          // could go stale if the user idled past a reorg. Mirrors
          // live_integration.mjs:recoverElectionStartHeightOrFail.
          setMintStatus("Validating electionStartHeight against chain…");
          const recoveredNum = await recoverAndPersistElectionStartHeight(
            launcherIdHex,
            session.configJson
          );
          if (recoveredNum == null) {
            throw new Error(
              "Could not match this election's eve singleton against any " +
                "electionStartHeight in a ±60 block window. The most likely " +
                "cause is that the election was deployed with a different " +
                "puzzle revision than the dApp now uses (e.g. before the " +
                "weighted-voting upgrade). Deploy a fresh election with the " +
                "current SDK to use create_ballot."
            );
          }
          if (recoveredNum !== electionStartHeight) {
            electionStartHeight = recoveredNum;
            const fresh = readElectionBootstrap(launcherIdHex);
            if (fresh) setSession(fresh);
          }

          // ── 0. Parse voter choices for THIS ballot. ─────────────
          const cleanChoiceLabels = mintBallotChoices
            .split(",")
            .map((l) => l.trim())
            .filter((l) => l.length > 0);
          if (cleanChoiceLabels.length < 2) {
            throw new Error(
              "Enter at least two voter choices (comma-separated, e.g. \"Yes,No\")."
            );
          }
          if (new Set(cleanChoiceLabels).size !== cleanChoiceLabels.length) {
            throw new Error(
              "Voter choices must be unique — two labels with the same text would hash to the same vote_data."
            );
          }
          const ballotChoices = await makeChoices(cleanChoiceLabels);

          // ── 0a. M12: honor the election's vote-mode lock. Compute
          //     the vote_options_root the new ballot will be curried
          //     with, then validate against the election's lock.
          //
          //     vote_options_root scheme: sha256("vote:"+label) per
          //     option (matches the existing `makeChoices`/cast-vote
          //     hashing convention), sorted ascending, merkle-rooted
          //     via wasm.merkleRootOfSortedCoinIds.
          const NO_LOCK_HEX = "0x" + "ff".repeat(32);
          const FREE_LOCK_HEX = "0x" + "00".repeat(32);
          const lockHexNorm = (h: string | null): string =>
            h ? (h.startsWith("0x") ? h : "0x" + h).toLowerCase() : NO_LOCK_HEX;
          const electionLock = lockHexNorm(electionVoteModeLockHex);

          const optionHashesHex: string[] = [];
          for (const label of cleanChoiceLabels) {
            const enc = new TextEncoder().encode("vote:" + label);
            const ab = new ArrayBuffer(enc.byteLength);
            new Uint8Array(ab).set(enc);
            const buf = await window.crypto.subtle.digest("SHA-256", ab);
            const arr = new Uint8Array(buf);
            let s = "";
            for (let i = 0; i < arr.length; i++) {
              s += arr[i].toString(16).padStart(2, "0");
            }
            optionHashesHex.push(s);
          }
          const computedRootRaw = (await wasm.merkleRootOfSortedCoinIds(
            optionHashesHex.join("")
          )) as string;
          const computedRoot = computedRootRaw.startsWith("0x")
            ? computedRootRaw.toLowerCase()
            : ("0x" + computedRootRaw).toLowerCase();

          // Decide ballot's vote_options_root + reject mismatches.
          let ballotVoteOptionsRootHex: string;
          if (electionLock === FREE_LOCK_HEX) {
            // Locked Mode1Free — no per-ballot restriction allowed.
            ballotVoteOptionsRootHex = FREE_LOCK_HEX;
          } else if (electionLock === NO_LOCK_HEX) {
            // No election-level lock — per-ballot Restricted.
            ballotVoteOptionsRootHex = computedRoot;
          } else {
            // Locked Restricted — choices MUST hash to the locked root.
            if (computedRoot !== electionLock) {
              throw new Error(
                `This election is locked to a specific options root ` +
                  `(${electionLock.slice(0, 18)}…) but the entered choices ` +
                  `hash to ${computedRoot.slice(0, 18)}…. Use the locked ` +
                  `option list (see the read-only banner above the choices ` +
                  `field) — operator-set at /create time.`
              );
            }
            ballotVoteOptionsRootHex = electionLock;
          }

          // ── 1. Find an XCH coin in the operator's wallet to fund the launcher.
          //     Sage owns the coins — fetch them via chip0002_getAssetCoins
          //     which returns the puzzle reveal alongside each coin.
          //     Uncurrying the standard p2 puzzle gives the synthetic_pk
          //     directly — no chip0002_getPublicKeys scan needed.
          setMintStatus("Finding XCH funder coin…");
          const { listXchCoinsWithKeys } = await import("../lib/sageAssetCoins");
          const sageXch = await listXchCoinsWithKeys({
            minAmount: 100,
            includeLocked: false,
            limit: 200,
          });
          if (sageXch.length === 0) {
            throw new Error(
              "No spendable XCH coins in your wallet (need ≥ 100 mojos for the funder + change)."
            );
          }
          // Pick the largest coin so change > 0 (the StandardLayer
          // spend panics on `delegatedSpend([])` if change == 0).
          sageXch.sort((a, b) => Number(BigInt(b.coin.amount) - BigInt(a.coin.amount)));
          const sageFunder = sageXch[0];
          const funderCoin = {
            parentCoinInfo: sageFunder.coin.parent_coin_info.replace(/^0x/, ""),
            puzzleHash: sageFunder.coin.puzzle_hash,
            amount: sageFunder.coin.amount,
          };
          const synthPk = sageFunder.syntheticPkHex;

          // ── 2. Build the funder StandardLayer spend (unsigned —
          //      Sage signs it later as part of the bundle's AggSigMe
          //      sweep).
          const change = BigInt(funderCoin.amount) - 2n;
          const funderSpendBytes = wasm.buildXchFunderSpend(
            "0x" + funderCoin.parentCoinInfo,
            synthPk,
            BigInt(funderCoin.amount),
            change
          );

          // ── 3. Pick ballot params.
          const ballotSeed = new Uint8Array(32);
          globalThis.crypto.getRandomValues(ballotSeed);
          const ballotSeedHex =
            "0x" + Array.from(ballotSeed).map((b) => b.toString(16).padStart(2, "0")).join("");
          const peak = await peakHeight();
          if (!peak) throw new Error("Could not read chain peak");
          // Operator-configurable voting duration. Validates >0 and
          // an integer to avoid an off-by-one or NaN setting an
          // immediate-close ballot. Mainnet block cadence is ~52s.
          const blocksParsed = Number.parseInt(mintBallotBlocks.trim(), 10);
          if (!Number.isFinite(blocksParsed) || blocksParsed < 1) {
            throw new Error(
              "Voting duration (blocks) must be a positive integer."
            );
          }
          const voteCloseHeight = peak + blocksParsed;
          // Deterministic placeholder outcome domain. Production
          // deployments would tree-hash a structured proposal here.
          const outcomeDomainHashHex = "0x" + "01".repeat(32);
          const voteThresholdNum = 1;
          const voteThresholdDen = 2;

          const createParams = {
            ballotSeedHex,
            voteCloseHeight,
            outcomeDomainHashHex,
            // M12: per-ballot vote-mode commitment, gated against the
            // election's lock above.
            voteOptionsRootHex: ballotVoteOptionsRootHex,
          };

          // ── 4. createBallotBundle (singleton create_ballot action).
          setMintStatus("Building createBallot bundle…");
          const backend = createChainBackend();
          const createdJson = await wasm.createBallotBundle(
            backend as any,
            session.configJson,
            funderSpendBytes,
            JSON.stringify(createParams),
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const created = JSON.parse(createdJson) as {
            ballotLauncherIdHex: string;
            ballotCoinIdHex: string;
            spendBundleHex: string;
          };

          // ── 5. Sage signs the bundle's coin_spends (covers the
          //      funder's StandardLayer AggSigMe).
          setMintStatus("Awaiting Sage signature for createBallot…");
          const createBundleBytes = hexToBytes(created.spendBundleHex);
          const wcSpendsJson = wasm.extractWalletCoinSpendsFromBundle(createBundleBytes);
          const wcSpends = JSON.parse(wcSpendsJson);
          const sigHex = await walletConnect.signCoinSpends(wcSpends, false, false);
          if (!sigHex) throw new Error("Wallet rejected the createBallot signature request");

          setMintStatus("Verifying createBallot bundle locally…");
          const finalCreateBundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(wcSpends),
            sigHex
          );
          wasm.verifyBundleLocally(finalCreateBundleBytes, wasm.WasmNetwork.Mainnet);

          setMintStatus("Submitting createBallot bundle…");
          const createBundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(finalCreateBundleBytes)
          ) as SpendBundleJson;
          await pushTx(createBundleJson);

          const launcherIdToWatch = created.ballotLauncherIdHex;
          const launcherOk = await waitBroadcastConfirm({
            title: "Confirming ballot launcher",
            intro:
              `Waiting until the ballot launcher coin lands on chain. ` +
              `Launcher id ${launcherIdToWatch.slice(0, 10)}…`,
            predicate: async () => {
              const rec = await coinRecordByName(launcherIdToWatch);
              return !!rec && (rec.confirmedHeight ?? 0) > 0;
            },
          });
          if (!launcherOk) return;

          // ── 6. Capture pre-launch Election Singleton state — the
          //      registration snapshot the eve Ballot Coin will be
          //      curried with. Every later actor must mirror these.
          setBusy("Capturing election state snapshot…");
          const stateJson = await wasm.readElectionSingletonState(
            backend as any,
            session.configJson,
            BigInt(electionStartHeight)
          );
          const preLaunchState = JSON.parse(stateJson) as {
            registrationMerkleRootHex: string;
            registrationVoteWeight: number;
            registrationCount: number;
          };

          // ── 7. launchBallotBundle (launcher second-spend → eve).
          setMintStatus("Building launchBallot bundle…");
          const launchParams = {
            voteCloseHeight,
            outcomeDomainHashHex,
            voteThresholdNum,
            voteThresholdDen,
            // M12: MUST match createParams.voteOptionsRootHex byte-for-
            // byte — the predicted eve Ballot Coin puzzle hash includes
            // this in oracle's curry.
            voteOptionsRootHex: ballotVoteOptionsRootHex,
          };
          const launchedJson = await wasm.launchBallotBundle(
            backend as any,
            session.configJson,
            "0x" + created.ballotLauncherIdHex.replace(/^0x/, ""),
            JSON.stringify(launchParams),
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const launched = JSON.parse(launchedJson) as {
            ballotLauncherIdHex: string;
            eveBallotCoinIdHex: string;
            eveBallotPuzzleHashHex: string;
            spendBundleHex: string;
          };

          setMintStatus("Verifying launchBallot bundle locally…");
          const launchBundleBytes = hexToBytes(launched.spendBundleHex);
          wasm.verifyBundleLocally(launchBundleBytes, wasm.WasmNetwork.Mainnet);

          setMintStatus("Submitting launchBallot bundle…");
          const launchBundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(launchBundleBytes)
          ) as SpendBundleJson;
          await pushTx(launchBundleJson);

          const eveIdToWatch = launched.eveBallotCoinIdHex;
          const eveOk = await waitBroadcastConfirm({
            title: "Confirming eve ballot coin",
            intro:
              `Waiting until the eve Ballot Coin (the launcher's first child) ` +
              `lands on chain. Eve coin id ${eveIdToWatch.slice(0, 10)}…`,
            predicate: async () => {
              const rec = await coinRecordByName(eveIdToWatch);
              return !!rec && (rec.confirmedHeight ?? 0) > 0;
            },
          });
          if (!eveOk) return;
          const eveRec = await coinRecordByName(eveIdToWatch);

          // ── 8. Persist per-ballot bootstrap so castVote / finalize
          //      / release can read the snapshot without a chain walk.
          const bb: BallotBootstrap = {
            electionLauncherIdHex: launcherIdHex,
            ballotLauncherIdHex: created.ballotLauncherIdHex,
            eveBallotCoinIdHex: launched.eveBallotCoinIdHex,
            eveBallotPuzzleHashHex: launched.eveBallotPuzzleHashHex,
            launchedAtHeight: eveRec?.confirmedHeight,
            voteCloseHeight,
            outcomeDomainHashHex,
            ballotSeedHex,
            voteThresholdNum,
            voteThresholdDen,
            registrationMerkleRootSnapshotHex: preLaunchState.registrationMerkleRootHex,
            registrationVoteWeightSnapshot: preLaunchState.registrationVoteWeight,
            registrationCountSnapshot: preLaunchState.registrationCount,
            addedAt: new Date().toISOString(),
            choices: ballotChoices,
            // M13: persist the per-ballot vote-mode commitment so
            // /ballot can render the right mode badge + UI without
            // re-walking chain.
            voteOptionsRootHex: ballotVoteOptionsRootHex,
          };
          writeBallotBootstrap(bb);
          setBallotsListEpoch((n) => n + 1);
          setSelectedBallotId(created.ballotLauncherIdHex);

          setTxStatus(
            `Ballot launched. close height ${voteCloseHeight} (~${50 * 52}s window). ` +
              `Voters can register / cast against ballot ${created.ballotLauncherIdHex.slice(0, 10)}…`
          );
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setBusy(null);
          setMintBallotModal(null);
        }
      };

      // ── REGISTER FLOW (post-CHIP-bls-unify) ──────────────────────
      // CAT collateral: try receive-address synthetic key, then page
      // chip0002_getPublicKeys until coinset finds a suitable coin or
      // Sage returns no more keys — see `discoverCatCollateralForRegistration`.
      const REGISTER_PUSH_MAX_ATTEMPTS = 12;
      const REGISTER_PUSH_RETRY_MS = 1200;

      const handleRegister = async () => {
        if (!session || !address) return;
        setError(null);
        setTxStatus(null);
        setBusy(null);
        setRegistrationModal({
          title: "Prepare registration",
          detail: "Connecting to Sage and searching for CAT collateral…",
        });

        const cfg = JSON.parse(session.configJson);
        const minColl = BigInt(String(cfg.collateral_amount ?? 0));
        const lockedMojos = parseCat(registrationLockCollateralCat.trim());
        if (lockedMojos === null) {
            throw new Error(
            "Enter a valid CAT lock amount (e.g. 1 or 1.25 — up to 3 decimal places)."
            );
          }
        if (lockedMojos < minColl) {
          throw new Error(
            `Locked collateral must be at least ${formatCat(minColl)} (this election's on-chain minimum).`
          );
        }
        if (lockedMojos > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(
            "Locked amount is too large for this browser build — use a smaller stake or the CLI."
          );
        }
        const collateralAmount = lockedMojos;
        const triedCatDedupeKeys = new Set<string>();

        try {
          await walletConnect.waitForInit();

          const onCollateralProgress = (p: CollateralScanProgress) => {
            if (p.phase === "receive_key") {
              setRegistrationModal({
                title: "Scanning for collateral",
                detail:
                  "Checking your Sage receive-address synthetic key against coinset…",
              });
            } else {
              setRegistrationModal({
                title: "Scanning for collateral",
                detail:
                  `Searching coinset for each additional synthetic key Sage returns.\n\n` +
                  `Keys checked so far: ${p.keysChecked.toLocaleString()} — this stops immediately when enough CAT collateral is found, or when the wallet runs out of keys to try.`,
              });
            }
          };

          for (let attempt = 0; attempt < REGISTER_PUSH_MAX_ATTEMPTS; attempt++) {
            if (attempt > 0) {
              await syncSnapshot();
              setRegistrationModal({
                title: "Retry registration",
                detail:
                  `Coinset conflict (e.g. MINTING_COIN — a spent coin still looks spendable).\n\n` +
                  `Using a different CAT UTXO and rebuilding (attempt ${attempt + 1}/${REGISTER_PUSH_MAX_ATTEMPTS})…`,
              });
              await new Promise((r) => setTimeout(r, REGISTER_PUSH_RETRY_MS));
            }

            const discovery = await discoverCatCollateralForRegistration({
              catTailHashHex: String(cfg.cat_tail_hash_hex ?? ""),
              collateralAmountMojos: collateralAmount,
              preferredSyntheticPkHex: voterPk,
              excludeDedupeKeys: triedCatDedupeKeys,
              onProgress: onCollateralProgress,
            });
            const signingPk = discovery.voterPk;
            const catCoin = discovery.catCoin;

            // ── Compute CAT input coin id (sha256(parent || ph || amount_be8)).
            //    The Sage-friendly buildCatRegistrationSpendForWallet
            //    walks the chain via voter_hint to find the lineage
            //    proof, so we no longer need reconstructCatLineage
            //    locally — just hand it the coin id.
            setRegistrationModal({
              title: "Build registration transaction",
              detail: "Building CAT collateral coin spend…",
            });
            const { Coin } = await import("chia-wallet-sdk-wasm");
            const catCoinIdBytes = new Coin(
              hexToBytes(catCoin.parentCoinInfo),
              hexToBytes(catCoin.puzzleHash),
              BigInt(catCoin.amount)
            ).coinId();
            const catCoinIdHex =
              "0x" +
              Array.from(catCoinIdBytes)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
            const catTailHex =
              "0x" + String(cfg.cat_tail_hash_hex ?? "").replace(/^0x/, "");
            const electionLauncherHex =
              "0x" + String(cfg.election_launcher_id_hex ?? "").replace(/^0x/, "");
            const backend = createChainBackend();
            const catParentSpendBytes = await wasm.buildCatRegistrationSpendForWallet(
              backend as any,
              signingPk,        // voter_pk (account-path / self-registering)
              signingPk,        // validator_synthetic_pk — self-registration
              catCoinIdHex,
              electionLauncherHex,
              catTailHex,
              collateralAmount
            );

            // CHIP rev 2026-05-02: no separate registration_fee /
            // mempool_fee inputs in the bundle. If a fee output is
            // desired, attach a free-standing XCH funder spend and
            // include it in the bundle's coin_spends list before
            // signing — out of scope for the standard register flow.

            // ── Build unsigned register coin_spends ─────────────
            setRegistrationModal({
              title: "Build registration transaction",
              detail: "Assembling unsigned register bundle (singleton + CAT)…",
            });
            const electionStartHeight = Number(
            session?.electionStartHeight ??
              cfg.election_start_height ??
              0
          );
            // Weighted voting: the wasm export now syncs the SMT
            // from chain internally (so per-voter `locked_amount`s
            // come from the on-chain register CCAs, not a flat
            // pubkey list this browser session happened to track).
            // We just pass our chosen lock amount; the puzzle re-
            // verifies it's >= the curried minimum.
            const unsignedJson = await wasm.registerBuildUnsignedCoinSpends(
              backend as any,
              session.configJson,
              signingPk,
              catParentSpendBytes,
              collateralAmount,
              wasm.WasmNetwork.Mainnet,
              BigInt(electionStartHeight)
            );
            const unsigned = JSON.parse(unsignedJson) as {
              coinSpends: SpendBundleJson["coin_spends"];
            };
            const wcSpends = unsigned.coinSpends;

            setRegistrationModal({
              title: "Sign in Sage",
              detail:
                (attempt === 0 ? "" : `Retry ${attempt + 1}/${REGISTER_PUSH_MAX_ATTEMPTS} — `) +
                "Approve signing on your device. The app submits via coinset.org.",
            });
            const sigHex = await walletConnect.signCoinSpends(
              wcSpends,
              true,   // partial — Sage returns aggregate of all wallet-key AggSigMe
              false   // no auto-submit
            );
            if (!sigHex) {
              throw new Error("Wallet rejected the signature request");
            }

            setRegistrationModal({
              title: "Submitting bundle",
              detail:
                attempt === 0
                  ? "Pushing signed spend bundle to coinset mempool…"
                  : `Retry ${attempt + 1}/${REGISTER_PUSH_MAX_ATTEMPTS} — submitting…`,
            });
            const regBundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
              JSON.stringify(wcSpends),
              sigHex
            );
            wasm.verifyBundleLocally(regBundleBytes, wasm.WasmNetwork.Mainnet);

            // Capture pre-push chain state. We poll for the SMT
            // root / registration count to flip — `votersHex` is
            // session-storage-derived and only updates AFTER this
            // confirm resolves, so polling it would deadlock.
            const baseline = snapshotBrief(await pullFreshSnapshot());

            try {
              const bundleJson = JSON.parse(
                wasm.bundleBytesToWalletJson(regBundleBytes)
              ) as SpendBundleJson;
              await pushTx(bundleJson);
            } catch (pushErr: unknown) {
              const lastTry = attempt >= REGISTER_PUSH_MAX_ATTEMPTS - 1;
              if (!isConsensusRetriablePushError(pushErr) || lastTry) {
                throw pushErr;
              }
              triedCatDedupeKeys.add(catCollateralDedupeKey(catCoin));
              console.warn(
                "[register] push_tx rejected; trying another CAT UTXO:",
                pushErr
              );
              continue;
            }

            setRegistrationModal(null);

            const regOk = await waitBroadcastConfirm({
              title: "Confirming registration",
              intro:
                "Waiting for the Election Singleton state (registration count + Merkle root) to advance after your register spend confirms.",
              predicate: async () => {
                const s = await pullFreshSnapshot();
                return snapshotBrief(s) !== baseline;
              },
            });
            if (!regOk) return;

            const merged = mergeBootstrapPubkeyRegistered(
              launcherIdHex,
              signingPk
            );
            if (merged) {
              setSession(merged);
              upsertElection({
                launcherIdHex: merged.launcherIdHex,
                configJson: merged.configJson,
                label: merged.label,
                addedAt: merged.addedAt ?? new Date().toISOString(),
                eveCoinIdHex: merged.eveCoinIdHex,
                provingKeyBase64: merged.provingKeyBase64,
                choices: merged.choices,
                registeredPubkeysHex: merged.registeredPubkeysHex,
              });
            }
            setVoterPk(signingPk);
            setTxStatus(
              `Registered. Locked ${formatCat(collateralAmount)} ${collateralAssetShort} — ` +
                `your vote weight on every ballot under this election is ${formatCat(collateralAmount)}.`
            );
            return;
          }

          throw new Error(
            "Registration exhausted mempool retries — wait for confirmations, split CAT holdings, then try Refresh state."
          );
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setRegistrationModal(null);
          setBusy(null);
        }
      };

      // ── VOTE FLOW ───────────────────────────────────────────────
      // Two paths:
      //   1. The election has `choices` → user picks one via radio
      //      buttons; we send `choice.voteDataHex` straight through.
      //   2. No choices → fall back to the freeform "type any text"
      //      input (legacy / power-user path); we sha256 the text.
      const handleRelease = async () => {
        if (!session || !effectiveVoterPk) return;
        setError(null);
        setTxStatus(null);
        setBusy("Releasing collateral…");
        try {
          const baseline = snapshotBrief(snapshot);
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(
            session?.electionStartHeight ??
              cfg.election_start_height ??
              0
          );
          const catTail = "0x" + String(cfg.cat_tail_hash_hex ?? "").replace(/^0x/, "");

          // ── 1. Find the voter's CURRENT registration coin via
          //      voter_hint. After cast_vote the reg coin gets
          //      recreated at a state-shifted ph that the static
          //      `freshRegistrationCoinPuzzleHash` no longer
          //      predicts. Filter out the released-CAT coin (also
          //      hinted with voter_hint).
          const voterHintHex = wasm.voterHint(
            "0x" + String(cfg.election_launcher_id_hex ?? "").replace(/^0x/, ""),
            catTail,
            effectiveVoterPk
          );
          const dest = wasm.standardPuzzleHash(effectiveVoterPk);
          const releasedCatPh = String(
            wasm.catOuterPuzzleHash(catTail, dest)
          )
            .replace(/^0x/, "")
            .toLowerCase();
          const backend = createChainBackend();
          setBusy("Locating registration coin via voter_hint…");
          const { coinRecordsByHint } = await import("../lib/coinset");
          const hintRecords = await coinRecordsByHint(voterHintHex, true);
          const unspentReg = hintRecords.find(
            (c) =>
              c.spentHeight === 0 &&
              String(c.puzzleHash).replace(/^0x/, "").toLowerCase() !== releasedCatPh
          );
          if (!unspentReg) {
            throw new Error(
              "No unspent Registration Coin at your voter_hint — already released, or never registered."
            );
          }
          // Compute coin id (sha256(parent || ph || amount be8)).
          const { Coin } = await import("chia-wallet-sdk-wasm");
          const coin = new Coin(
            hexToBytes(unspentReg.parentCoinInfo),
            hexToBytes(unspentReg.puzzleHash),
            BigInt(unspentReg.amount)
          );
          const regCoinIdBytes = coin.coinId();
          const regCoinIdHex =
            "0x" +
            Array.from(regCoinIdBytes)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");

          // ── 2. Voter pubkey list — must match on-chain SMT. The
          //      session bootstrap tracks every voter we know about.
          //      Empty list = SMT root mismatch downstream; the SDK
          //      surfaces a clear "re-sync" error.
          // Weighted voting: SMT is reconstructed from chain inside
          // wasm — no need to thread a voter_pubkeys list (each
          // voter's locked_amount is parsed from the on-chain
          // register announcement CCAs).

          // ── 3. Build unsigned coin_spends (Sage signs externally).
          setBusy("Building release coin_spends…");
          const unsignedJson = await wasm.releaseCollateralBuildUnsignedCoinSpends(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            regCoinIdHex,
            dest,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const unsigned = JSON.parse(unsignedJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
          };

          setBusy("Awaiting Sage signature on bundle…");
          const sigHex = await walletConnect.signCoinSpends(
            unsigned.coinSpends,
            true,
            false
          );
          if (!sigHex) {
            throw new Error("Wallet rejected the signature request");
          }

          setBusy("Assembling and verifying bundle…");
          const relBundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(unsigned.coinSpends),
            sigHex
          );
          wasm.verifyBundleLocally(relBundleBytes, wasm.WasmNetwork.Mainnet);

          setBusy("Submitting collateral release bundle (coinset)…");
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(relBundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          const released = await waitBroadcastConfirm({
            title: "Confirming collateral release",
            intro:
              "Waiting until synced election state changes after your release spend clears.",
            predicate: async () => {
              const s = await pullFreshSnapshot();
              return snapshotBrief(s) !== baseline;
            },
          });
          if (released) {
            setTxStatus(
              `Deregistered. Your locked ${collateralAssetShort} CAT is back in ` +
                `your wallet and you've been removed from the election's voter set.`
            );
            // Phase 1c: refresh the chain snapshot so the UI immediately
            // reflects the deregistration. Without this, snapshot
            // stays stale (myReg → true → release button still shown
            // → user clicks again → "No unspent Registration Coin"
            // error). Also re-runs syncSnapshot to refresh the
            // registered-voter list + per-voter weight derivations.
            syncSnapshot();
          }
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setBusy(null);
        }
      };

      // ── FINALIZE FLOW — modal + Sage bundle submit ──────────────

      // (handleOracle removed — CHIP rev 2026-05-02 dropped the
      //  standalone `buildOracleBundle`. The Ballot Coin oracle
      //  action is co-spent implicitly by every cast_vote /
      //  update_vote / finalize.)

      // ── RENDER ──────────────────────────────────────────────────

      if (!launcherIdRaw) {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8">
            <div className="card-elev">
              <h2 className="text-lg font-semibold">No election selected</h2>
              <p className="text-[var(--color-muted)] mt-2">
                Pick one from{" "}
                <Link
                  href="/"
                  className="text-[var(--color-accent)] hover:underline"
                >
                  the home page
                </Link>{" "}
                or paste a launcher id there.
              </p>
            </div>
          </main>
        );
      }

      if (chainStatus === "checking") {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8">
            <div className="card animate-pulse h-48" />
          </main>
        );
      }

      // PENDING: bundle is in the mempool, no confirmed coin yet.
      // Show a friendly "waiting for confirmation" card with the
      // election's basic params so users see something useful while
      // the chain catches up. Polling continues in the effect above.
      if (chainStatus === "pending" && !session) {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8 space-y-6">
            <Link
              href="/"
              className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
            >
              ← back
            </Link>
            <div className="card-elev">
              <h2 className="text-lg font-semibold">ElectionConfig required</h2>
              <p className="text-[var(--color-muted)] mt-2 text-sm">
                Waiting for launcher confirmation, but no session bootstrap was
                found — paste your deploy output (ElectionConfig JSON) below so
                this tab can keep polling and render parameters.
              </p>
              <ImportConfigForm
                launcherIdHex={launcherIdHex}
                wasm={wasm}
                session={session}
                setSession={setSession}
              />
            </div>
            <Footer />
          </main>
        );
      }

      if (chainStatus === "pending" && session) {
        const cfg = JSON.parse(session.configJson);
        return (
          <main className="max-w-4xl mx-auto px-4 py-8 space-y-6">
            <Link
              href="/"
              className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
            >
              ← back
            </Link>
            <div className="card-elev">
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-[var(--color-accent)] animate-pulse" />
                <h2 className="text-lg font-semibold">
                  Waiting for first confirmation…
                </h2>
              </div>
              <p className="text-[var(--color-muted)] mt-2">
                Your deploy bundle was accepted by the wallet. We're
                polling{" "}
                <span className="mono">api.coinset.org</span> for the
                launcher coin to confirm — typically one block on
                mainnet (~52 s). Don't close this tab.
              </p>
              <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="text-xs text-[var(--color-muted)]">
                    Launcher
                  </div>
                  <div className="mono">
                    {truncHex(launcherIdHex, 12, 8)}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-[var(--color-muted)]">
                    Polls so far
                  </div>
                  <div className="mono">{pendingPoll}</div>
                </div>
                <div>
                  <div className="text-xs text-[var(--color-muted)]">
                    Collateral (CAT)
                  </div>
                  <div className="mono">
                    {formatCat(cfg.collateral_amount)} ·{" "}
                    {truncHex(
                      "0x" + normalizeHex32(cfg.cat_tail_hash_hex ?? ""),
                      6,
                      4
                    )}
                  </div>
                </div>
              </div>
              <p className="text-xs text-[var(--color-muted)] mt-4">
                Times out after 5 min. If that happens the bundle was
                likely rejected — the launcher coin spend would never
                have reached a block.
              </p>
            </div>
            <Footer />
          </main>
        );
      }

      if (chainStatus === "not-found") {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8">
            <Link href="/" className="text-sm text-[var(--color-muted)]">
              ← back
            </Link>
            <div className="card-elev mt-4">
              <h2 className="text-lg font-semibold">Election not found</h2>
              <p className="text-[var(--color-muted)] mt-2">
                No launcher coin at{" "}
                <span className="mono">{truncHex(launcherIdHex, 10, 8)}</span> —
                check the ID, or paste the ElectionConfig/share bundle once the
                deploy has confirmed.
              </p>
              <ImportConfigForm
                launcherIdHex={launcherIdHex}
                wasm={wasm}
                session={session}
                setSession={setSession}
              />
            </div>
          </main>
        );
      }

      if (chainStatus === "deployed" && !session) {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8">
            <Link href="/" className="text-sm text-[var(--color-muted)]">
              ← back
            </Link>
            <div className="card-elev mt-4">
              <h2 className="text-lg font-semibold">Launcher on-chain</h2>
              <p className="text-[var(--color-muted)] mt-2">
                Coinset indexed this launcher, but CHIP still needs your
                off-chain ElectionConfig JSON (participant-distributed metadata)
                to query registration coins, hinted vote transactions, and
                singleton lineage. Paste the bundle from your deployer, or open
                this election from the home list so your browser session can
                carry the config across.
              </p>
              <ImportConfigForm
                launcherIdHex={launcherIdHex}
                wasm={wasm}
                session={session}
                setSession={setSession}
              />
            </div>
          </main>
        );
      }

      if (!session) {
        return (
          <main className="max-w-4xl mx-auto px-4 py-8">
            <div className="card-elev text-sm text-[var(--color-muted)]">
              Loading election session…
            </div>
          </main>
        );
      }

      const cfg = JSON.parse(session.configJson);
      const collateralAssetShort = truncHex(
        `0x${normalizeHex32(String(cfg.cat_tail_hash_hex ?? ""))}`,
        8,
        4
      );
      const minCollateralMojos = BigInt(String(cfg.collateral_amount ?? 0));
      const registrationLockParsedMojos = parseCat(
        registrationLockCollateralCat.trim()
      );
      const registrationLockSatisfiesMinimum =
        registrationLockParsedMojos !== null &&
        registrationLockParsedMojos >= minCollateralMojos;
      // CHIP weighted-voting rev: chain canonical total = sum of real
      // per-voter locks (each register action's `locked_cat_mojos`).
      // The Election Singleton tracks this in `registration_vote_weight`,
      // which the chain walker surfaces via readElectionSingletonState.
      const totalLockedCollateral =
        snapshot === null
          ? null
          : BigInt(snapshot.registrationVoteWeight ?? 0);
      // CHIP rev 2026-05-02 dropped per-voter registration_fee from
      // the on-chain ElectionConfig — the totalRegFees stat is gone
      // from the UI.

      const finalizedOnChain = snapshot?.finalized === true;

      // CHIP rev 2026-05-02: Election Singleton has no per-election
      // expiry / finalize window. The "expired no ballots" and
      // "finished voting period" banners no longer apply at the
      // election level — per-ballot expiry display lives in
      // BallotsList. Kept as `false` constants so the legacy JSX
      // gates compile-out cleanly.
      const showElectionExpiredNoBallots = false as const;
      const showElectionFinishedVotingPeriod = false as const;

      return (
        <>
          {broadcastAwait && (
            <BroadcastWaitModal
              title={broadcastAwait.title}
              detail={broadcastAwait.detail}
              titleId="broadcast-await-title"
            />
          )}
          {registrationModal && (
            <div
              className="fixed inset-0 z-[120] flex items-center justify-center bg-black/60 px-4 backdrop-blur-sm"
              role="dialog"
              aria-modal="true"
              aria-labelledby="reg-modal-title"
              aria-busy="true"
            >
              <div className="w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-bg)] shadow-2xl p-6 space-y-4">
                <div className="flex gap-4">
                  <div
                    className="mt-1 h-11 w-11 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent animate-spin"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    <h2
                      id="reg-modal-title"
                      className="font-semibold text-lg leading-snug"
                    >
                      {registrationModal.title}
                    </h2>
                    <p className="text-sm text-[var(--color-muted)] mt-2 whitespace-pre-wrap leading-relaxed">
                      {registrationModal.detail}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
          {mintBallotModal && (
            <BroadcastWaitModal
              title={mintBallotModal.title}
              detail={mintBallotModal.detail}
              titleId="mint-ballot-modal-title"
            />
          )}
          {finalizeModal && (
            <div
              className="fixed inset-0 z-[121] flex items-center justify-center bg-black/60 px-4 backdrop-blur-sm"
              role="dialog"
              aria-modal="true"
              aria-labelledby="finalize-modal-title"
              aria-busy="true"
            >
              <div className="w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-bg)] shadow-2xl p-6 space-y-4">
                <div className="flex gap-4">
                  <div
                    className="mt-1 h-11 w-11 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent animate-spin"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1 space-y-2">
                    <p className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)]">
                      {finalizeModal.phase === "collect"
                        ? "Enumerate ballots"
                        : finalizeModal.phase === "tally"
                          ? "Tally votes"
                          : finalizeModal.phase === "prove"
                            ? "Groth16 prove"
                            : finalizeModal.phase === "verify"
                              ? "Verify bundle"
                              : "Submit"}
                    </p>
                    <h2
                      id="finalize-modal-title"
                      className="font-semibold text-lg leading-snug"
                    >
                      {finalizeModal.title}
                    </h2>
                    {finalizeModal.phase === "prove" &&
                      finalizeModal.outcomeSummary && (
                        <p className="text-sm font-medium text-[var(--color-foreground)] leading-snug">
                          {finalizeModal.outcomeSummary}
                        </p>
                      )}
                    <p className="text-sm text-[var(--color-muted)] whitespace-pre-wrap leading-relaxed">
                      {finalizeModal.detail}
                    </p>
                    {finalizeModal.phase === "collect" && finalizeModal.collect && (
                      <div className="rounded-xl border border-[var(--color-border)] bg-black/[0.03] dark:bg-white/[0.04] px-3 py-2 space-y-2">
                        <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-[var(--color-muted)]">
                          <span>
                            Step:{" "}
                            <strong className="text-[var(--color-foreground)] font-medium">
                              {finalizeCollectStageLabel(
                                finalizeModal.collect.stage
                              )}
                            </strong>
                          </span>
                          <span>
                            Ballots decoded:{" "}
                            <strong className="text-[var(--color-foreground)] font-medium">
                              {finalizeModal.collect.ballotsCollected}
                            </strong>
                          </span>
                        </div>
                        {finalizeModal.collect.votersTotal > 0 && (
                          <>
                            <div className="flex justify-between text-[11px] text-[var(--color-muted)]">
                              <span>Registrant rows</span>
                              <span>
                                {finalizeModal.collect.voterIndex + 1} /{" "}
                                {finalizeModal.collect.votersTotal}
                              </span>
                            </div>
                            <div
                              className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-border)]"
                              role="progressbar"
                              aria-valuemin={0}
                              aria-valuemax={100}
                              aria-valuenow={
                                finalizeCollectHarvestPct(finalizeModal.collect)
                              }
                            >
                              <div
                                className="h-full rounded-full bg-[var(--color-accent)] transition-[width] duration-200 ease-out"
                                style={{
                                  width: `${finalizeCollectHarvestPct(
                                    finalizeModal.collect
                                  )}%`,
                                }}
                              />
                            </div>
                          </>
                        )}
                        {finalizeModal.collect.stage === "syncElectionSingleton" && (
                          <p className="text-[11px] text-[var(--color-muted)] leading-relaxed">
                            Walking the singleton lineage and rebuilding the voter
                            Merkle snapshot before ballots are enumerated.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
          <div className="flex items-center gap-2">
            <Link
              href="/"
              className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
            >
              ← back
            </Link>
          </div>

          <header className="flex justify-between items-start gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 gap-y-2">
                <h1 className="text-3xl font-bold">{session.label}</h1>
                {finalizedOnChain && (
                  <span
                    className="inline-flex shrink-0 text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full border border-emerald-600/45 bg-emerald-500/[0.15] text-emerald-950 dark:text-emerald-100"
                    title="Election singleton is finalized"
                  >
                    Finalized
                  </span>
                )}
                {!finalizedOnChain && showElectionExpiredNoBallots && (
                  <span
                    className="inline-flex shrink-0 text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full border border-rose-700/45 bg-rose-500/[0.12] text-rose-950 dark:text-rose-100"
                    title="Time-lock elapsed with no ballots"
                  >
                    Expired
                  </span>
                )}
                {!finalizedOnChain && showElectionFinishedVotingPeriod && (
                  <span
                    className="inline-flex shrink-0 text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full border border-sky-700/45 bg-sky-500/[0.12] text-sky-950 dark:text-sky-100"
                    title="Voting window over — finalize pending"
                  >
                    Voting ended
                  </span>
                )}
              </div>
              <div className="mono text-sm text-[var(--color-muted)] mt-1 break-all">
                {launcherIdHex}
              </div>
            </div>
            <button
              onClick={syncSnapshot}
              className="btn-secondary text-sm"
              disabled={snapshotLoading}
            >
              {snapshotLoading ? "Syncing…" : "Refresh state"}
            </button>
          </header>

          {finalizedOnChain && (
            <section
              className="rounded-xl border border-emerald-600/35 bg-emerald-500/[0.12] px-4 py-3 text-sm shadow-sm"
              aria-live="polite"
            >
              <div className="font-semibold text-emerald-900 dark:text-emerald-200">
                Election finished
              </div>
              <p className="text-xs text-[var(--color-muted)] mt-1.5 leading-relaxed">
                Outcome is finalized on-chain — registration and voting are closed.
              </p>
            </section>
          )}

          {!finalizedOnChain && showElectionExpiredNoBallots && (
            <section
              className="rounded-xl border border-rose-700/35 bg-rose-500/[0.1] px-4 py-3 text-sm shadow-sm"
              aria-live="polite"
            >
              <div className="font-semibold text-rose-900 dark:text-rose-200">
                Election expired
              </div>
              <p className="text-xs text-[var(--color-muted)] mt-1.5 leading-relaxed">
                The finalize time-lock has elapsed and no votes were recorded. Voting is closed. Finalization still records the eventual outcome when an operator submits it.
              </p>
            </section>
          )}

          {!finalizedOnChain && showElectionFinishedVotingPeriod && (
            <section
              className="rounded-xl border border-sky-700/35 bg-sky-500/[0.1] px-4 py-3 text-sm shadow-sm"
              aria-live="polite"
            >
              <div className="font-semibold text-sky-950 dark:text-sky-100">
                Election finished
              </div>
              <p className="text-xs text-[var(--color-muted)] mt-1.5 leading-relaxed">
                Voting period has ended (time-lock satisfied). Finalize when ready so the tally is cemented on-chain.
              </p>
            </section>
          )}

          {/* CHIP rev 2026-05-02: <ElectionFinalizeQuietBanner>
              removed — per-election quiet/finalize countdown was
              based on `election_start_height + election_length_blocks`
              and no longer applies. Per-ballot countdowns live in
              BallotsList. */}

          {/* ────────── Election parameters ────────── */}
          <section className="card-elev">
            <h2 className="text-lg font-semibold mb-4">Election parameters</h2>
            <div className="grid sm:grid-cols-3 gap-4">
              <Stat
                label="Minimum collateral (CAT)"
                value={`${formatCat(cfg.collateral_amount)} (${collateralAssetShort})`}
              />
              <Stat
                label="CAT TAIL (asset id)"
                value={truncHex(
                  "0x" + normalizeHex32(String(cfg.cat_tail_hash_hex ?? "")),
                  10,
                  6
                )}
                mono
              />
              <Stat
                label="Tree depth (slots)"
                value={`2^${cfg.tree_depth}`}
              />
              <Stat
                label="Max signers"
                value={cfg.max_signers.toLocaleString()}
              />
              <Stat
                label="Finalize quorum (weighted)"
                value={`${Number(cfg?.vote_threshold_num ?? 1)} / ${Number(
                  cfg?.vote_threshold_den ?? 2
                )} of total stake`}
              />
            </div>
          </section>

          {/* ────────── On-chain state ────────── */}
          <section className="card">
            <h2 className="text-lg font-semibold mb-4">On-chain state</h2>
            {snapshotError && (
              <div className="text-sm text-[var(--color-danger)] mb-3">
                Sync failed: {snapshotError}
              </div>
            )}
            <div className="grid sm:grid-cols-3 gap-4">
              <Stat
                label="Registrations"
                value={
                  snapshot === null
                    ? "—"
                    : snapshot.registrationCount.toLocaleString()
                }
              />
              <Stat
                label="Total vote weight"
                value={
                  totalLockedCollateral === null
                    ? "—"
                    : `${formatCat(totalLockedCollateral)} (${collateralAssetShort})`
                }
                hint="Sum of every voter's locked CAT (the chain-canonical
                  registration_vote_weight). Drives the quorum threshold for
                  every ballot under this election."
              />
              {myReg && (
                <Stat
                  label="Your weight"
                  value={(() => {
                    if (myLockedAmount == null) return "—";
                    const formatted = formatCat(myLockedAmount);
                    if (
                      totalLockedCollateral != null &&
                      totalLockedCollateral > 0n
                    ) {
                      const pct =
                        Number(
                          (myLockedAmount * 10000n) / totalLockedCollateral
                        ) / 100;
                      return `${formatted} (${pct.toFixed(2)}%)`;
                    }
                    return formatted;
                  })()}
                  hint="Your share of the total vote weight. Locking more CAT
                    at register time increases your weight proportionally on
                    every ballot's quorum check."
                />
              )}
              <Stat
                label="Ballots cast"
                value={
                  electionLc.status === "ready"
                    ? electionLc.ballotsCast.toLocaleString()
                    : "—"
                }
              />
              <Stat
                label="Status"
                value={
                  snapshot === null
                    ? "—"
                    : snapshot.finalized
                      ? "At least one ballot finalized"
                      : "Active"
                }
              />
              <Stat
                label="Outcome"
                value={(() => {
                  if (!snapshot || !snapshot.finalized) return "—";
                  // Decode outcome against the local choices (if any)
                  // so finalized elections surface the human label
                  // ("Yes" / "Approve") instead of opaque hex.
                  const outcome = snapshot.voteOutcomeHex
                    .toLowerCase()
                    .replace(/^0x/, "");
                  const match = session.choices?.find(
                    (c) =>
                      c.voteDataHex.toLowerCase().replace(/^0x/, "") ===
                      outcome
                  );
                  return match
                    ? match.label
                    : truncHex(snapshot.voteOutcomeHex, 10, 6);
                })()}
                mono={
                  !session.choices ||
                  !snapshot ||
                  !snapshot.finalized ||
                  !session.choices.find(
                    (c) =>
                      c.voteDataHex.toLowerCase().replace(/^0x/, "") ===
                      snapshot.voteOutcomeHex
                        .toLowerCase()
                        .replace(/^0x/, "")
                  )
                }
              />
            </div>
          </section>

          {/* ────────── On-chain vote tally (coinset-backed) ────────── */}
          <section className="card">
            <h2 className="text-lg font-semibold mb-2">Vote tally (on-chain)</h2>
            <p className="text-xs text-[var(--color-muted)] mb-4 leading-relaxed">
              Counts come from on-chain hinted vote spends: WASM{" "}
              <span className="mono">collectVotes</span> walks per-voter{" "}
              <span className="mono">coin_records_by_hint</span>, parses parent
              spends and memos (same extractor as finalize). Refresh after new
              votes index (typically one mainnet block).
            </p>
            <OnChainVoteBarChart rows={onChainVoteTally} />
          </section>

          {/* ────────── Action banner: progress / errors ─────────── */}
          {(busy || priorRegScanBusy || txStatus || error) && (
            <section className="card">
              {busy && (
                <div className="flex items-center gap-2 text-[var(--color-accent)]">
                  <div className="w-3 h-3 rounded-full bg-[var(--color-accent)] animate-pulse" />
                  <span>{busy}</span>
                </div>
              )}
              {priorRegScanBusy && !busy && (
                <div className="flex items-center gap-2 text-[var(--color-muted)] text-sm">
                  <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-muted)] animate-pulse" />
                  <span>{priorRegScanBusy}</span>
                </div>
              )}
              {txStatus && (
                <div className="text-[var(--color-accent)]">{txStatus}</div>
              )}
              {error && (
                <div
                  role="alert"
                  className="rounded-xl border-2 border-rose-500/60 bg-rose-500/10 p-4 flex items-start gap-3"
                >
                  <span aria-hidden className="text-rose-500 text-lg leading-none mt-0.5">
                    ⚠
                  </span>
                  <div className="flex-1 text-rose-700 dark:text-rose-300 text-sm whitespace-pre-wrap break-words">
                    <div className="font-semibold mb-1">Something went wrong</div>
                    <div>{error}</div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setError(null)}
                    className="text-rose-700/70 dark:text-rose-300/70 hover:text-rose-700 dark:hover:text-rose-200 text-xs px-2 py-1 rounded border border-rose-500/40 hover:bg-rose-500/10"
                    aria-label="Dismiss error"
                  >
                    Dismiss
                  </button>
                </div>
              )}
            </section>
          )}

          {/* ────────── Voter identity ────────── */}
          <section className="card">
            <h2 className="text-lg font-semibold mb-2">Voter identity</h2>
            {!address ? (
              <p className="text-[var(--color-muted)]">
                Connect Sage Wallet (top right) to register, vote, or route finalize rewards.
              </p>
            ) : pubkeyResolutionBusy ? (
              <p className="text-[var(--color-muted)] text-sm">
                Resolving wallet pubkey…
              </p>
            ) : effectiveVoterPk ? (
              <div className="space-y-2">
                <p className="text-sm text-[var(--color-muted)]">
                  {voterPk &&
                  registeredAsPk &&
                  normalizeHex32(voterPk) !== normalizeHex32(registeredAsPk)
                    ? "Your receive address mapped to one synthetic key, but this election " +
                      "registered collateral under a different Sage synthetic key."
                    : "Voting under your wallet synthetic pubkey — Sage signs voter-side spends."}
                </p>
                <div className="text-sm">
                  <span className="text-[var(--color-muted)]">Pubkey:</span>{" "}
                  <span className="mono">
                    {truncHex(effectiveVoterPk, 12, 8)}
                  </span>
                </div>
                <div className="text-xs text-[var(--color-muted)]">
                  {myReg ? "✓ Registered for this election" : "Not yet registered"}
                </div>
              </div>
            ) : !voterPk ? (
              <div className="space-y-2 text-sm">
                <p className="text-[var(--color-muted)]">
                  {walletKeyNote ??
                    "No matching synthetic key for this receive address yet."}
                </p>
                <p className="text-xs text-[var(--color-muted)]">
                  You can still register: the app scans all synthetic keys
                  Sage returns until it finds matching CAT collateral.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-sm text-[var(--color-muted)]">
                  Waiting for chain snapshot to derive your voting pubkey… Use
                  Refresh state if this persists after connecting.
                </p>
              </div>
            )}
          </section>

          {/* ────────── Participate: register before vote ────────── */}
          <section className="card">
            <h2 className="text-lg font-semibold">Participate</h2>
            <p className="text-sm text-[var(--color-muted)] mt-1.5 leading-relaxed max-w-2xl">
              <span className="text-[var(--color-foreground)] font-medium">
                Join, vote during the poll, then finalize.
              </span>{" "}
              Registration locks collateral and collects on-chain registration
              fees. After the time-lock passes, whoever runs finalize (with the
              shared proving key from the organizer) commits the ballot tally —
              first successful submission wins — and collects accumulated XCH fees
              to their connected Sage address.
            </p>
            {!address ? (
              <p className="text-[var(--color-muted)] mt-6">
                Connect Sage Wallet (top right) to register, vote, or route finalize rewards.
              </p>
            ) : (
              <div className="mt-6 space-y-5">
                {/* Step 1 — join / register */}
                <div
                  className={`rounded-xl border p-5 ${
                    myReg
                      ? "border-[var(--color-accent)]/35 bg-[var(--color-accent)]/[0.06]"
                      : "border-[var(--color-border)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                    <span
                      className="inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent)]/20 px-2 text-[11px] font-bold text-[var(--color-accent)]"
                      aria-hidden
                    >
                      1
                    </span>
                    <span className="font-semibold">Join this election</span>
                    {!myReg &&
                      !snapshot?.finalized &&
                      chainStatus === "deployed" && (
                        <span className="text-[11px] font-medium uppercase tracking-wide rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-800 dark:text-amber-300">
                          Required before voting
                        </span>
                      )}
                  </div>
                  {myReg ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      <span className="font-medium text-[var(--color-accent)]">
                        You&apos;re registered.
                      </span>{" "}
                      Use step&nbsp;2 to cast your ballot.
                    </p>
                  ) : snapshot?.finalized ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      This election is finalized — registration is closed.
                    </p>
                  ) : chainStatus !== "deployed" ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Wait until this election is deployed on-chain before
                      joining.
                    </p>
                  ) : (
                    <>
                      <p className="text-sm text-[var(--color-muted)] mb-2">
                        Minimum lock{" "}
                        <span className="font-medium text-[var(--color-foreground)]">
                          {formatCat(cfg.collateral_amount)}
                        </span>{" "}
                        {collateralAssetShort} — you may stake more; finalize
                        weights ballots by locked CAT at registration.
                      </p>
                      <label className="block text-xs font-medium text-[var(--color-muted)] mb-1.5">
                        Lock amount = your vote weight (minimum{" "}
                        {formatCat(cfg.collateral_amount)})
                      </label>
                      <input
                        type="text"
                        inputMode="decimal"
                        autoComplete="off"
                        className="input mono mb-1 max-w-xs"
                        placeholder={formatCat(cfg.collateral_amount)}
                        value={registrationLockCollateralCat}
                        onChange={(e) =>
                          setRegistrationLockCollateralCat(e.target.value)
                        }
                        disabled={
                          !!busy ||
                          !!registrationModal ||
                          myReg ||
                          snapshot?.finalized ||
                          chainStatus !== "deployed"
                        }
                        aria-invalid={!registrationLockSatisfiesMinimum}
                      />
                      {registrationLockSatisfiesMinimum &&
                        registrationLockCollateralCat.trim() !== "" && (
                          <p className="text-xs text-[var(--color-accent)] mb-3">
                            ✓ Your vote weight will be{" "}
                            <span className="mono font-semibold">
                              {registrationLockCollateralCat.trim()}
                            </span>{" "}
                            {collateralAssetShort}. Weight scales linearly:
                            5× the floor = 5× the say in finalize tally.
                          </p>
                        )}
                      {!registrationLockSatisfiesMinimum &&
                        registrationLockCollateralCat.trim() !== "" && (
                          <p className="text-xs text-rose-700 dark:text-rose-300 mb-3">
                            Must be at least {formatCat(minCollateralMojos)}{" "}
                            {collateralAssetShort}.
                          </p>
                        )}
                      <button
                        type="button"
                        onClick={handleRegister}
                        disabled={
                          !!busy ||
                          !!registrationModal ||
                          myReg ||
                          snapshot?.finalized ||
                          chainStatus !== "deployed" ||
                          !registrationLockSatisfiesMinimum
                        }
                        className="btn-primary w-full sm:w-auto min-w-[220px] mt-2"
                      >
                        Register to vote
                      </button>
                    </>
                  )}
                </div>

                {/* Operator-only — mint a new ballot under this election.
                    Visible only when this session holds the Groth16
                    proving key (= the deployer / share-bundle holder).
                    Persists per-ballot snapshot to ballotBootstrap so
                    voter / finalize / release flows can read it
                    without re-walking the chain. */}
                {session?.provingKeyBase64 ? (
                  <div className="rounded-xl border border-[var(--color-accent)]/35 bg-[var(--color-accent)]/[0.04] p-5">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                      <span
                        className="inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full px-2 text-[11px] font-bold bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                        aria-hidden
                      >
                        OP
                      </span>
                      <h3 className="font-semibold">Mint a new ballot</h3>
                    </div>
                    <p className="text-sm text-[var(--color-muted)] mb-3">
                      Operator action: create a Ballot Coin lineage under
                      this election. Funds the launcher with 2 mojos from
                      your Sage XCH wallet, captures the current
                      registration snapshot, and persists the ballot’s
                      curry pack so voters can cast against it.
                    </p>
                    {(() => {
                      // M12: render an election-lock banner so the
                      // operator knows whether choices are gated.
                      const lockHex =
                        electionVoteModeLockHex?.replace(/^0x/, "") ?? null;
                      const NO_LOCK = "ff".repeat(32);
                      const FREE_LOCK = "00".repeat(32);
                      if (lockHex == null) return null;
                      if (lockHex === NO_LOCK) {
                        return (
                          <p className="text-xs mb-3" style={{ color: "#666" }}>
                            Election vote mode: <strong>no lock</strong> —
                            this ballot's choices set its own merkle root.
                          </p>
                        );
                      }
                      if (lockHex === FREE_LOCK) {
                        return (
                          <p className="text-xs mb-3" style={{ color: "#1a7f1a" }}>
                            ✓ Election locked to <strong>Mode1Free</strong> —
                            any 32-byte vote_data accepted; the choices
                            below are advisory (vote_options_root forced
                            to 0x00…00).
                          </p>
                        );
                      }
                      return (
                        <div className="text-xs mb-3" style={{ color: "#1a7f1a" }}>
                          ✓ Election locked to <strong>Mode2Restricted</strong>
                          {" "}(root=0x{lockHex.slice(0, 16)}…). Voter choices
                          must hash to this exact root.
                          {lockedRestrictedLabels && lockedRestrictedLabels.length > 0 ? (
                            <p className="mt-1" style={{ color: "#666" }}>
                              Locked options:{" "}
                              <code className="mono">
                                {lockedRestrictedLabels.join(", ")}
                              </code>
                            </p>
                          ) : (
                            <p className="mt-1" style={{ color: "#b00020" }}>
                              ⚠ No labels in localStorage for this root —
                              ask the operator who deployed for the canonical
                              comma-separated label list.
                            </p>
                          )}
                        </div>
                      );
                    })()}
                    <label className="block text-xs font-medium text-[var(--color-muted)] mb-1.5">
                      Voter choices (comma-separated, ≥ 2 unique labels)
                    </label>
                    <input
                      type="text"
                      value={mintBallotChoices}
                      onChange={(e) => setMintBallotChoices(e.target.value)}
                      placeholder="Yes,No"
                      className="input mono mb-3 w-full sm:max-w-md"
                      disabled={!!busy}
                    />
                    <p className="text-xs text-[var(--color-muted)] mb-3">
                      Each label hashes to <span className="mono">vote_data = sha256(&quot;vote:&quot; + label)</span>. Voters pick one
                      at cast time; finalize tallies the winning label.
                    </p>
                    <label className="block text-xs font-medium text-[var(--color-muted)] mb-1.5">
                      Voting duration (blocks)
                    </label>
                    <input
                      type="number"
                      min={1}
                      step={1}
                      value={mintBallotBlocks}
                      onChange={(e) => setMintBallotBlocks(e.target.value)}
                      placeholder="50"
                      className="input mono mb-1 w-full sm:max-w-xs"
                      disabled={!!busy}
                    />
                    {(() => {
                      const n = Number.parseInt(
                        mintBallotBlocks.trim(),
                        10
                      );
                      if (!Number.isFinite(n) || n < 1) {
                        return (
                          <p className="text-xs text-rose-700 dark:text-rose-300 mb-3">
                            Enter a positive integer.
                          </p>
                        );
                      }
                      const seconds = n * 52;
                      const fmtDuration = (s: number) => {
                        if (s < 60) return `~${s}s`;
                        const m = s / 60;
                        if (m < 60) return `~${m.toFixed(0)} min`;
                        const h = m / 60;
                        if (h < 48) return `~${h.toFixed(1)} h`;
                        const d = h / 24;
                        return `~${d.toFixed(1)} days`;
                      };
                      return (
                        <p className="text-xs text-[var(--color-muted)] mb-3">
                          {fmtDuration(seconds)} on mainnet (~52s/block).
                          Sets <code className="mono">vote_close_height = peak + {n}</code>;
                          voters can cast/change up until that block, then
                          anyone with the proving key can finalize.
                        </p>
                      );
                    })()}
                    <button
                      type="button"
                      onClick={handleCreateAndLaunchBallot}
                      disabled={!!busy || !address}
                      className="btn-primary w-full sm:w-auto min-w-[220px]"
                    >
                      {busy?.startsWith("Creating ballot") ||
                      busy?.includes("ballot")
                        ? busy
                        : "Create new ballot"}
                    </button>
                  </div>
                ) : null}

                {/* Ballots list — every ballot under this election
                    plus its status. Click a row to navigate to
                    /ballot for voting / finalize / tally view. */}
                <BallotsList
                  electionLauncherIdHex={launcherIdHex}
                  configJson={session?.configJson ?? ""}
                  currentPeak={
                    electionLc.status === "ready" ? electionLc.peak : 0
                  }
                  refreshKey={ballotsListEpoch}
                />

                {/* Step 2 — election-level deregister + claim CAT.
                    Release operates on the Election Singleton's
                    release_collateral action — it doesn't care which
                    ballots are open / closed / finalized. Spending the
                    voter's reg coin removes them from the SMT, melts
                    the locked CAT back to a fresh CAT under the same
                    TAIL, and returns the synthetic-key payout. Voting
                    + finalize moved to per-ballot pages — click any
                    row in the Ballots list above to navigate. */}
                <div
                  className={`rounded-xl border p-5 ${
                    myReg
                      ? "border-[var(--color-accent)]/35 bg-[var(--color-accent)]/[0.06]"
                      : "border-[var(--color-border)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                    <span
                      className={`inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full px-2 text-[11px] font-bold ${
                        myReg
                          ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                          : "border border-[var(--color-muted)]/40 text-[var(--color-muted)]"
                      }`}
                      aria-hidden
                    >
                      2
                    </span>
                    <span className="font-semibold">
                      Claim your CAT collateral &amp; deregister
                    </span>
                  </div>
                  {!myReg ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Only voters who joined this election can reclaim locked CAT.
                    </p>
                  ) : (
                    <>
                      <p className="text-sm text-[var(--color-muted)] mb-4">
                        Election-level action — deregisters you from the Election
                        Singleton (removes your pubkey from the voter SMT) and
                        returns your locked{" "}
                        <span className="mono">{collateralAssetShort}</span>{" "}
                        as a fresh CAT to your wallet. You can re-register
                        later with another spend if you want.
                      </p>
                      <button
                        type="button"
                  onClick={handleRelease}
                        disabled={
                          !!busy ||
                          !!finalizeModal ||
                          !effectiveVoterPk
                        }
                        className="btn-primary w-full sm:w-auto min-w-[220px]"
                      >
                        Release collateral &amp; deregister
                      </button>
                    </>
                  )}
                </div>

                {/* Step 5 (oracle) removed — CHIP rev 2026-05-02
                    dropped the standalone Oracle action. */}
              </div>
            )}
          </section>

          {/* ────────── Ballot / share bundle ────────── */}
          <section className="card">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg font-semibold">Ballot</h2>
              <ShareBundleButton session={session} />
            </div>
            {!session.choices || session.choices.length === 0 ? (
              <p className="text-[var(--color-muted)] text-sm">
                No UI choices defined for this election. Voters can still
                cast any 32-byte payload via the freeform input.
              </p>
            ) : (
              <ol className="space-y-1.5">
                {session.choices.map((c, i) => (
                  <li
                    key={c.voteDataHex}
                    className="flex items-center gap-3 text-sm"
                  >
                    <span className="text-xs text-[var(--color-muted)] w-6 text-right">
                      #{i + 1}
                    </span>
                    <span className="font-medium flex-1">{c.label}</span>
                    <span className="mono text-xs text-[var(--color-muted)]">
                      {truncHex(c.voteDataHex, 10, 4)}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </section>

          {/* ────────── Voter set ────────── */}
          <section className="card">
            <h2 className="text-lg font-semibold mb-2">Voter set</h2>
            {!snapshot ? (
              <p className="text-[var(--color-muted)]">
                Sync state to view voters.
              </p>
            ) : snapshot.votersHex.length === 0 ? (
              <p className="text-[var(--color-muted)]">No voters yet.</p>
            ) : (
              <ul className="space-y-1 max-h-60 overflow-y-auto">
                {snapshot.votersHex.map((pk, i) => (
                  <li key={pk} className="mono text-sm flex items-center gap-2">
                    <span className="text-[var(--color-muted)] text-xs w-6">
                      #{i + 1}
                    </span>
                    {truncHex(pk, 12, 6)}
                    {effectiveVoterPk &&
                      normalizeHex32(pk) ===
                        normalizeHex32(effectiveVoterPk) && (
                        <span className="text-xs text-[var(--color-accent)]">
                          ← you
                        </span>
                      )}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <Footer />
        </main>
        </>
      );
    };
  },
  { ssr: false, loading: () => <div className="card animate-pulse h-96 m-8" /> }
);

/**
 * Page-level wrapper. Two responsibilities beyond the inner
 * dynamic component:
 *   1. Wrap in `<Suspense>` — Next.js 15 + static export requires
 *      any component that calls `useSearchParams()` to be inside
 *      a Suspense boundary, otherwise the export pass refuses
 *      to emit the page.
 *   2. (Future) any non-wasm chrome (breadcrumbs, share buttons,
 *      etc.) that doesn't need the wasm bundle goes here so it
 *      can render before the heavy wasm download finishes.
 */
export default function ElectionPageRoute() {
  return (
    <Suspense
      fallback={<div className="card animate-pulse h-96 m-8" />}
    >
      <ElectionPageInner />
    </Suspense>
  );
}

// ============================================================================
// Helper components
// ============================================================================

function computeOnChainVoteTallyFromWire(
  wireVotes: readonly { voteDataHex: string }[],
  choices: ElectionChoice[] | undefined
): { label: string; count: number; barKey: string }[] {
  const tally = new Map<string, number>();
  for (const v of wireVotes) {
    const k = normalizeHex32(v.voteDataHex);
    tally.set(k, (tally.get(k) ?? 0) + 1);
  }
  const rows: { label: string; count: number; barKey: string }[] = [];

  if (choices && choices.length > 0) {
    const leftover = new Map(tally);
    for (const c of choices) {
      const k = normalizeHex32(c.voteDataHex);
      const n = leftover.get(k) ?? 0;
      rows.push({ label: c.label, count: n, barKey: `choice:${k}` });
      leftover.delete(k);
    }
    for (const [hex, count] of leftover) {
      if (count <= 0) continue;
      rows.push({
        label: `Other (${truncHex(`0x${hex}`, 6, 4)})`,
        count,
        barKey: `unknown:${hex}`,
      });
    }
    rows.sort(
      (a, b) => b.count - a.count || a.barKey.localeCompare(b.barKey)
    );
  } else {
    for (const [hex, count] of tally) {
      rows.push({
        label: truncHex(`0x${hex}`, 14, 6),
        count,
        barKey: hex,
      });
    }
    rows.sort(
      (a, b) => b.count - a.count || a.barKey.localeCompare(b.barKey)
    );
  }
  return rows;
}

function OnChainVoteBarChart({
  rows,
}: {
  rows: { label: string; count: number; barKey: string }[];
}) {
  const total = rows.reduce((s, r) => s + r.count, 0);
  const maxCount =
    rows.length > 0 ? Math.max(...rows.map((r) => r.count), 1) : 1;
  if (total === 0) {
    return (
      <p className="text-sm text-[var(--color-muted)]">
        No ballots recorded on-chain yet.
      </p>
    );
  }
  return (
    <div
      className="space-y-4"
      role="img"
      aria-label="On-chain vote counts by option"
    >
      {rows.map((r) => (
        <div key={r.barKey}>
          <div className="flex justify-between gap-3 text-sm mb-1">
            <span className="min-w-0 truncate font-medium">{r.label}</span>
            <span className="shrink-0 mono text-[var(--color-muted)] tabular-nums">
              {r.count}
              <span className="text-xs ml-1 opacity-80">
                ({Math.round((100 * r.count) / total)}%)
              </span>
            </span>
          </div>
          <div className="h-3 rounded-full bg-[var(--color-border)] overflow-hidden">
            <div
              className="h-full rounded-full bg-[var(--color-accent)] min-w-[2px] transition-[width] duration-500"
              style={{ width: `${(100 * r.count) / maxCount}%` }}
            />
          </div>
        </div>
      ))}
      <div className="text-xs text-[var(--color-muted)] pt-1 tabular-nums">
        Total ballots: {total.toLocaleString()}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  mono,
}: {
  label: string;
  value: string;
  hint?: string;
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-[var(--color-muted)]">
        {label}
      </div>
      <div className={`text-xl font-semibold mt-1 ${mono ? "mono" : ""}`}>
        {value}
      </div>
      {hint && (
        <div className="text-xs text-[var(--color-muted)] mt-1">{hint}</div>
      )}
    </div>
  );
}

/**
 * Three-mode import flow keyed off `parseShareablePayload`:
 *
 *  1. CHOICES-ONLY — requires ElectionBootstrap already loaded (paste full config first).

 *  2–3. Writes sessionStorage + mirrored `upsertElection` for home list only.
 *
 * For cases 2 and 3 the `launcherId` is verified to match the
 * URL's id; mismatch surfaces a clear error so a user pasting
 * the wrong election's bundle doesn't silently overwrite.
 */
function ImportConfigForm({
  launcherIdHex,
  wasm,
  session,
  setSession,
}: {
  launcherIdHex: string;
  wasm: typeof import("chip-voting-wasm");
  session: ElectionBootstrap | null;
  setSession: (next: ElectionBootstrap | null) => void;
}) {
  const [json, setJson] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleImport = () => {
    try {
      const parsed = parseShareablePayload(json);
      const wantLid = launcherIdHex.toLowerCase().replace(/^0x/, "");

      // CASE 1: choices-only payload. Need bootstrap with full config JSON.
      if (!parsed.configJson) {
        if (!parsed.launcherIdHex) {
          throw new Error("Choices-only bundle is missing `launcherId`.");
        }
        const bundleLid = parsed.launcherIdHex
          .toLowerCase()
          .replace(/^0x/, "");
        if (bundleLid !== wantLid) {
          throw new Error(
            `Bundle launcherId (${parsed.launcherIdHex}) doesn't match this URL's id (${launcherIdHex}).`
          );
        }
        if (!session) {
          throw new Error(
            "Choices-only bundle, but paste the full ElectionConfig first " +
              "(JSON with a top-level `config` field)."
          );
        }
        if (parsed.catTailHashHex) {
          let existingTail: string;
          try {
            const c = JSON.parse(session.configJson) as {
              cat_tail_hash_hex?: string;
            };
            existingTail = normalizeHex32(String(c.cat_tail_hash_hex ?? ""));
          } catch {
            throw new Error("ElectionConfig JSON for this launcher is invalid.");
          }
          const bundleTail = normalizeHex32(parsed.catTailHashHex);
          if (
            !/^[0-9a-f]{64}$/.test(existingTail) ||
            !/^[0-9a-f]{64}$/.test(bundleTail)
          ) {
            throw new Error(
              "CAT asset id in the bundle or config must be exactly 64 hex chars."
            );
          }
          if (existingTail !== bundleTail) {
            throw new Error(
              `Share bundle declares CAT asset ${truncHex(parsed.catTailHashHex, 8, 4)} ` +
                `but this election expects ${truncHex("0x" + existingTail, 8, 4)} — ` +
                `wrong bundle or mismatched launcher.`
            );
          }
        }
        const merged: ElectionBootstrap = {
          ...session,
          launcherIdHex,
          label: parsed.label || session.label,
          choices: parsed.choices ?? session.choices,
        };
        writeElectionBootstrap(merged);
        setSession(merged);
        upsertElection({
          launcherIdHex: merged.launcherIdHex,
          configJson: merged.configJson,
          label: merged.label,
          addedAt: merged.addedAt ?? new Date().toISOString(),
          eveCoinIdHex: merged.eveCoinIdHex,
          provingKeyBase64: merged.provingKeyBase64,
          choices: merged.choices,
          registeredPubkeysHex: merged.registeredPubkeysHex,
        });
        setJson("");
        return;
      }

      // CASES 2 + 3: full ElectionConfig present. Verify launcher_id matches the URL.
      const summary = wasm.parseElectionConfig(parsed.configJson) as any;
      const summaryLid = summary.launcherIdHex
        .toLowerCase()
        .replace(/^0x/, "");
      if (summaryLid !== wantLid) {
        throw new Error(
          `Config launcher_id (${summary.launcherIdHex}) doesn't match this URL's id (${launcherIdHex}).`
        );
      }
      const next: ElectionBootstrap = {
        launcherIdHex,
        configJson: parsed.configJson,
        label:
          parsed.label ||
          summary.label ||
          `Election ${launcherIdHex.slice(2, 10)}`,
        choices: parsed.choices,
      };
      writeElectionBootstrap(next);
      setSession(next);
      upsertElection({
        launcherIdHex,
        configJson: next.configJson,
        label: next.label,
        addedAt: new Date().toISOString(),
        choices: next.choices,
      });
      setJson("");
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : typeof e === "string" ? e : String(e);
      setError(msg);
    }
  };

  return (
    <div className="mt-4 space-y-2">
      <textarea
        value={json}
        onChange={(e) => setJson(e.target.value)}
        rows={6}
        className="input mono text-xs"
        placeholder='{"launcherId": "0x...", "catTailHashHex": "0x...", "label": "...", "choices": [...]}'
      />
      {error && (
        <div className="text-xs text-[var(--color-danger)] whitespace-pre-wrap">
          {error}
        </div>
      )}
      <button
        onClick={handleImport}
        className="btn-secondary text-sm"
        disabled={!json.trim()}
      >
        Import
      </button>
    </div>
  );
}

/**
 * "Share bundle" — copies `{ launcherId, catTailHashHex, label,
 * choices }` so collaborators can sanity-check collateral CAT ids
 * without re-pasting full ElectionConfig (still bulky for chat).
 *
 * Recipient pastes into `/election/?id=` import; merging rules are
 * the same as choices-only payloads in `parseShareablePayload`.
 */
function ShareBundleButton({ session }: { session: ElectionBootstrap }) {
  const [copied, setCopied] = useState(false);
  const handleShare = async () => {
    let catTailHashHex: string;
    try {
      const c = JSON.parse(session.configJson) as {
        cat_tail_hash_hex?: string;
      };
      catTailHashHex = canonicalCatTail0x(String(c.cat_tail_hash_hex ?? ""));
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : typeof e === "string" ? e : String(e);
      window.alert(
        `Cannot build share bundle: invalid CAT asset in ElectionConfig (${msg}).`
      );
      return;
    }
    const bundle = {
      launcherId: session.launcherIdHex,
      catTailHashHex,
      label: session.label,
      choices: session.choices ?? [],
    };
    try {
      await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Fallback: open a prompt with the bundle so the user can
      // copy manually (some browsers block clipboard write
      // outside explicit user gestures — though this IS one).
      window.prompt("Copy bundle:", JSON.stringify(bundle));
    }
  };
  return (
    <button onClick={handleShare} className="btn-secondary text-xs">
      {copied ? "Copied!" : "Share bundle"}
    </button>
  );
}

// ============================================================================
// Helpers (chain + utility)
// ============================================================================

interface SyncSnapshotShape {
  registrationCount: number;
  /**
   * Sum of every voter's `locked_cat_mojos` (chain-canonical, from
   * the Election Singleton's `registration_vote_weight` state field).
   * This is the denominator used by every ballot's quorum threshold.
   */
  registrationVoteWeight: number;
  registrationMerkleRootHex: string;
  finalized: boolean;
  voteOutcomeHex: string;
  electionStartHeight: number;
  votersHex: string[];
  smtRootHex: string;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const c of b) s += c.toString(16).padStart(2, "0");
  return s;
}
function base64ToBytes(b64: string): Uint8Array {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/**
 * Decode the streamable bytes for a single CoinSpend that
 * `buildCatCollateralSpend` returns into the JSON shape Sage
 * Wallet's `chip0002_signCoinSpends` expects (`{ coin: {
 * parent_coin_info, puzzle_hash, amount }, puzzle_reveal,
 * solution }`). Because we already have the raw bytes, we
 * delegate to a tiny re-implementation here that matches the
 * SDK's CoinSpend layout.
 *
 * STREAMABLE LAYOUT for `CoinSpend`:
 *   coin: parent_coin_info[32] || puzzle_hash[32] || amount(BigEndian u64)
 *   puzzle_reveal: u32 length || bytes
 *   solution: u32 length || bytes
 */
function decodeCoinSpend(bytes: Uint8Array): {
  coin: { parent_coin_info: string; puzzle_hash: string; amount: number };
  puzzle_reveal: string;
  solution: string;
} {
  let off = 0;
  const parent = "0x" + bytesToHex(bytes.slice(off, off + 32));
  off += 32;
  const puzzleHash = "0x" + bytesToHex(bytes.slice(off, off + 32));
  off += 32;
  // 8-byte big-endian amount.
  let amount = 0n;
  for (let i = 0; i < 8; i++) amount = (amount << 8n) | BigInt(bytes[off + i]);
  off += 8;
  // 4-byte big-endian length prefix for puzzle_reveal.
  const prLen =
    (bytes[off] << 24) |
    (bytes[off + 1] << 16) |
    (bytes[off + 2] << 8) |
    bytes[off + 3];
  off += 4;
  const puzzleReveal = "0x" + bytesToHex(bytes.slice(off, off + prLen));
  off += prLen;
  // 4-byte length prefix for solution.
  const solLen =
    (bytes[off] << 24) |
    (bytes[off + 1] << 16) |
    (bytes[off + 2] << 8) |
    bytes[off + 3];
  off += 4;
  const solution = "0x" + bytesToHex(bytes.slice(off, off + solLen));
  return {
    coin: {
      parent_coin_info: parent,
      puzzle_hash: puzzleHash,
      amount: Number(amount),
    },
    puzzle_reveal: puzzleReveal,
    solution,
  };
}
