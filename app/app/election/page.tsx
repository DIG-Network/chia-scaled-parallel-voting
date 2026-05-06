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
  coinRecordsByPuzzleHash,
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
  type ElectionChoice,
} from "../lib/elections";
import {
  readElectionBootstrap,
  writeElectionBootstrap,
  mergeBootstrapPubkeyRegistered,
  type ElectionBootstrap,
} from "../lib/electionBootstrap";
import {
  writeBallotBootstrap,
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
import {
  discoverMempoolFeeXch,
  discoverRegistrationFeeXch,
} from "../lib/registrationFeeDiscovery";
import { findSyntheticPkForWalletAddress } from "../lib/sageSyntheticKey";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { createChainBackend } from "../lib/chainBackend";
import { walletConnect } from "../lib/walletConnectInstance";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { ElectionFinalizeQuietBanner } from "../components/ElectionFinalizeQuietBanner";
import { pollUntilConfirmed } from "../lib/pollUntil";
import { reconstructCatLineage } from "../lib/reconstructCatLineage";
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

      /** Height-lock + tally for expired / finished messaging (poll; same basis as finalize banner). */
      const POLL_ELECTION_LC_MS = 32_000;
      type ElectionLifecycle =
        | { status: "idle" }
        | { status: "loading" }
        | { status: "error"; message: string }
        | {
            status: "ready";
            finalized: boolean;
            quietElapsed: boolean;
            ballotsCast: number;
            peak: number;
            finalizeMinHeight: number;
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
          const electionStartHeight = Number(cfg.election_start_height ?? 0);
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
          const { listBallotBootstraps } = await import("../lib/ballotBootstrap");
          const ballots = listBallotBootstraps(launcherIdHex);
          const finalizedBallot = ballots.find((b) => !!b.finalizedAtHeight);
          const snap: SyncSnapshotShape = {
            registrationCount: state.registrationCount,
            registrationMerkleRootHex: state.registrationMerkleRootHex,
            finalized: !!finalizedBallot,
            voteOutcomeHex: finalizedBallot?.voteOutcomeHex ?? "0x" + "0".repeat(64),
            accumulatedFees: 0,
            electionStartHeight: state.electionStartHeight,
            votersHex: session.registeredPubkeysHex ?? [],
            smtRootHex: state.registrationMerkleRootHex,
          };
          setSnapshot(snap);
        } catch (e: any) {
          setSnapshotError(e?.message ?? String(e));
        } finally {
          setSnapshotLoading(false);
        }
      }, [session, launcherIdHex]);

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
            const { listBallotBootstraps } = await import("../lib/ballotBootstrap");
            const allBallots = listBallotBootstraps(launcherIdHex);
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

            if (snapshotRef.current?.finalized === true) {
              const peakSnap = await peakHeight();
              if (!cancelled) {
                const ph = peakSnap ?? 0;
                setElectionLc({
                  status: "ready",
                  finalized: true,
                  quietElapsed: true,
                  ballotsCast,
                  peak: ph,
                  finalizeMinHeight: ph,
                });
              }
              return;
            }

            // The Election Singleton itself doesn't carry a "finalized"
            // bit — that's a per-ballot state in the new model. We
            // treat the snapshot as finalized iff at least one tracked
            // ballot has a finalize confirmation in its bootstrap.
            const tipFinalized = allBallots.some((b) => !!b.finalizedAtHeight);
            const tip = { coinIdHex: "", finalized: tipFinalized };

            if (cancelled) return;

            const snapFresh = snapshotRef.current;
            if (tip.finalized || (snapFresh && snapFresh.finalized)) {
              const peakDone = await peakHeight();
              if (!cancelled) {
                const ph = peakDone ?? 0;
                setElectionLc({
                  status: "ready",
                  finalized: true,
                  quietElapsed: true,
                  ballotsCast,
                  peak: ph,
                  finalizeMinHeight: ph,
                });
              }
              return;
            }

            const peak = await peakHeight();
            const parsed = JSON.parse(configJson) as {
              election_length_blocks?: number | string;
              election_start_height?: number | string;
            };
            const len = Number(parsed.election_length_blocks ?? 0);
            const anchorFromConfig = Number(parsed.election_start_height ?? 0);
            const snapR = snapshotRef.current;
            const anchor =
              snapR?.electionStartHeight != null &&
              snapR.electionStartHeight > 0
                ? snapR.electionStartHeight
                : anchorFromConfig;

            if (cancelled) return;
            if (peak === null) {
              if (!cancelled) {
                setElectionLc({
                  status: "error",
                  message: "Peak height unavailable.",
                });
              }
              return;
            }
            if (anchor <= 0 || !Number.isFinite(anchor)) {
              if (!cancelled) {
                setElectionLc({
                  status: "error",
                  message:
                    "Election config is missing election_start_height — paste an updated ElectionConfig from the coordinator.",
                });
              }
              return;
            }

            const finalizeMinHeight = anchor + len;
            const quietElapsed = finalizeMinHeight <= peak;

            if (!cancelled) {
              setElectionLc({
                status: "ready",
                finalized: false,
                quietElapsed,
                ballotsCast,
                peak,
                finalizeMinHeight,
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
        const electionStartHeight = Number(cfg.election_start_height ?? 0);
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
        const { listBallotBootstraps } = await import("../lib/ballotBootstrap");
        const ballots = listBallotBootstraps(launcherIdHex);
        const finalizedBallot = ballots.find((b) => !!b.finalizedAtHeight);
        return {
          registrationCount: state.registrationCount,
          registrationMerkleRootHex: state.registrationMerkleRootHex,
          finalized: !!finalizedBallot,
          voteOutcomeHex: finalizedBallot?.voteOutcomeHex ?? "0x" + "0".repeat(64),
          accumulatedFees: 0,
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
          String(s.accumulatedFees ?? 0),
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
            const { listBallotBootstraps } = await import("../lib/ballotBootstrap");
            // Aggregate this voter's most-recent vote across all
            // tracked ballots (newest ballot wins if multiple).
            const allBallots = [...listBallotBootstraps(launcherIdHex)].sort(
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
            const { listBallotBootstraps } = await import("../lib/ballotBootstrap");
            // Tally aggregates votes across every tracked ballot
            // for this election. Aligns with the per-ballot model:
            // each Voting Coin lineage hangs off a specific ballot,
            // so we walk each ballot separately and union the rows.
            const allBallots = listBallotBootstraps(launcherIdHex);
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

      const votesClosed = useMemo(
        () =>
          electionLc.status === "ready" &&
          !electionLc.finalized &&
          electionLc.quietElapsed,
        [electionLc]
      );

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
        const electionStartHeight = Number(cfg.election_start_height ?? 0);
        if (!electionStartHeight) {
          setError("Election start height missing from session config — re-import.");
          return;
        }

        setError(null);
        setTxStatus(null);
        setBusy("Creating ballot…");

        try {
          await walletConnect.waitForInit();

          // ── 1. Find an XCH coin in the operator's wallet to fund the launcher.
          //     Need amount > 2 so change > 0 (the StandardLayer
          //     spend panics on `delegatedSpend([])`).
          setBusy("Finding XCH funder coin…");
          const userPh = await puzzleHashHexFromWalletAddress(address);
          if (!userPh) throw new Error("Could not decode Sage wallet address");
          const xchPh = "0x" + userPh;
          const xchCoins = await coinRecordsByPuzzleHash(xchPh, false);
          const candidates = xchCoins
            .filter((c) => c.spentHeight === 0 && c.amount >= 100)
            .sort((a, b) => a.amount - b.amount);
          if (candidates.length === 0) {
            throw new Error(
              "No spendable XCH coin (≥100 mojos) at your connected receive address. " +
                "Top up the wallet or switch addresses."
            );
          }
          const funderCoin = candidates[0];

          // Resolve synthetic pubkey for the funder coin's puzzle hash.
          const synthPk = await findSyntheticPkForWalletAddress(address);
          if (!synthPk) {
            throw new Error(
              "Could not resolve synthetic pubkey for receive address from Sage. " +
                "Wallet may have rejected chip0002_getPublicKeys."
            );
          }

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
          // ~25 minutes mainnet (52s/block), ~50 blocks. Configurable
          // via UI in a follow-up.
          const voteCloseHeight = peak + 50;
          // Deterministic placeholder outcome domain. Production
          // deployments would tree-hash a structured proposal here.
          const outcomeDomainHashHex = "0x" + "01".repeat(32);
          const voteThresholdNum = 1;
          const voteThresholdDen = 2;

          const createParams = {
            ballotSeedHex,
            voteCloseHeight,
            outcomeDomainHashHex,
          };

          // ── 4. createBallotBundle (singleton create_ballot action).
          setBusy("Building createBallot bundle…");
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
          setBusy("Awaiting Sage signature for createBallot…");
          const createBundleBytes = hexToBytes(created.spendBundleHex);
          const wcSpendsJson = wasm.extractWalletCoinSpendsFromBundle(createBundleBytes);
          const wcSpends = JSON.parse(wcSpendsJson);
          const sigHex = await walletConnect.signCoinSpends(wcSpends, false, false);
          if (!sigHex) throw new Error("Wallet rejected the createBallot signature request");

          setBusy("Verifying createBallot bundle locally…");
          const finalCreateBundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(wcSpends),
            sigHex
          );
          wasm.verifyBundleLocally(finalCreateBundleBytes, wasm.WasmNetwork.Mainnet);

          setBusy("Submitting createBallot bundle…");
          const createBundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(finalCreateBundleBytes)
          ) as SpendBundleJson;
          await pushTx(createBundleJson);

          setBusy("Polling for ballot launcher confirmation…");
          const launcherIdToWatch = created.ballotLauncherIdHex;
          const launcherOk = await pollUntilConfirmed({
            predicate: async () => {
              const rec = await coinRecordByName(launcherIdToWatch);
              return !!rec && (rec.confirmedHeight ?? 0) > 0;
            },
            pollMs: 30_000,
            timeoutMs: 600_000,
          });
          if (!launcherOk) {
            throw new Error("ballot launcher coin not confirmed within 10 min");
          }

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
          setBusy("Building launchBallot bundle…");
          const launchParams = {
            voteCloseHeight,
            outcomeDomainHashHex,
            voteThresholdNum,
            voteThresholdDen,
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

          setBusy("Verifying launchBallot bundle locally…");
          const launchBundleBytes = hexToBytes(launched.spendBundleHex);
          wasm.verifyBundleLocally(launchBundleBytes, wasm.WasmNetwork.Mainnet);

          setBusy("Submitting launchBallot bundle…");
          const launchBundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(launchBundleBytes)
          ) as SpendBundleJson;
          await pushTx(launchBundleJson);

          setBusy("Polling for eve ballot coin confirmation…");
          const eveIdToWatch = launched.eveBallotCoinIdHex;
          const eveOk = await pollUntilConfirmed({
            predicate: async () => {
              const rec = await coinRecordByName(eveIdToWatch);
              return !!rec && (rec.confirmedHeight ?? 0) > 0;
            },
            pollMs: 30_000,
            timeoutMs: 600_000,
          });
          if (!eveOk) {
            throw new Error("eve ballot coin not confirmed within 10 min");
          }
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
          };
          writeBallotBootstrap(bb);

          setTxStatus(
            `Ballot launched. close height ${voteCloseHeight} (~${50 * 52}s window). ` +
              `Voters can register / cast against ballot ${created.ballotLauncherIdHex.slice(0, 10)}…`
          );
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setBusy(null);
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
            const electionStartHeight = Number(cfg.election_start_height ?? 0);
            // SMT input must reflect on-chain registered voters, NOT
            // including the voter being registered (non-membership
            // proof). Filter out signingPk if the session bootstrap
            // already lists it (e.g. on retry).
            const otherPubkeys = (session.registeredPubkeysHex ?? []).filter(
              (p) => normalizeHex32(p) !== normalizeHex32(signingPk)
            );
            const unsignedJson = await wasm.registerBuildUnsignedCoinSpends(
              backend as any,
              session.configJson,
              signingPk,
              JSON.stringify(otherPubkeys),
              catParentSpendBytes,
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

            const pkNorm = normalizeHex32(signingPk);
            const regOk = await waitBroadcastConfirm({
              title: "Confirming registration",
              intro:
                "Waiting until your pubkey appears on the voter list seen from chain snapshots.",
              predicate: async () => {
                const s = await pullFreshSnapshot();
                return !!s?.votersHex?.some(
                  (v) => normalizeHex32(v) === pkNorm
                );
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
            setTxStatus("Registration confirmed on-chain.");
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
      const [pickedChoiceIdx, setPickedChoiceIdx] = useState<number | null>(null);
      const [freeformVote, setFreeformVote] = useState("");
      /** Replace-ballot flow: new choice index (must differ from current ballot). */
      const [changeBallotPickIdx, setChangeBallotPickIdx] = useState<number | null>(
        null
      );
      const [changeBallotFreeform, setChangeBallotFreeform] = useState("");
      // Two-call vote flow:
      //   1. wasm.voteBuildPreviewSpend → wallet-shape coin spends
      //      with a placeholder zero-sig in the memo.
      //   2. Sage signs (partial mode) → returns the canonical
      //      signature (the spend's only AGG_SIG_UNSAFE has the
      //      voter's pubkey + canonical message, so the partial
      //      aggregate IS that single sig).
      //   3. wasm.voteBuildFinalBundle → rebuilds the spend with
      //      the real sig embedded in the memo + uses the same
      //      sig as the bundle's aggregated_signature. Memo
      //      content doesn't affect the AGG_SIG message, so
      //      Sage's step-2 sig is still valid for the final
      //      spend.
      const handleVote = async () => {
        if (!session || !effectiveVoterPk) return;
        setError(null);
        setTxStatus(null);
        setBusy("Voting…");
        try {
          // ── 1. Resolve vote_data from UI input ────────────────
          let voteHex: string;
          if (session.choices && session.choices.length > 0) {
            if (pickedChoiceIdx === null) {
              throw new Error("Pick a choice before voting.");
            }
            voteHex = session.choices[pickedChoiceIdx].voteDataHex;
          } else {
            voteHex = freeformVote.trim();
            if (!voteHex.startsWith("0x")) voteHex = "0x" + voteHex;
            if (voteHex.length !== 66) {
              const enc = new TextEncoder().encode(freeformVote);
              const hash = await crypto.subtle.digest("SHA-256", enc);
              voteHex =
                "0x" +
                Array.from(new Uint8Array(hash))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");
            }
          }

          // ── 2. Pick the open ballot to cast against ────────────
          // Reads from per-ballot bootstrap (populated by
          // handleCreateAndLaunchBallot or share-bundle import). The
          // CHIP-rev-2026-05-02 vote flow is per-ballot, not
          // per-election: every cast_vote spends one specific Ballot
          // Coin singleton's oracle action and is curried to a
          // specific (vote_close_height, threshold, registration
          // snapshot).
          setBusy("Locating an open ballot…");
          const peak = await peakHeight();
          if (!peak) throw new Error("Could not read chain peak");
          const ballot = pickOpenBallotForVoting(launcherIdHex, peak);
          if (!ballot) {
            throw new Error(
              "No open ballot in this session. Ask the deployer to mint one (Mint a new ballot card), " +
                "or import a share bundle that includes ballot bootstrap."
            );
          }

          const params = {
            ballotLauncherIdHex: ballot.ballotLauncherIdHex,
            voteDataHex: voteHex,
            voteCloseHeight: ballot.voteCloseHeight,
            voteThresholdNum: ballot.voteThresholdNum,
            voteThresholdDen: ballot.voteThresholdDen,
            registrationMerkleRootSnapshotHex:
              ballot.registrationMerkleRootSnapshotHex,
            registrationVoteWeightSnapshot:
              ballot.registrationVoteWeightSnapshot,
            votingCoinAmount: 1,
          };
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(cfg.election_start_height ?? 0);

          const backend = createChainBackend();

          // ── 3. Sage signs the vote_message via a one-condition
          //      AggSigUnsafe shim spend. The wallet's partial-mode
          //      aggregate is byte-for-byte equal to
          //      sign_unsafe(vote_message). ─────────────────────────
          setBusy("Building preview vote spend…");
          const previewJson = await wasm.castVoteBuildPreviewSpend(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            JSON.stringify(params)
          );
          const preview = JSON.parse(previewJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            voteMessageHex: string;
          };

          setBusy("Awaiting Sage signature on vote message…");
          const voteSigHex = await walletConnect.signCoinSpends(
            preview.coinSpends,
            true,  // partial — single AGG_SIG_UNSAFE
            false  // no auto-submit
          );
          if (!voteSigHex) {
            throw new Error("Wallet rejected the vote-message signature request");
          }

          // ── 4. Build the real cast_vote coin_spends with the
          //      voter's signature embedded in the mint_voting_coin
          //      memo. Returns the unsigned bundle in wallet shape;
          //      Sage will sign it (its AGG_SIG_ME conditions) in the
          //      next step. ────────────────────────────────────────
          setBusy("Building cast_vote bundle…");
          const unsignedJson = await wasm.castVoteBuildUnsignedCoinSpends(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            JSON.stringify(params),
            voteSigHex,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const unsigned = JSON.parse(unsignedJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            votingCoinIdHex: string;
            voteSignatureHex: string;
            voteMessageHex: string;
          };

          // ── 5. Sage signs the full bundle's AGG_SIG_ME conditions.
          setBusy("Awaiting Sage signature on bundle…");
          const aggSigHex = await walletConnect.signCoinSpends(
            unsigned.coinSpends,
            true,  // partial — wallet returns aggregate without auto-submit
            false
          );
          if (!aggSigHex) {
            throw new Error("Wallet rejected the bundle signature request");
          }

          // ── 6. Assemble + verify + push ────────────────────────
          setBusy("Assembling and verifying bundle…");
          const bundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(unsigned.coinSpends),
            aggSigHex
          );
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);

          setBusy("Submitting bundle to mempool (coinset)…");
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          // ── 7. Optimistic state + on-chain confirm ─────────────
          const vdCanon = voteHex.trim().startsWith("0x")
            ? voteHex.trim().toLowerCase()
            : `0x${normalizeHex32(voteHex)}`;
          setOptimisticVoteDataHex(vdCanon);

          const pkNorm = normalizeHex32(effectiveVoterPk);
          const vdNorm = normalizeHex32(voteHex);
          const voteOk = await waitBroadcastConfirm({
            title: "Confirming vote",
            intro:
              "Waiting until coinset-backed reads detect your ballot (same source as tally).",
            predicate: async () => {
              const b = createChainBackend();
              const rowsJson = (await wasm.collectVotesForBallot(
                b as any,
                session.configJson,
                ballot.ballotLauncherIdHex,
                JSON.stringify([effectiveVoterPk])
              )) as string;
              const rows = JSON.parse(rowsJson) as Array<
                Record<string, string | undefined>
              >;
              for (const row of rows ?? []) {
                const rk = normalizeHex32(
                  row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
                );
                const rv = normalizeHex32(
                  row.vote_data_hex ?? row.voteDataHex ?? ""
                );
                if (rk === pkNorm && rv === vdNorm) return true;
              }
              return false;
            },
          });
          if (voteOk) {
            setTxStatus("Vote confirmed on-chain.");
          }
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setBusy(null);
        }
      };

      /** Before finalize: oracle + CAT change_vote (two spends; wallet signs full aggregate). */
      const handleChangeVote = async () => {
        if (!session || !effectiveVoterPk || !resolvedMyVoteDataHex) return;
        setError(null);
        setTxStatus(null);
        setBusy("Replacing ballot…");
        try {
          // ── 1. Resolve new vote_data from UI input ─────────────
          let voteHex: string;
          if (session.choices && session.choices.length > 0) {
            if (changeBallotPickIdx === null) {
              throw new Error("Pick a new choice before replacing your ballot.");
            }
            voteHex = session.choices[changeBallotPickIdx].voteDataHex;
          } else {
            voteHex = changeBallotFreeform.trim();
            if (!voteHex.startsWith("0x")) voteHex = "0x" + voteHex;
            if (voteHex.length !== 66) {
              const enc = new TextEncoder().encode(changeBallotFreeform);
              const hash = await crypto.subtle.digest("SHA-256", enc);
              voteHex =
                "0x" +
                Array.from(new Uint8Array(hash))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");
            }
          }
          if (
            normalizeHex32(voteHex) === normalizeHex32(resolvedMyVoteDataHex)
          ) {
            throw new Error(
              "New ballot must differ from your current on-chain vote."
            );
          }

          // ── 2. Pick the open ballot the existing vote is on ─────
          setBusy("Locating an open ballot…");
          const peak = await peakHeight();
          if (!peak) throw new Error("Could not read chain peak");
          const ballot = pickOpenBallotForVoting(launcherIdHex, peak);
          if (!ballot) {
            throw new Error(
              "No open ballot in this session. update_vote is per-ballot — make sure you're voting on a ballot whose snapshot is in your bootstrap."
            );
          }

          // ── 3. Find the voter's CURRENT Voting Coin via collectVotesForBallot.
          //      The row tells us voting_coin_id + registration_coin_id —
          //      both required by UpdateVoteParams. ──────────────────
          const backend = createChainBackend();
          const rowsJson = (await wasm.collectVotesForBallot(
            backend as any,
            session.configJson,
            ballot.ballotLauncherIdHex,
            JSON.stringify([effectiveVoterPk])
          )) as string;
          const rows = JSON.parse(rowsJson) as Array<
            Record<string, string | undefined>
          >;
          const pkNorm = normalizeHex32(effectiveVoterPk);
          const myRow = rows.find(
            (r) =>
              normalizeHex32(
                r.voter_pubkey_hex ?? r.voterPubkeyHex ?? ""
              ) === pkNorm
          );
          if (!myRow) {
            throw new Error(
              "Could not locate your existing Voting Coin on chain — has the prior cast_vote confirmed?"
            );
          }
          const votingCoinIdHex =
            myRow.voting_coin_id_hex ?? myRow.votingCoinIdHex ?? "";
          const registrationCoinIdHex =
            myRow.registration_coin_id_hex ?? myRow.registrationCoinIdHex ?? "";
          const oldVoteDataHex =
            myRow.vote_data_hex ?? myRow.voteDataHex ?? resolvedMyVoteDataHex;
          if (!votingCoinIdHex || !registrationCoinIdHex) {
            throw new Error("collectVotesForBallot row missing voting / registration coin ids.");
          }

          const params = {
            votingCoinIdHex,
            oldVoteDataHex,
            newVoteDataHex: voteHex,
            registrationCoinIdHex,
            ballotLauncherIdHex: ballot.ballotLauncherIdHex,
            voteCloseHeight: ballot.voteCloseHeight,
            voteThresholdNum: ballot.voteThresholdNum,
            voteThresholdDen: ballot.voteThresholdDen,
            registrationMerkleRootSnapshotHex:
              ballot.registrationMerkleRootSnapshotHex,
            registrationVoteWeightSnapshot:
              ballot.registrationVoteWeightSnapshot,
          };
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(cfg.election_start_height ?? 0);

          // ── 4. Sage signs new_vote_message via the AggSigUnsafe shim.
          setBusy("Building change-vote preview spend…");
          const previewJson = await wasm.updateVoteBuildPreviewSpend(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            JSON.stringify(params)
          );
          const preview = JSON.parse(previewJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            voteMessageHex: string;
          };

          setBusy("Awaiting Sage signature on new vote message…");
          const newVoteSigHex = await walletConnect.signCoinSpends(
            preview.coinSpends,
            true,
            false
          );
          if (!newVoteSigHex) {
            throw new Error("Wallet rejected the new-vote-message signature request");
          }

          // ── 5. Build the unsigned update_vote coin_spends. ──────
          setBusy("Building update_vote bundle…");
          const unsignedJson = await wasm.updateVoteBuildUnsignedCoinSpends(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            JSON.stringify(params),
            newVoteSigHex,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const unsigned = JSON.parse(unsignedJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            recreatedVotingCoinIdHex: string;
            newVoteSignatureHex: string;
            newVoteMessageHex: string;
          };

          // ── 6. Sage signs the bundle aggregate.
          setBusy("Awaiting Sage signature on bundle…");
          const aggSigHex = await walletConnect.signCoinSpends(
            unsigned.coinSpends,
            true,
            false
          );
          if (!aggSigHex) {
            throw new Error("Wallet rejected the bundle signature request");
          }

          // ── 7. Assemble + verify + push ────────────────────────
          setBusy("Assembling and verifying bundle…");
          const bundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(unsigned.coinSpends),
            aggSigHex
          );
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);

          setBusy("Submitting change-vote bundle…");
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          // ── 8. Optimistic state + on-chain confirm ─────────────
          const vdCanon = voteHex.trim().startsWith("0x")
            ? voteHex.trim().toLowerCase()
            : `0x${normalizeHex32(voteHex)}`;
          setOptimisticVoteDataHex(vdCanon);

          const vdNorm = normalizeHex32(voteHex);
          const ok = await waitBroadcastConfirm({
            title: "Confirming replaced ballot",
            intro:
              "Waiting until coinset-backed reads show your updated vote_data.",
            predicate: async () => {
              const b = createChainBackend();
              const rowsJson2 = (await wasm.collectVotesForBallot(
                b as any,
                session.configJson,
                ballot.ballotLauncherIdHex,
                JSON.stringify([effectiveVoterPk])
              )) as string;
              const rows2 = JSON.parse(rowsJson2) as Array<
                Record<string, string | undefined>
              >;
              for (const row of rows2 ?? []) {
                const rk = normalizeHex32(
                  row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
                );
                const rv = normalizeHex32(
                  row.vote_data_hex ?? row.voteDataHex ?? ""
                );
                if (rk === pkNorm && rv === vdNorm) return true;
              }
              return false;
            },
          });
          if (ok) {
            setTxStatus("Ballot replaced on-chain.");
            setChangeBallotPickIdx(null);
            setChangeBallotFreeform("");
          }
        } catch (e: unknown) {
          setError(e instanceof Error ? e.message : String(e));
        } finally {
          setBusy(null);
        }
      };

      // ── RELEASE COLLATERAL FLOW ─────────────────────────────────
      const handleRelease = async () => {
        if (!session || !effectiveVoterPk) return;
        setError(null);
        setTxStatus(null);
        setBusy("Releasing collateral…");
        try {
          const baseline = snapshotBrief(snapshot);
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(cfg.election_start_height ?? 0);
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
          const voterPubkeys = session.registeredPubkeysHex ?? [];

          // ── 3. Build unsigned coin_spends (Sage signs externally).
          setBusy("Building release coin_spends…");
          const unsignedJson = await wasm.releaseCollateralBuildUnsignedCoinSpends(
            backend as any,
            session.configJson,
            effectiveVoterPk,
            JSON.stringify(voterPubkeys),
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
            setTxStatus("Collateral release reflected on-chain.");
          }
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setBusy(null);
        }
      };

      // ── FINALIZE FLOW — modal + Sage bundle submit ──────────────
      const handleFinalize = async () => {
        if (!session || !address) return;
        if (!votesClosed) {
          setError(
            "Finalize is disabled until the voting period has ended " +
              "(finalize time-lock on the election singleton)."
          );
          return;
        }
        if (!session.provingKeyBase64) {
          setError(
            "This browser session does not have the Groth16 proving key. " +
              "Import the election share bundle from the organizer (create flow / Share bundle) — " +
              "it includes the key anyone can use to finalize once the time-lock passes."
          );
          return;
        }
        setError(null);
        setTxStatus(null);
        setBusy("Finalizing election…");
        setFinalizeModal({
          title: "Finalize election",
          phase: "collect",
          detail: "Initializing Sage Wallet…",
          collect: null,
        });

        try {
          await walletConnect.waitForInit();

          let dest =
            finalizePayoutPh ??
            (await puzzleHashHexFromWalletAddress(address.trim()));
          if (!dest && effectiveVoterPk) {
            dest = wasm.standardPuzzleHash(effectiveVoterPk);
          }
          if (!dest) {
            throw new Error(
              "Could not derive an XCH puzzle hash from your Sage address for the finalizer reward. " +
                "Reconnect the wallet or wait for pubkey resolution."
            );
          }

          if (!session.choices || session.choices.length === 0) {
            throw new Error(
              "Election has no UI choices defined; cannot auto-tally. " +
                "Re-import a shareable bundle that includes choices, or " +
                "extend the finalize flow with a manual outcome input."
            );
          }

          const backend = createChainBackend();

          setFinalizeModal({
            title: "Finalize election",
            phase: "collect",
            detail:
              "Each registered voter may require multiple chain reads " +
              "(hint → parent spend → memo decode). Stay on this tab.",
            collect: null,
          });
          type VoteWireLite = {
            vote_data_hex?: string;
            voteDataHex?: string;
          };

          type CollectProgressWasm = Partial<FinalizeCollectPayload> & {
            voter_index?: unknown;
            voters_total?: unknown;
            stage?: unknown;
            ballotsCollected?: unknown;
            ballots_collected?: unknown;
          };

          const readCollectProgress = (
            raw: unknown
          ): FinalizeCollectPayload | null => {
            if (!raw || typeof raw !== "object") return null;
            const o = raw as CollectProgressWasm;
            const vi =
              typeof o.voterIndex === "number"
                ? o.voterIndex
                : typeof o.voter_index === "number"
                  ? o.voter_index
                  : null;
            const vt =
              typeof o.votersTotal === "number"
                ? o.votersTotal
                : typeof o.voters_total === "number"
                  ? o.voters_total
                  : null;
            const stRaw = typeof o.stage === "string" ? o.stage : null;
            const bcRaw =
              typeof o.ballotsCollected === "number"
                ? o.ballotsCollected
                : typeof o.ballots_collected === "number"
                  ? o.ballots_collected
                  : undefined;
            if (vi === null || vt === null || stRaw === null) return null;
            const ballotCount =
              typeof bcRaw === "number" ? bcRaw : 0;
            if (
              !(
                stRaw === "syncElectionSingleton" ||
                stRaw === "fetchHintCoins" ||
                stRaw === "fetchParentSpend" ||
                stRaw === "decodeBallot"
              )
            ) {
              return null;
            }
            return {
              voterIndex: vi,
              votersTotal: vt,
              stage: stRaw,
              ballotsCollected: ballotCount,
            };
          };

          // CHIP rev 2026-05-02: votes are per-ballot. Pick the
          // newest closed ballot whose snapshot we hold; the
          // collectVotesForBallot walk traverses the Voting Coin
          // lineage hint-indexed by voter_hint, scoped to this one
          // ballot's launcher.
          const peakNow = await peakHeight();
          if (!peakNow) throw new Error("Could not read chain peak");
          const closedBallots = (await import("../lib/ballotBootstrap"))
            .listBallotBootstraps(launcherIdHex)
            .filter((b) => b.voteCloseHeight <= peakNow && !!b.eveBallotCoinIdHex)
            .sort((a, b) => (b.launchedAtHeight ?? 0) - (a.launchedAtHeight ?? 0));
          const finalizeBallot = closedBallots[0];
          if (!finalizeBallot) {
            throw new Error(
              "No closed ballot in this session. The vote close height must have passed for the ballot you want to finalize."
            );
          }

          // Voter pubkey list — the union of every voter we know about
          // from the session bootstrap. Empty list = no votes; the
          // SDK errors below if zero ballots collected.
          const voterPubkeys = session.registeredPubkeysHex ?? [];

          setFinalizeModal({
            title: "Finalize election",
            phase: "collect",
            detail:
              `Walking Voting Coin lineage for ballot ${finalizeBallot.ballotLauncherIdHex.slice(0, 10)}… ` +
              `(${voterPubkeys.length} known voter pubkey(s)).`,
            collect: null,
          });
          const wireVotesJson = (await wasm.collectVotesForBallot(
            backend as any,
            session.configJson,
            finalizeBallot.ballotLauncherIdHex,
            JSON.stringify(voterPubkeys)
          )) as string;
          const wireVotes = JSON.parse(wireVotesJson) as VoteWireLite[];

          setFinalizeModal({
            title: "Finalize election",
            phase: "tally",
            detail: "Applying plurality tally to recovered ballot payloads…",
          });

          const tally = new Map<string, number>();
          const normHex = (h: unknown) =>
            String(h ?? "")
              .toLowerCase()
              .replace(/^0x/, "");
          for (const v of wireVotes) {
            const raw = v.vote_data_hex ?? v.voteDataHex;
            const k = normHex(raw);
            if (!k || k === "00".repeat(32)) continue;
            tally.set(k, (tally.get(k) ?? 0) + 1);
          }
          let winner = session.choices[0];
          let winnerCount = -1;
          for (const c of session.choices) {
            const k = normHex(c.voteDataHex);
            const n = tally.get(k) ?? 0;
            if (n > winnerCount) {
              winner = c;
              winnerCount = n;
            }
          }
          if (winnerCount < 1) {
            throw new Error(
              "No valid cast ballots recovered from chain hints — finalize would fail BelowThreshold."
            );
          }
          const outcomeHex = winner.voteDataHex;

          setFinalizeModal({
            title: "Finalize election",
            phase: "prove",
            outcomeSummary:
              `Outcome: "${winner.label}" (${winnerCount} ballot(s)); ` +
              `building aggregates + Groth16 proof.`,
            detail:
              "The proving step typically runs tens of seconds to a few minutes depending on quorum size — leave this tab open.",
          });
          const pkBytes = base64ToBytes(session.provingKeyBase64);
          const cfg = JSON.parse(session.configJson);
          const electionStartHeight = Number(cfg.election_start_height ?? 0);
          // Per-ballot finalize. Snapshot fields MUST mirror what
          // `BallotIssuer::launch_ballot` curried into the eve Ballot
          // Coin (captured by handleCreateAndLaunchBallot via
          // wasm.readElectionSingletonState).
          const finalizeParams = {
            voteCloseHeight: finalizeBallot.voteCloseHeight,
            voteThresholdNum: finalizeBallot.voteThresholdNum,
            voteThresholdDen: finalizeBallot.voteThresholdDen,
            registrationMerkleRootSnapshotHex:
              finalizeBallot.registrationMerkleRootSnapshotHex,
            registrationVoteWeightSnapshot:
              finalizeBallot.registrationVoteWeightSnapshot,
          };
          const bundleHex = await wasm.buildBallotFinalizeBundle(
            backend as any,
            session.configJson,
            finalizeBallot.ballotLauncherIdHex,
            outcomeHex,
            JSON.stringify(finalizeParams),
            wireVotesJson,
            pkBytes,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          const bundleBytes = hexToBytes(bundleHex);

          setFinalizeModal({
            title: "Finalize election",
            phase: "verify",
            detail: "Dry-running CLVM spends and validating BLS / proof shape locally…",
          });
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);

          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          const finalizedBefore = (await pullFreshSnapshot())?.finalized === true;

          // CHIP‑0002: prefer full-node mempool submit over `chip0002_sendTransaction`.
          // Finalize has no wallet-owned AGG_SIG (identity agg sig); Sage WC relay often
          // fails to propagate large proof-bearing bundles. Same path as oracle `pushTx`.
          setFinalizeModal({
            title: "Broadcast finalized bundle",
            phase: "submit",
            detail:
              "Sending to api.coinset.org (Groth16 proof + singleton spend included in mempool submit)…",
          });
          await pushTx(bundleJson);

          setFinalizeModal(null);

          // Persist finalize state to the ballot bootstrap so
          // syncSnapshot's `finalized` aggregator picks it up. Done
          // optimistically right after push: pullFreshSnapshot
          // already polls until visible, but the snapshot tracker
          // only sees finalize via this bootstrap field.
          const peakAfter = await peakHeight();
          const updatedBootstrap: BallotBootstrap = {
            ...finalizeBallot,
            finalizedAtHeight: peakAfter ?? finalizeBallot.voteCloseHeight,
            voteOutcomeHex: outcomeHex.startsWith("0x")
              ? outcomeHex
              : "0x" + outcomeHex,
          };
          writeBallotBootstrap(updatedBootstrap);

          const finOk = await waitBroadcastConfirm({
            title: "Confirming finalization",
            intro:
              "Waiting until the election snapshot reflects ballot finalize.",
            predicate: async () => {
              const s = await pullFreshSnapshot();
              return !!(s?.finalized && !finalizedBefore);
            },
          });
          if (finOk) {
            setTxStatus("Election finalized on-chain.");
          }
        } catch (e: any) {
          setError(e?.message ?? String(e));
        } finally {
          setFinalizeModal(null);
          setBusy(null);
          void syncSnapshot();
        }
      };

      // ── ORACLE FLOW ─────────────────────────────────────────────
      const handleOracle = async () => {
        // CHIP rev 2026-05-02: the standalone `buildOracleBundle`
        // export was removed. The Ballot Coin oracle action is now
        // co-spent automatically by every cast_vote / update_vote /
        // finalize spend (it's the open-state check), so a separate
        // oracle button is no longer meaningful. Kept as a no-op so
        // existing JSX bindings still compile; will be removed in a
        // follow-up cleanup.
        setError(
          "Standalone oracle action is deprecated. The oracle is now co-spent " +
            "implicitly by every cast_vote / update_vote / finalize spend."
        );
      };

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
                <div>
                  <div className="text-xs text-[var(--color-muted)]">
                    Reg. fee
                  </div>
                  <div className="mono">
                    {formatXch(cfg.registration_fee)} XCH
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
      const totalLockedCollateral =
        snapshot === null
          ? null
          : BigInt(snapshot.registrationCount) * minCollateralMojos;
      const totalRegFees =
        snapshot === null
          ? null
          : BigInt(snapshot.registrationCount) * BigInt(cfg.registration_fee);

      const finalizedOnChain = snapshot?.finalized === true;

      const showElectionExpiredNoBallots =
        snapshot !== null &&
        electionLc.status === "ready" &&
        !electionLc.finalized &&
        electionLc.quietElapsed &&
        electionLc.ballotsCast === 0;

      const showElectionFinishedVotingPeriod =
        snapshot !== null &&
        electionLc.status === "ready" &&
        !electionLc.finalized &&
        electionLc.quietElapsed &&
        electionLc.ballotsCast > 0;

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

          <ElectionFinalizeQuietBanner
            finalized={snapshot?.finalized === true}
            lifecycleErrorMessage={
              electionLc.status === "error" ? electionLc.message : undefined
            }
            lifecycleStatus={
              electionLc.status === "idle" ? "loading" : electionLc.status
            }
            quietCountdown={
              electionLc.status === "ready" && !electionLc.finalized
                ? {
                    blocksRemaining: Math.max(
                      0,
                      electionLc.finalizeMinHeight - electionLc.peak
                    ),
                    finalizeMinHeight: electionLc.finalizeMinHeight,
                    peak: electionLc.peak,
                  }
                : null
            }
            show={
              snapshot !== null &&
              chainStatus === "deployed" &&
              !(
                electionLc.status === "ready" &&
                !electionLc.finalized &&
                electionLc.quietElapsed
              )
            }
          />

          {/* ────────── Election parameters ────────── */}
          <section className="card-elev">
            <h2 className="text-lg font-semibold mb-4">Election parameters</h2>
            <div className="grid sm:grid-cols-3 gap-4">
              <Stat
                label="Minimum collateral (CAT)"
                value={`${formatCat(cfg.collateral_amount)} (${collateralAssetShort})`}
              />
              <Stat
                label="Registration fee"
                value={`${formatXch(cfg.registration_fee)} XCH`}
              />
              <Stat
                label="Window"
                value={`${cfg.election_length_blocks} blocks`}
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
                label="Locked collateral (floor)"
                value={
                  totalLockedCollateral === null
                    ? "—"
                    : `${formatCat(totalLockedCollateral)} (${collateralAssetShort})`
                }
                hint="Uses minimum per registrant; higher locks are supported at registration."
              />
              <Stat
                label="Ballots cast"
                value={
                  electionLc.status === "ready"
                    ? electionLc.ballotsCast.toLocaleString()
                    : "—"
                }
              />
              <Stat
                label="Total reg. fees collected"
                value={
                  totalRegFees === null ? "—" : `${formatXch(totalRegFees)} XCH`
                }
              />
              <Stat
                label="Status"
                value={
                  snapshot === null
                    ? "—"
                    : snapshot.finalized
                    ? "Finalized"
                      : electionLc.status === "ready"
                        ? electionLc.quietElapsed &&
                          electionLc.ballotsCast === 0
                          ? "Expired"
                          : electionLc.quietElapsed
                            ? "Voting ended"
                            : "Open"
                    : "Open"
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
              <Stat
                label="Accumulated fees"
                value={
                  snapshot === null
                    ? "—"
                    : `${formatXch(snapshot.accumulatedFees)} XCH`
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
          {(busy || txStatus || error) && (
            <section className="card">
              {busy && (
                <div className="flex items-center gap-2 text-[var(--color-accent)]">
                  <div className="w-3 h-3 rounded-full bg-[var(--color-accent)] animate-pulse" />
                  <span>{busy}</span>
                </div>
              )}
              {txStatus && (
                <div className="text-[var(--color-accent)]">{txStatus}</div>
              )}
              {error && (
                <div className="text-[var(--color-danger)] text-sm whitespace-pre-wrap">
                  {error}
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
                      <p className="text-sm text-[var(--color-muted)] mb-3">
                        Registration fee{" "}
                        <span className="font-medium text-[var(--color-foreground)]">
                          {formatXch(cfg.registration_fee)} XCH
                        </span>{" "}
                        (per voter).
                      </p>
                      <label className="block text-xs font-medium text-[var(--color-muted)] mb-1.5">
                        CAT to lock (minimum {formatCat(cfg.collateral_amount)})
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
                      Vote-close height defaults to peak + 50 (~25 min on
                      mainnet).
                    </p>
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

                {/* Step 2 — ballot (meaningful UI only once registered + pubkey) */}
                <div
                  className={`rounded-xl border p-5 ${
                    !myReg
                      ? "border-dashed border-[var(--color-border)] bg-[var(--color-bg)]/50"
                      : resolvedMyVoteDataHex
                        ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.04]"
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
                      {resolvedMyVoteDataHex
                        ? "Your ballot"
                        : "Cast your ballot"}
                    </span>
                    {!myReg && (
                      <span className="text-xs text-[var(--color-muted)]">
                        Unlocks after step&nbsp;1
                      </span>
                    )}
                  </div>

                  {!myReg ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Ballot choices and the submit button appear here after
                      you&apos;ve registered. Use{" "}
                      <span className="font-medium text-[var(--color-foreground)]">
                        Register to vote
                      </span>{" "}
                      above.
                    </p>
                  ) : !effectiveVoterPk ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Voting pubkeys aren&apos;t available yet (waiting for Sage
                      or chain snapshot). Refresh state or reopen this page once
                      the wallet resolves your synthetic key.
                    </p>
                  ) : votesClosed && !resolvedMyVoteDataHex ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      {showElectionExpiredNoBallots
                        ? "Election expired — the voting window closed with no ballots cast."
                        : "Election finished — the voting window closed before finalization."}{" "}
                      New ballots aren&apos;t accepted from this UI.
                    </p>
                  ) : resolvedMyVoteDataHex ? (
                    <div className="space-y-3 rounded-lg border border-[var(--color-accent)]/35 bg-[var(--color-accent)]/[0.06] p-4">
                      <p className="text-sm font-medium text-[var(--color-accent)]">
                        You already voted in this election.
                      </p>
                      {votesClosed && (
                        <p className="text-xs text-[var(--color-muted)]">
                          The voting window has closed — your ballot remains
                          on-chain.
                        </p>
                      )}
                      {optimisticVoteDataHex && !indexedMyVoteDataHex && (
                        <p className="text-xs text-amber-800 dark:text-amber-300">
                          Confirming your ballot with the indexer (usually one
                          block)…
                        </p>
                      )}
                      {(() => {
                        const vn = normalizeHex32(resolvedMyVoteDataHex);
                        const matched = session.choices?.find(
                          (c) => normalizeHex32(c.voteDataHex) === vn
                        );
                        return matched ? (
                          <div className="space-y-1">
                  <div className="text-sm text-[var(--color-muted)]">
                              Your choice
                  </div>
                            <div className="text-lg font-semibold">
                              {matched.label}
                            </div>
                            <div className="mono text-xs text-[var(--color-muted)]">
                              {truncHex(resolvedMyVoteDataHex, 12, 6)}
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-1">
                            <div className="text-sm text-[var(--color-muted)]">
                              Vote payload
                            </div>
                            <div className="mono text-sm break-all">
                              {truncHex(resolvedMyVoteDataHex, 18, 8)}
                            </div>
                          </div>
                        );
                      })()}
                      {!snapshot?.finalized &&
                        !votesClosed &&
                        myReg &&
                        effectiveVoterPk && (
                          <div className="mt-4 pt-4 border-t border-[var(--color-border)] space-y-3">
                            <p className="text-sm font-medium text-[var(--color-foreground)]">
                              Replace ballot
                            </p>
                            <p className="text-xs text-[var(--color-muted)] leading-relaxed">
                              Until finalization you can publish a corrected vote
                              (
                              <code className="mono text-[11px]">change_vote</code>
                              + oracle). Signing covers two coin spends — approve
                              the full bundle in Sage.
                            </p>
                            {session.choices && session.choices.length > 0 ? (
                              <>
                                <div className="space-y-1">
                                  {session.choices.map((c, i) => (
                                    <label
                                      key={`ch-${c.voteDataHex}`}
                                      className={`flex items-center gap-3 p-2 rounded-lg border cursor-pointer transition-colors ${
                                        changeBallotPickIdx === i
                                          ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                                          : "border-[var(--color-border)] hover:border-[var(--color-accent)]"
                                      }`}
                                    >
                  <input
                                        type="radio"
                                        name="changeChoice"
                                        value={i}
                                        checked={changeBallotPickIdx === i}
                                        onChange={() =>
                                          setChangeBallotPickIdx(i)
                                        }
                                        disabled={
                                          !!busy ||
                                          normalizeHex32(c.voteDataHex) ===
                                            normalizeHex32(
                                              resolvedMyVoteDataHex
                                            )
                                        }
                                        className="accent-[var(--color-accent)]"
                                      />
                                      <div className="flex-1">
                                        <div className="font-medium">{c.label}</div>
                                        <div className="mono text-xs text-[var(--color-muted)]">
                                          {truncHex(c.voteDataHex, 10, 6)}
                                        </div>
                                      </div>
                                    </label>
                                  ))}
                                </div>
                                <button
                                  type="button"
                                  onClick={handleChangeVote}
                                  className="btn-secondary text-sm"
                                  disabled={
                                    !!busy ||
                                    changeBallotPickIdx === null ||
                                    !effectiveVoterPk
                                  }
                                >
                                  Replace with selected choice
                                </button>
                              </>
                            ) : (
                              <>
                                <input
                                  value={changeBallotFreeform}
                                  onChange={(e) =>
                                    setChangeBallotFreeform(e.target.value)
                                  }
                                  placeholder="New vote payload (text or 0x-hex)"
                                  className="input text-sm"
                                />
                                <button
                                  type="button"
                                  onClick={handleChangeVote}
                                  className="btn-secondary text-sm"
                                  disabled={
                                    !!busy ||
                                    !changeBallotFreeform.trim() ||
                                    !effectiveVoterPk
                                  }
                                >
                                  Replace with new payload
                                </button>
                              </>
                            )}
                          </div>
                        )}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {session.choices && session.choices.length > 0 ? (
                        <>
                          <div className="text-sm text-[var(--color-muted)]">
                            Pick one option. On-chain{" "}
                            <span className="mono font-normal">
                              vote_data =
                              sha256(&quot;vote:&quot; + label)
                            </span>
                            .
                          </div>
                          <div className="space-y-1">
                            {session.choices.map((c, i) => (
                              <label
                                key={c.voteDataHex}
                                className={`flex items-center gap-3 p-2 rounded-lg border cursor-pointer transition-colors ${
                                  pickedChoiceIdx === i
                                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                                    : "border-[var(--color-border)] hover:border-[var(--color-accent)]"
                                }`}
                              >
                                <input
                                  type="radio"
                                  name="choice"
                                  value={i}
                                  checked={pickedChoiceIdx === i}
                                  onChange={() => setPickedChoiceIdx(i)}
                                  disabled={
                                    !!busy ||
                                    !myReg ||
                                    !effectiveVoterPk ||
                                    snapshot?.finalized ||
                                    votesClosed
                                  }
                                  className="accent-[var(--color-accent)]"
                                />
                                <div className="flex-1">
                                  <div className="font-medium">{c.label}</div>
                                  <div className="mono text-xs text-[var(--color-muted)]">
                                    {truncHex(c.voteDataHex, 10, 6)}
                                  </div>
                                </div>
                              </label>
                            ))}
                          </div>
                          <button
                            type="button"
                            onClick={handleVote}
                            className="btn-primary"
                            disabled={
                              !!busy ||
                              !myReg ||
                              !effectiveVoterPk ||
                              pickedChoiceIdx === null ||
                              snapshot?.finalized ||
                              votesClosed
                            }
                          >
                            Cast vote
                          </button>
                        </>
                      ) : (
                        <>
                          <div className="text-sm text-[var(--color-muted)]">
                            No UI choices defined. Enter text — it is hashed
                            to a 32-byte vote payload.
                          </div>
                          <input
                            value={freeformVote}
                            onChange={(e) => setFreeformVote(e.target.value)}
                    placeholder="yes"
                    className="input"
                  />
                  <button
                            type="button"
                    onClick={handleVote}
                    className="btn-primary"
                    disabled={
                              !!busy ||
                              !myReg ||
                              !effectiveVoterPk ||
                              !freeformVote.trim() ||
                              snapshot?.finalized ||
                              votesClosed
                    }
                  >
                    Cast vote
                  </button>
                        </>
                      )}
                    </div>
                  )}
                </div>

                {/* Step 3 — finalize election (permissionless once time-lock + proving key in session) */}
                <div
                  className={`rounded-xl border p-5 ${
                    snapshot?.finalized
                      ? "border-[var(--color-border)] opacity-95"
                      : votesClosed &&
                          session.provingKeyBase64 &&
                          address &&
                          (finalizePayoutPh || effectiveVoterPk)
                        ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.04]"
                        : "border-[var(--color-border)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                    <span
                      className={`inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full px-2 text-[11px] font-bold ${
                        snapshot?.finalized
                          ? "border border-[var(--color-muted)]/40 text-[var(--color-muted)]"
                          : votesClosed
                            ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                            : "border border-[var(--color-muted)]/40 text-[var(--color-muted)]"
                      }`}
                      aria-hidden
                    >
                      3
                    </span>
                    <span className="font-semibold">
                      Finalize the election tally
                    </span>
                  </div>

                  {snapshot?.finalized ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      This election is finalized on-chain — tally and rewards are settled.
                    </p>
                  ) : chainStatus !== "deployed" ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Wait until deployment completes before finalize is possible.
                    </p>
                  ) : !votesClosed ? (
                    <div className="space-y-2 text-sm text-[var(--color-muted)]">
                      <p>
                        Finalize unlocks once the singleton&apos;s voting-period
                        height lock is satisfied (election length in blocks since
                        the current tip coin was indexed).
                      </p>
                      {electionLc.status === "ready" && !electionLc.finalized && (
                        <p className="text-xs mono">
                          ≈{" "}
                          <span className="font-medium">
                            {Math.max(
                              0,
                              electionLc.finalizeMinHeight - electionLc.peak
                            )}
                          </span>{" "}
                          blocks remaining at peak{" "}
                          <span className="font-medium">{electionLc.peak}</span>{" "}
                          (finalize at height ≥{" "}
                          <span className="font-medium">
                            {electionLc.finalizeMinHeight}
                          </span>
                          ).
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]/80 p-3 text-sm">
                        <div className="font-medium text-[var(--color-foreground)] mb-2">
                          Finalizer reward (on-chain, first successful finalize)
                        </div>
                        <ul className="space-y-1.5 text-[var(--color-muted)] text-xs leading-relaxed">
                          <li>
                            Accrued registration fees on the singleton:&nbsp;
                            <span className="mono font-medium text-[var(--color-foreground)]">
                              {snapshot === null
                                ? "—"
                                : `${formatXch(snapshot.accumulatedFees)} XCH`}
                            </span>
                            {snapshot !== null &&
                              snapshot.accumulatedFees <= 0 && (
                                <span>
                                  {" "}
                                  — this deployment may use a zero registration
                                  fee.
                                </span>
                              )}
                          </li>
                          <li>
                            Pays out to the standard puzzle hash of your{" "}
                            <span className="font-medium">
                              connected Sage receive address
                            </span>
                            {finalizePayoutPh ? (
                              <span className="mono block mt-1 break-all opacity-90">
                                {truncHex(normalizeHex32(finalizePayoutPh), 16, 10)}
                              </span>
                            ) : (
                              <span className="block mt-1 text-amber-800 dark:text-amber-300">
                                Decoding payout address… (reconnect Sage if stuck)
                              </span>
                            )}
                          </li>
                          <li>
                            You need this tab&apos;s imported{" "}
                            <span className="font-medium">share bundle / proving key</span>{" "}
                            plus Groth16 in your browser (~30–90s) before mempool
                            submit.
                          </li>
                        </ul>
                      </div>
                      {!session.provingKeyBase64 ? (
                        <p className="text-sm text-[var(--color-muted)]">
                          Add the organizer&apos;s share bundle via{" "}
                          <span className="font-medium">Ballot → Import</span> so
                          the proving key loads into this session — any participant can use it once the window closes.
                        </p>
                      ) : !finalizePayoutPh && !effectiveVoterPk ? (
                        <p className="text-sm text-amber-800 dark:text-amber-300">
                          Connect Sage Wallet and wait until your receive-address
                          puzzle hash resolves (needed for payout routing).
                        </p>
                      ) : (
                        <button
                          type="button"
                  onClick={handleFinalize}
                  disabled={
                            !!busy ||
                            !!finalizeModal ||
                            !session.provingKeyBase64 ||
                            snapshot?.finalized ||
                            !votesClosed ||
                            (!finalizePayoutPh && !effectiveVoterPk)
                          }
                          className="btn-primary w-full sm:w-auto min-w-[220px]"
                        >
                          Finalize election
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {/* Step 4 — release collateral (registered voters post-finalize) */}
                <div
                  className={`rounded-xl border p-5 ${
                    snapshot?.finalized && myReg
                      ? "border-[var(--color-accent)]/35 bg-[var(--color-accent)]/[0.06]"
                      : "border-[var(--color-border)]"
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                    <span
                      className={`inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full px-2 text-[11px] font-bold ${
                        snapshot?.finalized && myReg
                          ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                          : "border border-[var(--color-muted)]/40 text-[var(--color-muted)]"
                      }`}
                      aria-hidden
                    >
                      4
                    </span>
                    <span className="font-semibold">Claim your CAT collateral</span>
                  </div>
                  {!myReg ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      Only voters who joined this election can reclaim locked CAT
                      after finalize.
                    </p>
                  ) : !snapshot?.finalized ? (
                    <p className="text-sm text-[var(--color-muted)]">
                      After finalize, this step unlocks and returns your collateral
                      (minus consensus rules enforced on-chain).
                    </p>
                  ) : (
                    <>
                      <p className="text-sm text-[var(--color-muted)] mb-4">
                        Finalize landed — reclaim your CAT at{" "}
                        <span className="mono">{collateralAssetShort}</span>.
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
                        Release collateral
                      </button>
                    </>
                  )}
                </div>

                {/* Step 5 — oracle */}
                <div className="rounded-xl border border-[var(--color-border)] p-5">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mb-3">
                    <span
                      className="inline-flex h-7 min-w-7 shrink-0 items-center justify-center rounded-full px-2 text-[11px] font-bold bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                      aria-hidden
                    >
                      5
                    </span>
                    <span className="font-semibold">Oracle announcement</span>
                  </div>
                  <p className="text-sm text-[var(--color-muted)] mb-4">
                    Optionally re-publish or update the{" "}
                    {snapshot?.finalized
                      ? "finalized"
                      : "pending (not yet finalized)"}{" "}
                    outcome announcement for indexers tracking this bulletin.
                  </p>
                  <button
                    type="button"
                  onClick={handleOracle}
                    disabled={!!busy || !!finalizeModal}
                    className="btn-secondary w-full sm:w-auto min-w-[220px]"
                  >
                    Submit oracle announcement
                  </button>
                </div>
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
  registrationMerkleRootHex: string;
  finalized: boolean;
  voteOutcomeHex: string;
  accumulatedFees: number;
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
