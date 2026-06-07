"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import {
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useSearchParams } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import {
  CoinRecord,
  isConsensusRetriablePushError,
  peakHeight,
  pushTx,
} from "../lib/coinset";
import type { SpendBundleJson } from "../lib/coinset";
import {
  readElectionBootstrap,
  type ElectionBootstrap,
} from "../lib/electionBootstrap";
import { recoverAndPersistElectionStartHeight } from "../lib/recoverElectionStartHeight";
import { getBallotMerged } from "../lib/electionBallots";
import {
  readBallotBootstrap,
  writeBallotBootstrap,
  type BallotBootstrap,
} from "../lib/ballotBootstrap";
import { normalizeHex32, truncHex } from "../lib/units";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { createChainBackend } from "../lib/chainBackend";
import { walletConnect } from "../lib/walletConnectInstance";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { pollUntilConfirmed } from "../lib/pollUntil";
import { getWasm } from "../lib/sdk";

function normalize0x(hex: string): string {
  const raw = (hex ?? "").trim().replace(/^0x/i, "").toLowerCase();
  return raw ? `0x${raw}` : "";
}

type BallotStatus =
  | { kind: "open"; blocksRemaining: number }
  | { kind: "closed"; blocksOver: number }
  | { kind: "finalized"; height: number | null };

function ballotStatus(
  b: BallotBootstrap,
  peak: number | null
): BallotStatus | null {
  // Chain-derived `b.finalized` is the canonical "is finalized" bit
  // (set by getBallotMerged from wasm.getBallot's BallotState). Local
  // `b.finalizedAtHeight` carries the actual block height when this
  // browser witnessed the finalize broadcast itself; cross-browser
  // observers fall back to height=null.
  const isFinalized = !!b.finalized || !!b.finalizedAtHeight;
  if (isFinalized) {
    return {
      kind: "finalized",
      height:
        b.finalizedAtHeight && b.finalizedAtHeight > 0
          ? b.finalizedAtHeight
          : null,
    };
  }
  if (peak == null || peak <= 0) return null;
  if (b.voteCloseHeight > peak) {
    return { kind: "open", blocksRemaining: b.voteCloseHeight - peak };
  }
  return { kind: "closed", blocksOver: peak - b.voteCloseHeight };
}

const BallotPageInner = dynamic(
  async function DynamicElem() {
    const wasm = await getWasm();

    return function BallotPage() {
      const sp = useSearchParams();
      const electionId = normalize0x(
        sp?.get("electionId") ?? sp?.get("election") ?? ""
      );
      const ballotId = normalize0x(
        sp?.get("ballotId") ?? sp?.get("ballot") ?? ""
      );
      const electionHomeHref = electionId
        ? `/election?id=${electionId.replace(/^0x/, "")}`
        : "/";

      const { address } = useAppSelector((s) => s.wallet);
      const [election, setElection] = useState<ElectionBootstrap | null>(null);
      const [ballot, setBallot] = useState<BallotBootstrap | null>(null);
      const [peak, setPeak] = useState<number | null>(null);
      const [voterPk, setVoterPk] = useState<string | null>(null);
      const [pubkeyResolutionBusy, setPubkeyResolutionBusy] = useState(false);
      const [busy, setBusy] = useState<string | null>(null);
      const [error, setError] = useState<string | null>(null);
      const [txStatus, setTxStatus] = useState<string | null>(null);
      const [broadcastAwait, setBroadcastAwait] = useState<
        { title: string; detail: string } | null
      >(null);
      /** Full-screen progress modal during cast vote / replace vote. */
      const [castVoteModal, setCastVoteModal] = useState<
        { title: string; detail: string } | null
      >(null);
      /**
       * Stopgap: when Sage returns the BLS identity point as a
       * "signature" (it doesn't recognize our shim coin's custom
       * puzzle hash as wallet-owned), prompt the user to paste a
       * manually-computed `sign_raw(sk, vote_message)` hex. They can
       * compute it via a CLI / chia-blockchain `bls_sign_raw` /
       * a separate signer that has access to their voting secret key.
       * This unblocks voting until chip0002 adds a `signMessageUnsafe`
       * method or the protocol migrates to augmented BLS.
       *
       * The promise resolves with the user-supplied hex, or rejects
       * if they cancel.
       */
      const [manualSigPrompt, setManualSigPrompt] = useState<{
        voteMessageHex: string;
        voterPubkeyHex: string;
        resolve: (sig: string | null) => void;
      } | null>(null);
      const [manualSigInput, setManualSigInput] = useState("");

      function isBlsIdentityG2Sig(sigHex: string): boolean {
        const stripped = sigHex.replace(/^0x/i, "").toLowerCase();
        return stripped === "c0" + "00".repeat(95);
      }

      function requestManualVoteSig(opts: {
        voteMessageHex: string;
        voterPubkeyHex: string;
      }): Promise<string | null> {
        return new Promise((resolve) => {
          setManualSigInput("");
          setManualSigPrompt({
            voteMessageHex: opts.voteMessageHex,
            voterPubkeyHex: opts.voterPubkeyHex,
            resolve,
          });
        });
      }
      const [pickedChoiceIdx, setPickedChoiceIdx] = useState<number | null>(
        null
      );
      const [freeformVote, setFreeformVote] = useState("");
      // Phase 1c: bumped after every successful write (cast / replace /
      // finalize). Wired into the deps of every chain-query useEffect
      // so the UI immediately reflects the new chain state without
      // a manual refresh. Mirrors /election's syncSnapshot() pattern.
      const [chainRefreshKey, setChainRefreshKey] = useState(0);
      const bumpChainRefresh = useCallback(
        () => setChainRefreshKey((n) => n + 1),
        []
      );
      const [optimisticVoteDataHex, setOptimisticVoteDataHex] = useState<
        string | null
      >(null);
      const [indexedVoteDataHex, setIndexedVoteDataHex] = useState<
        string | null
      >(null);
      const [finalizeModal, setFinalizeModal] = useState<
        { title: string; detail: string } | null
      >(null);
      const [finalizePayoutPh, setFinalizePayoutPh] = useState<string | null>(
        null
      );

      // ── Load bootstraps from sessionStorage on mount ─────────────
      useEffect(() => {
        if (!electionId) return;
        setElection(readElectionBootstrap(electionId));
      }, [electionId]);
      useEffect(() => {
        if (!electionId || !ballotId) return;
        // Optimistic load from session cache so the UI renders fast;
        // the chain refresh below overwrites with on-chain truth.
        setBallot(readBallotBootstrap(electionId, ballotId));
      }, [electionId, ballotId]);

      // Chain-derive per-ballot detail (voteCloseHeight, eve coin id,
      // outcomeDomainHash, finalized bit, voteOutcomeHex) via
      // wasm.getBallot once we have an election configJson. Mirrors
      // live_integration.mjs's getBallot point lookup. Bootstrap is
      // kept only for dApp-only metadata (label, choices, voteThreshold,
      // registration snapshots) and as a fallback when chain misses.
      useEffect(() => {
        if (!electionId || !ballotId || !election?.configJson) return;
        let cancelled = false;
        void (async () => {
          const fresh = await getBallotMerged(
            election.configJson,
            electionId,
            ballotId
          );
          if (cancelled) return;
          if (fresh) setBallot(fresh);
        })();
        return () => {
          cancelled = true;
        };
      }, [electionId, ballotId, election?.configJson, chainRefreshKey]);

      // Chain-derive electionStartHeight once per election, BEFORE any
      // wasm chain-walking export (cast_vote / finalize / release /
      // collectVotesForBallot / listRegisteredVoters) is invoked. The
      // bootstrap value is set at deploy time (peak) and can drift if
      // the deployer's submission peak differed from the launcher's
      // confirmed_height. Mirrors live_integration.mjs's
      // recoverElectionStartHeightOrFail. Helper persists the
      // recovered value back to sessionStorage so the existing
      // election.electionStartHeight reads pick it up automatically.
      const eshVerifiedRef = useRef<string>("");
      useEffect(() => {
        if (!election?.configJson || !election?.launcherIdHex) return;
        const launcher = election.launcherIdHex;
        if (eshVerifiedRef.current === launcher) return;
        eshVerifiedRef.current = launcher;
        let cancelled = false;
        void (async () => {
          const recovered = await recoverAndPersistElectionStartHeight(
            launcher,
            election.configJson
          );
          if (cancelled) return;
          if (recovered != null && recovered !== election.electionStartHeight) {
            const fresh = readElectionBootstrap(launcher);
            if (fresh) setElection(fresh);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [election]);

      // ── Chain peak ticker ─────────────────────────────────────────
      useEffect(() => {
        let cancelled = false;
        let timer: ReturnType<typeof setInterval> | null = null;
        const tick = async () => {
          try {
            const p = await peakHeight();
            if (!cancelled && typeof p === "number") setPeak(p);
          } catch {
            /* */
          }
        };
        void tick();
        timer = setInterval(tick, 32_000);
        return () => {
          cancelled = true;
          if (timer) clearInterval(timer);
        };
      }, []);

      // ── Voter pubkey resolution ─────────────────────────────────
      //
      // Resolution priority (fast → slow):
      //   1. `election.registeredPubkeysHex` from the session
      //      bootstrap — set at register time. Instant.
      //   2. On-chain `voter_hint` lookup
      //      (`discoverPriorRegistrations`): scan Sage's keys, hash
      //      `sha256(election || cat_tail || pk)`, query coinset's
      //      hint index. Any registration coin with that hint = that
      //      key is registered.
      // Surfaces progress to the UI so a slow scan doesn't look like
      // a hang. Caps total time at HARD_TIMEOUT_MS — past that we
      // surface a "couldn't resolve" state instead of spinning.
      const [pubkeyResolutionDetail, setPubkeyResolutionDetail] = useState<
        string | null
      >(null);
      useEffect(() => {
        if (!address?.trim() || !election) {
          setVoterPk(null);
          return;
        }
        const cfg = (() => {
          try {
            return JSON.parse(election.configJson);
          } catch {
            return null;
          }
        })();
        if (!cfg?.election_launcher_id_hex || !cfg?.cat_tail_hash_hex) return;

        let cancelled = false;
        setPubkeyResolutionBusy(true);
        setPubkeyResolutionDetail("Checking session bootstrap…");
        const HARD_TIMEOUT_MS = 60_000;
        const timeoutId = setTimeout(() => {
          if (!cancelled) {
            setPubkeyResolutionBusy(false);
            setPubkeyResolutionDetail(
              "Timed out scanning Sage keys. Reconnect the wallet, " +
                "or refresh after the registration's voter_hint indexes."
            );
            setVoterPk(null);
          }
        }, HARD_TIMEOUT_MS);
        void (async () => {
          try {
            // ── 1. Fast path: bootstrap-tracked pubkeys ─────────
            const tracked = (election.registeredPubkeysHex ?? []).map((p) =>
              p.startsWith("0x") ? p : "0x" + p
            );
            if (tracked.length > 0) {
              setVoterPk(tracked[0]);
              return;
            }

            // ── 2. Chain hint lookup ────────────────────────────
            setPubkeyResolutionDetail(
              "Scanning Sage keys for an existing registration on chain…"
            );
            const { discoverPriorRegistrations } = await import(
              "../lib/priorRegistrationDiscovery"
            );
            const hits = await discoverPriorRegistrations({
              electionLauncherIdHex:
                "0x" + String(cfg.election_launcher_id_hex).replace(/^0x/, ""),
              catTailHashHex:
                "0x" + String(cfg.cat_tail_hash_hex).replace(/^0x/, ""),
              preferredSyntheticPkHex: undefined,
              stopOnFirst: true,
              onProgress: (p) => {
                if (cancelled) return;
                if (p.phase === "receive_key") {
                  setPubkeyResolutionDetail(
                    "Checking your receive-address synthetic key…"
                  );
                } else {
                  setPubkeyResolutionDetail(
                    `Scanning Sage synthetic keys for prior registration ` +
                      `(${p.keysChecked.toLocaleString()} checked)…`
                  );
                }
              },
            });
            if (cancelled) return;
            if (hits.length > 0) {
              setVoterPk(hits[0].syntheticPkHex);
            } else {
              setVoterPk(null);
              setPubkeyResolutionDetail(
                "No registered key found for this Sage wallet on this election."
              );
            }
          } catch (e) {
            if (!cancelled) {
              setVoterPk(null);
              setPubkeyResolutionDetail(
                "Resolution failed: " +
                  (e instanceof Error ? e.message : String(e))
              );
            }
          } finally {
            clearTimeout(timeoutId);
            if (!cancelled) setPubkeyResolutionBusy(false);
          }
        })();
        return () => {
          cancelled = true;
          clearTimeout(timeoutId);
        };
      }, [address, election]);

      // ── Resolve finalize payout puzzle hash ─────────────────────
      useEffect(() => {
        if (!address?.trim()) {
          setFinalizePayoutPh(null);
          return;
        }
        let cancelled = false;
        void (async () => {
          const ph = await puzzleHashHexFromWalletAddress(address.trim());
          if (!cancelled && ph) setFinalizePayoutPh(ph);
        })();
        return () => {
          cancelled = true;
        };
      }, [address]);

      // ── Chain-discovered registered voters ─────────────────────
      // Browsers that didn't witness the register actions directly
      // (share-bundle imports, second-device finalize) have an empty
      // session-storage pubkey list. Walk the Election Singleton's
      // lineage via wasm.listRegisteredVoters to get every voter's
      // pubkey + locked amount from chain. Drives finalize +
      // change-vote + tally lookups.
      const [allRegisteredVoters, setAllRegisteredVoters] = useState<
        string[] | null
      >(null);
      // Parallel pubkey → lockedAmount index. Powers weighted tally
      // bars + live signed-weight gauge (Phase D). Derived from the
      // same listRegisteredVoters chain walk that drives the pubkey
      // list, so a single chain RTT covers both.
      const [voterWeights, setVoterWeights] = useState<Map<
        string,
        number
      > | null>(null);
      useEffect(() => {
        if (!election) return;
        const cfg = (() => {
          try {
            return JSON.parse(election.configJson);
          } catch {
            return null;
          }
        })();
        const electionStartHeight = Number(
          election.electionStartHeight ?? cfg?.election_start_height ?? 0
        );
        if (!electionStartHeight) return;
        let cancelled = false;
        void (async () => {
          try {
            const backend = createChainBackend();
            const json = await wasm.listRegisteredVoters(
              backend as any,
              election.configJson,
              wasm.WasmNetwork.Mainnet,
              BigInt(electionStartHeight)
            );
            if (cancelled) return;
            const list = JSON.parse(json) as Array<{
              pubkeyHex: string;
              lockedAmount: number;
            }>;
            setAllRegisteredVoters(list.map((v) => v.pubkeyHex));
            const weights = new Map<string, number>();
            for (const v of list) {
              weights.set(normalizeHex32(v.pubkeyHex), Number(v.lockedAmount));
            }
            setVoterWeights(weights);
          } catch (e) {
            console.warn("[ballot] listRegisteredVoters failed:", e);
            // Fall back to bootstrap-tracked pks if the chain walk
            // fails (rare — keeps the page functional in degraded
            // network conditions). voterWeights stays null so the UI
            // falls back to count-tally semantics.
            if (!cancelled) {
              setAllRegisteredVoters(election.registeredPubkeysHex ?? []);
            }
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [election, chainRefreshKey]);

      // ── Fetch this voter's existing vote on this ballot ──────────
      useEffect(() => {
        if (!election || !ballot || !voterPk) return;
        let cancelled = false;
        void (async () => {
          try {
            const backend = createChainBackend();
            const rowsJson = (await wasm.collectVotesForBallot(
              backend as any,
              election.configJson,
              ballot.ballotLauncherIdHex,
              JSON.stringify([voterPk])
            )) as string;
            const rows = JSON.parse(rowsJson) as Array<
              Record<string, string | undefined>
            >;
            if (cancelled) return;
            const pkNorm = normalizeHex32(voterPk);
            for (const row of rows ?? []) {
              const rk = normalizeHex32(
                row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
              );
              if (rk === pkNorm) {
                const rv = normalizeHex32(
                  row.vote_data_hex ?? row.voteDataHex ?? ""
                );
                setIndexedVoteDataHex("0x" + rv);
                break;
              }
            }
          } catch {
            /* tolerate fetch errors — UI just won't show prior vote */
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [election, ballot, voterPk, chainRefreshKey]);

      const myVoteDataHex = indexedVoteDataHex ?? optimisticVoteDataHex;

      // ── Per-choice tally for post-finalize bars ──────────────────
      // Fetched once when the ballot reaches the finalized state.
      // Uses collectVotesForBallot (the same wire format finalize
      // ran the tally over) and buckets by vote_data_hex.
      const [perChoiceTally, setPerChoiceTally] = useState<Map<string, number>>(
        new Map()
      );
      // ── Live signed weight for pre-finalize gauge (Phase D-2) ─
      // Polls collectVotesForBallot every 30s, sums voter weights
      // of voters who have cast on this ballot. Displayed against
      // the threshold (registrationVoteWeightSnapshot * num/den)
      // so users can see how close the ballot is to being
      // finalize-able. Mirrors aggregator threshold logic on chain.
      const [signedWeight, setSignedWeight] = useState<number | null>(null);
      useEffect(() => {
        if (!election || !ballot) return;
        if (ballot.finalized || ballot.finalizedAtHeight) return;
        const voterPubkeys =
          allRegisteredVoters && allRegisteredVoters.length > 0
            ? allRegisteredVoters
            : election.registeredPubkeysHex ?? [];
        if (voterPubkeys.length === 0) return;
        let cancelled = false;
        const tick = async () => {
          try {
            const backend = createChainBackend();
            const rowsJson = (await wasm.collectVotesForBallot(
              backend as any,
              election.configJson,
              ballot.ballotLauncherIdHex,
              JSON.stringify(voterPubkeys)
            )) as string;
            if (cancelled) return;
            const rows = JSON.parse(rowsJson) as Array<
              Record<string, string | undefined>
            >;
            let signed = 0;
            const seen = new Set<string>();
            for (const r of rows ?? []) {
              const k = String(r.vote_data_hex ?? r.voteDataHex ?? "")
                .toLowerCase()
                .replace(/^0x/, "");
              if (!k || k === "00".repeat(32)) continue;
              const pkRaw = String(
                r.voter_pubkey_hex ?? r.voterPubkeyHex ?? ""
              );
              if (!pkRaw) continue;
              const pk = normalizeHex32(pkRaw);
              if (seen.has(pk)) continue;
              seen.add(pk);
              signed += voterWeights?.get(pk) ?? 1;
            }
            if (!cancelled) setSignedWeight(signed);
          } catch {
            /* tolerate transient network errors; gauge keeps last value */
          }
        };
        void tick();
        const id = setInterval(tick, 30_000);
        return () => {
          cancelled = true;
          clearInterval(id);
        };
      }, [election, ballot, allRegisteredVoters, voterWeights]);
      useEffect(() => {
        if (!election || !ballot) return;
        if (!ballot.finalized && !ballot.finalizedAtHeight) return;
        let cancelled = false;
        void (async () => {
          try {
            // Prefer chain-discovered voter list (covers voters this
          // browser didn't witness register). Fall back to bootstrap
          // tracking only if chain walk hasn't completed yet.
          const voterPubkeys =
            allRegisteredVoters && allRegisteredVoters.length > 0
              ? allRegisteredVoters
              : election.registeredPubkeysHex ?? [];
            if (voterPubkeys.length === 0) return;
            const backend = createChainBackend();
            const rowsJson = (await wasm.collectVotesForBallot(
              backend as any,
              election.configJson,
              ballot.ballotLauncherIdHex,
              JSON.stringify(voterPubkeys)
            )) as string;
            if (cancelled) return;
            const rows = JSON.parse(rowsJson) as Array<
              Record<string, string | undefined>
            >;
            // Weighted tally (Phase D-1): bucket by vote_data_hex,
            // accumulate the voter's locked-CAT weight from
            // voterWeights. Falls back to count-tally (+1 per vote)
            // when voterWeights hasn't loaded — keeps the bars
            // useful in degraded mode.
            const buckets = new Map<string, number>();
            for (const r of rows ?? []) {
              const raw = r.vote_data_hex ?? r.voteDataHex;
              const k = String(raw ?? "")
                .toLowerCase()
                .replace(/^0x/, "");
              if (!k || k === "00".repeat(32)) continue;
              const voterPkRaw = String(
                r.voter_pubkey_hex ?? r.voterPubkeyHex ?? ""
              );
              const voterPk = voterPkRaw ? normalizeHex32(voterPkRaw) : "";
              const w = voterPk
                ? voterWeights?.get(voterPk) ?? 1
                : 1;
              buckets.set(k, (buckets.get(k) ?? 0) + w);
            }
            setPerChoiceTally(buckets);
          } catch {
            /* tolerate; UI just shows winner only */
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [election, ballot, allRegisteredVoters, voterWeights]);
      const status = useMemo(
        () => (ballot ? ballotStatus(ballot, peak) : null),
        [ballot, peak]
      );
      const isOpen = status?.kind === "open";
      const isClosed = status?.kind === "closed";
      const isFinalized =
        status?.kind === "finalized" ||
        !!ballot?.finalized ||
        !!ballot?.finalizedAtHeight;

      // Voter's chain-state on this election. Derived from the
      // listRegisteredVoters chain walk (allRegisteredVoters) and the
      // collectVotesForBallot lookup (myVoteDataHex). Drives the
      // action-button gating so the UI never offers cast/replace/
      // release on a state where the SDK would reject (e.g., voter has
      // already released → no unspent registration coin to spend).
      //
      //   "registered"   — voterPk is in the on-chain registered set;
      //                    cast/replace/release are valid actions.
      //   "released"     — voterPk was registered + voted (we have a
      //                    vote record) but is no longer in the
      //                    registered set → release ran. No further
      //                    actions on this ballot.
      //   "unregistered" — voterPk is not in the registered set and we
      //                    have no vote record. Either never registered
      //                    on this election, or released without ever
      //                    voting. Voter must register on /election.
      //   "unknown"      — voterPk hasn't resolved yet, or the chain
      //                    walk hasn't completed. UI falls back to the
      //                    existing "loading" affordances.
      const voterRegistrationStatus: "registered" | "released" | "unregistered" | "unknown" =
        useMemo(() => {
          if (!voterPk || !allRegisteredVoters) return "unknown";
          const pkNorm = normalizeHex32(voterPk);
          const inRegistered = allRegisteredVoters.some(
            (p) => normalizeHex32(p) === pkNorm
          );
          if (inRegistered) return "registered";
          if (myVoteDataHex) return "released";
          return "unregistered";
        }, [voterPk, allRegisteredVoters, myVoteDataHex]);
      const isReleased = voterRegistrationStatus === "released";
      const isUnregistered = voterRegistrationStatus === "unregistered";

      // ── waitBroadcastConfirm helper (mirrors /election) ──────────
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
          if (!ok) {
            setError(
              `${opts.title}: bundle was submitted but chain confirmation timed out after 5 min. ` +
                `Inspect coinset / your wallet's activity.`
            );
          }
          return ok;
        },
        []
      );

      // ── handleVote ───────────────────────────────────────────────
      const handleVote = async () => {
        if (!election || !ballot || !voterPk) return;
        setError(null);
        setTxStatus(null);
        const setCastStatus = (detail: string) => {
          setBusy(detail);
          setCastVoteModal({ title: "Cast vote", detail });
        };
        setCastStatus("Voting…");
        try {
          const peakNow = await peakHeight();
          if (!peakNow) throw new Error("Could not read chain peak");
          if (ballot.voteCloseHeight <= peakNow) {
            throw new Error(
              "This ballot is closed (vote_close_height passed). " +
                "You can no longer cast votes against it."
            );
          }

          const choices =
            ballot.choices && ballot.choices.length > 0
              ? ballot.choices
              : election.choices;
          // M13: in Mode2Restricted (vote_options_root != 0x00…00) the
          // voter MUST pick from the curated list — no freeform vote.
          // The Ballot Coin's oracle is curried with the merkle root,
          // so any 32-byte vote_data not in the locked set will fail
          // the (M5-revised) merkle membership check.
          const voteOptionsRootHex = ballot.voteOptionsRootHex
            ?.replace(/^0x/, "")
            .toLowerCase();
          const MODE_FREE = "00".repeat(32);
          const isRestricted =
            !!voteOptionsRootHex && voteOptionsRootHex !== MODE_FREE;
          if (isRestricted && (!choices || choices.length === 0)) {
            throw new Error(
              "This ballot is Mode2Restricted but no option labels are " +
                "available locally. Ask the ballot operator for the " +
                "labels list (it should match merkle root 0x" +
                (voteOptionsRootHex ?? "??").slice(0, 18) +
                "…) and re-import via the share-bundle flow."
            );
          }
          let voteHex: string;
          if (choices && choices.length > 0) {
            if (pickedChoiceIdx === null) {
              throw new Error("Pick a choice before voting.");
            }
            voteHex = choices[pickedChoiceIdx].voteDataHex;
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

          // M5r-merkle-f: when the ballot is Mode2Restricted, build the
          // merkle inclusion proof for `voteHex` against the locked
          // sorted-options tree. The on-chain mint_voting_coin's
          // M5r-merkle-e gate verifies sha256(vote_data) reduces up to
          // vote_options_root via this proof. Mode1Free skips below.
          const castRestrictedRootHexRaw = ballot.voteOptionsRootHex
            ?.replace(/^0x/, "")
            .toLowerCase();
          const castIsModeRestricted =
            !!castRestrictedRootHexRaw &&
            castRestrictedRootHexRaw !== "00".repeat(32);
          let castModeRestrictedFields: {
            voteOptionsRootHex: string;
            voteOptionLeafIndex: number;
            voteOptionProofHex: string[];
          } | undefined;
          if (castIsModeRestricted) {
            if (!choices || choices.length === 0) {
              throw new Error(
                "Mode2Restricted ballot but no option list locally — " +
                  "import the operator's share-bundle to recover labels."
              );
            }
            const optionsConcat = choices
              .map((c) => c.voteDataHex.replace(/^0x/, ""))
              .join("");
            const target = voteHex.startsWith("0x") ? voteHex : "0x" + voteHex;
            const proofRaw = (await wasm.merkleProofForOption(
              optionsConcat,
              target
            )) as unknown;
            if (proofRaw == null) {
              throw new Error(
                "Picked option not found in the local options list — proof unbuildable."
              );
            }
            const proofObj = (proofRaw instanceof Map
              ? Object.fromEntries(proofRaw)
              : proofRaw) as { leafIndex: number; proofHex: string[] };
            castModeRestrictedFields = {
              voteOptionsRootHex: ballot.voteOptionsRootHex!,
              voteOptionLeafIndex: Number(proofObj.leafIndex),
              voteOptionProofHex: proofObj.proofHex,
            };
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
            ...(castModeRestrictedFields ?? {}),
          };
          const cfg = JSON.parse(election.configJson);
          const electionStartHeight = Number(
            election.electionStartHeight ?? cfg.election_start_height ?? 0
          );

          console.time("[chip:cast] waitForInit");
          await walletConnect.waitForInit();
          console.timeEnd("[chip:cast] waitForInit");
          const backend = createChainBackend();

          setCastStatus("Building preview vote spend…");
          console.time("[chip:cast] castVoteBuildPreviewSpend (wasm)");
          const previewJson = await wasm.castVoteBuildPreviewSpend(
            backend as any,
            election.configJson,
            voterPk,
            JSON.stringify(params)
          );
          console.timeEnd("[chip:cast] castVoteBuildPreviewSpend (wasm)");
          const preview = JSON.parse(previewJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            voteMessageHex: string;
          };

          setCastStatus("Awaiting Sage signature on vote message…");
          console.time("[chip:cast] signCoinSpends preview (Sage)");
          let voteSigHex = await walletConnect.signCoinSpends(
            preview.coinSpends,
            true,
            false
          );
          console.timeEnd("[chip:cast] signCoinSpends preview (Sage)");
          if (!voteSigHex) {
            throw new Error("Wallet rejected the vote-message signature request");
          }
          // Sage returns the BLS G2 identity (`0xc0` + 95 zeros) when
          // it doesn't recognize our shim coin's custom puzzle hash
          // as wallet-owned. Stopgap: prompt the user to paste a
          // manually-computed `sign_raw(sk, vote_message)` hex.
          if (isBlsIdentityG2Sig(voteSigHex)) {
            setCastStatus(
              "Sage returned identity sig. Provide a manual sign_raw signature…"
            );
            const manual = await requestManualVoteSig({
              voteMessageHex: preview.voteMessageHex,
              voterPubkeyHex: voterPk,
            });
            if (!manual) {
              throw new Error("User cancelled manual signature input.");
            }
            voteSigHex = manual.startsWith("0x") ? manual : `0x${manual}`;
          }

          setCastStatus("Building cast_vote bundle…");
          console.time("[chip:cast] castVoteBuildUnsignedCoinSpends (wasm + chain walk)");
          const unsignedJson = await wasm.castVoteBuildUnsignedCoinSpends(
            backend as any,
            election.configJson,
            voterPk,
            JSON.stringify(params),
            voteSigHex,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          console.timeEnd("[chip:cast] castVoteBuildUnsignedCoinSpends (wasm + chain walk)");
          const unsigned = JSON.parse(unsignedJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            votingCoinIdHex: string;
            voteSignatureHex: string;
            voteMessageHex: string;
          };

          setCastStatus("Awaiting Sage signature on bundle…");
          console.time("[chip:cast] signCoinSpends bundle (Sage)");
          const aggSigHex = await walletConnect.signCoinSpends(
            unsigned.coinSpends,
            true,
            false
          );
          console.timeEnd("[chip:cast] signCoinSpends bundle (Sage)");
          if (!aggSigHex) {
            throw new Error("Wallet rejected the bundle signature request");
          }

          setCastStatus("Assembling and verifying bundle…");
          console.time("[chip:cast] assemble + verifyBundleLocally (wasm)");
          const bundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(unsigned.coinSpends),
            aggSigHex
          );
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
          console.timeEnd("[chip:cast] assemble + verifyBundleLocally (wasm)");

          setCastStatus("Submitting bundle to mempool (coinset)…");
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          const vdCanon = voteHex.trim().startsWith("0x")
            ? voteHex.trim().toLowerCase()
            : `0x${normalizeHex32(voteHex)}`;
          setOptimisticVoteDataHex(vdCanon);

          const pkNorm = normalizeHex32(voterPk);
          const vdNorm = normalizeHex32(voteHex);
          const ballotLauncherFrozen = ballot.ballotLauncherIdHex;
          const voteOk = await waitBroadcastConfirm({
            title: "Confirming vote",
            intro:
              "Waiting until coinset-backed reads detect your ballot (same source as tally).",
            predicate: async () => {
              const b = createChainBackend();
              const rowsJson = (await wasm.collectVotesForBallot(
                b as any,
                election.configJson,
                ballotLauncherFrozen,
                JSON.stringify([voterPk])
              )) as string;
              const rows = JSON.parse(rowsJson) as Array<
                Record<string, string | undefined>
              >;
              // Diagnostic: surface every row the walker sees so the
              // user (or developer console) can compare against the
              // expected (pk, vote_data) pair if polling stalls.
              console.log(
                "[castVote] poll: walker returned",
                rows.length,
                "row(s) for ballot",
                ballotLauncherFrozen.slice(0, 14),
                "and voterPk",
                voterPk.slice(0, 14)
              );
              for (const row of rows ?? []) {
                const rk = normalizeHex32(
                  row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
                );
                const rv = normalizeHex32(
                  row.vote_data_hex ?? row.voteDataHex ?? ""
                );
                console.log(
                  "[castVote] row pk=",
                  rk.slice(0, 14),
                  "vd=",
                  rv.slice(0, 14),
                  "want pk=",
                  pkNorm.slice(0, 14),
                  "want vd=",
                  vdNorm.slice(0, 14),
                  "match?",
                  rk === pkNorm && rv === vdNorm
                );
                if (rk === pkNorm && rv === vdNorm) return true;
              }
              return false;
            },
          });
          if (voteOk) {
            setIndexedVoteDataHex(vdCanon);
            setTxStatus("Vote confirmed on-chain.");
            bumpChainRefresh();
          } else {
            // Bundle pushed but no matching row in 5 min. Surface the
            // optimistic state and let the user verify manually via
            // coinset / their wallet's activity feed.
            setTxStatus(
              `Vote bundle was submitted but coinset's hint index hasn't ` +
                `surfaced the matching voting coin within 5 min. Your spend ` +
                `may still be propagating — check coinset for ` +
                `voter_pubkey ${voterPk.slice(0, 14)}… on this ballot. ` +
                `Open browser DevTools → Console for per-poll details.`
            );
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          setError(msg);
        } finally {
          setBusy(null);
          setCastVoteModal(null);
        }
      };

      // ── handleChangeVote (replace existing vote on this ballot) ──
      const handleChangeVote = async () => {
        if (!election || !ballot || !voterPk) return;
        if (!myVoteDataHex) {
          setError("No existing vote to replace — use Cast vote instead.");
          return;
        }
        setError(null);
        setTxStatus(null);
        const setReplaceStatus = (detail: string) => {
          setBusy(detail);
          setCastVoteModal({ title: "Replace vote", detail });
        };
        setReplaceStatus("Replacing ballot…");
        try {
          const peakNow = await peakHeight();
          if (!peakNow) throw new Error("Could not read chain peak");
          if (ballot.voteCloseHeight <= peakNow) {
            throw new Error(
              "This ballot is closed (vote_close_height passed); votes can no longer be changed."
            );
          }

          const choices =
            ballot.choices && ballot.choices.length > 0
              ? ballot.choices
              : election.choices;
          let voteHex: string;
          if (choices && choices.length > 0) {
            if (pickedChoiceIdx === null) {
              throw new Error("Pick a new choice before replacing your vote.");
            }
            voteHex = choices[pickedChoiceIdx].voteDataHex;
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
          if (
            normalizeHex32(voteHex) === normalizeHex32(myVoteDataHex)
          ) {
            throw new Error(
              "New vote must differ from your current on-chain vote."
            );
          }

          await walletConnect.waitForInit();
          const backend = createChainBackend();

          // Find current Voting Coin via collectVotesForBallot — its row
          // gives us voting_coin_id + registration_coin_id, both required
          // by UpdateVoteParams.
          const rowsJson = (await wasm.collectVotesForBallot(
            backend as any,
            election.configJson,
            ballot.ballotLauncherIdHex,
            JSON.stringify([voterPk])
          )) as string;
          const rows = JSON.parse(rowsJson) as Array<
            Record<string, string | undefined>
          >;
          const pkNorm = normalizeHex32(voterPk);
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
            myRow.vote_data_hex ?? myRow.voteDataHex ?? myVoteDataHex;
          if (!votingCoinIdHex || !registrationCoinIdHex) {
            throw new Error(
              "collectVotesForBallot row missing voting / registration coin ids."
            );
          }

          // M5r-merkle-d: when the ballot is Mode2Restricted, build the
          // merkle inclusion proof for `voteHex` against the locked
          // sorted-options tree. The on-chain update_vote action's
          // M5r-merkle gate verifies sha256(new_vote_data) reduces up
          // to vote_options_root via this proof; without it the spend
          // raises. Mode1Free ballots leave the proof fields absent so
          // the wasm wrapper threads None and the puzzle short-circuits.
          const restrictedRootHexRaw = ballot.voteOptionsRootHex
            ?.replace(/^0x/, "")
            .toLowerCase();
          const isModeRestrictedNow =
            !!restrictedRootHexRaw && restrictedRootHexRaw !== "00".repeat(32);
          let modeRestrictedFields: {
            voteOptionsRootHex: string;
            voteOptionLeafIndex: number;
            voteOptionProofHex: string[];
          } | undefined;
          if (isModeRestrictedNow) {
            if (!choices || choices.length === 0) {
              throw new Error(
                "Mode2Restricted ballot but no option list locally — " +
                  "import the operator's share-bundle to recover labels."
              );
            }
            const optionsConcat = choices
              .map((c) => c.voteDataHex.replace(/^0x/, ""))
              .join("");
            const target = voteHex.startsWith("0x") ? voteHex : "0x" + voteHex;
            const proofRaw = (await wasm.merkleProofForOption(
              optionsConcat,
              target
            )) as unknown;
            if (proofRaw == null) {
              throw new Error(
                "Picked option not found in the local options list — proof unbuildable."
              );
            }
            const proofObj = (proofRaw instanceof Map
              ? Object.fromEntries(proofRaw)
              : proofRaw) as { leafIndex: number; proofHex: string[] };
            modeRestrictedFields = {
              voteOptionsRootHex: ballot.voteOptionsRootHex!,
              voteOptionLeafIndex: Number(proofObj.leafIndex),
              voteOptionProofHex: proofObj.proofHex,
            };
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
            ...(modeRestrictedFields ?? {}),
          };
          const cfg = JSON.parse(election.configJson);
          const electionStartHeight = Number(
            election.electionStartHeight ?? cfg.election_start_height ?? 0
          );

          setReplaceStatus("Building change-vote preview spend…");
          console.time("[chip:replace] updateVoteBuildPreviewSpend (wasm)");
          const previewJson = await wasm.updateVoteBuildPreviewSpend(
            backend as any,
            election.configJson,
            voterPk,
            JSON.stringify(params)
          );
          console.timeEnd("[chip:replace] updateVoteBuildPreviewSpend (wasm)");
          const preview = JSON.parse(previewJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
            voteMessageHex: string;
          };

          setReplaceStatus("Awaiting Sage signature on new vote message…");
          console.time("[chip:replace] signCoinSpends preview (Sage)");
          let newVoteSigHex = await walletConnect.signCoinSpends(
            preview.coinSpends,
            true,
            false
          );
          console.timeEnd("[chip:replace] signCoinSpends preview (Sage)");
          if (!newVoteSigHex) {
            throw new Error(
              "Wallet rejected the new-vote-message signature request"
            );
          }
          if (isBlsIdentityG2Sig(newVoteSigHex)) {
            setReplaceStatus(
              "Sage returned identity sig. Provide a manual sign_raw signature…"
            );
            const manual = await requestManualVoteSig({
              voteMessageHex: preview.voteMessageHex,
              voterPubkeyHex: voterPk,
            });
            if (!manual) {
              throw new Error("User cancelled manual signature input.");
            }
            newVoteSigHex = manual.startsWith("0x") ? manual : `0x${manual}`;
          }

          setReplaceStatus("Building update_vote bundle…");
          console.time("[chip:replace] updateVoteBuildUnsignedCoinSpends (wasm + chain walk)");
          const unsignedJson = await wasm.updateVoteBuildUnsignedCoinSpends(
            backend as any,
            election.configJson,
            voterPk,
            JSON.stringify(params),
            newVoteSigHex,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          console.timeEnd("[chip:replace] updateVoteBuildUnsignedCoinSpends (wasm + chain walk)");
          const unsigned = JSON.parse(unsignedJson) as {
            coinSpends: SpendBundleJson["coin_spends"];
          };

          setReplaceStatus("Awaiting Sage signature on bundle…");
          console.time("[chip:replace] signCoinSpends bundle (Sage)");
          const aggSigHex = await walletConnect.signCoinSpends(
            unsigned.coinSpends,
            true,
            false
          );
          console.timeEnd("[chip:replace] signCoinSpends bundle (Sage)");
          if (!aggSigHex) {
            throw new Error("Wallet rejected the bundle signature request");
          }

          setReplaceStatus("Assembling and verifying bundle…");
          console.time("[chip:replace] assemble + verifyBundleLocally (wasm)");
          const bundleBytes = wasm.assembleSpendBundleFromWalletCoinSpends(
            JSON.stringify(unsigned.coinSpends),
            aggSigHex
          );
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
          console.timeEnd("[chip:replace] assemble + verifyBundleLocally (wasm)");

          setReplaceStatus("Submitting change-vote bundle…");
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          const vdCanon = voteHex.trim().startsWith("0x")
            ? voteHex.trim().toLowerCase()
            : `0x${normalizeHex32(voteHex)}`;
          setOptimisticVoteDataHex(vdCanon);

          const vdNorm = normalizeHex32(voteHex);
          const ballotLauncherFrozen = ballot.ballotLauncherIdHex;
          const ok = await waitBroadcastConfirm({
            title: "Confirming replaced ballot",
            intro:
              "Waiting until coinset-backed reads show your updated vote_data.",
            predicate: async () => {
              const b = createChainBackend();
              const rowsJson2 = (await wasm.collectVotesForBallot(
                b as any,
                election.configJson,
                ballotLauncherFrozen,
                JSON.stringify([voterPk])
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
            setIndexedVoteDataHex(vdCanon);
            setTxStatus("Ballot replaced on-chain.");
            bumpChainRefresh();
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          setError(msg);
        } finally {
          setBusy(null);
          setCastVoteModal(null);
        }
      };

      // ── handleFinalize (permissionless once proving key in session) ──
      const handleFinalize = async () => {
        if (!election || !ballot) return;
        if (!election.provingKeyBase64) {
          setError(
            "Finalize is permissionless but needs the Groth16 proving key. " +
              "Import the election share bundle so this browser holds the key."
          );
          return;
        }
        if (!address) {
          setError("Connect Sage Wallet to receive the finalize payout.");
          return;
        }
        if (!isClosed) {
          setError(
            "Finalize is gated by AssertHeightAbsolute(VOTE_CLOSE_HEIGHT) on " +
              "the eve Ballot Coin. The ballot is not yet closed."
          );
          return;
        }
        setError(null);
        setTxStatus(null);
        setBusy("Finalizing ballot…");
        setFinalizeModal({
          title: "Finalize ballot",
          detail: "Initializing wallet + collecting votes from chain…",
        });
        try {
          await walletConnect.waitForInit();

          let dest =
            finalizePayoutPh ??
            (await puzzleHashHexFromWalletAddress(address.trim()));
          if (!dest && voterPk) {
            dest = wasm.standardPuzzleHash(voterPk);
          }
          if (!dest) {
            throw new Error(
              "Could not derive an XCH puzzle hash for the finalizer reward. " +
                "Reconnect the wallet."
            );
          }

          const ballotChoices =
            ballot.choices && ballot.choices.length > 0
              ? ballot.choices
              : election.choices;
          if (!ballotChoices || ballotChoices.length === 0) {
            throw new Error(
              "This ballot has no UI choices defined; cannot auto-tally."
            );
          }

          const backend = createChainBackend();
          // Prefer chain-discovered voter list (covers voters this
          // browser didn't witness register). Fall back to bootstrap
          // tracking only if chain walk hasn't completed yet.
          const voterPubkeys =
            allRegisteredVoters && allRegisteredVoters.length > 0
              ? allRegisteredVoters
              : election.registeredPubkeysHex ?? [];

          setFinalizeModal({
            title: "Finalize ballot",
            detail: `Walking Voting Coin lineage for ballot ${ballot.ballotLauncherIdHex.slice(
              0,
              10
            )}… (${voterPubkeys.length} known voter pubkey(s)).`,
          });
          console.time("[chip:finalize] collectVotesForBallot (wasm + chain walk)");
          const wireVotesJson = (await wasm.collectVotesForBallot(
            backend as any,
            election.configJson,
            ballot.ballotLauncherIdHex,
            JSON.stringify(voterPubkeys)
          )) as string;
          console.timeEnd("[chip:finalize] collectVotesForBallot (wasm + chain walk)");
          const wireVotes = JSON.parse(wireVotesJson) as Array<
            Record<string, string | undefined>
          >;

          setFinalizeModal({
            title: "Finalize ballot",
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
          let winner = ballotChoices[0];
          let winnerCount = -1;
          for (const c of ballotChoices) {
            const k = normHex(c.voteDataHex);
            const n = tally.get(k) ?? 0;
            if (n > winnerCount) {
              winner = c;
              winnerCount = n;
            }
          }
          if (winnerCount < 1) {
            throw new Error(
              "No valid cast ballots recovered from chain hints — " +
                "finalize would fail BelowThreshold."
            );
          }
          const outcomeHex = winner.voteDataHex;

          const winnerKey = normHex(outcomeHex);
          const winnerVotes = wireVotes.filter((v) => {
            const k = normHex(v.vote_data_hex ?? v.voteDataHex);
            return k === winnerKey;
          });

          const cfg = JSON.parse(election.configJson);
          const electionStartHeight = Number(
            election.electionStartHeight ?? cfg.election_start_height ?? 0
          );
          const finalizeParams = {
            voteCloseHeight: ballot.voteCloseHeight,
            voteThresholdNum: ballot.voteThresholdNum,
            voteThresholdDen: ballot.voteThresholdDen,
            registrationMerkleRootSnapshotHex:
              ballot.registrationMerkleRootSnapshotHex,
            registrationVoteWeightSnapshot:
              ballot.registrationVoteWeightSnapshot,
          };

          setFinalizeModal({
            title: "Finalize ballot",
            detail:
              `Building Groth16 proof + assembling bundle. ` +
              `Outcome: "${winner.label}" (${winnerCount} ballot(s)). ` +
              `Proving step typically runs tens of seconds.`,
          });
          const pkBytes = base64ToBytes(election.provingKeyBase64);
          console.time("[chip:finalize] buildBallotFinalizeBundle (wasm Groth16 prove + chain walk)");
          const bundleHex = await wasm.buildBallotFinalizeBundle(
            backend as any,
            election.configJson,
            ballot.ballotLauncherIdHex,
            outcomeHex,
            JSON.stringify(finalizeParams),
            JSON.stringify(winnerVotes),
            pkBytes,
            wasm.WasmNetwork.Mainnet,
            BigInt(electionStartHeight)
          );
          console.timeEnd("[chip:finalize] buildBallotFinalizeBundle (wasm Groth16 prove + chain walk)");
          const bundleBytes = hexToBytes(bundleHex);

          setFinalizeModal({
            title: "Finalize ballot",
            detail: "Verifying CLVM spends + BLS / proof shape locally…",
          });
          console.time("[chip:finalize] verifyBundleLocally (wasm)");
          wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
          console.timeEnd("[chip:finalize] verifyBundleLocally (wasm)");

          setFinalizeModal({
            title: "Finalize ballot",
            detail: "Submitting bundle to mempool (coinset)…",
          });
          const bundleJson = JSON.parse(
            wasm.bundleBytesToWalletJson(bundleBytes)
          ) as SpendBundleJson;
          await pushTx(bundleJson);

          setFinalizeModal(null);
          const finOk = await waitBroadcastConfirm({
            title: "Confirming finalize",
            intro:
              "Waiting until the ballot's finalize state lands on chain.",
            predicate: async () => {
              return true; // optimistic; refine with chain query in polish
            },
          });
          if (finOk) {
            // Persist finalize state to bootstrap so future page loads
            // see the ballot as finalized.
            const updated: BallotBootstrap = {
              ...ballot,
              finalizedAtHeight: peak ?? 0,
              voteOutcomeHex: outcomeHex,
            };
            writeBallotBootstrap(updated);
            setBallot(updated);
            setTxStatus(
              `Finalize confirmed. Outcome: "${winner.label}" with ` +
                `${winnerCount} ballot(s) for the winner.`
            );
            bumpChainRefresh();
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          setError(msg);
        } finally {
          setBusy(null);
          setFinalizeModal(null);
        }
      };

      // ── Render ───────────────────────────────────────────────────
      if (!electionId || !ballotId) {
        return (
          <div className="container py-8 space-y-6">
            <div className="card space-y-3">
              <h1 className="text-xl font-semibold">Invalid ballot URL</h1>
              <p className="text-[var(--color-muted)] text-sm">
                Both <code className="mono">electionId</code> and{" "}
                <code className="mono">ballotId</code> query params are
                required.
              </p>
              <Link href="/" className="btn-secondary text-sm">
                Back to home
              </Link>
            </div>
            <Footer />
          </div>
        );
      }

      if (!election) {
        return (
          <div className="container py-8 space-y-6">
            <div className="card space-y-3">
              <h1 className="text-xl font-semibold">No election session</h1>
              <p className="text-[var(--color-muted)] text-sm">
                This browser has no bootstrap for election{" "}
                <code className="mono">{truncHex(electionId, 10, 6)}</code>.
                Open the election page first — it will hydrate the session
                from WalletConnect home or a share-bundle import.
              </p>
              <Link href={electionHomeHref} className="btn-secondary text-sm">
                Open election page
              </Link>
            </div>
            <Footer />
          </div>
        );
      }

      if (!ballot) {
        return (
          <div className="container py-8 space-y-6">
            <div className="card space-y-3">
              <h1 className="text-xl font-semibold">Ballot not found</h1>
              <p className="text-[var(--color-muted)] text-sm">
                No bootstrap for ballot{" "}
                <code className="mono">{truncHex(ballotId, 10, 6)}</code>{" "}
                under this election. Open the election page and pick this
                ballot from the list.
              </p>
              <Link href={electionHomeHref} className="btn-secondary text-sm">
                Open election page
              </Link>
            </div>
            <Footer />
          </div>
        );
      }

      // Status badge styling.
      const statusBadge = (() => {
        if (isFinalized) {
          const height =
            (ballot?.finalizedAtHeight && ballot.finalizedAtHeight > 0
              ? ballot.finalizedAtHeight
              : null) ??
            (status?.kind === "finalized" ? status.height : null);
          return {
            label: height
              ? `Finalized at block ${height.toLocaleString()}`
              : "Finalized",
            cls: "bg-[var(--color-accent)]/15 text-[var(--color-accent)]",
          };
        }
        if (status?.kind === "open") {
          return {
            label: `Open · ${status.blocksRemaining} blocks left`,
            cls: "bg-green-500/15 text-green-700 dark:text-green-400",
          };
        }
        if (status?.kind === "closed") {
          return {
            label: `Closed · pending finalize (+${status.blocksOver} blocks)`,
            cls: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
          };
        }
        return { label: "Loading…", cls: "bg-[var(--color-muted)]/15" };
      })();

      const totalWeight = ballot.registrationVoteWeightSnapshot ?? 0;
      const quorumNum = ballot.voteThresholdNum;
      const quorumDen = ballot.voteThresholdDen;
      const requiredWeight =
        totalWeight > 0
          ? Math.ceil((totalWeight * quorumNum) / quorumDen)
          : 0;

      const choices =
        ballot.choices && ballot.choices.length > 0
          ? ballot.choices
          : election.choices ?? [];
      const myReg = !!voterPk;
      const canVote = myReg && isOpen && !!address;

      return (
        <div className="container py-8 space-y-6">
          <nav className="text-xs text-[var(--color-muted)]">
            <Link href={electionHomeHref} className="hover:underline">
              ← Back to election
            </Link>
          </nav>

          {/* ────────── Header ────────── */}
          <header className="card space-y-3">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h1 className="text-xl font-semibold">
                Ballot{" "}
                <span className="mono text-base">
                  {truncHex(normalizeHex32(ballot.ballotLauncherIdHex), 10, 6)}
                </span>
              </h1>
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold ${statusBadge.cls}`}
              >
                {statusBadge.label}
              </span>
              {(() => {
                // M13: render the per-ballot vote-mode badge from
                // BallotBootstrap.voteOptionsRootHex.
                //   - missing / 0x00…00 → Mode1Free
                //   - any other 32-byte hex → Mode2Restricted (N options)
                //     where N is the count from local ballot.choices.
                const lockHex = ballot.voteOptionsRootHex
                  ?.replace(/^0x/, "")
                  .toLowerCase();
                const FREE = "00".repeat(32);
                if (!lockHex || lockHex === FREE) {
                  return (
                    <span className="inline-flex items-center rounded-full bg-blue-500/15 text-blue-700 dark:text-blue-300 px-2 py-0.5 text-[11px] font-bold">
                      Mode: free
                    </span>
                  );
                }
                const n = ballot.choices?.length ?? 0;
                return (
                  <span className="inline-flex items-center rounded-full bg-purple-500/15 text-purple-700 dark:text-purple-300 px-2 py-0.5 text-[11px] font-bold">
                    Mode: restricted ({n} option{n === 1 ? "" : "s"})
                  </span>
                );
              })()}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs text-[var(--color-muted)]">
              <div>
                <div className="font-medium text-[var(--color-foreground)]">
                  Vote close
                </div>
                <div className="mono">
                  {ballot.voteCloseHeight.toLocaleString()}
                  {peak != null && (
                    <span className="opacity-60">
                      {" "}
                      / {peak.toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
              <div>
                <div className="font-medium text-[var(--color-foreground)]">
                  Total vote weight
                </div>
                <div className="mono">{totalWeight.toLocaleString()}</div>
              </div>
              <div>
                <div className="font-medium text-[var(--color-foreground)]">
                  Quorum
                </div>
                <div className="mono">
                  {quorumNum} / {quorumDen}
                </div>
                <div className="text-[10px] opacity-70">
                  needs ≥ {requiredWeight.toLocaleString()} weight
                </div>
              </div>
              <div>
                <div className="font-medium text-[var(--color-foreground)]">
                  Snapshot voters
                </div>
                <div className="mono">
                  {ballot.registrationCountSnapshot ?? "?"}
                </div>
              </div>
            </div>
          </header>

          {/* ────────── Status banner — error/busy/tx ────────── */}
          {(busy || txStatus || error) && (
            <section className="card space-y-2">
              {busy && (
                <div className="flex items-center gap-2 text-[var(--color-accent)] text-sm">
                  <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
                  <span>{busy}</span>
                </div>
              )}
              {txStatus && (
                <div className="text-[var(--color-accent)] text-sm">
                  {txStatus}
                </div>
              )}
              {error && (
                <div
                  role="alert"
                  className="rounded-xl border-2 border-rose-500/60 bg-rose-500/10 p-4 flex items-start gap-3"
                >
                  <span
                    aria-hidden
                    className="text-rose-500 text-lg leading-none mt-0.5"
                  >
                    ⚠
                  </span>
                  <div className="flex-1 text-rose-700 dark:text-rose-300 text-sm whitespace-pre-wrap break-words">
                    <div className="font-semibold mb-1">
                      Something went wrong
                    </div>
                    <div>{error}</div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setError(null)}
                    className="text-rose-700/70 dark:text-rose-300/70 hover:text-rose-700 dark:hover:text-rose-200 text-xs px-2 py-1 rounded border border-rose-500/40 hover:bg-rose-500/10"
                  >
                    Dismiss
                  </button>
                </div>
              )}
            </section>
          )}

          {/* ────────── Your vote ────────── */}
          {myVoteDataHex && (
            <section className="card space-y-2">
              <h2 className="text-sm font-semibold">Your vote</h2>
              {(() => {
                const matched = choices.find(
                  (c) =>
                    normalizeHex32(c.voteDataHex) ===
                    normalizeHex32(myVoteDataHex)
                );
                return (
                  <div className="text-sm">
                    {matched ? (
                      <span>
                        You voted{" "}
                        <span className="font-semibold">{matched.label}</span>{" "}
                        <span className="mono text-xs opacity-70">
                          ({truncHex(myVoteDataHex, 10, 6)})
                        </span>
                      </span>
                    ) : (
                      <span className="mono text-xs">
                        {truncHex(myVoteDataHex, 18, 10)}
                      </span>
                    )}
                  </div>
                );
              })()}
            </section>
          )}

          {/* ── Threshold progress (Phase D-2): live signed weight ── */}
          {!isFinalized &&
            ballot &&
            ballot.registrationVoteWeightSnapshot > 0 &&
            ballot.voteThresholdDen > 0 &&
            (() => {
              const total = ballot.registrationVoteWeightSnapshot;
              const required = Math.ceil(
                (total * ballot.voteThresholdNum) / ballot.voteThresholdDen
              );
              const signed = signedWeight ?? 0;
              const pct =
                required > 0 ? Math.min(100, (signed / required) * 100) : 0;
              const met = required > 0 && signed >= required;
              return (
                <section className="card space-y-2">
                  <h2 className="text-sm font-semibold">
                    Threshold progress
                  </h2>
                  <div className="flex flex-wrap items-baseline justify-between gap-x-3 text-xs">
                    <span>
                      Signed weight:{" "}
                      <span className="font-semibold">
                        {signed.toLocaleString()}
                      </span>{" "}
                      / required{" "}
                      <span className="font-semibold">
                        {required.toLocaleString()}
                      </span>{" "}
                      <span className="text-[var(--color-muted)]">
                        (of {total.toLocaleString()} total registered weight)
                      </span>
                    </span>
                    <span
                      className={
                        met
                          ? "font-bold text-green-700 dark:text-green-400"
                          : ""
                      }
                    >
                      {pct.toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full h-2 rounded bg-[var(--color-border)] overflow-hidden">
                    <div
                      className={`h-full transition-[width] duration-500 ${
                        met
                          ? "bg-green-500"
                          : "bg-[var(--color-accent)]"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-[var(--color-muted)]">
                    {met
                      ? "Threshold met — anyone holding the proving key can finalize once the voting window closes."
                      : "Awaiting more signed weight before this ballot can be finalized."}
                    {voterWeights == null
                      ? " (Loading per-voter weights from chain…)"
                      : null}
                  </p>
                </section>
              );
            })()}

          {/* ── Voter status banner (chain-derived) ─────────────── */}
          {address && voterRegistrationStatus === "released" && (
            <section className="card space-y-1 border-2 border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.05]">
              <h2 className="text-sm font-semibold">Released</h2>
              <p className="text-xs text-[var(--color-muted)]">
                Your registration coin is no longer on chain — collateral
                has been returned. No further actions available on this
                ballot for your wallet.
              </p>
            </section>
          )}
          {address && voterRegistrationStatus === "unregistered" && !isFinalized && (
            <section className="card space-y-1 border-2 border-amber-500/40 bg-amber-500/[0.04]">
              <h2 className="text-sm font-semibold">Not registered</h2>
              <p className="text-xs text-[var(--color-muted)]">
                Your wallet is not in the on-chain registered voter set.{" "}
                <Link
                  href={electionHomeHref}
                  className="text-[var(--color-accent)] hover:underline"
                >
                  Visit the election page
                </Link>{" "}
                to register before casting a vote.
              </p>
            </section>
          )}

          {/* ────────── Cast / change vote ────────── */}
          {!isFinalized && isOpen && !isReleased && !isUnregistered && (
            <section className="card space-y-3">
              <h2 className="text-sm font-semibold">
                {myVoteDataHex ? "Change your vote" : "Cast your vote"}
              </h2>
              {!address ? (
                <p className="text-[var(--color-muted)] text-sm">
                  Connect Sage Wallet (top right) to vote.
                </p>
              ) : pubkeyResolutionBusy ? (
                <div className="text-[var(--color-muted)] text-sm flex items-start gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-[var(--color-muted)]/50 animate-pulse mt-1.5" />
                  <span>
                    Resolving voter pubkey…
                    {pubkeyResolutionDetail ? (
                      <span className="block text-xs opacity-70 mt-0.5">
                        {pubkeyResolutionDetail}
                      </span>
                    ) : null}
                  </span>
                </div>
              ) : !voterPk ? (
                <div className="text-[var(--color-muted)] text-sm">
                  <p>
                    Could not match your Sage wallet to a registered voter on
                    this election.
                  </p>
                  {pubkeyResolutionDetail ? (
                    <p className="text-xs opacity-70 mt-1">
                      {pubkeyResolutionDetail}
                    </p>
                  ) : null}
                  <p className="text-xs mt-2">
                    If you registered in another browser or a fresh session,
                    re-import the share bundle on{" "}
                    <Link
                      href={electionHomeHref}
                      className="text-[var(--color-accent)] hover:underline"
                    >
                      the election page
                    </Link>{" "}
                    so this browser tracks your pubkey, then return here.
                  </p>
                </div>
              ) : choices.length > 0 ? (
                <>
                  <div className="space-y-1">
                    {choices.map((c, i) => (
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
                          disabled={!!busy}
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
                    onClick={myVoteDataHex ? handleChangeVote : handleVote}
                    className="btn-primary"
                    disabled={!!busy || !canVote || pickedChoiceIdx === null}
                  >
                    {myVoteDataHex ? "Replace vote" : "Cast vote"}
                  </button>
                </>
              ) : (
                <>
                  <input
                    value={freeformVote}
                    onChange={(e) => setFreeformVote(e.target.value)}
                    placeholder="yes"
                    className="input"
                    disabled={!!busy}
                  />
                  <button
                    type="button"
                    onClick={myVoteDataHex ? handleChangeVote : handleVote}
                    className="btn-primary"
                    disabled={!!busy || !canVote || !freeformVote.trim()}
                  >
                    {myVoteDataHex ? "Replace vote" : "Cast vote"}
                  </button>
                </>
              )}
            </section>
          )}

          {/* ────────── Finalize (anyone with proving key) ────────── */}
          {!isFinalized && isClosed && (
            <section className="card space-y-3 border-2 border-amber-500/40 bg-amber-500/[0.04]">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold">Finalize this ballot</h2>
                <span className="text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                  Permissionless
                </span>
              </div>
              <p className="text-xs text-[var(--color-muted)]">
                The voting period has ended. Anyone holding the Groth16
                proving key can finalize. The first successful finalize wins;
                subsequent attempts no-op.
              </p>
              {!election.provingKeyBase64 ? (
                <p className="text-sm text-amber-700 dark:text-amber-300">
                  Proving key not loaded in this browser. Import the share
                  bundle for this election to enable finalize.
                </p>
              ) : !address ? (
                <p className="text-sm text-[var(--color-muted)]">
                  Connect Sage Wallet — finalize routes the operator reward
                  to your receive address.
                </p>
              ) : (
                <button
                  type="button"
                  onClick={handleFinalize}
                  className="btn-primary"
                  disabled={!!busy || !!finalizeModal}
                >
                  Finalize ballot
                </button>
              )}
            </section>
          )}

          {/* ────────── Post-finalize tally view ────────── */}
          {isFinalized && (
            <section className="card space-y-3">
              <h2 className="text-sm font-semibold">Final outcome</h2>
              {(() => {
                const winnerChoice = choices.find(
                  (c) =>
                    ballot.voteOutcomeHex &&
                    normalizeHex32(c.voteDataHex) ===
                      normalizeHex32(ballot.voteOutcomeHex)
                );
                const totalVotes = Array.from(
                  perChoiceTally.values()
                ).reduce((a, b) => a + b, 0);
                return (
                  <>
                    <div className="text-sm">
                      {winnerChoice ? (
                        <p>
                          Winner:{" "}
                          <span className="font-semibold">
                            {winnerChoice.label}
                          </span>{" "}
                          <span className="mono text-xs opacity-70">
                            ({truncHex(winnerChoice.voteDataHex, 10, 6)})
                          </span>
                        </p>
                      ) : ballot.voteOutcomeHex ? (
                        <p className="mono text-xs">
                          {truncHex(ballot.voteOutcomeHex, 18, 10)}
                        </p>
                      ) : (
                        <p className="text-[var(--color-muted)]">
                          Outcome not yet recorded in this session — re-import
                          the share bundle for the latest finalize state.
                        </p>
                      )}
                    </div>
                    {choices.length > 0 && totalVotes > 0 && (
                      <div className="space-y-2 mt-3">
                        <div className="text-xs text-[var(--color-muted)]">
                          Vote distribution ({totalVotes.toLocaleString()}{" "}
                          ballot{totalVotes === 1 ? "" : "s"}; weights resolve
                          on-chain via finalize)
                        </div>
                        {choices.map((c) => {
                          const k = normalizeHex32(c.voteDataHex).replace(
                            /^0x/,
                            ""
                          );
                          const count = perChoiceTally.get(k) ?? 0;
                          const pct =
                            totalVotes > 0
                              ? (count / totalVotes) * 100
                              : 0;
                          const isWinner =
                            winnerChoice &&
                            normalizeHex32(winnerChoice.voteDataHex) ===
                              normalizeHex32(c.voteDataHex);
                          return (
                            <div key={c.voteDataHex} className="space-y-1">
                              <div className="flex items-center justify-between gap-3 text-xs">
                                <span
                                  className={`font-medium ${
                                    isWinner
                                      ? "text-[var(--color-accent)]"
                                      : ""
                                  }`}
                                >
                                  {c.label}
                                  {isWinner ? " 🏆" : ""}
                                </span>
                                <span className="mono opacity-80">
                                  {count} · {pct.toFixed(1)}%
                                </span>
                              </div>
                              <div className="h-2 rounded-full bg-[var(--color-muted)]/10 overflow-hidden">
                                <div
                                  className={`h-full rounded-full transition-all ${
                                    isWinner
                                      ? "bg-[var(--color-accent)]"
                                      : "bg-[var(--color-muted)]/40"
                                  }`}
                                  style={{ width: `${pct}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </>
                );
              })()}
            </section>
          )}

          {/* ────────── Choices reference ────────── */}
          {choices.length > 0 && !isFinalized && (
            <section className="card space-y-2">
              <h2 className="text-sm font-semibold">Choices</h2>
              <ul className="space-y-1.5">
                {choices.map((c) => (
                  <li
                    key={c.voteDataHex}
                    className="flex items-center justify-between gap-3 text-sm"
                  >
                    <span className="font-medium">{c.label}</span>
                    <span className="mono text-xs text-[var(--color-muted)]">
                      {truncHex(c.voteDataHex, 10, 6)}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* ────────── Modals ────────── */}
          {broadcastAwait && (
            <BroadcastWaitModal
              title={broadcastAwait.title}
              detail={broadcastAwait.detail}
            />
          )}
          {castVoteModal && !manualSigPrompt && (
            <BroadcastWaitModal
              title={castVoteModal.title}
              detail={castVoteModal.detail}
              titleId="cast-vote-modal-title"
            />
          )}
          {manualSigPrompt && (
            <div
              className="fixed inset-0 z-[140] flex items-center justify-center bg-black/70 px-4 backdrop-blur-sm"
              role="dialog"
              aria-modal="true"
              aria-labelledby="manual-sig-modal-title"
            >
              <div className="w-full max-w-2xl rounded-2xl border border-[var(--color-border)] bg-[var(--color-bg)] shadow-2xl p-6 space-y-4">
                <h2
                  id="manual-sig-modal-title"
                  className="font-semibold text-lg leading-snug"
                >
                  Manual signature required
                </h2>
                <p className="text-sm text-[var(--color-muted)] leading-relaxed">
                  Sage Wallet returned the BLS identity point — it doesn&rsquo;t
                  expose unaugmented (<span className="mono">sign_raw</span>) BLS
                  signing for messages, which the CHIP voting protocol requires.
                  Compute the signature locally and paste the 96-byte hex below.
                </p>
                <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-elev)] p-3 space-y-2">
                  <div>
                    <div className="text-[11px] uppercase tracking-wide text-[var(--color-muted)]">
                      Voter pubkey (synthetic G1, 48 bytes)
                    </div>
                    <div className="mono text-xs break-all">
                      {manualSigPrompt.voterPubkeyHex}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] uppercase tracking-wide text-[var(--color-muted)]">
                      Vote message (32 bytes — sign this)
                    </div>
                    <div className="mono text-xs break-all">
                      {manualSigPrompt.voteMessageHex}
                    </div>
                  </div>
                </div>
                <p className="text-xs text-[var(--color-muted)] leading-relaxed">
                  Compute via Python:{" "}
                  <span className="mono">
                    chia.bls.sign_raw(sk, bytes.fromhex(message))
                  </span>{" "}
                  — paste the resulting 96-byte G2 sig hex below.
                </p>
                <textarea
                  value={manualSigInput}
                  onChange={(e) => setManualSigInput(e.target.value)}
                  placeholder="0x... (192 hex chars)"
                  className="w-full h-28 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-elev)] p-3 mono text-xs focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
                />
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => {
                      manualSigPrompt.resolve(null);
                      setManualSigPrompt(null);
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={
                      manualSigInput.replace(/^0x/i, "").trim().length !== 192
                    }
                    onClick={() => {
                      const sig = manualSigInput.trim();
                      manualSigPrompt.resolve(sig);
                      setManualSigPrompt(null);
                    }}
                  >
                    Submit signature
                  </button>
                </div>
              </div>
            </div>
          )}
          {finalizeModal && (
            <BroadcastWaitModal
              title={finalizeModal.title}
              detail={finalizeModal.detail}
            />
          )}

          <Footer />
        </div>
      );
    };
  },
  { ssr: false }
);

function base64ToBytes(b64: string): Uint8Array {
  const binStr = atob(b64);
  const arr = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) arr[i] = binStr.charCodeAt(i);
  return arr;
}

function hexToBytes(h: string): Uint8Array {
  const raw = h.replace(/^0x/, "");
  const out = new Uint8Array(raw.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(raw.substr(i * 2, 2), 16);
  }
  return out;
}

export default function BallotPage() {
  return (
    <Suspense
      fallback={
        <div className="container py-8">
          <div className="space-y-4">
            <div className="skeleton h-9 w-1/2" />
            <div className="skeleton h-32" />
            <div className="skeleton h-24" />
          </div>
        </div>
      }
    >
      <BallotPageInner />
    </Suspense>
  );
}
