"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import walletConnect from "../lib/walletConnectInstance";
import type { WalletConnectCoinSpend } from "../lib/WalletConnect";
import {
  coinRecordsByPuzzleHash,
  coinRecordByName,
  isConsensusRetriablePushError,
  peakHeight,
  pushTx,
  stripHex,
} from "../lib/coinset";
import type { CoinRecord, SpendBundleJson } from "../lib/coinset";
import { upsertElection } from "../lib/elections";
import { writeElectionBootstrap } from "../lib/electionBootstrap";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { parseCat } from "../lib/units";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { pollUntilConfirmed } from "../lib/pollUntil";
import {
  findCeremonyVoucherCoin,
  getWasm,
  recoverCeremonyBootstrap,
} from "../lib/sdk";
import type { CeremonyVoucherCoin } from "../lib/sdk";

// ─────────────────────────────────────────────────────────────────────
// Helpers (declared before dynamic() so nested components resolve them reliably)
// ─────────────────────────────────────────────────────────────────────

/** Stable fingerprint for launcher parent selection / deduping retries. */
function coinRecordDedupeKey(c: CoinRecord): string {
  return `${stripHex(c.parentCoinInfo)}|${stripHex(c.puzzleHash)}|${c.amount}`;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// CRITICAL WASM IMPORT PATTERN — see comment in WalletBalances.tsx.
// The dynamic factory loads `chip-voting-wasm` exactly once on the
// client; the returned component closes over the loaded `wasm`
// reference and uses it freely.
export default dynamic(
  async function DynamicElem() {
    const wasm = await getWasm();

    return function CreateElectionPage() {
      const router = useRouter();
      const searchParams = useSearchParams();
      const { address } = useAppSelector((s) => s.wallet);

      const [label, setLabel] = useState("");
      const [catTailHex, setCatTailHex] = useState("");
      // Verification key the deploy form will curry into the Election
      // Singleton. Pasted by the user (from /ceremony's click-to-copy
      // VK panel) or auto-filled via ?vkHex=... URL param. When empty,
      // the form falls back to the in-browser single-participant
      // trusted setup behind a "test mode" disclosure.
      const [vkHex, setVkHex] = useState("");

      useEffect(() => {
        const vkParam = searchParams.get("vkHex");
        if (vkParam) {
          setVkHex(vkParam.replace(/^0x/, ""));
        }
      }, [searchParams]);

      // V10: optional ceremony→election link. When `?ceremonyId=...` is
      // set, the dApp discovers the unspent voucher coin and threads its
      // fields into deployElectionBundle so the election commits to the
      // ceremony's (vk_hash, max_voters, ceremony_launcher_id) triple
      // via AssertCoinAnnouncement.
      const [ceremonyIdHex, setCeremonyIdHex] = useState<string>("");
      useEffect(() => {
        const param = searchParams.get("ceremonyId");
        if (param) setCeremonyIdHex(param.startsWith("0x") ? param : `0x${param}`);
      }, [searchParams]);

      // M11: per-election vote-mode lock. When operators want every
      // ballot from this election to use a specific mode (Free or a
      // pre-committed restricted set), pick "Free" or "Restricted" and
      // the dApp computes the on-chain `vote_mode_lock` value the
      // election will enforce.
      const [voteModeLockChoice, setVoteModeLockChoice] = useState<
        "none" | "free" | "restricted"
      >("none");
      const [voteOptionLabelsText, setVoteOptionLabelsText] = useState("");
      type LockComputation =
        | { kind: "idle" }
        | { kind: "computing" }
        | {
            kind: "ready";
            voteModeLockHex: string; // 32-byte hex, "0x" prefix
            labels: string[];
            optionHashes: string[]; // 32-byte hex, "0x" prefix, same order as labels
          }
        | { kind: "error"; message: string };
      const [voteModeLock, setVoteModeLock] = useState<LockComputation>({
        kind: "idle",
      });

      type VoucherDiscovery =
        | { kind: "idle" }
        | { kind: "looking" }
        | {
            kind: "found";
            launcherIdHex: string;
            maxVoters: number;
            vkHashHex: string;
            voucher: CeremonyVoucherCoin;
          }
        | { kind: "not_found"; launcherIdHex: string; reason: string }
        | { kind: "error"; message: string };
      const [voucher, setVoucher] = useState<VoucherDiscovery>({ kind: "idle" });

      // Compute sha256(vk_bytes) → vk_hash. The on-chain voucher's
      // canonical announcement binds this exact hash; we MUST hash the
      // pasted VK locally so a vk paste that doesn't match the
      // ceremony's derived VK fails fast (rather than silently
      // missing-voucher at deploy time).
      const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
        // Copy into a fresh ArrayBuffer so the digest API gets a strict
        // ArrayBuffer (its types reject SharedArrayBuffer-backed views).
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const buf = await window.crypto.subtle.digest("SHA-256", ab);
        const arr = new Uint8Array(buf);
        let s = "";
        for (let i = 0; i < arr.length; i++) {
          s += arr[i].toString(16).padStart(2, "0");
        }
        return `0x${s}`;
      };

      useEffect(() => {
        const trimmedVkHex = vkHex.trim().replace(/^0x/, "");
        const trimmedCeremony = ceremonyIdHex.trim();
        if (!trimmedCeremony || !trimmedVkHex) {
          setVoucher({ kind: "idle" });
          return;
        }
        let cancelled = false;
        setVoucher({ kind: "looking" });
        (async () => {
          try {
            const bootstrap = await recoverCeremonyBootstrap(trimmedCeremony);
            if (cancelled) return;
            if (!bootstrap) {
              setVoucher({
                kind: "not_found",
                launcherIdHex: trimmedCeremony,
                reason:
                  "Could not recover ceremony bootstrap from chain (launcher unspent or memo missing)",
              });
              return;
            }
            const vkBytes = hexToBytes(trimmedVkHex);
            const vkHashHex = await sha256Hex(vkBytes);
            const found = await findCeremonyVoucherCoin(
              trimmedCeremony,
              vkHashHex,
              bootstrap.maxVoters
            );
            if (cancelled) return;
            if (!found) {
              setVoucher({
                kind: "not_found",
                launcherIdHex: trimmedCeremony,
                reason:
                  "No unspent voucher coin at the predicted puzzle hash. Verify the pasted VK matches the ceremony's derived VK and that finalize has run.",
              });
              return;
            }
            setVoucher({
              kind: "found",
              launcherIdHex: trimmedCeremony,
              maxVoters: bootstrap.maxVoters,
              vkHashHex,
              voucher: found,
            });
          } catch (e) {
            if (cancelled) return;
            setVoucher({
              kind: "error",
              message: e instanceof Error ? e.message : String(e),
            });
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [ceremonyIdHex, vkHex]);

      // M11: recompute the vote-mode lock value whenever the operator
      // changes the lock choice or the option-label list. For "free"
      // the lock value is the 0x00…00 sentinel (Mode1Free). For
      // "restricted" we sha256 each label, sort the resulting hashes
      // ascending, and merkle-root them via the wasm helper.
      useEffect(() => {
        if (voteModeLockChoice === "none") {
          setVoteModeLock({ kind: "idle" });
          return;
        }
        if (voteModeLockChoice === "free") {
          setVoteModeLock({
            kind: "ready",
            voteModeLockHex: "0x" + "00".repeat(32),
            labels: [],
            optionHashes: [],
          });
          return;
        }
        // restricted: parse labels, hash, build merkle root.
        const rawLabels = voteOptionLabelsText
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0);
        if (rawLabels.length < 2) {
          setVoteModeLock({
            kind: "error",
            message:
              "Restricted mode requires at least 2 distinct option labels",
          });
          return;
        }
        const dedup = Array.from(new Set(rawLabels));
        if (dedup.length !== rawLabels.length) {
          setVoteModeLock({
            kind: "error",
            message: `Restricted mode requires unique labels (got ${rawLabels.length - dedup.length} duplicate(s))`,
          });
          return;
        }
        let cancelled = false;
        setVoteModeLock({ kind: "computing" });
        (async () => {
          try {
            const optionHashes: string[] = [];
            for (const label of dedup) {
              const enc = new TextEncoder().encode(label);
              const h = await sha256Hex(enc);
              optionHashes.push(h);
            }
            const concat = optionHashes
              .map((h) => h.replace(/^0x/, ""))
              .join("");
            // Wasm helper sorts ascending internally; we just feed the
            // raw concat. Returns "0x"-prefixed merkle root hex.
            const rootRaw = (await wasm.merkleRootOfSortedCoinIds(
              concat
            )) as string;
            if (cancelled) return;
            const root = rootRaw.startsWith("0x") ? rootRaw : "0x" + rootRaw;
            setVoteModeLock({
              kind: "ready",
              voteModeLockHex: root,
              labels: dedup,
              optionHashes,
            });
          } catch (e) {
            if (cancelled) return;
            setVoteModeLock({
              kind: "error",
              message: e instanceof Error ? e.message : String(e),
            });
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [voteModeLockChoice, voteOptionLabelsText]);

      // CHIP rev 2026-05-02:
      //   * `collateral_amount` is HARD-CODED to 1 CAT mojo in the
      //     registration_coin puzzle — not a deployer-tunable knob,
      //     not surfaced in the deploy form.
      //   * `election_length_blocks` and `vote_threshold_num/den`
      //     are per-ballot. Set when minting a ballot from
      //     /election → "Mint a new ballot".
      //   * Voter choices are per-ballot. Set when minting a ballot.
      const [status, setStatus] = useState<string>("Ready");
      const [busy, setBusy] = useState(false);
      const [deployAwait, setDeployAwait] = useState<null | {
        title: string;
        detail: string;
      }>(null);

      // CHIP rev 2026-05-02: voter choices are per-BALLOT, not
      // per-election. The deployer specifies them when minting a
      // ballot via /election → "Mint a new ballot".

      const handleDeploy = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!address) return;
        setBusy(true);
        try {
          // ---- 1. Get the Groth16 VK.
          //   Path A (production): user pasted a VK hex (from
          //     /ceremony's click-to-copy panel after a multi-
          //     participant ceremony's threshold was met). Use the
          //     bytes directly as DeployParams.verification_key.
          //   Path B (test mode): legacy in-browser single-participant
          //     trusted setup. UNSAFE for production — anyone who
          //     runs this can forge proofs against the resulting VK.
          let ceremony: {
            verificationKeyHex: string;
            provingKeyBytes: Uint8Array;
          };
          const trimmedVkHex = vkHex.trim().replace(/^0x/, "");
          if (trimmedVkHex.length > 0) {
            setStatus("Using pasted verification key…");
            ceremony = {
              verificationKeyHex: trimmedVkHex,
              // Aggregators run derive_vk themselves to recover the
              // PK from chain-walked records; the dApp doesn't need
              // the PK to deploy.
              provingKeyBytes: new Uint8Array(),
            };
          } else {
            setStatus("Running test-mode trusted-setup ceremony…");
            console.time("[chip:deploy] runSingleParticipantCeremony (wasm — Groth16 setup)");
            ceremony = (await wasm.runSingleParticipantCeremony()) as {
              verificationKeyHex: string;
              provingKeyBytes: Uint8Array;
            };
            console.timeEnd("[chip:deploy] runSingleParticipantCeremony (wasm — Groth16 setup)");
          }

          // ---- 2. Resolve XCH puzzle hash (parent coins refetched each attempt below).
          setStatus("Resolving puzzle hash…");
          console.time("[chip:deploy] puzzleHashHexFromWalletAddress");
          const xchPh = await puzzleHashHexFromWalletAddress(address);
          console.timeEnd("[chip:deploy] puzzleHashHexFromWalletAddress");
          if (!xchPh) throw new Error("Could not decode wallet address");

          // ---- 3. Read chain peak for election_start_height.
          console.time("[chip:deploy] peakHeight (coinset RPC)");
          const peak = await peakHeight();
          console.timeEnd("[chip:deploy] peakHeight (coinset RPC)");
          if (peak === null) {
            throw new Error(
              "Could not read chain peak (get_blockchain_state). Try again when the network is reachable."
            );
          }

          // V10: linked-deploy gate. If the operator selected a ceremony
          // (?ceremonyId=...), the discovery effect must have resolved
          // an unspent voucher. Refuse to deploy with mismatched/absent
          // voucher rather than silently falling through to the legacy
          // unlinked path.
          if (ceremonyIdHex.trim().length > 0 && voucher.kind !== "found") {
            throw new Error(
              voucher.kind === "looking"
                ? "Voucher discovery still running — wait for the linked-status panel to resolve"
                : voucher.kind === "not_found"
                ? `Linked deploy blocked: ${voucher.reason}`
                : voucher.kind === "error"
                ? `Linked deploy blocked: ${voucher.message}`
                : "Linked deploy blocked: select a ceremony with a finalized voucher or remove ?ceremonyId="
            );
          }

          const linkedFields =
            voucher.kind === "found"
              ? {
                  ceremonyLauncherIdHex: voucher.launcherIdHex,
                  vkHashHex: voucher.vkHashHex,
                  ceremonyVoucherCoinParentIdHex: voucher.voucher.parentCoinIdHex,
                  ceremonyVoucherAmount: voucher.voucher.amount,
                }
              : {};

          // M11: vote-mode lock. Block deploy when the operator picked
          // a lock mode but it didn't resolve cleanly (e.g. <2 labels).
          if (voteModeLockChoice !== "none" && voteModeLock.kind !== "ready") {
            throw new Error(
              voteModeLock.kind === "computing"
                ? "Vote-mode lock still computing — wait for the labels to hash"
                : voteModeLock.kind === "error"
                ? `Vote-mode lock blocked: ${voteModeLock.message}`
                : "Vote-mode lock unresolved — fix the lock selection or pick 'No lock'"
            );
          }
          const lockFields =
            voteModeLock.kind === "ready"
              ? { voteModeLockHex: voteModeLock.voteModeLockHex }
              : {};

          const params = {
            verificationKeyHex: ceremony.verificationKeyHex,
            catTailHashHex: catTailHex,
            // 1 CAT mojo — hard-coded in the registration_coin
            // puzzle's curry args; deployers cannot override.
            collateralAmount: 1,
            electionStartHeight: peak,
            label: label.trim() || null,
            ...linkedFields,
            ...lockFields,
          };

          // Persist label → option-hash mapping under the merkle root
          // so /ballot can recover human-readable strings later. Keyed
          // on the lock root because that's stable + recoverable from
          // chain (M8: BallotCoinSnapshot.vote_options_root).
          if (
            voteModeLock.kind === "ready" &&
            voteModeLock.labels.length > 0
          ) {
            try {
              const key = `chipVoteOptionLabels:${voteModeLock.voteModeLockHex}`;
              window.localStorage.setItem(
                key,
                JSON.stringify({
                  labels: voteModeLock.labels,
                  optionHashes: voteModeLock.optionHashes,
                })
              );
            } catch {
              // localStorage not available / quota — fail soft; the
              // election still deploys, just labels won't render.
            }
          }

          const maxParentAttempts = 10;
          const triedParents = new Set<string>();
          let artifacts: {
            coinSpendsBytes: Uint8Array;
            launcherIdHex: string;
            configJson: string;
            eveSingletonCoinIdHex: string;
          } | null = null;

          // ---- 4–7. Retry with fresh coinset reads + alternate XCH coins when mempool reports
          // launcher parent conflicts (e.g. MINTING_COIN after a concurrent spend path).
          // Sage owns the XCH coins — fetch them via chip0002_getAssetCoins
          // which returns the puzzle reveal alongside each coin. Uncurrying
          // the standard p2 puzzle gives the synthetic_pk directly, so we
          // skip the O(N) chip0002_getPublicKeys scan entirely. Replaces
          // the slow path that took ~57s on wallets with many derived keys.
          const { listXchCoinsWithKeys } = await import("../lib/sageAssetCoins");
          for (let parentAttempt = 0; parentAttempt < maxParentAttempts; parentAttempt++) {
            console.time(`[chip:deploy] listXchCoinsWithKeys attempt#${parentAttempt} (Sage getAssetCoins + uncurry)`);
            const sageCoins = await listXchCoinsWithKeys({
              minAmount: 2,
              includeLocked: false,
              limit: 200,
            });
            console.timeEnd(`[chip:deploy] listXchCoinsWithKeys attempt#${parentAttempt} (Sage getAssetCoins + uncurry)`);
            const fresh = sageCoins
              .map((s) => ({
                parentCoinInfo: s.coin.parent_coin_info,
                puzzleHash: s.coin.puzzle_hash,
                amount: s.coin.amount,
                // Sage doesn't track these per-coin; default to 0
                // (unspent) since we filter to non-locked already.
                spentHeight: 0,
                confirmedHeight: 0,
                syntheticPkHex: s.syntheticPkHex,
              }))
              .filter((c) => c.amount >= 2);
            fresh.sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
            const parent =
              fresh.find((c) => !triedParents.has(coinRecordDedupeKey(c))) ?? null;

            if (!parent) {
              throw new Error(
                triedParents.size === 0
                  ? "No XCH coin available in your wallet. Send at least 1 mojo to your address first."
                  : `Every usable XCH coin was tried (${triedParents.size}). Wait for mempool to settle or consolidate coins, then try again.`
              );
            }
            triedParents.add(coinRecordDedupeKey(parent));

            setStatus(
              parentAttempt === 0
                ? "Locating signing key…"
                : `Funding coin conflict — fetching another launcher parent (${parentAttempt + 1}/${maxParentAttempts})…`
            );
            if (parentAttempt > 0) {
              await new Promise((r) => setTimeout(r, 900));
            }

            // synthetic_pk came from the Sage-supplied puzzle reveal
            // uncurry — no scan needed.
            const synPk = parent.syntheticPkHex;
            if (!synPk) {
              throw new Error(
                "Sage's puzzle reveal didn't yield a synthetic_pk for the funder coin"
              );
            }

            setStatus("Building deploy spend bundle…");
            // serde_wasm_bindgen + #[serde(with = "serde_bytes")] emits
            // a JS Map (not a plain object) for the artifacts struct.
            // Convert via Object.fromEntries when that happens —
            // mirrors the dance in
            // wasm/integration-tests/live_integration.mjs::phaseDeploy.
            console.time(`[chip:deploy] buildDeployBundle attempt#${parentAttempt} (wasm)`);
            const artifactsRaw = await wasm.buildDeployBundle(params, parent, synPk);
            console.timeEnd(`[chip:deploy] buildDeployBundle attempt#${parentAttempt} (wasm)`);
            const candidate = (
              artifactsRaw instanceof Map
                ? Object.fromEntries(artifactsRaw)
                : artifactsRaw
            ) as {
              coinSpendsBytes: Uint8Array;
              launcherIdHex: string;
              configJson: string;
              eveSingletonCoinIdHex: string;
            };
            if (!candidate?.coinSpendsBytes) {
              throw new Error(
                "buildDeployBundle returned no coin_spends_bytes — wasm/JS shape mismatch"
              );
            }

            setStatus("Awaiting wallet signature…");
            const wcSpends = JSON.parse(
              wasm.coinSpendsBytesToWalletJson(candidate.coinSpendsBytes)
            ) as WalletConnectCoinSpend[];
            console.time(`[chip:deploy] signCoinSpends attempt#${parentAttempt} (Sage — approval modal) 🚦`);
            const signed = await walletConnect.signCoinSpends(
              wcSpends,
              false,
              false
            );
            console.timeEnd(`[chip:deploy] signCoinSpends attempt#${parentAttempt} (Sage — approval modal) 🚦`);
            if (!signed) throw new Error("Wallet declined to sign");

            setStatus("Assembling bundle…");
            const sigBytes = hexToBytes(signed);
            if (sigBytes.length !== 96) {
              throw new Error(
                `Wallet returned a ${sigBytes.length}-byte signature; ` +
                  `expected 96 bytes (G2 element). ` +
                  `Retry from a fresh launcher parent coin if signing failed.`
              );
            }
            console.time(`[chip:deploy] assembleSpendBundle attempt#${parentAttempt} (wasm)`);
            const bundleBytes = wasm.assembleSpendBundle(
              candidate.coinSpendsBytes,
              sigBytes
            );
            console.timeEnd(`[chip:deploy] assembleSpendBundle attempt#${parentAttempt} (wasm)`);
            setStatus("Verifying bundle locally…");
            console.time(`[chip:deploy] verifyBundleLocally attempt#${parentAttempt} (wasm)`);
            wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
            console.timeEnd(`[chip:deploy] verifyBundleLocally attempt#${parentAttempt} (wasm)`);

            const walletBundle = JSON.parse(
              wasm.bundleBytesToWalletJson(bundleBytes)
            ) as SpendBundleJson;
            setStatus(
              parentAttempt === 0
                ? "Submitting bundle to mempool (coinset)…"
                : `Submitting bundle (alternate parent ${parentAttempt + 1}/${maxParentAttempts})…`
            );

            try {
              console.time(`[chip:deploy] pushTx attempt#${parentAttempt} (coinset RPC)`);
              await pushTx(walletBundle);
              console.timeEnd(`[chip:deploy] pushTx attempt#${parentAttempt} (coinset RPC)`);
              artifacts = candidate;
              break;
            } catch (e: unknown) {
              const lastTry = parentAttempt >= maxParentAttempts - 1;
              if (!isConsensusRetriablePushError(e) || lastTry) {
                throw e;
              }
              console.warn("[deploy] push_tx rejected; will try another coin:", e);
            }
          }

          if (!artifacts) {
            throw new Error("Deploy submitted no bundle (unexpected)");
          }

          setStatus("Confirming launcher on-chain via coinset…");

          const launcherName = artifacts.launcherIdHex.trim().startsWith("0x")
            ? artifacts.launcherIdHex.trim()
            : "0x" + artifacts.launcherIdHex.trim();
          setDeployAwait({
            title: "Confirming deployment",
            detail:
              "Spend bundle pushed via coinset. Waiting until coinset indexes the launcher coin (usually ≤1 mainnet block, ~52s).",
          });
          const launcherOk = await pollUntilConfirmed({
            predicate: async () => !!(await coinRecordByName(launcherName)),
            pollMs: 6000,
            timeoutMs: 5 * 60 * 1000,
            onAttempt: ({ attempt, elapsedMs }) => {
              setDeployAwait({
                title: "Confirming deployment",
                detail:
                  "Spend bundle pushed via coinset. Waiting until coinset indexes the launcher coin.\n\n" +
                  `Poll #${attempt} — ${Math.round(
                    elapsedMs / 1000
                  )}s elapsed (~52s/block on mainnet).`,
              });
            },
          });
          setDeployAwait(null);
          if (launcherOk) {
            setStatus("Launcher confirmed on-chain.");
          } else {
            setStatus(
              "Launcher not indexed after 5 min — reject details from `/push_tx` were shown earlier if applicable; Refresh on the election page."
            );
          }

          // ---- 8. Persist locally + seed election tab session bootstrap + redirect.
          const labelStored =
            label.trim() || `Election ${artifacts.launcherIdHex.slice(2, 10)}`;
          const row = {
            launcherIdHex: artifacts.launcherIdHex,
            configJson: artifacts.configJson,
            label: labelStored,
            addedAt: new Date().toISOString(),
            eveCoinIdHex: artifacts.eveSingletonCoinIdHex,
            provingKeyBase64: btoa(
              String.fromCharCode(...ceremony.provingKeyBytes)
            ),
          };
          upsertElection(row);
          writeElectionBootstrap({
            launcherIdHex: row.launcherIdHex,
            configJson: row.configJson,
            label: row.label,
            addedAt: row.addedAt,
            eveCoinIdHex: row.eveCoinIdHex,
            provingKeyBase64: row.provingKeyBase64,
            // Persist the deploy peak so /election's chain-walking
            // wasm calls (`readElectionSingletonState`,
            // `cast_vote`, `register`, `release`,
            // `createBallotBundle`, `launchBallotBundle`) can predict
            // the right eve singleton ph. The SDK's ElectionConfig
            // doesn't carry this — it's an external constant the
            // launcher walker MUST receive.
            electionStartHeight: peak,
          });

          setStatus("Deployed! Redirecting…");
          router.push(
            `/election/?id=${artifacts.launcherIdHex.replace(/^0x/, "")}`
          );
        } catch (err: any) {
          console.error(err);
          setStatus(`Error: ${err?.message ?? err}`);
        } finally {
          setBusy(false);
        }
      };

      if (!address) {
        return (
          <main className="mx-auto max-w-3xl px-4 py-12 sm:px-6 lg:px-8">
            <Link
              href="/"
              className="text-sm text-[var(--color-muted)] transition-colors hover:text-[var(--color-foreground)]"
            >
              ← Back
            </Link>
            <div className="card-elev mt-5 flex flex-col items-center gap-3 text-center">
              <div
                aria-hidden
                className="grid h-12 w-12 place-items-center rounded-full border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 text-xl text-[var(--color-accent)]"
              >
                ◈
              </div>
              <h2 className="text-lg font-semibold">Connect your wallet</h2>
              <p className="max-w-md text-sm leading-relaxed text-[var(--color-muted-strong)]">
                Deploying an election spends 1 mojo XCH (the launcher coin) plus
                tx fees. Connect Sage Wallet — top right — to continue.
              </p>
            </div>
          </main>
        );
      }

      return (
        <>
          {deployAwait && (
            <BroadcastWaitModal
              title={deployAwait.title}
              detail={deployAwait.detail}
              titleId="deploy-await-title"
            />
          )}
          <main className="fade-up mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
            <Link
              href="/"
              className="inline-flex items-center gap-1 text-sm text-[var(--color-muted)] transition-colors hover:text-[var(--color-foreground)]"
            >
              ← Back
            </Link>
          <header className="mb-8 mt-5">
            <p className="eyebrow mb-2">Deploy</p>
            <h1 className="text-3xl font-medium tracking-tight">New election</h1>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--color-muted-strong)]">
              Deploy a new Election Singleton on Chia. Only the parameters
              below are configurable; the trusted setup runs in your browser.
            </p>
          </header>

          <form onSubmit={handleDeploy} className="card-elev space-y-5">
            <Field
              label="Label (optional)"
              hint="Shown on your local list. Not stored on-chain."
            >
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className="input"
                placeholder="DAO budget vote — Q3"
                disabled={busy}
              />
            </Field>

            <Field
              label="CAT TAIL (asset id)"
              hint="32-byte hex. Defaults to mainnet DIG."
            >
              <input
                type="text"
                value={catTailHex}
                onChange={(e) =>
                  setCatTailHex(e.target.value.replace(/^0x/, ""))
                }
                pattern="^[0-9a-fA-F]{64}$"
                className="input mono"
                required
                disabled={busy}
              />
            </Field>

            {/* Collateral per voter is hard-coded to 1 CAT mojo in the
                registration_coin puzzle — no input. Election length /
                finalize quorum are PER-BALLOT in
                CHIP rev 2026-05-02 — set when minting a ballot from
                /election → "Mint a new ballot", not at deploy. */}

            <Field
              label="Verification key (hex)"
              hint="Paste the VK from /ceremony's click-to-copy panel after the on-chain ceremony's threshold is met. Leave blank to fall back to a single-participant test-mode trusted setup (unsafe for production — anyone with the entropy can forge proofs)."
            >
              <textarea
                value={vkHex}
                onChange={(e) =>
                  setVkHex(e.target.value.replace(/^0x/, "").trim())
                }
                className="input mono"
                placeholder="1152 hex chars (576 bytes) — paste from /ceremony"
                rows={4}
                disabled={busy}
                style={{ wordBreak: "break-all", fontSize: "0.75em" }}
              />
              {vkHex.trim().length > 0 ? (
                <p className="mt-1 text-xs text-[var(--color-success)]">
                  ✓ {vkHex.trim().length / 2} bytes — will deploy with this VK
                  {vkHex.trim().length === 1152 ? " (canonical Groth16 layout ✓)" : ""}
                </p>
              ) : (
                <p className="mt-1 text-xs text-[var(--color-muted)]">
                  No VK supplied — deploy will run the in-browser
                  single-participant trusted setup (TEST MODE).
                </p>
              )}
            </Field>

            {/* Voter choices live on the BALLOT, not the election —
                operators set them when minting a ballot via
                /election → "Mint a new ballot". */}

            <Field
              label="Linked ceremony (optional)"
              hint="Launcher id of a finalized ceremony. When set, the deploy bundle co-spends the ceremony's voucher coin and asserts its canonical announcement, binding this election to (vk_hash, max_voters, ceremony_launcher_id). Leave blank for an unlinked legacy deploy."
            >
              <input
                type="text"
                value={ceremonyIdHex}
                onChange={(e) =>
                  setCeremonyIdHex(e.target.value.trim())
                }
                className="input mono"
                placeholder="0x… (32-byte hex)"
                disabled={busy}
              />
              {ceremonyIdHex.trim().length === 0 ? (
                <p className="mt-1 text-xs text-[var(--color-muted)]">
                  No ceremony selected — deploy will use the legacy
                  unlinked path.
                </p>
              ) : voucher.kind === "looking" ? (
                <p className="mt-1 text-xs text-[var(--color-muted)]">
                  Discovering voucher coin on chain…
                </p>
              ) : voucher.kind === "found" ? (
                <p className="mt-1 text-xs text-[var(--color-success)]">
                  ✓ Linked to ceremony{" "}
                  {voucher.launcherIdHex.slice(0, 18)}… (max_voters={" "}
                  {voucher.maxVoters}, vk_hash={voucher.vkHashHex.slice(0, 18)}…)
                </p>
              ) : voucher.kind === "not_found" ? (
                <p className="mt-1 text-xs text-[var(--color-danger)]">
                  ✗ {voucher.reason}
                </p>
              ) : voucher.kind === "error" ? (
                <p className="mt-1 text-xs text-[var(--color-danger)]">
                  ✗ Voucher discovery failed: {voucher.message}
                </p>
              ) : null}
            </Field>

            <Field
              label="Lock vote mode for all ballots?"
              hint="Default 'No lock' lets each ballot pick its own mode. Pick 'Free' to force every ballot of this election into Mode1Free (any 32-byte vote_data). Pick 'Restricted' to force every ballot into a fixed sorted-options merkle root — the dApp will sha256 each label and merkle-root them."
            >
              <div className="flex flex-wrap gap-2 text-sm">
                {(
                  [
                    ["none", "No lock (default)"],
                    ["free", "Free"],
                    ["restricted", "Restricted"],
                  ] as const
                ).map(([value, text]) => {
                  const selected = voteModeLockChoice === value;
                  return (
                    <label
                      key={value}
                      className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${
                        selected
                          ? "border-[var(--color-accent)]/55 bg-[var(--color-accent)]/[0.08] text-[var(--color-foreground)]"
                          : "border-[var(--color-border)] text-[var(--color-muted-strong)] hover:border-[var(--color-border-strong)]"
                      } ${busy ? "cursor-not-allowed opacity-60" : ""}`}
                    >
                      <input
                        type="radio"
                        name="voteModeLock"
                        value={value}
                        checked={selected}
                        onChange={() => setVoteModeLockChoice(value)}
                        disabled={busy}
                        className="accent-[var(--color-accent)]"
                      />
                      {text}
                    </label>
                  );
                })}
              </div>
              {voteModeLockChoice === "restricted" ? (
                <textarea
                  value={voteOptionLabelsText}
                  onChange={(e) => setVoteOptionLabelsText(e.target.value)}
                  className="input mono mt-2"
                  placeholder={"One option per line\n(e.g. Yes / No / Abstain)"}
                  rows={4}
                  disabled={busy}
                />
              ) : null}
              {voteModeLockChoice === "none" ? (
                <p className="mt-1 text-xs text-[var(--color-muted)]">
                  Per-ballot mode — each ballot picks Free or Restricted at
                  mint time.
                </p>
              ) : voteModeLock.kind === "computing" ? (
                <p className="mt-1 text-xs text-[var(--color-muted)]">
                  Hashing labels…
                </p>
              ) : voteModeLock.kind === "ready" && voteModeLockChoice === "free" ? (
                <p className="mt-1 text-xs text-[var(--color-success)]">
                  ✓ Locked to Mode1Free — every ballot of this election
                  must use vote_options_root = 0x00…00
                </p>
              ) : voteModeLock.kind === "ready" ? (
                <p className="mt-1 text-xs text-[var(--color-success)]">
                  ✓ Locked to Mode2Restricted ({voteModeLock.labels.length}{" "}
                  options): root={voteModeLock.voteModeLockHex.slice(0, 18)}…
                </p>
              ) : voteModeLock.kind === "error" ? (
                <p className="mt-1 text-xs text-[var(--color-danger)]">
                  ✗ {voteModeLock.message}
                </p>
              ) : null}
            </Field>

            <button
              type="submit"
              className="btn-primary w-full text-base"
              disabled={
                busy ||
                (ceremonyIdHex.trim().length > 0 && voucher.kind !== "found") ||
                (voteModeLockChoice !== "none" && voteModeLock.kind !== "ready")
              }
            >
              {busy
                ? status
                : ceremonyIdHex.trim().length > 0 && voucher.kind === "found"
                  ? "Deploy election (linked to ceremony)"
                  : ceremonyIdHex.trim().length > 0
                    ? "Voucher unresolved — fix ceremony selection"
                    : vkHex.trim().length > 0
                      ? "Deploy election with pasted VK"
                      : "Deploy election (TEST MODE — single-participant setup)"}
            </button>
            <div
              role="status"
              aria-live="polite"
              className={`text-center text-xs ${
                status.startsWith("Error")
                  ? "text-[var(--color-danger)]"
                  : busy
                    ? "text-[var(--color-accent)]"
                    : "text-[var(--color-muted)]"
              }`}
            >
              <span className="text-[var(--color-muted)]">Status:</span> {status}
            </div>
          </form>

          {/*
            Two-step ceremony flow: the wired-up "Deploy via on-chain
            ceremony" path replaces `runSingleParticipantCeremony` with
            a multi-participant Groth16 setup driven by the Ceremony
            Singleton (Phase 4 sub-step 7 surfaces the entry; Phase 5
            sub-step 4 wires the bundle build). For now this is an
            opt-in link to /ceremony — the existing single-participant
            button stays the default until the ceremony close + VK
            derivation flow ships.
          */}
          <Footer />
        </main>
        </>
      );
    };
  },
  {
    ssr: false,
    loading: () => (
      <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
        <div className="skeleton h-[28rem]" />
      </div>
    ),
  }
);

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium">{label}</label>
      {children}
      <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-muted)]">
        {hint}
      </p>
    </div>
  );
}

function CeremonyReadinessChecker() {
  const [launcherIdHex, setLauncherIdHex] = useState("");
  const [vkSeedHex, setVkSeedHex] = useState("");
  const [minParticipants, setMinParticipants] = useState<number>(1);
  const [status, setStatus] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const onCheck = async () => {
    setBusy(true);
    setStatus("Walking chain…");
    try {
      const {
        listCeremonyContributions,
        validateCeremonyContributions,
        deriveVkFromCeremony,
      } = await import("../lib/sdk");
      const records = await listCeremonyContributions(
        launcherIdHex.trim().startsWith("0x")
          ? launcherIdHex.trim()
          : `0x${launcherIdHex.trim()}`
      );
      setStatus(`Found ${records.length} contribution(s) on chain. Validating…`);
      const seedHex = vkSeedHex.trim().startsWith("0x")
        ? vkSeedHex.trim()
        : `0x${vkSeedHex.trim()}`;
      const result = await validateCeremonyContributions(
        records,
        seedHex,
        minParticipants
      );
      setStatus(
        `✓ Lineage + threshold OK (${result.count} contribs at min=${minParticipants}). Deriving VK…`
      );
      const vk = (await deriveVkFromCeremony(
        records,
        seedHex,
        minParticipants
      )) as { rawBytes?: Uint8Array; raw_bytes?: Uint8Array };
      const vkBytes = (vk.rawBytes ?? vk.raw_bytes ?? new Uint8Array()) as
        | Uint8Array
        | number[];
      const vkLen = (vkBytes as Uint8Array).length ?? 0;
      setStatus(
        `✓ Ceremony VK derived (${vkLen} bytes). Use this VK to deploy an election: paste into the form above's CAT TAIL placeholder logic, or extend the deploy form to take a launcher id directly (next iteration).`
      );
    } catch (e) {
      setStatus(
        `✗ Not ready: ${e instanceof Error ? e.message : String(e)}`
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card-elev mt-6 p-4">
      <h2 className="text-lg font-semibold mb-2">
        Step B: check if a ceremony is ready
      </h2>
      <p className="text-sm text-[var(--color-muted)] mb-3">
        Paste a ceremony launcher id + the deployer&apos;s vk_seed to chain-walk
        contributions and confirm the threshold is met before deploying an
        election with the derived VK.
      </p>
      <div className="space-y-2">
        <input
          type="text"
          placeholder="Ceremony launcher id (32-byte hex)"
          value={launcherIdHex}
          onChange={(e) => setLauncherIdHex(e.target.value)}
          className="input mono w-full"
          disabled={busy}
        />
        <input
          type="text"
          placeholder="vk_seed (32-byte hex)"
          value={vkSeedHex}
          onChange={(e) => setVkSeedHex(e.target.value)}
          className="input mono w-full"
          disabled={busy}
        />
        <input
          type="number"
          placeholder="min_participants"
          value={minParticipants}
          min={1}
          onChange={(e) =>
            setMinParticipants(Math.max(1, parseInt(e.target.value) || 1))
          }
          className="input w-full"
          disabled={busy}
        />
        <button
          type="button"
          onClick={onCheck}
          disabled={busy || !launcherIdHex || !vkSeedHex}
          className="btn-secondary w-full"
        >
          {busy ? "Checking…" : "Check readiness"}
        </button>
        {status ? (
          <div className="text-sm" style={{ marginTop: "0.5rem" }}>
            {status}
          </div>
        ) : null}
      </div>
    </div>
  );
}
