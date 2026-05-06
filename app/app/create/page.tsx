"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
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
import { upsertElection, makeChoices } from "../lib/elections";
import { writeElectionBootstrap } from "../lib/electionBootstrap";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { findSyntheticPkMatchingCoinPuzzleHashHex } from "../lib/sageSyntheticKey";
import { parseCat } from "../lib/units";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { pollUntilConfirmed } from "../lib/pollUntil";
import { getWasm } from "../lib/sdk";

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
      const { address } = useAppSelector((s) => s.wallet);

      const [label, setLabel] = useState("");
      const [catTailHex, setCatTailHex] = useState(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
      );
      const [collateralAmount, setCollateralAmount] = useState("1.000");
      /** ~1 calendar day at Chia target rate (32 blocks / 10 min). */
      const [electionLengthBlocks, setElectionLengthBlocks] = useState("4608");
      /** Weighted quorum N/D (strict tally * D > total_weight * N). Default strict majority (1/2). */
      const [voteThresholdNum, setVoteThresholdNum] = useState("1");
      const [voteThresholdDen, setVoteThresholdDen] = useState("2");
      const [status, setStatus] = useState<string>("Ready");
      const [busy, setBusy] = useState(false);
      const [deployAwait, setDeployAwait] = useState<null | {
        title: string;
        detail: string;
      }>(null);

      // Voter choices — at least 2 required. Defaults to a yes/no
      // ballot. The on-chain vote_data is `sha256("vote:" + label)`
      // (see `makeChoices`).
      const [choiceLabels, setChoiceLabels] = useState<string[]>([
        "Yes",
        "No",
      ]);
      const setChoiceAt = (i: number, v: string) =>
        setChoiceLabels((prev) => prev.map((p, idx) => (idx === i ? v : p)));
      const addChoice = () =>
        setChoiceLabels((prev) => [...prev, ""]);
      const removeChoice = (i: number) =>
        setChoiceLabels((prev) =>
          prev.length > 2 ? prev.filter((_, idx) => idx !== i) : prev
        );

      const handleDeploy = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!address) return;
        setBusy(true);
        try {
          // ---- 1. Run a single-participant trusted-setup ceremony.
          setStatus("Running trusted-setup ceremony…");
          const ceremony = (await wasm.runSingleParticipantCeremony()) as {
            verificationKeyHex: string;
            provingKeyBytes: Uint8Array;
          };

          // ---- 2. Resolve XCH puzzle hash (parent coins refetched each attempt below).
          setStatus("Resolving puzzle hash…");
          const xchPh = await puzzleHashHexFromWalletAddress(address);
          if (!xchPh) throw new Error("Could not decode wallet address");

          // ---- 3. Validate amounts + choices.
          const collMojos = parseCat(collateralAmount);
          if (collMojos === null || collMojos <= 0n) throw new Error("Bad collateral amount");

          const cleanChoiceLabels = choiceLabels
            .map((l) => l.trim())
            .filter((l) => l.length > 0);
          if (cleanChoiceLabels.length < 2) {
            throw new Error("Need at least two voter choices.");
          }
          if (new Set(cleanChoiceLabels).size !== cleanChoiceLabels.length) {
            throw new Error(
              "Voter choices must be unique (two choices with the " +
                "same label would hash to the same vote_data)."
            );
          }
          const choices = await makeChoices(cleanChoiceLabels);

          const peak = await peakHeight();
          if (peak === null) {
            throw new Error(
              "Could not read chain peak (get_blockchain_state). Try again when the network is reachable."
            );
          }

          const len = Number(electionLengthBlocks);
          const vtn = Number.parseInt(voteThresholdNum.trim(), 10);
          const vtd = Number.parseInt(voteThresholdDen.trim(), 10);
          if (!Number.isFinite(len) || len < 1) {
            throw new Error("Election length must be at least one block.");
          }
          if (!Number.isFinite(vtn) || !Number.isFinite(vtd) || vtn < 1 || vtd < 1) {
            throw new Error(
              "Vote quorum numerator and denominator must be integers ≥ 1."
            );
          }

          const params = {
            verificationKeyHex: ceremony.verificationKeyHex,
            catTailHashHex: catTailHex,
            collateralAmount: Number(collMojos),
            electionLengthBlocks: len,
            electionStartHeight: peak,
            voteThresholdNum: vtn,
            voteThresholdDen: vtd,
            label: label.trim() || null,
          };

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
          for (let parentAttempt = 0; parentAttempt < maxParentAttempts; parentAttempt++) {
            const fresh = (
              await coinRecordsByPuzzleHash(xchPh, false)
            ).filter((c) => c.amount >= 2);
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

            const synPk = await findSyntheticPkMatchingCoinPuzzleHashHex(
              parent.puzzleHash
            );
            if (!synPk) {
              throw new Error(
                "Could not find a synthetic key matching the parent coin"
              );
            }

            setStatus("Building deploy spend bundle…");
            // serde_wasm_bindgen + #[serde(with = "serde_bytes")] emits
            // a JS Map (not a plain object) for the artifacts struct.
            // Convert via Object.fromEntries when that happens —
            // mirrors the dance in
            // wasm/integration-tests/live_integration.mjs::phaseDeploy.
            const artifactsRaw = await wasm.buildDeployBundle(params, parent, synPk);
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
            const signed = await walletConnect.signCoinSpends(
              wcSpends,
              false,
              false
            );
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
            const bundleBytes = wasm.assembleSpendBundle(
              candidate.coinSpendsBytes,
              sigBytes
            );
            setStatus("Verifying bundle locally…");
            wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);

            const walletBundle = JSON.parse(
              wasm.bundleBytesToWalletJson(bundleBytes)
            ) as SpendBundleJson;
            setStatus(
              parentAttempt === 0
                ? "Submitting bundle to mempool (coinset)…"
                : `Submitting bundle (alternate parent ${parentAttempt + 1}/${maxParentAttempts})…`
            );

            try {
              await pushTx(walletBundle);
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
            choices,
          };
          upsertElection(row);
          writeElectionBootstrap({
            launcherIdHex: row.launcherIdHex,
            configJson: row.configJson,
            label: row.label,
            addedAt: row.addedAt,
            eveCoinIdHex: row.eveCoinIdHex,
            provingKeyBase64: row.provingKeyBase64,
            choices: row.choices,
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
          <main className="max-w-3xl mx-auto px-4 py-12">
            <div className="card-elev text-center">
              <h2 className="text-lg font-semibold">Connect your wallet</h2>
              <p className="text-[var(--color-muted)] mt-2">
                Deploying an election spends 1 mojo XCH (the launcher coin) +
                tx fees. Connect Sage Wallet to continue.
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
          <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Link href="/" className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)]">
              ← back
            </Link>
          <header className="mt-4 mb-8">
            <h1 className="text-3xl font-bold">New election</h1>
            <p className="text-[var(--color-muted)] mt-2">
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

            <Field
              label="Collateral per voter (CAT)"
              hint="Locked at registration; returned at release. 1 DIG = 1.000."
            >
              <input
                type="number"
                value={collateralAmount}
                onChange={(e) => setCollateralAmount(e.target.value)}
                step="0.001"
                min="0.001"
                className="input mono"
                required
                disabled={busy}
              />
            </Field>

            <Field
              label="Election length (blocks)"
              hint="Time-lock between deploy and earliest finalize. Default ~1 day (4608 blocks at 32 blocks/10 min)."
            >
              <input
                type="number"
                value={electionLengthBlocks}
                onChange={(e) => setElectionLengthBlocks(e.target.value)}
                step="1"
                min="1"
                className="input mono"
                required
                disabled={busy}
              />
            </Field>

            <Field
              label="Finalize quorum (weighted N / D)"
              hint={
                'On-chain strict rule tally × D > total_registration_weight × N. Majority-by-stake is typically 1/2.'
              }
            >
              <div className="flex gap-3 items-center">
                <input
                  type="number"
                  value={voteThresholdNum}
                  onChange={(e) => setVoteThresholdNum(e.target.value)}
                  step="1"
                  min="1"
                  className="input mono flex-1"
                  title="Numerator N"
                  required
                  disabled={busy}
                />
                <span className="text-[var(--color-muted)]">/</span>
                <input
                  type="number"
                  value={voteThresholdDen}
                  onChange={(e) => setVoteThresholdDen(e.target.value)}
                  step="1"
                  min="1"
                  className="input mono flex-1"
                  title="Denominator D"
                  required
                  disabled={busy}
                />
              </div>
            </Field>

            <Field
              label="Voter choices"
              hint={
                "At least two. Each voter picks exactly one. " +
                "vote_data on-chain is sha256(\"vote:\" + label) — share " +
                "the same labels with every voter so the eventual outcome decodes."
              }
            >
              <div className="space-y-2">
                {choiceLabels.map((c, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-xs text-[var(--color-muted)] w-6 text-right">
                      #{i + 1}
                    </span>
                    <input
                      type="text"
                      value={c}
                      onChange={(e) => setChoiceAt(i, e.target.value)}
                      className="input flex-1"
                      placeholder={i === 0 ? "Yes" : i === 1 ? "No" : "Option"}
                      disabled={busy}
                    />
                    <button
                      type="button"
                      onClick={() => removeChoice(i)}
                      disabled={busy || choiceLabels.length <= 2}
                      className="text-[var(--color-muted)] hover:text-[var(--color-danger)]
                                 disabled:opacity-40 disabled:cursor-not-allowed text-xl px-2"
                      title={
                        choiceLabels.length <= 2
                          ? "At least two choices required"
                          : "Remove this choice"
                      }
                    >
                      ×
                    </button>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={addChoice}
                  disabled={busy}
                  className="btn-secondary text-sm"
                >
                  + Add choice
                </button>
              </div>
            </Field>

            <button
              type="submit"
              className="btn-primary w-full text-base"
              disabled={busy}
            >
              {busy ? status : "Deploy election"}
            </button>
            <div className="text-xs text-[var(--color-muted)] text-center">
              Status: {status}
            </div>
          </form>

          <Footer />
        </main>
        </>
      );
    };
  },
  { ssr: false, loading: () => <div className="card animate-pulse h-96 m-8" /> }
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
      <label className="block text-sm font-medium mb-1">{label}</label>
      {children}
      <p className="text-xs text-[var(--color-muted)] mt-1">{hint}</p>
    </div>
  );
}
