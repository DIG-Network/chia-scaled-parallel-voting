"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { Suspense, useState } from "react";
import { useRouter } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import walletConnect from "../lib/walletConnectInstance";
import type { WalletConnectCoinSpend } from "../lib/WalletConnect";
import {
  coinRecordByName,
  isConsensusRetriablePushError,
  peakHeight,
  pushTx,
} from "../lib/coinset";
import type { SpendBundleJson } from "../lib/coinset";
import Footer from "../components/Footer";
import { BroadcastWaitModal } from "../components/BroadcastWaitModal";
import { pollUntilConfirmed } from "../lib/pollUntil";
import { getWasm } from "../lib/sdk";
import { writeCeremonyBootstrap } from "../lib/ceremonyBootstrap";

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function coinDedupeKey(c: { parentCoinInfo: string; puzzleHash: string; amount: number }): string {
  return `${c.parentCoinInfo}:${c.puzzleHash}:${c.amount}`;
}

const CreateCeremonyInner = dynamic(
  async function DynamicElem() {
    const wasm = await getWasm();
    return function CreateCeremonyInner() {
      const router = useRouter();
      const { address } = useAppSelector((s) => s.wallet);

      const [label, setLabel] = useState("");
      const [startBlockHeight, setStartBlockHeight] = useState<number>(0);
      const [ceremonyLengthBlocks, setCeremonyLengthBlocks] =
        useState<number>(1000);
      const [minParticipants, setMinParticipants] = useState<number>(2);
      const [maxVoters, setMaxVoters] = useState<number>(20_000);
      const [vkSeedHex, setVkSeedHex] = useState(
        "0000000000000000000000000000000000000000000000000000000000000001"
      );
      const [status, setStatus] = useState("Ready");
      const [busy, setBusy] = useState(false);
      const [deployAwait, setDeployAwait] = useState<null | {
        title: string;
        detail: string;
      }>(null);

      const handleDeploy = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!address) return;
        setBusy(true);
        try {
          // ---- 1. Resolve current peak (lets the user use 0 = "from now").
          const peak = await peakHeight();
          if (peak === null) {
            throw new Error("Could not read chain peak; try again later");
          }
          // If user left start at 0, default to current peak (start now).
          const effectiveStart =
            startBlockHeight === 0 ? peak : startBlockHeight;

          const params = {
            startBlockHeight: effectiveStart,
            ceremonyLengthBlocks,
            minParticipants,
            maxVoters,
            vkSeedHex: vkSeedHex.trim().replace(/^0x/, ""),
            label: label.trim() || null,
          };

          // ---- 2–4. Sage funder discovery + bundle build + sign + push,
          // mirroring /create's election deploy flow but calling
          // `wasm.deployCeremonyBundle` instead of `wasm.buildDeployBundle`.
          const maxParentAttempts = 5;
          const triedParents = new Set<string>();
          let result: {
            coinSpendsBytes: Uint8Array;
            launcherIdHex: string;
          } | null = null;

          const { listXchCoinsWithKeys } = await import("../lib/sageAssetCoins");
          for (
            let parentAttempt = 0;
            parentAttempt < maxParentAttempts;
            parentAttempt++
          ) {
            setStatus(
              parentAttempt === 0
                ? "Discovering funder coins via Sage…"
                : `Retrying with another parent coin (${parentAttempt + 1}/${maxParentAttempts})…`
            );
            const sageCoins = await listXchCoinsWithKeys({
              minAmount: 2,
              includeLocked: false,
              limit: 200,
            });
            const fresh = sageCoins
              .map((s) => ({
                parentCoinInfo: s.coin.parent_coin_info,
                puzzleHash: s.coin.puzzle_hash,
                amount: s.coin.amount,
                spentHeight: 0,
                confirmedHeight: 0,
                syntheticPkHex: s.syntheticPkHex,
              }))
              .filter((c) => c.amount >= 2);
            fresh.sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
            const parent =
              fresh.find((c) => !triedParents.has(coinDedupeKey(c))) ?? null;
            if (!parent) {
              throw new Error(
                triedParents.size === 0
                  ? "No XCH coin available in your wallet (need ≥2 mojos)."
                  : `Tried every usable XCH coin (${triedParents.size}). Wait for mempool to settle, then retry.`
              );
            }
            triedParents.add(coinDedupeKey(parent));

            setStatus("Building ceremony deploy bundle…");
            const artifactsRaw = await wasm.deployCeremonyBundle(
              params,
              parent,
              parent.syntheticPkHex
            );
            const candidate = (
              artifactsRaw instanceof Map
                ? Object.fromEntries(artifactsRaw)
                : artifactsRaw
            ) as { coinSpendsBytes: Uint8Array; launcherIdHex: string };
            if (!candidate?.coinSpendsBytes) {
              throw new Error("deployCeremonyBundle returned no coin_spends_bytes");
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

            setStatus("Assembling and verifying bundle…");
            const sigBytes = hexToBytes(signed);
            if (sigBytes.length !== 96) {
              throw new Error(
                `Wallet returned a ${sigBytes.length}-byte signature; expected 96 (BLS G2)`
              );
            }
            const bundleBytes = wasm.assembleSpendBundle(
              candidate.coinSpendsBytes,
              sigBytes
            );
            wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);

            const walletBundle = JSON.parse(
              wasm.bundleBytesToWalletJson(bundleBytes)
            ) as SpendBundleJson;
            setStatus("Submitting bundle to mempool (coinset)…");
            try {
              await pushTx(walletBundle);
              result = candidate;
              break;
            } catch (e: unknown) {
              const lastTry = parentAttempt >= maxParentAttempts - 1;
              if (!isConsensusRetriablePushError(e) || lastTry) throw e;
              console.warn("[ceremony-deploy] push_tx rejected; retrying:", e);
            }
          }

          if (!result) throw new Error("Ceremony deploy submitted no bundle");

          // ---- 5. Wait for the launcher to confirm on chain.
          setDeployAwait({
            title: "Confirming ceremony deploy…",
            detail: `launcher_id = ${result.launcherIdHex.slice(0, 18)}…`,
          });
          await pollUntilConfirmed({
            predicate: async () => {
              const rec = await coinRecordByName(result!.launcherIdHex);
              return rec != null && rec.confirmedHeight > 0;
            },
            timeoutMs: 300_000,
          });

          // ---- 6. Persist bootstrap to sessionStorage so /ceremony +
          // /ceremonies can reload it without re-typing params.
          writeCeremonyBootstrap({
            launcherIdHex: result.launcherIdHex,
            startBlockHeight: effectiveStart,
            ceremonyLengthBlocks,
            minParticipants,
            maxVoters: params.maxVoters,
            vkSeedHex: params.vkSeedHex,
            label: params.label,
          });
          setDeployAwait(null);
          setStatus("Deployed! Redirecting to /ceremony…");
          router.push(
            `/ceremony?id=${result.launcherIdHex.replace(/^0x/, "")}`
          );
        } catch (e: unknown) {
          setDeployAwait(null);
          setStatus(`Failed: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
          setBusy(false);
        }
      };

      if (!address) {
        return (
          <main className="mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
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
                Deploying a ceremony spends 1 mojo XCH (the launcher) plus tx
                fees. Connect Sage Wallet — top right — to continue.
              </p>
            </div>
            <Footer />
          </main>
        );
      }

      return (
        <>
          {deployAwait && (
            <BroadcastWaitModal
              title={deployAwait.title}
              detail={deployAwait.detail}
              titleId="ceremony-deploy-await-title"
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
              <h1 className="text-3xl font-medium tracking-tight">
                New ceremony
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--color-muted-strong)]">
                Deploy a new on-chain Groth16 trusted-setup ceremony. Anyone can
                contribute during the time window. Once the threshold is met,
                /ceremony will surface a derived VK ready to paste into{" "}
                <Link
                  href="/create"
                  className="text-[var(--color-accent)] hover:underline"
                >
                  New Election
                </Link>
                .
              </p>
            </header>

            <form onSubmit={handleDeploy} className="card-elev space-y-5">
              <Field
                label="Label (optional)"
                hint="Shown on /ceremonies. Not stored on-chain."
              >
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  className="input"
                  placeholder="DAO budget vote — Q3 ceremony"
                  disabled={busy}
                />
              </Field>

              <Field
                label="Start block height"
                hint="Earliest block at which contributions are accepted. 0 = use current peak (start immediately)."
              >
                <input
                  type="number"
                  min={0}
                  value={startBlockHeight}
                  onChange={(e) =>
                    setStartBlockHeight(
                      Math.max(0, parseInt(e.target.value) || 0)
                    )
                  }
                  className="input"
                  required
                  disabled={busy}
                />
              </Field>

              <Field
                label="Ceremony length (blocks)"
                hint="Window length after start. Mainnet blocks are ~52s. 1000 ≈ 14h."
              >
                <input
                  type="number"
                  min={1}
                  value={ceremonyLengthBlocks}
                  onChange={(e) =>
                    setCeremonyLengthBlocks(
                      Math.max(1, parseInt(e.target.value) || 1)
                    )
                  }
                  className="input"
                  required
                  disabled={busy}
                />
              </Field>

              <Field
                label="Minimum participants"
                hint="VK derivation refuses to produce a usable VK below this. 1-of-N honest assumption: a higher minimum makes the ceremony harder to complete without strengthening soundness. 2-3 is typical."
              >
                <input
                  type="number"
                  min={1}
                  value={minParticipants}
                  onChange={(e) =>
                    setMinParticipants(
                      Math.max(1, parseInt(e.target.value) || 1)
                    )
                  }
                  className="input"
                  required
                  disabled={busy}
                />
              </Field>

              <Field
                label="Max voters"
                hint={`Maximum voters this ceremony's circuit will support. Determines the Groth16 circuit shape (tree_depth = ⌈log₂(maxVoters)⌉ = ${Math.max(1, Math.ceil(Math.log2(Math.max(2, maxVoters))))}). Larger = more expensive contribution; smaller = cheaper but caps every election that uses this VK. Default 20,000.`}
              >
                <input
                  type="number"
                  min={2}
                  max={1_048_576}
                  value={maxVoters}
                  onChange={(e) =>
                    setMaxVoters(
                      Math.max(
                        2,
                        Math.min(1_048_576, parseInt(e.target.value) || 2)
                      )
                    )
                  }
                  className="input"
                  required
                  disabled={busy}
                />
                <p className="text-xs text-[var(--color-muted)] mt-1 mono">
                  tree_depth = {Math.max(1, Math.ceil(Math.log2(Math.max(2, maxVoters))))}
                </p>
              </Field>

              <Field
                label="vk_seed (32-byte hex)"
                hint="Deterministic genesis previous-contribution hash curried into the singleton. Pin one and remember it — required to derive the final VK after the ceremony closes. Click Randomize for a fresh 32-byte value."
              >
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={vkSeedHex}
                    onChange={(e) =>
                      setVkSeedHex(e.target.value.replace(/^0x/, ""))
                    }
                    pattern="^[0-9a-fA-F]{64}$"
                    className="input mono flex-1"
                    required
                    disabled={busy}
                  />
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={busy}
                    onClick={() => {
                      const bytes = new Uint8Array(32);
                      window.crypto.getRandomValues(bytes);
                      const hex = Array.from(bytes)
                        .map((b) => b.toString(16).padStart(2, "0"))
                        .join("");
                      setVkSeedHex(hex);
                    }}
                    title="Generate a random 32-byte vk_seed"
                  >
                    Randomize
                  </button>
                </div>
                {vkSeedHex.length > 0 && !/^[0-9a-fA-F]{64}$/.test(vkSeedHex) ? (
                  <p className="mt-1 text-xs text-[var(--color-warning)]">
                    vk_seed must be exactly 64 hex chars (got {vkSeedHex.length}).
                  </p>
                ) : null}
              </Field>

              <button
                type="submit"
                className="btn-primary w-full text-base"
                disabled={
                  busy ||
                  !/^[0-9a-fA-F]{64}$/.test(vkSeedHex) ||
                  !Number.isInteger(maxVoters) ||
                  maxVoters < 2 ||
                  maxVoters > 1_048_576
                }
                title={
                  /^[0-9a-fA-F]{64}$/.test(vkSeedHex)
                    ? undefined
                    : "vk_seed must be exactly 64 hex chars"
                }
              >
                {busy ? status : "Deploy ceremony"}
              </button>
              <div
                role="status"
                aria-live="polite"
                className={`text-center text-xs ${
                  status.startsWith("Failed")
                    ? "text-[var(--color-danger)]"
                    : busy
                      ? "text-[var(--color-accent)]"
                      : "text-[var(--color-muted)]"
                }`}
              >
                <span className="text-[var(--color-muted)]">Status:</span>{" "}
                {status}
              </div>
            </form>

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
        <div className="skeleton h-[32rem]" />
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

export default function CreateCeremonyPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
          <div className="skeleton h-[32rem]" />
        </div>
      }
    >
      <CreateCeremonyInner />
    </Suspense>
  );
}
