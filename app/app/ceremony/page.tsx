"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import { peakHeight } from "../lib/coinset";
import { truncHex } from "../lib/units";
import {
  listCeremonyContributions,
  deriveVkFromCeremony,
  publicKeyFromSecretKeyBytes,
  signParticipantUnsafe,
  aggregateSignaturesG2,
  findCurrentCeremonySingleton,
  contributeToCeremony,
  recoverCeremonyBootstrap,
  getWasm,
  type CeremonyContributionRecord,
} from "../lib/sdk";
import walletConnect from "../lib/walletConnectInstance";
import type { WalletConnectCoinSpend } from "../lib/WalletConnect";
import {
  coinRecordByName,
  isConsensusRetriablePushError,
  pushTx,
} from "../lib/coinset";
import type { SpendBundleJson } from "../lib/coinset";
import { pollUntilConfirmed } from "../lib/pollUntil";
import Footer from "../components/Footer";
import { HexId } from "../components/HexId";
import {
  readCeremonyBootstrap,
  writeCeremonyBootstrap,
  type CeremonyBootstrap,
} from "../lib/ceremonyBootstrap";

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function coinDedupeKey(c: { parentCoinInfo: string; puzzleHash: string; amount: number }): string {
  return `${c.parentCoinInfo}:${c.puzzleHash}:${c.amount}`;
}

type CeremonyStatus =
  | { kind: "pre-open"; blocksUntilStart: number }
  | { kind: "open"; blocksRemaining: number }
  | { kind: "closed"; blocksOver: number };

function ceremonyStatus(
  bootstrap: CeremonyBootstrap,
  peak: number | null
): CeremonyStatus | null {
  if (peak == null || peak <= 0) return null;
  const start = bootstrap.startBlockHeight;
  const end = start + bootstrap.ceremonyLengthBlocks;
  if (peak < start) {
    return { kind: "pre-open", blocksUntilStart: start - peak };
  }
  if (peak < end) {
    return { kind: "open", blocksRemaining: end - peak };
  }
  return { kind: "closed", blocksOver: peak - end };
}

const CeremonyPageInner = dynamic(
  async function DynamicElem() {
    return function CeremonyPageInner() {
      const search = useSearchParams();
      const { address } = useAppSelector((s) => s.wallet);
      const launcherIdParam = search.get("id") ?? "";
      const launcherId = useMemo(
        () => launcherIdParam.toLowerCase().replace(/^0x/, ""),
        [launcherIdParam]
      );

      const [bootstrap, setBootstrap] = useState<CeremonyBootstrap | null>(
        null
      );
      const [peak, setPeak] = useState<number | null>(null);
      const [bootstrapMissing, setBootstrapMissing] = useState(false);
      const [contributions, setContributions] = useState<
        CeremonyContributionRecord[]
      >([]);
      const [contributionsError, setContributionsError] = useState<string | null>(
        null
      );
      // Live chain-walked Ceremony Singleton tip — surfaces coin id,
      // launcher id, finalize state, vk_hash, marker_root for the IDs
      // panel.
      const [singletonTip, setSingletonTip] = useState<
        import("../lib/sdk").CeremonySingletonTip | null
      >(null);
      const [singletonTipError, setSingletonTipError] = useState<string | null>(
        null
      );
      const [submitStatus, setSubmitStatus] = useState<string | null>(null);
      const [submitError, setSubmitError] = useState<string | null>(null);
      const [submittedMarker, setSubmittedMarker] = useState<string | null>(null);
      const [submitting, setSubmitting] = useState(false);
      const [derivedVkHex, setDerivedVkHex] = useState<string | null>(null);
      const [vkDeriveError, setVkDeriveError] = useState<string | null>(null);
      const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
      // Mouse-entropy capture state. Standard pattern for Groth16
      // ceremonies: collect a stream of (x, y, time_ms) samples from
      // mouse movement over a fixed 60-second window, then hash with
      // crypto.getRandomValues bytes to mix user-supplied + browser-
      // RNG entropy.
      const [collectingEntropy, setCollectingEntropy] = useState<{
        name: string;
        samples: number[];
      } | null>(null);

      // Load bootstrap. Try localStorage first; on miss, fall back
      // to on-chain recovery via the launcher's `key_value_list`
      // (D6). On chain recovery success, also persist back to
      // localStorage so subsequent visits in the same browser are
      // instant. Legacy ceremonies deployed before D6 have an empty
      // launcher memo and will surface the "no bootstrap" message.
      useEffect(() => {
        if (!launcherId) return;
        let cancelled = false;
        const b = readCeremonyBootstrap(`0x${launcherId}`);
        if (b) {
          setBootstrap(b);
          return;
        }
        (async () => {
          try {
            const recovered = await recoverCeremonyBootstrap(`0x${launcherId}`);
            if (cancelled) return;
            if (!recovered) {
              setBootstrapMissing(true);
              return;
            }
            const reconstructed: CeremonyBootstrap = {
              launcherIdHex: `0x${launcherId}`,
              startBlockHeight: recovered.startBlockHeight,
              ceremonyLengthBlocks: recovered.ceremonyLengthBlocks,
              minParticipants: recovered.minParticipants,
              maxVoters: recovered.maxVoters,
              vkSeedHex: recovered.vkSeedHex,
              label: recovered.label,
            };
            writeCeremonyBootstrap(reconstructed);
            setBootstrap(reconstructed);
          } catch {
            if (!cancelled) setBootstrapMissing(true);
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [launcherId]);

      // Poll peak height every 30s for status display.
      useEffect(() => {
        let cancelled = false;
        async function tick() {
          try {
            const h = await peakHeight();
            if (!cancelled) setPeak(h);
          } catch {
            /* swallow — UI shows "?" until next tick */
          }
        }
        tick();
        const id = setInterval(tick, 30_000);
        return () => {
          cancelled = true;
          clearInterval(id);
        };
      }, []);

      // Derive VK whenever the chain-walked contribution count crosses
      // the deployer's curried threshold. Re-runs when the count grows
      // past min OR the bootstrap loads. The derive call hits
      // SimulatedBackend so it's deterministic from (records, vk_seed).
      useEffect(() => {
        if (!bootstrap) return;
        if (contributions.length < bootstrap.minParticipants) {
          setDerivedVkHex(null);
          setVkDeriveError(null);
          return;
        }
        let cancelled = false;
        (async () => {
          try {
            const vk = (await deriveVkFromCeremony(
              contributions,
              bootstrap.vkSeedHex,
              bootstrap.minParticipants
            )) as { rawBytes?: Uint8Array; raw_bytes?: Uint8Array };
            const bytes = (vk.rawBytes ?? vk.raw_bytes ?? new Uint8Array()) as
              | Uint8Array
              | number[];
            const hex = Array.from(bytes as Uint8Array)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
            if (!cancelled) {
              setDerivedVkHex(hex);
              setVkDeriveError(null);
            }
          } catch (e) {
            if (!cancelled) {
              setDerivedVkHex(null);
              setVkDeriveError(e instanceof Error ? e.message : String(e));
            }
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [bootstrap, contributions]);

      // Poll chain-walked contributions every 30s.
      useEffect(() => {
        if (!launcherId) return;
        let cancelled = false;
        async function tick() {
          try {
            const records = await listCeremonyContributions(`0x${launcherId}`);
            if (!cancelled) {
              setContributions(records);
              setContributionsError(null);
            }
          } catch (e) {
            if (!cancelled) {
              setContributionsError(
                e instanceof Error ? e.message : String(e)
              );
            }
          }
        }
        tick();
        const id = setInterval(tick, 30_000);
        return () => {
          cancelled = true;
          clearInterval(id);
        };
      }, [launcherId]);

      // Poll the chain-walked Ceremony Singleton tip every 30s — used
      // by the IDs panel to surface the live coin id, finalize state,
      // vk_hash, and marker_root.
      useEffect(() => {
        if (!launcherId || !bootstrap) return;
        let cancelled = false;
        async function tick() {
          try {
            const tip = await findCurrentCeremonySingleton(
              `0x${launcherId}`,
              bootstrap!.vkSeedHex
            );
            if (!cancelled) {
              setSingletonTip(tip);
              setSingletonTipError(null);
            }
          } catch (e) {
            if (!cancelled) {
              setSingletonTipError(
                e instanceof Error ? e.message : String(e)
              );
            }
          }
        }
        tick();
        const id = setInterval(tick, 30_000);
        return () => {
          cancelled = true;
          clearInterval(id);
        };
      }, [launcherId, bootstrap]);

      const status = useMemo(
        () => (bootstrap ? ceremonyStatus(bootstrap, peak) : null),
        [bootstrap, peak]
      );

      // Build + sign + push the contribute spend. Two-signer flow:
      //   - Sage signs the funder coin's AGG_SIG_ME path.
      //   - We locally sign the participant AGG_SIG_UNSAFE on
      //     `signatureMsgHex` (which is the contribution_hash) with a
      //     fresh per-contribution participant SK, since Sage's
      //     signCoinSpends does not produce AGG_SIG_UNSAFE sigs.
      // Then aggregate the two G2 sigs into a single bundle sig.
      const submitContribution = useCallback(
        async (entropyHex: string, name: string) => {
          if (!bootstrap) {
            setSubmitError("No ceremony bootstrap loaded");
            return;
          }
          setSubmitError(null);
          setSubmittedMarker(null);
          setSubmitting(true);
          try {
            // 1. Fresh participant BLS keypair, independent from
            //    `entropy_hex` (the entropy is the *contribution*; the
            //    SK is just the AGG_SIG_UNSAFE signing key).
            setSubmitStatus("Generating participant key…");
            const skBytes = new Uint8Array(32);
            window.crypto.getRandomValues(skBytes);
            const skHex = bytesToHex(skBytes);
            const participantPkHex = await publicKeyFromSecretKeyBytes(skHex);

            // 2. Build payload bytes + contribution_hash.
            const payloadJson = JSON.stringify({
              entropy_hex: entropyHex,
              name,
            });
            const payloadBytes = new TextEncoder().encode(payloadJson);
            const payloadHex = bytesToHex(payloadBytes);
            const digestBuf = await window.crypto.subtle.digest(
              "SHA-256",
              payloadBytes
            );
            const contributionHashHex = bytesToHex(new Uint8Array(digestBuf));

            // 3. Walk to the singleton's current unspent tip + state.
            setSubmitStatus("Walking ceremony singleton…");
            const tip = await findCurrentCeremonySingleton(
              `0x${launcherId}`,
              bootstrap.vkSeedHex
            );

            const wasm = await getWasm();
            const { listXchCoinsWithKeys } = await import(
              "../lib/sageAssetCoins"
            );

            const triedParents = new Set<string>();
            const maxParentAttempts = 5;
            let result: {
              coinSpendsBytes: Uint8Array;
              signatureMsgHex: string;
              markerCoinIdHex: string;
            } | null = null;

            for (
              let parentAttempt = 0;
              parentAttempt < maxParentAttempts;
              parentAttempt++
            ) {
              setSubmitStatus(
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
              fresh.sort((a, b) =>
                Number(BigInt(b.amount) - BigInt(a.amount))
              );
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

              setSubmitStatus("Building contribute bundle…");
              // The wasm `JsCoinRecord` deserializer expects
              // `{parentCoinInfo, puzzleHash, amount, spentHeight,
              // confirmedHeight}` (camelCase, no `Hex` suffix). The
              // chain-walked `tip.coin` from `findCurrentCeremonySingleton`
              // and the Sage `parent` both arrive in different shapes,
              // so translate here to match. The TS-level `CoinRecordJs`
              // interface uses Hex-suffixed names but that's a lie at
              // the wasm boundary.
              const singletonForWasm = {
                coin: {
                  parentCoinInfo: tip.coin.parentCoinInfoHex,
                  puzzleHash: tip.coin.puzzleHashHex,
                  amount: tip.coin.amount,
                  spentHeight: 0,
                  confirmedHeight: 0,
                },
                lineageProof: tip.lineageProof,
                state: tip.state,
              };
              const funderCoinForWasm = {
                parentCoinInfo: parent.parentCoinInfo,
                puzzleHash: parent.puzzleHash,
                amount: parent.amount,
                spentHeight: 0,
                confirmedHeight: 0,
              };
              const built = await contributeToCeremony(
                {
                  startBlockHeight: bootstrap.startBlockHeight,
                  ceremonyLengthBlocks: bootstrap.ceremonyLengthBlocks,
                  minParticipants: bootstrap.minParticipants,
                  maxVoters: bootstrap.maxVoters ?? 20_000,
                  vkSeedHex: bootstrap.vkSeedHex,
                  label: bootstrap.label ?? undefined,
                  launcherIdHex: `0x${launcherId}`,
                },
                singletonForWasm as unknown as Parameters<typeof contributeToCeremony>[1],
                funderCoinForWasm as unknown as Parameters<typeof contributeToCeremony>[2],
                parent.syntheticPkHex,
                {
                  participantPkHex,
                  contributionHashHex,
                  prevContributionHashHex: tip.state.lastContributionHashHex,
                  entropyHex,
                  payloadHex,
                }
              );

              setSubmitStatus("Awaiting Sage signature on funder coin…");
              const wcSpends = JSON.parse(
                wasm.coinSpendsBytesToWalletJson(built.coinSpendsBytes)
              ) as WalletConnectCoinSpend[];
              // Pre-filter to send Sage ONLY the funder coin's spend.
              // The bundle also contains the singleton's contribute
              // spend (participant AGG_SIG_UNSAFE — signed locally
              // below) whose puzzle Sage has no key for. Sage's
              // partial-sign mode still throws "Missing secret key"
              // when it sees a coin it can't sign at all, so we
              // narrow the request before sending. The full
              // `built.coinSpendsBytes` is preserved for the bundle
              // assembly step.
              const normalizeHex = (h: string) =>
                h.toLowerCase().replace(/^0x/, "");
              const funderParentHex = normalizeHex(parent.parentCoinInfo);
              const funderPuzHashHex = normalizeHex(parent.puzzleHash);
              const funderSpends = wcSpends.filter(
                (s) =>
                  normalizeHex(s.coin.parent_coin_info) === funderParentHex &&
                  normalizeHex(s.coin.puzzle_hash) === funderPuzHashHex &&
                  Number(s.coin.amount) === Number(parent.amount)
              );
              if (funderSpends.length !== 1) {
                throw new Error(
                  `Internal: expected exactly 1 funder spend in bundle, found ${funderSpends.length}`
                );
              }
              const sageSignedHex = await walletConnect.signCoinSpends(
                funderSpends,
                false,
                false
              );
              if (!sageSignedHex) throw new Error("Wallet declined to sign");
              const sageSigBytes = hexToBytes(sageSignedHex);
              if (sageSigBytes.length !== 96) {
                throw new Error(
                  `Wallet returned a ${sageSigBytes.length}-byte signature; expected 96`
                );
              }

              setSubmitStatus("Locally signing participant AGG_SIG_UNSAFE…");
              const participantSigHex = await signParticipantUnsafe(
                skHex,
                built.signatureMsgHex
              );

              setSubmitStatus("Aggregating signatures…");
              const aggSigHex = await aggregateSignaturesG2(
                sageSignedHex.replace(/^0x/, "") +
                  participantSigHex.replace(/^0x/, "")
              );
              const aggSigBytes = hexToBytes(aggSigHex);

              setSubmitStatus("Assembling and verifying bundle…");
              const bundleBytes = wasm.assembleSpendBundle(
                built.coinSpendsBytes,
                aggSigBytes
              );
              wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
              const walletBundle = JSON.parse(
                wasm.bundleBytesToWalletJson(bundleBytes)
              ) as SpendBundleJson;

              setSubmitStatus("Submitting bundle to mempool…");
              try {
                await pushTx(walletBundle);
                result = built;
                break;
              } catch (e: unknown) {
                const lastTry = parentAttempt >= maxParentAttempts - 1;
                if (!isConsensusRetriablePushError(e) || lastTry) throw e;
                console.warn(
                  "[ceremony-contribute] push_tx rejected; retrying:",
                  e
                );
              }
            }

            if (!result) throw new Error("Contribution submitted no bundle");

            setSubmitStatus("Waiting for marker coin to confirm on chain…");
            const markerCoinId = result.markerCoinIdHex;
            await pollUntilConfirmed({
              predicate: async () => {
                const rec = await coinRecordByName(markerCoinId);
                return rec != null && rec.confirmedHeight > 0;
              },
              timeoutMs: 600_000,
            });

            setSubmittedMarker(markerCoinId);
            setSubmitStatus(null);
          } catch (e: unknown) {
            setSubmitError(e instanceof Error ? e.message : String(e));
            setSubmitStatus(null);
          } finally {
            setSubmitting(false);
          }
        },
        [bootstrap, launcherId]
      );

      if (!launcherId) {
        return (
          <main className="container">
            <h1>Ceremony</h1>
            <p>
              No ceremony selected. Pass <code>?id=&lt;launcher_hex&gt;</code> in
              the URL.
            </p>
            <p>
              <Link href="/create">← Back to Create</Link>
            </p>
            <Footer />
          </main>
        );
      }

      if (bootstrapMissing && !bootstrap) {
        return (
          <main className="container">
            <h1>Ceremony</h1>
            <p>
              No bootstrap found in this browser session for ceremony{" "}
              <code>{truncHex(`0x${launcherId}`)}</code>.
            </p>
            <p>
              Cross-browser bootstrap recovery (chain-walk of the ceremony
              singleton's launcher memo) lands in Phase 5 — until then, deploy
              the ceremony from this browser via <Link href="/create">/create</Link>.
            </p>
            <Footer />
          </main>
        );
      }

      if (!bootstrap) {
        return (
          <main className="container">
            <h1>Ceremony</h1>
            <p>Loading…</p>
          </main>
        );
      }

      const thresholdMet =
        contributions.length >= bootstrap.minParticipants;

      return (
        <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Link
            href="/ceremonies"
            className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
          >
            ← all ceremonies
          </Link>
          <header className="mt-4 mb-6">
            <h1 className="text-3xl font-bold">
              {bootstrap.label || "Ceremony"}
            </h1>
            <p className="text-sm text-[var(--color-muted)] mt-1 mono">
              {truncHex(`0x${launcherId}`)}
            </p>
          </header>

          {/* === Singleton info card === */}
          <section className="card-elev p-4 mb-4">
            <h2 className="text-lg font-semibold mb-3">Singleton info</h2>
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-[var(--color-muted)]">Status</dt>
              <dd>
                {status ? (
                  <span
                    style={{
                      color:
                        status.kind === "open"
                          ? "#1a7f1a"
                          : status.kind === "pre-open"
                            ? "#888"
                            : "#b35900",
                    }}
                  >
                    {formatStatus(status)}
                  </span>
                ) : (
                  "—"
                )}
              </dd>
              <dt className="text-[var(--color-muted)]">Start height</dt>
              <dd>{bootstrap.startBlockHeight}</dd>
              <dt className="text-[var(--color-muted)]">Length (blocks)</dt>
              <dd>{bootstrap.ceremonyLengthBlocks}</dd>
              <dt className="text-[var(--color-muted)]">Current peak</dt>
              <dd>{peak ?? "—"}</dd>
              <dt className="text-[var(--color-muted)]">Min participants</dt>
              <dd>{bootstrap.minParticipants}</dd>
              <dt className="text-[var(--color-muted)]">Threshold</dt>
              <dd>
                {contributions.length} / {bootstrap.minParticipants}{" "}
                {thresholdMet ? (
                  <span style={{ color: "#1a7f1a" }}>✓ met</span>
                ) : (
                  <span style={{ color: "#888" }}>
                    (need {bootstrap.minParticipants - contributions.length}{" "}
                    more)
                  </span>
                )}
              </dd>
              <dt className="text-[var(--color-muted)]">vk_seed</dt>
              <dd>
                <HexId hex={bootstrap.vkSeedHex} />
              </dd>
              <dt className="text-[var(--color-muted)]">launcher_id</dt>
              <dd>
                <HexId hex={`0x${launcherId}`} />
              </dd>
              <dt className="text-[var(--color-muted)]">tip coin_id</dt>
              <dd>
                <HexId hex={singletonTip?.coinIdHex ?? null} />
              </dd>
              <dt className="text-[var(--color-muted)]">tip parent_coin_info</dt>
              <dd>
                <HexId
                  hex={singletonTip?.coin.parentCoinInfoHex ?? null}
                />
              </dd>
              <dt className="text-[var(--color-muted)]">tip puzzle_hash</dt>
              <dd>
                <HexId hex={singletonTip?.coin.puzzleHashHex ?? null} />
              </dd>
              <dt className="text-[var(--color-muted)]">finalized</dt>
              <dd>
                {singletonTip == null
                  ? "—"
                  : singletonTip.state.finalized
                    ? <span style={{ color: "#1a7f1a" }}>✓ true</span>
                    : <span style={{ color: "#888" }}>false (pre-finalize)</span>}
              </dd>
              <dt className="text-[var(--color-muted)]">state.vk_hash</dt>
              <dd>
                <HexId hex={singletonTip?.state.vkHashHex ?? null} />
              </dd>
              <dt className="text-[var(--color-muted)]">state.marker_root</dt>
              <dd>
                <HexId hex={singletonTip?.state.markerRootHex ?? null} />
              </dd>
              <dt className="text-[var(--color-muted)]">last_contribution_hash</dt>
              <dd>
                <HexId
                  hex={singletonTip?.state.lastContributionHashHex ?? null}
                />
              </dd>
            </dl>
            {singletonTipError ? (
              <p className="text-xs mt-3" style={{ color: "red" }}>
                Singleton tip walk error: {singletonTipError}
              </p>
            ) : null}
            {contributionsError ? (
              <p className="text-xs mt-3" style={{ color: "red" }}>
                Chain-walk error: {contributionsError}
              </p>
            ) : null}
          </section>

          {/* === Contribute action card === */}
          <section className="card-elev p-4 mb-4">
            <h2 className="text-lg font-semibold mb-2">Contribute</h2>
            <p className="text-sm text-[var(--color-muted)] mb-3">
              Generate a contribution payload by moving your mouse for
              60 seconds. Entropy is mixed with the browser CSPRNG and
              hashed to 32 bytes — the secret τ for this contribution.
            </p>
          <button
            type="button"
            className="btn-primary"
            disabled={status?.kind !== "open" || !address || submitting}
            title={
              !address
                ? "Connect your Sage wallet first"
                : submitting
                  ? "A contribution is already in flight"
                  : status?.kind === "open"
                    ? "Move your mouse for 60s to generate entropy"
                    : "Window closed or not yet open"
            }
            onClick={() => {
              if (!address) {
                window.alert(
                  "Connect your Sage wallet first — the contribution is recorded against your wallet address."
                );
                return;
              }
              setCollectingEntropy({ name: address, samples: [] });
            }}
          >
            {submitting ? "Submitting…" : "Generate contribution payload"}
          </button>

          {collectingEntropy ? (
            <CollectMouseEntropy
              name={collectingEntropy.name}
              onCancel={() => setCollectingEntropy(null)}
              onDone={async (mouseSamples) => {
                const participantName = collectingEntropy.name;
                // Mix mouse stream + browser CSPRNG bytes via SHA-256
                // to keep the cryptographic floor when the user
                // intentionally barely moves the mouse.
                const csprng = new Uint8Array(32);
                window.crypto.getRandomValues(csprng);
                const mouseBytes = new Uint8Array(
                  Float64Array.from(mouseSamples).buffer
                );
                const mixed = new Uint8Array(csprng.length + mouseBytes.length);
                mixed.set(csprng, 0);
                mixed.set(mouseBytes, csprng.length);
                const digest = await window.crypto.subtle.digest("SHA-256", mixed);
                const entropyHex = bytesToHex(new Uint8Array(digest));
                setCollectingEntropy(null);
                await submitContribution(entropyHex, participantName);
              }}
            />
          ) : null}

          {submitting && submitStatus ? (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.75rem",
                border: "1px solid var(--color-border)",
                borderRadius: "0.25rem",
                background: "#fafafa",
                color: "#222",
              }}
            >
              <h3 className="text-base font-semibold">Submitting contribution…</h3>
              <p className="text-sm mt-1">{submitStatus}</p>
              <p className="text-xs text-[var(--color-muted)] mt-2">
                Two-signer flow: Sage signs the funder coin (AGG_SIG_ME)
                and a fresh local participant key signs the
                AGG_SIG_UNSAFE on the contribution_hash. The two G2
                sigs are aggregated before broadcast.
              </p>
            </div>
          ) : null}

          {submitError ? (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.75rem",
                border: "1px solid #c33",
                borderRadius: "0.25rem",
                background: "#fff5f5",
                color: "#900",
              }}
            >
              <h3 className="text-base font-semibold">Contribution failed</h3>
              <p className="text-sm mt-1" style={{ wordBreak: "break-all" }}>
                {submitError}
              </p>
            </div>
          ) : null}

          {submittedMarker ? (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.75rem",
                border: "1px solid #1a7f1a",
                borderRadius: "0.25rem",
                background: "#e6f7e6",
                color: "#0a3d0a",
              }}
            >
              <h3 className="text-base font-semibold">
                ✓ Contribution submitted
              </h3>
              <p className="text-sm mt-1">
                Marker coin id:{" "}
                <code className="mono">{truncHex(submittedMarker)}</code>
              </p>
              <p className="text-xs mt-2">
                The on-chain coin index below will refresh on its next
                30s poll. Once the threshold is reached this page
                will surface the derived VK.
              </p>
            </div>
          ) : null}
          </section>

          {/* === VK ready card (only when threshold met) === */}
          {contributions.length >= bootstrap.minParticipants ? (
            <section
              className="card-elev p-4 mb-4"
              style={{ background: "#e6f7e6", color: "#0a3d0a" }}
            >
              <h2 className="text-lg font-semibold mb-2">
                ✓ Verification key ready
              </h2>
              <p>
                Threshold met ({contributions.length}/
                {bootstrap.minParticipants}). The Groth16 VK derived
                from these on-chain contributions:
              </p>
              {derivedVkHex ? (
                <>
                  <pre
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(derivedVkHex);
                        setCopyFeedback("copied!");
                        setTimeout(() => setCopyFeedback(null), 2000);
                      } catch (e) {
                        setCopyFeedback(
                          `copy failed: ${e instanceof Error ? e.message : String(e)}`
                        );
                        setTimeout(() => setCopyFeedback(null), 2000);
                      }
                    }}
                    title="Click to copy"
                    style={{
                      cursor: "pointer",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      background: "#fff",
                      color: "#000",
                      padding: "0.5rem",
                      border: "1px solid #ccc",
                      fontSize: "0.75em",
                      maxHeight: "10rem",
                      overflow: "auto",
                    }}
                  >
                    {derivedVkHex}
                  </pre>
                  <div
                    style={{
                      fontSize: "0.85em",
                      color: copyFeedback === "copied!" ? "#1a7f1a" : "#888",
                      marginTop: "0.25rem",
                    }}
                  >
                    {copyFeedback ?? "Click the box above to copy. Paste into /create's Verification key field."}
                  </div>
                  <Link
                    href={`/create?vkHex=${derivedVkHex}&ceremonyId=0x${launcherId}`}
                    className="btn-primary inline-block"
                    style={{ marginTop: "0.5rem" }}
                  >
                    Use this VK to launch an election →
                  </Link>
                </>
              ) : vkDeriveError ? (
                <div style={{ color: "red" }}>
                  Error deriving VK: {vkDeriveError}
                </div>
              ) : (
                <div>Deriving VK…</div>
              )}
            </section>
          ) : null}

          {/* === On-chain coin index card === */}
          {contributions.length > 0 ? (
            <section className="card-elev p-4 mb-4">
              <h2 className="text-lg font-semibold mb-2">
                On-chain ceremony coins
              </h2>
              <p className="text-sm text-[var(--color-muted)] mb-3">
                {contributions.length} marker coin
                {contributions.length !== 1 ? "s" : ""}, hinted with this
                ceremony's launcher id. Each is a child of the
                singleton's recreate spend at amount=2.
              </p>
              <table
                style={{
                  marginTop: "0.5rem",
                  width: "100%",
                  fontSize: "0.85em",
                  borderCollapse: "collapse",
                }}
              >
                <thead>
                  <tr style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>
                    <th style={{ padding: "0.25rem" }}>#</th>
                    <th>participant_pubkey</th>
                    <th>contribution_hash</th>
                    <th>entropy_hex</th>
                    <th>marker coin_id</th>
                    <th>block</th>
                  </tr>
                </thead>
                <tbody>
                  {contributions.map((c, i) => {
                    const entropyHex = c.entropyHex ?? "";
                    const entropyDisplay = entropyHex
                      ? truncHex(entropyHex)
                      : "—";
                    return (
                      <tr key={c.coinIdHex} style={{ borderBottom: "1px solid #eee" }}>
                        <td style={{ padding: "0.25rem" }}>
                          {i + 1}
                          {i === 0 ? " (gen)" : ""}
                        </td>
                        <td><code>{truncHex(c.participantPkHex)}</code></td>
                        <td><code>{truncHex(c.contributionHashHex)}</code></td>
                        <td><code>{entropyDisplay}</code></td>
                        <td><code>{truncHex(c.coinIdHex)}</code></td>
                        <td>{c.blockHeight}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <p className="text-xs text-[var(--color-muted)] mt-3">
                Each row is a marker CeremonyCoin minted by the
                singleton's contribute action (amount=2). The
                singleton itself recreates with each contribution,
                advancing its curried state to (count+1,
                last_hash=contribution_hash).
              </p>
            </section>
          ) : null}

          <Footer />
        </main>
      );
    };
  },
  {
    ssr: false,
    loading: () => (
      <main className="container">
        <h1>Ceremony</h1>
        <p>Loading…</p>
      </main>
    ),
  }
);

function formatStatus(s: CeremonyStatus): string {
  if (s.kind === "pre-open") {
    return `opens in ${s.blocksUntilStart} block(s)`;
  }
  if (s.kind === "open") {
    return `open — ${s.blocksRemaining} block(s) remaining`;
  }
  return `closed ${s.blocksOver} block(s) ago`;
}

export default function CeremonyPage() {
  return (
    <Suspense
      fallback={
        <main className="container">
          <h1>Ceremony</h1>
          <p>Loading…</p>
        </main>
      }
    >
      <CeremonyPageInner />
    </Suspense>
  );
}

/**
 * CollectMouseEntropy — fullscreen modal that captures mouse-movement
 * samples for 60 seconds, then enables a Submit button so the
 * participant can review the elapsed time before committing. Samples
 * are flat (x, y, performance.now()) triples; the parent hashes
 * them with crypto.getRandomValues to produce the final 32-byte
 * entropy.
 */
function CollectMouseEntropy({
  name,
  durationMs = 60_000,
  onCancel,
  onDone,
}: {
  name: string;
  durationMs?: number;
  onCancel: () => void;
  onDone: (samples: number[]) => void;
}) {
  const samplesRef = useRef<number[]>([]);
  const startRef = useRef(performance.now());
  const lastMoveRef = useRef(0);
  const [elapsed, setElapsed] = useState(0);
  const [count, setCount] = useState(0);

  // Tick every 100ms to update the timer + progress bar even when the
  // mouse is briefly stationary.
  useEffect(() => {
    const id = setInterval(() => {
      const now = performance.now();
      const e = Math.min(durationMs, now - startRef.current);
      setElapsed(e);
    }, 100);
    return () => clearInterval(id);
  }, [durationMs]);

  const onMove = useCallback((ev: React.MouseEvent<HTMLDivElement>) => {
    // Throttle to ~one sample per 8 ms to keep the buffer compact
    // on high-rate devices.
    const now = performance.now();
    if (now - lastMoveRef.current < 8) return;
    lastMoveRef.current = now;
    samplesRef.current.push(ev.clientX, ev.clientY, now);
    setCount(Math.floor(samplesRef.current.length / 3));
  }, []);

  const pct = Math.min(100, Math.round((elapsed / durationMs) * 100));
  const secondsLeft = Math.max(0, Math.ceil((durationMs - elapsed) / 1000));
  const ready = elapsed >= durationMs;

  return (
    <div
      onMouseMove={onMove}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.9)",
        color: "#fff",
        zIndex: 9999,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "crosshair",
        overflowY: "auto",
      }}
    >
      <div
        style={{
          maxWidth: "36rem",
          width: "100%",
          padding: "2rem",
          textAlign: "center",
          pointerEvents: "none",
          maxHeight: "100vh",
          overflowY: "auto",
        }}
      >
        <h2 style={{ margin: 0, fontSize: "1.75rem" }}>
          {ready ? "Entropy collected" : "Move your mouse to generate entropy"}
        </h2>
        <p style={{ marginTop: "1rem", color: "#ccc" }}>
          Contribution by:{" "}
          <strong style={{ wordBreak: "break-all" }}>
            {name.length > 24 ? `${name.slice(0, 12)}…${name.slice(-8)}` : name}
          </strong>
        </p>
        <p style={{ marginTop: "0.5rem", color: "#bbb", fontSize: "0.9em" }}>
          The randomness of your mouse path becomes the secret τ for
          this Groth16 contribution. Move freely for the full window;
          longer & more chaotic paths give better entropy.
        </p>
        <div
          style={{
            marginTop: "2rem",
            width: "100%",
            height: "1.25rem",
            background: "#333",
            borderRadius: "0.25rem",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${pct}%`,
              height: "100%",
              background: ready ? "#4caf50" : "#2e8aef",
              transition: "width 0.1s linear",
            }}
          />
        </div>
        <p style={{ marginTop: "0.5rem", fontSize: "0.95em" }}>
          {ready ? "Done — click Submit" : `${secondsLeft}s remaining`}
        </p>
        <p style={{ fontSize: "0.8em", color: "#888" }}>
          {count} samples captured
        </p>
        <div style={{ marginTop: "1.5rem", display: "flex", gap: "0.5rem", justifyContent: "center" }}>
          <button
            type="button"
            onClick={onCancel}
            style={{
              padding: "0.5rem 1rem",
              pointerEvents: "auto",
              background: "#444",
              color: "#fff",
              border: "1px solid #666",
              borderRadius: "0.25rem",
              cursor: "pointer",
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!ready}
            onClick={() => onDone(samplesRef.current.slice())}
            style={{
              padding: "0.5rem 1.5rem",
              pointerEvents: "auto",
              background: ready ? "#4caf50" : "#888",
              color: "#fff",
              border: "1px solid " + (ready ? "#6cc06c" : "#aaa"),
              borderRadius: "0.25rem",
              cursor: ready ? "pointer" : "not-allowed",
              fontWeight: 600,
              opacity: ready ? 1 : 0.7,
            }}
          >
            {ready ? "Submit contribution" : `Submit (${secondsLeft}s)`}
          </button>
        </div>
      </div>
    </div>
  );
}
