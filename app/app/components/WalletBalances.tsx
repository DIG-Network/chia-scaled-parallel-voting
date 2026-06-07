"use client";

import dynamic from "next/dynamic";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAppSelector } from "../redux/hooks";
import { coinRecordsByPuzzleHash } from "../lib/coinset";
import { loadElections } from "../lib/elections";
import { puzzleHashHexFromWalletAddress } from "../lib/chiaAddress";
import { dexieCatAssetUrl, formatCat, formatXch, normalizeHex32 } from "../lib/units";
import { getWasm } from "../lib/sdk";

// CRITICAL WASM IMPORT PATTERN: Components that touch wasm MUST be
// imported via `dynamic(async () => { const w = await import(...);
// return Component; }, { ssr: false })`. The factory is what gets
// executed on the client only — top-level `import "chip-voting-wasm"`
// crashes Next.js's prerender pass.
export default dynamic(
  async function DynamicElem() {
    const wasm = await getWasm();

    function uniqueCatTailsFromStorage(): string[] {
      const set = new Set<string>();
      for (const e of loadElections()) {
        try {
          const c = JSON.parse(e.configJson) as { cat_tail_hash_hex?: string };
          const raw = c.cat_tail_hash_hex;
          if (typeof raw !== "string") continue;
          const n = normalizeHex32(raw);
          if (/^[0-9a-f]{64}$/.test(n)) set.add(n);
        } catch {
          /* skip malformed */
        }
      }
      return [...set];
    }

    return function WalletBalances() {
      const { address } = useAppSelector((s) => s.wallet);
      const pathname = usePathname();
      const [xch, setXch] = useState<bigint | null>(null);
      const [cats, setCats] = useState<{ tail: string; mojos: bigint }[]>([]);
      const [loading, setLoading] = useState(false);

      const WALLET_BALANCES_DEBOUNCE_MS = 650;

      useEffect(() => {
        if (!address) {
          setXch(null);
          setCats([]);
          return;
        }
        let cancel = false;
        const debounceId = window.setTimeout(() => {
          (async () => {
            setLoading(true);
            try {
              const xchPh = await puzzleHashHexFromWalletAddress(address);
              if (!xchPh) {
                if (!cancel) {
                  setXch(0n);
                  setCats([]);
                }
                return;
              }
              const xchCoins = await coinRecordsByPuzzleHash(xchPh, false);
              const xchTotal = xchCoins.reduce(
                (acc: bigint, c) => acc + BigInt(c.amount),
                0n
              );
              const tails = uniqueCatTailsFromStorage();
              const rows: { tail: string; mojos: bigint }[] = [];
              for (const tail of tails) {
                const digOuterPh = wasm.catOuterPuzzleHash(
                  `0x${tail}`,
                  xchPh
                );
                const catCoins = await coinRecordsByPuzzleHash(
                  digOuterPh,
                  false
                );
                const total = catCoins.reduce(
                  (acc: bigint, c) => acc + BigInt(c.amount),
                  0n
                );
                rows.push({ tail, mojos: total });
              }
              rows.sort((a, b) => (a.tail < b.tail ? -1 : 1));
              if (cancel) return;
              setXch(xchTotal);
              setCats(rows);
            } finally {
              if (!cancel) setLoading(false);
            }
          })();
        }, WALLET_BALANCES_DEBOUNCE_MS);

        return () => {
          cancel = true;
          window.clearTimeout(debounceId);
        };
      }, [address, pathname]);

      if (!address) return null;

      return (
        <div className="card-elev grid gap-5">
          <div>
            <div className="eyebrow mb-1.5">XCH balance</div>
            <div className="mono text-3xl font-semibold tabular-nums">
              {loading ? (
                <span className="inline-block h-8 w-32 animate-pulse rounded bg-[var(--color-muted-bg)] align-middle" />
              ) : xch === null ? (
                <span className="text-[var(--color-muted)]">—</span>
              ) : (
                formatXch(xch)
              )}
            </div>
          </div>
          <div className="h-px bg-[var(--color-border)]" />
          <div>
            <div className="eyebrow mb-2.5">
              CAT collateral · per saved election asset
            </div>
            {loading ? (
              <div className="space-y-2">
                <div className="h-7 w-40 animate-pulse rounded bg-[var(--color-muted-bg)]" />
                <div className="h-7 w-32 animate-pulse rounded bg-[var(--color-muted-bg)]" />
              </div>
            ) : cats.length === 0 ? (
              <p className="text-sm leading-relaxed text-[var(--color-muted-strong)]">
                Save an election locally (deploy or import its config), then
                balances for that CAT tail appear here. Each election picks its
                own asset at deploy time — there is no single default token.
              </p>
            ) : (
              <ul className="space-y-3">
                {cats.map(({ tail, mojos }) => (
                  <li
                    key={tail}
                    className="flex flex-wrap items-baseline gap-x-3 gap-y-1"
                  >
                    <span className="mono text-2xl font-semibold tabular-nums">
                      {formatCat(mojos)}
                    </span>
                    <span className="mono text-xs text-[var(--color-muted)]">
                      0x{tail.slice(0, 8)}…{tail.slice(-6)}
                    </span>
                    <Link
                      href={dexieCatAssetUrl(`0x${tail}`)}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-[var(--color-accent)] hover:underline"
                    >
                      View on Dexie ↗
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      );
    };
  },
  { ssr: false, loading: () => <div className="skeleton h-28" /> }
);
