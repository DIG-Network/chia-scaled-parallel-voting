"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { peakHeight } from "../lib/coinset";
import { truncHex } from "../lib/units";
import Footer from "../components/Footer";
import {
  listAllCeremonies,
  type CeremonyBootstrap,
} from "../lib/ceremonyBootstrap";
import { listCeremonyContributions } from "../lib/sdk";

type Status = "pre-open" | "open" | "closed";

function statusOf(b: CeremonyBootstrap, peak: number | null): Status | null {
  if (peak == null) return null;
  if (peak < b.startBlockHeight) return "pre-open";
  if (peak < b.startBlockHeight + b.ceremonyLengthBlocks) return "open";
  return "closed";
}

const CeremoniesIndexInner = dynamic(
  async function DynamicElem() {
    return function CeremoniesIndexInner() {
      const [ceremonies, setCeremonies] = useState<CeremonyBootstrap[]>([]);
      const [peak, setPeak] = useState<number | null>(null);
      // Per-launcher contribution counts. `undefined` = not yet fetched
      // (badge shows "—"); a number = chain-walked count. Cached for
      // the lifetime of this page (one fetch per ceremony on mount);
      // /ceremony itself polls a fresh count every 30s.
      const [counts, setCounts] = useState<Record<string, number>>({});

      useEffect(() => {
        setCeremonies(listAllCeremonies());
      }, []);

      // Fetch contribution counts once per known ceremony. Errors are
      // swallowed — a launcher that never confirmed an eve will throw
      // here, and we'd rather show "—" than block the index render.
      useEffect(() => {
        if (ceremonies.length === 0) return;
        let cancelled = false;
        (async () => {
          for (const b of ceremonies) {
            try {
              const records = await listCeremonyContributions(b.launcherIdHex);
              if (cancelled) return;
              setCounts((prev) => ({
                ...prev,
                [b.launcherIdHex]: records.length,
              }));
            } catch {
              /* swallow — badge stays "—" for unfetchable rows */
            }
          }
        })();
        return () => {
          cancelled = true;
        };
      }, [ceremonies]);

      useEffect(() => {
        let cancelled = false;
        async function tick() {
          try {
            const h = await peakHeight();
            if (!cancelled) setPeak(h);
          } catch {
            /* ignore */
          }
        }
        tick();
        const id = setInterval(tick, 30_000);
        return () => {
          cancelled = true;
          clearInterval(id);
        };
      }, []);

      const annotated = useMemo(
        () =>
          ceremonies.map((b) => ({
            bootstrap: b,
            status: statusOf(b, peak),
          })),
        [ceremonies, peak]
      );
      const active = annotated.filter((a) => a.status !== "closed");
      const completed = annotated.filter((a) => a.status === "closed");

      return (
        <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <header className="mt-4 mb-6 flex justify-between items-start gap-4">
            <div>
              <h1 className="text-3xl font-bold">Ceremonies</h1>
              <p className="text-[var(--color-muted)] mt-2">
                Every CHIP trusted-setup ceremony known to this browser.
                Each row links to its singleton info, on-chain
                contribution coins, and the derived verifying key once
                the threshold is met.
              </p>
              <p className="text-sm text-[var(--color-muted)] mt-2">
                Current peak: {peak ?? "—"}. Active: {active.length}.
                Completed: {completed.length}.
              </p>
            </div>
            <Link
              href="/create-ceremony"
              className="btn-primary text-sm whitespace-nowrap"
            >
              + New Ceremony
            </Link>
          </header>

          <section className="card-elev p-4 mb-6">
            <h2 className="text-lg font-semibold mb-2">
              What is a ceremony?
            </h2>
            <p className="text-sm text-[var(--color-muted)]">
              CHIP elections rely on Groth16 zero-knowledge proofs to
              keep individual ballots private while still letting anyone
              verify the tally. Groth16 needs a per-circuit verifying
              key, and that key is only safe if no single party knows
              the secret randomness used to generate it.
            </p>
            <p className="text-sm text-[var(--color-muted)] mt-2">
              A ceremony is a multi-participant on-chain ritual where
              each contributor mixes in fresh randomness and immediately
              destroys their share. As long as <em>one</em> participant
              is honest, the resulting verifying key is trustworthy.
              Once a ceremony reaches its participant threshold and
              finalizes, the VK it produces can be wired into any
              election &mdash; that's the link from /create that says
              "max voters from chosen ceremony."
            </p>
          </section>

          {ceremonies.length === 0 ? (
            <div className="card-elev p-4">
              <p>
                No ceremonies in this browser yet.{" "}
                <Link
                  href="/create-ceremony"
                  className="text-[var(--color-accent)]"
                >
                  Create one
                </Link>
                .
              </p>
            </div>
          ) : null}

          {active.length > 0 ? (
            <section className="card-elev p-4 mb-6">
              <h2 className="text-lg font-semibold mb-2">Active</h2>
              <CeremonyList items={active} counts={counts} />
            </section>
          ) : null}

          {completed.length > 0 ? (
            <section className="card-elev p-4">
              <h2 className="text-lg font-semibold mb-2">Completed</h2>
              <CeremonyList items={completed} counts={counts} />
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
      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1>Ceremony singletons</h1>
        <p>Loading…</p>
      </main>
    ),
  }
);

function CeremonyList({
  items,
  counts,
}: {
  items: { bootstrap: CeremonyBootstrap; status: Status | null }[];
  counts: Record<string, number>;
}) {
  return (
    <ul className="divide-y divide-[var(--color-border)]">
      {items.map(({ bootstrap, status }) => {
        const id = bootstrap.launcherIdHex.replace(/^0x/, "");
        const count = counts[bootstrap.launcherIdHex];
        const min = bootstrap.minParticipants;
        const thresholdMet = count !== undefined && count >= min;
        return (
          <li key={id} className="py-2">
            <Link
              href={`/ceremony?id=${id}`}
              className="block hover:bg-[var(--color-muted-bg)] px-2 py-1 rounded"
            >
              <div className="flex justify-between items-baseline">
                <code className="mono">{truncHex(bootstrap.launcherIdHex)}</code>
                <div className="flex gap-2 items-baseline">
                  <span
                    className="text-xs"
                    title={
                      count === undefined
                        ? "loading contribution count…"
                        : `${count} of ${min} participants`
                    }
                    style={{
                      color: thresholdMet
                        ? "#1a7f1a"
                        : count === undefined
                          ? "#888"
                          : "#b35900",
                    }}
                  >
                    {count === undefined ? "—" : `${count}/${min}`}
                    {thresholdMet ? " ✓" : ""}
                  </span>
                  <span
                    className="text-xs"
                    style={{
                      color: status === "closed" ? "#888" : "#1a7f1a",
                    }}
                  >
                    {status ?? "?"}
                  </span>
                </div>
              </div>
              {bootstrap.label ? (
                <div className="text-sm mt-1">{bootstrap.label}</div>
              ) : null}
              <div className="text-xs text-[var(--color-muted)] mt-1">
                start={bootstrap.startBlockHeight} length=
                {bootstrap.ceremonyLengthBlocks} min={min}
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

export default function CeremoniesIndex() {
  return (
    <Suspense
      fallback={
        <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <h1>Ceremony singletons</h1>
          <p>Loading…</p>
        </main>
      }
    >
      <CeremoniesIndexInner />
    </Suspense>
  );
}
