"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import Footer from "../components/Footer";
import { loadElections, type StoredElection } from "../lib/elections";

const ElectionsIndexInner = dynamic(
  async function DynamicElem() {
    return function ElectionsIndexInner() {
      const [elections, setElections] = useState<StoredElection[]>([]);

      useEffect(() => {
        setElections(loadElections());
      }, []);

      return (
        <main className="fade-up mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
          <header className="mb-8 flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="eyebrow mb-2">Index</p>
              <h1 className="text-3xl font-medium tracking-tight">Elections</h1>
              <p className="mt-2 max-w-xl text-sm leading-relaxed text-[var(--color-muted-strong)]">
                Every CHIP election known to this browser. Each row links to the
                election&apos;s vote / register / finalize page.
              </p>
            </div>
            <Link
              href="/create"
              className="btn-primary whitespace-nowrap text-sm"
            >
              + New Election
            </Link>
          </header>

          {elections.length === 0 ? (
            <div className="card-elev border-dashed text-center">
              <p className="font-medium">No elections in this browser yet</p>
              <p className="mt-1.5 text-sm text-[var(--color-muted-strong)]">
                <Link href="/create" className="text-[var(--color-accent)] hover:underline">
                  Create one
                </Link>{" "}
                to get started.
              </p>
            </div>
          ) : (
            <ul className="space-y-2.5">
              {elections.map((e) => {
                const id = e.launcherIdHex.replace(/^0x/, "");
                const trunc =
                  id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-8)}` : id;
                return (
                  <li key={e.launcherIdHex}>
                    <Link
                      href={`/election?id=${id}`}
                      className="card card-interactive block"
                    >
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="truncate font-medium">
                          {e.label || (
                            <span className="text-[var(--color-muted)]">
                              (unlabelled)
                            </span>
                          )}
                        </span>
                        <code className="mono shrink-0 text-xs text-[var(--color-muted)]">
                          {trunc}
                        </code>
                      </div>
                      {e.addedAt ? (
                        <div className="mt-1.5 text-xs text-[var(--color-muted)]">
                          added {new Date(e.addedAt).toLocaleString()}
                        </div>
                      ) : null}
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}

          <Footer />
        </main>
      );
    };
  },
  {
    ssr: false,
    loading: () => (
      <main className="mx-auto max-w-3xl px-4 py-10 sm:px-6 lg:px-8">
        <p className="eyebrow mb-2">Index</p>
        <h1 className="text-3xl font-medium tracking-tight">Elections</h1>
        <div className="mt-8 space-y-2.5">
          <div className="skeleton h-16" />
          <div className="skeleton h-16" />
          <div className="skeleton h-16" />
        </div>
      </main>
    ),
  }
);

export default function ElectionsIndex() {
  return (
    <Suspense
      fallback={
        <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <h1>Elections</h1>
          <p>Loading…</p>
        </main>
      }
    >
      <ElectionsIndexInner />
    </Suspense>
  );
}
