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
        <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <header className="mt-4 mb-6 flex justify-between items-start gap-4">
            <div>
              <h1 className="text-3xl font-bold">Elections</h1>
              <p className="text-[var(--color-muted)] mt-2">
                Every CHIP election known to this browser. Each row links
                to the election's vote / register / finalize page.
              </p>
            </div>
            <Link
              href="/create"
              className="btn-primary text-sm whitespace-nowrap"
            >
              + New Election
            </Link>
          </header>

          {elections.length === 0 ? (
            <div className="card-elev p-4">
              <p>
                No elections in this browser yet.{" "}
                <Link
                  href="/create"
                  className="text-[var(--color-accent)]"
                >
                  Create one
                </Link>
                .
              </p>
            </div>
          ) : (
            <ul className="card-elev p-2 divide-y divide-[var(--color-border)]">
              {elections.map((e) => {
                const id = e.launcherIdHex.replace(/^0x/, "");
                const trunc =
                  id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-8)}` : id;
                return (
                  <li key={e.launcherIdHex} className="py-2">
                    <Link
                      href={`/election?id=${id}`}
                      className="block hover:bg-[var(--color-muted-bg)] px-2 py-1 rounded"
                    >
                      <div className="flex justify-between items-baseline">
                        <span className="font-medium">
                          {e.label || "(unlabelled)"}
                        </span>
                        <code className="mono text-xs text-[var(--color-muted)]">
                          {trunc}
                        </code>
                      </div>
                      {e.addedAt ? (
                        <div className="text-xs text-[var(--color-muted)] mt-1">
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
      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1>Elections</h1>
        <p>Loading…</p>
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
