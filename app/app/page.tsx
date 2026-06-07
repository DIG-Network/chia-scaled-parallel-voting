"use client";

import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAppSelector } from "./redux/hooks";
import WalletBalances from "./components/WalletBalances";
import ElectionList from "./components/ElectionList";
import Footer from "./components/Footer";

export default function Home() {
  const { isInitialized, address } = useAppSelector((s) => s.wallet);
  const router = useRouter();
  const [importId, setImportId] = useState("");
  const [importError, setImportError] = useState<string | null>(null);

  const handleImport = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = importId.trim().replace(/^0x/, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(trimmed)) {
      setImportError(null);
      router.push(`/election/?id=${trimmed}`);
    } else {
      setImportError(
        "Enter a 64-character hex launcher id (with or without a 0x prefix)."
      );
    }
  };

  return (
    <main className="mx-auto max-w-5xl px-4 py-10 sm:px-6 lg:px-8">
      {/* ── Hero ── */}
      <header className="fade-up mb-12">
        <p className="eyebrow mb-3">On-chain governance · Chia</p>
        <h1 className="max-w-3xl text-4xl font-medium leading-[1.05] tracking-tight sm:text-5xl">
          Vote on-chain,
          <br />
          <span className="text-[var(--color-accent)]">prove the tally.</span>
        </h1>
        <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-[var(--color-muted-strong)]">
          CAT-collateralised registration and Groth16-proven finalization. Your
          wallet signs spends locally — nothing about your vote ever leaves your
          device unencrypted.
        </p>
        <div className="mt-7 flex flex-wrap items-center gap-3">
          <Link href="/create" className="btn-primary">
            New election
          </Link>
          <Link href="/ceremonies" className="btn-secondary">
            Browse ceremonies
          </Link>
        </div>
      </header>

      {/* ── Wallet state ── */}
      {!isInitialized ? (
        <div className="skeleton mb-10 h-28" aria-busy aria-label="Loading wallet" />
      ) : !address ? (
        <section className="card-elev mb-10 flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold">Get started</h2>
            <p className="mt-1 text-sm text-[var(--color-muted-strong)]">
              Connect Sage Wallet to see your balances and participate.
            </p>
          </div>
          <span className="hidden shrink-0 text-sm text-[var(--color-muted)] sm:inline">
            Use the{" "}
            <span className="font-medium text-[var(--color-foreground)]">
              Connect Wallet
            </span>{" "}
            button, top right ↗
          </span>
        </section>
      ) : (
        <div className="mb-10">
          <WalletBalances />
        </div>
      )}

      {/* ── Your elections ── */}
      <section className="mb-12">
        <div className="mb-4 flex items-baseline justify-between gap-4">
          <h2 className="text-xl font-semibold">Your elections</h2>
          <Link
            href="/create"
            className="btn-secondary text-sm"
            aria-label="Create a new election"
          >
            + New
          </Link>
        </div>
        <ElectionList />
      </section>

      {/* ── Import ── */}
      <section className="mb-10">
        <h2 className="mb-1 text-xl font-semibold">Import an election</h2>
        <p className="mb-4 text-sm text-[var(--color-muted)]">
          Paste any election&apos;s launcher_id to view its on-chain state, even
          if you weren&apos;t its creator.
        </p>
        <form onSubmit={handleImport} className="flex flex-col gap-2 sm:flex-row">
          <div className="flex-1">
            <label htmlFor="import-id" className="sr-only">
              Election launcher id
            </label>
            <input
              id="import-id"
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              value={importId}
              onChange={(e) => {
                setImportId(e.target.value);
                if (importError) setImportError(null);
              }}
              placeholder="0xab12…  (64-hex-char launcher id)"
              className="input mono"
              aria-invalid={importError ? true : undefined}
              aria-describedby={importError ? "import-error" : undefined}
            />
          </div>
          <button type="submit" className="btn-secondary">
            Open
          </button>
        </form>
        {importError && (
          <p
            id="import-error"
            role="alert"
            className="mt-2 text-sm text-[var(--color-danger)]"
          >
            {importError}
          </p>
        )}
      </section>

      <Footer />
    </main>
  );
}
