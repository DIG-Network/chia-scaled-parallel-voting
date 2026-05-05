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

  const handleImport = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = importId.trim().replace(/^0x/, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(trimmed)) {
      router.push(`/election/?id=${trimmed}`);
    }
  };

  return (
    <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <header className="mb-10">
        <h1 className="text-3xl font-bold tracking-tight">Elections</h1>
        <p className="text-[var(--color-muted)] mt-2 max-w-2xl">
          Vote on-chain with CAT-collateralised registration and Groth16-proven
          finalization. Your wallet signs spends locally; nothing about your vote
          ever leaves your device unencrypted.
        </p>
      </header>

      {!isInitialized ? (
        <div className="card animate-pulse h-24" />
      ) : !address ? (
        <div className="card-elev mb-6">
          <h2 className="font-semibold text-lg">Get started</h2>
          <p className="text-[var(--color-muted)] mt-1">
            Connect Sage Wallet (top right) to see your balance and participate.
          </p>
        </div>
      ) : (
        <div className="mb-6">
          <WalletBalances />
        </div>
      )}

      <section className="mb-10">
        <div className="flex items-baseline justify-between mb-4">
          <h2 className="text-xl font-semibold">Your elections</h2>
          <Link href="/create" className="btn-primary">
            + New
          </Link>
        </div>
        <ElectionList />
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-3">Import an election</h2>
        <form onSubmit={handleImport} className="flex gap-2">
          <input
            type="text"
            value={importId}
            onChange={(e) => setImportId(e.target.value)}
            placeholder="0xab12…  (64-hex-char launcher id)"
            className="input mono"
            pattern="^(0x)?[0-9a-fA-F]{64}$"
          />
          <button type="submit" className="btn-secondary">
            Open
          </button>
        </form>
        <p className="text-xs text-[var(--color-muted)] mt-2">
          Paste any election's launcher_id to view its on-chain state, even if
          you weren't its creator.
        </p>
      </section>

      <Footer />
    </main>
  );
}
