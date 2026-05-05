"use client";

import Link from "next/link";
import WalletConnector from "./WalletConnector";

export default function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 bg-[var(--color-background)]/80 backdrop-blur-md border-b border-[var(--color-border)] z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16 items-center">
          <div className="flex items-center gap-8">
            <Link
              href="/"
              className="text-xl font-bold tracking-tight"
            >
              <span className="text-[var(--color-accent)]">CHIP</span>{" "}
              Voting
            </Link>
            <Link
              href="/create"
              className="text-sm text-[var(--color-muted)] hover:text-[var(--color-foreground)] transition-colors"
            >
              New Election
            </Link>
          </div>
          <WalletConnector />
        </div>
      </div>
    </nav>
  );
}
