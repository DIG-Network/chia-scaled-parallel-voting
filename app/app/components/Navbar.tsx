"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import WalletConnector from "./WalletConnector";

const NAV_LINKS = [
  { href: "/elections", label: "Elections" },
  { href: "/ceremonies", label: "Ceremonies" },
];

function isActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  // Treat detail routes as belonging to their index (e.g. /election → Elections).
  const root = href.replace(/s$/, "");
  return pathname === href || pathname.startsWith(`${root}`);
}

export default function Navbar() {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState(false);

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-30 border-b border-[var(--color-border)] bg-[var(--color-background)]/80 backdrop-blur-md"
      aria-label="Primary"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between">
          <div className="flex items-center gap-1 sm:gap-6">
            <Link
              href="/"
              className="group flex items-center gap-2 rounded-lg pr-2 text-lg font-bold tracking-tight"
            >
              <span
                aria-hidden
                className="grid h-7 w-7 place-items-center rounded-md border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 font-mono text-sm text-[var(--color-accent)] transition-transform duration-200 group-hover:scale-105"
              >
                ◈
              </span>
              <span className="font-display">
                <span className="text-[var(--color-accent)]">CHIP</span>{" "}
                <span className="text-[var(--color-foreground)]">Voting</span>
              </span>
            </Link>

            <div className="ml-2 hidden items-center gap-1 sm:flex">
              {NAV_LINKS.map((l) => {
                const active = isActive(pathname, l.href);
                return (
                  <Link
                    key={l.href}
                    href={l.href}
                    aria-current={active ? "page" : undefined}
                    className={`relative rounded-md px-3 py-1.5 text-sm transition-colors ${
                      active
                        ? "text-[var(--color-foreground)]"
                        : "text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
                    }`}
                  >
                    {l.label}
                    {active && (
                      <span className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-[var(--color-accent)]" />
                    )}
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <WalletConnector />
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              aria-controls="mobile-nav"
              aria-label="Toggle navigation menu"
              className="btn-ghost sm:hidden"
            >
              <svg
                className="h-5 w-5"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                aria-hidden
              >
                {open ? (
                  <path strokeLinecap="round" d="M6 6l12 12M6 18L18 6" />
                ) : (
                  <path strokeLinecap="round" d="M4 7h16M4 12h16M4 17h16" />
                )}
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile drawer */}
      {open && (
        <div
          id="mobile-nav"
          className="border-t border-[var(--color-border)] bg-[var(--color-background)]/95 px-4 py-2 sm:hidden"
        >
          {NAV_LINKS.map((l) => {
            const active = isActive(pathname, l.href);
            return (
              <Link
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                aria-current={active ? "page" : undefined}
                className={`block rounded-md px-3 py-2.5 text-sm transition-colors ${
                  active
                    ? "bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "text-[var(--color-muted)] hover:bg-[var(--color-muted-bg)] hover:text-[var(--color-foreground)]"
                }`}
              >
                {l.label}
              </Link>
            );
          })}
        </div>
      )}
    </nav>
  );
}
