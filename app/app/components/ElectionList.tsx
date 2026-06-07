"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAppSelector } from "../redux/hooks";
import { loadElections, removeElection, StoredElection } from "../lib/elections";
import { writeElectionBootstrap, bootstrapFromStored } from "../lib/electionBootstrap";
import { formatCat, formatXch, truncHex, normalizeHex32 } from "../lib/units";

export default function ElectionList() {
  const { address } = useAppSelector((s) => s.wallet);
  const [list, setList] = useState<StoredElection[]>([]);

  useEffect(() => {
    setList(loadElections());
  }, []);

  const handleRemove = (id: string) => {
    if (!confirm("Remove this election from your local list? (It stays on-chain.)")) return;
    removeElection(id);
    setList(loadElections());
  };

  if (list.length === 0) {
    return (
      <div className="card border-dashed text-[var(--color-muted-strong)]">
        <p className="font-medium text-[var(--color-foreground)]">
          No elections yet
        </p>
        <p className="mt-1.5 text-sm">
          <Link
            href="/create"
            className="text-[var(--color-accent)] hover:underline"
          >
            Create a new election
          </Link>{" "}
          or paste a launcher_id below to import an existing one.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {list.map((e) => {
        const cfg = JSON.parse(e.configJson);
        const participated = address
          ? (e.registeredPubkeysHex ?? []).length > 0
          : false;
        const href = `/election/?id=${e.launcherIdHex.replace(/^0x/, "")}`;
        return (
          <div
            key={e.launcherIdHex}
            className="card card-interactive relative"
          >
            {/* Full-card click target; the remove button sits above it
                with its own z-index so the anchor isn't nested in a
                button (valid HTML + keyboard-reachable controls). */}
            <Link
              href={href}
              onClick={() => writeElectionBootstrap(bootstrapFromStored(e))}
              className="absolute inset-0 rounded-[inherit]"
              aria-label={`Open election ${e.label}`}
            />
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="truncate text-lg font-semibold">{e.label}</h3>
                  {participated && (
                    <span className="badge badge-accent">Registered</span>
                  )}
                </div>
                <div className="mono mt-1 text-xs text-[var(--color-muted)]">
                  {truncHex(e.launcherIdHex, 10, 8)}
                </div>
                <div className="mt-4 grid grid-cols-3 gap-2 text-sm">
                  <div>
                    <div className="text-xs uppercase tracking-wide text-[var(--color-muted)]">
                      Collateral
                    </div>
                    <div className="mono mt-0.5">
                      {formatCat(cfg.collateral_amount)}
                      <span className="ml-1 text-xs text-[var(--color-muted)]">
                        {truncHex(
                          "0x" +
                            normalizeHex32(String(cfg.cat_tail_hash_hex ?? "")),
                          4,
                          4
                        )}
                      </span>
                    </div>
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-wide text-[var(--color-muted)]">
                      Reg. fee
                    </div>
                    <div className="mono mt-0.5">
                      {formatXch(cfg.registration_fee)} XCH
                    </div>
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-wide text-[var(--color-muted)]">
                      Window
                    </div>
                    <div className="mono mt-0.5">
                      {cfg.election_length_blocks} blocks
                    </div>
                  </div>
                </div>
              </div>
              <button
                onClick={() => handleRemove(e.launcherIdHex)}
                className="relative z-10 -mr-1 -mt-1 grid h-8 w-8 shrink-0 place-items-center rounded-md text-[var(--color-muted)] transition-colors hover:bg-[var(--color-danger)]/10 hover:text-[var(--color-danger)]"
                aria-label={`Remove ${e.label} from your local list`}
                title="Remove from local list"
              >
                <svg
                  className="h-4 w-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                  aria-hidden
                >
                  <path strokeLinecap="round" d="M6 6l12 12M6 18L18 6" />
                </svg>
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
