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
      <div className="card text-[var(--color-muted)]">
        <p>No elections in your local list yet.</p>
        <p className="mt-2">
          <Link href="/create" className="text-[var(--color-accent)] hover:underline">
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
        return (
          <Link
            key={e.launcherIdHex}
            href={`/election/?id=${e.launcherIdHex.replace(/^0x/, "")}`}
            className="block card hover:border-[var(--color-accent)] transition-colors"
            onClick={() => writeElectionBootstrap(bootstrapFromStored(e))}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-semibold text-lg truncate">{e.label}</h3>
                  {participated && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
                      Registered
                    </span>
                  )}
                </div>
                <div className="mono text-xs text-[var(--color-muted)] mt-1">
                  {truncHex(e.launcherIdHex, 10, 8)}
                </div>
                <div className="grid grid-cols-3 gap-2 mt-3 text-sm">
                  <div>
                    <div className="text-xs text-[var(--color-muted)]">Collateral</div>
                    <div className="mono">
                      {formatCat(cfg.collateral_amount)}
                      <span className="text-[var(--color-muted)] text-xs ml-1">
                        {truncHex(
                          "0x" + normalizeHex32(String(cfg.cat_tail_hash_hex ?? "")),
                          4,
                          4
                        )}
                      </span>
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[var(--color-muted)]">Reg. fee</div>
                    <div className="mono">{formatXch(cfg.registration_fee)} XCH</div>
                  </div>
                  <div>
                    <div className="text-xs text-[var(--color-muted)]">Window</div>
                    <div className="mono">{cfg.election_length_blocks} blocks</div>
                  </div>
                </div>
              </div>
              <button
                onClick={(ev) => {
                  ev.preventDefault();
                  ev.stopPropagation();
                  handleRemove(e.launcherIdHex);
                }}
                className="text-[var(--color-muted)] hover:text-[var(--color-danger)] text-xl"
                title="Remove from local list"
              >
                ×
              </button>
            </div>
          </Link>
        );
      })}
    </div>
  );
}
