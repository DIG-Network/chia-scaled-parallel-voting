"use client";

import {
  APPROX_BLOCK_TIME_SEC_MAINNET,
  formatApproxEtaSeconds,
} from "../lib/formatApproxEta";

export type QuietCountdown = {
  blocksRemaining: number;
  finalizeMinHeight: number;
  peak: number;
};

/**
 * Finalize countdown for the **current** singleton (height-relative lock).
 * Fully **derived from the parent election page** lifecycle tick — no
 * wasm/coinset polling here (avoids duplicating RPCs alongside the tick).
 */
export function ElectionFinalizeQuietBanner({
  finalized,
  show,
  lifecycleStatus,
  lifecycleErrorMessage,
  quietCountdown,
}: {
  finalized: boolean;
  show: boolean;
  lifecycleStatus: "idle" | "loading" | "error" | "ready";
  lifecycleErrorMessage?: string;
  /** Present when lifecycle is ready, election not finalized — from parent tick */
  quietCountdown: QuietCountdown | null;
}) {
  if (!show || finalized) return null;

  const loading =
    lifecycleStatus === "idle" ||
    lifecycleStatus === "loading" ||
    (lifecycleStatus === "ready" && !quietCountdown);

  const err =
    lifecycleStatus === "error" ? (lifecycleErrorMessage ?? "Unknown error.") : null;

  return (
    <section
      className="rounded-xl border border-[var(--color-border)] bg-[var(--color-accent)]/10 px-4 py-3 text-sm"
      aria-live="polite"
    >
      <div className="font-medium text-[var(--color-foreground)]">
        {loading && "Finalization timer — loading chain data…"}

        {!loading && err && (
          <span className="text-[var(--color-muted)]">{err}</span>
        )}

        {!loading &&
          !err &&
          quietCountdown &&
          quietCountdown.blocksRemaining > 0 && (
            <>
              Approximate quiet period left (~{APPROX_BLOCK_TIME_SEC_MAINNET}{" "}
              s/block):{" "}
              <span className="font-semibold text-[var(--color-accent)]">
                {formatApproxEtaSeconds(
                  quietCountdown.blocksRemaining * APPROX_BLOCK_TIME_SEC_MAINNET
                )}
              </span>
              <span className="text-[var(--color-muted)]">
                {" "}
                (~{quietCountdown.blocksRemaining.toLocaleString()} blocks)
              </span>
            </>
          )}

        {!loading &&
          !err &&
          quietCountdown &&
          quietCountdown.blocksRemaining <= 0 && (
            <>
              Quiet period elapsed —{" "}
              <span className="font-semibold text-green-700 dark:text-green-400">
                finalize time-lock satisfied
              </span>
              <span className="text-[var(--color-muted)]">
                {" "}
                (Groth16 + vote tally still required)
              </span>
            </>
          )}
      </div>
      <p className="text-xs text-[var(--color-muted)] mt-2 leading-relaxed">
        On-chain countdown is measured from the{" "}
        <strong className="text-[var(--color-foreground)]/90">
          current singleton
        </strong>{" "}
        (the election coin). It resets whenever that coin is recreated —
        notably after a new voter registers — so registrations extend the
        quiet window.
      </p>
    </section>
  );
}
