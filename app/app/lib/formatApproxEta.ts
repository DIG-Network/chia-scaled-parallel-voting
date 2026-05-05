/** Mainnet-ish average; UI copy elsewhere uses ~52s/block. */
export const APPROX_BLOCK_TIME_SEC_MAINNET = 52;

/** Human-readable ETA from approximate seconds (>0). */
export function formatApproxEtaSeconds(totalSeconds: number): string {
  const sec = Math.max(0, Math.floor(totalSeconds));
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return "<1m";
}
