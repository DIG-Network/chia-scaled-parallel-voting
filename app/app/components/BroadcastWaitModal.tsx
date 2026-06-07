/**
 * Blocking overlay shown while polling chain reads after a spend bundle
 * submit (typically coinset `push_tx`), waiting for explorers to observe it.
 */
export function BroadcastWaitModal({
  title,
  detail,
  titleId = "broadcast-wait-title",
}: {
  title: string;
  detail: string;
  titleId?: string;
}) {
  return (
    <div
      className="fixed inset-0 z-[130] flex items-center justify-center bg-black/60 px-4 backdrop-blur-sm fade-up"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-busy="true"
    >
      <div className="w-full max-w-md space-y-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-card-elevated)] p-6 shadow-[var(--shadow-lg)]">
        <div className="flex gap-4">
          <div
            className="mt-1 h-11 w-11 shrink-0 animate-spin rounded-full border-2 border-[var(--color-accent)] border-t-transparent"
            aria-hidden
          />
          <div className="min-w-0 flex-1">
            <p className="eyebrow mb-1">Working</p>
            <h2 id={titleId} className="text-lg font-semibold leading-snug">
              {title}
            </h2>
            <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-muted-strong)]">
              {detail}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
