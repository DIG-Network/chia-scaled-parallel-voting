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
      className="fixed inset-0 z-[130] flex items-center justify-center bg-black/60 px-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-busy="true"
    >
      <div className="w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-bg)] shadow-2xl p-6 space-y-4">
        <div className="flex gap-4">
          <div
            className="mt-1 h-11 w-11 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent animate-spin"
            aria-hidden
          />
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="font-semibold text-lg leading-snug">
              {title}
            </h2>
            <p className="text-sm text-[var(--color-muted)] mt-2 whitespace-pre-wrap leading-relaxed">
              {detail}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
