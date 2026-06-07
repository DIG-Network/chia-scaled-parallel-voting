export default function Footer() {
  return (
    <footer className="mt-16 w-full border-t border-[var(--color-border)] pt-8 text-sm text-[var(--color-muted)]">
      <div
        role="note"
        className="mx-auto mb-6 flex max-w-2xl items-start gap-3 rounded-xl border border-[var(--color-warning)]/30 bg-[var(--color-warning)]/[0.08] px-4 py-3 text-left"
      >
        <svg
          className="mt-0.5 h-5 w-5 shrink-0 text-[var(--color-warning)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          aria-hidden
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 9v4m0 4h.01M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.42 0Z"
          />
        </svg>
        <p className="leading-relaxed">
          <span className="font-semibold text-[var(--color-warning)]">
            Experimental.
          </span>{" "}
          Every transaction spends real XCH and CAT. Audit the on-chain
          singleton before participating.
        </p>
      </div>
      <div className="text-center">
        Built on{" "}
        <a
          href="https://github.com/Chia-Network/chia-blockchain"
          className="text-[var(--color-accent)] hover:underline"
          target="_blank"
          rel="noreferrer"
        >
          Chia
        </a>{" "}
        <span className="text-[var(--color-border-strong)]">·</span>{" "}
        <a
          href="https://github.com/dig-network/CHIP"
          className="text-[var(--color-accent)] hover:underline"
          target="_blank"
          rel="noreferrer"
        >
          source
        </a>
      </div>
    </footer>
  );
}
