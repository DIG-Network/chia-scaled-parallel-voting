export default function Footer() {
  return (
    <footer className="w-full py-8 mt-16 text-center text-sm text-[var(--color-muted)] border-t border-[var(--color-border)]">
      <p>
        ⚠️ Experimental — every transaction spends real XCH and CAT.
        Audit the on-chain singleton before participating.
      </p>
      <p className="mt-1">
        Built on{" "}
        <a
          href="https://github.com/Chia-Network/chia-blockchain"
          className="text-[var(--color-accent)] hover:underline"
          target="_blank"
        >
          Chia
        </a>{" "}
        ·{" "}
        <a
          href="https://github.com/dig-network/CHIP"
          className="text-[var(--color-accent)] hover:underline"
          target="_blank"
        >
          source
        </a>
      </p>
    </footer>
  );
}
