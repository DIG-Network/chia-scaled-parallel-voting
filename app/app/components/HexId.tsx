"use client";

import { useState } from "react";

/**
 * Reusable display component for 32-byte (or any) hex identifiers.
 *
 * Convention enforced across the dApp:
 *   * NEVER truncate — render the full hex string verbatim.
 *   * Click anywhere on the value copies it to the clipboard.
 *   * Brief inline "copied!" flash gives feedback (1.2s).
 *
 * Use this anywhere a hex coin id / launcher id / vk hash / vote_data
 * etc. is shown to the operator. Replaces the legacy `truncHex(...)`
 * helper + manual `<span className="mono">` patterns scattered through
 * the UI.
 *
 * Props:
 *   * `hex`     — the value to render. Pass with or without a leading
 *                 `0x`. Empty / null / undefined renders as "—".
 *   * `label`   — optional aria-label override (defaults to `hex`).
 *   * `className` — extra classes for the container span.
 *   * `prefix`  — optional human prefix shown before the hex (e.g.
 *                 "coin: "). Not part of the copied payload.
 */
export function HexId({
  hex,
  label,
  className,
  prefix,
}: {
  hex: string | null | undefined;
  label?: string;
  className?: string;
  prefix?: string;
}) {
  const [copied, setCopied] = useState(false);
  if (!hex || hex.length === 0) {
    return (
      <span className={className} style={{ color: "var(--color-muted)" }}>
        —
      </span>
    );
  }
  const display = hex.startsWith("0x") ? hex : `0x${hex}`;
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(display);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard API can fail on insecure contexts / older browsers.
      // Surface nothing — the value is already selectable as text.
    }
  };
  return (
    <span
      role="button"
      tabIndex={0}
      aria-label={label ?? display}
      onClick={onCopy}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          void onCopy();
        }
      }}
      className={`mono ${className ?? ""}`}
      title={copied ? "copied!" : "Click to copy"}
      style={{
        cursor: "pointer",
        wordBreak: "break-all",
        userSelect: "all",
        // Subtle hover affordance — underline on hover/focus signals
        // the click target without being noisy in the resting state.
        textDecoration: copied ? "none" : undefined,
        color: copied ? "#1a7f1a" : undefined,
      }}
    >
      {prefix ? <span style={{ color: "var(--color-muted)" }}>{prefix}</span> : null}
      {display}
      {copied ? (
        <span
          aria-live="polite"
          style={{
            marginLeft: "0.5em",
            fontSize: "0.75em",
            color: "#1a7f1a",
          }}
        >
          copied!
        </span>
      ) : null}
    </span>
  );
}
