"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  title: string;
}

/**
 * Portal-based modal.
 *
 * WHY A PORTAL: the natural place for `<Modal/>` is INSIDE its
 * trigger component (e.g. `<WalletConnector/>` which lives inside
 * `<Navbar/>`). But the navbar uses `backdrop-blur-md` (Tailwind ⇒
 * `backdrop-filter: blur(...)`), and per the CSS spec ANY ancestor
 * with a non-`none` `backdrop-filter` becomes the containing block
 * for descendant `position: fixed` elements.
 *
 * Result: a fixed-position modal nested inside the navbar would
 * resolve `inset-0` against the 64px-tall navbar instead of the
 * viewport, clipping the overlay to the header. Same hazard
 * applies to ancestors with `transform`, `filter`, `perspective`,
 * `contain: paint`, etc.
 *
 * Solution: render the overlay through `createPortal(…, document.body)`
 * so it escapes the navbar's containing block and stacks above
 * everything, regardless of where the trigger lives in the tree.
 *
 * SSR note: `document` doesn't exist server-side, so we mount
 * the portal lazily on first client render. The brief delay is
 * imperceptible and avoids `ReferenceError: document is not defined`
 * during the static-export prerender pass (`output: "export"`).
 */
export default function Modal({
  isOpen,
  onClose,
  children,
  title,
}: ModalProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted || !isOpen) return null;

  const overlay = (
    <div
      className="fixed inset-0 z-[1000] overflow-y-auto bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div className="flex min-h-full items-center justify-center p-4">
        <div
          className="relative card-elev max-w-md w-full mx-4"
          // Stop propagation so clicks INSIDE the card don't dismiss
          // the modal — only clicks on the dimmed backdrop should.
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-[var(--color-border)]">
            <h3 className="text-lg font-semibold">{title}</h3>
            <button
              onClick={onClose}
              className="text-[var(--color-muted)] hover:text-[var(--color-foreground)]"
              aria-label="Close"
            >
              <svg
                className="h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
          <div>{children}</div>
        </div>
      </div>
    </div>
  );

  return createPortal(overlay, document.body);
}
