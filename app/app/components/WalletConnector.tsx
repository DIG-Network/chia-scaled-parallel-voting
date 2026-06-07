"use client";

import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Toaster, toast } from "react-hot-toast";
import Modal from "./Modal";
import { useAppSelector } from "../redux/hooks";
import { disconnect } from "../redux/walletSlice";
import { store } from "../redux/store";
import { walletConnect } from "../lib/walletConnectInstance";
import { truncHex } from "../lib/units";

export default function WalletConnector() {
  const { address, isInitialized, qrUri } = useAppSelector(
    (state) => state.wallet
  );
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  const handleModalClose = () => {
    setIsModalOpen(false);
    store.dispatch(disconnect());
  };

  const handleConnect = async () => {
    setIsModalOpen(true);
    try {
      const success = await walletConnect.connectWallet();
      if (success) setIsModalOpen(false);
    } catch (e) {
      console.error("Wallet connection failed:", e);
    }
  };

  const handleCopyLink = async () => {
    if (!qrUri) return;
    try {
      await navigator.clipboard.writeText(qrUri);
      setIsCopied(true);
      toast.success("Link copied");
      setTimeout(() => setIsCopied(false), 1200);
    } catch {
      toast.error("Failed to copy");
    }
  };

  const handleCopyAddress = async () => {
    if (!address) return;
    try {
      await navigator.clipboard.writeText(address);
      toast.success("Address copied");
    } catch {
      toast.error("Failed to copy");
    }
  };

  return (
    <>
      {!isInitialized || !address ? (
        <button
          onClick={handleConnect}
          className="btn-primary text-sm"
          disabled={!isInitialized}
        >
          {isInitialized ? "Connect Wallet" : "Starting…"}
        </button>
      ) : (
        <div className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-card)] py-1 pl-1 pr-1">
          <button
            onClick={handleCopyAddress}
            title="Copy full address"
            className="flex items-center gap-2 rounded-md px-2 py-1 text-sm transition-colors hover:bg-[var(--color-muted-bg)]"
          >
            <span
              aria-hidden
              className="h-2 w-2 rounded-full bg-[var(--color-success)]"
            />
            <span className="mono text-[var(--color-muted-strong)]">
              {truncHex(address, 7, 4)}
            </span>
          </button>
          <button
            onClick={() => walletConnect.disconnectWallet()}
            className="btn-ghost px-2 py-1 text-xs"
            title="Disconnect wallet"
          >
            Disconnect
          </button>
        </div>
      )}

      <Modal
        isOpen={isModalOpen}
        onClose={handleModalClose}
        title="Connect Sage Wallet"
      >
        <div className="flex flex-col items-center gap-4">
          {qrUri ? (
            <>
              <div className="rounded-xl bg-white p-4 shadow-sm">
                <QRCodeSVG value={qrUri} size={236} />
              </div>
              <button
                onClick={handleCopyLink}
                className="btn-secondary text-sm"
              >
                {isCopied ? "Copied ✓" : "Copy connection link"}
              </button>
              <p className="mt-1 text-center text-sm leading-relaxed text-[var(--color-muted-strong)]">
                Scan this code in Sage Wallet, or copy the link and paste it
                into the WalletConnect dialog.
              </p>
            </>
          ) : (
            <div
              className="flex flex-col items-center gap-3 p-6"
              aria-busy
              aria-live="polite"
            >
              <div className="h-9 w-9 animate-spin rounded-full border-2 border-[var(--color-accent)] border-t-transparent" />
              <p className="text-sm text-[var(--color-muted)]">
                Preparing a secure connection…
              </p>
            </div>
          )}
        </div>
      </Modal>

      <Toaster
        position="bottom-right"
        toastOptions={{
          duration: 3000,
          style: {
            background: "var(--color-card-elevated)",
            color: "var(--color-foreground)",
            border: "1px solid var(--color-border)",
            borderRadius: "0.75rem",
            fontSize: "0.875rem",
          },
        }}
      />
    </>
  );
}
