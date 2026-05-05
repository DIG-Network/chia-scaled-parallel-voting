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
      toast.success("Link copied!");
      setTimeout(() => setIsCopied(false), 1000);
    } catch {
      toast.error("Failed to copy");
    }
  };

  return (
    <>
      {!isInitialized || !address ? (
        <button onClick={handleConnect} className="btn-primary">
          Connect Wallet
        </button>
      ) : (
        <div className="flex items-center gap-3">
          <span className="mono text-[var(--color-muted)]">
            {truncHex(address, 7, 4)}
          </span>
          <button
            onClick={() => walletConnect.disconnectWallet()}
            className="btn-secondary text-sm"
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
              <div className="bg-white p-4 rounded-lg">
                <QRCodeSVG value={qrUri} size={256} />
              </div>
              <button
                onClick={handleCopyLink}
                className={`btn-secondary text-sm ${
                  isCopied ? "text-[var(--color-accent)]" : ""
                }`}
              >
                {isCopied ? "Copied!" : "Copy Link"}
              </button>
              <p className="text-sm text-center text-[var(--color-muted)] mt-1">
                Scan in Sage Wallet, or copy the link and paste it
                into the WalletConnect dialog.
              </p>
            </>
          ) : (
            <div className="flex items-center justify-center p-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[var(--color-accent)]" />
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
          },
        }}
      />
    </>
  );
}
