"use client";

import { useEffect } from "react";
import { walletConnect } from "../lib/walletConnectInstance";

/**
 * Mounts once at the top of the app to kick off WalletConnect's
 * `init()` (peer client setup + previous-session restore). Renders
 * nothing — the actual wallet UI lives in `WalletConnector`.
 */
export default function WalletInitializer() {
  useEffect(() => {
    walletConnect
      .waitForInit()
      .then(() => console.log("WalletConnect ready"))
      .catch((err) => console.error("WalletConnect init failed:", err));
  }, []);
  return null;
}
