// ============================================================================
// walletConnectInstance.ts — page-global WalletConnect singleton
// ============================================================================
//
// MODULE: lib/walletConnectInstance
// PURPOSE: One `WalletConnect` instance per page load. Constructed
//          eagerly because the app runs in pure-SPA mode
//          (`output: "export"` in `next.config.ts`) — there is no
//          server-side rendering pass to worry about, so we don't
//          need lazy / `typeof window` guards. This mirrors the
//          streaming-ui reference 1:1.

import { WalletConnect } from "./WalletConnect";

export const walletConnect = new WalletConnect();
export default walletConnect;
