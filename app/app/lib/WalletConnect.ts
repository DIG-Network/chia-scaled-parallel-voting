// ============================================================================
// WalletConnect.ts — Sage Wallet RPC bridge (mirrors streaming-ui pattern)
// ============================================================================
//
// MODULE: lib/WalletConnect
// PURPOSE: Singleton WalletConnect (`@walletconnect/sign-client`) wrapper
//          that talks to Sage Wallet (the canonical Chia-aware light
//          wallet that exposes the official Chia RPC methods over WC).
//
// SUPPORTED RPCs (Sage exposes; CHIP-0002 + native chia_*):
//   * chia_getAddress              — current XCH address (bech32m)
//   * chia_send                    — send XCH or a CAT to an address
//   * chip0002_getPublicKeys       — synthetic pubkeys for the active key
//   * chip0002_signCoinSpends      — sign an unsigned coin-spend list
//   * chip0002_sendTransaction     — push a signed bundle
//
// We also want to ALWAYS keep the wallet-connect singleton outside
// React state — exactly one instance per page load. See
// `walletConnectInstance.ts` for the singleton.

import SignClient from "@walletconnect/sign-client";
import { SessionTypes } from "@walletconnect/types";
import { toast } from "react-hot-toast";
import { store } from "../redux/store";
import {
  initialize,
  generateQrCode,
  disconnect,
} from "../redux/walletSlice";
import type { SpendBundleJson } from "./coinset";

/** JSON-shaped Coin matching the WalletConnect/Sage RPC convention. */
export class WalletConnectCoin {
  parent_coin_info: string;
  puzzle_hash: string;
  amount: number;
  constructor(parentCoinInfo: string, puzzleHash: string, amount: number) {
    this.parent_coin_info = parentCoinInfo;
    this.puzzle_hash = puzzleHash;
    this.amount = amount;
  }
}

/** JSON-shaped CoinSpend matching the WalletConnect/Sage RPC convention. */
export class WalletConnectCoinSpend {
  coin: WalletConnectCoin;
  puzzle_reveal: string;
  solution: string;
  constructor(coin: WalletConnectCoin, puzzleReveal: string, solution: string) {
    this.coin = coin;
    this.puzzle_reveal = puzzleReveal;
    this.solution = solution;
  }
}

export class WalletConnect {
  private client: SignClient | undefined;
  private initPromise: Promise<void>;

  constructor() {
    this.initPromise = this.init();
  }

  private async init() {
    // SSR GUARD: even though the app is configured for static
    // export (`output: "export"` in `next.config.ts`), Next still
    // prerenders every page once at build time. The prerender
    // runs in Node where `indexedDB` doesn't exist — and
    // `SignClient.init` opens an IndexedDB store via
    // `@walletconnect/keyvaluestorage`. Skip the init server-side
    // and let it run when the browser actually mounts.
    if (typeof window === "undefined") {
      // Resolve the init promise so `waitForInit()` doesn't
      // hang for SSR consumers (none today, but cheap insurance).
      return;
    }
    try {
      await this.initClient();
      await this.restorePreviousSession();
    } catch (error) {
      console.error("Failed to initialize WalletConnect:", error);
      store.dispatch(initialize({}));
    }
  }

  public async waitForInit(): Promise<void> {
    await this.initPromise;
  }

  private async restorePreviousSession() {
    if (!this.client) {
      store.dispatch(initialize({}));
      return;
    }
    try {
      const sessions = this.client.session.getAll();
      for (const session of sessions) {
        if (this.client.session.keys.includes(session.topic)) {
          const address = await this.getAddressFromSession(session);
          if (address) {
            this.setupEventListeners();
            store.dispatch(initialize({ session, address }));
            return;
          }
        }
      }
      store.dispatch(initialize({}));
    } catch (error) {
      console.error("Failed to restore session:", error);
      store.dispatch(initialize({}));
    }
  }

  private async initClient(): Promise<SignClient | undefined> {
    if (this.client) return this.client;
    const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID;
    if (!projectId) {
      // Surfacing this loudly avoids the cryptic
      //   "Failed to load resource: the server responded with a status of 400"
      // that the WalletConnect relay returns when handed an empty
      // projectId. Get a free one from https://cloud.reown.com
      // (formerly cloud.walletconnect.com) and put it in
      // `app/.env.local` as `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=…`.
      const msg =
        "Missing NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID. " +
        "Create one at https://cloud.reown.com and add it to app/.env.local " +
        "(then restart `npm run build && npm run serve`).";
      console.error("[CHIP/WalletConnect]", msg);
      toast.error(msg, { duration: 8000 });
      return undefined;
    }
    try {
      // Pin metadata.url to the page's actual origin. WalletConnect
      // emits a console warning if these differ ("metadata.url
      // differs from the actual page url"), and Sage's verification
      // pipeline can flag the dApp as suspicious. Letting this be
      // dynamic means the same build serves localhost dev,
      // staging, and prod without rebuilding.
      const origin =
        typeof window !== "undefined" && window.location
          ? window.location.origin
          : "https://voting.dig.net";
      this.client = await SignClient.init({
        logger: "error",
        projectId,
        metadata: {
          name: "CHIP Voting",
          description:
            "On-chain voting on Chia (Election Singleton + CAT collateral)",
          url: origin,
          icons: ["https://avatars.githubusercontent.com/u/37784886"],
        },
      });
      this.setupEventListeners();
      return this.client;
    } catch (e) {
      console.error("Failed to initialize WalletConnect client:", e);
      toast.error(`WalletConnect init failed: ${(e as Error)?.message ?? e}`);
      return undefined;
    }
  }

  private setupEventListeners() {
    if (!this.client) return;
    this.client.on("session_delete", this.handleSessionDelete);
    this.client.on("session_expire", this.handleSessionExpire);
    this.client.on("session_update", this.handleSessionUpdate);
  }

  private handleSessionDelete = () => this.disconnectWallet();
  private handleSessionExpire = () => this.disconnectWallet();
  private handleSessionUpdate = async () => {
    const state = store.getState();
    if (state.wallet.session?.topic) {
      const address = await this.getAddressFromSession(state.wallet.session);
      if (address) {
        store.dispatch(initialize({ session: state.wallet.session, address }));
      }
    }
  };

  async connectWallet(): Promise<boolean> {
    try {
      const client = await this.initClient();
      if (!client) return false;
      // CHIA NAMESPACE — Sage Wallet's CHIP-0002 / native chia_*
      // methods. Two notes:
      //   1. We declare these under `optionalNamespaces`. WalletConnect
      //      2.x deprecated `requiredNamespaces` (and silently
      //      forwards them to `optionalNamespaces` with a console
      //      warning, but Sage's approval flow rejects sessions
      //      whose chia namespace arrived via the deprecated path
      //      with "missing chia namespace"). Sending under the
      //      current key is the canonical fix.
      //   2. We list every method the dApp will ever request. Sage
      //      surfaces an approval UI keyed off this list — anything
      //      not declared here is rejected at request time even if
      //      the wallet supports it.
      const namespaces = {
        chia: {
          methods: [
            "chia_getAddress",
            "chia_send",
            "chip0002_getPublicKeys",
            "chip0002_signCoinSpends",
            "chip0002_sendTransaction",
          ],
          chains: ["chia:mainnet"],
          events: [],
        },
      };
      const { uri, approval } = await client.connect({
        optionalNamespaces: namespaces,
      });
      if (!uri) return false;
      store.dispatch(generateQrCode(uri));
      try {
        const session = await approval();
        const address = await this.getAddressFromSession(session);
        if (address) {
          store.dispatch(initialize({ session, address }));
          toast.success("Connected to wallet!");
          return true;
        }
      } catch (error) {
        console.error("Connection approval failed:", error);
        toast.error("Failed to connect wallet");
        store.dispatch(disconnect());
      }
      return false;
    } catch (error) {
      console.error("Connection failed:", error);
      toast.error("Failed to connect wallet");
      return false;
    }
  }

  private async getAddressFromSession(
    session: SessionTypes.Struct
  ): Promise<string | undefined> {
    if (!this.client) return undefined;
    try {
      const response = await this.client.request<{ address: string }>({
        topic: session.topic,
        chainId: "chia:mainnet",
        request: { method: "chia_getAddress", params: {} },
      });
      return response.address;
    } catch (error) {
      console.error("Failed to get address:", error);
      return undefined;
    }
  }

  /**
   * Send XCH or a CAT to `address`. `assetId === ""` (or null) sends
   * XCH; otherwise it's a CAT asset id (32-byte hex). `amount` and
   * `fee` are in mojos (XCH=1e12 mojos, CAT=1e3 mojos / token).
   */
  async sendAsset(
    assetId: string | null,
    address: string,
    amount: string,
    fee: string,
    memos: string[]
  ): Promise<boolean> {
    if (!this.client) return false;
    const state = store.getState();
    try {
      await this.client.request<{}>({
        topic: state.wallet.session?.topic ?? "",
        chainId: "chia:mainnet",
        request: {
          method: "chia_send",
          params: { assetId, address, amount, fee, memos },
        },
      });
      return true;
    } catch (error) {
      console.error("Failed to send:", error);
      return false;
    }
  }

  /** Get a page of synthetic pubkeys (one per account index). */
  async getPublicKeys(
    limit: number,
    offset: number
  ): Promise<string[] | undefined> {
    if (!this.client) return undefined;
    const state = store.getState();
    try {
      const response = await this.client.request<string[]>({
        topic: state.wallet.session?.topic ?? "",
        chainId: "chia:mainnet",
        request: {
          method: "chip0002_getPublicKeys",
          params: { limit, offset },
        },
      });
      return response;
    } catch (error) {
      console.error("Failed to get public keys:", error);
      return undefined;
    }
  }

  /**
   * Sign + (optionally) auto-submit a list of coin spends. Returns
   * the aggregated BLS signature (96-byte hex, possibly `0x`-prefixed)
   * when `auto_submit=false`. When `auto_submit=true`, Sage broadcasts
   * the signed bundle itself (streaming-ui convention); the return
   * value may still be the aggregated signature hex for local assembly.
   */
  async signCoinSpends(
    coinSpends: WalletConnectCoinSpend[],
    partial: boolean,
    auto_submit: boolean
  ): Promise<string | undefined> {
    if (!this.client) return undefined;
    const state = store.getState();
    try {
      const response = await this.client.request<string>({
        topic: state.wallet.session?.topic ?? "",
        chainId: "chia:mainnet",
        request: {
          method: "chip0002_signCoinSpends",
          params: { coinSpends, partial, auto_submit },
        },
      });
      return response;
    } catch (error) {
      console.error("Failed to sign coin spends:", error);
      return undefined;
    }
  }

  /**
   * Push a signed spend bundle through Sage (`chip0002_sendTransaction`).
   * The CHIP Voting app prefers `coinset.pushTx(...)` instead (streaming-ui pattern)
   * for reliable mempool acknowledgement; keep this only for experiments or
   * wallets that disallow third-party relays.
   */
  async sendSpendBundle(spendBundle: SpendBundleJson): Promise<void> {
    if (!this.client) {
      throw new Error("WalletConnect not initialized.");
    }
    const state = store.getState();
    const topic = state.wallet.session?.topic;
    if (!topic) {
      throw new Error("No active WalletConnect session.");
    }
    const raw = await this.client.request({
      topic,
      chainId: "chia:mainnet",
      request: {
        method: "chip0002_sendTransaction",
        params: { spendBundle },
      },
    });
    this.assertMempoolAckOk(raw);
  }

  /** CHIP-0002 `TransactionResp` / `transaction_ack`; tolerate array or single ack. */
  private assertMempoolAckOk(raw: unknown): void {
    const ack: { status?: number; error?: string } = Array.isArray(raw)
      ? (raw.length > 0 && raw[0] && typeof raw[0] === "object"
          ? (raw[0] as { status?: number; error?: string })
          : {})
      : raw && typeof raw === "object"
        ? (raw as { status?: number; error?: string })
        : {};
    const blob = `${ack.error ?? ""}`.toUpperCase();
    if (blob.includes("ALREADY_INCLUDING_TRANSACTION")) {
      return;
    }
    const status = ack.status ?? 3;
    if (status === 1 || status === 2) {
      return;
    }
    throw new Error(
      ack.error?.trim() ??
        `Sage rejected mempool submit (CHIP-0002 status ${status}, 3=FAILED).`
    );
  }

  async disconnectWallet() {
    const state = store.getState();
    if (this.client && state.wallet.session?.topic) {
      try {
        await this.client.disconnect({
          topic: state.wallet.session.topic,
          reason: { code: 6000, message: "User disconnected." },
        });
      } catch (e) {
        console.error("Error disconnecting:", e);
      }
    }
    store.dispatch(disconnect());
    toast.success("Disconnected from wallet");
  }

  isConnected(): boolean {
    return !!store.getState().wallet.address;
  }

  getActiveAddress(): string | undefined {
    return store.getState().wallet.address;
  }
}
