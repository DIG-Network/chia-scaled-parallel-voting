import type { NextConfig } from "next";

// CRITICAL: this app runs as a pure client-side SPA via Next.js's
// static export (`output: "export"`). There is no server-side
// rendering, no API routes, no edge runtime — the build emits a
// `out/` directory of static HTML/JS/wasm that any CDN can serve.
//
// WHY STATIC EXPORT:
//   * WalletConnect's `SignClient` opens an IndexedDB store at
//     construction time (via `@walletconnect/keyvaluestorage`).
//     IndexedDB doesn't exist in Node, so any SSR pass crashes
//     with `ReferenceError: indexedDB is not defined`.
//   * The `chip-voting-wasm` package is a 1.6 MB Rust→wasm bundle
//     that's pointless to ship to the server (every consumer is
//     in the browser).
//   * Sage Wallet integration is inherently client-side — it
//     talks to a wallet running on the user's device.
//
// CONSEQUENCE: dynamic route segments like `[launcherId]` are not
// supported in pure export mode (would require a fixed
// `generateStaticParams` list at build time). We use query-string
// routing instead: `/election/?id=<launcher_id_hex>`.
//
// WEBPACK CONFIG: required so Webpack 5 supports `.wasm` modules
// (default is off). The `webassemblyModuleFilename` shape is
// taken from the official Next.js wasm example. `pino-pretty` /
// `lokijs` / `encoding` are silenced — they're optional dev-time
// deps of `@walletconnect/sign-client` the browser bundle never
// needs.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,

  // Static export disables Next.js's image optimisation server,
  // so we ask Next to skip the loader (we don't use <Image/>
  // anywhere in the app yet, but flip this on now to be explicit).
  images: { unoptimized: true },

  // Prevents Next from trying to lint/typecheck the full route tree
  // during the export pass — keeps the build snappy. (`tsc` is
  // still run by `next build` in its own pre-build step.)
  eslint: { ignoreDuringBuilds: true },

  webpack(config, { isServer, dev }) {
    config.externals.push("pino-pretty", "lokijs", "encoding");

    config.output.webassemblyModuleFilename =
      isServer && !dev
        ? "../static/wasm/[modulehash].wasm"
        : "static/wasm/[modulehash].wasm";

    config.experiments = { ...config.experiments, asyncWebAssembly: true };

    return config;
  },
};

export default nextConfig;
