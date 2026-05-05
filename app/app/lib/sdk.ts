// ============================================================================
// sdk.ts — lazy WASM loader for `chip-voting-wasm`
// ============================================================================
//
// MODULE: lib/sdk
// PURPOSE: Centralise the dynamic-import pattern that loads the
//          `chip-voting-wasm` package. The streaming-ui reference
//          (where this approach was originally proven) uses
//          `dynamic(async () => { const wasm = await import(...)
//          ; return Component })` for any component that calls
//          into wasm — we follow the same shape inside React
//          components themselves, but for non-component utilities
//          (helpers called from event handlers / effects) we expose
//          the SDK through this `getWasm()` accessor (`web` &
//          `bundler` wasm-pack targets both supported — see loader).
//
// WHY LAZY: Next.js prerenders pages on the server. Importing the
// wasm package at module-top-level crashes the prerender pass with
// "WebAssembly.instantiate" / "ReferenceError: window is not
// defined" depending on the bundling stage. A `'use client'`
// directive plus a dynamic `await import(...)` inside an effect
// (or inside a `dynamic(..., {ssr: false})` factory) is the
// supported workflow.
//
// USAGE FROM A COMPONENT (preferred):
//
//   export default dynamic(
//     async function DynamicElem() {
//       const wasm = await getWasm(); // works for wasm-pack `--target web` or `bundler`
//       return function MyComponent() {
//         // ... use wasm.* freely here
//       };
//     },
//     { ssr: false, loading: () => <Spinner /> }
//   );
//
// USAGE FROM AN EFFECT / EVENT HANDLER:
//
//   const handleClick = async () => {
//     const wasm = await getWasm();  // cached after first call
//     const summary = wasm.parseElectionConfig(json);
//     ...
//   };

let cached: typeof import("chip-voting-wasm") | null = null;
let loading: Promise<typeof import("chip-voting-wasm")> | null = null;

/**
 * Lazily load (or return the cached) `chip-voting-wasm` module.
 * Safe to call from anywhere on the client; throws on the server
 * (you should be inside `'use client'` + an effect / handler).
 */
export async function getWasm(): Promise<typeof import("chip-voting-wasm")> {
  if (cached) return cached;
  if (loading) return loading;
  loading = (async () => {
    const wasm = await import("chip-voting-wasm");
    // `--target web`: `default()` async-instantiates `.wasm` before exports work.
    // `--target bundler` (our `wasm-pack build` default): WASM starts in the glue
    // entry — there is no `default` export.
    const d = wasm as { default?: unknown };
    if (typeof d.default === "function") {
      await (d.default as () => Promise<unknown>)();
    }
    wasm.init();
    cached = wasm;
    return wasm;
  })();
  return loading;
}

/** Re-export the WasmNetwork enum for convenient typed access. */
export type WasmModule = typeof import("chip-voting-wasm");
