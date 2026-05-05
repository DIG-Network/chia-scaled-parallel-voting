# CHIP Voting — Next.js dApp

Browser front-end for on-chain voting on Chia. Imports the local
`chip-voting-wasm` package (built from `../wasm/`), talks to Sage
Wallet via WalletConnect for signing + balance, and reads chain
state from `api.coinset.org`.

## Quick start

```bash
# 1. Build the wasm package (one-time, requires clang on PATH for blst)
cd ../wasm && wasm-pack build --target bundler --release && cd ../app

# 2. Install + configure
npm install
cp .env.local.example .env.local
# edit .env.local — paste your free WalletConnect Cloud project id

# 3. Run
npm run dev
# open http://localhost:3000
```

## Architecture

```
   ┌──────────────────────────────────────────────────────────────┐
   │  Browser (this app)                                            │
   │                                                                 │
   │  ┌──────────────┐    ┌────────────────────┐                   │
   │  │ React UI     │───▶│ chip-voting-wasm   │                   │
   │  │ (Tailwind)   │    │  - puzzle hashes    │                   │
   │  └──────────────┘    │  - ceremony         │                   │
   │         │            │  - deploy assembly  │                   │
   │         │            │  - signing          │                   │
   │         ▼            └────────────────────┘                   │
   │  ┌──────────────┐                                              │
   │  │ Redux store  │                                              │
   │  │ (wallet)     │                                              │
   │  └──────────────┘                                              │
   │         │                                                       │
   │         ▼                                                       │
   │  ┌──────────────────────┐    ┌─────────────────────────────┐  │
   │  │ WalletConnect (Sage) │    │ coinset.org HTTP fetch       │  │
   │  │  - chia_send         │    │  - get_coin_records_by_*     │  │
   │  │  - chip0002_sign…    │    │  - get_blockchain_state      │  │
   │  └──────────────────────┘    │  - push_tx                   │  │
   │                                └─────────────────────────────┘  │
   └──────────────────────────────────────────────────────────────┘
```

## Pages

| Route                      | Purpose                                        |
|----------------------------|------------------------------------------------|
| `/`                        | List of locally-tracked elections + balances   |
| `/create`                  | New election form (ceremony + deploy)          |
| `/election/[launcherId]`   | Election detail (config + state + actions)     |

## Status

| Feature                        | Status                            |
|--------------------------------|-----------------------------------|
| Connect Sage Wallet            | ✓                                 |
| List local elections           | ✓                                 |
| Show XCH balance               | ✓                                 |
| Show DIG balance               | partial (tail-aware lookup TODO)  |
| Create election (deploy)       | ✓ (ceremony + bundle + WC sign)   |
| Import election config         | ✓                                 |
| Display election parameters    | ✓                                 |
| Live registration count        | TODO (lineage walk via wasm)      |
| Register                       | TODO (CAT collateral spend wrap)  |
| Vote                           | TODO                              |
| Finalize                       | TODO (browser Groth16 prover)     |
| Release collateral             | TODO                              |

## Critical: WASM imports

Components that touch wasm MUST be imported via `dynamic(async () =>
{ const wasm = await import("chip-voting-wasm"); return Component;
}, { ssr: false })`. Top-level `import "chip-voting-wasm"` crashes
Next.js's prerender pass with `ReferenceError: window is not defined`
or `WebAssembly.instantiate is not a function`. This pattern is
inherited from the
[streaming-ui reference](https://github.com/dig-network/streaming-ui).

The pattern is enforced in `app/components/WalletBalances.tsx`,
`app/create/page.tsx`, and `app/election/[launcherId]/page.tsx`.

`next.config.ts` also requires `experiments.asyncWebAssembly = true`
plus the `webassemblyModuleFilename` tweak.

## Build

```bash
npm run build
# Output: .next/  (deploy via Vercel, Netlify, etc. — pure static)
```
