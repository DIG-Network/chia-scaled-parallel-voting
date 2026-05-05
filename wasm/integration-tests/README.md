# `chip-voting-wasm` integration tests

Node.js port of `cli/src/bin/live_integration_test.rs` that exercises the
wasm bindings instead of calling the SDK directly. Validates that every
wasm export round-trips correctly against live mainnet via `coinset.org`
+ a JS-side `JsChainBackend`.

## Setup

```bash
# 1. Build wasm for the nodejs target (overwrites wasm/pkg-node)
cd wasm
wasm-pack build --target nodejs --out-dir pkg-node

# 2. Install the harness's local file: dep
cd integration-tests
npm install

# 3. Run
node live_integration.mjs
```

## What it covers

### Stage A — read-side (this commit, working)

Validates the wasm imports cleanly into Node, the `JsChainBackend`
adapter integrates with `coinset.org`, and `chia-protocol` `Bytes32`
serde produces the documented 0x-prefixed hex format.

- **Phase 0** — wasm `init()` runs, `coinset.org` reachable, mainnet
  peak height surfaces a plausible value.
- **Phase 1** — pure-helper exports (`canonicalVoteMessage`,
  `standardPuzzleHash`, `voterHint`, `catOuterPuzzleHash`) all
  round-trip without throwing.
- **Phase 2** — chain-walking read exports (`listBallots`,
  `getBallot`) drive a real coinset.org HTTP round-trip via
  `JsChainBackend`. Defaults to a synthesised minimal config
  pointing at a non-existent launcher (proves the chain wiring
  works without requiring a deployed election); pass
  `--config <path-to-election-config.json>` to exercise against a
  real on-chain election.

### Stage B — write-side (pending)

The Rust live test's spending phases (deploy / register /
create_ballot / launch_ballot / vote / finalize / release) each
require JS-side ceremony pieces that the SDK currently delegates to
`dig-l1-wallet`:

- BIP39 mnemonic → BLS secret derivation (chia path
  `m/12381/8444/...`)
- XCH funder pre-spend construction (`StandardLayer` puzzle +
  signing with the funder secret)
- CAT issuance / transfer pre-spend construction (the
  `chia-sdk-driver::Cat` primitive)
- SpendBundle assembly via `wasm.assembleSpendBundle`
- Bundle push via `coinset.org /push_tx`
- Confirmation polling via `coinRecordByName`

Wiring this would mirror `live_integration_test.rs` lines 1123–2400.
The pieces all exist in the chia ecosystem (`chia-wallet-sdk-wasm`
covers most puzzle math; `bip39` + chia's BLS path live in
`chia_bls`'s wasm build) — it's just substantial JS plumbing.

## Flags

```
--config <path>        Path to an ElectionConfig JSON file. When
                       supplied, Phase 2 reads ballots from that
                       on-chain election; otherwise Phase 2 uses a
                       synthesised non-existent launcher.

--credentials <path>   Path to .test-credentials. Currently only
                       parsed in Phase 3+ (Stage B); Stage A doesn't
                       need keys.

--verbose / -v         Log every JsChainBackend call.
```

## Why two wasm-pack targets

The dApp (`app/`) consumes `wasm/pkg/` (built with `--target bundler`
for Webpack/Next.js/Vite). This harness consumes `wasm/pkg-node/`
(built with `--target nodejs` for Node's CommonJS-shaped wasm
loader). Same `lib.rs` — different glue.

Both build artifacts are gitignored.
