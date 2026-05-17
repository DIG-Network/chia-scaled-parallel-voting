# Parallel voting on Chia

Reference implementation and **CHIP draft** for large-scale, permissionless voting on [Chia](https://www.chia.net/): an **Election Singleton** orchestrates registration and ballot issuance; **Registration**, **Ballot**, and **Voting** coins separate enrollment from parallel votes; each ballot finalizes with **Groth16** and an aggregate **BLS** check on-chain ([CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md)). Inner actions follow the [CHIP-0050](https://github.com/Yakuhito/chips/blob/b23ed49e00164cbc62b9b6ae4d48071930c5b1d2/CHIPs/chip-0050.md) action layer. A **ceremony** lineage produces the circuit verification key used at election deploy.

**Maintainer:** [DIG Network](https://github.com/DIG-Network) · **Repository:** [github.com/DIG-Network/chia-parallel-voting](https://github.com/DIG-Network/chia-parallel-voting)

## Quick deploy (web app)

Run the Next.js dApp in [`app/`](app/) (uses [`chip-voting-wasm`](wasm/) via `file:../wasm/pkg`). You need **Rust**, **`wasm-pack`**, and a C toolchain on `PATH` (**`clang`** is required to build **`blst`** for WASM). **Node.js 20+** recommended.

```bash
# From repository root
cd wasm && wasm-pack build --target bundler --release && cd ../app
npm install
cp .env.local.example .env.local
# Edit .env.local — set your WalletConnect Cloud project id
npm run dev
# Open http://localhost:3000
```

**Windows (PowerShell), same steps from repo root:**

```powershell
Set-Location wasm; wasm-pack build --target bundler --release; Set-Location ..\app
npm install
Copy-Item .env.local.example .env.local
npm run dev
```

More detail, architecture, and page routes: [`app/README.md`](app/README.md).

### SAGE Wallet (browser limits)

The dApp integrates **[SAGE Wallet](https://sagewallet.net/)** via **WalletConnect**. SAGE does **not** yet expose the **`SIGN_UNSAFE`** WalletConnect API that unsafe/CHIP-0002-style spend signing relies on, so you can only get **partway** through on-chain flows in the browser before the UI is blocked. The **CLI live integration tests** (e.g. `chip-voting-live-test`) already run the **full** election lifecycle end-to-end against a real network. Once SAGE adds the **`SIGN_UNSAFE`** endpoint, the browser app can be **completed** without changing this repository’s voting protocol.

## Features

- **Parallel voting lane** — `mint_voting_coin` / `update_vote` do not spend the election singleton.
- **Per-ballot finality** — `finalize` on the Ballot Coin verifies a constant-size Groth16 proof plus BLS aggregation over a canonical `vote_message`.
- **CAT-collateralized registration** — membership in a registration sparse Merkle tree; per-registration ballot trees enforce one voting lineage per ballot.
- **Trusted-setup ceremony** — contribute / finalize flow with voucher binding for `vk_hash` and deployment limits.
- **Rust SDK and CLI** — construct spends and bundles; callers push transactions (e.g. via `chia-query`).
- **WASM** — browser-side helpers for dApps; **Next.js app** under `app/` with **SAGE Wallet** (WalletConnect); see **SAGE Wallet (browser limits)** above.

## Documentation

CHIP text and normative companions with **links to source on `main`**: **[`docs/` on GitHub](https://github.com/DIG-Network/chia-parallel-voting/tree/main/docs)**.

| Resource | Description |
|----------|-------------|
| [docs/CHIP_DRAFT.md](docs/CHIP_DRAFT.md) | Main CHIP draft ([blob](https://github.com/DIG-Network/chia-parallel-voting/blob/main/docs/CHIP_DRAFT.md)) |
| [docs/README.md](docs/README.md) | Companion index + source map ([blob](https://github.com/DIG-Network/chia-parallel-voting/blob/main/docs/README.md)) |
| [sdk/README.md](sdk/README.md) | SDK architecture, crates, actors, and API overview |

Companion docs spell out inner actions, Merkle rules, public inputs, announcements, and end-to-end phases. Figures live in [`assets/`](assets/) · [GitHub tree](https://github.com/DIG-Network/chia-parallel-voting/tree/main/assets).

## Repository layout

| Path | Role |
|------|------|
| [`puzzles/`](puzzles/) | Chialisp (**Rue**) sources for election, ballot, registration, voting, and ceremony puzzles |
| [`puzzles/compiled/`](puzzles/compiled/) | Generated CLVM hex + puzzle hashes (run the build script after editing `.rue`) |
| [`sdk/`](sdk/) | `chip-voting-sdk` — actors, state, merkle helpers, Groth16 prover integration |
| [`cli/`](cli/) | `chip-voting` CLI and integration-test binaries |
| [`wasm/`](wasm/) | WASM bindings for wallets and UI |
| [`app/`](app/) | Next.js reference UI and internal migration / compliance notes |
| [`docs/`](docs/) | CHIP draft + normative companion Markdown |
| [`assets/`](assets/) | Diagrams referenced from the docs |

## Prerequisites

- **Rust** (2021 edition), stable toolchain
- **Rue** compiler on `PATH` — used by [`build.ps1`](build.ps1) / [`build.sh`](build.sh) (`rue build …`)

## Build

Compile puzzles first so `puzzles/compiled/` matches the `.rue` sources, then build the Rust workspace.

**Windows (PowerShell):**

```powershell
.\build.ps1
cargo build --workspace
```

**Linux / macOS:**

```sh
./build.sh
cargo build --workspace
```

Run SDK tests from the `sdk` crate (see [`sdk/README.md`](sdk/README.md) for fuller workflows):

```sh
cd sdk
cargo test
```

## CLI

The primary binary is **`chip-voting`** (package `chip-voting-cli`):

```sh
cargo run -p chip-voting-cli -- --help
```

## License

MIT — see workspace `Cargo.toml` and crate manifests.

## Standards

This project targets interoperability with:

- [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md) — BLS12-381 / pairing operations in CLVM  
- [CHIP-0050](https://github.com/Yakuhito/chips/blob/b23ed49e00164cbc62b9b6ae4d48071930c5b1d2/CHIPs/chip-0050.md) — action-layer singleton pattern  

The authoritative protocol text for this repo is the Markdown under [`docs/`](docs/), not this README.
