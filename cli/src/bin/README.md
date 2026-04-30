# `chip-voting-live-test` — live-network integration test

A standalone binary that drives the **complete** election lifecycle
against a real Chia network:

```
PHASE 0:  Trusted-setup ceremony (single-party SimulatedBackend)
PHASE 1:  Deploy Election Singleton (broadcast + wait_for_confirmation)
PHASE 2:  Register voter1 → wait spent + confirmed
          Register voter2 → wait spent + confirmed
PHASE 3:  Wait for `--election-length-blocks` to elapse on chain
PHASE 4:  voter1 votes → wait spent
          voter2 votes → wait spent
PHASE 5:  Aggregator collects votes + builds Groth16 proof + finalizes
PHASE 6:  voter1 releases collateral → wait spent
          voter2 releases collateral → wait spent
```

Every phase is gated on `chia_query::ChiaQuery::wait_for_confirmation`
so the script never advances on a coin that hasn't actually landed in
a block.

**After any change** to the SDK, puzzles, or this binary, run the live
test to completion (`PHASE 0` → `PHASE 6` exit 0) before merging. It
exercises real RPC, confirmations, and spends that unit tests do not
cover.

## Quick start

```bash
# Make sure you have a .test-credentials file in the CHIP root
# (see CHIP/.test-credentials for the expected format).
# It is gitignored — never commit it.

cd CHIP
cargo run --release --bin chip-voting-live-test -- \
    --credentials ./.test-credentials \
    --network mainnet \
    --collateral-amount 1000 \
    --election-length-blocks 4 \
    --yes      # skip per-phase confirmation prompts
```

`--collateral-amount 1000` = **1 DIG** (Chia CATs use 3-decimal
precision: 1 token = 1000 mojos).

## Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--credentials` | `.test-credentials` | Path to the credentials file. |
| `--network` | from credentials | `mainnet` / `testnet11` override. |
| `--cat-tail-hash` | DIG mainnet asset id | CAT TAIL hash for voter collateral. |
| `--collateral-amount` | `1000` | Per-voter CAT collateral, in mojos. Default = 1 DIG (1 token = 1000 mojos). |
| `--registration-fee` | `0` | XCH fee per registration. |
| `--election-length-blocks` | `4` | `ASSERT_HEIGHT_RELATIVE` window. ~52s/block on mainnet. |
| `--launcher-amount` | `1` | Singleton launcher coin amount. |
| `--poll-interval-secs` | `8` | Confirmation poll interval. |
| `--confirmation-timeout-secs` | `900` | Per-phase timeout. |
| `--skip-release` | off | Stop after finalize; leave registration coins on-chain. |
| `--yes` / `-y` | off | Skip confirmation prompts (CI-friendly). |
| `--verbose` / `--trace` | off | Bumps tracing level. |

## Credentials format

Operator-friendly `KEY=VALUE` lines plus `# Mnemonic: ...` comment
lines. The script reads three blocks:

```
WALLET_NAME=l2-funding
WALLET_NETWORK=mainnet
WALLET_ADDRESS=xch1...
# Mnemonic: 24 words ...

VALIDATOR1_WALLET_NAME=validator1-mainnet
VALIDATOR1_PUBKEY=0x... (account pubkey, used as a sanity check)
VALIDATOR1_ADDRESS=xch1...
# Mnemonic: 24 words ...

VALIDATOR2_WALLET_NAME=validator2-mainnet
VALIDATOR2_PUBKEY=0x...
VALIDATOR2_ADDRESS=xch1...
# Mnemonic: 24 words ...
```

The funding wallet must have:
- An XCH coin worth `≥ --launcher-amount` mojos to back the launcher.

Each validator wallet must have:
- A CAT coin (asset id = `--cat-tail-hash`) worth `≥
  --collateral-amount` mojos.

The script DOES spend real XCH (transaction-mojo dust) and real CAT
(`--collateral-amount` per voter). On the happy path (release phase
runs), the CAT is returned to the same wallet's standard puzzle hash.

## Cost on mainnet

- **Time:** ~10–15 minutes wall-clock with `--election-length-blocks 4`
  (mainnet's 52s blocks dominate the budget).
- **XCH:** the launcher coin is currently destroyed by the singleton's
  finalize action; budget `--launcher-amount` mojos (default 1) plus
  any per-spend fees the network demands (default 0).
- **CAT:** `2 × --collateral-amount` mojos locked during the election;
  returned at release.

## Architecture

A single `bin/live_integration_test.rs` file with these sections:

1. CLI parsing
2. `.test-credentials` parsing
3. Wallet key derivation (BIP-39 → BLS master → wallet-unhardened →
   `derive_synthetic` → standard p2 puzzle hash)
4. `chia_query` helpers (`wait_for_confirmation`, `wait_for_spend`,
   `current_peak_height`, `wait_for_block_height`, XCH/CAT coin
   discovery)
5. CAT collateral spend builder (uses `chia_sdk_driver::Cat::spend_all`
   to assemble a CAT spend that creates the registration coin at the
   exact CAT-wrapped puzzle hash and emits the
   `CreateCoinAnnouncement` `puzzles/election/register.rue` asserts)
6. Phase implementations (`phase_deploy`, `phase_register_voter`,
   `phase_wait_window`, `phase_vote`, `phase_finalize`,
   `phase_release`)
7. Helpers (`push_tx`, `verify_bundle_locally`, `confirm_or_bail`,
   `make_independent_chain`)
8. `main()` orchestrator

Pre-broadcast bundle verification goes through
`chip_voting_sdk::verify_bundle_signatures` which calls
`chia_sdk_signer::RequiredSignature::from_coin_spends` and
`chia_bls::aggregate_verify` — the same checks the network would apply,
locally, before any RPC traffic.

## Offline tests

Four unit tests cover the offline plumbing:

- `parse_credentials_extracts_all_three_wallets`
- `parse_credentials_rejects_missing_mnemonic`
- `derive_wallet_keys_is_deterministic`
- `compute_create_reg_msg_matches_register_rue_formula`

Run with `cargo test --bin chip-voting-live-test`.

## Known limitations

- The single-party `SimulatedBackend` ceremony is **NOT
  cryptographically sound** (the toxic waste is recoverable from the
  public transcript). It IS structurally identical to a real ceremony's
  output — the deploy / finalize plumbing is validated on a real chain.
  For production deploys, run a real multi-party ceremony via
  `chip-voting ceremony {init,contribute,accept,finalize}`.

- The voter's BLS key is intentionally REUSED from the validator's
  synthetic SK so the credentials file is self-contained. Production
  deployments should rotate per-election BLS keys (see
  `chip-voting wallet generate-key`).

- Each registration is sequential (voter1 → wait → voter2 → wait) so
  every phase's effects are observable at well-defined block heights.
  Parallelising is straightforward but obscures the per-phase
  confirmations the integration test is meant to surface.
