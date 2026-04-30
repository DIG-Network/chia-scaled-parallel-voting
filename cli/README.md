# `chip-voting` — CLI for the Chia voting CHIP

Production command-line interface for the Chia voting CHIP. Wraps
`chip-voting-sdk` with a clap-based shell so each actor (Deployer,
Voter, Aggregator, Indexer) plus the MPC trusted-setup ceremony can
be driven from the terminal.

```text
chip-voting <verb> <subcommand> [--global-flag] ... [--subcommand-flag] ...
```

## Build

```bash
cargo build --release -p chip-voting-cli
# binary lands at target/release/chip-voting (or .exe on Windows)
```

## Global flags

| Flag                       | Effect                                                           |
|----------------------------|------------------------------------------------------------------|
| `--network mainnet`        | Default. Selects mainnet AGG_SIG additional data + DNS seeds.    |
| `--network testnet11`      | Use testnet11 instead.                                           |
| `--rpc <url>`              | Override the coinset.org HTTP fallback URL.                      |
| `--json`                   | Emit structured JSON to stdout (logs still go to stderr).        |
| `-y` / `--yes`             | Skip "broadcast?" confirmation prompts (CI / scripting).         |
| `-v` / `--verbose`         | Bump log level to `debug`.                                       |
| `--trace`                  | Bump log level to `trace`.                                       |

## Verbs at a glance

| Verb         | What it does                                                              |
|--------------|---------------------------------------------------------------------------|
| `ceremony`   | Run / audit the Groth16 MPC trusted setup.                                |
| `deployer`   | Deploy the Election Singleton (genesis spend).                            |
| `voter`      | Register / vote / release collateral as a single voter.                   |
| `aggregator` | Sync chain state, collect votes, build the finalize bundle.               |
| `indexer`    | Read-only chain state queries.                                            |
| `oracle`     | Permissionless oracle-action spend producer (read the (un)finalized vote result on-chain). |
| `wallet`     | BLS keygen + key inspection (no chain access).                            |
| `puzzle`     | Print embedded puzzle bytecode tree hashes (no chain access).             |

Run `chip-voting <verb> --help` for the full subcommand list under
each verb. Every subcommand has its own `--help` page.

## End-to-end walkthrough

This is the full happy path from "no election exists" to "election
finalized + collateral released".

### 1. Run the MPC ceremony (off-chain)

```bash
# Coordinator
chip-voting ceremony init \
    --circuit-id chip-voting-v1 \
    --output transcript.0.json

# Participant 1 (on an air-gapped machine)
#   * Generate 32 bytes of entropy from a HARDWARE RNG into entropy.bin.
chip-voting ceremony contribute \
    --input transcript.0.json \
    --output transcript.1.json \
    --participant-name alice \
    --message "contributed at chia-eve 2026" \
    --entropy-file entropy.bin

# Coordinator absorbs the contribution
chip-voting ceremony accept \
    --current transcript.0.json \
    --contribution transcript.1.json \
    --output transcript.1.json

# (repeat contribute + accept for each participant)

# Anyone can audit:
chip-voting ceremony verify --input transcript.N.json

# Coordinator extracts the final VK:
chip-voting ceremony finalize \
    --input transcript.N.json \
    --vk-output vk.json
```

> **Security**: every participant **MUST** run `contribute` on an
> air-gapped machine, supply true hardware entropy via
> `--entropy-file`, and securely erase that entropy file after the
> contribution. A single honest participant suffices for soundness;
> ALL participants must be malicious for the toxic-waste secret to
> leak.

### 2. Deploy the Election Singleton

```bash
# Off-chain prediction (no chain access — pre-computes the Election
# Singleton's puzzle hash so you can verify it).
chip-voting deployer predict-puzzle-hash \
    --vk-file vk.json \
    --cat-tail-hash 0x<governance_token_tail_hash> \
    --collateral-amount 1000 \
    --registration-fee 100 \
    --election-length-blocks 12096 \
    --parent-coin-id 0x<your_xch_coin_id>

# Dry-run: build + serialise the unsigned bundle.
chip-voting deployer dry-run \
    --vk-file vk.json \
    --cat-tail-hash 0x... --collateral-amount 1000 \
    --registration-fee 100 --election-length-blocks 12096 \
    --parent-coin-id 0x<coin_id> \
    --parent-puzzle-hash 0x<your_p2_puzzle_hash> \
    --parent-amount 1 \
    --parent-synthetic-pubkey 0x<your_synthetic_pk_48b> \
    --output-file unsigned-deploy.json

# Full deploy (build + sign + broadcast). Reads the synthetic
# secret from an env var to avoid shell-history exposure.
export PARENT_SK=0x<32_byte_synthetic_secret_hex>
chip-voting deployer deploy \
    --vk-file vk.json \
    --cat-tail-hash 0x... --collateral-amount 1000 \
    --registration-fee 100 --election-length-blocks 12096 \
    --parent-coin-id 0x... --parent-puzzle-hash 0x... \
    --parent-amount 1 \
    --parent-synthetic-pubkey 0x... \
    --parent-secret-env PARENT_SK \
    --config-output election-config.json \
    --bundle-output deploy-bundle.json
```

The deploy command writes `election-config.json` — this is the
canonical artifact every other participant needs (voters,
aggregator, indexer). Distribute it via your election's website.

### 3. Voter operations

Each voter generates a BLS keypair and uses it for the entire
election lifetime.

```bash
# 3a. Generate voter keys (DO THIS ONCE, OFFLINE)
chip-voting wallet generate-key --output-file voter-keys.json

# 3b. Inspect the voter's election-specific identifiers
export VOTER_SK=0x<32_byte_secret>
chip-voting voter status \
    --election-config election-config.json \
    --voter-secret-env VOTER_SK
# Prints: voter_pubkey, fresh_registration_puzzle_hash, voter_hint, slot.

# 3c. Register
chip-voting voter register \
    --election-config election-config.json \
    --voter-secret-env VOTER_SK \
    --wallet-name my-wallet \
    --unlock-password-env WALLET_PASSWORD \
    --bundle-fee 100 \
    --bundle-output register-bundle.json

# 3d. Vote
chip-voting voter vote \
    --election-config election-config.json \
    --voter-secret-env VOTER_SK \
    --vote-data 0x<32_byte_payload> \
    --wallet-name my-wallet \
    --unlock-password-env WALLET_PASSWORD

# 3e. Release collateral (after the election is finalized)
chip-voting voter release \
    --election-config election-config.json \
    --voter-secret-env VOTER_SK \
    --destination 0x<your_xch_puzzle_hash> \
    --wallet-name my-wallet \
    --unlock-password-env WALLET_PASSWORD
```

### 4. Aggregator (election close)

```bash
# 4a. Sync the chain state (also useful for diagnostics).
chip-voting aggregator sync --election-config election-config.json

# 4b. Collect every cast vote.
chip-voting aggregator collect-votes --election-config election-config.json \
    --json > votes.json

# 4c. Pure off-chain witness preparation — no proof generated, no
# chain writes. Verifies majority + BLS aggregation.
chip-voting aggregator prepare-witness \
    --election-config election-config.json \
    --votes-file votes.json \
    --vote-outcome 0x<32_byte_outcome>

# 4d. Build + sign + broadcast the finalize bundle.
chip-voting aggregator finalize \
    --election-config election-config.json \
    --votes-file votes.json \
    --vote-outcome 0x<outcome> \
    --reward-address 0x<your_p2_puzzle_hash> \
    --bundle-output finalize-bundle.json
```

### 5. Indexer (read-only monitoring)

```bash
# Print current state
chip-voting indexer status --election-config election-config.json

# List registered voters
chip-voting indexer voters --election-config election-config.json

# List cast votes (after voting starts)
chip-voting indexer votes --election-config election-config.json

# Print puzzle hashes for an arbitrary voter pubkey (no chain access).
chip-voting indexer puzzle-hashes \
    --election-config election-config.json \
    --voter-pubkey 0x<48b>
```

### 6. Oracle — assert the vote result in another puzzle

The Election Singleton's `oracle` action is permissionless and emits
a `CreateCoinAnnouncement` carrying either:

  * `sha256("oracle_finalized"   || vote_outcome || count_be8 || merkle_root)` (when finalized), or
  * `sha256("oracle_unfinalized" || count_be8     || merkle_root)`            (otherwise).

Distinct prefixes guarantee downstream puzzles can never confuse the
two variants. To assert against the announcement, your puzzle pairs
its spend with the oracle spend in the same bundle and emits
`AssertCoinAnnouncement { id: sha256(singleton_coin_id || message) }`
— the CLI prints both the message AND the precomputed
`announcement_id` for you.

```bash
# Read-only preview: which announcement (variant + message bytes)
# would the oracle emit RIGHT NOW?
chip-voting oracle predict \
    --election-config election-config.json
# Prints: variant ("finalized" | "unfinalized"), message,
# registration_count, registration_merkle_root, [vote_outcome].

# Build the SINGLE oracle CoinSpend for inclusion in your own
# bundle (alongside the spend(s) that assert the announcement).
chip-voting oracle build-spend \
    --election-config election-config.json \
    --output-file oracle-coin-spend.json
# Output JSON: { coin_spend, singleton_coin_id, announcement_id, ... }

# Build a STANDALONE bundle carrying only the oracle spend (no
# downstream caller — useful for notarising the result).
chip-voting oracle bundle \
    --election-config election-config.json \
    --output-file oracle-bundle.json

# Build + broadcast the standalone bundle (with confirmation prompt).
chip-voting oracle broadcast \
    --election-config election-config.json \
    --bundle-output oracle-bundle.json
```

The oracle action emits NO `AggSig*` conditions — no caller secret
keys are required. The bundle's aggregate signature is the BLS
identity element.

## Output formats

Every subcommand supports two output modes selected by the global
`--json` flag:

* **Human (default)**: indented `key = value` layout, easy to read in
  a terminal.
* **JSON (`--json`)**: pretty-printed `serde_json` output, ready to
  pipe into `jq` / scripts.

Logs (status / errors / progress) always go to **stderr**, so
piping JSON to disk won't pollute the file:

```bash
chip-voting --json indexer status \
    --election-config election-config.json > status.json 2> status.log
```

## Implementation status

| Verb / Subcommand                    | Status                                                                 |
|--------------------------------------|------------------------------------------------------------------------|
| `puzzle hashes`                      | Fully working (offline).                                               |
| `wallet generate-key` / `pubkey`     | Fully working (offline).                                               |
| `ceremony init` / `contribute` / `verify` / `finalize` / `accept` | Fully working with the `SimulatedBackend` (NOT cryptographically sound — for production swap in `phase2` or `arkworks-snark-mpc`). |
| `deployer predict-puzzle-hash`       | Fully working (offline).                                               |
| `deployer dry-run`                   | Fully working (offline).                                               |
| `deployer deploy`                    | Fully working — builds + signs + broadcasts.                           |
| `indexer status` / `voters` / `votes` / `puzzle-hashes` | Fully working for the eve case + lineage walk to the latest singleton. Per-spend voter-set reconstruction is best-effort (relies on emitted CreateCoinAnnouncements). |
| `aggregator sync` / `collect-votes` / `prepare-witness` | Sync walks the singleton lineage forward; collect-votes returns the empty set when no voters exist; prepare-witness runs all 6 pre-checks + BLS aggregation + scalar derivation. |
| `aggregator finalize`                | **Wired** to `Aggregator::build_finalize_with_proof`. Caller supplies the Groth16 proof JSON (produced by their prover service from the witness emitted by `prepare-witness`); the CLI assembles the action-layer + singleton spend, signs, and broadcasts. |
| `voter status`                       | Fully working (offline).                                               |
| `voter vote`                         | **Wired** end-to-end — locates the registration coin via hint, reconstructs the CAT lineage proof, builds the action-layer + CAT spend with the `vote` action, signs (AggSigUnsafe), broadcasts. |
| `voter release`                      | **Wired** end-to-end — paired bundle: Election Singleton's `announce_finalization` action + Registration Coin's `release` action with the announcer's coin id supplied via solution. |
| `voter register`                     | The Election Singleton half is **wired** (action layer + register-action curry), but the paired CAT issuance spend (`Cat::issue_with_coin`) needs to be supplied by the caller (the CAT-issuance helper has no zero-config path; in production the operator pairs this register bundle with their own CAT mint spend). The CLI surfaces a clear "needs CAT issuance" error pointing to the wiring point. |
| `oracle predict` / `build-spend` / `bundle` / `broadcast` | Fully working — walks the singleton lineage to find the latest unspent coin, builds the action-layer + singleton spend with the `oracle` action selected, and either emits the `CoinSpend` JSON for embedding in another bundle or assembles a standalone bundle (no AggSig conditions, BLS-identity signature). |

### What's wired in the SDK

Every action method now lives in [`sdk/src/actors/`](../sdk/src/actors/) and uses the shared
[`sdk/src/action_spends.rs`](../sdk/src/action_spends.rs) helpers for:

* `build_action_layer_puzzle(ctx, finalizer_node, merkle_root, state_node)` — curries our
  embedded `action.rue` HEX with `(FINALIZER, MERKLE_ROOT, STATE)`.
* `build_action_layer_solution(ctx, action_root_leaves, action_spends, finalizer_solution)` —
  builds the `RawActionLayerSolution` shape (puzzles, selectors_and_proofs, solutions,
  finalizer_solution) with proper Merkle proofs against our deployment-specific roots.
* `build_singleton_spend(ctx, coin, launcher_id, inner, inner_solution, lineage_proof)` —
  wraps the inner with the singleton outer + proof.
* `build_cat_spend(ctx, coin, tail_hash, inner, inner_solution, lineage, ...)` —
  wraps with the CAT v2 outer (single-CAT ring).
* `build_election_finalizer_full(ctx, election_launcher_id)` — the Election Singleton's
  custom finalizer puzzle (1st curry binds `(ACTION_LAYER_MOD_HASH, HINT)`, 2nd curry
  binds the finalizer's own first-curry hash per CHIP-0050).
* `build_registration_finalizer_full(ctx, voter_hint)` — same pattern for the Registration
  Coin's custom finalizer.

These helpers are public — extra integrations (e.g., a custom Voter::register pairing flow)
can compose them directly without going through the actor methods.

## Security notes

* **Wallet passwords**: NEVER pass `--password <literal>` (no such
  flag exists, deliberately). Use `--unlock-password-env <ENVNAME>`
  and export the password in the env var.
* **Voter BLS secrets**: NEVER use `--voter-secret-hex` outside
  testing. Use `--voter-secret-env` or `--voter-secret-file`.
* **Air-gapped machines**: ceremony `contribute` MUST run on an
  air-gapped machine for the toxic-waste destruction to be
  credible. The CLI cannot enforce this — it's your machine
  hygiene.
* **Bundle confirmation**: every broadcast prompts before it pushes
  to the network. Use `-y` only in CI / scripting.

## Exit codes

| Code | Meaning                                                            |
|------|--------------------------------------------------------------------|
| `0`  | Success.                                                           |
| `1`  | User / configuration error (bad args, missing file, parse fail).   |
| `2`  | Chain / network error (RPC unreachable, bundle rejected).          |
| `3`  | Cryptographic error (signature verification failed, bad VK).       |
