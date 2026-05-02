# chip-voting-sdk

Reference Rust driver for the Chia voting CHIP (rev 2026-05-02):
**orchestrator-only Election Singleton** + CAT-collateralised
Registration Coin + per-Ballot-Coin Groth16 finalization.

The full spec lives in [`../CHIP.md`](../CHIP.md). The phased migration plan
that drove this rev lives in
[`../app/docs/superpowers/plans/2026-05-02-chip-migration.md`](../app/docs/superpowers/plans/2026-05-02-chip-migration.md).

## Architecture (CHIP rev 2026-05-02)

The voting CHIP runs four coin lineages:

* **Election Singleton** — orchestrator only. Holds the registered-voter
  SMT root and per-voter mint state. Spawns Ballot Coins via the
  `createBallot` action and Registration Coins via `register`. It does
  NOT carry election outcome state.
* **Registration Coin** — one per voter. Wraps `collateral_amount` of
  CAT, gates `mint_voting_coin` (one Voting Coin per ballot per voter),
  and gates `release` (deregister + return CAT).
* **Ballot Coin** — one per ballot. Minted under `createBallot`, carries
  its own `vote_close_height` + `outcome_domain_hash`, and asserts the
  6-input Groth16 proof at `finalize`. The verification key is curried
  per-ballot, not on the singleton.
* **Voting Coin** — one per (voter, ballot). Created by
  `mint_voting_coin`; carries the voter's signed payload and is consumed
  by the Ballot Coin's vote-collection step.

There is no XCH cost beyond the standard mempool bundle fee — collateral
is denominated entirely in the governance CAT.

## Crate composition

The SDK delegates as much as possible to the existing Chia ecosystem:

| Layer | Crates |
|-------|--------|
| Wallet (XCH + CAT, encrypted keystore, BIP-39, coin selection, signing) | [`dig-l1-wallet`](https://crates.io/crates/dig-l1-wallet), [`dig-keystore`](https://crates.io/crates/dig-keystore) |
| Chain I/O (peers + coinset.org HTTP fallback, `push_tx`, hints) | [`chia-query`](https://crates.io/crates/chia-query) |
| Spend construction (`SpendContext`, `Launcher`, `Cat`, `StandardLayer`, `Singleton`, `ActionLayer`, `Spends`) | [`chia-wallet-sdk`](https://crates.io/crates/chia-wallet-sdk) (+ `chia-sdk-driver`, `-signer`, `-types`, `-utils`) |
| Puzzle constants + curry helpers | [`chia-puzzles`](https://crates.io/crates/chia-puzzles), [`chia-puzzle-types`](https://crates.io/crates/chia-puzzle-types) |
| CLVM serde + tree hashing | [`clvm-utils`](https://crates.io/crates/clvm-utils), [`clvm-traits`](https://crates.io/crates/clvm-traits) |
| BLS | [`chia-bls`](https://crates.io/crates/chia-bls), [`blst`](https://crates.io/crates/blst) |
| Groth16 (off-chain prover) | [`ark-groth16`](https://crates.io/crates/ark-groth16), [`ark-bls12-381`](https://crates.io/crates/ark-bls12-381) |

This crate contributes only the voting-CHIP-specific layer:
`puzzles::*`, `actors::*`, `ceremony::*`, `merkle::*`, `prover::*`.

The SDK never broadcasts. Every mutating operation returns a
`chia_protocol::SpendBundle`; the caller pushes it via
`ChiaQuery::push_tx`.

## Build

```powershell
# At the CHIP project root, regenerate compiled puzzles first:
.\build.ps1     # Windows
./build.sh      # Linux / macOS

# Then:
cd sdk
cargo build
cargo test --lib
```

No native build deps: pure Rust + `native-tls` (Windows SChannel /
macOS SecureTransport / Linux OpenSSL via system).

## Public API

### Per-actor

| Actor              | Operations |
|--------------------|------------|
| `ElectionDeployer` | `build_deploy_bundle`, `deploy_signed` → `DeploymentArtifacts` |
| `BallotIssuer`     | `create_ballot(seed, vote_close_height, outcome_domain_hash)` (operator) |
| `BallotReader`     | `list_ballots`, `get_ballot` (read-only) |
| `Voter`            | `register`, `cast_vote(ballot_launcher_id, ...)`, `update_vote(...)`, `release_collateral` |
| `Aggregator`       | `sync`, `collect_votes_for_ballot(ballot_launcher_id)`, `build_finalize_for_ballot(...)` |
| `Indexer`          | `ballots`, `ballot_state`, `votes_for_ballot`, `is_finalized_for`, `vote_outcome_for` |

### MPC ceremony

| Type                  | Purpose |
|-----------------------|---------|
| `CeremonyCoordinator` | Drives the sequence of participant contributions |
| `CeremonyParticipant` | A single participant's local view (air-gapped) |
| `MpcBackend`          | Pluggable backend (e.g. `phase2`, `arkworks-rs/snark-mpc`) |
| `verify_transcript`   | Independent verifier — anyone can audit the chain |

### Puzzle hash arithmetic

Helpers in `chip_voting_sdk::puzzles` compute the same hashes the Rue
puzzles compute on-chain. They are public so any external indexer or
wallet can predict puzzle hashes without running CLVM. See the source
for the full set; canonical entry points:

* `fresh_registration_coin_puzzle_hash(cat_tail, voter_pk, launcher_id)`
* `election_singleton_puzzle_hash(launcher_id, inner_ph)`
* `voter_hint(launcher_id, cat_tail, voter_pk)` — coin-state lookup key
  for `chain.get_coin_records_by_hint`.

## Usage sketches

### Deploy

```rust
use chip_voting_sdk::actors::deployer::{DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::{CeremonyCoordinator, SimulatedBackend};
use chip_voting_sdk::NetworkType;

// 1. MPC ceremony.
let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
coord.start("chip-voting-v1".into())?;
// ... at least one participant contributes ...
let vk = coord.finalize()?;

// 2. Build + sign the deploy bundle.
let deployer = ElectionDeployer::new(DeployParams {
    verification_key: vk,
    cat_tail_hash: governance_cat_id,
    collateral_amount: 100,
    // L1 height anchor used by the singleton's genesis state. Per-ballot
    // vote-close heights are set later, at `createBallot` time.
    election_start_height: peak_height,
    label: Some("Founding board vote".into()),
});
let artifacts = deployer.deploy_signed(
    parent_coin, parent_pk, &[parent_sk], NetworkType::Mainnet,
)?;
chain.push_tx(&hex::encode(artifacts.spend_bundle.to_bytes()?)).await?;
std::fs::write("election_config.json", artifacts.config.to_json())?;
```

### Voter

```rust
use chip_voting_sdk::actors::voter::{Voter, VoterKeys};

let voter = Voter::new(
    election_config.clone(),
    VoterKeys::new(my_voter_sk),
    NetworkType::Mainnet,
);

// Register: locks `collateral_amount` of CAT into a Registration Coin.
let bundle = voter.register(&chain, &[wallet_sk]).await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;

// Cast a vote on a specific ballot (mints the Voting Coin).
let bundle = voter
    .cast_vote(ballot_launcher_id, b"yes_for_proposal_42".to_vec(), &chain)
    .await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;

// Optionally amend before the ballot's `vote_close_height`.
let bundle = voter
    .update_vote(ballot_launcher_id, b"abstain".to_vec(), &chain)
    .await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;

// After every ballot the voter participated in has finalized:
// deregister and return locked CAT to a destination.
let bundle = voter.release_collateral(my_cat_destination, &chain).await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;
```

### BallotIssuer + Aggregator (per-ballot)

```rust
use chip_voting_sdk::actors::ballot::{BallotIssuer, CreateBallotParams};
use chip_voting_sdk::actors::Aggregator;

// Operator: mint a fresh ballot.
let issuer = BallotIssuer::new(election_config.clone(), NetworkType::Mainnet);
let created = issuer.create_ballot(
    CreateBallotParams { ballot_seed, vote_close_height, outcome_domain_hash },
    &chain,
).await?;
chain.push_tx(&hex::encode(created.spend_bundle.to_bytes()?)).await?;

// Aggregator: tally + finalize.
let mut agg = Aggregator::new(
    election_config.clone(), chain, NetworkType::Mainnet,
);
agg.sync().await?;
let votes   = agg.collect_votes_for_ballot(created.ballot_launcher_id).await?;
let outcome = tally_winning_outcome(&votes);
let bundle  = agg
    .build_finalize_for_ballot(created.ballot_launcher_id, outcome, &votes)
    .await?;
agg.chain().push_tx(&hex::encode(bundle.to_bytes()?)).await?;
```

### Indexer (per-ballot accessors)

```rust
use chip_voting_sdk::actors::Indexer;

let mut indexer = Indexer::new(election_config.clone(), chain);
indexer.sync().await?;

println!("Registered: {}", indexer.registration_count()?);
for b in indexer.ballots().await? {
    let id = b.launcher_id;
    println!(
        "Ballot {}: finalized={:?} outcome={:?} votes={}",
        hex::encode(id),
        indexer.is_finalized_for(id).await?,
        indexer.vote_outcome_for(id).await?,
        indexer.votes_for_ballot(id).await?.len(),
    );
}
```

## Implementation status

The puzzle-hash arithmetic, type layouts, signing helpers, and deploy
spend bundle are production-implemented. The per-ballot lane methods
(`Voter::cast_vote` / `update_vote` / `release_collateral`,
`BallotIssuer::create_ballot`, `BallotReader::*`, `Indexer::ballots` /
`ballot_state` / `votes_for_ballot` / `is_finalized_for` /
`vote_outcome_for`, `Aggregator::collect_votes_for_ballot` /
`build_finalize_for_ballot`) are public-API stubs returning
`VotingError::Other("... pending Phase 6")`. The inline source on each
documents the precise sequence of `chia_sdk_driver::Cat::spend_all` /
`Cat::parse_children` / `Spends::add` / `sign_bundle_signature` calls
to make. See the migration plan referenced above.

### Signature flow

The SDK exposes a single signing entry point that uses the recommended
upstream chain end-to-end:

```rust
use chip_voting_sdk::{sign_bundle_signature, NetworkType};

let signature = sign_bundle_signature(
    &coin_spends,
    &[wallet_sk, voter_sk],
    NetworkType::Mainnet,
)?;
let bundle = chia_protocol::SpendBundle::new(coin_spends, signature);
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;
```

Internally this calls `chia_sdk_signer::RequiredSignature::from_coin_spends`
under `MAINNET_CONSTANTS` / `TESTNET11_CONSTANTS`, walks every
`AGG_SIG_*` condition, and aggregates the BLS signatures (raw + synthetic
PK both indexed into the keypair table). `dig_l1_wallet::transaction::sign_coin_spends`
wraps the same chain.

## License

MIT
