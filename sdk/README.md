# chip-voting-sdk

Reference Rust driver for the Chia voting CHIP — Election Singleton +
CAT-collateralised Registration Coin + Groth16 finalization.

## Architecture

The SDK delegates as much work as possible to the existing Chia
ecosystem crates and contributes only the voting-CHIP-specific layer
on top:

| Layer | Crates | Provided by SDK |
|-------|--------|-----------------|
| Wallet (XCH + CAT, encrypted keystore, BIP-39, coin selection, signing) | [`dig-l1-wallet`](https://crates.io/crates/dig-l1-wallet), [`dig-keystore`](https://crates.io/crates/dig-keystore) | — |
| Chain I/O (decentralised peers + coinset.org HTTP fallback, `push_tx`, hint queries, puzzle/solution fetch) | [`chia-query`](https://crates.io/crates/chia-query) | — |
| Spend bundle construction (`SpendContext`, `Launcher`, `Cat`, `CatSpend`, `StandardLayer`, `Singleton`, `ActionLayer`, `Spends`) | [`chia-wallet-sdk`](https://crates.io/crates/chia-wallet-sdk) (`action-layer` feature) + sub-crates `chia-sdk-driver`, `chia-sdk-signer`, `chia-sdk-types`, `chia-sdk-utils` | — |
| Standard puzzle constants (`CAT_PUZZLE_HASH`, `SINGLETON_LAUNCHER_HASH`, `SINGLETON_TOP_LAYER_V1_1_HASH`) + curry helpers (`CatArgs::curry_tree_hash`, `SingletonArgs::curry_tree_hash`) | [`chia-puzzles`](https://crates.io/crates/chia-puzzles), [`chia-puzzle-types`](https://crates.io/crates/chia-puzzle-types) | — |
| CLVM serde + tree hashing (`CurriedProgram`, `ToTreeHash`, `tree_hash_atom`, `tree_hash_pair`) | [`clvm-utils`](https://crates.io/crates/clvm-utils), [`clvm-traits`](https://crates.io/crates/clvm-traits) | — |
| BLS keys + signatures | [`chia-bls`](https://crates.io/crates/chia-bls), [`blst`](https://crates.io/crates/blst) | — |
| Groth16 prover (off-chain) | [`ark-groth16`](https://crates.io/crates/ark-groth16), [`ark-bls12-381`](https://crates.io/crates/ark-bls12-381), `ark-r1cs-std` | Voting-circuit definition (`prover::VotingCircuit`) |
| Voting CHIP puzzles (Rue source, compiled CLVM bytecode embedded) | this crate | `puzzles::*`, `actors::*`, `ceremony::*`, `merkle::*` |

The SDK never broadcasts. Every mutating operation returns a
`chia_protocol::SpendBundle`; the caller pushes it via
`ChiaQuery::push_tx`.

## Build

The SDK embeds compiled puzzle bytecode and tree hashes from
`../puzzles/compiled/`. Compile the Rue puzzles first:

```powershell
# At the CHIP project root:
.\build.ps1     # Windows
./build.sh      # Linux / macOS
```

Then build the SDK:

```bash
cd sdk
cargo build
cargo test --lib
```

No native build deps required: pure Rust + `native-tls` (Windows
SChannel / macOS SecureTransport / Linux OpenSSL via system).

## Public API

### Per-actor

| Actor              | Operations                                                           |
|--------------------|----------------------------------------------------------------------|
| `ElectionDeployer` | `build_deploy_bundle(parent_coin, parent_pk) → DeploymentArtifacts`  |
| `Voter`            | `register`, `vote`, `release_collateral`                             |
| `Aggregator`       | `sync`, `collect_votes`, `build_finalize`                            |
| `Indexer`          | read-only state queries                                              |

### MPC ceremony

| Type                  | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `CeremonyCoordinator` | Drives the sequence of participant contributions    |
| `CeremonyParticipant` | A single participant's local view (air-gapped)      |
| `MpcBackend`          | Pluggable cryptography backend (e.g., `phase2`)      |
| `verify_transcript`   | Independent verifier — anyone can audit the chain   |

### Puzzle hash arithmetic

These helpers compute the same hashes the Rue puzzles compute on-chain,
using upstream `chia_puzzle_types` and `clvm_utils`. They are public so
any external indexer or wallet can predict puzzle hashes without
running CLVM:

```rust
use chip_voting_sdk::puzzles::{
    fresh_registration_coin_puzzle_hash,
    election_singleton_puzzle_hash,
    voter_hint,
    PuzzleHashes,
};

// Predict where a voter's CAT-wrapped registration coin will land:
let reg_ph = fresh_registration_coin_puzzle_hash(
    cat_tail_hash,
    &voter_pubkey,
    election_launcher_id,
);

// Predict the Election Singleton's full puzzle hash:
let inner_ph = deployer.genesis_inner_puzzle_hash(launcher_id);
let singleton_ph = election_singleton_puzzle_hash(launcher_id, inner_ph);

// Per-voter coin-state lookup key (for `chain.get_coin_records_by_hint`):
let hint = voter_hint(election_launcher_id, cat_tail_hash, &voter_pubkey);
```

## Per-actor usage

### Election Deployer

```rust
use chip_voting_sdk::actors::deployer::{DeployParams, ElectionDeployer};
use chip_voting_sdk::ceremony::{CeremonyCoordinator, SimulatedBackend};
use chip_voting_sdk::{ChiaQuery, ChiaQueryConfig, L1Wallet, NetworkType};

// 1. MPC ceremony.
let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
coord.start("chip-voting-v1".into())?;
// ... at least one participant contributes ...
let vk = coord.finalize()?;

// 2. Wallet + chain client.
let wallet = L1Wallet::new(Default::default()).await?;
wallet.unlock("my-wallet", "password")?;
let chain = ChiaQuery::new(ChiaQueryConfig::default()).await?;

// 3. Pick a parent coin to fund the launcher (1 mojo + bundle fee).
let selection = wallet
    .select_coins("my-wallet", Some(0), 1 + bundle_fee,
                  chip_voting_sdk::CoinSelectionStrategy::Knapsack)
    .await?;
let parent_coin = selection.coins[0].clone();   // chia_protocol::Coin
let parent_sk = wallet.get_account_sk("my-wallet", 0)?;
let parent_pk = parent_sk.public_key();

// 4. Build + sign the deploy bundle in one step. Internally calls
//    `dig_l1_wallet::transaction::sign_coin_spends`, which uses
//    `chia_sdk_signer::RequiredSignature::from_coin_spends` to walk
//    every AGG_SIG_* condition and aggregate the BLS signatures.
let deployer = ElectionDeployer::new(DeployParams {
    verification_key: vk,
    cat_tail_hash: governance_cat_id,
    collateral_amount: 100,
    registration_fee: 1_000_000,
    election_length_blocks: 4032,
    label: Some("Founding board vote".into()),
});
let artifacts = deployer.deploy_signed(
    parent_coin,
    parent_pk,
    &[parent_sk],
    NetworkType::Mainnet,
)?;

// 5. Broadcast.
chain.push_tx(&hex::encode(chia_traits::Streamable::to_bytes(&artifacts.spend_bundle)?)).await?;

// 6. Persist config for participants.
std::fs::write("election_config.json", artifacts.config.to_json())?;
```

### Voter

```rust
use chip_voting_sdk::actors::{Voter, voter::VoterKeys};
use chia_query::{ChiaQuery, ChiaQueryConfig};
use dig_l1_wallet::L1Wallet;

let wallet = L1Wallet::load("alice", "password")?;
let chain  = ChiaQuery::new(ChiaQueryConfig::default()).await?;

let voter = Voter::new(
    election_config.clone(),
    VoterKeys::new(my_voter_secret_key),
    wallet,
    "alice".into(),
);

// Register: locks COLLATERAL_AMOUNT of CAT + pays REGISTRATION_FEE.
let smt = aggregator.merkle_tree()?.clone();
let bundle = voter.register(&smt, /* fee */ 1_000_000, &chain).await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;

// Vote.
let bundle = voter.vote(b"yes_for_proposal_42".into(), &chain).await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;

// After finalization: recover collateral.
let bundle = voter.release_collateral(my_cat_destination, &chain).await?;
chain.push_tx(&hex::encode(bundle.to_bytes()?)).await?;
```

### Aggregator

```rust
use chip_voting_sdk::actors::Aggregator;
use chia_query::{ChiaQuery, ChiaQueryConfig};

let chain = ChiaQuery::new(ChiaQueryConfig::default()).await?;
let mut agg = Aggregator::new(election_config.clone(), chain);

let voter_set = agg.sync().await?;
let votes     = agg.collect_votes().await?;
let outcome   = tally_winning_outcome(&votes);

let bundle = agg.build_finalize(outcome, &votes, my_reward_dest).await?;
agg.chain().push_tx(&hex::encode(bundle.to_bytes()?)).await?;
```

### Indexer

```rust
use chip_voting_sdk::actors::Indexer;
use chia_query::{ChiaQuery, ChiaQueryConfig};

let chain = ChiaQuery::new(ChiaQueryConfig::default()).await?;
let mut indexer = Indexer::new(election_config.clone(), chain);
indexer.sync().await?;

println!("Registered: {}", indexer.registration_count()?);
println!("Finalized:  {}", indexer.is_finalized()?);
println!("Outcome:    {:?}", indexer.vote_outcome()?);
```

## MPC ceremony

The Groth16 trusted setup is the most security-sensitive part of any
zk-SNARK system. **A single-party setup is unsafe.** The CHIP requires
a multi-party ceremony where at least one honest participant ensures
the toxic waste is never reconstructable.

### Coordinator (online, public)

```rust
use chip_voting_sdk::ceremony::{CeremonyCoordinator, SimulatedBackend};

let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
coord.start("chip-voting-v1".into())?;

let contributed = receive_from_participant_1();
coord.accept_contribution(contributed)?;

for attestation in coord.published_attestations()? {
    println!("Contribution {}: {} → hash {}",
        attestation.index,
        attestation.participant_name,
        attestation.transcript_hash_hex);
}

let vk = coord.finalize()?;     // Errs with UnsafeSingleParty if zero contributions.
```

### Participant (offline, air-gapped)

```rust
use chip_voting_sdk::ceremony::{CeremonyParticipant, SimulatedBackend};

let input = read_transcript_from_file("input.transcript.json")?;

let mut entropy = [0u8; 32];
read_entropy_from_hardware(&mut entropy)?;

let participant = CeremonyParticipant::new(
    Box::new(SimulatedBackend),
    "alice".into(),
    Some("Contributed at chia-eve 2026, Alice".into()),
);
let output = participant.contribute(&input, entropy)?;

// SECURELY ERASE entropy. Disconnect the air-gapped machine.
// Send output.transcript back to the coordinator.
// Publish output.attestation publicly.
```

### Independent verification

```rust
use chip_voting_sdk::ceremony::{verify_transcript, SimulatedBackend};

let final_transcript = download_published_transcript()?;
verify_transcript(&final_transcript, &SimulatedBackend)?;
```

### MPC backend selection

The `SimulatedBackend` shipped with the SDK is a stub for testing —
**never use it in production**. For real deployments, plug in:

* **`phase2`** ([github.com/ebfull/phase2](https://github.com/ebfull/phase2))
  — Sean Bowe's classic Groth16 phase-2 implementation (BLS12-381).
  Battle-tested, used by Zcash Sapling.
* **`arkworks-rs/snark-mpc`** — pure-arkworks implementation, cleanly
  matches our `ark-groth16` proving stack.

Both are wrapped behind the `MpcBackend` trait.

## Production wiring strategy

The puzzle hash arithmetic, type layouts, signing helpers, and deploy
spend bundle are **production-implemented** using the recommended
upstream patterns:

| Operation | Implementation |
|-----------|----------------|
| Tree hashing | `clvm_utils::tree_hash_atom` / `tree_hash_pair` / `CurriedProgram::tree_hash` |
| CAT outer wrap | `chia_puzzle_types::cat::CatArgs::curry_tree_hash` |
| Singleton wrap | `chia_puzzle_types::singleton::SingletonArgs::curry_tree_hash` |
| Standard CAT mod hash | `chia_puzzles::CAT_PUZZLE_HASH` |
| Standard launcher hash | `chia_puzzles::SINGLETON_LAUNCHER_HASH` |
| Singleton launch | `chia_sdk_driver::Launcher::new(parent_id, 1).spend(ctx, inner_ph, ())` |
| P2 spend | `chia_sdk_driver::StandardLayer::new(pk).spend(ctx, coin, conditions)` |
| Signature collection | `chia_sdk_signer::RequiredSignature::from_coin_spends` |
| Aggregated bundle signing | `dig_l1_wallet::transaction::sign_coin_spends` (wraps the above) |
| Top-level convenience | [`chip_voting_sdk::sign_bundle_signature`] |
| XCH coin selection | `dig_l1_wallet::L1Wallet::select_coins(.., Knapsack)` |
| CAT coin selection | `dig_l1_wallet::L1Wallet::select_cat_coins(.., Knapsack)` |
| Chain reads + `push_tx` | `chia_query::ChiaQuery` |

The `Voter::{register, vote, release_collateral}` and
`Aggregator::{sync, collect_votes, build_finalize}` methods currently
return `VotingError::Other("... pending")` — the inline source on each
contains the precise sequence of `chia_sdk_driver::Cat::spend_all` /
`Cat::parse_children` / `Spends::add` / `sign_bundle_signature` calls
to make.

Building these bundles end-to-end is mechanical work that mostly
mirrors [`chia-l2-consensus`](https://crates.io/crates/chia-l2-consensus)'s
structurally identical methods:

* `chia_l2_consensus::puzzles::deploy::deploy_both_singletons` — the
  deploy spend pattern (already mirrored in
  `ElectionDeployer::build_deploy_bundle` / `deploy_signed`).
* `chia_l2_consensus::client::register_validator` — the
  "CAT collateral + singleton spend + XCH funding + AGG_SIG_ME"
  composition that `Voter::register` produces.
* `chia_l2_consensus::indexer` — the chain-walk + lineage-verification
  pattern (`Aggregator::sync` / `Indexer::sync`).

### Signature flow (recommended path)

The SDK exposes a single signing entry point that uses the
recommended upstream chain end-to-end:

```rust
use chip_voting_sdk::{sign_bundle_signature, NetworkType};

// `coin_spends` is `Vec<chia_protocol::CoinSpend>` returned by your
// SpendContext. `secret_keys` includes every key that needs to sign
// (wallet payment key, voter key, etc.) — the function maps each one
// to both its raw and synthetic forms.
let signature = sign_bundle_signature(
    &coin_spends,
    &[wallet_sk, voter_sk],
    NetworkType::Mainnet,
)?;

// Internally:
//   1. Builds AggSigConstants from MAINNET_CONSTANTS / TESTNET11_CONSTANTS.
//   2. Calls RequiredSignature::from_coin_spends(allocator, &coin_spends, &constants).
//      This walks every AGG_SIG_* condition emitted by every coin spend,
//      computes the augmented message under the network's
//      agg_sig_me_additional_data, and returns Vec<RequiredSignature>.
//   3. For each RequiredSignature::Bls(req), looks up req.public_key
//      in the keypair table (PK + synthetic PK both included), signs
//      req.message() with the matching secret, and adds to the running
//      G2 aggregate.
//
// Returned Signature is the bundle-level aggregated_signature.

let bundle = chia_protocol::SpendBundle::new(coin_spends, signature);
chain.push_tx(&hex::encode(chia_traits::Streamable::to_bytes(&bundle)?)).await?;
```

## License

MIT
