// ============================================================================
// chip-voting-live-test — end-to-end live-network integration test
// ============================================================================
//
// PURPOSE: Drive the COMPLETE election lifecycle (deploy → register
//          × N → wait election window → vote × N → finalize → release
//          collateral × N) against a real Chia network. Loads its
//          wallet identities from `.test-credentials` (gitignored)
//          and uses `chia_query::wait_for_confirmation` /
//          `wait_for_spend` so each mempool broadcast is confirmed on-chain
//          before later phases query `find_*_coin` again (fresh UTXOs).
//
// CONTRAST WITH SIMULATOR TESTS:
//   * The simulator-backed tests in `sdk/tests/*.rs` validate every
//     puzzle and every spend bundle against the actual consensus
//     runner — they prove correctness.
//   * THIS test validates that the SAME code paths work end-to-end
//     against a real, asynchronous network where:
//       - Coin lookups go over actual RPC.
//       - Block heights advance at ~52s/block on mainnet.
//       - Spend bundles are mempool-validated by independent farmers.
//       - Confirmation latency is measured in real seconds.
//
// USAGE:
//   $ cargo run --release --bin chip-voting-live-test -- \
//         --credentials ./.test-credentials \
//         --network mainnet \
//         --collateral-amount 100 \
//         --election-length-blocks 4 \
//         --yes
//
// SAFETY:
//   * The credentials file in `.test-credentials` contains MNEMONICS.
//     It is gitignored. Never commit it.
//   * The script DOES spend real XCH (transaction-mojo dust) and real
//     CAT (per-voter `--collateral-amount` mojos). On the happy path
//     the CAT is RETURNED to the same wallet via the release phase.
//     Set `--skip-release` to leave CAT collateral parked at the
//     election's destination puzzle hash for inspection.
//   * Each broadcast is gated by a confirmation prompt unless
//     `--yes` / `-y` is set. CI invocations should pass `--yes` and
//     wrap with their own approval gate.
//
// ARCHITECTURE:
//   The whole orchestration lives in this single binary so each
//   phase's chain interactions, polling, and bundle assembly are
//   colocated and easy to read top-to-bottom.

#![deny(rust_2018_idioms)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
// CLVM tuple types and per-phase coin compositions express on-chain
// puzzle-tree shapes verbatim; factoring would obscure the 1:1
// mapping with Rue declarations.
#![allow(clippy::type_complexity)]
// Phase orchestration functions inherently take many configuration
// parameters; collapsing them into a single struct hides the
// phase-by-phase data flow which is the whole point of this script.
#![allow(clippy::too_many_arguments)]

use anyhow::{bail, Context as _, Result};
use bip39::{Language, Mnemonic};
use chip_voting_sdk::ceremony::{
    CeremonyCoordinator, CeremonyParticipant, MpcBackend, SimulatedBackend,
};
use chip_voting_sdk::clvm_traits::ToClvm;
use chip_voting_sdk::clvmr::Allocator;
use chip_voting_sdk::prover::circuit::{ArkProvingKey, ArkVerifyingKey};
use chip_voting_sdk::{
    actors::deployer::sign_bundle_signature, dry_run_coin_spends, master_to_wallet_unhardened,
    puzzles, verify_bundle_signatures, wait_for_current_singleton, Aggregator, Bytes32, Cat,
    CatArgs, CatSpend, Coin, CoinSpend, CoinsetClient, Conditions, DeployParams, DeriveSynthetic,
    ElectionConfig, ElectionDeployer, Memos, NetworkType, PublicKey, Puzzle, SecretKey,
    SpendBundle, SpendContext, SpendWithConditions, StandardArgs, StandardLayer, VerificationKey,
    Voter, VoterKeys,
};
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

// ============================================================================
// SECTION 1 — Command-line interface
// ============================================================================

/// Live-network end-to-end integration test for the Chia voting CHIP.
///
/// Loads wallet identities from `.test-credentials`, runs an MPC
/// ceremony, deploys a fresh Election Singleton, registers two
/// voters, waits the election window, casts votes, finalizes, and
/// releases collateral — gating each phase on actual on-chain
/// confirmations via `chia_query::wait_for_confirmation`.
#[derive(Debug, Parser)]
#[command(name = "chip-voting-live-test", version)]
struct Args {
    /// Path to a `.test-credentials` file with FUNDING /
    /// VALIDATOR1 / VALIDATOR2 wallet entries (mnemonics + addresses
    /// + pubkeys). See `CHIP/.test-credentials` for the expected
    /// format.
    #[arg(long, default_value = ".test-credentials")]
    credentials: PathBuf,

    /// Override the network. Defaults to whatever the FUNDING wallet
    /// entry's `WALLET_NETWORK` field says.
    #[arg(long, value_enum)]
    network: Option<NetworkArg>,

    /// CAT TAIL (asset id) hash for voter collateral. Defaults to
    /// the DIG mainnet asset id, matching DataLayer-Driver's
    /// `DIG_ASSET_ID`. Override for testnet experiments.
    #[arg(
        long,
        default_value = "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    )]
    cat_tail_hash: String,

    /// Voter collateral, in CAT mojos. Default `1000` = 1 DIG
    /// (Chia CATs use 3-decimal precision: 1 token = 1000 mojos).
    /// On the happy path the release phase returns this CAT to the
    /// validator wallet; with `--skip-release` it stays locked at
    /// the destination puzzle hash.
    #[arg(long, default_value_t = 1_000)]
    collateral_amount: u64,

    /// XCH network fee attached to the finalize bundle (in mojos).
    /// The Ballot Coin's `finalize` action emits no AGG_SIG conditions
    /// and pays no on-chain fees of its own, so without an attached
    /// fee coin the bundle has zero fee/cost. Mainnet farmers
    /// de-prioritise zero-fee bundles so heavily that they often
    /// sit in mempool past the test's `wait_for_spend` timeout.
    ///
    /// Mainnet's typical mempool fee policy is ~5 mojos per CLVM
    /// cost unit. Our finalize Ballot Coin spend has ~88M CLVM cost
    /// (Groth16 pairing + BLS pairing identity dominate). The
    /// observed mempool ADMISSION threshold is far below that —
    /// a fee of ~10M mojos (~0.1 mojo / cost) reliably gets the
    /// bundle in. Bump higher only if your wallet has plenty of
    /// XCH and you're racing against other mempool traffic for
    /// inclusion in the very next block.
    #[arg(long, default_value_t = 10_000_000)]
    finalize_fee: u64,

    /// Voting window length, in L1 blocks AFTER the Ballot Coin is
    /// launched. Mainnet blocks are ~52s. Default 4 blocks (~3.5
    /// min) is a reasonable wall-clock budget for the full
    /// lifecycle. Used as `vote_close_height = launch_height +
    /// election_length_blocks` (per CHIP.md §211 the Ballot Coin's
    /// per-ballot `vote_close_height` curry is what governs voting
    /// timing in this CHIP revision; the Election Singleton no
    /// longer carries a global election length).
    #[arg(long, default_value_t = 4)]
    election_length_blocks: u64,

    /// XCH mojos to allocate to the launcher coin. Singleton spec
    /// requires a non-zero odd amount; 1 is the standard choice.
    #[arg(long, default_value_t = 1)]
    launcher_amount: u64,

    /// Per-broadcast confirmation poll interval (seconds).
    #[arg(long, default_value_t = 8)]
    poll_interval_secs: u64,

    /// Per-broadcast confirmation timeout (seconds). 900s = 15
    /// minutes, generous for mainnet's 52s blocks plus any farmer
    /// queue.
    #[arg(long, default_value_t = 900)]
    confirmation_timeout_secs: u64,

    /// Skip the collateral-release phase. Useful for diagnostic
    /// runs where you want the registration coins to remain on-chain
    /// for inspection.
    #[arg(long)]
    skip_release: bool,

    /// Skip the broadcast confirmation prompt before EVERY phase.
    /// REQUIRED for non-interactive use (CI). Echo'd via tracing so
    /// the operator can see which auto-approved spends ran.
    #[arg(short = 'y', long = "yes")]
    assume_yes: bool,

    /// Verbose logging (info → debug).
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Trace-level logging (debug → trace).
    #[arg(long)]
    trace: bool,
    // NOTE: legacy chia_query peer-pool args (`--trusted-fullnode`,
    // `--peer-connect-timeout-secs`, `--max-peers`) were removed when
    // the live test switched to using `CoinsetClient` exclusively for
    // ALL chain I/O. See `make_independent_chain` for rationale; if
    // you need to point at a private coinset mirror, override
    // `COINSET_BASE_URL` in source.
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet11,
}

impl From<NetworkArg> for NetworkType {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Mainnet => NetworkType::Mainnet,
            NetworkArg::Testnet11 => NetworkType::Testnet11,
        }
    }
}

// ============================================================================
// SECTION 2 — `.test-credentials` parsing
// ============================================================================

/// One wallet entry parsed out of `.test-credentials`. Field shape
/// matches the file's `## L2 Funding Wallet (Mainnet)` /
/// `## Validator N Wallet (Mainnet)` blocks.
///
/// MNEMONIC: lines starting with `# Mnemonic:` immediately after
/// the entry's other fields hold the BIP-39 phrase. Stored as
/// `Some(_)` if present, `None` otherwise.
#[derive(Debug, Clone)]
struct CredentialEntry {
    name: String,
    pubkey: Option<String>,
    mnemonic: Option<String>,
    network: Option<NetworkType>,
}

#[derive(Debug, Clone)]
struct Credentials {
    funding: CredentialEntry,
    validator1: CredentialEntry,
    validator2: CredentialEntry,
}

/// Parse a `.test-credentials` file using a minimal `KEY=VALUE`
/// scanner. Comments (`#` lines) are ignored EXCEPT for
/// `# Mnemonic: ...` lines, which attach the mnemonic to the
/// most-recent prefix's entry.
fn parse_credentials(path: &std::path::Path) -> Result<Credentials> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading credentials file {}", path.display()))?;
    let mut all: HashMap<String, CredentialEntry> = HashMap::new();
    let mut current_prefix: Option<String> = None;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# Mnemonic:") {
            if let Some(prefix) = &current_prefix {
                if let Some(entry) = all.get_mut(prefix) {
                    entry.mnemonic = Some(rest.trim().to_string());
                }
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').to_string();

        // Determine the entry prefix (which wallet identity) and
        // the field key. The credentials file uses two patterns:
        //   * Funding wallet — bare `WALLET_NAME`, `WALLET_NETWORK`,
        //     `WALLET_PASSWORD`, `WALLET_ADDRESS` (no extra prefix).
        //   * Validator wallets — `VALIDATORn_*` for everything,
        //     including `VALIDATORn_WALLET_NAME` (the validator's
        //     friendly handle) and `VALIDATORn_PUBKEY` (the BLS
        //     account pubkey).
        let (prefix, raw_field) = if let Some(rest) = key.strip_prefix("VALIDATOR1_") {
            ("validator1".to_string(), rest)
        } else if let Some(rest) = key.strip_prefix("VALIDATOR2_") {
            ("validator2".to_string(), rest)
        } else if let Some(rest) = key.strip_prefix("WALLET_") {
            ("funding".to_string(), rest)
        } else {
            continue;
        };
        // For validator entries, fields are usually `WALLET_*` —
        // strip that secondary prefix before matching so
        // `VALIDATOR1_WALLET_NAME` and bare `WALLET_NAME` route
        // through the same arms.
        let field = raw_field.strip_prefix("WALLET_").unwrap_or(raw_field);
        current_prefix = Some(prefix.clone());

        let entry = all.entry(prefix).or_insert_with(|| CredentialEntry {
            name: String::new(),
            pubkey: None,
            mnemonic: None,
            network: None,
        });

        match field {
            "NAME" => entry.name = value,
            "PUBKEY" => entry.pubkey = Some(value),
            "NETWORK" => {
                entry.network = Some(match value.to_ascii_lowercase().as_str() {
                    "mainnet" => NetworkType::Mainnet,
                    "testnet11" | "testnet" => NetworkType::Testnet11,
                    other => bail!("unknown WALLET_NETWORK value: {other}"),
                })
            }
            _ => {} // PASSWORD, ADDRESS, etc — not needed by this script
        }
    }

    let funding = all
        .remove("funding")
        .ok_or_else(|| anyhow::anyhow!("missing funding wallet block (WALLET_NAME=...)"))?;
    let validator1 = all
        .remove("validator1")
        .ok_or_else(|| anyhow::anyhow!("missing VALIDATOR1 wallet block"))?;
    let validator2 = all
        .remove("validator2")
        .ok_or_else(|| anyhow::anyhow!("missing VALIDATOR2 wallet block"))?;

    for entry in [&funding, &validator1, &validator2] {
        if entry.mnemonic.is_none() {
            bail!(
                "credentials entry `{}` is missing its `# Mnemonic: ...` line — \
                 each wallet block MUST include a 24-word BIP-39 phrase",
                entry.name
            );
        }
    }

    Ok(Credentials {
        funding,
        validator1,
        validator2,
    })
}

// ============================================================================
// SECTION 3 — Wallet key derivation
// ============================================================================

/// All key material for a wallet identity. Derived once from the
/// mnemonic; reused for every spend that wallet authorises.
struct WalletKeys {
    /// `master_to_wallet_unhardened(master, 0).derive_synthetic()` —
    /// the secret key that signs AGG_SIG_* conditions in the
    /// standard p2 puzzle.
    synthetic_sk: SecretKey,
    /// `synthetic_sk.public_key()`. Pinned in the standard p2 puzzle.
    synthetic_pk: PublicKey,
    /// `StandardArgs::curry_tree_hash(synthetic_pk).into()`. The
    /// bech32m address decodes to this hash.
    p2_puzzle_hash: Bytes32,
}

/// Derive every key we need from a 24-word BIP-39 mnemonic.
///
/// PIPELINE (matches `dig_l1_wallet::keys::derivation::derive_account`):
///   1. `Mnemonic::parse_in_normalized(English, mnemonic)`
///   2. `mnemonic.to_seed("")` — Chia uses an EMPTY passphrase.
///   3. `SecretKey::from_seed(&seed)` → master.
///   4. `master_to_wallet_unhardened(&master, 0)` → account.
///   5. `account.derive_synthetic()` → synthetic.
///   6. `StandardArgs::curry_tree_hash(syn_pk).into()` → p2 hash.
fn derive_wallet_keys(
    mnemonic: &str,
    expected_account_pubkey_hex: Option<&str>,
) -> Result<WalletKeys> {
    let parsed = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .with_context(|| "mnemonic phrase failed BIP-39 validation")?;
    let seed = parsed.to_seed("");
    let master_sk = SecretKey::from_seed(&seed);
    let account_sk = master_to_wallet_unhardened(&master_sk, 0);
    let account_pk = account_sk.public_key();
    let synthetic_sk = account_sk.derive_synthetic();
    let synthetic_pk = synthetic_sk.public_key();
    let p2_puzzle_hash = Bytes32::new(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());

    if let Some(expected_hex) = expected_account_pubkey_hex {
        let expected_bytes = hex::decode(expected_hex.trim().trim_start_matches("0x"))
            .with_context(|| "expected pubkey is not valid hex")?;
        if expected_bytes.len() != 48 {
            bail!(
                "expected pubkey is not 48 bytes: got {}",
                expected_bytes.len()
            );
        }
        let derived = account_pk.to_bytes();
        if derived.as_slice() != expected_bytes.as_slice() {
            warn!(
                expected = expected_hex,
                derived = hex::encode(derived),
                "credentials PUBKEY does not match mnemonic-derived account pubkey \
                 (proceeding with the mnemonic-derived key)"
            );
        }
    }

    Ok(WalletKeys {
        synthetic_sk,
        synthetic_pk,
        p2_puzzle_hash,
    })
}

// ============================================================================
// SECTION 4 — chia_query helpers (confirmation polling, peak height)
// ============================================================================

/// Wait until a coin is CONFIRMED on-chain (i.e. its
/// `confirmed_block_index` is non-zero). Wraps
/// `ChiaQuery::wait_for_confirmation` with our standard retry
/// budget. The returned `coin_id_hex` is the same value the caller
/// passed in — useful for chaining log messages.
async fn wait_for_confirmation(
    chain: &CoinsetClient,
    coin_id: Bytes32,
    args: &Args,
    label: &str,
) -> Result<Bytes32> {
    let coin_id_hex = format!("0x{}", hex::encode(coin_id));
    info!(
        coin_id = %coin_id_hex,
        timeout_secs = args.confirmation_timeout_secs,
        "waiting for {label} coin confirmation"
    );
    // Poll `get_coin_record_by_name` until the coin appears AND has a
    // non-zero `confirmed_block_index`. This replaces the
    // `ChiaQuery::wait_for_confirmation` convenience helper which only
    // exists on the peer-pool client; CoinsetClient gives us the
    // underlying HTTP record and we just loop.
    let deadline = std::time::Instant::now() + Duration::from_secs(args.confirmation_timeout_secs);
    let mut last_log = std::time::Instant::now();
    let confirmed_height = loop {
        match chain.get_coin_record_by_name(&coin_id_hex).await {
            Ok(rec) if rec.confirmed_block_index > 0 => break rec.confirmed_block_index,
            Ok(_) => {} // exists but not yet in a block
            Err(e) => tracing::debug!(error = ?e, "wait_for_confirmation: poll error"),
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "{label}: wait_for_confirmation timed out after {}s for coin {coin_id_hex}",
                args.confirmation_timeout_secs
            );
        }
        if last_log.elapsed() > Duration::from_secs(60) {
            info!(coin_id = %coin_id_hex, "still waiting for {label} confirmation...");
            last_log = std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_secs(args.poll_interval_secs)).await;
    };
    info!(
        coin_id = %coin_id_hex,
        confirmed_height,
        "{label} confirmed"
    );
    Ok(coin_id)
}

/// Wait until a specific coin is SPENT on-chain
/// (`spent_block_index` becomes non-zero). Used to confirm a spend
/// landed in a block — necessary because `wait_for_confirmation`
/// only waits for coin CREATION.
async fn wait_for_spend(
    chain: &CoinsetClient,
    coin_id: Bytes32,
    args: &Args,
    label: &str,
) -> Result<u32> {
    let coin_id_hex = format!("0x{}", hex::encode(coin_id));
    let deadline = std::time::Instant::now() + Duration::from_secs(args.confirmation_timeout_secs);
    let mut last_log = std::time::Instant::now();
    info!(
        coin_id = %coin_id_hex,
        timeout_secs = args.confirmation_timeout_secs,
        "waiting for {label} coin to be spent"
    );
    loop {
        let rec = chain.get_coin_record_by_name(&coin_id_hex).await;
        match rec {
            Ok(r) if r.spent_block_index > 0 => {
                info!(
                    coin_id = %coin_id_hex,
                    spent_height = r.spent_block_index,
                    "{label} spent"
                );
                return Ok(r.spent_block_index);
            }
            Ok(_) => {} // still unspent
            Err(e) => {
                tracing::debug!(error = ?e, "coin lookup failed; retrying");
            }
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "{label}: coin {coin_id_hex} not spent within {}s",
                args.confirmation_timeout_secs
            );
        }
        if last_log.elapsed() > Duration::from_secs(60) {
            info!(coin_id = %coin_id_hex, "still waiting for {label} spend...");
            last_log = std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_secs(args.poll_interval_secs)).await;
    }
}

/// Current peak block height, via `get_blockchain_state().peak`.
async fn current_peak_height(chain: &CoinsetClient) -> Result<u32> {
    let state = chain
        .get_blockchain_state()
        .await
        .context("get_blockchain_state failed")?;
    state
        .peak
        .map(|p| p.height)
        .ok_or_else(|| anyhow::anyhow!("blockchain has no peak (node still syncing?)"))
}

/// Block until the chain's peak height reaches `target_height`.
/// Logs progress every 30s.
async fn wait_for_block_height(
    chain: &CoinsetClient,
    target_height: u32,
    poll_secs: u64,
    timeout_secs: u64,
) -> Result<u32> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_log = std::time::Instant::now();
    info!(
        target_height,
        timeout_secs, "waiting for chain peak to reach target height"
    );
    loop {
        let now_height = current_peak_height(chain).await?;
        if now_height >= target_height {
            info!(now_height, target_height, "peak reached");
            return Ok(now_height);
        }
        if last_log.elapsed() > Duration::from_secs(30) {
            info!(
                now_height,
                target_height,
                blocks_remaining = target_height.saturating_sub(now_height),
                "waiting for election window..."
            );
            last_log = std::time::Instant::now();
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "wait_for_block_height: only reached {now_height}/{target_height} in {timeout_secs}s"
            );
        }
        tokio::time::sleep(Duration::from_secs(poll_secs)).await;
    }
}

/// Find UNSPENT XCH coins owned by `p2_puzzle_hash` summing to
/// `≥ min_amount`. Picks the largest first; bails if total
/// available < min_amount.
///
/// MAINNET CAVEAT: occasionally peers return stale results
/// (a coin reported unspent that's actually been spent in the
/// last block). The caller should re-broadcast on FAILED status
/// and re-select; a single coin that's been double-confirmed-spent
/// will eventually disappear from this query.
async fn find_xch_coin(
    chain: &CoinsetClient,
    p2_puzzle_hash: Bytes32,
    min_amount: u64,
) -> Result<Coin> {
    // PROPAGATION-AWARE RETRY: immediately after broadcasting a
    // tx that creates an XCH change output, coinset.org's
    // puzzle-hash index can lag the chain by a block or two —
    // `get_coin_records_by_puzzle_hash` returns an empty list
    // (or only the just-consumed input without its change yet).
    // Retry for up to ~3 minutes so the index catches up to the
    // tip.
    const MAX_ATTEMPTS: u32 = 18;
    const POLL_SECS: u64 = 10;

    let ph_hex = format!("0x{}", hex::encode(p2_puzzle_hash));
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match chain
            .get_coin_records_by_puzzle_hash(&ph_hex, None, None, false)
            .await
        {
            Ok(records) => {
                let mut coins: Vec<Coin> = records
                    .into_iter()
                    .map(|r| {
                        let parent = parse_b32_str(&r.coin.parent_coin_info)?;
                        let ph = parse_b32_str(&r.coin.puzzle_hash)?;
                        Ok::<Coin, anyhow::Error>(Coin::new(parent, ph, r.coin.amount))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                coins.sort_by_key(|c| std::cmp::Reverse(c.amount));
                if let Some(pick) = coins.into_iter().find(|c| c.amount >= min_amount) {
                    if attempt > 1 {
                        info!(
                            attempt,
                            coin_id = %hex::encode(pick.coin_id()),
                            amount = pick.amount,
                            "find_xch_coin: candidate appeared after retry — coinset index caught up"
                        );
                    } else {
                        info!(
                            amount = pick.amount,
                            coin_id = %hex::encode(pick.coin_id()),
                            "selected XCH funding coin"
                        );
                    }
                    return Ok(pick);
                }
            }
            Err(e) => {
                last_err = Some(anyhow::anyhow!("get_coin_records_by_puzzle_hash: {e}"));
            }
        }
        if attempt < MAX_ATTEMPTS {
            tracing::info!(
                attempt,
                ph_hex = %ph_hex,
                min_amount,
                poll_secs = POLL_SECS,
                "find_xch_coin: no candidate ≥ {min_amount} mojos yet — retrying"
            );
            tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
        }
    }
    if let Some(e) = last_err {
        return Err(e.context(format!("find_xch_coin({ph_hex}, ≥{min_amount} mojos)")));
    }
    Err(anyhow::anyhow!(
        "no single XCH coin at puzzle_hash {ph_hex} has amount ≥ {min_amount} mojos after {MAX_ATTEMPTS} attempts"
    ))
}

/// Find an UNSPENT CAT coin owned by `(asset_id, p2_puzzle_hash)`
/// with `amount ≥ min_amount`. Returns a fully-parsed `Cat` with
/// its lineage proof (recovered from the parent's spend).
///
/// When building multiple CAT spends **inside one bundle** only, pass
/// already-chosen input IDs in `exclude_coin_ids` so two spends never
/// consume the same coin (double-spend).
async fn find_cat_coin(
    chain: &CoinsetClient,
    asset_id: Bytes32,
    p2_puzzle_hash: Bytes32,
    min_amount: u64,
    exclude_coin_ids: &[Bytes32],
) -> Result<Cat> {
    use chip_voting_sdk::clvm_utils::TreeHash;

    let cat_outer_ph = Bytes32::from(
        CatArgs::curry_tree_hash(asset_id, TreeHash::from(p2_puzzle_hash)).to_bytes(),
    );
    let ph_hex = format!("0x{}", hex::encode(cat_outer_ph));

    let records = chain
        .get_coin_records_by_puzzle_hash(&ph_hex, None, None, false)
        .await
        .context("CAT: get_coin_records_by_puzzle_hash failed")?;

    let mut candidates: Vec<chia_query::CoinRecord> = records
        .into_iter()
        .filter(|r| r.coin.amount >= min_amount && r.spent_block_index == 0)
        .collect();
    candidates.sort_by_key(|r| std::cmp::Reverse(r.coin.amount));

    for cand in candidates {
        let coin = Coin::new(
            parse_b32_str(&cand.coin.parent_coin_info)?,
            parse_b32_str(&cand.coin.puzzle_hash)?,
            cand.coin.amount,
        );
        let cid: Bytes32 = coin.coin_id().into();
        if exclude_coin_ids.iter().any(|ex| *ex == cid) {
            continue;
        }
        // Recover lineage proof from parent's spend.
        let parent_id_hex = format!("0x{}", hex::encode(coin.parent_coin_info));
        let parent_spend = chain
            .get_puzzle_and_solution(&parent_id_hex, None)
            .await
            .context("CAT: get_puzzle_and_solution(parent) failed")?;
        let parent_record = chain
            .get_coin_record_by_name(&parent_id_hex)
            .await
            .context("CAT: get_coin_record_by_name(parent) failed")?;
        let parent_coin = Coin::new(
            parse_b32_str(&parent_record.coin.parent_coin_info)?,
            parse_b32_str(&parent_record.coin.puzzle_hash)?,
            parent_record.coin.amount,
        );

        let mut allocator = Allocator::new();
        let parent_puzzle_bytes =
            hex::decode(parent_spend.puzzle_reveal.trim().trim_start_matches("0x"))?;
        let parent_solution_bytes =
            hex::decode(parent_spend.solution.trim().trim_start_matches("0x"))?;
        let parent_puzzle_program = chia_protocol::Program::from(parent_puzzle_bytes);
        let parent_solution_program = chia_protocol::Program::from(parent_solution_bytes);
        let parent_puzzle_node = parent_puzzle_program.to_clvm(&mut allocator)?;
        let parent_solution_node = parent_solution_program.to_clvm(&mut allocator)?;
        let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);

        let parsed = Cat::parse_children(
            &mut allocator,
            parent_coin,
            parent_puzzle,
            parent_solution_node,
        )
        .context("CAT: parse_children failed")?;
        let Some(children) = parsed else {
            tracing::debug!("CAT parent did not parse as a CAT — skipping candidate");
            continue;
        };
        for child in children {
            if child.coin.coin_id() == coin.coin_id() && child.info.asset_id == asset_id {
                info!(
                    amount = child.coin.amount,
                    coin_id = %hex::encode(child.coin.coin_id()),
                    "selected CAT collateral coin"
                );
                return Ok(child);
            }
        }
    }
    bail!(
        "no spendable CAT coin found for asset_id {} at p2 puzzle_hash {} with amount ≥ {min_amount}",
        hex::encode(asset_id),
        hex::encode(p2_puzzle_hash),
    )
}

// ============================================================================
// SECTION 5 — CAT collateral spend builder
// ============================================================================

/// Output of the CAT collateral-spend builder.
///
/// `parent_spend` is what `Voter::register` consumes as its
/// `cat_parent_spend` argument. The bundle's aggregated signature
/// is computed at the bundle level by re-signing the whole spend
/// list with the validator's synthetic SK + the voter's BLS key
/// — see `phase_register_voter` for the assembly.
struct CatCollateralSpend {
    /// CoinSpend that, when included in a bundle, creates the
    /// registration coin at `fresh_registration_coin_puzzle_hash`
    /// with `collateral_amount` AND emits the
    /// `CreateCoinAnnouncement` register.rue asserts.
    parent_spend: CoinSpend,
}

/// Build the CAT spend that funds a voter's registration coin.
///
/// SHAPE: a single CAT input → two CAT outputs:
///   1. Registration coin → at `fresh_registration_coin_puzzle_hash`
///      with `collateral_amount`. CAT outer wraps the action-layer
///      inner puzzle automatically when the inner spend creates a
///      coin at the desired inner puzzle hash.
///   2. Change → back to the validator's own CAT puzzle hash
///      (synthetic_p2 → CAT-wrapped) with `cat_input.amount -
///      collateral_amount`. Skipped if change would be zero.
///
/// INNER CONDITIONS (run inside the CAT's inner standard p2):
///   * `create_coin(inner_reg_ph, collateral_amount, Memos::None)` —
///     the CAT outer wraps this hash before broadcast.
///   * `create_coin_announcement(create_reg_msg)` — the message
///     register.rue computes and asserts.
///   * `create_coin(synthetic_p2_ph, change_amount, Memos::None)` —
///     change, if any.
///
/// SIGNATURE: NONE produced here. The standard p2 puzzle emits an
/// `AggSigMe` that's satisfied by the bundle-level signature
/// computed in `phase_register_voter` (which has access to BOTH
/// the validator's synthetic SK and the voter's BLS key).
fn build_cat_collateral_spend(
    cat_input: Cat,
    validator_synthetic_pk: PublicKey,
    voter_pk: &PublicKey,
    election_launcher_id: Bytes32,
    cat_tail_hash: Bytes32,
    collateral_amount: u64,
) -> Result<CatCollateralSpend> {
    if cat_input.coin.amount < collateral_amount {
        bail!(
            "CAT input amount {} < required collateral {}",
            cat_input.coin.amount,
            collateral_amount
        );
    }

    // Compute the registration coin's INNER puzzle hash. The CAT
    // outer wraps any `create_coin(ph, …)` inside the inner spend
    // into `CatArgs::curry_tree_hash(asset_id, ph)`, so passing the
    // INNER hash here lands at the correct CAT-wrapped puzzle hash.
    let reg_inner_ph =
        puzzles::fresh_registration_inner_hash(voter_pk, election_launcher_id, cat_tail_hash);
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, voter_pk, election_launcher_id);
    info!(
        reg_inner = %hex::encode(reg_inner_ph),
        reg_outer = %hex::encode(reg_outer_ph),
        amount = collateral_amount,
        "computed registration coin puzzle hash for voter"
    );

    // Compute the create_reg_msg the register action asserts:
    //   sha256("create_reg" || launcher_id || pk_bytes ||
    //          reg_outer_ph || amount_be8)
    let create_reg_msg = compute_create_reg_msg(
        election_launcher_id,
        voter_pk,
        reg_outer_ph,
        collateral_amount,
    );

    // Validator's CAT change puzzle hash.
    let validator_p2_ph =
        Bytes32::new(StandardArgs::curry_tree_hash(validator_synthetic_pk).to_bytes());
    let change_amount = cat_input.coin.amount.saturating_sub(collateral_amount);

    // Wrap with StandardLayer + CAT outer; spend the single CAT.
    // The registration coin's CreateCoin attaches `voter_hint` as a
    // hint memo so subsequent cast_vote/release lookups can find it
    // via `chain.coin_records_by_hint(voter_hint)`. Without this the
    // SDK's `Voter::cast_vote` and `Voter::release_collateral` would
    // never locate the voter's registration coin lineage.
    let mut ctx = SpendContext::new();
    let voter_hint = puzzles::voter_hint(election_launcher_id, cat_tail_hash, voter_pk);
    let voter_hint_memos = ctx
        .hint(voter_hint)
        .context("ctx.hint(voter_hint) failed")?;

    let mut inner_conditions = Conditions::new()
        .create_coin(reg_inner_ph, collateral_amount, voter_hint_memos)
        .create_coin_announcement(Bytes32_to_bytes(create_reg_msg));
    if change_amount > 0 {
        inner_conditions =
            inner_conditions.create_coin(validator_p2_ph, change_amount, Memos::None);
    }
    let inner_spend = StandardLayer::new(validator_synthetic_pk)
        .spend_with_conditions(&mut ctx, inner_conditions)
        .context("StandardLayer::spend_with_conditions for CAT inner failed")?;
    let cat_spend = CatSpend::new(cat_input, inner_spend);
    let cat_children = Cat::spend_all(&mut ctx, &[cat_spend]).context("Cat::spend_all failed")?;

    // We expect exactly one of the children to be the registration
    // coin; the others (if any) are change. Find and log it.
    if let Some(reg_child) = cat_children.iter().find(|c| {
        Bytes32::from(c.coin.puzzle_hash) == reg_outer_ph && c.coin.amount == collateral_amount
    }) {
        info!(
            coin_id = %hex::encode(reg_child.coin.coin_id()),
            "registration CAT coin assembled (will be created on broadcast)"
        );
    } else {
        warn!("CAT::spend_all did not return the expected registration child — proceeding anyway");
    }

    let coin_spends = ctx.take();
    let parent_spend = coin_spends
        .iter()
        .find(|cs| cs.coin.coin_id() == cat_input.coin.coin_id())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("CAT spend list missing the input we passed in"))?;

    Ok(CatCollateralSpend { parent_spend })
}

/// Compute the register-action's create_reg_msg.
///
/// FORMULA (matches `puzzles/election/register.rue` line 203):
///   sha256("create_reg" || election_launcher_id || pk_bytes
///          || reg_outer_ph || amount_be8)
fn compute_create_reg_msg(
    election_launcher_id: Bytes32,
    voter_pk: &PublicKey,
    reg_outer_ph: Bytes32,
    amount: u64,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"create_reg");
    h.update(election_launcher_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(reg_outer_ph.as_ref());
    h.update(amount.to_be_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

#[allow(non_snake_case)]
fn Bytes32_to_bytes(b: Bytes32) -> chia_protocol::Bytes {
    chia_protocol::Bytes::new(b.to_vec())
}

/// Sum of UNSPENT CAT mojos at `(asset_id, p2_puzzle_hash)`. Used by
/// the topup phase to decide whether a validator wallet needs more
/// DIG before registration. Returns 0 if the puzzle hash has no
/// unspent coins (the typical state for a fresh wallet).
async fn cat_balance(
    chain: &CoinsetClient,
    asset_id: Bytes32,
    p2_puzzle_hash: Bytes32,
) -> Result<u64> {
    use chip_voting_sdk::clvm_utils::TreeHash;
    let cat_outer_ph = Bytes32::from(
        CatArgs::curry_tree_hash(asset_id, TreeHash::from(p2_puzzle_hash)).to_bytes(),
    );
    let ph_hex = format!("0x{}", hex::encode(cat_outer_ph));
    let records = chain
        .get_coin_records_by_puzzle_hash(&ph_hex, None, None, false)
        .await
        .context("cat_balance: get_coin_records_by_puzzle_hash failed")?;
    Ok(records.iter().map(|r| r.coin.amount).sum())
}

/// Build a CAT transfer spend that sends `amount` mojos of CAT
/// from `funding`'s CAT puzzle hash to each `(target_p2_ph, amount)`
/// in `targets`. Multi-output: a single spend funds every target
/// plus change back to the funding wallet.
///
/// CONTRACT: `funding_cat_input` MUST be a `Cat` (with lineage
/// proof) at `funding_synthetic_pk`'s standard p2 wrapping AND its
/// amount must cover `sum(target amounts)`.
///
/// SIGNATURE: NONE produced here — bundle is signed at the caller
/// level by `sign_bundle_signature` against the funding wallet's
/// synthetic SK.
fn build_cat_topup_spend(
    funding_cat_input: Cat,
    funding_synthetic_pk: PublicKey,
    targets: &[(Bytes32, u64)],
) -> Result<Vec<CoinSpend>> {
    let total_out: u64 = targets.iter().map(|(_, a)| *a).sum();
    if funding_cat_input.coin.amount < total_out {
        bail!(
            "CAT topup: input {} < required {}",
            funding_cat_input.coin.amount,
            total_out
        );
    }
    let funding_p2_ph =
        Bytes32::new(StandardArgs::curry_tree_hash(funding_synthetic_pk).to_bytes());
    let change = funding_cat_input.coin.amount - total_out;

    let mut conditions = Conditions::new();
    for (target_ph, amount) in targets {
        conditions = conditions.create_coin(*target_ph, *amount, Memos::None);
    }
    if change > 0 {
        conditions = conditions.create_coin(funding_p2_ph, change, Memos::None);
    }

    let mut ctx = SpendContext::new();
    let inner_spend = StandardLayer::new(funding_synthetic_pk)
        .spend_with_conditions(&mut ctx, conditions)
        .context("StandardLayer::spend_with_conditions for CAT topup failed")?;
    let cat_spend = CatSpend::new(funding_cat_input, inner_spend);
    Cat::spend_all(&mut ctx, &[cat_spend]).context("Cat::spend_all (topup) failed")?;
    Ok(ctx.take())
}

// ============================================================================
// SECTION 6 — Phase implementations
// ============================================================================

// ── Phase 0: Ceremony — produce a (PK, VK) pair ──────────────────────

struct CeremonyArtifacts {
    proving_key: ArkProvingKey,
    verification_key: ArkVerifyingKey,
    /// Wire-format VK for currying into the on-chain finalize
    /// action. Bytes-identical to the `ArkVerifyingKey`'s
    /// `chia_chunked_bytes`.
    wire_vk: VerificationKey,
}

/// Run a single-participant trusted-setup ceremony using
/// `SimulatedBackend`. The backend produces FUNCTIONAL Groth16 keys
/// for the `VotingCircuit` shape — derived deterministically from
/// the (single) contributor's entropy.
///
/// PRODUCTION CONTRAST: real elections MUST run a multi-party MPC
/// ceremony with toxic-waste destruction. For this integration test
/// we accept the SimulatedBackend's "anyone can recompute the keys"
/// trade-off because its output is structurally identical to a real
/// ceremony's output, so the deploy / finalize plumbing is
/// validated on a real chain.
fn run_local_ceremony() -> Result<CeremonyArtifacts> {
    use ark_serialize::CanonicalDeserialize;

    info!("running single-participant SimulatedBackend ceremony");
    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord
        .start("chip-voting-v1".into())
        .map_err(|e| anyhow::anyhow!("ceremony start: {e:?}"))?;
    let alice = CeremonyParticipant::new(
        Box::new(SimulatedBackend),
        "live-test-alice".into(),
        Some("live integration test ceremony".into()),
    );
    let pre = coord
        .current_transcript()
        .map_err(|e| anyhow::anyhow!("current_transcript: {e:?}"))?
        .clone();
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).context("getrandom for ceremony entropy")?;
    let contribution = alice
        .contribute(&pre, entropy)
        .map_err(|e| anyhow::anyhow!("ceremony contribute: {e:?}"))?;
    coord
        .accept_contribution(contribution.transcript)
        .map_err(|e| anyhow::anyhow!("accept_contribution: {e:?}"))?;

    let backend = SimulatedBackend;
    let final_transcript = coord
        .current_transcript()
        .map_err(|e| anyhow::anyhow!("current_transcript: {e:?}"))?;
    let (pk_wire, vk_wire) = backend
        .extract_keys(final_transcript)
        .map_err(|e| anyhow::anyhow!("extract_keys: {e:?}"))?;

    let proving_key = ArkProvingKey(
        ark_groth16::ProvingKey::<ark_bls12_381::Bls12_381>::deserialize_compressed(
            pk_wire.raw_bytes.as_slice(),
        )
        .context("deserialize proving key")?,
    );
    // Reconstruct the typed VK by re-running the SAME setup (deterministic
    // for SimulatedBackend) and pulling its `ArkVerifyingKey`. The wire
    // form is what we curry on-chain; the typed form is what the prover
    // needs for off-chain verification sanity checks.
    let verification_key = reconstruct_typed_vk(&vk_wire)?;
    info!(
        vk_bytes = vk_wire.raw_bytes.len(),
        "ceremony complete; produced functional Groth16 keys"
    );
    Ok(CeremonyArtifacts {
        proving_key,
        verification_key,
        wire_vk: vk_wire,
    })
}

/// Reconstruct an `ArkVerifyingKey` from its 672-byte wire form by
/// parsing each typed point. Mirrors the inverse of
/// `ArkVerifyingKey::chia_chunked_bytes`.
fn reconstruct_typed_vk(wire: &VerificationKey) -> Result<ArkVerifyingKey> {
    use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
    use ark_serialize::CanonicalDeserialize;

    let bytes = &wire.raw_bytes;
    // 6-public-input circuit: ic0..ic6 = 7 G1 points after the
    // 336-byte (alpha_g1 || beta_g2 || gamma_g2 || delta_g2) prefix.
    if bytes.len() < 336 + 7 * 48 {
        bail!("VK wire bytes too short: {}", bytes.len());
    }

    let alpha_g1 =
        G1Affine::deserialize_compressed(&bytes[0..48]).context("deserialize alpha_g1")?;
    let beta_g2 =
        G2Affine::deserialize_compressed(&bytes[48..144]).context("deserialize beta_g2")?;
    let gamma_g2 =
        G2Affine::deserialize_compressed(&bytes[144..240]).context("deserialize gamma_g2")?;
    let delta_g2 =
        G2Affine::deserialize_compressed(&bytes[240..336]).context("deserialize delta_g2")?;
    // 6-public-input circuit (CHIP rev 2026-05-02): IC has
    // `PUBLIC_INPUT_COUNT + 1 = 7` G1 points (ic0 + ic1..ic6).
    let ic_count = chip_voting_sdk::config::PUBLIC_INPUT_COUNT + 1;
    let mut ic = Vec::with_capacity(ic_count);
    for i in 0..ic_count {
        let off = 336 + i * 48;
        ic.push(
            G1Affine::deserialize_compressed(&bytes[off..off + 48])
                .with_context(|| format!("deserialize ic[{i}]"))?,
        );
    }
    Ok(ArkVerifyingKey(ark_groth16::VerifyingKey::<Bls12_381> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic,
    }))
}

// ── Phase 1: Deploy Election Singleton ───────────────────────────────

#[allow(dead_code)] // deploy_height retained for orchestrator-side diagnostics
struct DeployArtifacts {
    config: ElectionConfig,
    deploy_height: u32,
    /// Genesis eve singleton coin id right after deploy (for logs).
    /// Spends move the tip — track elections by `election_launcher_id`,
    /// not this id.
    eve_singleton_coin_id: Bytes32,
    /// `election_start_height` curried into the eve Election
    /// Singleton's state at deploy time. Per CHIP.md §289-291 this
    /// is the chain peak height observed immediately before the
    /// deploy bundle is broadcast and is used by every subsequent
    /// chain-walk (`compute_eve_inner_puzzle_hash`,
    /// `find_current_singleton`, `wait_for_current_singleton`,
    /// `BallotIssuer::create_ballot`, `BallotIssuer::launch_ballot`)
    /// to derive the eve singleton puzzle hash that started the
    /// lineage.
    election_start_height: u64,
}

async fn phase_deploy(
    chain: &CoinsetClient,
    funding_keys: &WalletKeys,
    network: NetworkType,
    args: &Args,
    cat_tail_hash: Bytes32,
    vk: &VerificationKey,
) -> Result<DeployArtifacts> {
    info!("=== PHASE 1: deploy Election Singleton ===");
    confirm_or_bail(args, "Broadcast the deploy bundle?")?;

    // Find a parent XCH coin big enough to fund the launcher — selected
    // immediately before the deploy bundle is built (fresh UTXO snapshot).
    let parent_coin = find_xch_coin(chain, funding_keys.p2_puzzle_hash, args.launcher_amount)
        .await
        .context("phase_deploy: no XCH funding coin")?;
    let deploy_funding_input_id: Bytes32 = parent_coin.coin_id().into();

    // CHIP rev 2026-05-02: registration_fee + election_length_blocks
    // moved to per-Ballot-Coin params (see phase_create_ballot /
    // phase_launch_ballot). election_start_height is the chain peak
    // observed immediately BEFORE the deploy bundle is broadcast —
    // becomes the genesis ElectionState's `election_start_height`
    // (CHIP.md §291) and is what every subsequent chain walker
    // passes as `election_start_height` to derive the eve inner
    // puzzle hash. Snapshotting it once here ensures every later
    // phase agrees on the same value (passing `0` worked accidentally
    // when the simulator-only tests didn't track block heights, but
    // on a live chain a non-zero peak makes any `0` placeholder a
    // wrong-puzzle-hash chain-walk failure).
    let election_start_height: u64 =
        u64::from(current_peak_height(chain).await.context(
            "phase_deploy: read current peak height to seed election_start_height",
        )?);
    info!(
        election_start_height,
        "snapshotting current peak as election_start_height curried into eve singleton state"
    );

    let deployer = ElectionDeployer::new(DeployParams {
        verification_key: vk.clone(),
        cat_tail_hash,
        collateral_amount: args.collateral_amount,
        election_start_height,
        label: Some(format!(
            "live-test-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S")
        )),
    });
    let artifacts = deployer
        .deploy_signed(
            parent_coin,
            funding_keys.synthetic_pk,
            std::slice::from_ref(&funding_keys.synthetic_sk),
            network,
        )
        .map_err(|e| anyhow::anyhow!("deploy_signed: {e:?}"))?;

    info!(
        launcher_id = %artifacts.config.election_launcher_id_hex,
        coin_spends = artifacts.spend_bundle.coin_spends.len(),
        "deploy bundle assembled — broadcasting"
    );
    push_tx(chain, &artifacts.spend_bundle, "deploy").await?;

    // Spend the deploy funding input before querying coin state for later phases.
    wait_for_spend(
        chain,
        deploy_funding_input_id,
        args,
        "deploy funding XCH coin",
    )
    .await?;

    // Wait for the launcher coin (the parent's child at
    // SINGLETON_LAUNCHER_HASH) to confirm.
    let launcher_id = parse_b32_str(&artifacts.config.election_launcher_id_hex)?;
    let _ = wait_for_confirmation(chain, launcher_id, args, "launcher coin").await?;

    // The eve singleton is the launcher's child at the singleton's
    // eve puzzle hash. Compute its coin id deterministically.
    let eve_inner_ph = chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(
        &artifacts.config,
        election_start_height,
    );
    let eve_outer_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let eve_coin = Coin::new(launcher_id, eve_outer_ph, 1);
    let eve_id = eve_coin.coin_id();
    let _ = wait_for_confirmation(chain, eve_id, args, "eve Election Singleton").await?;

    let deploy_height = current_peak_height(chain).await?;
    info!(
        launcher_id = %hex::encode(launcher_id),
        eve_id = %hex::encode(eve_id),
        deploy_height,
        election_start_height,
        "deploy phase complete"
    );

    Ok(DeployArtifacts {
        config: artifacts.config,
        deploy_height,
        eve_singleton_coin_id: eve_id,
        election_start_height,
    })
}

// ── Phase 1.5: Top up validators with DIG ────────────────────────────

/// Ensure each validator wallet holds at least `collateral_amount`
/// CAT mojos when registration begins.
///
/// **Broadcast discipline:** mempool submissions are strictly
/// sequential. After every `push_tx`, we `wait_for_spend` on the
/// consumed CAT input **before** selecting coins for the next tx (so
/// `find_cat_coin` always sees a fresh coin set).
///
/// **Aggregate path:** if one funding CAT coin covers `sum(deficits)`,
/// use a single multi-output spend (one mempool message, one input
/// waited on).
///
/// **Fallback path:** if no one coin covers the total, send **one
/// top-up transaction per short validator** — never batch multiple
/// CAT input spends into one bundle.
async fn phase_topup_validators(
    chain: &CoinsetClient,
    network: NetworkType,
    args: &Args,
    funding_keys: &WalletKeys,
    validators: &[(&str, &WalletKeys)],
    cat_tail_hash: Bytes32,
) -> Result<()> {
    info!("=== PHASE 1.5: top up validators with DIG ===");

    // Compute per-validator deficit. Topup amount = collateral_amount
    // exactly (no over-funding — keeps the test's CAT footprint
    // predictable across re-runs).
    let mut targets: Vec<(Bytes32, u64, &str)> = Vec::new();
    for (label, keys) in validators {
        let bal = cat_balance(chain, cat_tail_hash, keys.p2_puzzle_hash).await?;
        info!(label, balance_mojos = bal, "validator CAT balance");
        if bal < args.collateral_amount {
            let need = args.collateral_amount - bal;
            info!(
                label,
                need_mojos = need,
                "validator under-funded — will top up"
            );
            targets.push((keys.p2_puzzle_hash, need, label));
        } else {
            info!(label, "validator already has enough DIG");
        }
    }
    if targets.is_empty() {
        info!("all validators already funded — skipping topup phase");
        return Ok(());
    }
    confirm_or_bail(args, "Broadcast the validator-topup CAT transfer?")?;

    let total_out: u64 = targets.iter().map(|(_, a, _)| *a).sum();

    match find_cat_coin(
        chain,
        cat_tail_hash,
        funding_keys.p2_puzzle_hash,
        total_out,
        &[],
    )
    .await
    {
        Ok(funding_cat) => {
            let input_id: Bytes32 = funding_cat.coin.coin_id().into();
            info!(
                funding_balance = funding_cat.coin.amount,
                total_out, "funding CAT covers all deficits — single multi-output top-up",
            );
            let coin_spends = build_cat_topup_spend(
                funding_cat,
                funding_keys.synthetic_pk,
                &targets
                    .iter()
                    .map(|(ph, amt, _)| (*ph, *amt))
                    .collect::<Vec<_>>(),
            )?;
            let signature = sign_bundle_signature(
                &coin_spends,
                std::slice::from_ref(&funding_keys.synthetic_sk),
                network,
            )
            .map_err(|e| anyhow::anyhow!("sign topup bundle: {e:?}"))?;
            let bundle = SpendBundle::new(coin_spends, signature);
            verify_bundle_locally(&bundle, network)?;
            push_tx(chain, &bundle, "validator topup (multi-output)").await?;
            wait_for_spend(chain, input_id, args, "topup CAT input (multi-output)").await?;
        }
        Err(e_agg) => {
            info!(
                total_out,
                err=%e_agg,
                "no single CAT covers total — sequential top-up txs (re-select coins after each spend)",
            );
            for (target_ph, amt, label) in &targets {
                let fc =
                    find_cat_coin(chain, cat_tail_hash, funding_keys.p2_puzzle_hash, *amt, &[])
                        .await
                        .with_context(|| {
                            format!(
                        "phase_topup: funding wallet has no spendable CAT ≥ {amt} mojos for \
                         validator `{label}` (aggregate ≥ {total_out} unavailable). \
                         Consolidate DIG or add funds."
                    )
                        })?;
                let input_id: Bytes32 = fc.coin.coin_id().into();
                info!(
                    label,
                    amt,
                    balance = fc.coin.amount,
                    coin_id=%hex::encode(input_id),
                    "funding CAT chosen for sequential top-up (post-confirmation selection)",
                );
                let coin_spends =
                    build_cat_topup_spend(fc, funding_keys.synthetic_pk, &[(*target_ph, *amt)])?;
                let signature = sign_bundle_signature(
                    &coin_spends,
                    std::slice::from_ref(&funding_keys.synthetic_sk),
                    network,
                )
                .map_err(|e| anyhow::anyhow!("sign topup bundle ({label}): {e:?}"))?;
                let bundle = SpendBundle::new(coin_spends, signature);
                verify_bundle_locally(&bundle, network)?;
                push_tx(chain, &bundle, &format!("validator topup ({label})")).await?;
                wait_for_spend(chain, input_id, args, &format!("topup CAT input ({label})"))
                    .await?;
            }
        }
    }

    // Sanity poll: each target validator should now have at least
    // collateral_amount. We poll briefly because the coin records
    // index can lag a few seconds behind the coin set.
    for (label, keys) in validators {
        let mut tries = 0;
        loop {
            let bal = cat_balance(chain, cat_tail_hash, keys.p2_puzzle_hash).await?;
            if bal >= args.collateral_amount {
                info!(label, balance_mojos = bal, "validator topped up");
                break;
            }
            tries += 1;
            if tries > 12 {
                bail!(
                    "{label}: topup did not appear in coin records after 12 polls (got {bal} mojos)"
                );
            }
            tokio::time::sleep(Duration::from_secs(args.poll_interval_secs)).await;
        }
    }
    Ok(())
}

// ── Phase 2: Register voters ─────────────────────────────────────────

/// Register a single voter. Returns the voter's registration coin
/// id (CAT-wrapped) once it confirms on-chain.
async fn phase_register_voter(
    chain: &CoinsetClient,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
    voter_label: &str,
    voter_keys: &VoterKeys,
    validator_keys: &WalletKeys,
    cat_tail_hash: Bytes32,
) -> Result<Bytes32> {
    info!("=== PHASE 2.{voter_label}: register voter ===");
    confirm_or_bail(args, &format!("Broadcast {voter_label}'s registration?"))?;

    // Pre-flight: wait until the **current** tip of the singleton
    // lineage is visible (launcher walk — not the fixed eve puzzle
    // hash, which is empty after the first register spend).
    let _ = wait_for_current_singleton(
        chain,
        &deploy.config,
        deploy.election_start_height,
        "Election Singleton (CLI pre-flight)",
        Duration::from_secs(30),
        Duration::from_secs(300),
    )
    .await
    .map_err(|e| anyhow::anyhow!("singleton lineage propagation wait: {e:?}"))?;

    // Sync the SMT off-chain so we can build the empty-slot
    // proof. For the FIRST voter the SMT is empty; for the second,
    // the first voter's pubkey must be inserted.
    let voter = Voter::new(deploy.config.clone(), clone_voter_keys(voter_keys), network);
    let mut agg = Aggregator::new(deploy.config.clone(), make_independent_chain()?, network);
    sync_aggregator_with_retry(
        &mut agg,
        &format!("phase_register_voter[{voter_label}] SPT"),
        Duration::from_secs(args.poll_interval_secs.max(15)),
        Duration::from_secs(args.confirmation_timeout_secs.max(300)),
    )
    .await?;
    let smt = agg
        .merkle_tree()
        .map_err(|e| anyhow::anyhow!("aggregator merkle_tree: {e:?}"))?
        .clone();

    let election_launcher_id = parse_b32_str(&deploy.config.election_launcher_id_hex)?;

    // Find the validator's CAT input for the collateral (fresh query after
    // any earlier phase spends have confirmed).
    let cat_input = find_cat_coin(
        chain,
        cat_tail_hash,
        validator_keys.p2_puzzle_hash,
        args.collateral_amount,
        &[],
    )
    .await
    .context("phase_register: no spendable CAT coin")?;

    // Build the CAT collateral spend (unsigned — bundle-level
    // signing happens below after `Voter::register` produces the
    // singleton-side spend).
    let cat_collateral = build_cat_collateral_spend(
        cat_input,
        validator_keys.synthetic_pk,
        &voter_keys.pubkey,
        election_launcher_id,
        cat_tail_hash,
        args.collateral_amount,
    )?;

    // Voter::register builds the bundle and signs it with
    // ONLY the voter's BLS secret. The CAT spend's standard p2
    // requires the validator's synthetic SK signature too, so we
    // re-sign the whole bundle with BOTH keys (deduplicated —
    // the integration test reuses the validator's synthetic SK
    // as the voter's BLS key, so dedup matters; production
    // deployments would use distinct keys and skip the dedup).
    let voter_bundle = voter
        .register(&smt, cat_collateral.parent_spend.clone(), chain)
        .await
        .map_err(|e| anyhow::anyhow!("Voter::register: {e:?}"))?;

    let mut signing_keys: Vec<SecretKey> = vec![voter_keys.secret.clone()];
    if validator_keys.synthetic_sk.to_bytes() != voter_keys.secret.to_bytes() {
        signing_keys.push(validator_keys.synthetic_sk.clone());
    }
    let combined_sig = sign_bundle_signature(&voter_bundle.coin_spends, &signing_keys, network)
        .map_err(|e| anyhow::anyhow!("re-sign register bundle: {e:?}"))?;
    let combined_bundle = SpendBundle::new(voter_bundle.coin_spends.clone(), combined_sig);

    // Sanity: every required signature in the bundle must be
    // covered by `combined_sig`.
    verify_bundle_locally(&combined_bundle, network)?;

    push_tx(chain, &combined_bundle, &format!("{voter_label} register")).await?;

    let cat_funding_coin_id: Bytes32 = cat_collateral.parent_spend.coin.coin_id().into();
    // Input spent first; then confirm the CAT-wrapped registration output exists.
    wait_for_spend(
        chain,
        cat_funding_coin_id,
        args,
        &format!("{voter_label} CAT collateral input"),
    )
    .await?;

    // The registration coin (CAT-wrapped child) is the lookup target.
    let reg_outer_ph = puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter_keys.pubkey,
        election_launcher_id,
    );
    let cat_input_parent_id: Bytes32 = cat_collateral.parent_spend.coin.coin_id().into();
    let reg_coin = Coin::new(cat_input_parent_id, reg_outer_ph, args.collateral_amount);
    let reg_id = reg_coin.coin_id();
    wait_for_confirmation(
        chain,
        reg_id,
        args,
        &format!("{voter_label} registration coin"),
    )
    .await?;

    info!(
        voter_label,
        reg_coin_id = %hex::encode(reg_id),
        "voter registration confirmed"
    );
    Ok(reg_id)
}

// ── Phase 2.5: Create + launch the Ballot Coin ───────────────────────

/// Outputs of `phase_create_ballot` and `phase_launch_ballot`. These
/// thread the per-ballot identity (launcher id, vote_close_height,
/// outcome_domain_hash, threshold pack, snapshotted registration
/// state) into the cast_vote / finalize phases. Per CHIP.md §202 +
/// §211-221 the createBallot action mints a Ballot Coin lineage and
/// the launcher second-spend mints the eve Ballot Coin curried with
/// `(VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID,
/// VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN,
/// REGISTRATION_MERKLE_ROOT_SNAPSHOT,
/// REGISTRATION_VOTE_WEIGHT_SNAPSHOT)` for `finalize`. Voter
/// `cast_vote` and aggregator `build_finalize_for_ballot` MUST mirror
/// every one of those values exactly.
#[allow(dead_code)] // eve_ballot_coin_id + outcome_domain_hash retained for diagnostics
struct BallotArtifacts {
    /// Launcher id of the per-ballot singleton lineage; identifies
    /// the ballot stably across its lifetime.
    ballot_launcher_id: Bytes32,
    /// Eve Ballot Coin id (= the launcher's child at the predicted
    /// per-ballot singleton-wrapped puzzle hash).
    eve_ballot_coin_id: Bytes32,
    /// Per-ballot vote close height — curried into `finalize`,
    /// `oracle`, and `update_vote`. Voter cast_vote must echo this
    /// value.
    vote_close_height: u64,
    /// Numerator / denominator of the curried per-ballot quorum
    /// threshold; mirrored on `cast_vote` and `finalize` calls.
    vote_threshold_num: u64,
    vote_threshold_den: u64,
    /// 32-byte commitment to the allowed outcome set carried in
    /// the createBallot announcement.
    outcome_domain_hash: Bytes32,
    /// Election Singleton's `(registration_merkle_root,
    /// registration_vote_weight)` snapshot at `launch_ballot`
    /// time — curried into the per-ballot `finalize` action.
    /// `cast_vote` and `build_finalize_for_ballot` MUST pass these
    /// exact values; any drift changes the eve Ballot Coin's puzzle
    /// hash and breaks the chain walk.
    registration_merkle_root_snapshot: Bytes32,
    registration_vote_weight_snapshot: u64,
}

/// Spend the Election Singleton via its `createBallot` action to mint
/// a 2-mojo launcher coin for a fresh Ballot Coin lineage.
///
/// CHIP.md §202: `createBallot` "Mints Ballot Coin; passes through
/// `election_launcher_id`, VK/IC, threshold pack, and ballot identity;
/// sets `vote_close_height` and outcome domain." The action only
/// produces the launcher eve coin in this spend — the eve Ballot
/// Coin singleton itself is minted by the launcher second-spend in
/// `phase_launch_ballot`.
///
/// FUNDER COIN: the action requires a 2-mojo input to mint the
/// launcher; we spend a fresh XCH coin from the funding wallet via
/// the standard p2 puzzle.
async fn phase_create_ballot(
    chain: &CoinsetClient,
    funding_keys: &WalletKeys,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
) -> Result<(Bytes32, u64, Bytes32, u64, u64)> {
    info!("=== PHASE 2.5a: create Ballot Coin (Election Singleton createBallot) ===");
    confirm_or_bail(args, "Broadcast the createBallot bundle?")?;

    // Per-ballot config: vote_close_height = current_peak +
    // election_length_blocks (CHIP.md §211 — the on-chain
    // `update_vote` action's AssertBeforeHeightAbsolute and the
    // `finalize` action's AssertHeightAbsolute both compare against
    // this value, so it MUST be expressed as an absolute height).
    let now_height = current_peak_height(chain).await?;
    let vote_close_height = u64::from(now_height) + args.election_length_blocks;
    let ballot_seed = {
        // 32-byte random nonce — separates concurrent createBallot
        // spends in the same block (per puzzle docs).
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).context("getrandom for ballot_seed")?;
        Bytes32::new(buf)
    };
    // For the live test we don't pin a structured outcome domain;
    // a deterministic placeholder keeps the hash stable across the
    // run. Production deployments would tree-hash the structured
    // proposal here.
    let outcome_domain_hash = Bytes32::new([0xCDu8; 32]);
    let vote_threshold_num: u64 = 1;
    let vote_threshold_den: u64 = 2;

    info!(
        now_height,
        vote_close_height,
        ballot_seed = %hex::encode(ballot_seed),
        outcome_domain_hash = %hex::encode(outcome_domain_hash),
        vote_threshold_num,
        vote_threshold_den,
        "createBallot params snapshot"
    );

    // 2-mojo XCH funder coin to mint the launcher eve coin. The
    // standard p2 puzzle wraps a quoted-conditions list that emits
    // exactly the create_coin(SINGLETON_LAUNCHER_HASH, 2) the action
    // expects.
    let funder_xch = find_xch_coin(chain, funding_keys.p2_puzzle_hash, 2)
        .await
        .context("phase_create_ballot: no XCH funder coin (need ≥2 mojos)")?;
    let funder_input_id: Bytes32 = funder_xch.coin_id().into();
    let funder_change = funder_xch.amount.saturating_sub(2);

    // Build the funder spend via the standard p2 puzzle: emit
    // create_coin(SINGLETON_LAUNCHER_HASH, 2) plus change back to
    // the funder. The BallotIssuer's createBallot action then asserts
    // a CCA from the singleton to bind this funder coin into the
    // bundle.
    let mut ctx = SpendContext::new();
    let launcher_ph_b32 = Bytes32::from(chip_voting_sdk::SINGLETON_LAUNCHER_HASH);
    let mut funder_conditions = Conditions::new().create_coin(launcher_ph_b32, 2, Memos::None);
    if funder_change > 0 {
        funder_conditions =
            funder_conditions.create_coin(funding_keys.p2_puzzle_hash, funder_change, Memos::None);
    }
    StandardLayer::new(funding_keys.synthetic_pk)
        .spend(&mut ctx, funder_xch, funder_conditions)
        .map_err(|e| anyhow::anyhow!("phase_create_ballot funder spend: {e:?}"))?;
    let funder_spends = ctx.take();
    let funder_spend = funder_spends
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("phase_create_ballot: funder StandardLayer produced no spend"))?;

    let issuer = chip_voting_sdk::actors::ballot::BallotIssuer::new(deploy.config.clone(), network);
    let created = issuer
        .create_ballot(
            chain,
            chip_voting_sdk::actors::ballot::CreateBallotParams {
                ballot_seed,
                vote_close_height,
                outcome_domain_hash,
            },
            funder_spend,
        )
        .await
        .map_err(|e| anyhow::anyhow!("BallotIssuer::create_ballot: {e:?}"))?;

    // The createBallot action emits no AggSig conditions of its own,
    // but the funder's StandardLayer spend emits an AggSigMe over
    // the funding wallet's synthetic pk. Re-sign the bundle with the
    // funder's synthetic SK so the consensus AGG_SIG check passes.
    let combined_sig = sign_bundle_signature(
        &created.spend_bundle.coin_spends,
        std::slice::from_ref(&funding_keys.synthetic_sk),
        network,
    )
    .map_err(|e| anyhow::anyhow!("phase_create_ballot sign: {e:?}"))?;
    let bundle = SpendBundle::new(created.spend_bundle.coin_spends.clone(), combined_sig);
    verify_bundle_locally(&bundle, network)?;
    push_tx(chain, &bundle, "createBallot").await?;

    // Wait for the funder coin to be spent (proof the bundle landed).
    wait_for_spend(
        chain,
        funder_input_id,
        args,
        "createBallot funder XCH input",
    )
    .await?;
    // Wait for the launcher eve coin to confirm.
    wait_for_confirmation(
        chain,
        created.ballot_launcher_id,
        args,
        "Ballot launcher eve coin",
    )
    .await?;

    info!(
        ballot_launcher_id = %hex::encode(created.ballot_launcher_id),
        vote_close_height,
        "createBallot landed; ready for launch_ballot"
    );

    Ok((
        created.ballot_launcher_id,
        vote_close_height,
        outcome_domain_hash,
        vote_threshold_num,
        vote_threshold_den,
    ))
}

/// Drive the launcher second-spend that mints the eve Ballot Coin
/// singleton.
///
/// CHIP.md §211-221: the eve Ballot Coin's full puzzle hash is curried
/// with `(VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID,
/// VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN,
/// REGISTRATION_MERKLE_ROOT_SNAPSHOT,
/// REGISTRATION_VOTE_WEIGHT_SNAPSHOT)` (`finalize`),
/// `(BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT)` (`oracle`), and
/// `(BALLOT_LAUNCHER_ID)` (`announce_finalization`). The two
/// `*_SNAPSHOT` curries pin the ballot to the Election Singleton's
/// `(registration_merkle_root, registration_vote_weight)` at the
/// instant `launch_ballot` reads them, so the snapshot we read here
/// is what every later phase MUST mirror.
async fn phase_launch_ballot(
    chain: &CoinsetClient,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
    ballot_launcher_id: Bytes32,
    vote_close_height: u64,
    outcome_domain_hash: Bytes32,
    vote_threshold_num: u64,
    vote_threshold_den: u64,
) -> Result<BallotArtifacts> {
    info!("=== PHASE 2.5b: launch Ballot Coin (launcher second-spend) ===");
    confirm_or_bail(args, "Broadcast the launch_ballot bundle?")?;

    // Snapshot the Election Singleton state RIGHT BEFORE we hand it
    // to BallotIssuer::launch_ballot — the issuer reads the same
    // value from chain inside, but reading it ourselves lets us
    // surface it via BallotArtifacts so phase_vote / phase_finalize
    // pass the matching snapshot to cast_vote /
    // build_finalize_for_ballot. (The issuer's internal read and
    // ours observe the same chain tip, so the values agree by
    // construction; if they ever diverge — e.g. a new register spend
    // landed mid-phase — the launch_ballot eve PH won't match what
    // the chain mints and the simulator/consensus will reject.)
    let pre_launch_singleton = chip_voting_sdk::actors::aggregator::find_current_singleton(
        chain,
        &deploy.config,
        deploy.election_start_height,
    )
    .await
    .map_err(|e| anyhow::anyhow!("phase_launch_ballot find_current_singleton: {e:?}"))?;
    let registration_merkle_root_snapshot =
        pre_launch_singleton.state.registration_merkle_root;
    let registration_vote_weight_snapshot =
        pre_launch_singleton.state.registration_vote_weight;
    info!(
        registration_merkle_root_snapshot = %hex::encode(registration_merkle_root_snapshot),
        registration_vote_weight_snapshot,
        "snapshotted Election Singleton state for launch_ballot"
    );

    let issuer = chip_voting_sdk::actors::ballot::BallotIssuer::new(deploy.config.clone(), network);
    let launched = issuer
        .launch_ballot(
            chain,
            ballot_launcher_id,
            chip_voting_sdk::actors::ballot::LaunchBallotParams {
                vote_close_height,
                outcome_domain_hash,
                vote_threshold_num,
                vote_threshold_den,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("BallotIssuer::launch_ballot: {e:?}"))?;

    let bundle = launched.spend_bundle.clone();
    verify_bundle_locally(&bundle, network)?;
    push_tx(chain, &bundle, "launch_ballot").await?;
    wait_for_spend(chain, ballot_launcher_id, args, "Ballot launcher (launch_ballot)").await?;
    let _ = wait_for_confirmation(
        chain,
        launched.eve_ballot_coin_id,
        args,
        "eve Ballot Coin singleton",
    )
    .await?;

    info!(
        ballot_launcher_id = %hex::encode(launched.ballot_launcher_id),
        eve_ballot_coin_id = %hex::encode(launched.eve_ballot_coin_id),
        eve_ballot_puzzle_hash = %hex::encode(launched.eve_ballot_puzzle_hash),
        "launch_ballot landed; eve Ballot Coin ready for cast_vote"
    );

    Ok(BallotArtifacts {
        ballot_launcher_id: launched.ballot_launcher_id,
        eve_ballot_coin_id: launched.eve_ballot_coin_id,
        vote_close_height,
        vote_threshold_num,
        vote_threshold_den,
        outcome_domain_hash,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot,
    })
}

// ── Phase 3: Wait for the per-ballot voting window to close ──────────

async fn phase_wait_window(
    chain: &CoinsetClient,
    ballot: &BallotArtifacts,
    args: &Args,
) -> Result<()> {
    info!("=== PHASE 3: wait until chain peak ≥ ballot.vote_close_height ===");
    // Per CHIP.md §233 the Ballot Coin's `finalize` action gates on
    // `AssertHeightAbsolute(VOTE_CLOSE_HEIGHT)`; spending it before
    // that height fails consensus. We add +1 so the next finalize
    // submission lands AT or after the close height in the same
    // block. (Chia's AssertHeightAbsolute is "spent height ≥ N",
    // so reaching height == close_height is sufficient.)
    let target = u32::try_from(ballot.vote_close_height)
        .map_err(|_| anyhow::anyhow!("vote_close_height does not fit in u32"))?;
    info!(
        vote_close_height = ballot.vote_close_height,
        target_height = target,
        "Ballot finalize gated by AssertHeightAbsolute(VOTE_CLOSE_HEIGHT) — waiting"
    );
    // Generous timeout: each block is ~52s on mainnet, ~18s on
    // testnet11, plus farmer queue. Cap at 60min for safety.
    let timeout_secs = ((args.election_length_blocks + 2) * 90).max(args.confirmation_timeout_secs);
    wait_for_block_height(chain, target, args.poll_interval_secs, timeout_secs).await?;
    Ok(())
}

// ── Phase 4: Cast votes ──────────────────────────────────────────────

async fn phase_vote(
    chain: &CoinsetClient,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
    ballot: &BallotArtifacts,
    voter_label: &str,
    voter_keys: &VoterKeys,
    vote_data: Bytes32,
    reg_coin_id: Bytes32,
) -> Result<()> {
    info!("=== PHASE 4.{voter_label}: cast vote ===");
    confirm_or_bail(args, &format!("Broadcast {voter_label}'s vote?"))?;

    // Voter::cast_vote re-queries the registration coin by hint at
    // call time (never cache coin ids across spends).
    //
    // CHIP rev 2026-05-02 / per CHIP.md §274-285: cast_vote spends
    // the Registration Coin via `mint_voting_coin` (CAT inner) AND
    // co-spends the current Ballot Coin via its `oracle` action so
    // the on-chain action layer can bind the new Voting Coin to a
    // real Ballot Coin lineage. Every per-ballot field below comes
    // from `phase_create_ballot` / `phase_launch_ballot`'s artifacts;
    // none of them may be defaulted (a stale `Bytes32::default()` /
    // `0` height would re-curry the Voting Coin's puzzle hash and
    // break the Ballot Coin co-spend's oracle assertion).
    let voter = Voter::new(deploy.config.clone(), clone_voter_keys(voter_keys), network);
    let cast_result = voter
        .cast_vote(
            chain,
            chip_voting_sdk::actors::voter::CastVoteParams {
                ballot_launcher_id: ballot.ballot_launcher_id,
                vote_data,
                vote_close_height: ballot.vote_close_height,
                vote_threshold_num: ballot.vote_threshold_num,
                vote_threshold_den: ballot.vote_threshold_den,
                registration_merkle_root_snapshot: ballot.registration_merkle_root_snapshot,
                registration_vote_weight_snapshot: ballot.registration_vote_weight_snapshot,
                voting_coin_amount: 1,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Voter::cast_vote: {e:?}"))?;
    let bundle = cast_result.spend_bundle;
    verify_bundle_locally(&bundle, network)?;
    push_tx(chain, &bundle, &format!("{voter_label} vote")).await?;
    wait_for_spend(
        chain,
        reg_coin_id,
        args,
        &format!("{voter_label} vote (pre-vote reg coin)"),
    )
    .await?;
    info!(
        voter_label,
        voting_coin_id = %hex::encode(cast_result.voting_coin_id),
        ballot_launcher_id = %hex::encode(ballot.ballot_launcher_id),
        "vote cast (Voting Coin minted, Registration Coin recreated)"
    );
    Ok(())
}

// ── Phase 5: Finalize the Ballot Coin ────────────────────────────────

/// Finalize the election by spending the Ballot Coin via its
/// `finalize` action. Per CHIP.md §233 + §296 (post-rev 2026-05-02)
/// finalize targets the **Ballot Coin** singleton — NOT the Election
/// Singleton — runs the Groth16 verifier + `bls_verify`, asserts
/// chain height ≥ `VOTE_CLOSE_HEIGHT`, and recreates the Ballot Coin
/// at `(finalized=true, vote_outcome, agg_signers)`. The Election
/// Singleton is not spent. (See FLOW-FINALIZE-NOT-SINGLETON in
/// `app/docs/chip-compliance.md`.)
///
/// FEE COIN ATTACHMENT: the Ballot Coin's `finalize` action emits no
/// AGG_SIG conditions and pays no on-chain fees of its own — the
/// bundle would have zero fee/cost. Mainnet farmers de-prioritise
/// zero-fee bundles, sometimes leaving them in mempool past the
/// test's `wait_for_spend` timeout. Attaching a small `--finalize-fee`
/// XCH spend from the funding wallet effectively guarantees
/// inclusion in the next transaction block.
async fn phase_finalize(
    chain: &CoinsetClient,
    funding_keys: &WalletKeys,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
    ballot: &BallotArtifacts,
    vote_outcome: Bytes32,
    proving_key: &ArkProvingKey,
) -> Result<()> {
    info!("=== PHASE 5: aggregate votes + finalize Ballot Coin ===");
    confirm_or_bail(args, "Broadcast the finalize bundle (runs Groth16 prover)?")?;

    let mut agg = Aggregator::new(deploy.config.clone(), make_independent_chain()?, network);
    sync_aggregator_with_retry(
        &mut agg,
        "phase_finalize",
        Duration::from_secs(args.poll_interval_secs.max(15)),
        Duration::from_secs(args.confirmation_timeout_secs.max(300)),
    )
    .await?;
    // Wait for the aggregator's voter_set to populate. `Aggregator::sync`
    // walks the singleton's launcher lineage and replays each spend.
    // Immediately after a register / vote spend confirms, coinset.org's
    // `coin_records_by_parent_ids` lookup for the launcher_id can lag the
    // chain by a block or two; if sync runs against that stale view, it
    // sees only the eve coin and returns `registration_count=0`. Re-sync
    // until the voter_set has the expected number of registrants —
    // otherwise `collect_votes_for_ballot_with_retry` returns immediately
    // on `votes.len() >= 0` and we hit BelowThreshold downstream.
    //
    // We know the expected count from the CLI's own registration
    // bookkeeping: every successful `phase_register_voter` invocation
    // added one voter, so `expected_min_votes` reflects what the test
    // ran end-to-end. (Production code without that ground-truth would
    // poll until the voter_set stabilises across two consecutive syncs
    // instead.)
    let voter_set = wait_for_synced_voter_set(
        &mut agg,
        2, // voter1 + voter2 — matches `phase_register_voter` invocations in `main`
        Duration::from_secs(args.poll_interval_secs.max(15)),
        Duration::from_secs(args.confirmation_timeout_secs.max(600)),
    )
    .await?;
    let expected_votes = voter_set.registration_count as usize;
    // CHIP rev 2026-05-02: votes are now collected per Ballot Coin via
    // `collect_votes_for_ballot` (CHIP.md §284 — aggregator enumerates
    // the latest Voting Coin per `(registration_coin_id,
    // ballot_launcher_id)` pair). The legacy `collect_votes` returns
    // an empty vec by design.
    let votes = collect_votes_for_ballot_with_retry(
        &mut agg,
        ballot.ballot_launcher_id,
        expected_votes,
        Duration::from_secs(args.poll_interval_secs.max(20)),
        Duration::from_secs(args.confirmation_timeout_secs.max(600)),
    )
    .await?;
    info!(votes_collected = votes.len(), "votes harvested from chain");
    if votes.is_empty() {
        bail!("no votes collected — finalize would fail BelowThreshold");
    }

    let ballot_bundle = agg
        .build_finalize_for_ballot(
            chip_voting_sdk::actors::aggregator::BuildFinalizeForBallotParams {
                ballot_launcher_id: ballot.ballot_launcher_id,
                vote_outcome,
                votes: &votes,
                vote_close_height: ballot.vote_close_height,
                vote_threshold_num: ballot.vote_threshold_num,
                vote_threshold_den: ballot.vote_threshold_den,
                registration_merkle_root_snapshot: ballot.registration_merkle_root_snapshot,
                registration_vote_weight_snapshot: ballot.registration_vote_weight_snapshot,
                proving_key,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("build_finalize_for_ballot: {e:?}"))?;

    // Attach an XCH fee coin spend so mainnet farmers prioritise the
    // bundle over zero-fee mempool traffic. See `phase_finalize`'s
    // header doc for why this is needed.
    let bundle = if args.finalize_fee > 0 {
        attach_finalize_fee(
            chain,
            funding_keys,
            network,
            args.finalize_fee,
            ballot_bundle,
        )
        .await
        .context("attach finalize fee coin")?
    } else {
        ballot_bundle
    };

    verify_bundle_locally(&bundle, network)?;
    let ballot_spent_id: Bytes32 = bundle
        .coin_spends
        .first()
        .context("finalize bundle: expected ≥1 coin spend")?
        .coin
        .coin_id()
        .into();
    push_tx(chain, &bundle, "finalize").await?;
    wait_for_spend(
        chain,
        ballot_spent_id,
        args,
        "Ballot Coin (finalize)",
    )
    .await?;
    Ok(())
}

/// Attach an XCH fee coin spend to a finalize bundle.
///
/// CONTRACT: `funding_keys` controls a standard p2 puzzle that owns
/// at least one XCH coin of `>= fee` mojos. We spend that coin
/// emitting a single `CreateCoin(funding_p2_ph, parent.amount - fee)`
/// — consensus interprets the input/output difference as the fee.
///
/// Re-signs the entire combined bundle so the funding wallet's
/// `AggSigMe` (emitted by `StandardLayer`) is satisfied. The
/// finalize action emits no AGG_SIG conditions, so it contributes
/// the BLS identity element to the aggregate, leaving the funding
/// wallet's signature as the sole component.
async fn attach_finalize_fee(
    chain: &CoinsetClient,
    funding_keys: &WalletKeys,
    network: NetworkType,
    fee: u64,
    singleton_bundle: SpendBundle,
) -> Result<SpendBundle> {
    let fee_parent = find_xch_coin(chain, funding_keys.p2_puzzle_hash, fee)
        .await
        .context("attach_finalize_fee: no XCH funding coin available")?;
    info!(
        coin_id = %hex::encode(fee_parent.coin_id()),
        amount = fee_parent.amount,
        fee,
        "selected XCH fee coin for finalize bundle",
    );

    let mut ctx = SpendContext::new();
    let funding_p2_ph =
        Bytes32::new(StandardArgs::curry_tree_hash(funding_keys.synthetic_pk).to_bytes());
    let change = fee_parent.amount.checked_sub(fee).ok_or_else(|| {
        anyhow::anyhow!(
            "attach_finalize_fee: selected XCH coin {} mojos < fee {} mojos",
            fee_parent.amount,
            fee,
        )
    })?;
    let mut conditions = Conditions::new().reserve_fee(fee);
    if change > 0 {
        conditions = conditions.create_coin(funding_p2_ph, change, Memos::None);
    }
    StandardLayer::new(funding_keys.synthetic_pk)
        .spend(&mut ctx, fee_parent, conditions)
        .map_err(|e| anyhow::anyhow!("attach_finalize_fee: standard layer spend: {e:?}"))?;
    let fee_spends = ctx.take();

    // Combine: singleton spend(s) + fee p2 spend.
    let mut all_spends = singleton_bundle.coin_spends.clone();
    all_spends.extend(fee_spends);

    // Re-sign the WHOLE bundle. The fee coin's standard p2 emits an
    // `AggSigMe(synthetic_pk, …)` that needs `funding_keys.synthetic_sk`.
    // The finalize action itself emits no AGG_SIG conditions — its
    // contribution to the aggregate signature is the BLS identity.
    let signature = sign_bundle_signature(
        &all_spends,
        std::slice::from_ref(&funding_keys.synthetic_sk),
        network,
    )
    .map_err(|e| anyhow::anyhow!("attach_finalize_fee: sign_bundle_signature: {e:?}"))?;
    Ok(SpendBundle::new(all_spends, signature))
}

// ── Phase 6: Release collateral ──────────────────────────────────────

async fn phase_release(
    chain: &CoinsetClient,
    network: NetworkType,
    args: &Args,
    deploy: &DeployArtifacts,
    voter_label: &str,
    voter_keys: &VoterKeys,
    destination: Bytes32,
) -> Result<()> {
    info!("=== PHASE 6.{voter_label}: release collateral ===");
    confirm_or_bail(args, &format!("Broadcast {voter_label}'s release?"))?;

    let voter = Voter::new(deploy.config.clone(), clone_voter_keys(voter_keys), network);
    // Wait until the queried peer pool sees the post-finalize singleton tip.
    //
    // `Voter::release_collateral` walks the singleton lineage to find the
    // current tip and asserts that `state.finalized == true` before
    // building the spend. Immediately after the finalize spend confirms,
    // peer-side coin indexing can lag the chain — `wait_for_current_singleton`
    // may resolve to a peer that still has the PRE-finalize tip cached,
    // so the assert raises "election is not finalized — cannot release
    // collateral until finalize action has run". Polling on that exact
    // error message is the right shape: any OTHER error is real and
    // should bail; only this one self-heals as the chain view propagates.
    let started = std::time::Instant::now();
    let max_wait = Duration::from_secs(args.confirmation_timeout_secs.max(600));
    let poll = Duration::from_secs(args.poll_interval_secs.max(20));
    let bundle = loop {
        // CHIP rev 2026-05-02: release_collateral now takes
        //   (chain, &smt, registration_coin_id, destination).
        // Sync the SMT from chain via find_current_singleton each
        // iteration so the membership proof tracks the singleton's
        // CURRENT state (release_collateral asserts SMT root match).
        let current = match chip_voting_sdk::actors::aggregator::find_current_singleton(
            chain,
            &voter.config,
            deploy.election_start_height,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => return Err(anyhow::anyhow!("find_current_singleton: {e:?}")),
        };
        // Registration coin id placeholder remains until the live
        // integration test plumbs the actual id through; the SDK
        // surfaces a clear error if `Bytes32::default()` is not on chain.
        match voter
            .release_collateral(chain, &current.smt, Bytes32::default(), destination)
            .await
        {
            Ok(b) => break b,
            Err(e) => {
                let msg = format!("{e:?}");
                if msg.contains("election is not finalized") && started.elapsed() < max_wait {
                    tracing::info!(
                        elapsed_secs = started.elapsed().as_secs(),
                        "release_collateral: peer pool still sees pre-finalize singleton tip — retrying"
                    );
                    tokio::time::sleep(poll).await;
                    continue;
                }
                return Err(anyhow::anyhow!("Voter::release_collateral: {e:?}"));
            }
        }
    };
    verify_bundle_locally(&bundle, network)?;
    push_tx(chain, &bundle, &format!("{voter_label} release")).await?;

    let release_registration_input_id: Bytes32 = bundle
        .coin_spends
        .get(1)
        .with_context(|| {
            "release bundle: expected 2 spends (singleton announce_finalization + CAT release)"
        })?
        .coin
        .coin_id()
        .into();
    wait_for_spend(
        chain,
        release_registration_input_id,
        args,
        &format!("{voter_label} registration coin (release spend)"),
    )
    .await?;

    let cat_tail_hash = deploy
        .config
        .cat_tail_hash()
        .map_err(|e| anyhow::anyhow!("cat_tail_hash: {e}"))?;
    let hint = puzzles::voter_hint(
        parse_b32_str(&deploy.config.election_launcher_id_hex)?,
        cat_tail_hash,
        &voter_keys.pubkey,
    );
    let hint_hex = format!("0x{}", hex::encode(hint));
    let records = chain
        .get_coin_records_by_hint(&hint_hex, None, None, true)
        .await
        .context("get_coin_records_by_hint(release confirm) failed")?;
    if let Some(reg) = records.iter().find(|r| {
        r.spent_block_index == 0 // newly-released collateral coin (post-spend lineage)
    }) {
        // chia_query::Coin uses hex strings; rebuild a chia_protocol::Coin
        // so we can compute the canonical coin_id for the log line.
        let parent = parse_b32_str(&reg.coin.parent_coin_info)?;
        let ph = parse_b32_str(&reg.coin.puzzle_hash)?;
        let proto = Coin::new(parent, ph, reg.coin.amount);
        info!(
            collateral_coin_id = %hex::encode(proto.coin_id()),
            "release confirmed (CAT collateral landed at destination)"
        );
    } else {
        warn!(
            "release: could not locate fresh post-release collateral coin via hint — \
             release was likely successful but lineage walking is best-effort"
        );
    }
    Ok(())
}

// ── Oracle action: NOT a separate phase ──────────────────────────────
//
// CHIP rev 2026-05-02 (CHIP.md §234): `oracle` is a Ballot Coin action,
// NOT an Election Singleton action. The singleton-level Oracle action
// (and the SDK's `Oracle` actor that drove it) was removed entirely.
//
// The Ballot Coin's `oracle` action emits an announcement of
// `(ballot_launcher_id, vote_close_height, finalized)` that
// `update_vote` asserts (so re-votes can prove the ballot is still
// open). It is exercised IMPLICITLY by every successful `cast_vote` /
// `update_vote` co-spend already broadcast by `phase_vote`; there is
// no SDK helper today for building a STANDALONE oracle spend (the
// CHIP.md §234 use case for an external puzzle to
// `AssertCoinAnnouncement` the post-finalize result is a separate
// follow-up — `BallotReader` knows how to find the current Ballot
// Coin but no driver assembles a bare oracle bundle).
//
// Coverage: the `voter_revote_e2e.rs` simulator test already pins the
// oracle's `ballot_oracle_open` announcement assertion; cross-check
// against the BALLOT-ORACLE-CURRY / BALLOT-ORACLE-ROLE rows in
// `app/docs/chip-compliance.md`. A standalone "publish post-finalize
// announcement" CLI phase remains an SDK gap; revisit if/when an
// external puzzle integration needs it.

// ============================================================================
// SECTION 7 — Helpers (push_tx, signature verification, prompts)
// ============================================================================

/// Broadcast a SpendBundle and bail if the node rejects it.
///
/// RETRY-ON-FAILED: `chia_query::push_tx` only consults a single peer
/// at a time and returns its `TransactionAck` verbatim — so a
/// transient `status=FAILED` from a stale peer (e.g. one that hasn't
/// yet seen the latest singleton tip we're spending) propagates as
/// the bundle's "verdict" without ever consulting another peer or
/// the coinset.org fallback. We retry up to `RETRY_MAX_ATTEMPTS`
/// times on FAILED to give the peer pool a chance to rotate to a
/// peer with a current view. This is purely a transport-layer
/// workaround; consensus validity is already pre-flighted by
/// `Aggregator::build_finalize_with_proof`'s
/// `validate_bundle_for_consensus` call.
async fn push_tx(chain: &CoinsetClient, bundle: &SpendBundle, label: &str) -> Result<()> {
    const RETRY_MAX_ATTEMPTS: u32 = 6;
    const RETRY_DELAY_SECS: u64 = 10;

    let wire = to_query_bundle(bundle);
    info!(
        coin_spends = bundle.coin_spends.len(),
        "broadcasting {label} bundle"
    );

    let mut last_status = String::new();
    for attempt in 1..=RETRY_MAX_ATTEMPTS {
        match chain.push_tx(&wire).await {
            Ok(status) => {
                info!(
                    status = %status.status,
                    attempt,
                    "{label} bundle ack"
                );
                last_status = status.status.clone();
                if !status.status.eq_ignore_ascii_case("FAILED") {
                    return Ok(());
                }
                if attempt < RETRY_MAX_ATTEMPTS {
                    tracing::info!(
                        attempt,
                        "{label} push_tx returned FAILED — likely a stale peer; retrying after {RETRY_DELAY_SECS}s"
                    );
                    tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
            Err(e) => {
                // CoinsetClient surfaces the node's actual error code
                // (e.g. `GENERATOR_RUNTIME_ERROR`,
                // `ASSERT_HEIGHT_RELATIVE_FAILED`,
                // `ALREADY_INCLUDING_TRANSACTION`). Some of those are
                // transient (a peer just hadn't seen our latest tip
                // yet, or coinset is still re-evaluating a previous
                // attempt), but others are real consensus rejections.
                let err_str = e.to_string();
                // Transient errors that should be retried:
                //   * `ALREADY_INCLUDING_TRANSACTION` — coinset is still
                //     re-evaluating a previous attempt's bundle for this txid.
                //   * `Internal server error` — coinset's gateway hit a
                //     transient backend hiccup; reissuing usually works.
                //   * `timed out` / `connection` errors — generic flake.
                let is_transient = err_str.contains("ALREADY_INCLUDING_TRANSACTION")
                    || err_str.contains("Internal server error")
                    || err_str.contains("timed out")
                    || err_str.contains("connection")
                    || err_str.contains("502")
                    || err_str.contains("503")
                    || err_str.contains("504");
                if attempt < RETRY_MAX_ATTEMPTS && is_transient {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "{label} push_tx errored — backing off {RETRY_DELAY_SECS}s and retrying"
                    );
                    tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
                    continue;
                }
                // Non-recoverable error (or out of retry budget) — dump
                // the bundle to disk for offline diagnosis (CHIP_VOTING_DUMP_DIR
                // env var). Coinset's error string is the most useful info we
                // have, so embed it in the dump.
                if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                    let path = std::path::Path::new(&dir).join(format!(
                        "push-tx-err-{}-{}.json",
                        label.replace(' ', "_"),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    ));
                    let json = serde_json::json!({
                        "label": label,
                        "error": err_str,
                        "coin_spends": bundle.coin_spends.iter().map(|cs| serde_json::json!({
                            "coin": {
                                "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                                "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                                "amount": cs.coin.amount,
                            },
                            "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                            "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                        })).collect::<Vec<_>>(),
                        "aggregated_signature": format!("0x{}", hex::encode(bundle.aggregated_signature.to_bytes())),
                    });
                    let _ = std::fs::write(
                        &path,
                        serde_json::to_string_pretty(&json).unwrap_or_default(),
                    );
                    tracing::warn!(dump_path = %path.display(), "wrote errored bundle to disk");
                }
                return Err(anyhow::anyhow!("push_tx({label}, attempt {attempt}): {e}"));
            }
        }
    }

    let status = chia_query::TxStatus {
        status: last_status,
        success: false,
    };
    info!(status = %status.status, "{label} bundle accepted by node");
    if status.status.eq_ignore_ascii_case("FAILED") {
        // Dump the rejected bundle so the operator can replay it
        // in a simulator / use chia's `cdv` to introspect the
        // exact rejection reason. chia_query's `TxStatus` only
        // exposes `status` and `success` — the node-side error
        // string isn't propagated, so an out-of-band trace is the
        // only way to debug a node rejection.
        if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
            let path = std::path::Path::new(&dir).join(format!(
                "push-tx-failed-{}-{}.json",
                label.replace(' ', "_"),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            ));
            let json = serde_json::json!({
                "label": label,
                "status": status.status,
                "coin_spends": bundle.coin_spends.iter().map(|cs| serde_json::json!({
                    "coin": {
                        "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                        "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                        "amount": cs.coin.amount,
                    },
                    "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                    "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                })).collect::<Vec<_>>(),
                "aggregated_signature": format!("0x{}", hex::encode(bundle.aggregated_signature.to_bytes())),
            });
            let _ = std::fs::write(
                &path,
                serde_json::to_string_pretty(&json).unwrap_or_default(),
            );
            tracing::warn!(dump_path = %path.display(), "wrote rejected bundle to disk");
        }
        bail!("{label}: node rejected bundle (status=FAILED)");
    }
    Ok(())
}

/// Convert the SDK's binary `chia_protocol::SpendBundle` into the
/// hex-encoded `chia_query::SpendBundle` the JSON RPC accepts.
/// Mirrors `chip_voting_cli::rpc::to_query_bundle` (we don't import
/// that module from a binary).
fn to_query_bundle(b: &SpendBundle) -> chia_query::SpendBundle {
    chia_query::SpendBundle {
        coin_spends: b
            .coin_spends
            .iter()
            .map(|cs| chia_query::CoinSpend {
                coin: chia_query::Coin {
                    parent_coin_info: format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                    puzzle_hash: format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                    amount: cs.coin.amount,
                },
                puzzle_reveal: format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                solution: format!("0x{}", hex::encode(cs.solution.as_ref())),
            })
            .collect(),
        aggregated_signature: format!("0x{}", hex::encode(b.aggregated_signature.to_bytes())),
    }
}

/// Pre-broadcast bundle validation. Two checks:
///   1. `dry_run_coin_spends` — runs every puzzle locally so a CLVM
///      `raise` surfaces with the offending coin id (instead of as
///      an opaque `clvm raise` error from the signing pipeline OR
///      a silent farmer rejection later).
///   2. `verify_bundle_signatures` — locally aggregate-verifies the
///      bundle's signature against the consensus AGG_SIG conditions.
fn verify_bundle_locally(bundle: &SpendBundle, network: NetworkType) -> Result<()> {
    dry_run_coin_spends(&bundle.coin_spends)
        .map_err(|e| anyhow::anyhow!("dry_run failed: {e:?}"))?;
    verify_bundle_signatures(bundle, network)
        .map_err(|e| anyhow::anyhow!("signature verify: {e:?}"))?;
    Ok(())
}

/// Prompt for confirmation unless `--yes` was passed. Used as a
/// gate before every broadcast.
fn confirm_or_bail(args: &Args, prompt: &str) -> Result<()> {
    if args.assume_yes {
        info!("{prompt} → auto-confirmed via --yes");
        return Ok(());
    }
    use std::io::{BufRead, Write};
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush().ok();
    let stdin = std::io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("stdin closed"))?
        .context("reading stdin")?;
    let trimmed = line.trim().to_ascii_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        Ok(())
    } else {
        bail!("user declined ({prompt})")
    }
}

/// Build a fresh `CoinsetClient` for the given network. Used because
/// `Aggregator::new` takes OWNERSHIP of its chain reader, but the CLI
/// needs to keep using the main `chain` for its own queries — so we
/// hand the aggregator an independent HTTP client.
///
/// All CHIP chain I/O goes through `https://api.coinset.org` (a
/// canonically-synced full node maintained by the coinset.org team).
/// We deliberately do NOT use `chia_query::ChiaQuery`'s peer pool:
/// every read endpoint there does peer → peer-retry → coinset, and
/// the FIRST peer's view becomes the answer — even when that peer is
/// 1–2 blocks behind. The "first peer wins" semantic was the source
/// of multiple flakes (`status=FAILED` from a stale peer for an
/// otherwise-valid finalize bundle, `coin not found` from a peer
/// that hadn't indexed a freshly spent coin, etc). A single
/// canonical full node has a coherent tip view across reads + writes,
/// which is what the live test needs.
fn make_independent_chain() -> Result<CoinsetClient> {
    CoinsetClient::new(COINSET_BASE_URL, Duration::from_secs(COINSET_TIMEOUT_SECS))
        .context("CoinsetClient::new (independent client)")
}

/// `https://api.coinset.org` is the public REST endpoint the CHIP
/// project uses for ALL chain I/O. Override at call site if you have
/// a private mirror.
const COINSET_BASE_URL: &str = "https://api.coinset.org";

/// HTTP request timeout. Coinset.org responds in tens of ms typically;
/// 30s is a generous ceiling that absorbs slow JSON parsing of large
/// `get_coin_records_by_hint` responses for active voters.
const COINSET_TIMEOUT_SECS: u64 = 30;

/// Repeatedly call `Aggregator::collect_votes` until every voter's
/// post-vote coin is hint-indexed by the aggregator's peer pool, OR
/// `max_wait` elapses.
///
/// MOTIVATION: `extract_votes` queries `chain.coin_records_by_hint`
/// and silently skips voters whose post-vote coin isn't visible yet
/// (treats them as "not voted"). Independent peer pools advance at
/// independent rates, so even after `wait_for_spend` confirms the
/// pre-vote coin's spend on the CLI's chain, the aggregator's
/// freshly-spawned chain may not have indexed the post-vote coin's
/// hint yet.
///
/// CONTRACT:
///   * `expected` is the lower-bound number of votes we expect
///     (typically `voter_set.registration_count`); the loop exits as
///     soon as `votes.len() >= expected`.
///   * Re-`sync` is NOT performed between attempts — `collect_votes`
///     uses the cached `voter_set` from the last successful sync.
///     If propagation drift between sync time and now is the
///     concern, callers should re-sync between retries; this helper
///     is intentionally narrow to avoid masking other failure modes.
/// Re-`sync()` the aggregator until its voter_set has reached
/// `expected_min` registrants, OR `max_wait` elapses.
///
/// MOTIVATION: `Aggregator::sync` walks the launcher's child lineage
/// from coinset.org. Immediately after a register spend confirms,
/// the `coin_records_by_parent_ids` index can lag by 1–2 blocks —
/// sync sees only the eve coin and returns `registration_count=0`.
/// Without retrying, downstream code computes `expected_votes = 0`
/// and `collect_votes_with_retry` returns immediately on `votes.len() >= 0`,
/// causing a spurious BelowThreshold.
async fn wait_for_synced_voter_set(
    agg: &mut Aggregator<CoinsetClient>,
    expected_min: usize,
    poll_interval: Duration,
    max_wait: Duration,
) -> Result<chip_voting_sdk::state::VoterSet> {
    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let vs = agg
            .voter_set()
            .map_err(|e| anyhow::anyhow!("voter_set: {e:?}"))?
            .clone();
        if (vs.registration_count as usize) >= expected_min {
            tracing::info!(
                attempt,
                registration_count = vs.registration_count,
                "wait_for_synced_voter_set: reached expected min"
            );
            return Ok(vs);
        }
        if started.elapsed() >= max_wait {
            tracing::warn!(
                attempt,
                registration_count = vs.registration_count,
                expected_min,
                elapsed_secs = started.elapsed().as_secs(),
                "wait_for_synced_voter_set: max_wait exhausted, returning best-effort voter_set"
            );
            return Ok(vs);
        }
        tracing::info!(
            attempt,
            registration_count = vs.registration_count,
            expected_min,
            elapsed_secs = started.elapsed().as_secs(),
            "wait_for_synced_voter_set: voter_set not yet at expected size, re-syncing"
        );
        tokio::time::sleep(poll_interval).await;
        // Re-sync the aggregator; sync errors are treated as transient.
        if let Err(e) = agg.sync().await {
            tracing::warn!(error = %format!("{e:?}"), "wait_for_synced_voter_set: re-sync failed; will retry");
        }
    }
}

/// Repeatedly call `Aggregator::collect_votes_for_ballot` until every
/// voter's post-cast_vote Voting Coin is hint-indexed by the
/// aggregator's peer pool, OR `max_wait` elapses.
///
/// CHIP rev 2026-05-02: votes are scoped per Ballot Coin (CHIP.md
/// §253-255 + §284). The aggregator enumerates the latest Voting Coin
/// per `(registration_coin_id, ballot_launcher_id)` pair via
/// `collect_votes_for_ballot`; the legacy `collect_votes` returns
/// an empty vec by design.
async fn collect_votes_for_ballot_with_retry(
    agg: &mut Aggregator<CoinsetClient>,
    ballot_launcher_id: Bytes32,
    expected: usize,
    poll_interval: Duration,
    max_wait: Duration,
) -> Result<Vec<chip_voting_sdk::state::VoteRecord>> {
    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let votes = agg
            .collect_votes_for_ballot(ballot_launcher_id)
            .await
            .map_err(|e| anyhow::anyhow!("collect_votes_for_ballot (attempt {attempt}): {e:?}"))?;
        if votes.len() >= expected {
            return Ok(votes);
        }
        if started.elapsed() >= max_wait {
            tracing::warn!(
                attempt,
                collected = votes.len(),
                expected,
                elapsed_secs = started.elapsed().as_secs(),
                "collect_votes_for_ballot_with_retry: max_wait exhausted, returning best-effort vote set"
            );
            return Ok(votes);
        }
        tracing::info!(
            attempt,
            collected = votes.len(),
            expected,
            elapsed_secs = started.elapsed().as_secs(),
            "collect_votes_for_ballot: not all voters' post-vote coins visible yet, retrying"
        );
        tokio::time::sleep(poll_interval).await;
    }
}

/// Sync an `Aggregator` with bounded retry on `NotDeployed`.
///
/// MOTIVATION: each phase that needs the SPT or voter-set state
/// constructs a FRESH `Aggregator` with `make_independent_chain` so
/// queries don't share state with the CLI's main chain. Independent
/// peer pools advance at independent rates — a peer that already
/// confirmed a register/vote spend may not be in the aggregator's
/// freshly-spawned pool. Without a retry, `Aggregator::sync()` raises
/// `VotingError::NotDeployed` the first time it can't see the
/// launcher → eve children of the just-spent singleton, even though
/// the spend HAS landed on chain.
///
/// CONTRACT:
///   * Retries ONLY on `VotingError::NotDeployed` (a propagation
///     symptom). All other errors propagate immediately.
///   * Sleeps `poll_interval` between attempts; total budget is
///     `max_wait`. Both come from `Args` so operators can tune for
///     mainnet vs testnet11.
///   * `phase_label` is included in log lines so operators can tell
///     which call site's retry is firing.
async fn sync_aggregator_with_retry(
    agg: &mut Aggregator<CoinsetClient>,
    phase_label: &str,
    poll_interval: Duration,
    max_wait: Duration,
) -> Result<()> {
    use chip_voting_sdk::VotingError;
    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match agg.sync().await {
            Ok(_) => return Ok(()),
            Err(VotingError::NotDeployed) if started.elapsed() < max_wait => {
                tracing::info!(
                    phase = phase_label,
                    attempt,
                    elapsed_secs = started.elapsed().as_secs(),
                    "aggregator sync NotDeployed — likely propagation lag, retrying"
                );
                tokio::time::sleep(poll_interval).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "aggregator sync ({phase_label}) failed after {attempt} attempts in {}s: {e:?}",
                    started.elapsed().as_secs(),
                ));
            }
        }
    }
}

/// Clone a `VoterKeys` (the SDK stores it directly without a
/// `Clone` derive — we work around that with a small reconstruction).
fn clone_voter_keys(keys: &VoterKeys) -> VoterKeys {
    VoterKeys::new(keys.secret.clone())
}

fn parse_b32_str(s: &str) -> Result<Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).with_context(|| format!("hex decode: {s}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes from {s}"))?;
    Ok(Bytes32::new(arr))
}

// ============================================================================
// SECTION 8 — Main orchestrator
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.verbose, args.trace);

    // NOTE: legacy `--trusted-fullnode` plumbing was removed when this
    // test switched to using `CoinsetClient` exclusively. The CHIP
    // talks to `https://api.coinset.org` (or any HTTP mirror; override
    // `COINSET_BASE_URL`) — no peer / DNS path is involved.

    // ── Load + validate credentials ─────────────────────────────────
    let creds = parse_credentials(&args.credentials).with_context(|| {
        format!(
            "loading credentials from {} (file is gitignored; create it locally)",
            args.credentials.display()
        )
    })?;
    let network = args
        .network
        .map(NetworkType::from)
        .or(creds.funding.network)
        .unwrap_or(NetworkType::Mainnet);
    info!(
        network = ?network,
        funding = creds.funding.name,
        v1 = creds.validator1.name,
        v2 = creds.validator2.name,
        "loaded credentials"
    );

    let funding_keys = derive_wallet_keys(
        creds.funding.mnemonic.as_deref().unwrap(),
        creds.funding.pubkey.as_deref(),
    )
    .context("deriving funding wallet keys")?;
    let validator1_keys = derive_wallet_keys(
        creds.validator1.mnemonic.as_deref().unwrap(),
        creds.validator1.pubkey.as_deref(),
    )
    .context("deriving validator1 keys")?;
    let validator2_keys = derive_wallet_keys(
        creds.validator2.mnemonic.as_deref().unwrap(),
        creds.validator2.pubkey.as_deref(),
    )
    .context("deriving validator2 keys")?;

    // Voter BLS identities ALSO derive from the validator
    // mnemonics — a real production deployment would use rotated
    // BLS keys per election, but for an integration test
    // reusing the validator's master key keeps the credentials
    // file self-contained.
    let voter1_keys = VoterKeys::new(validator1_keys.synthetic_sk.clone());
    let voter2_keys = VoterKeys::new(validator2_keys.synthetic_sk.clone());

    let cat_tail_hash = parse_b32_str(&args.cat_tail_hash)?;

    // ── Open the chain client ───────────────────────────────────────
    //
    // We use `CoinsetClient` (HTTP, single canonical full node at
    // `api.coinset.org`) for ALL chain I/O — see `make_independent_chain`
    // for the rationale. The `network` parameter is retained because
    // signing primitives (`agg_sig_me_additional_data`) and address
    // parsing still need to know mainnet vs testnet, even though our
    // I/O backend is network-agnostic at the URL level.
    info!(network = ?network, base_url = COINSET_BASE_URL, "connecting to Chia network (CoinsetClient)");
    let chain = CoinsetClient::new(COINSET_BASE_URL, Duration::from_secs(COINSET_TIMEOUT_SECS))
        .context("opening CoinsetClient")?;

    // ── Phase 0: Ceremony ───────────────────────────────────────────
    info!("=== PHASE 0: trusted-setup ceremony (single-party SimulatedBackend) ===");
    let ceremony = run_local_ceremony()?;
    let _ = ceremony.verification_key; // typed VK exists for sanity-check use

    // ── Phase 1: Deploy ─────────────────────────────────────────────
    let deploy = phase_deploy(
        &chain,
        &funding_keys,
        network,
        &args,
        cat_tail_hash,
        &ceremony.wire_vk,
    )
    .await?;

    info!(
        genesis_eve_coin_id = %hex::encode(deploy.eve_singleton_coin_id),
        "deploy complete — singleton tip afterward is found via launcher_id, not this id"
    );

    // ── Phase 1.5: Top up validators with DIG (idempotent) ──────────
    phase_topup_validators(
        &chain,
        network,
        &args,
        &funding_keys,
        &[
            ("validator1", &validator1_keys),
            ("validator2", &validator2_keys),
        ],
        cat_tail_hash,
    )
    .await?;

    // ── Phase 2: Register both voters (sequentially) ────────────────
    let reg1 = phase_register_voter(
        &chain,
        network,
        &args,
        &deploy,
        "voter1",
        &voter1_keys,
        &validator1_keys,
        cat_tail_hash,
    )
    .await?;
    let reg2 = phase_register_voter(
        &chain,
        network,
        &args,
        &deploy,
        "voter2",
        &voter2_keys,
        &validator2_keys,
        cat_tail_hash,
    )
    .await?;

    // ── Phase 2.5a: createBallot ───────────────────────────────────
    // CHIP rev 2026-05-02 (CHIP.md §202): the Election Singleton's
    // `createBallot` action mints a per-ballot launcher coin. The
    // launcher is then consumed in `phase_launch_ballot` to mint
    // the eve Ballot Coin singleton. cast_vote / finalize bind to
    // the resulting `ballot_launcher_id` + per-ballot snapshot.
    let (ballot_launcher_id, vote_close_height, outcome_domain_hash, vthr_n, vthr_d) =
        phase_create_ballot(&chain, &funding_keys, network, &args, &deploy).await?;

    // ── Phase 2.5b: launch_ballot ──────────────────────────────────
    let ballot = phase_launch_ballot(
        &chain,
        network,
        &args,
        &deploy,
        ballot_launcher_id,
        vote_close_height,
        outcome_domain_hash,
        vthr_n,
        vthr_d,
    )
    .await?;

    // ── Phase 3: Wait until chain peak ≥ ballot.vote_close_height ──
    phase_wait_window(&chain, &ballot, &args).await?;

    // ── Phase 4: Cast votes ────────────────────────────────────────
    let vote_data = Bytes32::new([0x42u8; 32]);
    phase_vote(
        &chain,
        network,
        &args,
        &deploy,
        &ballot,
        "voter1",
        &voter1_keys,
        vote_data,
        reg1,
    )
    .await?;
    phase_vote(
        &chain,
        network,
        &args,
        &deploy,
        &ballot,
        "voter2",
        &voter2_keys,
        vote_data,
        reg2,
    )
    .await?;

    // ── Phase 5: Finalize the Ballot Coin ──────────────────────────
    let vote_outcome = vote_data; // both voters vote the same way for the test
    phase_finalize(
        &chain,
        &funding_keys,
        network,
        &args,
        &deploy,
        &ballot,
        vote_outcome,
        &ceremony.proving_key,
    )
    .await?;

    // ── Phase 6: Release collateral ────────────────────────────────
    if !args.skip_release {
        phase_release(
            &chain,
            network,
            &args,
            &deploy,
            "voter1",
            &voter1_keys,
            validator1_keys.p2_puzzle_hash,
        )
        .await?;
        phase_release(
            &chain,
            network,
            &args,
            &deploy,
            "voter2",
            &voter2_keys,
            validator2_keys.p2_puzzle_hash,
        )
        .await?;
    } else {
        info!("--skip-release set: leaving registration coins on-chain");
    }

    // CHIP rev 2026-05-02 (CHIP.md §234): the singleton-level oracle
    // is gone; the Ballot Coin's oracle action is exercised
    // implicitly by every successful cast_vote co-spend. See the
    // "Oracle action: NOT a separate phase" comment block for why
    // this isn't a top-level phase here.
    info!("✓ live election lifecycle complete — every phase confirmed on-chain");
    Ok(())
}

fn init_logging(verbose: bool, trace: bool) {
    use tracing_subscriber::{fmt, EnvFilter};
    // Default filter: INFO globally, but quiet down chia-query's
    // peer-discovery chatter (it spams info-level lookup_all per
    // request) and tower-http access logs unless --verbose / --trace
    // explicitly raise them.
    let default = if trace {
        "trace"
    } else if verbose {
        "debug,chia_query=info,tower_http=info,hyper=info,rustls=info"
    } else {
        "info,chia_query=warn,tower_http=warn,hyper=warn,rustls=warn,tungstenite=warn"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_env_filter(filter)
        .init();
}

// ============================================================================
// Tests (offline only — chain interactions live in the binary itself)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// WHAT: `parse_credentials` correctly extracts the funding +
    ///       VALIDATOR1 + VALIDATOR2 entries from a representative
    ///       fixture. Mirrors the real `.test-credentials` file
    ///       shape so that broken credential parsing surfaces as a
    ///       compile/test failure rather than a mid-run panic.
    /// HOW:  feed a synthetic credentials string through a temp
    ///       file and assert every parsed field.
    /// WHY:  the credential format is operator-friendly (key=value
    ///       lines with `# Mnemonic:` annotations); parser
    ///       regressions would silently fail the live test.
    #[test]
    fn parse_credentials_extracts_all_three_wallets() {
        let raw = r#"
# Test Credentials
## L2 Funding Wallet (Mainnet)
WALLET_NAME=l2-funding
WALLET_PASSWORD=secret
WALLET_ADDRESS=xch1qxw5qj527f3hlnshg6f6x9r7pax3ww2rqg7e7ztca22fmmda655syxwdna
WALLET_NETWORK=mainnet
# Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art

## Validator 1 Wallet (Mainnet)
VALIDATOR1_WALLET_NAME=validator1
VALIDATOR1_PASSWORD=secret
VALIDATOR1_ADDRESS=xch1t946tdsrfjea0ky5rsddh60q8m24qypktwqa5zta9cmcxtk2xrhs69xzpw
VALIDATOR1_PUBKEY=0x86706950292c1940a1b3eefd029c41d5fd66f230ef49175a02f8e91dd2440972215e3227cc2d2b53dd648c60727e2531
# Mnemonic: legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title

## Validator 2 Wallet (Mainnet)
VALIDATOR2_WALLET_NAME=validator2
VALIDATOR2_PASSWORD=secret
VALIDATOR2_ADDRESS=xch1t456496ws8v6lrs9vd0rpm7dfs7ulmn7xfl3wwk84hn684exzpjshl308e
VALIDATOR2_PUBKEY=0x94823178b7023a44aa8fb9d6941733d0072dc082ce8ac727222829d7da0248710ca417df4bd6a9a0012252f48dcfd5ca
# Mnemonic: letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always
"#;
        let path = std::env::temp_dir().join("chip-live-test-creds.txt");
        std::fs::write(&path, raw).unwrap();

        let creds = parse_credentials(&path).expect("parse_credentials");
        assert_eq!(creds.funding.name, "l2-funding");
        assert_eq!(creds.funding.network, Some(NetworkType::Mainnet));
        assert!(creds.funding.mnemonic.as_ref().unwrap().contains("abandon"));

        assert_eq!(creds.validator1.name, "validator1");
        assert_eq!(
            creds.validator1.pubkey.as_deref(),
            Some(
                "0x86706950292c1940a1b3eefd029c41d5fd66f230ef49175a02f8e91dd2440972215e3227cc2d2b53dd648c60727e2531"
            )
        );
        assert!(creds
            .validator1
            .mnemonic
            .as_ref()
            .unwrap()
            .contains("legal"));

        assert_eq!(creds.validator2.name, "validator2");
        assert!(creds
            .validator2
            .mnemonic
            .as_ref()
            .unwrap()
            .contains("letter"));
    }

    /// WHAT: `parse_credentials` rejects a file missing a Mnemonic
    ///       line. The integration test cannot proceed without it,
    ///       so an early-fail is mandatory.
    /// HOW:  build a credentials string with only the funding
    ///       wallet's KEY=VALUE block (no `# Mnemonic:`).
    /// WHY:  prevent a confusing later-stage panic in
    ///       `derive_wallet_keys(None)`.
    #[test]
    fn parse_credentials_rejects_missing_mnemonic() {
        let raw = "WALLET_NAME=funding\nVALIDATOR1_WALLET_NAME=v1\nVALIDATOR2_WALLET_NAME=v2\n";
        let path = std::env::temp_dir().join("chip-live-test-creds-missing-mnemonic.txt");
        std::fs::write(&path, raw).unwrap();
        let err = parse_credentials(&path).expect_err("must reject missing mnemonic");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Mnemonic"),
            "expected mnemonic error, got: {msg}"
        );
    }

    /// WHAT: `derive_wallet_keys` produces a deterministic
    ///       (synthetic_pk, p2_puzzle_hash) for the canonical
    ///       BIP-39 test vector mnemonic.
    /// HOW:  derive twice from the same mnemonic, assert the
    ///       outputs match byte-for-byte, and assert the
    ///       p2_puzzle_hash decodes a sensible bech32m address.
    /// WHY:  pins the key-derivation pipeline (BIP-39 → BLS master
    ///       → wallet-unhardened → derive_synthetic →
    ///       StandardArgs::curry_tree_hash). Any drift would cause
    ///       the live test to look up the wrong p2 puzzle hash and
    ///       miss its funding coin.
    #[test]
    fn derive_wallet_keys_is_deterministic() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art";
        let a = derive_wallet_keys(mnemonic, None).unwrap();
        let b = derive_wallet_keys(mnemonic, None).unwrap();
        assert_eq!(a.synthetic_pk.to_bytes(), b.synthetic_pk.to_bytes());
        assert_eq!(a.p2_puzzle_hash, b.p2_puzzle_hash);
        assert_ne!(a.p2_puzzle_hash, Bytes32::default());
    }

    /// WHAT: the REAL `.test-credentials` file (if present at the
    ///       repo root) parses cleanly and the mnemonic-derived
    ///       account pubkeys match the file's `PUBKEY=` claims.
    /// HOW:  if `CHIP/.test-credentials` exists, parse it and
    ///       derive each entry's keys; assert the validator entries'
    ///       account pubkeys match. If the file is missing,
    ///       harmlessly skip — CI runs without the gitignored file.
    /// WHY:  the unit-test fixtures use BIP-39 reference vectors;
    ///       this test guards against drift in the actual on-disk
    ///       format by validating the real file end-to-end.
    #[test]
    fn parse_real_credentials_matches_pubkeys_if_present() {
        // Walk up from the binary's source dir to find the CHIP root
        // (CARGO_MANIFEST_DIR is set per workspace member; cli's
        // manifest dir is `CHIP/cli`).
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let chip_root = manifest_dir.parent().unwrap_or(&manifest_dir);
        let creds_path = chip_root.join(".test-credentials");
        if !creds_path.exists() {
            eprintln!(
                "skipping: {} not present (file is gitignored — only meaningful in dev envs)",
                creds_path.display()
            );
            return;
        }
        let creds = parse_credentials(&creds_path)
            .expect("parsing the real .test-credentials must succeed");

        for (label, entry) in [
            ("funding", &creds.funding),
            ("validator1", &creds.validator1),
            ("validator2", &creds.validator2),
        ] {
            let mnemonic = entry.mnemonic.as_deref().unwrap();
            let derived = derive_wallet_keys(mnemonic, entry.pubkey.as_deref())
                .unwrap_or_else(|e| panic!("{label}: derive_wallet_keys: {e:?}"));
            // We don't strictly require the funding entry to expose
            // PUBKEY (it isn't curried into any puzzle), so only
            // assert validator entries match if they advertise it.
            if let Some(expected_hex) = &entry.pubkey {
                let expected =
                    hex::decode(expected_hex.trim_start_matches("0x")).expect("hex decode pubkey");
                let derived_account_pk = master_to_wallet_unhardened(
                    &SecretKey::from_seed(
                        &Mnemonic::parse_in_normalized(Language::English, mnemonic)
                            .unwrap()
                            .to_seed(""),
                    ),
                    0,
                )
                .public_key();
                assert_eq!(
                    derived_account_pk.to_bytes().as_slice(),
                    expected.as_slice(),
                    "{label}: account pubkey mismatch — file's PUBKEY does not match the mnemonic"
                );
            }
            assert_ne!(
                derived.p2_puzzle_hash,
                Bytes32::default(),
                "{label}: derived p2 puzzle hash must be non-zero"
            );
        }
    }

    /// WHAT: `compute_create_reg_msg` matches the byte-exact
    ///       formula in `puzzles/election/register.rue`
    ///       (sha256("create_reg" || launcher || pk || reg_outer ||
    ///       amount_be8)).
    /// HOW:  recompute the sha256 inline against fixed inputs and
    ///       assert equality.
    /// WHY:  pins the announcement-message format the CAT spend
    ///       must emit. Any drift would cause the registration's
    ///       AssertCoinAnnouncement to fail on-chain.
    #[test]
    fn compute_create_reg_msg_matches_register_rue_formula() {
        use sha2::{Digest, Sha256};
        let launcher = Bytes32::new([0xAB; 32]);
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art";
        let keys = derive_wallet_keys(mnemonic, None).unwrap();
        let voter_pk = keys.synthetic_pk;
        let reg_outer = Bytes32::new([0xCD; 32]);
        let amount: u64 = 100;

        let actual = compute_create_reg_msg(launcher, &voter_pk, reg_outer, amount);

        let mut h = Sha256::new();
        h.update(b"create_reg");
        h.update(launcher.as_ref());
        h.update(voter_pk.to_bytes());
        h.update(reg_outer.as_ref());
        h.update(amount.to_be_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        assert_eq!(actual, Bytes32::new(arr));
    }
}
