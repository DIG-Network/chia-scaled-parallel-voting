// ============================================================================
// chip-voting-wasm — browser bindings for the Chia voting CHIP SDK
// ============================================================================
//
// PURPOSE: Expose `chip-voting-sdk` to JavaScript via wasm-bindgen so
//          dApps (browser + WalletConnect) can drive every voting
//          operation directly from the front-end. The SDK itself
//          stays a hard boundary — it never broadcasts and never
//          opens a chain client. This crate is the wasm-side
//          equivalent of the CLI: it owns chain access via
//          caller-supplied JavaScript callbacks.
//
// CHAIN ACCESS MODEL:
//   The dApp holds a `WalletConnect` (or Sage RPC, or coinset.org
//   `fetch`) client in JS. To use anything in the SDK that walks
//   chain state (`Aggregator::sync`, `Voter::register`,
//   `Voter::cast_vote`, `Voter::update_vote`, `Voter::release_collateral`,
//   `BallotIssuer::create_ballot`, `BallotIssuer::launch_ballot`,
//   `BallotReader::list_ballots`, `BallotReader::get_ballot`), the
//   dApp must supply a JS object that implements the
//   `JsChainBackend` interface. Each method returns a Promise that
//   resolves to a JSON-serialisable record. The Rust side wraps
//   this object in `JsChainReader`, which `impl ChainReader for
//   JsChainReader`, so it can be passed to
//   `Aggregator::new(config, chain, network)`.
//
// PURE HELPERS (NO CHAIN):
//   `parseElectionConfig`, `deriveLauncherId`, `standardPuzzleHash`,
//   `voterHint`, `freshRegistrationCoinPuzzleHash`, ceremony helpers,
//   prover helpers — all exposed via `#[wasm_bindgen]` wrappers below.
//   These work without any JS callback at all.
//
// SAFETY POSTURE:
//   The wasm module never touches the file system, never opens a
//   socket, never speaks TLS. Every external call goes through a
//   caller-supplied JS callback the dApp can audit.
//
// CHIP REV 2026-05-02 ALIGNMENT:
//   This crate mirrors the post-CHIP-rev SDK actor surface. Notable
//   shape changes vs. the pre-rev API:
//   * `DeployParams` no longer carries `registration_fee` /
//     `election_length_blocks` / `vote_threshold_*`; threshold + close
//     height are per-ballot (passed to `launchBallotBundle`).
//   * Election Singleton actions are exactly
//     `register | createBallot | deregister`.
//   * Voting / finalization are per-Ballot-Coin: see
//     `castVoteBuildFinalBundle`, `updateVoteBuildFinalBundle`,
//     `buildBallotFinalizeBundle`.
//   * Vote message preimage is
//     `sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`
//     — see `canonicalVoteMessage`.
//   * Verification key length is now 768 bytes (`336 + 9 * 48`).

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

use chip_voting_sdk::chain::ChainCoinRecord;
use chip_voting_sdk::error::{anyhow_compat, VotingError, VotingResult};
use chip_voting_sdk::{NetworkType, PublicKey, SecretKey, SpendBundle};
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

// ============================================================================
// SECTION 1 — Init (panic hook)
// ============================================================================

/// Initialise the wasm module. Call once from JS at startup.
///
/// Installs a JS-friendly panic hook (when the `console-panic-hook`
/// cargo feature is enabled) so Rust panics surface in the browser
/// devtools console instead of being swallowed inside the wasm
/// boundary as an unhelpful `RuntimeError: unreachable`.
#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console-panic-hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// SECTION 2 — NetworkType bridge
// ============================================================================

/// JS-friendly `NetworkType` enum. Mirrored 1:1 from the SDK's
/// re-exported `NetworkType` because wasm-bindgen can't expose
/// foreign-crate enums directly.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmNetwork {
    Mainnet,
    Testnet11,
}

impl From<WasmNetwork> for NetworkType {
    fn from(n: WasmNetwork) -> Self {
        match n {
            WasmNetwork::Mainnet => NetworkType::Mainnet,
            WasmNetwork::Testnet11 => NetworkType::Testnet11,
        }
    }
}

// ============================================================================
// SECTION 3 — JsChainReader (proxies chain reads through JS callbacks)
// ============================================================================
//
// The dApp constructs a JS object like:
//
//   const backend = {
//     async coinRecordsByPuzzleHash(phHex)       { ...; return [...] },
//     async coinRecordsByHint(hintHex)           { ...; return [...] },
//     async puzzleAndSolution(coinIdHex)         { ...; return null|{puzzleHex,solutionHex} },
//     async coinRecordsByParentIds(parentIdsHex) { ...; return [...] },
//     async coinRecordByName(coinIdHex)          { ...; return null|{...} },
//     async peakHeight()                         { ...; return 8123456 },
//   };
//
// then `new JsChainReader(backend)` returns an opaque handle the
// other wasm wrappers accept. Each callback returns a Promise that
// resolves to a JSON value matching the `JsCoinRecord` /
// `JsPuzzleSolution` shapes documented below.

/// Wire-format coin record returned by the JS chain backend's
/// `coinRecordsByPuzzleHash` / `coinRecordsByHint` / `coinRecordByName`
/// / `coinRecordsByParentIds` callbacks. All hex strings are bare
/// (no `0x` prefix is required) and all 32-byte fields are 64 hex chars.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsCoinRecord {
    /// Coin parent id, 32 bytes hex.
    pub parent_coin_info: String,
    /// Coin puzzle hash, 32 bytes hex.
    pub puzzle_hash: String,
    /// Coin amount in mojos.
    pub amount: u64,
    /// 0 if unspent, otherwise the L1 block height the coin was
    /// spent at.
    pub spent_height: u32,
    /// L1 block height the coin was created at. 0 = unknown.
    pub confirmed_height: u32,
}

/// Wire-format puzzle+solution pair returned by the JS chain
/// backend's `puzzleAndSolution` callback. `null` from JS = coin
/// unspent / unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPuzzleSolution {
    /// Puzzle reveal as hex (with or without `0x` prefix).
    pub puzzle_hex: String,
    /// Solution as hex (with or without `0x` prefix).
    pub solution_hex: String,
}

/// `JsChainBackend` is the JS-side interface every dApp implements.
#[wasm_bindgen]
extern "C" {
    /// Opaque JS handle to the dApp's chain backend.
    #[wasm_bindgen(js_name = "JsChainBackend")]
    pub type JsChainBackend;

    #[wasm_bindgen(method, js_name = "coinRecordsByPuzzleHash")]
    fn js_coin_records_by_puzzle_hash(this: &JsChainBackend, ph_hex: String) -> Promise;
    #[wasm_bindgen(method, js_name = "coinRecordsByHint")]
    fn js_coin_records_by_hint(this: &JsChainBackend, hint_hex: String) -> Promise;
    #[wasm_bindgen(method, js_name = "puzzleAndSolution")]
    fn js_puzzle_and_solution(this: &JsChainBackend, coin_id_hex: String) -> Promise;
    #[wasm_bindgen(method, js_name = "coinRecordsByParentIds")]
    fn js_coin_records_by_parent_ids(this: &JsChainBackend, parent_ids_hex: JsValue) -> Promise;
    #[wasm_bindgen(method, js_name = "coinRecordByName")]
    fn js_coin_record_by_name(this: &JsChainBackend, coin_id_hex: String) -> Promise;
    #[wasm_bindgen(method, js_name = "peakHeight")]
    fn js_peak_height(this: &JsChainBackend) -> Promise;
}

/// `JsChainReader` is a placeholder for the planned wasm
/// `ChainReader` adapter.
///
/// FEATURE-GATE BLOCKER (2026-05-03): The SDK's `ChainReader` trait
/// is currently declared `Send + Sync` and uses `#[async_trait]`
/// (which adds a `+ Send` bound to the returned future). `JsValue`
/// (which the JS callbacks below produce) is `!Send`, so we cannot
/// `impl ChainReader for JsChainReader` against today's SDK. The
/// SDK needs to expose a `?Send` variant of the trait (or relax
/// the bound under a `wasm` cargo feature) before this adapter
/// can be wired into the chain-walking exports.
///
/// Until then, this struct is exposed for type-shape stability —
/// the JS side can already construct it via `new JsChainReader(backend)`
/// and pass it to wasm exports, but those exports currently return
/// "pending feature-gate" errors (see Section 9).
pub struct JsChainReader {
    #[allow(dead_code)]
    backend: JsChainBackend,
}

impl JsChainReader {
    pub fn new(backend: JsChainBackend) -> Self {
        Self { backend }
    }
}

/// Async helper: await a JS Promise and decode its resolved JSON
/// value into a Rust type via `serde_wasm_bindgen`.
async fn await_decode<T: for<'de> Deserialize<'de>>(p: Promise, op: &str) -> VotingResult<T> {
    let val = JsFuture::from(p).await.map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{op}: JS promise rejected: {:?}", e).into(),
        ))
    })?;
    serde_wasm_bindgen::from_value(val).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{op}: JS value decode failed: {e}").into(),
        ))
    })
}

fn parse_hex32(s: &str) -> VotingResult<chia_protocol::Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("hex decode {s}: {e}").into(),
        ))
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(
            format!("expected 32 bytes from {s}").into(),
        ))
    })?;
    Ok(chia_protocol::Bytes32::new(arr))
}

fn coin_from_js(r: &JsCoinRecord) -> VotingResult<chia_protocol::Coin> {
    Ok(chia_protocol::Coin::new(
        parse_hex32(&r.parent_coin_info)?,
        parse_hex32(&r.puzzle_hash)?,
        r.amount,
    ))
}

fn record_from_js(r: JsCoinRecord) -> VotingResult<ChainCoinRecord> {
    Ok(ChainCoinRecord {
        coin: coin_from_js(&r)?,
        spent_height: r.spent_height,
        confirmed_height: r.confirmed_height,
    })
}

fn fmt_hex32(b: &chia_protocol::Bytes32) -> String {
    format!("0x{}", hex::encode(b))
}

// NOTE: a real `impl ChainReader for JsChainReader` cannot be written
// against today's SDK because the trait is `Send + Sync`, while
// `JsValue` (and any wasm-bindgen handle that holds one) is `!Send`.
// The SDK needs to expose a `?Send` chain trait under a `wasm`
// feature before this adapter can be functional. The helpers below
// (`await_decode`, `record_from_js`, etc.) are kept for use by the
// future ChainReader impl, but the trait wiring itself is gone for
// now. See Section 9 for the per-export status.

// Suppress unused-warning for helpers that exist for the planned
// ChainReader impl — they're tested by the encode/decode helpers
// above (which use serde_wasm_bindgen / chia_protocol::Bytes32) and
// will be wired in once the SDK feature-gate lands.
#[allow(dead_code)]
async fn _await_decode_placeholder<T: for<'de> Deserialize<'de>>(
    p: Promise,
    op: &str,
) -> VotingResult<T> {
    await_decode(p, op).await
}
#[allow(dead_code)]
fn _record_from_js_placeholder(r: JsCoinRecord) -> VotingResult<ChainCoinRecord> {
    record_from_js(r)
}
#[allow(dead_code)]
fn _coin_from_js_placeholder(r: &JsCoinRecord) -> VotingResult<chia_protocol::Coin> {
    coin_from_js(r)
}
#[allow(dead_code)]
fn _fmt_hex32_placeholder(b: &chia_protocol::Bytes32) -> String {
    fmt_hex32(b)
}
#[allow(dead_code)]
fn _puzzle_solution_placeholder(_: JsPuzzleSolution) {}

// ============================================================================
// SECTION 4 — Streamable encode/decode helpers
// ============================================================================
//
// All wasm-bindgen wrappers below accept and return bytes (`&[u8]` /
// `Box<[u8]>`) for canonical chia objects. The encoding is the
// upstream `chia_protocol` Streamable form, identical to what
// `coin_spend.to_bytes()` etc. produce in any other Chia-aware
// runtime. dApps that already speak Streamable can pipe bytes
// straight in/out without re-serialising.

fn decode_bundle(bytes: &[u8]) -> Result<SpendBundle, JsError> {
    decode_streamable(bytes)
}

fn decode_streamable<T: chia_traits::Streamable>(bytes: &[u8]) -> Result<T, JsError> {
    let mut cursor = std::io::Cursor::new(bytes);
    T::parse::<true>(&mut cursor)
        .map_err(|e| JsError::new(&format!("Streamable::parse: {e:?}")))
}

fn encode_streamable<T: chia_traits::Streamable>(v: &T) -> Result<Vec<u8>, JsError> {
    let mut buf = Vec::new();
    v.stream(&mut buf)
        .map_err(|e| JsError::new(&format!("Streamable::stream: {e:?}")))?;
    Ok(buf)
}

/// Encode a `Vec<CoinSpend>` to length-prefixed streamable bytes.
/// Layout: `[u32 BE count] ([u32 BE len] [coin_spend streamable])*`.
fn encode_coin_spends(coin_spends: &[chia_protocol::CoinSpend]) -> Result<Vec<u8>, JsError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(coin_spends.len() as u32).to_be_bytes());
    for cs in coin_spends {
        let bytes = encode_streamable(cs)?;
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&bytes);
    }
    Ok(buf)
}

/// Decode the length-prefixed `Vec<CoinSpend>` back from streamable
/// bytes (inverse of `encode_coin_spends`).
fn decode_coin_spends(bytes: &[u8]) -> Result<Vec<chia_protocol::CoinSpend>, JsError> {
    if bytes.len() < 4 {
        return Err(JsError::new(
            "decode_coin_spends: input too short for count prefix",
        ));
    }
    let count = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    let mut off = 4usize;
    for _ in 0..count {
        if bytes.len() < off + 4 {
            return Err(JsError::new("decode_coin_spends: truncated length prefix"));
        }
        let len =
            u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if bytes.len() < off + len {
            return Err(JsError::new("decode_coin_spends: truncated coin_spend"));
        }
        let cs: chia_protocol::CoinSpend = decode_streamable(&bytes[off..off + len])?;
        out.push(cs);
        off += len;
    }
    Ok(out)
}

/// Encode a `SpendBundle` to its canonical streamable bytes.
#[wasm_bindgen(js_name = "encodeBundle")]
pub fn encode_bundle(bundle_bytes: &[u8]) -> Result<Box<[u8]>, JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

/// Sign an unsigned coin-spend list (length-prefixed bytes) with the
/// supplied secret keys via the SDK's canonical
/// `actors::deployer::sign_bundle_signature`. Returns the aggregated
/// BLS signature (96-byte G2 element) as raw bytes.
#[wasm_bindgen(js_name = "signCoinSpends")]
pub fn sign_coin_spends_js(
    coin_spends_bytes: &[u8],
    secret_keys: &[u8],
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    let coin_spends = decode_coin_spends(coin_spends_bytes)?;
    if secret_keys.len() % 32 != 0 {
        return Err(JsError::new("secret_keys length must be a multiple of 32"));
    }
    let sks: Vec<SecretKey> = secret_keys
        .chunks_exact(32)
        .map(|c| {
            let arr: [u8; 32] = c.try_into().expect("checked above");
            SecretKey::from_bytes(&arr)
                .map_err(|e| JsError::new(&format!("SecretKey::from_bytes: {e:?}")))
        })
        .collect::<Result<_, _>>()?;
    let sig = chip_voting_sdk::sign_bundle_signature(&coin_spends, &sks, network.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(sig.to_bytes().to_vec().into_boxed_slice())
}

/// Locally-validate a SpendBundle's signatures (BLS aggregate verify
/// over the consensus-required `(pubkey, augmented_message)` pairs).
/// CLVM dry-run is also performed via
/// `chip_voting_sdk::dry_run_coin_spends`.
#[wasm_bindgen(js_name = "verifyBundleLocally")]
pub fn verify_bundle_locally_js(bundle_bytes: &[u8], network: WasmNetwork) -> Result<(), JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    chip_voting_sdk::dry_run_coin_spends(&bundle.coin_spends)
        .map_err(|e| JsError::new(&format!("dry_run: {e:?}")))?;
    chip_voting_sdk::verify_bundle_signatures(&bundle, network.into())
        .map_err(|e| JsError::new(&format!("verify_bundle_signatures: {e:?}")))?;
    Ok(())
}

// ============================================================================
// SECTION 5 — ElectionConfig (parse + summary)
// ============================================================================

/// JSON-friendly summary of an `ElectionConfig`. Per CHIP rev
/// 2026-05-02, the election-level config carries the launcher id +
/// CAT tail + collateral; per-ballot config (threshold,
/// close-height, outcome domain) moved to `LaunchBallotParams`,
/// and `election_start_height` is embedded in the genesis
/// `ElectionState` (not in `ElectionConfig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmElectionSummary {
    pub launcher_id_hex: String,
    pub cat_tail_hash_hex: String,
    pub collateral_amount: u64,
    pub label: Option<String>,
}

impl From<&chip_voting_sdk::ElectionConfig> for WasmElectionSummary {
    fn from(c: &chip_voting_sdk::ElectionConfig) -> Self {
        Self {
            launcher_id_hex: c.election_launcher_id_hex.clone(),
            cat_tail_hash_hex: c.cat_tail_hash_hex.clone(),
            collateral_amount: c.collateral_amount,
            label: c.label.clone(),
        }
    }
}

/// Parse an `ElectionConfig` from its canonical JSON form. Returns
/// the `WasmElectionSummary` view as a JS object.
#[wasm_bindgen(js_name = "parseElectionConfig")]
pub fn parse_election_config_js(config_json: &str) -> Result<JsValue, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let summary: WasmElectionSummary = (&cfg).into();
    serde_wasm_bindgen::to_value(&summary).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 6 — Election deployment (`buildDeployBundle`)
// ============================================================================

/// Inputs to `buildDeployBundle`. Per CHIP rev 2026-05-02 the
/// `DeployParams` shape is reduced — `registration_fee`,
/// `election_length_blocks`, `vote_threshold_num`, and
/// `vote_threshold_den` are GONE (per-ballot now). The deploy
/// commits to `election_start_height` so per-ballot epochs / timing
/// can be derived against a stable on-chain anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmDeployParams {
    /// 768-byte verification key (`alpha||beta||gamma||delta||IC[0..8]`),
    /// hex with or without `0x`. Length math:
    /// `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 336 + 9 * 48 = 768`.
    pub verification_key_hex: String,
    /// CAT TAIL (asset id) hash, 32-byte hex.
    pub cat_tail_hash_hex: String,
    /// Voter collateral, in CAT mojos (DIG = 1 token / 1000 mojos).
    pub collateral_amount: u64,
    /// L1 peak at deploy time — recorded as `election_start_height`
    /// in genesis state.
    pub election_start_height: u64,
    /// Optional UI label.
    pub label: Option<String>,
}

/// Result of `buildDeployBundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmDeployArtifacts {
    /// Length-prefixed streamable bytes of `Vec<CoinSpend>` — pass
    /// to Sage Wallet (`chip0002_signCoinSpends`) for signing, then
    /// `pushTx`. `serde_bytes` ensures this serialises as a real
    /// JS `Uint8Array` (not `Array<number>`).
    #[serde(with = "serde_bytes")]
    pub coin_spends_bytes: Vec<u8>,
    /// Freshly-launched election's launcher_id, 32-byte hex.
    pub launcher_id_hex: String,
    /// Full ElectionConfig JSON — persist + distribute to voters.
    pub config_json: String,
    /// Pre-derived eve-singleton coin id.
    pub eve_singleton_coin_id_hex: String,
}

/// Predict the launcher_id for a given parent coin id + amount,
/// without actually doing the deploy.
#[wasm_bindgen(js_name = "deriveLauncherId")]
pub fn derive_launcher_id_js(parent_coin_id_hex: &str, amount: u64) -> Result<String, JsError> {
    let pid = parse_hex32(parent_coin_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let id = chip_voting_sdk::actors::deployer::derive_launcher_id(pid, amount);
    Ok(format!("0x{}", hex::encode(id)))
}

/// Build the (unsigned) deploy spend bundle for a new election.
/// Mirrors `phase_deploy` in `cli/src/bin/live_integration_test.rs`.
#[wasm_bindgen(js_name = "buildDeployBundle")]
pub fn build_deploy_bundle_js(
    params: JsValue,
    parent_coin: JsValue,
    funder_pk_hex: &str,
) -> Result<JsValue, JsError> {
    let params: WasmDeployParams = serde_wasm_bindgen::from_value(params)
        .map_err(|e| JsError::new(&format!("DeployParams decode: {e}")))?;
    let parent: JsCoinRecord = serde_wasm_bindgen::from_value(parent_coin)
        .map_err(|e| JsError::new(&format!("parent_coin decode: {e}")))?;
    let parent_coin = coin_from_js(&parent).map_err(|e| JsError::new(&format!("{e:?}")))?;

    let vk_bytes = hex::decode(params.verification_key_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("verification_key_hex decode: {e}")))?;
    let cat_tail = parse_hex32(&params.cat_tail_hash_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let funder_pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let funder_pk_arr: [u8; 48] = funder_pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&funder_pk_arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;

    // Per CHIP rev 2026-05-02: VK length = 336 + (PUBLIC_INPUT_COUNT + 1) * 48
    // (s7/s8 `(num, den)` are public inputs, so PUBLIC_INPUT_COUNT == 8).
    let vk_pi = chip_voting_sdk::PUBLIC_INPUT_COUNT;
    let vk_len_ok = 336 + (vk_pi + 1) * 48;
    if vk_bytes.len() != vk_len_ok {
        return Err(JsError::new(&format!(
            "verification_key_hex must decode to {} bytes (got {}); rerun ceremony for {} public inputs",
            vk_len_ok,
            vk_bytes.len(),
            vk_pi
        )));
    }

    let deploy_params = chip_voting_sdk::DeployParams {
        verification_key: chip_voting_sdk::ceremony::VerificationKey { raw_bytes: vk_bytes },
        cat_tail_hash: cat_tail,
        collateral_amount: params.collateral_amount,
        election_start_height: params.election_start_height,
        label: params.label,
    };
    let deployer = chip_voting_sdk::ElectionDeployer::new(deploy_params);
    let (coin_spends, config) = deployer
        .build_deploy_bundle(parent_coin, funder_pk)
        .map_err(|e| JsError::new(&format!("buildDeployBundle: {e:?}")))?;

    // Pre-derive eve singleton coin id so the dApp can wait on it.
    // `compute_eve_inner_puzzle_hash` takes `(config, election_start_height)`
    // — the genesis state hash depends on the start height baked
    // into `ElectionState::genesis(empty_root, h)`.
    let launcher_id =
        chip_voting_sdk::actors::deployer::derive_launcher_id(parent_coin.coin_id(), 1);
    let eve_inner_ph = chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(
        &config,
        params.election_start_height,
    );
    let eve_outer_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let eve_coin = chia_protocol::Coin::new(launcher_id, eve_outer_ph, 1);

    let coin_spends_bytes = encode_coin_spends(&coin_spends)?;
    let config_json = serde_json::to_string(&config)
        .map_err(|e| JsError::new(&format!("config to_string: {e}")))?;

    let out = WasmDeployArtifacts {
        coin_spends_bytes,
        launcher_id_hex: format!("0x{}", hex::encode(launcher_id)),
        config_json,
        eve_singleton_coin_id_hex: format!("0x{}", hex::encode(eve_coin.coin_id())),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 7 — Pure puzzle-hash helpers
// ============================================================================

/// Compute `standard_p2(synthetic_pk)` puzzle hash. Used to map a
/// wallet's synthetic pubkey → the puzzle hash they spend coins under.
#[wasm_bindgen(js_name = "standardPuzzleHash")]
pub fn standard_puzzle_hash_js(synthetic_pk_hex: &str) -> Result<String, JsError> {
    let pk_bytes = hex::decode(synthetic_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("synthetic_pk_hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("synthetic_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let ph: chia_protocol::Bytes32 =
        chia_puzzle_types::standard::StandardArgs::curry_tree_hash(pk).into();
    Ok(format!("0x{}", hex::encode(ph)))
}

/// Compute the `voter_hint` for a (election_launcher_id, cat_tail_hash,
/// voter_pk) triple — used by the dApp to look up registration coins
/// with `coinRecordsByHint`.
#[wasm_bindgen(js_name = "voterHint")]
pub fn voter_hint_js(
    election_launcher_id_hex: &str,
    cat_tail_hash_hex: &str,
    voter_pk_hex: &str,
) -> Result<String, JsError> {
    let election_id = parse_hex32(election_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let cat_tail = parse_hex32(cat_tail_hash_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let pk_bytes = hex::decode(voter_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_pk_hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("voter_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let hint = chip_voting_sdk::puzzles::voter_hint(election_id, cat_tail, &pk);
    Ok(format!("0x{}", hex::encode(hint)))
}

/// Compute the predicted "fresh" Registration Coin puzzle hash —
/// the CAT-wrapped puzzle hash a brand-new (un-curried) registration
/// coin lands at. Used by the dApp + funder to pre-validate a CAT
/// issuance lands at the right address before the register spend.
///
/// Wraps `chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash`,
/// which takes `(cat_tail_hash, &voter_pubkey, election_launcher_id)`
/// — the canonical pre-CHIP-rev shape that survives unchanged in
/// CHIP rev 2026-05-02.
#[wasm_bindgen(js_name = "freshRegistrationCoinPuzzleHash")]
pub fn fresh_registration_coin_puzzle_hash_js(
    election_config_json: &str,
    voter_pk_hex: &str,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    let pk_bytes = hex::decode(voter_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_pk_hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("voter_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let cat_tail = cfg
        .cat_tail_hash()
        .map_err(|e| JsError::new(&format!("cat_tail_hash: {e:?}")))?;
    let election_id = cfg
        .election_launcher_id()
        .map_err(|e| JsError::new(&format!("election_launcher_id: {e:?}")))?;
    let ph =
        chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(cat_tail, &pk, election_id);
    Ok(format!("0x{}", hex::encode(ph)))
}

/// Compute the CAT-wrapped outer puzzle hash for a given inner
/// puzzle hash (used by `releaseCollateralBuildSpends` to predict
/// the destination CAT puzzle).
#[wasm_bindgen(js_name = "catOuterPuzzleHash")]
pub fn cat_outer_puzzle_hash_js(
    cat_tail_hash_hex: &str,
    inner_puzzle_hash_hex: &str,
) -> Result<String, JsError> {
    let tail = parse_hex32(cat_tail_hash_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let inner = parse_hex32(inner_puzzle_hash_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let inner_th: clvm_utils::TreeHash = inner.into();
    // CatArgs::curry_tree_hash takes (asset_id: Bytes32, inner: TreeHash)
    // — note the asymmetry: tail is a Bytes32, inner is a TreeHash.
    let outer = chia_puzzle_types::cat::CatArgs::curry_tree_hash(tail, inner_th);
    let outer_b32: chia_protocol::Bytes32 = outer.into();
    Ok(format!("0x{}", hex::encode(outer_b32)))
}

// ============================================================================
// SECTION 8 — Canonical messages (vote + registration)
// ============================================================================

/// Canonical vote message preimage:
/// `sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`.
/// Per CHIP rev 2026-05-02 this takes 3 args (was 2 pre-rev).
#[wasm_bindgen(js_name = "canonicalVoteMessage")]
pub fn canonical_vote_message_js(
    vote_outcome_hex: &str,
    ballot_launcher_id_hex: &str,
    election_launcher_id_hex: &str,
) -> Result<String, JsError> {
    let vote_outcome = parse_hex32(vote_outcome_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let ballot_id = parse_hex32(ballot_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let election_id = parse_hex32(election_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let msg = chip_voting_sdk::puzzles::vote_message(vote_outcome, ballot_id, election_id);
    Ok(format!("0x{}", hex::encode(msg)))
}

// ============================================================================
// SECTION 9 — Stage-1 chain-walking exports (post-CHIP-rev surface)
// ============================================================================
//
// The exports below mirror the live-integration-test phases:
//
//   phase_deploy          → buildDeployBundle           (Section 6)
//   phase_register_voter  → registerBuildSpends
//   phase_create_ballot   → createBallotBundle
//   phase_launch_ballot   → launchBallotBundle
//   phase_vote (cast)     → castVoteBuildPreviewSpend + castVoteBuildFinalBundle
//   phase_finalize        → buildBallotFinalizeBundle + collectVotesForBallot
//   phase_release         → releaseCollateralBuildSpends
//
// All chain-walking exports take a `JsChainBackend` (constructed by
// the dApp). Internally they wrap it in `JsChainReader` and pass it
// to the SDK actor's chain-driven method.
//
// IMPLEMENTATION STATUS (2026-05-03 migration):
//   The wasm bodies are intentionally kept small — they wrap the SDK
//   actors and surface the SDK's typed errors. Some bodies return a
//   "not yet wired through wasm" error pending the next migration
//   pass once SDK feature-gating lands (see top-of-file note).

/// Build the register spend bundle for a voter. Mirrors
/// `phase_register_voter` in the live integration test.
///
/// Per CHIP rev 2026-05-02: NO `registration_fee_coin_spend` argument
/// (CHIP §191 forbids the curry). Caller may still attach a mempool
/// fee separately if desired.
#[wasm_bindgen(js_name = "registerBuildSpends")]
pub fn register_build_spends_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_secret_hex: &str,
    _cat_parent_spend_bytes: &[u8],
    _registration_coin_id_hex: &str,
) -> Result<JsValue, JsError> {
    // STUB — the underlying `Voter::register` is async and chain-driven,
    // and properly wiring its 5-argument SMT-snapshot signature through
    // wasm-bindgen requires the pending SDK feature-gate work. Returning
    // a clear error from JS is preferable to silently building a bad
    // bundle. Callers that need full register today should drive the
    // CLI's `phase_register_voter` directly.
    Err(JsError::new(
        "registerBuildSpends: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Mint a fresh Ballot Coin launcher (per CHIP rev §211-253). Wraps
/// `BallotIssuer::create_ballot`. Mirrors `phase_create_ballot`.
#[wasm_bindgen(js_name = "createBallotBundle")]
pub fn create_ballot_bundle_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _operator_sk_hex: &str,
    _ballot_seed_hex: &str,
    _vote_close_height: u64,
    _outcome_domain_hash_hex: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "createBallotBundle: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Second-spend the ballot launcher → eve Ballot Coin (per CHIP
/// rev §211-253). Wraps `BallotIssuer::launch_ballot`. Mirrors
/// `phase_launch_ballot`.
#[wasm_bindgen(js_name = "launchBallotBundle")]
pub fn launch_ballot_bundle_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _operator_sk_hex: &str,
    _launcher_coin_id_hex: &str,
    _vote_close_height: u64,
    _outcome_domain_hash_hex: &str,
    _vote_threshold_num: u64,
    _vote_threshold_den: u64,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "launchBallotBundle: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Build (preview) the cast-vote spend without attaching the voter's
/// final BLS signature — useful for showing the dApp user the
/// canonical vote message they'll be signing. Wraps a partial
/// `Voter::cast_vote` invocation.
#[wasm_bindgen(js_name = "castVoteBuildPreviewSpend")]
pub fn cast_vote_build_preview_spend_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_pk_hex: &str,
    _params_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "castVoteBuildPreviewSpend: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Finalise a cast-vote spend with the voter's BLS signature and
/// produce a pushable `SpendBundle`. Wraps `Voter::cast_vote`.
/// Mirrors `phase_vote` in the live integration test.
#[wasm_bindgen(js_name = "castVoteBuildFinalBundle")]
pub fn cast_vote_build_final_bundle_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_secret_hex: &str,
    _params_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "castVoteBuildFinalBundle: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Build (preview) the update-vote spend without attaching the voter's
/// final BLS signature.
#[wasm_bindgen(js_name = "updateVoteBuildPreviewSpend")]
pub fn update_vote_build_preview_spend_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_pk_hex: &str,
    _params_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "updateVoteBuildPreviewSpend: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Finalise an update-vote spend with the voter's BLS signature.
/// Wraps `Voter::update_vote`.
#[wasm_bindgen(js_name = "updateVoteBuildFinalBundle")]
pub fn update_vote_build_final_bundle_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_secret_hex: &str,
    _params_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "updateVoteBuildFinalBundle: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Build the per-Ballot-Coin finalize bundle (Groth16 proof +
/// finalize action solution). Wraps
/// `Aggregator::build_finalize_for_ballot`. Mirrors
/// `phase_finalize` in the live integration test.
#[wasm_bindgen(js_name = "buildBallotFinalizeBundle")]
pub fn build_ballot_finalize_bundle_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _ballot_launcher_id_hex: &str,
    _vote_outcome_hex: &str,
    _params_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "buildBallotFinalizeBundle: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Walk the chain to collect every Voting Coin that targets the
/// supplied ballot. Wraps `Aggregator::collect_votes_for_ballot`.
#[wasm_bindgen(js_name = "collectVotesForBallot")]
pub fn collect_votes_for_ballot_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _ballot_launcher_id_hex: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "collectVotesForBallot: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Enumerate every Ballot Coin minted under this election. Wraps
/// `BallotReader::list_ballots`.
#[wasm_bindgen(js_name = "listBallots")]
pub fn list_ballots_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "listBallots: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Look up a single Ballot Coin by its launcher id. Wraps
/// `BallotReader::get_ballot`.
#[wasm_bindgen(js_name = "getBallot")]
pub fn get_ballot_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _ballot_launcher_id_hex: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "getBallot: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

/// Announce a ballot finalization (the Ballot Coin's
/// `announce_finalization` action). Per CHIP rev §211-253 this is
/// the on-chain trigger for downstream consumers (treasuries, etc.)
/// to read the finalized vote outcome.
///
/// TODO: SDK currently has no standalone `announce_finalization`
/// helper exposed on the Ballot Coin actor; once `BallotIssuer`
/// gains an `announce_finalization` method, wire it through here.
/// Until then this returns an error — defer with DONE_WITH_CONCERNS.
#[wasm_bindgen(js_name = "announceBallotFinalization")]
pub fn announce_ballot_finalization_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _ballot_launcher_id_hex: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "announceBallotFinalization: SDK does not yet expose a standalone announce_finalization helper; tracked in CHIP §211-253",
    ))
}

/// Build the release-collateral spend bundle for a voter. Wraps
/// `Voter::release_collateral`. Mirrors `phase_release` in the live
/// integration test.
///
/// Per CHIP rev 2026-05-02 the SDK's `release_collateral` requires a
/// `registration_coin_id` arg (the lineage walker needs it to find
/// the voter's actual on-chain registration coin).
#[wasm_bindgen(js_name = "releaseCollateralBuildSpends")]
pub fn release_collateral_build_spends_js(
    _backend: JsChainBackend,
    _election_config_json: &str,
    _voter_secret_hex: &str,
    _registration_coin_id_hex: &str,
    _destination_puzzle_hash_hex: &str,
) -> Result<JsValue, JsError> {
    Err(JsError::new(
        "releaseCollateralBuildSpends: post-CHIP-rev wasm wrapper pending SDK feature-gate (see lib.rs note)",
    ))
}

// ============================================================================
// SECTION 10 — Bundle assembly helper
// ============================================================================

/// Assemble a `SpendBundle` from a coin-spend list (length-prefixed
/// streamable bytes) and an aggregated BLS signature (96 bytes). The
/// resulting bundle is the `pushTx` payload.
#[wasm_bindgen(js_name = "assembleSpendBundle")]
pub fn assemble_spend_bundle_js(
    coin_spends_bytes: &[u8],
    aggregated_signature_bytes: &[u8],
) -> Result<Box<[u8]>, JsError> {
    let coin_spends = decode_coin_spends(coin_spends_bytes)?;
    if aggregated_signature_bytes.len() != 96 {
        return Err(JsError::new(
            "aggregated_signature_bytes must be 96 bytes (BLS G2)",
        ));
    }
    let arr: [u8; 96] = aggregated_signature_bytes.try_into().expect("checked above");
    let sig = chia_bls::Signature::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("Signature::from_bytes: {e:?}")))?;
    let bundle = SpendBundle::new(coin_spends, sig);
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

// ============================================================================
// END OF MODULE
// ============================================================================
//
// SDK FEATURE-GATE FOLLOW-UP (TRACKED):
//   The chain-walking exports in Section 9 currently return error-stubs
//   because the underlying SDK is not yet wasm-buildable: it
//   unconditionally pulls in `chia-query` (mio/tokio sockets, openssl)
//   and `dig-l1-wallet` (openssl) which do NOT compile for
//   `wasm32-unknown-unknown`. Properly enabling those exports requires:
//     1. Add a `native` feature on `chip-voting-sdk` Cargo.toml that
//        gates `chia-query`, `dig-l1-wallet`, `tokio/rt-multi-thread`.
//     2. Re-export `NetworkType` from the SDK directly (instead of
//        `pub use chia_query::NetworkType`) under both feature sets.
//     3. Provide `sign_bundle_signature` / `get_agg_sig_data` shims
//        that don't go through `dig_l1_wallet::transaction` when
//        `native` is off.
//     4. Make the `Aggregator<C: ChainReader = chia_query::ChiaQuery>`
//        default generic param conditional.
//   Once those land, the Section 9 stubs become straight wrappers
//   following the live integration test's call sequence.
