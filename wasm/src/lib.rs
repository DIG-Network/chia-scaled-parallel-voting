// ============================================================================
// chip-voting-wasm — browser bindings for the Chia voting CHIP SDK
// ============================================================================
//
// PURPOSE: Expose `chip-voting-sdk` to JavaScript via wasm-bindgen so
//          dApps (browser + wallet-connect) can drive every voting
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
//   `Voter::vote`, `Voter::change_vote`, `Voter::release_collateral`, `Oracle::*`), the
//   dApp must supply a JS object that implements the
//   `JsChainBackend` interface (see `JsChainBackend` below). Every
//   method returns a `Promise` that resolves to a JSON-serialisable
//   coin / record. The Rust side wraps this object in
//   `JsChainReader`, which `impl ChainReader for JsChainReader`,
//   so it can be passed to `Aggregator::new(config, chain, network)`.
//
// PURE HELPERS (NO CHAIN):
//   `verify_bundle_locally`, `attach_xch_fee`, `build_cat_transfer`,
//   `derive_wallet_keys_from_master_sk`, `Voter::registration_message`,
//   `Voter::build_cat_collateral_spend`, ceremony helpers, prover
//   helpers — all exposed via `#[wasm_bindgen]` wrappers below.
//   These work without any JS callback at all.
//
// SAFETY POSTURE:
//   The wasm module never touches the file system, never opens a
//   socket, never speaks TLS. Every external call goes through a
//   caller-supplied JS callback the dApp can audit.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

use async_trait::async_trait;
use chip_voting_sdk::chain::{ChainCoinRecord, ChainReader};
use chip_voting_sdk::error::{anyhow_compat, VotingError, VotingResult};
use chip_voting_sdk::{
    CollectVotesProgress, CollectVotesStage, NetworkType, PublicKey, SecretKey, SpendBundle,
};
use chia_bls::Signature;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

// ============================================================================
// SECTION 1 — Init (panic hook + tracing)
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

/// JS-friendly `NetworkType` enum. Mirrored 1:1 from
/// `chip_voting_sdk::NetworkType` because wasm-bindgen can't expose
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
/// (no `0x` prefix) and all 32-byte fields are 64 hex chars.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsCoinRecord {
    /// Coin parent id, 32 bytes hex.
    pub parent_coin_info: String,
    /// Coin puzzle hash, 32 bytes hex.
    pub puzzle_hash: String,
    /// Coin amount in mojos. Use a string in JS to preserve u64
    /// precision; the wasm bridge accepts both `string` and `number`
    /// via serde_json.
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
/// We model it as a typed JS object holding the six callbacks the
/// SDK's `ChainReader` trait needs.
///
/// Implementing this in JS:
///
/// ```js
/// const backend = {
///   async coinRecordsByPuzzleHash(phHex)       { ... },
///   async coinRecordsByHint(hintHex)           { ... },
///   async puzzleAndSolution(coinIdHex)         { ... },
///   async coinRecordsByParentIds(parentIdsHex) { ... },
///   async coinRecordByName(coinIdHex)          { ... },
///   async peakHeight()                         { ... },
/// };
/// ```
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

/// `JsChainReader` adapts a `JsChainBackend` (caller-supplied JS
/// object) into the SDK's `ChainReader` trait so it can be passed
/// to `Aggregator::new` / `Voter::*` / `Oracle::*`.
///
/// `!Send`: the underlying `JsChainBackend` is a `JsValue`, which is
/// `!Send + !Sync`. The SDK's `ChainReader` trait is declared
/// `?Send` precisely so this wasm impl works without faking unsafe
/// Send (which would be unsound on multi-threaded targets).
pub struct JsChainReader {
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

#[async_trait(?Send)]
impl ChainReader for JsChainReader {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: chia_protocol::Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let p = self.backend.js_coin_records_by_puzzle_hash(fmt_hex32(&puzzle_hash));
        let raw: Vec<JsCoinRecord> = await_decode(p, "coinRecordsByPuzzleHash").await?;
        raw.into_iter().map(record_from_js).collect()
    }

    async fn coin_records_by_hint(
        &self,
        hint: chia_protocol::Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let p = self.backend.js_coin_records_by_hint(fmt_hex32(&hint));
        let raw: Vec<JsCoinRecord> = await_decode(p, "coinRecordsByHint").await?;
        raw.into_iter().map(record_from_js).collect()
    }

    async fn puzzle_and_solution(
        &self,
        coin_id: chia_protocol::Bytes32,
    ) -> VotingResult<Option<(chia_protocol::Program, chia_protocol::Program)>> {
        let p = self.backend.js_puzzle_and_solution(fmt_hex32(&coin_id));
        let raw: Option<JsPuzzleSolution> = await_decode(p, "puzzleAndSolution").await?;
        match raw {
            None => Ok(None),
            Some(ps) => {
                let pz = hex::decode(ps.puzzle_hex.trim_start_matches("0x"))
                    .map_err(|e| VotingError::Other(anyhow_compat::Error(
                        format!("puzzleAndSolution: puzzleHex decode: {e}").into(),
                    )))?;
                let sl = hex::decode(ps.solution_hex.trim_start_matches("0x"))
                    .map_err(|e| VotingError::Other(anyhow_compat::Error(
                        format!("puzzleAndSolution: solutionHex decode: {e}").into(),
                    )))?;
                Ok(Some((
                    chia_protocol::Program::from(pz),
                    chia_protocol::Program::from(sl),
                )))
            }
        }
    }

    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[chia_protocol::Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let hex_ids: Vec<String> = parent_ids.iter().map(fmt_hex32).collect();
        let js_ids = serde_wasm_bindgen::to_value(&hex_ids).map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("parent_ids serialize: {e}").into(),
            ))
        })?;
        let p = self.backend.js_coin_records_by_parent_ids(js_ids);
        let raw: Vec<JsCoinRecord> = await_decode(p, "coinRecordsByParentIds").await?;
        raw.into_iter().map(record_from_js).collect()
    }

    async fn coin_record_by_id(
        &self,
        coin_id: chia_protocol::Bytes32,
    ) -> VotingResult<Option<ChainCoinRecord>> {
        let p = self.backend.js_coin_record_by_name(fmt_hex32(&coin_id));
        let raw: Option<JsCoinRecord> = await_decode(p, "coinRecordByName").await?;
        raw.map(record_from_js).transpose()
    }

    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        let p = self.backend.js_peak_height();
        let raw: Option<u32> = await_decode(p, "peakHeight").await.unwrap_or(None);
        Ok(raw)
    }
}

// ============================================================================
// SECTION 4 — Pure SDK helper wrappers (no chain access)
// ============================================================================

/// Verify a SpendBundle locally:
///   * dry-run every CLVM puzzle (catches `raise` traps with the
///     offending coin id),
///   * BLS-aggregate-verify the bundle's signature against every
///     consensus-required `(pubkey, augmented_message)` pair.
///
/// Throws if either check fails. Returns nothing on success.
///
/// USAGE: every dApp should call this on a freshly-assembled bundle
/// BEFORE asking the wallet to broadcast — surfaces a CLVM trap or
/// signature mismatch with the offending coin id, instead of the
/// silent `status=FAILED` the chain peer would otherwise return.
#[wasm_bindgen(js_name = "verifyBundleLocally")]
pub fn verify_bundle_locally_js(bundle_bytes: &[u8], network: WasmNetwork) -> Result<(), JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    chip_voting_sdk::verify_bundle_locally(&bundle, network.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))
}

/// Encode a `SpendBundle` to its canonical streamable bytes (the
/// same encoding `chia_protocol::SpendBundle` accepts as input).
/// Use this in JS to round-trip a bundle through fetch / IPC.
#[wasm_bindgen(js_name = "encodeBundle")]
pub fn encode_bundle(bundle_bytes: &[u8]) -> Result<Box<[u8]>, JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

/// Sign an unsigned coin-spend list (bytes-encoded vec) with the
/// supplied secret keys. Returns the aggregated BLS signature
/// (96-byte G2 element) as raw bytes.
///
/// The `coin_spends_bytes` argument is the bincode/streamable
/// encoding of `Vec<CoinSpend>`. The `secret_keys` argument is a
/// flat `Vec<u8>` of `[u8; 32]` segments — one per secret key.
#[wasm_bindgen(js_name = "signCoinSpends")]
pub fn sign_coin_spends_js(
    coin_spends_bytes: &[u8],
    secret_keys: &[u8],
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    let coin_spends: Vec<chia_protocol::CoinSpend> = decode_streamable(coin_spends_bytes)?;
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
    let sig = chip_voting_sdk::sign_coin_spends(&coin_spends, &sks, network.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(sig.to_bytes().to_vec().into_boxed_slice())
}

/// Wallet-key derivation: master secret key (32 bytes) + account
/// index → `WalletKeys`. Returns a JS object with hex-encoded
/// `synthetic_sk` (32 bytes), `synthetic_pk` (48 bytes), and
/// `p2_puzzle_hash` (32 bytes).
///
/// The dApp does BIP-39 (mnemonic → seed → master_sk) itself — the
/// SDK doesn't pull in `bip39`. Use `chia-bls` JS bindings or any
/// other library to produce the master key from a mnemonic.
#[wasm_bindgen(js_name = "deriveWalletKeys")]
pub fn derive_wallet_keys_js(master_sk_bytes: &[u8], account_index: u32) -> Result<JsValue, JsError> {
    if master_sk_bytes.len() != 32 {
        return Err(JsError::new("master_sk_bytes must be 32 bytes"));
    }
    let arr: [u8; 32] = master_sk_bytes.try_into().expect("checked above");
    let master = SecretKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("SecretKey::from_bytes: {e:?}")))?;
    let keys = chip_voting_sdk::derive_wallet_keys_from_master_sk(&master, account_index);
    let out = serde_json::json!({
        "synthetic_sk":   format!("0x{}", hex::encode(keys.synthetic_sk.to_bytes())),
        "synthetic_pk":   format!("0x{}", hex::encode(keys.synthetic_pk.to_bytes())),
        "p2_puzzle_hash": format!("0x{}", hex::encode(keys.p2_puzzle_hash)),
    });
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 5 — Bytes encoding / decoding helpers (Streamable)
// ============================================================================
//
// All wasm-bindgen wrappers above accept and return bytes (`&[u8]` /
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

// ============================================================================
// SECTION 6 — Election deployment + config (the dApp's create-election path)
// ============================================================================

/// JSON-friendly summary of an `ElectionConfig`. The dApp persists
/// the full JSON serialised form (round-trips through the SDK's
/// own `serde` derive) and uses these accessors for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmElectionSummary {
    pub launcher_id_hex: String,
    pub cat_tail_hash_hex: String,
    pub collateral_amount: u64,
    pub registration_fee: u64,
    pub election_length_blocks: u64,
    /// L1 height baked into genesis state (absolute finalize anchor).
    pub election_start_height: u64,
    /// Weighted quorum numerator `N`: tally must satisfy
    /// `tally * D > registration_vote_weight * N` before finalize (strict).
    pub vote_threshold_num: u64,
    /// Weighted quorum denominator `D`.
    pub vote_threshold_den: u64,
    pub label: Option<String>,
}

impl From<&chip_voting_sdk::ElectionConfig> for WasmElectionSummary {
    fn from(c: &chip_voting_sdk::ElectionConfig) -> Self {
        Self {
            launcher_id_hex: c.election_launcher_id_hex.clone(),
            cat_tail_hash_hex: c.cat_tail_hash_hex.clone(),
            collateral_amount: c.collateral_amount,
            registration_fee: c.registration_fee,
            election_length_blocks: c.election_length_blocks,
            election_start_height: c.election_start_height,
            vote_threshold_num: c.vote_threshold_num,
            vote_threshold_den: c.vote_threshold_den,
            label: c.label.clone(),
        }
    }
}

/// Parse an `ElectionConfig` from its canonical JSON form
/// (`ElectionConfig` derives `serde::{Serialize, Deserialize}`).
/// Returns the same JSON back as a JS object plus the
/// `WasmElectionSummary` view, so callers can persist + display.
#[wasm_bindgen(js_name = "parseElectionConfig")]
pub fn parse_election_config_js(config_json: &str) -> Result<JsValue, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let summary: WasmElectionSummary = (&cfg).into();
    serde_wasm_bindgen::to_value(&summary).map_err(|e| JsError::new(&e.to_string()))
}

/// Inputs to `WasmElectionDeployer.buildDeployBundle`. The dApp
/// constructs this object in JS and passes it in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmDeployParams {
    /// 624-byte verification key (`alpha||beta||gamma||delta||IC[0..5]`), hex with or without `0x`.
    pub verification_key_hex: String,
    /// CAT TAIL (asset id) hash, 32-byte hex.
    pub cat_tail_hash_hex: String,
    /// Voter collateral, in CAT mojos (DIG = 1 token / 1000 mojos).
    pub collateral_amount: u64,
    /// XCH registration fee per voter, in mojos.
    pub registration_fee: u64,
    /// Window length; finalize earliest at election_start_height + this.
    pub election_length_blocks: u64,
    /// Current L1 peak — record as `election_start_height` in genesis state.
    pub election_start_height: u64,
    /// Strict weighted quorum numerator (default `1` = majority when `voteThresholdDen`=2).
    #[serde(default = "default_vote_threshold_num_js")]
    pub vote_threshold_num: u64,
    /// Strict weighted quorum denominator.
    #[serde(default = "default_vote_threshold_den_js")]
    pub vote_threshold_den: u64,
    /// Optional UI label.
    pub label: Option<String>,
}

fn default_vote_threshold_num_js() -> u64 {
    1
}
fn default_vote_threshold_den_js() -> u64 {
    2
}

/// Result of `buildDeployBundle`: the unsigned coin spends (as
/// streamable bytes) plus the freshly-derived `ElectionConfig`
/// JSON the dApp should persist + share with voters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmDeployArtifacts {
    /// Streamable bytes of `Vec<CoinSpend>` — pass to Sage Wallet
    /// (`chip0002_signCoinSpends`) for signing, then `pushTx`.
    ///
    /// `serde_bytes` is REQUIRED here. Without it, serde's default
    /// `Vec<u8>` impl goes through `serialize_seq`, which
    /// `serde-wasm-bindgen` maps to a regular `Array<number>` on
    /// the JS side. With it, serde calls `serialize_bytes`, which
    /// `serde-wasm-bindgen` maps to a real `Uint8Array` — the JS
    /// side can then use `.buffer`, `.byteOffset`, `new DataView()`,
    /// etc. without manual coercion.
    #[serde(with = "serde_bytes")]
    pub coin_spends_bytes: Vec<u8>,
    /// Freshly-launched election's launcher_id, 32-byte hex.
    pub launcher_id_hex: String,
    /// Full ElectionConfig JSON — persist + distribute to voters.
    pub config_json: String,
    /// Pre-derived eve-singleton coin id (for the dApp to wait on
    /// post-broadcast).
    pub eve_singleton_coin_id_hex: String,
}

/// Predict the launcher_id for a given parent coin id + amount,
/// without actually doing the deploy. Useful for the dApp to
/// pre-show the would-be election id before broadcast.
#[wasm_bindgen(js_name = "deriveLauncherId")]
pub fn derive_launcher_id_js(parent_coin_id_hex: &str, amount: u64) -> Result<String, JsError> {
    let pid = parse_hex32(parent_coin_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let id = chip_voting_sdk::actors::deployer::derive_launcher_id(pid, amount);
    Ok(format!("0x{}", hex::encode(id)))
}

/// Build the (unsigned) deploy spend bundle for a new election.
///
/// INPUTS:
///   * `params` — `WasmDeployParams` JSON (see above).
///   * `parent_coin` — JSON `{ parentCoinInfo, puzzleHash, amount }`
///     of the XCH coin the funder will spend (the dApp picks this
///     up from coinset.org `get_coin_records_by_puzzle_hash` for
///     the connected wallet's standard p2 puzzle hash).
///   * `funder_pk_hex` — funder's SYNTHETIC public key, 48-byte hex.
///     Sage Wallet exposes this via `chip0002_getPublicKeys` (each
///     entry returned is a synthetic pubkey for one of the wallet's
///     accounts — match the one whose `standardPuzzleHash` matches
///     the parent coin's puzzle hash).
///
/// OUTPUTS: `WasmDeployArtifacts` — pass `coinSpendsBytes` to
/// `chip0002_signCoinSpends`, then `pushTx` the resulting bundle.
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
    let cat_tail = parse_hex32(params.cat_tail_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let funder_pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let funder_pk_arr: [u8; 48] = funder_pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&funder_pk_arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;

    let vk_expected = chip_voting_sdk::PUBLIC_INPUT_COUNT; // documented for error string
    let vk_len_ok = 336 + (vk_expected + 1) * 48;
    if vk_bytes.len() != vk_len_ok {
        return Err(JsError::new(&format!(
            "verification_key_hex must decode to {} bytes (got {}); rerun ceremony for {} public inputs",
            vk_len_ok,
            vk_bytes.len(),
            vk_expected
        )));
    }

    if params.vote_threshold_num == 0 || params.vote_threshold_den == 0 {
        return Err(JsError::new(
            "voteThresholdNum and voteThresholdDen must both be greater than zero",
        ));
    }

    let deploy_params = chip_voting_sdk::DeployParams {
        verification_key: chip_voting_sdk::ceremony::VerificationKey { raw_bytes: vk_bytes },
        cat_tail_hash: cat_tail,
        collateral_amount: params.collateral_amount,
        registration_fee: params.registration_fee,
        election_length_blocks: params.election_length_blocks,
        election_start_height: params.election_start_height,
        vote_threshold_num: params.vote_threshold_num,
        vote_threshold_den: params.vote_threshold_den,
        label: params.label,
    };
    let deployer = chip_voting_sdk::ElectionDeployer::new(deploy_params);
    let (coin_spends, config) = deployer
        .build_deploy_bundle(parent_coin, funder_pk)
        .map_err(|e| JsError::new(&format!("buildDeployBundle: {e:?}")))?;

    // Pre-derive eve singleton coin id so the dApp can wait on it.
    let launcher_id =
        chip_voting_sdk::actors::deployer::derive_launcher_id(parent_coin.coin_id(), 1);
    let eve_inner_ph =
        chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(&config);
    let eve_outer_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let eve_coin = chia_protocol::Coin::new(launcher_id, eve_outer_ph, 1);

    // Encode coin spends as `Vec<CoinSpend>` streamable bytes —
    // the wasm-bindgen-friendly transport.
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

/// Encode a `Vec<CoinSpend>` to streamable bytes. We use length-
/// prefixed concatenation: `[u32 BE count] [coin_spend_0 streamable]
/// [coin_spend_1 streamable] ...`. JS recovers the count from the
/// first 4 bytes, then walks each coin spend with the chia-protocol
/// streamable parser.
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
/// bytes (inverse of `encode_coin_spends`). Used by `signCoinSpends`
/// and other helpers that take a coin-spend list.
fn decode_coin_spends(bytes: &[u8]) -> Result<Vec<chia_protocol::CoinSpend>, JsError> {
    if bytes.len() < 4 {
        return Err(JsError::new("decode_coin_spends: input too short for count prefix"));
    }
    let count = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    let mut off = 4;
    for _ in 0..count {
        if off + 4 > bytes.len() {
            return Err(JsError::new("decode_coin_spends: truncated length prefix"));
        }
        let n = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + n > bytes.len() {
            return Err(JsError::new("decode_coin_spends: truncated coin spend"));
        }
        let cs: chia_protocol::CoinSpend = decode_streamable(&bytes[off..off + n])?;
        out.push(cs);
        off += n;
    }
    Ok(out)
}

/// Assemble a final `SpendBundle` from the (signed) coin spends +
/// the aggregated BLS signature returned by the wallet. Returns
/// the bundle as streamable bytes for `pushTx`.
#[wasm_bindgen(js_name = "assembleSpendBundle")]
pub fn assemble_spend_bundle_js(
    coin_spends_bytes: &[u8],
    aggregated_signature_bytes: &[u8],
) -> Result<Box<[u8]>, JsError> {
    let coin_spends = decode_coin_spends(coin_spends_bytes)?;
    if aggregated_signature_bytes.len() != 96 {
        return Err(JsError::new(
            "aggregated_signature_bytes must be 96 bytes (G2 element)",
        ));
    }
    let arr: [u8; 96] = aggregated_signature_bytes
        .try_into()
        .map_err(|_| JsError::new("aggregated_signature_bytes try_into [u8;96] failed"))?;
    let sig = chia_bls::Signature::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("Signature::from_bytes: {e:?}")))?;
    let bundle = SpendBundle::new(coin_spends, sig);
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

// ============================================================================
// SECTION 7 — Puzzle-hash helpers (caller pre-computes addresses)
// ============================================================================

/// Standard p2 puzzle hash for a synthetic public key. Matches what
/// `chia_puzzle_types::standard::StandardArgs::curry_tree_hash`
/// produces. The wallet address (bech32m XCH) decodes to this hash.
#[wasm_bindgen(js_name = "standardPuzzleHash")]
pub fn standard_puzzle_hash_js(synthetic_pk_hex: &str) -> Result<String, JsError> {
    use chia_puzzle_types::standard::StandardArgs;
    let bytes = hex::decode(synthetic_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("synthetic_pk hex decode: {e}")))?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| JsError::new("synthetic_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let ph = StandardArgs::curry_tree_hash(pk);
    Ok(format!("0x{}", hex::encode(ph.to_bytes())))
}

/// Voter hint — the stable 32-byte hint coinset uses to track every
/// coin in a voter's registration → vote → release lineage.
/// Computed from `(election_launcher_id, cat_tail_hash, voter_pk)`.
#[wasm_bindgen(js_name = "voterHint")]
pub fn voter_hint_js(
    election_launcher_id_hex: &str,
    cat_tail_hash_hex: &str,
    voter_pk_hex: &str,
) -> Result<String, JsError> {
    let lid = parse_hex32(election_launcher_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let tail = parse_hex32(cat_tail_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let pk_bytes = hex::decode(voter_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_pk hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("voter_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let h = chip_voting_sdk::puzzles::voter_hint(lid, tail, &pk);
    Ok(format!("0x{}", hex::encode(h)))
}

/// CAT-wrapped puzzle hash where a voter's registration coin will
/// land. Computed from `(cat_tail_hash, voter_pk, election_launcher_id)`.
#[wasm_bindgen(js_name = "freshRegistrationCoinPuzzleHash")]
pub fn fresh_registration_coin_puzzle_hash_js(
    cat_tail_hash_hex: &str,
    voter_pk_hex: &str,
    election_launcher_id_hex: &str,
) -> Result<String, JsError> {
    let tail = parse_hex32(cat_tail_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let lid = parse_hex32(election_launcher_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let pk_bytes = hex::decode(voter_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_pk hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("voter_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(tail, &pk, lid);
    Ok(format!("0x{}", hex::encode(ph)))
}

// ============================================================================
// SECTION 8 — MPC ceremony (single-participant convenience for dApp UX)
// ============================================================================

/// Result of a single-participant `SimulatedBackend` ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCeremonyResult {
    /// 624-byte VK to commit on-chain (Groth16, 5 public inputs).
    pub verification_key_hex: String,
    /// Proving key, raw bytes (for callers who want to run the
    /// off-chain Groth16 prover later). Big — keep out of UI logs.
    pub proving_key_bytes: Vec<u8>,
}

/// Run a single-participant trusted-setup ceremony using the
/// `SimulatedBackend`. Suitable for development / demo flows. For
/// production use the multi-party `CeremonyCoordinator` /
/// `CeremonyParticipant` API (not yet wrapped — adds significant
/// surface).
///
/// USAGE: Create-Election form calls this once to mint a (PK, VK)
/// pair, persists the PK locally (needed later for `finalize`
/// proving), and curries the VK on-chain via `buildDeployBundle`.
///
/// PROD WARNING: SimulatedBackend's "anyone can recompute the
/// keys" trade-off makes the trusted setup non-toxic but also
/// non-binding. A real election MUST run a multi-party ceremony.
#[wasm_bindgen(js_name = "runSingleParticipantCeremony")]
pub fn run_single_participant_ceremony_js() -> Result<JsValue, JsError> {
    use chip_voting_sdk::ceremony::{
        CeremonyCoordinator, CeremonyParticipant, MpcBackend, SimulatedBackend,
    };

    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsError::new(&format!("getrandom: {e}")))?;

    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend));
    coord
        .start("chip-voting-wasm".into())
        .map_err(|e| JsError::new(&format!("ceremony.start: {e:?}")))?;
    let participant = CeremonyParticipant::new(
        Box::new(SimulatedBackend),
        "wasm-dapp".into(),
        Some("single-participant browser ceremony".into()),
    );
    let pre = coord
        .current_transcript()
        .map_err(|e| JsError::new(&format!("current_transcript: {e:?}")))?
        .clone();
    let contribution = participant
        .contribute(&pre, entropy)
        .map_err(|e| JsError::new(&format!("ceremony.contribute: {e:?}")))?;
    coord
        .accept_contribution(contribution.transcript)
        .map_err(|e| JsError::new(&format!("ceremony.accept_contribution: {e:?}")))?;

    let backend = SimulatedBackend;
    let final_transcript = coord
        .current_transcript()
        .map_err(|e| JsError::new(&format!("final transcript: {e:?}")))?;
    let (pk_wire, vk_wire) = backend
        .extract_keys(final_transcript)
        .map_err(|e| JsError::new(&format!("extract_keys: {e:?}")))?;

    let out = WasmCeremonyResult {
        verification_key_hex: format!("0x{}", hex::encode(&vk_wire.raw_bytes)),
        proving_key_bytes: pk_wire.raw_bytes,
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 9 — Voter helpers (registration message + CAT collateral spend)
// ============================================================================
//
// These are pure SDK calls — no chain access. The dApp uses them to
// assemble a register bundle locally; chain reads (find the current
// singleton, find a CAT input) live JS-side via coinset.org HTTP.

/// Compute the byte-exact `create_reg_msg` the Election Singleton's
/// register action asserts. Mirrors `Voter::registration_message`.
/// USAGE: dApp building its own CAT collateral spend by hand needs
/// this as the message inside the inner `create_coin_announcement`.
#[wasm_bindgen(js_name = "registrationMessage")]
pub fn registration_message_js(
    election_launcher_id_hex: &str,
    voter_pk_hex: &str,
    reg_outer_ph_hex: &str,
    amount: u64,
) -> Result<String, JsError> {
    use sha2::{Digest, Sha256};
    let lid = parse_hex32(election_launcher_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let reg_outer = parse_hex32(reg_outer_ph_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let pk_bytes = hex::decode(voter_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_pk hex decode: {e}")))?;
    let arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("voter_pk_hex must be 48 bytes"))?;
    let pk = PublicKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let mut h = Sha256::new();
    h.update(b"create_reg");
    h.update(lid.as_ref());
    h.update(pk.to_bytes());
    h.update(reg_outer.as_ref());
    h.update(amount.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(format!("0x{}", hex::encode(out)))
}

// ============================================================================
// SECTION 10 — Voter helpers (CAT collateral assembly + register/vote/release)
// ============================================================================
//
// All three actor methods now have wasm-compatible variants on the
// SDK side (`*_with_singleton` / no internal `tokio::time::sleep`).
// Here we wire them up via JsChainBackend so the dApp can drive the
// full lifecycle from the browser.
//
// VOTER KEY MODEL (browser-only): the dApp generates + persists a
// fresh BLS secret in localStorage and uses it as the voter's
// identity. Sage Wallet only signs the CAT funding side
// (StandardLayer's `AggSigMe` in the CAT parent spend); voter-side
// `AggSig*` conditions in the singleton spend are signed locally
// here with the voter's secret. The two partial signatures are
// then BLS-aggregated client-side before push.

/// Build the (UNSIGNED) CAT collateral spend a voter pre-assembles
/// before asking the wallet to sign. Mirrors
/// `Voter::build_cat_collateral_spend`.
///
/// The result is a single `CoinSpend` (the CAT input being spent
/// by the funder wallet's standard p2). The dApp:
///   1. asks Sage to sign this spend (chip0002_signCoinSpends),
///   2. combines with the singleton-spend signature from
///      `signSingletonSpends` below,
///   3. pushes the combined bundle.
///
/// CONTRACT: `cat_input_record` is a `JsCoinRecord` for the CAT
/// outer coin (the funder's DIG balance at their standard p2,
/// CAT-wrapped). The funder is responsible for picking the right
/// coin — the dApp queries coinset.org for unspent CAT records at
/// `catOuterPuzzleHashFromP2(funderP2, tail)`.
#[wasm_bindgen(js_name = "buildCatCollateralSpend")]
pub fn build_cat_collateral_spend_js(
    config_json: &str,
    voter_pk_hex: &str,
    funder_synthetic_pk_hex: &str,
    cat_input_record: JsValue,
    cat_input_lineage: JsValue,
    collateral_amount: u64,
) -> Result<Box<[u8]>, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let voter_pk = parse_pk(voter_pk_hex)?;
    let funder_pk = parse_pk(funder_synthetic_pk_hex)?;

    let voter_keys = chip_voting_sdk::VoterKeys {
        pubkey: voter_pk,
        // SECRET DOESN'T MATTER for build_cat_collateral_spend — it's
        // a pure assembly call. Use a zero placeholder so we don't
        // require the dApp to expose the voter SK just for this call.
        secret: SecretKey::from_bytes(&[1u8; 32]).expect("constant SK"),
    };
    let voter = chip_voting_sdk::Voter::new(
        config,
        voter_keys,
        chip_voting_sdk::NetworkType::Mainnet, // network only matters for signing
    );

    let cat_input = decode_cat(&cat_input_record, &cat_input_lineage, voter_pk)?;
    let cs = voter
        .build_cat_collateral_spend(cat_input, funder_pk, collateral_amount)
        .map_err(|e| JsError::new(&format!("build_cat_collateral_spend: {e:?}")))?;
    let bytes = encode_streamable(&cs)?;
    Ok(bytes.into_boxed_slice())
}

/// Build the unsigned standard-p2 XCH `CoinSpend` that forwards
/// `registration_fee_mojos` into the bundle (same transaction as CAT +
/// singleton register spend). Omit when election `registration_fee` is 0.
///
/// INPUT: `JsCoinRecord` for an UNSPENT XCH coin owned by `payer` at its
/// standard puzzle hash (`standardPuzzleHash(payerSyntheticPk)`), with
/// `amount ≥ registration_fee_mojos`.
#[wasm_bindgen(js_name = "buildRegistrationFeeXchSpend")]
pub fn build_registration_fee_xch_spend_js(
    payer_synthetic_pk_hex: &str,
    xch_coin_record: JsValue,
    registration_fee_mojos: u64,
) -> Result<Box<[u8]>, JsError> {
    let payer_pk = parse_pk(payer_synthetic_pk_hex)?;

    let r: JsCoinRecord = serde_wasm_bindgen::from_value(xch_coin_record.clone())
        .map_err(|e| JsError::new(&format!("xch coin record decode: {e}")))?;
    let coin = coin_from_js(&r).map_err(|e| JsError::new(&format!("{e:?}")))?;

    let cs =
        chip_voting_sdk::build_registration_fee_xch_spend(coin, payer_pk, registration_fee_mojos)
            .map_err(|e| JsError::new(&format!("build_registration_fee_xch_spend: {e:?}")))?;
    let bytes = encode_streamable(&cs)?;
    Ok(bytes.into_boxed_slice())
}

/// Build the unsigned standard-p2 XCH `CoinSpend` that sets
/// `RESERVE_FEE` (mempool priority). Pass as the last argument to
/// [`register_build_spends_js`]. Use a **different** XCH UTXO than
/// [`build_registration_fee_xch_spend_js`] when both apply.
#[wasm_bindgen(js_name = "buildMempoolFeeXchSpend")]
pub fn build_mempool_fee_xch_spend_js(
    payer_synthetic_pk_hex: &str,
    xch_coin_record: JsValue,
    fee_mojos: u64,
) -> Result<Box<[u8]>, JsError> {
    let payer_pk = parse_pk(payer_synthetic_pk_hex)?;

    let r: JsCoinRecord = serde_wasm_bindgen::from_value(xch_coin_record.clone())
        .map_err(|e| JsError::new(&format!("xch coin record decode: {e}")))?;
    let coin = coin_from_js(&r).map_err(|e| JsError::new(&format!("{e:?}")))?;

    let cs =
        chip_voting_sdk::build_mempool_fee_xch_spend(coin, payer_pk, fee_mojos)
            .map_err(|e| JsError::new(&format!("build_mempool_fee_xch_spend: {e:?}")))?;
    let bytes = encode_streamable(&cs)?;
    Ok(bytes.into_boxed_slice())
}

/// Decode a `JsCoinRecord` + lineage proof JSON into a typed `Cat`
/// suitable for `Voter::build_cat_collateral_spend`. The lineage
/// proof MUST come from the parent's spend (the dApp queries
/// coinset.org `get_puzzle_and_solution` and parses out the
/// CAT lineage info). For now we accept a JS-supplied
/// `{ parentParentCoinInfo, parentInnerPuzzleHash, parentAmount }`
/// triple.
fn decode_cat(
    record: &JsValue,
    lineage_json: &JsValue,
    voter_pk: PublicKey,
) -> Result<chia_sdk_driver::Cat, JsError> {
    use chia_puzzle_types::standard::StandardArgs;

    let r: JsCoinRecord = serde_wasm_bindgen::from_value(record.clone())
        .map_err(|e| JsError::new(&format!("cat record decode: {e}")))?;
    let coin = coin_from_js(&r).map_err(|e| JsError::new(&format!("{e:?}")))?;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LineageJson {
        parent_parent_coin_info: String,
        parent_inner_puzzle_hash: String,
        parent_amount: u64,
        asset_id_hex: String,
    }
    let l: LineageJson = serde_wasm_bindgen::from_value(lineage_json.clone())
        .map_err(|e| JsError::new(&format!("lineage decode: {e}")))?;

    let lineage_proof = chia_puzzle_types::LineageProof {
        parent_parent_coin_info: parse_hex32(&l.parent_parent_coin_info)
            .map_err(|e| JsError::new(&format!("{e:?}")))?,
        parent_inner_puzzle_hash: parse_hex32(&l.parent_inner_puzzle_hash)
            .map_err(|e| JsError::new(&format!("{e:?}")))?,
        parent_amount: l.parent_amount,
    };
    let asset_id = parse_hex32(&l.asset_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let voter_p2_ph =
        chia_protocol::Bytes32::new(StandardArgs::curry_tree_hash(voter_pk).to_bytes());
    let info = chia_sdk_driver::CatInfo {
        asset_id,
        hidden_puzzle_hash: None,
        p2_puzzle_hash: voter_p2_ph,
    };
    Ok(chia_sdk_driver::Cat {
        coin,
        lineage_proof: Some(lineage_proof),
        info,
    })
}

fn parse_pk(hex_str: &str) -> Result<PublicKey, JsError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("pk hex decode: {e}")))?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| JsError::new("pk must be 48 bytes"))?;
    PublicKey::from_bytes(&arr).map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))
}

// ============================================================================
// SECTION 11 — Chain-walk helpers (JsChainBackend-driven, async)
// ============================================================================
//
// Single-shot async wrappers around the SDK's `find_current_singleton`
// and `sync_with_chain`. The dApp passes a `JsChainBackend` that
// proxies the underlying `coinset.org` reads. Returned values are
// JSON-friendly so the dApp can render them directly.

/// JSON-friendly `CurrentSingleton` projection. Plain fields only —
/// the dApp uses this to RENDER state. To USE the singleton (e.g.,
/// register against it), pass the `JsChainBackend` to the relevant
/// wasm wrapper which will internally re-resolve the tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCurrentSingleton {
    pub coin_id_hex: String,
    pub finalized: bool,
    pub registration_count: u64,
    pub registration_merkle_root_hex: String,
    pub vote_outcome_hex: String,
    pub accumulated_fees: u64,
    pub election_start_height: u64,
}

/// Single-shot lookup: walk the launcher → tip lineage and return
/// the current Election Singleton (display-only projection).
/// Internally calls the SDK's `find_current_singleton`.
#[wasm_bindgen(js_name = "findCurrentSingleton")]
pub async fn find_current_singleton_js(
    backend: JsChainBackend,
    config_json: String,
) -> Result<JsValue, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let chain = JsChainReader::new(backend);
    let current =
        chip_voting_sdk::actors::aggregator::find_current_singleton(&chain, &config)
            .await
            .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;
    let summary = WasmCurrentSingleton {
        coin_id_hex: format!("0x{}", hex::encode(current.coin.coin_id())),
        finalized: current.state.finalized,
        registration_count: current.state.registration_count,
        registration_merkle_root_hex: format!(
            "0x{}",
            hex::encode(current.state.registration_merkle_root)
        ),
        vote_outcome_hex: format!("0x{}", hex::encode(current.state.vote_outcome)),
        accumulated_fees: current.state.accumulated_fees,
        election_start_height: current.state.election_start_height,
    };
    serde_wasm_bindgen::to_value(&summary).map_err(|e| JsError::new(&e.to_string()))
}

/// Snapshot summary returned by `syncSnapshot`. Display-only —
/// the dApp uses this to render registration count, root, voter
/// list, etc. Actor wrappers (`registerSigned`, etc.) re-derive
/// the SMT internally so the dApp never needs to ferry it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmSyncSnapshot {
    pub registration_count: u64,
    pub registration_merkle_root_hex: String,
    pub finalized: bool,
    pub vote_outcome_hex: String,
    pub accumulated_fees: u64,
    pub election_start_height: u64,
    /// 0x-hex voter pubkeys, in registration order.
    pub voters_hex: Vec<String>,
    /// 0x-hex SMT root after applying every register spend.
    pub smt_root_hex: String,
}

/// Walk the singleton lineage from the launcher to recover the
/// full (state, voter_set, smt). Mirrors `Aggregator::sync`.
#[wasm_bindgen(js_name = "syncSnapshot")]
pub async fn sync_snapshot_js(
    backend: JsChainBackend,
    config_json: String,
) -> Result<JsValue, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let chain = JsChainReader::new(backend);
    let eve_inner_ph =
        chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(&config);
    let launcher_id = parse_hex32(&config.election_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let eve_outer_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let snap = chip_voting_sdk::actors::aggregator::sync_with_chain(
        &chain,
        &config,
        eve_outer_ph,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_with_chain: {e:?}")))?;

    let out = WasmSyncSnapshot {
        registration_count: snap.state.registration_count,
        registration_merkle_root_hex: format!(
            "0x{}",
            hex::encode(snap.state.registration_merkle_root)
        ),
        finalized: snap.state.finalized,
        vote_outcome_hex: format!("0x{}", hex::encode(snap.state.vote_outcome)),
        accumulated_fees: snap.state.accumulated_fees,
        election_start_height: snap.state.election_start_height,
        voters_hex: snap
            .voter_set
            .voters
            .iter()
            .map(|pk| format!("0x{}", hex::encode(pk.to_bytes())))
            .collect(),
        smt_root_hex: format!("0x{}", hex::encode(snap.smt.root())),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 12 — Voter actor wrappers (register / vote / release)
// ============================================================================

/// Sign + assemble the register spend bundle.
///
/// INPUTS:
///   * `backend` — `JsChainBackend` for chain reads (sync + find
///     singleton happen internally).
///   * `config_json` — the ElectionConfig JSON.
///   * `voter_sk_hex` — 32-byte voter BLS secret (browser-managed).
///   * `cat_parent_spend_bytes` — streamable CoinSpend bytes from
///     `buildCatCollateralSpend`.
///   * `wallet_partial_signature_bytes` — 96-byte BLS sig the dApp
///     got from `chip0002_signCoinSpends` for the CAT side. Empty
///     if the wallet didn't need to sign (rare).
///   * `network` — Mainnet / Testnet11.
///
/// OUTPUT: streamable bytes of the SIGNED `SpendBundle`. Voter-side
/// `AggSigMe` is signed locally with `voter_sk_hex`; the wallet's
/// CAT-side partial sig is BLS-aggregated in. dApp pushes the
/// result directly via coinset.org `push_tx`.
/// Build the UNSIGNED register coin spends. Caller (the dApp)
/// is expected to ship them to Sage Wallet's
/// `chip0002_signCoinSpends` for signing — Sage handles BOTH the
/// CAT-side `AggSigMe` (funder synthetic key) AND the voter-side
/// `AggSigMe` over the registration message (because, post
/// CHIP-bls-unify, the voter identity is just a wallet synthetic
/// key Sage already owns).
///
/// Replaces the older `registerSigned` that internally signed
/// using a browser-managed BLS secret.
#[wasm_bindgen(js_name = "registerBuildSpends")]
pub async fn register_build_spends_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    cat_parent_spend_bytes: Vec<u8>,
    locked_cat_mojos: u64,
    registration_fee_coin_spend_bytes: Option<Vec<u8>>,
    mempool_fee_coin_spend_bytes: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let voter_pk = parse_pk(&voter_pk_hex)?;
    // Construct a Voter with a placeholder secret (never used —
    // the unsigned build path never touches `keys.secret`). The
    // Voter struct's API still requires a SecretKey field.
    let voter_keys = chip_voting_sdk::VoterKeys {
        pubkey: voter_pk,
        secret: SecretKey::from_bytes(&[1u8; 32]).expect("constant SK"),
    };
    let voter = chip_voting_sdk::Voter::new(
        config.clone(),
        voter_keys,
        chip_voting_sdk::NetworkType::Mainnet, // unused on the unsigned path
    );
    let cat_parent: chia_protocol::CoinSpend = decode_streamable(&cat_parent_spend_bytes)?;
    let registration_fee_xch_spend = match registration_fee_coin_spend_bytes {
        None => None,
        Some(b) => Some(decode_streamable(&b)?),
    };

    let chain = JsChainReader::new(backend);

    // Resolve the current Election Singleton + sync the SMT.
    let current =
        chip_voting_sdk::actors::aggregator::find_current_singleton(&chain, &config)
            .await
            .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;
    let eve_inner_ph =
        chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(&config);
    let launcher_id = parse_hex32(&config.election_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let eve_outer_ph =
        chip_voting_sdk::puzzles::election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let snap = chip_voting_sdk::actors::aggregator::sync_with_chain(
        &chain,
        &config,
        eve_outer_ph,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_with_chain: {e:?}")))?;

    let mut coin_spends = voter
        .register_with_singleton_unsigned(
            &snap.smt,
            cat_parent,
            registration_fee_xch_spend,
            locked_cat_mojos,
            current,
        )
        .map_err(|e| JsError::new(&format!("register_with_singleton_unsigned: {e:?}")))?;

    if let Some(b) = mempool_fee_coin_spend_bytes {
        let mempool_cs: chia_protocol::CoinSpend = decode_streamable(&b)?;
        coin_spends.push(mempool_cs);
    }

    // Return the wallet-shape JSON the dApp feeds straight into
    // `walletConnect.signCoinSpends(coinSpends, false, false)` —
    // Sage signs both the CAT-side and voter-side AGG_SIG_ME
    // conditions in one prompt and returns the aggregated
    // signature.
    let out: Vec<WalletCoinSpend> = coin_spends
        .into_iter()
        .map(coin_spend_to_wallet_json)
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 12a — Vote: two-call placeholder→sign→finalize flow
// ============================================================================
//
// Because the action's `vote_signature` solution field gets
// embedded in the recreated coin's MEMO and the AGG_SIG_UNSAFE
// message is independent of memo content, we can:
//
//   1. Build a "preview" vote spend with a placeholder zero-sig in
//      the memo. Output the wallet-shape JSON + the canonical
//      message bytes for the caller to inspect.
//   2. Caller asks Sage Wallet to sign it (partial mode). Sage
//      returns a 96-byte signature — this IS the canonical sig
//      because the spend has exactly one AGG_SIG_UNSAFE condition.
//   3. Build the FINAL vote spend with the real sig embedded in
//      the memo. The bundle's aggregated_signature == the sig
//      from step 2.
//
// The placeholder→real swap doesn't change the AGG_SIG_UNSAFE
// message (it's `sha256(vote_data || launcher_id)`, derived from
// state — not from the memo), so Sage's signature from step 2 is
// still valid for the final spend in step 3.

/// Step 1 of the two-call vote flow: build the preview vote spend
/// with a placeholder signature in the memo. Returns the wallet-
/// shape JSON ready for `walletConnect.signCoinSpends(...)`.
#[wasm_bindgen(js_name = "voteBuildPreviewSpend")]
pub async fn vote_build_preview_spend_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    vote_data_hex: String,
) -> Result<JsValue, JsError> {
    let bundle = build_vote_bundle_internal(
        backend,
        config_json,
        voter_pk_hex,
        vote_data_hex,
        // Placeholder signature — 96 zero bytes. The dApp throws
        // this away after Sage returns the real sig.
        Signature::default(),
    )
    .await?;
    let out: Vec<WalletCoinSpend> = bundle
        .coin_spends
        .into_iter()
        .map(coin_spend_to_wallet_json)
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// Step 3 of the two-call vote flow: rebuild the vote spend with
/// the real canonical signature (returned by Sage in step 2)
/// embedded in the memo, and use that same signature as the
/// bundle's aggregated_signature. Returns streamable bundle bytes
/// the dApp pushes via `pushTx(bundleToWalletJson(...))`.
#[wasm_bindgen(js_name = "voteBuildFinalBundle")]
pub async fn vote_build_final_bundle_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    vote_data_hex: String,
    canonical_signature_bytes: Vec<u8>,
) -> Result<Box<[u8]>, JsError> {
    if canonical_signature_bytes.len() != 96 {
        return Err(JsError::new(&format!(
            "canonical_signature_bytes must be 96 bytes; got {}",
            canonical_signature_bytes.len()
        )));
    }
    let arr: [u8; 96] = canonical_signature_bytes.as_slice().try_into().expect("checked above");
    let canonical_sig = chia_bls::Signature::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("Signature::from_bytes: {e:?}")))?;
    let bundle =
        build_vote_bundle_internal(backend, config_json, voter_pk_hex, vote_data_hex, canonical_sig)
            .await?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

/// Step 1: `change_vote` preview — oracle singleton + CAT; placeholder
/// signature embedded in the change_vote solution (same semantics as
/// [`vote_build_preview_spend_js`]).
#[wasm_bindgen(js_name = "changeVoteBuildPreviewSpend")]
pub async fn change_vote_build_preview_spend_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    new_vote_data_hex: String,
) -> Result<JsValue, JsError> {
    let bundle = build_change_vote_bundle_internal(
        backend,
        config_json,
        voter_pk_hex,
        new_vote_data_hex,
        Signature::default(),
    )
    .await?;
    let out: Vec<WalletCoinSpend> = bundle
        .coin_spends
        .into_iter()
        .map(coin_spend_to_wallet_json)
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// Step 3: rebuild change_vote bundle with the real canonical signature.
#[wasm_bindgen(js_name = "changeVoteBuildFinalBundle")]
pub async fn change_vote_build_final_bundle_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    new_vote_data_hex: String,
    canonical_signature_bytes: Vec<u8>,
) -> Result<Box<[u8]>, JsError> {
    if canonical_signature_bytes.len() != 96 {
        return Err(JsError::new(&format!(
            "canonical_signature_bytes must be 96 bytes; got {}",
            canonical_signature_bytes.len()
        )));
    }
    let arr: [u8; 96] = canonical_signature_bytes.as_slice().try_into().expect("checked above");
    let canonical_sig = chia_bls::Signature::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("Signature::from_bytes: {e:?}")))?;
    let bundle = build_change_vote_bundle_internal(
        backend,
        config_json,
        voter_pk_hex,
        new_vote_data_hex,
        canonical_sig,
    )
    .await?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

async fn build_change_vote_bundle_internal(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    new_vote_data_hex: String,
    signature: Signature,
) -> Result<SpendBundle, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let voter_pk = parse_pk(&voter_pk_hex)?;
    let voter_keys = chip_voting_sdk::VoterKeys {
        pubkey: voter_pk,
        secret: SecretKey::from_bytes(&[1u8; 32]).expect("constant SK"),
    };
    let voter = chip_voting_sdk::Voter::new(
        config,
        voter_keys,
        chip_voting_sdk::NetworkType::Mainnet,
    );
    let new_vote_data = parse_hex32(new_vote_data_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let chain = JsChainReader::new(backend);
    let current =
        chip_voting_sdk::actors::aggregator::find_current_singleton(&chain, &voter.config)
            .await
            .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;
    let coin_spends = voter
        .change_vote_with_singleton_unsigned(new_vote_data, &signature, current, &chain)
        .await
        .map_err(|e| JsError::new(&format!("change_vote_with_singleton_unsigned: {e:?}")))?;
    Ok(SpendBundle::new(coin_spends, signature))
}

/// Compute the canonical vote message the dApp can show ("you're
/// about to sign sha256(vote_data || launcher_id)…"). Pure helper —
/// no chain access.
#[wasm_bindgen(js_name = "canonicalVoteMessage")]
pub fn canonical_vote_message_js(
    election_launcher_id_hex: &str,
    vote_data_hex: &str,
) -> Result<String, JsError> {
    use sha2::{Digest, Sha256};
    let launcher = parse_hex32(election_launcher_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let vote_data = parse_hex32(vote_data_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let mut h = Sha256::new();
    h.update(vote_data.as_ref());
    h.update(launcher.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Ok(format!("0x{}", hex::encode(arr)))
}

async fn build_vote_bundle_internal(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    vote_data_hex: String,
    signature: Signature,
) -> Result<SpendBundle, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let voter_pk = parse_pk(&voter_pk_hex)?;
    let voter_keys = chip_voting_sdk::VoterKeys {
        pubkey: voter_pk,
        // Placeholder secret — `build_vote_bundle_with_signature`
        // never reads it (the caller supplies the signature).
        secret: SecretKey::from_bytes(&[1u8; 32]).expect("constant SK"),
    };
    let voter = chip_voting_sdk::Voter::new(
        config,
        voter_keys,
        chip_voting_sdk::NetworkType::Mainnet,
    );
    let vote_data = parse_hex32(vote_data_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let chain = JsChainReader::new(backend);
    voter
        .build_vote_bundle_with_signature(vote_data, signature, &chain)
        .await
        .map_err(|e| JsError::new(&format!("build_vote_bundle: {e:?}")))
}

/// Build the UNSIGNED release-collateral coin spends. The voter
/// signs an `AggSigMe` over the release_message via Sage; no
/// other signatures are needed (the singleton's
/// `announce_finalization` action emits no AGG_SIG conditions).
/// Returns wallet-shape JSON ready for
/// `walletConnect.signCoinSpends(...)`.
#[wasm_bindgen(js_name = "releaseCollateralBuildSpends")]
pub async fn release_collateral_build_spends_js(
    backend: JsChainBackend,
    config_json: String,
    voter_pk_hex: String,
    destination_hex: String,
) -> Result<JsValue, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let voter_pk = parse_pk(&voter_pk_hex)?;
    let voter_keys = chip_voting_sdk::VoterKeys {
        pubkey: voter_pk,
        secret: SecretKey::from_bytes(&[1u8; 32]).expect("constant SK"),
    };
    let voter = chip_voting_sdk::Voter::new(
        config.clone(),
        voter_keys,
        chip_voting_sdk::NetworkType::Mainnet,
    );
    let destination = parse_hex32(destination_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let chain = JsChainReader::new(backend);
    let current =
        chip_voting_sdk::actors::aggregator::find_current_singleton(&chain, &config)
            .await
            .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;
    let coin_spends = voter
        .release_collateral_with_singleton_unsigned(destination, current, &chain)
        .await
        .map_err(|e| JsError::new(&format!("release_collateral_with_singleton_unsigned: {e:?}")))?;
    let out: Vec<WalletCoinSpend> = coin_spends
        .into_iter()
        .map(coin_spend_to_wallet_json)
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// SECTION 13 — Aggregator wrappers (collect_votes + finalize)
// ============================================================================

/// Walk every voter's hint, fetch their post-vote registration coin,
/// extract the vote_data + signature memos. Returns the JSON-friendly
/// `VoteRecordWire` form (the typed `VoteRecord` doesn't implement
/// Serialize because of `PublicKey`).
#[wasm_bindgen(js_name = "collectVotes")]
pub async fn collect_votes_js(
    backend: JsChainBackend,
    config_json: String,
) -> Result<JsValue, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let chain = JsChainReader::new(backend);
    let mut agg = chip_voting_sdk::Aggregator::new(
        config,
        chain,
        chip_voting_sdk::NetworkType::Mainnet,
    );
    agg.sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e:?}")))?;
    let votes = agg
        .collect_votes()
        .await
        .map_err(|e| JsError::new(&format!("collect_votes: {e:?}")))?;
    let wire: Vec<chip_voting_sdk::state::VoteRecordWire> =
        votes.iter().map(|v| v.into()).collect();
    serde_wasm_bindgen::to_value(&wire).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = "collectVotesWithProgress")]
pub async fn collect_votes_with_progress_js(
    backend: JsChainBackend,
    config_json: String,
    on_progress: &js_sys::Function,
) -> Result<JsValue, JsError> {
    let emit = |p: CollectVotesProgress| {
        if let Ok(v) = serde_wasm_bindgen::to_value(&p) {
            let _ = on_progress.call1(&JsValue::UNDEFINED, &v);
        }
    };

    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let chain = JsChainReader::new(backend);
    let mut agg = chip_voting_sdk::Aggregator::new(
        config,
        chain,
        chip_voting_sdk::NetworkType::Mainnet,
    );

    emit(CollectVotesProgress {
        voter_index: 0,
        voters_total: 0,
        stage: CollectVotesStage::SyncElectionSingleton,
        ballots_collected: 0,
    });
    agg.sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e:?}")))?;

    let votes = agg
        .collect_votes_with_progress(|p| emit(p))
        .await
        .map_err(|e| JsError::new(&format!("collect_votes: {e:?}")))?;
    let wire: Vec<chip_voting_sdk::state::VoteRecordWire> =
        votes.iter().map(|v| v.into()).collect();
    serde_wasm_bindgen::to_value(&wire).map_err(|e| JsError::new(&e.to_string()))
}

/// Build the finalize spend bundle: aggregate signatures, run the
/// Groth16 prover (in-browser!), assemble + sign. Returns the
/// streamable bundle bytes ready to push.
///
/// The Groth16 prover runs entirely in wasm — this is heavy
/// (~5-30s on a modern laptop, depending on signer count). The
/// dApp should show a progress UI while this completes.
#[wasm_bindgen(js_name = "buildFinalizeBundle")]
pub async fn build_finalize_bundle_js(
    backend: JsChainBackend,
    config_json: String,
    proving_key_bytes: Vec<u8>,
    vote_outcome_hex: String,
    reward_address_ph_hex: String,
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    use ark_serialize::CanonicalDeserialize;

    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let vote_outcome = parse_hex32(vote_outcome_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let reward_address = parse_hex32(reward_address_ph_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let chain = JsChainReader::new(backend);

    let mut agg = chip_voting_sdk::Aggregator::new(config, chain, network.into());
    agg.sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e:?}")))?;
    let votes = agg
        .collect_votes()
        .await
        .map_err(|e| JsError::new(&format!("collect_votes: {e:?}")))?;
    if votes.is_empty() {
        return Err(JsError::new("no votes collected — finalize would fail BelowThreshold"));
    }

    // Deserialise the proving key (output of the ceremony).
    let pk = ark_groth16::ProvingKey::<ark_bls12_381::Bls12_381>::deserialize_compressed(
        proving_key_bytes.as_slice(),
    )
    .map_err(|e| JsError::new(&format!("proving key deserialize: {e}")))?;
    let proving_key = chip_voting_sdk::prover::circuit::ArkProvingKey(pk);

    let bundle = agg
        .build_finalize(vote_outcome, &votes, reward_address, &proving_key)
        .await
        .map_err(|e| JsError::new(&format!("build_finalize: {e:?}")))?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

/// Same as [`buildFinalizeBundle`] but uses vote rows already fetched via
/// [`collectVotes`]. Performs `Aggregator::sync` once, then `build_finalize`
/// — avoids walking voter hints twice in the browser.
#[wasm_bindgen(js_name = "buildFinalizeBundleFromCollectedVotes")]
pub async fn build_finalize_bundle_from_collected_votes_js(
    backend: JsChainBackend,
    config_json: String,
    proving_key_bytes: Vec<u8>,
    vote_outcome_hex: String,
    reward_address_ph_hex: String,
    votes_js: JsValue,
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    use ark_serialize::CanonicalDeserialize;

    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let vote_outcome = parse_hex32(vote_outcome_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let reward_address = parse_hex32(reward_address_ph_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let chain = JsChainReader::new(backend);

    let wires: Vec<chip_voting_sdk::VoteRecordWire> =
        serde_wasm_bindgen::from_value(votes_js)
            .map_err(|e| JsError::new(&format!("votes JSON: {e}")))?;
    let mut votes = Vec::with_capacity(wires.len());
    for w in wires {
        votes.push(w.into_record().map_err(|e| JsError::new(&e))?);
    }
    if votes.is_empty() {
        return Err(JsError::new("no votes — finalize would fail BelowThreshold"));
    }

    let mut agg = chip_voting_sdk::Aggregator::new(config, chain, network.into());
    agg.sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e:?}")))?;

    let pk = ark_groth16::ProvingKey::<ark_bls12_381::Bls12_381>::deserialize_compressed(
        proving_key_bytes.as_slice(),
    )
    .map_err(|e| JsError::new(&format!("proving key deserialize: {e}")))?;
    let proving_key = chip_voting_sdk::prover::circuit::ArkProvingKey(pk);

    let bundle = agg
        .build_finalize(vote_outcome, &votes, reward_address, &proving_key)
        .await
        .map_err(|e| JsError::new(&format!("build_finalize: {e:?}")))?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

// ============================================================================
// SECTION 14 — Oracle wrapper
// ============================================================================

/// Build the oracle spend bundle (publishes the (un)finalized
/// vote-outcome announcement). No signing required — the oracle
/// action emits no AGG_SIG conditions; aggregated signature is
/// the BLS identity.
#[wasm_bindgen(js_name = "buildOracleBundle")]
pub async fn build_oracle_bundle_js(
    backend: JsChainBackend,
    config_json: String,
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    let config: chip_voting_sdk::ElectionConfig = serde_json::from_str(&config_json)
        .map_err(|e| JsError::new(&format!("config parse: {e}")))?;
    let chain = JsChainReader::new(backend);
    let oracle = chip_voting_sdk::Oracle::new(config, chain, network.into());
    let bundle = oracle
        .build_oracle_bundle()
        .await
        .map_err(|e| JsError::new(&format!("build_oracle_bundle: {e:?}")))?;
    let bytes = encode_streamable(&bundle)?;
    Ok(bytes.into_boxed_slice())
}

// ============================================================================
// SECTION 15a — Coin-spend reshaping for Sage Wallet
// ============================================================================
//
// The dApp ferries `Vec<CoinSpend>` between wasm functions as raw
// streamable bytes (`encode_coin_spends` / `decode_coin_spends`),
// which is fine for a wasm-to-wasm hop — but Sage Wallet's
// `chip0002_signCoinSpends` RPC takes a JSON array of
// `{ coin: {parent_coin_info, puzzle_hash, amount}, puzzle_reveal,
//   solution }`. The chia streamable format for `Program` is raw
// CLVM bytes (no outer length prefix; the parser walks the CLVM
// tree), so we can't decode it from JS without reimplementing the
// CLVM walker.
//
// Solution: do the decode + reshape inside wasm, return a typed
// JS array. The dApp imports this helper and feeds the result
// directly into `walletConnect.signCoinSpends(...)`.

/// JSON-shaped coin spend matching Sage's `chip0002_signCoinSpends`
/// payload exactly. snake_case field names because that's what the
/// RPC expects on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCoinSpend {
    pub coin: WalletCoin,
    /// 0x-hex puzzle reveal.
    pub puzzle_reveal: String,
    /// 0x-hex solution.
    pub solution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCoin {
    pub parent_coin_info: String,
    pub puzzle_hash: String,
    /// Mojos. JS Number is fine for any realistic amount.
    pub amount: u64,
}

/// Decode the streamable `Vec<CoinSpend>` bytes (as produced by
/// `buildDeployBundle.coinSpendsBytes` etc.) into the JSON shape
/// Sage's `chip0002_signCoinSpends` expects. The dApp passes the
/// returned array to `walletConnect.signCoinSpends(coinSpends, ...)`
/// without further reshaping.
#[wasm_bindgen(js_name = "coinSpendsToWalletJson")]
pub fn coin_spends_to_wallet_json_js(bytes: &[u8]) -> Result<JsValue, JsError> {
    let decoded = decode_coin_spends(bytes)?;
    let out: Vec<WalletCoinSpend> = decoded
        .into_iter()
        .map(coin_spend_to_wallet_json)
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// JSON-shaped SpendBundle matching chia full-node `push_tx`
/// payload exactly. snake_case wire field names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSpendBundle {
    pub coin_spends: Vec<WalletCoinSpend>,
    /// 0x-hex 96-byte aggregated G2 signature.
    pub aggregated_signature: String,
}

/// Decode a streamable `SpendBundle` (as produced by `voteSigned`,
/// `registerSigned`, `releaseCollateralSigned`, `buildFinalizeBundle`,
/// `buildOracleBundle`) into the JSON shape coinset.org's `push_tx`
/// expects. Replaces the wrong "send raw hex bytes" pattern that
/// the chia full-node rejects with `INVALID_SPEND_BUNDLE`.
#[wasm_bindgen(js_name = "bundleToWalletJson")]
pub fn bundle_to_wallet_json_js(bundle_bytes: &[u8]) -> Result<JsValue, JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    let out = WalletSpendBundle {
        coin_spends: bundle
            .coin_spends
            .into_iter()
            .map(coin_spend_to_wallet_json)
            .collect(),
        aggregated_signature: format!(
            "0x{}",
            hex::encode(bundle.aggregated_signature.to_bytes())
        ),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

fn coin_spend_to_wallet_json(cs: chia_protocol::CoinSpend) -> WalletCoinSpend {
    WalletCoinSpend {
        coin: WalletCoin {
            parent_coin_info: format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
            puzzle_hash: format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
            amount: cs.coin.amount,
        },
        puzzle_reveal: format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
        solution: format!("0x{}", hex::encode(cs.solution.as_ref())),
    }
}

fn parse_hex32_j(s: &str) -> Result<chia_protocol::Bytes32, JsError> {
    parse_hex32(s).map_err(|e| JsError::new(&format!("{e:?}")))
}

fn wallet_coin_spend_to_coin_spend(w: WalletCoinSpend) -> Result<chia_protocol::CoinSpend, JsError> {
    let parent_coin_info = parse_hex32_j(&w.coin.parent_coin_info)?;
    let puzzle_hash = parse_hex32_j(&w.coin.puzzle_hash)?;
    let coin = chia_protocol::Coin::new(parent_coin_info, puzzle_hash, w.coin.amount);
    let pr = hex::decode(w.puzzle_reveal.trim().trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("puzzle_reveal hex: {e}")))?;
    let sl = hex::decode(w.solution.trim().trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("solution hex: {e}")))?;
    Ok(chia_protocol::CoinSpend::new(
        coin,
        chia_protocol::Program::from(pr),
        chia_protocol::Program::from(sl),
    ))
}

/// Assemble streamable SpendBundle bytes from wallet-format coin spends —
/// identical JSON shape to [`coinSpendsToWalletJson`] /
/// Sage `chip0002_signCoinSpends` input — plus the aggregated signature
/// hex (96-byte G₂) Sage returns when `partialSign/auto_submit` are
/// false.
///
/// **Why:** Prefer signing with auto-submit OFF, assembling here, verifying
/// with [`bundle_to_wallet_json_js`] + wallet `chip0002_sendTransaction`
/// — that yields a CHIP-0002 `transaction_ack`; some wallets return only
/// a signature hex from auto-submit flows without reliably surfacing
/// mempool failures (the dApp would otherwise poll forever).
#[wasm_bindgen(js_name = "assembleSpendBundleFromWalletCoinSpends")]
pub fn assemble_spend_bundle_from_wallet_coin_spends_js(
    coin_spends_js: JsValue,
    aggregated_signature_hex: &str,
) -> Result<Box<[u8]>, JsError> {
    let spends: Vec<WalletCoinSpend> = serde_wasm_bindgen::from_value(coin_spends_js).map_err(|e| {
        JsError::new(&format!("wallet coin spends JSON decode: {e}"))
    })?;
    let mut protocol_spends = Vec::with_capacity(spends.len());
    for w in spends {
        protocol_spends.push(wallet_coin_spend_to_coin_spend(w)?);
    }
    let coin_spends_encoded = encode_coin_spends(&protocol_spends)?;
    let sig_hex = aggregated_signature_hex.trim().trim_start_matches("0x");
    let sig_raw =
        hex::decode(sig_hex).map_err(|e| JsError::new(&format!("signature hex decode: {e}")))?;
    if sig_raw.len() != 96 {
        return Err(JsError::new(&format!(
            "aggregated signature must be 96 bytes (G₂), got {}",
            sig_raw.len()
        )));
    }
    assemble_spend_bundle_js(&coin_spends_encoded, &sig_raw)
}

// ============================================================================
// SECTION 15 — DIG balance helper (CAT outer puzzle hash)
// ============================================================================

/// Compute the CAT-wrapped puzzle hash for `(asset_id, p2_puzzle_hash)`.
/// The dApp uses this to query coinset.org for the wallet's DIG
/// balance: get_coin_records_by_puzzle_hash(catOuterPuzzleHash, false).
#[wasm_bindgen(js_name = "catOuterPuzzleHash")]
pub fn cat_outer_puzzle_hash_js(
    asset_id_hex: &str,
    p2_puzzle_hash_hex: &str,
) -> Result<String, JsError> {
    use chia_puzzle_types::cat::CatArgs;
    use clvm_utils::TreeHash;
    let asset_id = parse_hex32(asset_id_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let p2 = parse_hex32(p2_puzzle_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let outer = CatArgs::curry_tree_hash(asset_id, TreeHash::from(p2));
    Ok(format!("0x{}", hex::encode(outer.to_bytes())))
}

