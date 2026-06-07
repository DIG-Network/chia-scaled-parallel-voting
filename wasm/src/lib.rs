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

use async_trait::async_trait;
use chip_voting_sdk::chain::{ChainCoinRecord, ChainReader};
use chip_voting_sdk::error::{anyhow_compat, VotingError, VotingResult};
// `NetworkType` (originally `pub use dig_l1_wallet::NetworkType` in
// the SDK) is gated behind the SDK's `native` feature. The wasm
// crate disables that feature, so `chip_voting_sdk::NetworkType` is
// not in scope here. `WasmNetwork` below stands on its own as a
// pure JS-side enum; native-only entry points that previously took
// a `NetworkType` are stubbed in Section 9 / Section 4.
// `SecretKey` was used by the now-stubbed `signCoinSpends`; kept
// in scope (allow(unused_imports)) so the import survives once
// the non-native signing shim re-wires the call site.
#[allow(unused_imports)]
use chip_voting_sdk::{PublicKey, SecretKey, SpendBundle};
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

// NOTE: the original `From<WasmNetwork> for NetworkType` impl is
// deliberately removed. The SDK's `NetworkType` is `pub use
// dig_l1_wallet::NetworkType`, which lives behind the `native`
// feature. The wasm crate builds with `default-features = false`,
// so `NetworkType` is not in scope. `WasmNetwork` is now a
// stand-alone JS-side enum; the call sites that previously fed it
// into the SDK's signing helpers (`sign_bundle_signature`,
// `verify_bundle_signatures`) are stubbed in Section 4 and will
// be re-wired once non-native shims for those helpers land in the
// SDK.

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

/// `JsChainReader` is the wasm-side `ChainReader` adapter. Each
/// trait method awaits the matching JS callback (Promise) on the
/// dApp-supplied backend and decodes the resolved value into the
/// SDK's record types.
///
/// The SDK declares `ChainReader` as `?Send` on `target_arch =
/// "wasm32"` (see `chain::ChainReaderBounds`), so this `JsValue`-
/// holding adapter can stand in for `chia_query::ChiaQuery` /
/// `SharedSimulator` in any actor method (`Voter::register`,
/// `Aggregator::collect_votes_for_ballot`, `BallotReader::list_ballots`,
/// etc.) without restructuring callers.
pub struct JsChainReader {
    backend: JsChainBackend,
}

impl JsChainReader {
    pub fn new(backend: JsChainBackend) -> Self {
        Self { backend }
    }
}

// `JsChainBackend` is a `wasm_bindgen` extern type; the auto-derived
// `Clone` doesn't carry through to wrapper structs reliably. Implement
// it via the JsValue deref so we can pass an owned `JsChainReader` to
// `Aggregator::new(...)` (which consumes its `ChainReader`) AND keep
// the original around for follow-up actor calls in the same wasm
// export.
impl Clone for JsChainReader {
    fn clone(&self) -> Self {
        use wasm_bindgen::JsCast;
        let as_val: &wasm_bindgen::JsValue = AsRef::<wasm_bindgen::JsValue>::as_ref(&self.backend);
        Self {
            backend: as_val.clone().unchecked_into(),
        }
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

/// Decode a hex string (with or without `0x` prefix) into a
/// `chia_protocol::Program`. Used by `puzzle_and_solution` to lift
/// the JS-side hex blobs back into typed CLVM programs.
fn parse_program_hex(hex_str: &str, label: &str) -> VotingResult<chia_protocol::Program> {
    let trimmed = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: hex decode failed: {e}").into(),
        ))
    })?;
    Ok(chia_protocol::Program::from(bytes))
}

#[async_trait(?Send)]
impl ChainReader for JsChainReader {
    async fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: chia_protocol::Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let promise = self
            .backend
            .js_coin_records_by_puzzle_hash(hex::encode(puzzle_hash));
        let records: Vec<JsCoinRecord> =
            await_decode(promise, "coin_records_by_puzzle_hash").await?;
        records.into_iter().map(record_from_js).collect()
    }

    async fn coin_records_by_hint(
        &self,
        hint: chia_protocol::Bytes32,
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let promise = self.backend.js_coin_records_by_hint(hex::encode(hint));
        let records: Vec<JsCoinRecord> =
            await_decode(promise, "coin_records_by_hint").await?;
        records.into_iter().map(record_from_js).collect()
    }

    async fn puzzle_and_solution(
        &self,
        coin_id: chia_protocol::Bytes32,
    ) -> VotingResult<Option<(chia_protocol::Program, chia_protocol::Program)>> {
        let promise = self.backend.js_puzzle_and_solution(hex::encode(coin_id));
        let opt: Option<JsPuzzleSolution> =
            await_decode(promise, "puzzle_and_solution").await?;
        match opt {
            None => Ok(None),
            Some(ps) => Ok(Some((
                parse_program_hex(&ps.puzzle_hex, "puzzle_and_solution.puzzle_hex")?,
                parse_program_hex(&ps.solution_hex, "puzzle_and_solution.solution_hex")?,
            ))),
        }
    }

    async fn coin_records_by_parent_ids(
        &self,
        parent_ids: &[chia_protocol::Bytes32],
    ) -> VotingResult<Vec<ChainCoinRecord>> {
        let parent_hex: Vec<String> = parent_ids.iter().map(hex::encode).collect();
        let parent_ids_val = serde_wasm_bindgen::to_value(&parent_hex).map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("coin_records_by_parent_ids: encode parents: {e}").into(),
            ))
        })?;
        let promise = self.backend.js_coin_records_by_parent_ids(parent_ids_val);
        let records: Vec<JsCoinRecord> =
            await_decode(promise, "coin_records_by_parent_ids").await?;
        records.into_iter().map(record_from_js).collect()
    }

    async fn coin_record_by_id(
        &self,
        coin_id: chia_protocol::Bytes32,
    ) -> VotingResult<Option<ChainCoinRecord>> {
        let promise = self.backend.js_coin_record_by_name(hex::encode(coin_id));
        let opt: Option<JsCoinRecord> =
            await_decode(promise, "coin_record_by_id").await?;
        opt.map(record_from_js).transpose()
    }

    async fn peak_height(&self) -> VotingResult<Option<u32>> {
        let promise = self.backend.js_peak_height();
        await_decode::<Option<u32>>(promise, "peak_height").await
    }
}

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

/// Extract the `Vec<CoinSpend>` from a Streamable-encoded SpendBundle
/// and re-emit it in the length-prefixed list format the
/// `signCoinSpends` / `assembleSpendBundle` exports consume.
///
/// USAGE: round-tripping a bundle through wasm — e.g. take the bundle
/// produced by `createBallotBundle` (which has zero AGG_SIG sig
/// because the SDK calls sign_bundle_signature with empty keys),
/// extract its coin_spends, sign with a funder/voter secret via
/// `signCoinSpends`, then `assembleSpendBundle` the result. Keeps the
/// Streamable bytes within the wasm boundary so JS doesn't have to
/// re-implement chia_protocol's Bytes / Program encoding.
#[wasm_bindgen(js_name = "extractCoinSpendsFromBundle")]
pub fn extract_coin_spends_from_bundle_js(
    bundle_bytes: &[u8],
) -> Result<Box<[u8]>, JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    let bytes = encode_coin_spends(&bundle.coin_spends)?;
    Ok(bytes.into_boxed_slice())
}

/// Sign an unsigned coin-spend list (length-prefixed bytes) with the
/// supplied secret keys, returning the 96-byte aggregated BLS G2
/// signature.
///
/// `secret_keys` is a flat concatenation of 32-byte secrets; pass an
/// empty slice if the bundle has no AGG_SIG_* conditions and you only
/// need the BLS identity element back.
///
/// Walks every AGG_SIG_* condition emitted by every coin spend's
/// puzzle, augments per the chia consensus rules, signs each with
/// the matching secret, and aggregates. Errors if any AGG_SIG
/// condition has a public key with no matching secret. SECP signing
/// is not supported in wasm.
#[wasm_bindgen(js_name = "signCoinSpends")]
pub fn sign_coin_spends_js(
    coin_spends_bytes: &[u8],
    secret_keys: &[u8],
    network: WasmNetwork,
) -> Result<Box<[u8]>, JsError> {
    let coin_spends = decode_coin_spends(coin_spends_bytes)?;
    if !secret_keys.len().is_multiple_of(32) {
        return Err(JsError::new(
            "signCoinSpends: secret_keys length must be a multiple of 32 (flat \
             concatenation of 32-byte BLS secret keys)",
        ));
    }
    let mut secrets: Vec<SecretKey> = Vec::with_capacity(secret_keys.len() / 32);
    for (idx, chunk) in secret_keys.chunks_exact(32).enumerate() {
        let arr: [u8; 32] = chunk.try_into().expect("chunks_exact(32)");
        let sk = SecretKey::from_bytes(&arr).map_err(|e| {
            JsError::new(&format!(
                "signCoinSpends: secret_keys[{idx}] SecretKey::from_bytes: {e:?}"
            ))
        })?;
        secrets.push(sk);
    }
    let sig = chip_voting_sdk::actors::deployer::sign_bundle_signature(
        &coin_spends,
        &secrets,
        wasm_network_to_sdk(network),
    )
    .map_err(|e| JsError::new(&format!("sign_bundle_signature: {e}")))?;
    Ok(sig.to_bytes().to_vec().into_boxed_slice())
}

/// Locally-validate a SpendBundle's signatures (BLS aggregate verify
/// over the consensus-required `(pubkey, augmented_message)` pairs).
/// CLVM dry-run is also performed via
/// `chip_voting_sdk::dry_run_coin_spends`.
///
/// FEATURE-GATE STUB: the dry-run half (CLVM run_program) works in
/// wasm; the BLS-verify half currently goes through
/// `chip_voting_sdk::verify_bundle_signatures`, which is gated
/// behind `native` because it threads through `dig_l1_wallet::
/// transaction::get_agg_sig_data`. Until the SDK exposes a
/// non-native equivalent, this returns a typed `JsError`.
#[wasm_bindgen(js_name = "verifyBundleLocally")]
pub fn verify_bundle_locally_js(
    bundle_bytes: &[u8],
    _network: WasmNetwork,
) -> Result<(), JsError> {
    let bundle: SpendBundle = decode_bundle(bundle_bytes)?;
    // CLVM dry-run + bundle-balance check (catches MINTING_COIN class
    // before broadcast). Signature verification is the wallet's
    // responsibility on wasm targets — chia mainnet's full validation
    // (BLS aggregate verify against AGG_SIG_ME conditions) needs the
    // network's agg_sig_me_additional_data, which currently lives
    // behind dig_l1_wallet (native-only).
    chip_voting_sdk::dry_run_coin_spends(&bundle.coin_spends)
        .map_err(|e| JsError::new(&format!("dry_run: {e:?}")))?;
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
// SECTION 5a — XCH funder spend builder (`buildXchFunderSpend`)
// ============================================================================

/// Build a Streamable-encoded `CoinSpend` that spends an XCH coin
/// owned by `funder_synthetic_pk_hex` and emits a single
/// `CreateCoin(funder_p2_ph, change_amount)` if `change_amount > 0`.
/// Mirrors the funder pre-spend half of
/// `cli/src/bin/live_integration_test.rs::phase_create_ballot`.
///
/// The output bytes drop straight into `createBallotBundle`'s
/// `funder_spend_bytes` and `registerBuildSpends`'s
/// `cat_parent_spend_bytes` (after CAT-wrapping) without further
/// shaping.
///
/// The spend is UNSIGNED — the standard p2 puzzle emits an
/// `AggSigMe(synthetic_pk, msg)` condition that must be signed at
/// the bundle level by `signCoinSpends`. Pass the funder's synthetic
/// secret to `signCoinSpends` after the createBallot bundle is
/// assembled.
#[wasm_bindgen(js_name = "buildXchFunderSpend")]
pub fn build_xch_funder_spend_js(
    parent_coin_info_hex: &str,
    funder_synthetic_pk_hex: &str,
    amount: u64,
    change_amount: u64,
) -> Result<Box<[u8]>, JsError> {
    use chia_protocol::Coin;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chip_voting_sdk::Conditions;

    let parent = parse_hex32(parent_coin_info_hex)
        .map_err(|e| JsError::new(&format!("parent_coin_info_hex: {e}")))?;
    let pk_bytes = hex::decode(funder_synthetic_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_synthetic_pk_hex decode: {e}")))?;
    let pk_arr: [u8; 48] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("funder_synthetic_pk_hex must be 48 bytes"))?;
    let synthetic_pk = PublicKey::from_bytes(&pk_arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;
    let funder_p2_ph =
        chia_protocol::Bytes32::new(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());

    let coin = Coin::new(parent, funder_p2_ph, amount);

    let mut ctx = SpendContext::new();
    let mut conditions = Conditions::new();
    if change_amount > 0 {
        conditions = conditions.create_coin(funder_p2_ph, change_amount, Memos::None);
    }
    StandardLayer::new(synthetic_pk)
        .spend(&mut ctx, coin, conditions)
        .map_err(|e| JsError::new(&format!("StandardLayer::spend: {e:?}")))?;
    let spends = ctx.take();
    let cs = spends
        .into_iter()
        .next()
        .ok_or_else(|| JsError::new("StandardLayer::spend produced no coin spends"))?;
    let bytes = encode_streamable(&cs)?;
    Ok(bytes.into_boxed_slice())
}

// ============================================================================
// SECTION 5a2 — CAT registration spend builder (`buildCatRegistrationSpend`)
// ============================================================================

/// Build the Streamable-encoded CAT parent CoinSpend that funds a
/// voter's Registration Coin. Mirrors `cli/src/bin/live_integration_test
/// .rs::build_cat_collateral_spend` but takes a `JsChainBackend` and
/// reconstructs the CAT lineage proof on chain.
///
/// SHAPE — single CAT input → up to two CAT outputs:
///   1. Registration coin → at `fresh_registration_coin_puzzle_hash`
///      with `collateral_amount` (CAT outer wraps inner ph emitted by
///      the standard p2 spend).
///   2. Change → back to validator's CAT-wrapped p2 ph (skipped if
///      change == 0).
///
/// Inner conditions emitted by the standard p2 spend:
///   * `CreateCoin(reg_inner_ph, collateral, [voter_hint memo])`
///   * `CreateCoinAnnouncement(create_reg_msg)` — what
///      `register.rue` asserts.
///   * `CreateCoin(synthetic_p2, change)` if change > 0.
///
/// The resulting CoinSpend is the `cat_parent_spend` arg
/// `Voter::register` (and `wasm.registerBuildSpends`) consumes.
#[wasm_bindgen(js_name = "buildCatRegistrationSpend")]
pub async fn build_cat_registration_spend_js(
    backend: JsChainBackend,
    voter_secret_hex: String,
    cat_input_coin_id_hex: String,
    election_launcher_id_hex: String,
    cat_tail_hash_hex: String,
    collateral_amount: u64,
) -> Result<Vec<u8>, JsError> {
    use chia_puzzle_types::DeriveSynthetic;

    let voter_secret = parse_secret_hex(&voter_secret_hex, "voter_secret_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let voter_pk = voter_secret.public_key();
    let synthetic_pk = voter_secret.derive_synthetic().public_key();
    let voter_pk_hex = format!("0x{}", hex::encode(voter_pk.to_bytes()));
    let synthetic_pk_hex = format!("0x{}", hex::encode(synthetic_pk.to_bytes()));
    build_cat_registration_spend_for_wallet_js(
        backend,
        voter_pk_hex,
        synthetic_pk_hex,
        cat_input_coin_id_hex,
        election_launcher_id_hex,
        cat_tail_hash_hex,
        collateral_amount,
    )
    .await
}

/// Sage-friendly variant of [`buildCatRegistrationSpend`]. Takes the
/// voter's account-path pubkey and the validator's synthetic pubkey
/// externally (the dApp resolves both via Sage's
/// `chip0002_getPublicKeys` paging) so the secret never enters the
/// browser. Inner spend's StandardLayer is curried with the supplied
/// synthetic_pk; chip0002_signCoinSpends fills in the AGG_SIG_ME later
/// when the full register bundle is signed.
#[wasm_bindgen(js_name = "buildCatRegistrationSpendForWallet")]
pub async fn build_cat_registration_spend_for_wallet_js(
    backend: JsChainBackend,
    voter_pk_hex: String,
    validator_synthetic_pk_hex: String,
    cat_input_coin_id_hex: String,
    election_launcher_id_hex: String,
    cat_tail_hash_hex: String,
    collateral_amount: u64,
) -> Result<Vec<u8>, JsError> {
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{Cat as DriverCat, CatSpend, Puzzle, SpendContext, SpendWithConditions, StandardLayer};
    use chip_voting_sdk::clvm_traits::ToClvm;
    use chip_voting_sdk::clvmr::Allocator;
    use chip_voting_sdk::Conditions;
    use sha2::{Digest, Sha256};

    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let synthetic_pk =
        parse_pubkey_hex(&validator_synthetic_pk_hex, "validator_synthetic_pk_hex")
            .map_err(|e| JsError::new(&format!("{e}")))?;
    let p2_puzzle_hash =
        chia_protocol::Bytes32::new(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());

    let election_launcher_id = parse_hex32(&election_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("election_launcher_id_hex: {e}")))?;
    let cat_tail_hash = parse_hex32(&cat_tail_hash_hex)
        .map_err(|e| JsError::new(&format!("cat_tail_hash_hex: {e}")))?;
    let cat_input_coin_id = parse_hex32(&cat_input_coin_id_hex)
        .map_err(|e| JsError::new(&format!("cat_input_coin_id_hex: {e}")))?;

    let chain = JsChainReader::new(backend);

    // ── 1. Find CAT input coin
    let cat_input_record = chain
        .coin_record_by_id(cat_input_coin_id)
        .await
        .map_err(|e| JsError::new(&format!("coin_record_by_id: {e}")))?
        .ok_or_else(|| JsError::new("buildCatRegistrationSpend: CAT input coin not found"))?;
    let cat_input_coin = cat_input_record.coin;
    if cat_input_coin.amount < collateral_amount {
        return Err(JsError::new(&format!(
            "CAT input amount {} < required collateral {}",
            cat_input_coin.amount, collateral_amount,
        )));
    }

    // ── 2. Reconstruct CAT lineage proof from parent's spend
    let parent_id = cat_input_coin.parent_coin_info;
    let parent_record = chain
        .coin_record_by_id(parent_id)
        .await
        .map_err(|e| JsError::new(&format!("parent_coin_record: {e}")))?
        .ok_or_else(|| JsError::new("CAT parent coin not found"))?;
    let (puzzle_program, solution_program) = chain
        .puzzle_and_solution(parent_id)
        .await
        .map_err(|e| JsError::new(&format!("parent puzzle_and_solution: {e}")))?
        .ok_or_else(|| JsError::new("CAT parent coin is unspent — cannot derive lineage"))?;
    let mut allocator = Allocator::new();
    let parent_puzzle_node = puzzle_program
        .to_clvm(&mut allocator)
        .map_err(|e| JsError::new(&format!("parent puzzle to_clvm: {e}")))?;
    let parent_solution_node = solution_program
        .to_clvm(&mut allocator)
        .map_err(|e| JsError::new(&format!("parent solution to_clvm: {e}")))?;
    let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);
    let children = DriverCat::parse_children(
        &mut allocator,
        parent_record.coin,
        parent_puzzle,
        parent_solution_node,
    )
    .map_err(|e| JsError::new(&format!("Cat::parse_children: {e:?}")))?
    .ok_or_else(|| JsError::new("CAT parent is not a CAT spend"))?;
    let cat_input = children
        .into_iter()
        .find(|c| c.coin.coin_id() == cat_input_coin_id)
        .ok_or_else(|| JsError::new("CAT child not found among parent's CAT children"))?;

    // ── 3. Compute the inner / outer puzzle hashes + create_reg_msg
    let reg_inner_ph = chip_voting_sdk::puzzles::fresh_registration_inner_hash(
        &voter_pk,
        election_launcher_id,
        cat_tail_hash,
        collateral_amount,
    );
    let reg_outer_ph = chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
        cat_tail_hash,
        &voter_pk,
        election_launcher_id,
        collateral_amount,
    );
    let mut h = Sha256::new();
    h.update(b"create_reg");
    h.update(election_launcher_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(reg_outer_ph.as_ref());
    h.update(collateral_amount.to_be_bytes());
    let create_reg_msg: [u8; 32] = h.finalize().into();

    let voter_hint =
        chip_voting_sdk::puzzles::voter_hint(election_launcher_id, cat_tail_hash, &voter_pk);

    // ── 4. Build the inner spend (StandardLayer + Conditions)
    let mut ctx = SpendContext::new();
    let voter_hint_memos = ctx
        .hint(voter_hint)
        .map_err(|e| JsError::new(&format!("ctx.hint: {e:?}")))?;
    let change_amount = cat_input.coin.amount.saturating_sub(collateral_amount);
    let mut inner_conditions = Conditions::new()
        .create_coin(reg_inner_ph, collateral_amount, voter_hint_memos)
        .create_coin_announcement(chia_protocol::Bytes::new(create_reg_msg.to_vec()));
    if change_amount > 0 {
        inner_conditions = inner_conditions.create_coin(p2_puzzle_hash, change_amount, Memos::None);
    }
    let inner_spend = StandardLayer::new(synthetic_pk)
        .spend_with_conditions(&mut ctx, inner_conditions)
        .map_err(|e| JsError::new(&format!("StandardLayer::spend_with_conditions: {e:?}")))?;

    // ── 5. Wrap as Cat spend, run Cat::spend_all
    let cat_spend = CatSpend::new(cat_input, inner_spend);
    DriverCat::spend_all(&mut ctx, &[cat_spend])
        .map_err(|e| JsError::new(&format!("Cat::spend_all: {e:?}")))?;

    // ── 6. Find the spend whose input is our CAT coin
    let coin_spends = ctx.take();
    let parent_spend = coin_spends
        .into_iter()
        .find(|cs| cs.coin.coin_id() == cat_input_coin_id)
        .ok_or_else(|| JsError::new("CAT spend list missing the input we passed in"))?;

    let bytes = encode_streamable(&parent_spend)?;
    Ok(bytes)
}

// ============================================================================
// SECTION 5b — Trusted-setup ceremony (`runSingleParticipantCeremony`)
// ============================================================================

/// Result of [`run_single_participant_ceremony_js`]. The wire-format
/// VK hex goes straight into [`WasmDeployParams::verification_key_hex`];
/// the proving key bytes are the arkworks-compressed
/// `ProvingKey<Bls12_381>` payload that
/// [`buildBallotFinalizeBundle`] consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCeremonyArtifacts {
    /// 768-byte verification key (`alpha||beta||gamma||delta||IC[0..9]`),
    /// hex-encoded with `0x` prefix.
    pub verification_key_hex: String,
    /// Compressed `ProvingKey<Bls12_381>` bytes (arkworks
    /// CanonicalSerialize). Hand to `buildBallotFinalizeBundle` at
    /// finalize time. Many MB — cache to IndexedDB / disk.
    #[serde(with = "serde_bytes")]
    pub proving_key_bytes: Vec<u8>,
}

/// Run a single-participant trusted-setup ceremony using
/// [`SimulatedBackend`](chip_voting_sdk::SimulatedBackend::default()) and return
/// `(verificationKeyHex, provingKeyBytes)`.
///
/// SECURITY: the simulated backend is a deterministic toy — anyone
/// can recompute the keys, so the resulting setup is **not** secure
/// against forgery. It produces structurally identical artefacts to
/// a real MPC ceremony, so deploy / finalize plumbing is validated
/// end-to-end. For production, replace with a multi-party ceremony.
///
/// Mirrors `run_local_ceremony` in `cli/src/bin/live_integration_test.rs`.
#[wasm_bindgen(js_name = "runSingleParticipantCeremony")]
pub fn run_single_participant_ceremony_js() -> Result<JsValue, JsError> {
    use chip_voting_sdk::ceremony::{CeremonyCoordinator, CeremonyParticipant, MpcBackend};
    use chip_voting_sdk::SimulatedBackend;

    let mut coord = CeremonyCoordinator::new(Box::new(SimulatedBackend::default()));
    coord
        .start("chip-voting-v1".into())
        .map_err(|e| JsError::new(&format!("ceremony start: {e:?}")))?;

    let alice = CeremonyParticipant::new(
        Box::new(SimulatedBackend::default()),
        "wasm-single-participant".into(),
        Some("wasm runSingleParticipantCeremony".into()),
    );
    let pre = coord
        .current_transcript()
        .map_err(|e| JsError::new(&format!("current_transcript: {e:?}")))?
        .clone();

    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| JsError::new(&format!("getrandom: {e}")))?;

    let contribution = alice
        .contribute(&pre, entropy)
        .map_err(|e| JsError::new(&format!("ceremony contribute: {e:?}")))?;
    coord
        .accept_contribution(contribution.transcript)
        .map_err(|e| JsError::new(&format!("accept_contribution: {e:?}")))?;

    let final_transcript = coord
        .current_transcript()
        .map_err(|e| JsError::new(&format!("current_transcript: {e:?}")))?;
    let backend = SimulatedBackend::default();
    let (pk_wire, vk_wire) = backend
        .extract_keys(final_transcript)
        .map_err(|e| JsError::new(&format!("extract_keys: {e:?}")))?;

    let artifacts = WasmCeremonyArtifacts {
        verification_key_hex: format!("0x{}", hex::encode(&vk_wire.raw_bytes)),
        proving_key_bytes: pk_wire.raw_bytes,
    };
    serde_wasm_bindgen::to_value(&artifacts).map_err(|e| {
        JsError::new(&format!("serialise WasmCeremonyArtifacts: {e}"))
    })
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
///
/// FEATURE-GATE STUB: `actors::deployer::derive_launcher_id` lives
/// behind the SDK's `native` feature (the whole `actors` module is
/// gated). The launcher-id derivation is pure puzzle-hash math and
/// will be re-exposed under a non-`native` feature in a follow-up
/// SDK change; until then, this returns a typed `JsError`.
#[wasm_bindgen(js_name = "deriveLauncherId")]
pub fn derive_launcher_id_js(
    parent_coin_id_hex: &str,
    amount: u64,
) -> Result<String, JsError> {
    use chip_voting_sdk::actors::deployer::derive_launcher_id;
    let parent = parse_hex32(parent_coin_id_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let launcher = derive_launcher_id(parent, amount);
    Ok(format!("0x{}", hex::encode(launcher)))
}

/// Build the (unsigned) deploy spend bundle for a new election.
/// Mirrors `phase_deploy` in `cli/src/bin/live_integration_test.rs`.
///
/// FEATURE-GATE STUB: `ElectionDeployer` / `DeployParams` /
/// `actors::deployer::derive_launcher_id` /
/// `actors::aggregator::compute_eve_inner_puzzle_hash` all live
/// inside the SDK's `actors` module, which is gated behind the
/// `native` feature (because the actor surface unconditionally
/// pulls in `dig_l1_wallet::NetworkType` and a default
/// `chia_query::ChiaQuery` chain generic). Re-exposing the
/// puzzle-build half of these actors under a non-`native` feature
/// is the planned follow-up; until then, this returns a typed
/// `JsError`.
#[wasm_bindgen(js_name = "buildDeployBundle")]
pub fn build_deploy_bundle_js(
    params: JsValue,
    parent_coin: JsValue,
    funder_pk_hex: &str,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash;
    use chip_voting_sdk::actors::deployer::{derive_launcher_id, DeployParams, ElectionDeployer};
    use chip_voting_sdk::ceremony::VerificationKey;
    use chip_voting_sdk::puzzles::election_singleton_puzzle_hash;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsDeployParams {
        verification_key_hex: String,
        cat_tail_hash_hex: String,
        collateral_amount: u64,
        election_start_height: u64,
        // V9 + V10-finish: ceremony-link fields.
        // ALL-OR-NONE semantics:
        //   * All four fields present (and parseable) → use the V7
        //     linked-deploy path: co-spend the voucher and assert
        //     its canonical announcement.
        //   * All four fields absent (or empty/null) → fall back to
        //     the legacy unlinked path (`build_deploy_bundle` with
        //     `allow_unlinked_ceremony=true`). This keeps single-
        //     participant test-mode deploys working until the dApp
        //     /create page learns to discover real vouchers from a
        //     finalized ceremony.
        //   * Mixed presence → error (caller is in an inconsistent
        //     state and we can't safely default the missing fields).
        #[serde(default)]
        ceremony_launcher_id_hex: Option<String>,
        #[serde(default)]
        vk_hash_hex: Option<String>,
        #[serde(default)]
        ceremony_voucher_coin_parent_id_hex: Option<String>,
        #[serde(default)]
        ceremony_voucher_amount: Option<u64>,
        // M9: per-election ballot-mode lock. Optional. Defaults to
        // VOTE_MODE_LOCK_NONE sentinel ("no lock" — each ballot picks
        // its own mode). 32-byte hex; "ff..ff" = no lock,
        // "00..00" = lock to Mode1Free, anything else = lock to that
        // exact sorted-options-merkle-root.
        #[serde(default)]
        vote_mode_lock_hex: Option<String>,
        #[serde(default)]
        label: Option<String>,
    }
    let p: JsDeployParams = serde_wasm_bindgen::from_value(params)
        .map_err(|e| JsError::new(&format!("DeployParams decode: {e}")))?;
    let pc: JsCoinRecord = serde_wasm_bindgen::from_value(parent_coin)
        .map_err(|e| JsError::new(&format!("parent_coin decode: {e}")))?;

    let vk_bytes = hex::decode(p.verification_key_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("verification_key_hex decode: {e}")))?;
    let cat_tail = parse_hex32(&p.cat_tail_hash_hex)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let parent_coin_obj = coin_from_js(&pc)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let pk_arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&pk_arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;

    // V9 + V10-finish: route between linked and unlinked deploy paths
    // based on whether the caller supplied the full voucher field set.
    let voucher_fields_present = p.ceremony_launcher_id_hex.as_deref().filter(|s| !s.is_empty()).is_some()
        && p.vk_hash_hex.as_deref().filter(|s| !s.is_empty()).is_some()
        && p.ceremony_voucher_coin_parent_id_hex.as_deref().filter(|s| !s.is_empty()).is_some()
        && p.ceremony_voucher_amount.is_some();
    let voucher_fields_absent = p.ceremony_launcher_id_hex.as_deref().unwrap_or("").is_empty()
        && p.vk_hash_hex.as_deref().unwrap_or("").is_empty()
        && p.ceremony_voucher_coin_parent_id_hex.as_deref().unwrap_or("").is_empty()
        && p.ceremony_voucher_amount.is_none();
    if !voucher_fields_present && !voucher_fields_absent {
        return Err(JsError::new(
            "ceremony-link fields must be ALL provided (linked deploy) or ALL absent \
             (legacy unlinked deploy); mixed state rejected to prevent silent fallback",
        ));
    }

    // Parse ceremony-link inputs (only meaningful when present; default to
    // sentinel zeros for the unlinked path so DeployParams stays well-formed).
    let ceremony_launcher_id = match p.ceremony_launcher_id_hex.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => parse_hex32(s)
            .map_err(|e| JsError::new(&format!("ceremony_launcher_id_hex: {e:?}")))?,
        None => chia_protocol::Bytes32::default(),
    };
    let vk_hash = match p.vk_hash_hex.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => parse_hex32(s)
            .map_err(|e| JsError::new(&format!("vk_hash_hex: {e:?}")))?,
        None => chia_protocol::Bytes32::default(),
    };

    let vote_mode_lock = match &p.vote_mode_lock_hex {
        Some(s) if !s.is_empty() => parse_hex32(s)
            .map_err(|e| JsError::new(&format!("vote_mode_lock_hex: {e:?}")))?,
        _ => chip_voting_sdk::vote_mode::VOTE_MODE_LOCK_NONE,
    };

    let deployer = ElectionDeployer::new(DeployParams {
        verification_key: VerificationKey { raw_bytes: vk_bytes },
        cat_tail_hash: cat_tail,
        collateral_amount: p.collateral_amount,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: chip_voting_sdk::config::MAX_SIGNERS,
        election_start_height: p.election_start_height,
        ceremony_launcher_id,
        vk_hash,
        vote_mode_lock,
        label: p.label,
    });

    let (coin_spends, config) = if voucher_fields_present {
        // Linked deploy: reconstruct the voucher coin from supplied fields,
        // then call build_deploy_bundle_with_ceremony_link.
        let voucher_parent = parse_hex32(
            p.ceremony_voucher_coin_parent_id_hex
                .as_deref()
                .expect("voucher_fields_present checked above"),
        )
        .map_err(|e| JsError::new(&format!("ceremony_voucher_coin_parent_id_hex: {e:?}")))?;
        let voucher_ph = chip_voting_sdk::puzzles::ceremony_voucher_puzzle_hash(
            vk_hash,
            chip_voting_sdk::config::MAX_SIGNERS as u64,
            ceremony_launcher_id,
        );
        let voucher_coin = chia_protocol::Coin::new(
            voucher_parent,
            voucher_ph,
            p.ceremony_voucher_amount.unwrap(),
        );
        deployer
            .build_deploy_bundle_with_ceremony_link(parent_coin_obj, funder_pk, voucher_coin)
            .map_err(|e| JsError::new(&format!("build_deploy_bundle_with_ceremony_link: {e:?}")))?
    } else {
        // Unlinked legacy path (test-mode + back-compat). Caller MUST be aware
        // the deploy lacks the on-chain ceremony binding.
        deployer
            .build_deploy_bundle(parent_coin_obj, funder_pk, true)
            .map_err(|e| JsError::new(&format!("build_deploy_bundle (unlinked): {e:?}")))?
    };

    let launcher_id = derive_launcher_id(parent_coin_obj.coin_id(), 1);
    let eve_inner_ph = compute_eve_inner_puzzle_hash(&config, p.election_start_height);
    let eve_outer_ph = election_singleton_puzzle_hash(launcher_id, eve_inner_ph);
    let eve_coin = chia_protocol::Coin::new(launcher_id, eve_outer_ph, 1);
    let eve_id = eve_coin.coin_id();

    let coin_spends_bytes = encode_coin_spends(&coin_spends)?;

    let config_json = serde_json::to_string(&config)
        .map_err(|e| JsError::new(&format!("config serialize: {e}")))?;

    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "coinSpendsBytes": coin_spends_bytes,
        "launcherIdHex": format!("0x{}", hex::encode(launcher_id)),
        "configJson": config_json,
        "eveSingletonCoinIdHex": format!("0x{}", hex::encode(eve_id)),
    }))
    .map_err(|e| JsError::new(&format!("result encode: {e}")))?;
    Ok(result)
}

/// FN: deploy_ceremony_bundle_js
/// WHAT: Build the genesis spend bundle for a Ceremony Singleton
///       (Phase 4 wasm export). Mirrors `buildDeployBundle` in shape:
///       takes JS params + parent coin + funder pk; returns the
///       coin-spends bytes plus the predicted launcher id.
/// JS NAME: `deployCeremonyBundle`.
/// CONTRACT (JS shape):
///   params = {
///     startBlockHeight: number,
///     ceremonyLengthBlocks: number,
///     minParticipants: number,
///     vkSeedHex: string,        // 32-byte hex (with or without 0x)
///     label?: string,
///   }
///   parentCoin = JsCoinRecord
///   funderPkHex = 48-byte BLS G1 hex.
/// RETURNS:
///   { coinSpendsBytes, launcherIdHex }
#[wasm_bindgen(js_name = "deployCeremonyBundle")]
pub fn deploy_ceremony_bundle_js(
    params: JsValue,
    parent_coin: JsValue,
    funder_pk_hex: &str,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::ceremony::{CeremonyDeployer, CeremonyParams};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsCeremonyParams {
        start_block_height: u64,
        ceremony_length_blocks: u64,
        min_participants: u64,
        /// Post-E4: deploy-time circuit cap. Default 20_000 if missing
        /// (legacy callers); E5 makes the dApp form always send it.
        #[serde(default)]
        max_voters: Option<u64>,
        vk_seed_hex: String,
        #[serde(default)]
        label: Option<String>,
    }
    let p: JsCeremonyParams = serde_wasm_bindgen::from_value(params)
        .map_err(|e| JsError::new(&format!("CeremonyParams decode: {e}")))?;
    let pc: JsCoinRecord = serde_wasm_bindgen::from_value(parent_coin)
        .map_err(|e| JsError::new(&format!("parent_coin decode: {e}")))?;

    let vk_seed = parse_hex32(&p.vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vk_seed_hex: {e:?}")))?;
    let parent_coin_obj = coin_from_js(&pc)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let pk_arr: [u8; 48] = pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&pk_arr)
        .map_err(|e| JsError::new(&format!("PublicKey::from_bytes: {e:?}")))?;

    let deployer = CeremonyDeployer::new(CeremonyParams {
        start_block_height: p.start_block_height,
        ceremony_length_blocks: p.ceremony_length_blocks,
        min_participants: p.min_participants,
        max_voters: p.max_voters.unwrap_or(20_000),
        vk_seed,
        label: p.label,
    });
    let (coin_spends, launcher_id) = deployer
        .build_deploy_bundle(parent_coin_obj, funder_pk)
        .map_err(|e| JsError::new(&format!("build_deploy_bundle: {e:?}")))?;

    let coin_spends_bytes = encode_coin_spends(&coin_spends)?;

    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "coinSpendsBytes": coin_spends_bytes,
        "launcherIdHex": format!("0x{}", hex::encode(launcher_id)),
    }))
    .map_err(|e| JsError::new(&format!("result encode: {e}")))?;
    Ok(result)
}

/// FN: contribute_to_ceremony_js
/// WHAT: Build the spend bundle for a single Ceremony contribution.
///       The dApp UI calls this AFTER off-chain Groth16 contribution
///       computation finishes — passing in the (locally-derived)
///       contribution_hash + payload bytes plus the chain-walked
///       singleton tip + lineage proof.
/// JS NAME: `contributeToCeremony`.
/// CONTRACT (JS shape):
///   ceremony = {                       // matches deployCeremonyBundle params
///     launcherIdHex: string,
///     startBlockHeight: number,
///     ceremonyLengthBlocks: number,
///     minParticipants: number,
///     vkSeedHex: string,
///   }
///   singleton = {
///     coin: JsCoinRecord,              // the unspent singleton tip
///     lineageProof: { kind: "eve"|"lineage", ... },
///     state: { contributionCount: number, lastContributionHashHex: string },
///   }
///   funderCoin = JsCoinRecord
///   funderPkHex = 48-byte BLS G1 hex
///   contribution = {
///     participantPkHex: string,        // 48-byte BLS G1 hex
///     contributionHashHex: string,     // 32-byte hex (caller-computed)
///     prevContributionHashHex: string, // 32-byte hex
///     payloadHex: string,              // off-chain Groth16 contribution bytes (hex)
///   }
/// RETURNS:
///   { coinSpendsBytes, signatureMsgHex, markerCoinIdHex }
///   * `signatureMsgHex` is the UNAUGMENTED 32-byte digest the
///     participant must sign with `sign_raw` to satisfy the action's
///     AGG_SIG_UNSAFE.
///   * `markerCoinIdHex` is the predicted coin id of the marker
///     CeremonyCoin emitted by the spend (handy for UI tracking).
#[wasm_bindgen(js_name = "contributeToCeremony")]
pub fn contribute_to_ceremony_js(
    ceremony: JsValue,
    singleton: JsValue,
    funder_coin: JsValue,
    funder_pk_hex: &str,
    contribution: JsValue,
) -> Result<JsValue, JsError> {
    use chia_protocol::Coin;
    use chia_puzzle_types::{EveProof, LineageProof, Proof};
    use chip_voting_sdk::actors::ceremony::{
        ceremony_coin_marker_puzzle_hash, CeremonyContributor, CeremonyParams,
        ContributeParams,
    };
    use chip_voting_sdk::state::CeremonyState;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsCeremony {
        launcher_id_hex: String,
        start_block_height: u64,
        ceremony_length_blocks: u64,
        min_participants: u64,
        vk_seed_hex: String,
    }
    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "lowercase")]
    enum JsLineageProof {
        Eve {
            #[serde(rename = "parentParentCoinInfoHex")]
            parent_parent_coin_info_hex: String,
            #[serde(rename = "parentAmount")]
            parent_amount: u64,
        },
        Lineage {
            #[serde(rename = "parentParentCoinInfoHex")]
            parent_parent_coin_info_hex: String,
            #[serde(rename = "parentInnerPuzzleHashHex")]
            parent_inner_puzzle_hash_hex: String,
            #[serde(rename = "parentAmount")]
            parent_amount: u64,
        },
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsSingletonState {
        contribution_count: u64,
        last_contribution_hash_hex: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsSingleton {
        coin: JsCoinRecord,
        lineage_proof: JsLineageProof,
        state: JsSingletonState,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsContribution {
        participant_pk_hex: String,
        contribution_hash_hex: String,
        prev_contribution_hash_hex: String,
        /// Raw 32-byte τ entropy hex. Embedded in the marker coin's
        /// memos (post-B1) so chain-walkers can recover entropy
        /// directly from `coin_records_by_hint(launcher_id)` without
        /// parsing the full puzzle_and_solution.
        #[serde(default)]
        entropy_hex: String,
        /// Off-chain Groth16 payload as hex (with or without `0x`).
        /// Hex over base64 keeps the wasm dep set tight; the payload
        /// only travels through this boundary once per contribution.
        payload_hex: String,
    }

    let c: JsCeremony = serde_wasm_bindgen::from_value(ceremony)
        .map_err(|e| JsError::new(&format!("ceremony decode: {e}")))?;
    let s: JsSingleton = serde_wasm_bindgen::from_value(singleton)
        .map_err(|e| JsError::new(&format!("singleton decode: {e}")))?;
    let fc: JsCoinRecord = serde_wasm_bindgen::from_value(funder_coin)
        .map_err(|e| JsError::new(&format!("funder_coin decode: {e}")))?;
    let cb: JsContribution = serde_wasm_bindgen::from_value(contribution)
        .map_err(|e| JsError::new(&format!("contribution decode: {e}")))?;

    let launcher_id = parse_hex32(&c.launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcherIdHex: {e:?}")))?;
    let vk_seed = parse_hex32(&c.vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vkSeedHex: {e:?}")))?;
    let last_hash = parse_hex32(&s.state.last_contribution_hash_hex)
        .map_err(|e| JsError::new(&format!("lastContributionHashHex: {e:?}")))?;
    let contrib_hash = parse_hex32(&cb.contribution_hash_hex)
        .map_err(|e| JsError::new(&format!("contributionHashHex: {e:?}")))?;
    let prev_hash = parse_hex32(&cb.prev_contribution_hash_hex)
        .map_err(|e| JsError::new(&format!("prevContributionHashHex: {e:?}")))?;

    let singleton_coin: Coin = coin_from_js(&s.coin)
        .map_err(|e| JsError::new(&format!("singleton coin: {e:?}")))?;
    let funder_coin_obj: Coin = coin_from_js(&fc)
        .map_err(|e| JsError::new(&format!("funder coin: {e:?}")))?;

    let lineage_proof = match s.lineage_proof {
        JsLineageProof::Eve {
            parent_parent_coin_info_hex,
            parent_amount,
        } => Proof::Eve(EveProof {
            parent_parent_coin_info: parse_hex32(&parent_parent_coin_info_hex)
                .map_err(|e| JsError::new(&format!("parentParentCoinInfoHex: {e:?}")))?,
            parent_amount,
        }),
        JsLineageProof::Lineage {
            parent_parent_coin_info_hex,
            parent_inner_puzzle_hash_hex,
            parent_amount,
        } => Proof::Lineage(LineageProof {
            parent_parent_coin_info: parse_hex32(&parent_parent_coin_info_hex)
                .map_err(|e| JsError::new(&format!("parentParentCoinInfoHex: {e:?}")))?,
            parent_inner_puzzle_hash: parse_hex32(&parent_inner_puzzle_hash_hex)
                .map_err(|e| JsError::new(&format!("parentInnerPuzzleHashHex: {e:?}")))?,
            parent_amount,
        }),
    };

    let funder_pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let funder_pk_arr: [u8; 48] = funder_pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&funder_pk_arr)
        .map_err(|e| JsError::new(&format!("funder PublicKey::from_bytes: {e:?}")))?;

    let participant_pk_bytes = hex::decode(cb.participant_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("participant_pk_hex decode: {e}")))?;
    let participant_pk_arr: [u8; 48] = participant_pk_bytes
        .try_into()
        .map_err(|_| JsError::new("participant_pk_hex must be 48 bytes"))?;
    let participant_pk = PublicKey::from_bytes(&participant_pk_arr)
        .map_err(|e| JsError::new(&format!("participant PublicKey::from_bytes: {e:?}")))?;

    let payload = hex::decode(cb.payload_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("payload_hex decode: {e}")))?;

    let entropy_bytes = if cb.entropy_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(cb.entropy_hex.trim_start_matches("0x"))
            .map_err(|e| JsError::new(&format!("entropy_hex decode: {e}")))?
    };

    let params = CeremonyParams {
        start_block_height: c.start_block_height,
        ceremony_length_blocks: c.ceremony_length_blocks,
        min_participants: c.min_participants,
        max_voters: 20_000,
        vk_seed,
        label: None,
    };
    let contributor = CeremonyContributor::new(launcher_id, params);

    let state = CeremonyState {
        contribution_count: s.state.contribution_count,
        last_contribution_hash: last_hash,
        // D5 will extend JsSingleton state with finalized/vkHash/markerRoot.
        // For now contribute on a finalized ceremony will trap on the
        // puzzle's `assert state.finalized == false`, which is the
        // correct outcome — these defaults only describe the
        // pre-finalize case the dApp uses today.
        finalized: false,
        vk_hash: chia_protocol::Bytes32::default(),
        marker_root: chia_protocol::Bytes32::default(),
    };
    let contrib_params = ContributeParams {
        participant_pubkey: participant_pk.clone(),
        contribution_hash: contrib_hash,
        prev_contribution_hash: prev_hash,
        entropy_hex: chia_protocol::Bytes::new(entropy_bytes),
        payload,
    };

    let coin_spends = contributor
        .build_contribute_bundle(
            singleton_coin,
            lineage_proof,
            state,
            funder_coin_obj,
            funder_pk,
            contrib_params.clone(),
        )
        .map_err(|e| JsError::new(&format!("build_contribute_bundle: {e:?}")))?;

    let coin_spends_bytes = encode_coin_spends(&coin_spends)?;
    let sig_msg = contributor.contribution_signature_msg(&contrib_params);
    let marker_ph = ceremony_coin_marker_puzzle_hash(
        launcher_id,
        &participant_pk,
        contrib_hash,
        prev_hash,
    );
    // Marker coin id = sha256(parent || ph || amount). Parent is the
    // singleton coin id (the singleton emits the marker). Amount is 2
    // (even — singleton outer requires only one odd CreateCoin per
    // spend, claimed by the recreation; see contribute.rue).
    let marker_coin = Coin::new(singleton_coin.coin_id(), marker_ph, 2);
    let marker_id = marker_coin.coin_id();

    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "coinSpendsBytes": coin_spends_bytes,
        "signatureMsgHex": format!("0x{}", hex::encode(sig_msg)),
        "markerCoinIdHex": format!("0x{}", hex::encode(marker_id)),
    }))
    .map_err(|e| JsError::new(&format!("result encode: {e}")))?;
    Ok(result)
}

/// FN: finalize_ceremony_js
/// WHAT: Build the (unsigned) coin spends for the singleton's
///       finalize action — bakes (vk_hash, marker_root, vk_bytes)
///       into the singleton's curried state and emits a marker coin
///       hinted with launcher_id whose memos carry the full VK.
///       Permissionless on the singleton side: only the funder coin
///       requires Sage AGG_SIG_ME; no participant signing needed.
/// JS NAME: `finalizeCeremony`.
/// CONTRACT (JS):
///   ceremony   = { launcherIdHex, startBlockHeight, ceremonyLengthBlocks,
///                  minParticipants, vkSeedHex }
///   singleton  = { coin: JsCoinRecord, lineageProof: {...},
///                  state: { contributionCount, lastContributionHashHex,
///                           finalized?, vkHashHex?, markerRootHex? } }
///   funderCoin = JsCoinRecord
///   funderPkHex = 48-byte hex
///   inputs     = { vkHashHex, markerRootHex, vkHex }
/// RETURNS (Map → Object via dApp wrapper):
///   { coinSpendsBytes: Uint8Array, finalizedMarkerCoinIdHex: string }
#[wasm_bindgen(js_name = "finalizeCeremony")]
pub fn finalize_ceremony_js(
    ceremony: JsValue,
    singleton: JsValue,
    funder_coin: JsValue,
    funder_pk_hex: String,
    inputs: JsValue,
) -> Result<JsValue, JsError> {
    use chia_protocol::Coin;
    use chia_puzzle_types::{EveProof, LineageProof, Proof};
    use chip_voting_sdk::actors::ceremony::{
        CeremonyFinalizer, CeremonyParams, FinalizeParams,
    };
    use chip_voting_sdk::state::CeremonyState;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsCeremony {
        launcher_id_hex: String,
        start_block_height: u64,
        ceremony_length_blocks: u64,
        min_participants: u64,
        vk_seed_hex: String,
    }
    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "lowercase")]
    enum JsLineageProof {
        Eve {
            #[serde(rename = "parentParentCoinInfoHex")]
            parent_parent_coin_info_hex: String,
            #[serde(rename = "parentAmount")]
            parent_amount: u64,
        },
        Lineage {
            #[serde(rename = "parentParentCoinInfoHex")]
            parent_parent_coin_info_hex: String,
            #[serde(rename = "parentInnerPuzzleHashHex")]
            parent_inner_puzzle_hash_hex: String,
            #[serde(rename = "parentAmount")]
            parent_amount: u64,
        },
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsSingletonState {
        contribution_count: u64,
        last_contribution_hash_hex: String,
        #[serde(default)]
        finalized: bool,
        #[serde(default)]
        vk_hash_hex: String,
        #[serde(default)]
        marker_root_hex: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsSingleton {
        coin: JsCoinRecord,
        lineage_proof: JsLineageProof,
        state: JsSingletonState,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsFinalizeInputs {
        vk_hash_hex: String,
        marker_root_hex: String,
        vk_hex: String,
    }

    let c: JsCeremony = serde_wasm_bindgen::from_value(ceremony)
        .map_err(|e| JsError::new(&format!("ceremony decode: {e}")))?;
    let s: JsSingleton = serde_wasm_bindgen::from_value(singleton)
        .map_err(|e| JsError::new(&format!("singleton decode: {e}")))?;
    let fc: JsCoinRecord = serde_wasm_bindgen::from_value(funder_coin)
        .map_err(|e| JsError::new(&format!("funder_coin decode: {e}")))?;
    let inp: JsFinalizeInputs = serde_wasm_bindgen::from_value(inputs)
        .map_err(|e| JsError::new(&format!("finalize inputs decode: {e}")))?;

    let launcher_id = parse_hex32(&c.launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcherIdHex: {e:?}")))?;
    let vk_seed = parse_hex32(&c.vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vkSeedHex: {e:?}")))?;
    let last_hash = parse_hex32(&s.state.last_contribution_hash_hex)
        .map_err(|e| JsError::new(&format!("lastContributionHashHex: {e:?}")))?;
    let state_vk_hash = if s.state.vk_hash_hex.is_empty() {
        chia_protocol::Bytes32::default()
    } else {
        parse_hex32(&s.state.vk_hash_hex)
            .map_err(|e| JsError::new(&format!("state.vkHashHex: {e:?}")))?
    };
    let state_marker_root = if s.state.marker_root_hex.is_empty() {
        chia_protocol::Bytes32::default()
    } else {
        parse_hex32(&s.state.marker_root_hex)
            .map_err(|e| JsError::new(&format!("state.markerRootHex: {e:?}")))?
    };
    let in_vk_hash = parse_hex32(&inp.vk_hash_hex)
        .map_err(|e| JsError::new(&format!("inputs.vkHashHex: {e:?}")))?;
    let in_marker_root = parse_hex32(&inp.marker_root_hex)
        .map_err(|e| JsError::new(&format!("inputs.markerRootHex: {e:?}")))?;
    let in_vk_bytes = hex::decode(inp.vk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("inputs.vkHex decode: {e}")))?;

    let singleton_coin: Coin = coin_from_js(&s.coin)
        .map_err(|e| JsError::new(&format!("singleton coin: {e:?}")))?;
    let funder_coin_obj: Coin = coin_from_js(&fc)
        .map_err(|e| JsError::new(&format!("funder coin: {e:?}")))?;

    let lineage_proof = match s.lineage_proof {
        JsLineageProof::Eve {
            parent_parent_coin_info_hex,
            parent_amount,
        } => Proof::Eve(EveProof {
            parent_parent_coin_info: parse_hex32(&parent_parent_coin_info_hex)
                .map_err(|e| JsError::new(&format!("parentParentCoinInfoHex: {e:?}")))?,
            parent_amount,
        }),
        JsLineageProof::Lineage {
            parent_parent_coin_info_hex,
            parent_inner_puzzle_hash_hex,
            parent_amount,
        } => Proof::Lineage(LineageProof {
            parent_parent_coin_info: parse_hex32(&parent_parent_coin_info_hex)
                .map_err(|e| JsError::new(&format!("parentParentCoinInfoHex: {e:?}")))?,
            parent_inner_puzzle_hash: parse_hex32(&parent_inner_puzzle_hash_hex)
                .map_err(|e| JsError::new(&format!("parentInnerPuzzleHashHex: {e:?}")))?,
            parent_amount,
        }),
    };

    let funder_pk_bytes = hex::decode(funder_pk_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("funder_pk_hex decode: {e}")))?;
    let funder_pk_arr: [u8; 48] = funder_pk_bytes
        .try_into()
        .map_err(|_| JsError::new("funder_pk_hex must be 48 bytes"))?;
    let funder_pk = PublicKey::from_bytes(&funder_pk_arr)
        .map_err(|e| JsError::new(&format!("funder PublicKey::from_bytes: {e:?}")))?;

    let params = CeremonyParams {
        start_block_height: c.start_block_height,
        ceremony_length_blocks: c.ceremony_length_blocks,
        min_participants: c.min_participants,
        max_voters: 20_000,
        vk_seed,
        label: None,
    };
    let finalizer = CeremonyFinalizer::new(launcher_id, params);

    let state = CeremonyState {
        contribution_count: s.state.contribution_count,
        last_contribution_hash: last_hash,
        finalized: s.state.finalized,
        vk_hash: state_vk_hash,
        marker_root: state_marker_root,
    };
    let fparams = FinalizeParams {
        vk_hash: in_vk_hash,
        marker_root: in_marker_root,
        vk_bytes: in_vk_bytes,
    };

    let artifacts = finalizer
        .build_finalize_bundle(
            singleton_coin,
            lineage_proof,
            state,
            funder_coin_obj,
            funder_pk,
            fparams,
        )
        .map_err(|e| JsError::new(&format!("build_finalize_bundle: {e:?}")))?;

    let coin_spends_bytes = encode_coin_spends(&artifacts.coin_spends)?;

    // Predict the finalize marker ph the same way `finalize.rue` does:
    //   curry_tree_hash(CEREMONY_COIN_MOD_HASH, [launcher, vk_hash, marker_root]).
    let marker_ph = chip_voting_sdk::puzzles::curry_tree_hash(
        chip_voting_sdk::puzzles::PuzzleHashes::ceremony_coin_marker(),
        &[
            chip_voting_sdk::puzzles::hash_atom_b32(&launcher_id),
            chip_voting_sdk::puzzles::hash_atom_b32(&in_vk_hash),
            chip_voting_sdk::puzzles::hash_atom_b32(&in_marker_root),
        ],
    );
    let marker_coin = Coin::new(singleton_coin.coin_id(), marker_ph, 2);
    let marker_id = marker_coin.coin_id();

    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "coinSpendsBytes": coin_spends_bytes,
        "finalizedMarkerCoinIdHex": format!("0x{}", hex::encode(marker_id)),
        "voucherCoinIdHex": format!("0x{}", hex::encode(artifacts.voucher_coin_id)),
        "voucherPuzzleHashHex": format!("0x{}", hex::encode(artifacts.voucher_puzzle_hash)),
    }))
    .map_err(|e| JsError::new(&format!("finalize result encode: {e}")))?;
    Ok(result)
}

/// FN: merkle_root_of_sorted_coin_ids_js
/// WHAT: Compute the SHA-256 binary-tree merkle root over the sorted
///       set of contribution marker coin ids — used by the finalize
///       action to commit to the contribution set on-chain.
/// JS NAME: `merkleRootOfSortedCoinIds`.
/// CONTRACT: `idsHexConcat` is one or more 32-byte hex coin ids
///       concatenated (each 64 hex chars, no `0x` prefix or with).
///       Order in the input doesn't matter — the helper sorts
///       ascending internally.
#[wasm_bindgen(js_name = "merkleRootOfSortedCoinIds")]
pub fn merkle_root_of_sorted_coin_ids_js(
    ids_hex_concat: String,
) -> Result<String, JsError> {
    let trimmed = ids_hex_concat.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| JsError::new(&format!("ids_hex_concat decode: {e}")))?;
    if bytes.len() % 32 != 0 {
        return Err(JsError::new(&format!(
            "ids_hex_concat must be a multiple of 32 bytes (got {})",
            bytes.len()
        )));
    }
    let ids: Vec<chia_protocol::Bytes32> = bytes
        .chunks_exact(32)
        .map(|c| chia_protocol::Bytes32::try_from(c).unwrap())
        .collect();
    let root = chip_voting_sdk::merkle::merkle_root_of_sorted_coin_ids(&ids);
    Ok(format!("0x{}", hex::encode(root)))
}

/// FN: merkle_proof_for_option_js
/// WHAT: Index-aware merkle inclusion proof generator for the M5r-merkle
///       Mode2Restricted gate in `puzzles/voting_coin/update_vote.rue`.
///       Bridges `chip_voting_sdk::vote_mode::BallotVoteMode::merkle_proof_for_option`
///       so the dApp can build the proof a voter must supply alongside
///       their `vote_data` when the ballot is locked-Restricted.
/// JS NAME: `merkleProofForOption`.
/// CONTRACT (JS shape returned):
///   { leafIndex: number, proofHex: string[] }
/// `optionsHexConcat` is one or more 32-byte hex option hashes
/// concatenated (each 64 hex chars). The wrapper sorts them ascending
/// internally to match `merkle_root_of_sorted_coin_ids`. `targetOptionHex`
/// must be one of the entries — returns null if not found.
#[wasm_bindgen(js_name = "merkleProofForOption")]
pub fn merkle_proof_for_option_js(
    options_hex_concat: String,
    target_option_hex: String,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::vote_mode::BallotVoteMode;

    let trimmed = options_hex_concat.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| JsError::new(&format!("options_hex_concat decode: {e}")))?;
    if bytes.len() % 32 != 0 {
        return Err(JsError::new(&format!(
            "options_hex_concat must be a multiple of 32 bytes (got {})",
            bytes.len()
        )));
    }
    let options: Vec<chia_protocol::Bytes32> = bytes
        .chunks_exact(32)
        .map(|c| chia_protocol::Bytes32::try_from(c).unwrap())
        .collect();
    let target = parse_hex32(&target_option_hex)
        .map_err(|e| JsError::new(&format!("target_option_hex: {e}")))?;
    let mode = BallotVoteMode::Restricted { options };
    match mode.merkle_proof_for_option(target) {
        None => Ok(JsValue::NULL),
        Some((leaf_index, proof)) => {
            let proof_hex: Vec<String> =
                proof.iter().map(|b| format!("0x{}", hex::encode(b))).collect();
            serde_wasm_bindgen::to_value(&serde_json::json!({
                "leafIndex": leaf_index,
                "proofHex": proof_hex,
            }))
            .map_err(|e| JsError::new(&format!("encode merkle proof: {e}")))
        }
    }
}

/// FN: find_current_ceremony_singleton_js
/// WHAT: Chain-walk the ceremony singleton lineage and return the
///       unspent tip's coin record + lineage proof + curried state.
/// JS NAME: `findCurrentCeremonySingleton`.
/// CONTRACT (JS shape returned):
///   {
///     coin: { parentCoinInfoHex, puzzleHashHex, amount },
///     lineageProof: { kind: "eve" | "lineage", ... },
///     state: { contributionCount: number, lastContributionHashHex: string }
///   }
/// USE: dApp calls this just before invoking `contributeToCeremony` so
///      it can supply the singleton tip + state + lineage proof.
#[wasm_bindgen(js_name = "findCurrentCeremonySingleton")]
pub async fn find_current_ceremony_singleton_js(
    backend: JsChainBackend,
    launcher_id_hex: String,
    vk_seed_hex: String,
) -> Result<String, JsError> {
    use chia_puzzle_types::Proof;
    use chip_voting_sdk::actors::ceremony::CeremonyReader;

    let launcher_id = parse_hex32(&launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcher_id_hex: {e}")))?;
    let vk_seed = parse_hex32(&vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vk_seed_hex: {e}")))?;
    let chain = JsChainReader::new(backend);
    let (coin, proof, state) =
        CeremonyReader::find_current_singleton(&chain, launcher_id, vk_seed)
            .await
            .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;

    let proof_json = match proof {
        Proof::Eve(p) => serde_json::json!({
            "kind": "eve",
            "parentParentCoinInfoHex": format!("0x{}", hex::encode(p.parent_parent_coin_info)),
            "parentAmount": p.parent_amount,
        }),
        Proof::Lineage(p) => serde_json::json!({
            "kind": "lineage",
            "parentParentCoinInfoHex": format!("0x{}", hex::encode(p.parent_parent_coin_info)),
            "parentInnerPuzzleHashHex": format!("0x{}", hex::encode(p.parent_inner_puzzle_hash)),
            "parentAmount": p.parent_amount,
        }),
    };

    let coin_id = coin.coin_id();
    serde_json::to_string(&serde_json::json!({
        "launcherIdHex": format!("0x{}", hex::encode(launcher_id)),
        "coinIdHex": format!("0x{}", hex::encode(coin_id)),
        "coin": {
            "parentCoinInfoHex": format!("0x{}", hex::encode(coin.parent_coin_info)),
            "puzzleHashHex": format!("0x{}", hex::encode(coin.puzzle_hash)),
            "amount": coin.amount,
        },
        "lineageProof": proof_json,
        "state": {
            "contributionCount": state.contribution_count,
            "lastContributionHashHex": format!("0x{}", hex::encode(state.last_contribution_hash)),
            "finalized": state.finalized,
            "vkHashHex": format!("0x{}", hex::encode(state.vk_hash)),
            "markerRootHex": format!("0x{}", hex::encode(state.marker_root)),
        },
    }))
    .map_err(|e| JsError::new(&format!("encode singleton tip: {e}")))
}

/// FN: find_ceremony_voucher_coin_js
/// WHAT: locate the unspent voucher coin spawned by a finalized
///       ceremony. Returns the coin's parent_coin_info + amount so
///       the dApp can pass them into `deployElectionBundle` for the
///       V7 linked-deploy path.
/// JS NAME: `findCeremonyVoucherCoin`.
/// CONTRACT (JS shape returned):
///   { parentCoinIdHex: string, amount: number } | null
/// `null` means no unspent voucher exists at the predicted puzzle
/// hash — either the ceremony hasn't been finalized yet, or every
/// historical voucher has been consumed without re-creation (which
/// can't happen with the V1 voucher puzzle, but the dApp should
/// still handle the null case defensively).
#[wasm_bindgen(js_name = "findCeremonyVoucherCoin")]
pub async fn find_ceremony_voucher_coin_js(
    backend: JsChainBackend,
    launcher_id_hex: String,
    vk_hash_hex: String,
    max_voters: u64,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::ceremony::CeremonyReader;

    let launcher_id = parse_hex32(&launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcher_id_hex: {e}")))?;
    let vk_hash = parse_hex32(&vk_hash_hex)
        .map_err(|e| JsError::new(&format!("vk_hash_hex: {e}")))?;
    let chain = JsChainReader::new(backend);

    let coin_opt = CeremonyReader::find_voucher_coin(&chain, launcher_id, vk_hash, max_voters)
        .await
        .map_err(|e| JsError::new(&format!("find_voucher_coin: {e:?}")))?;

    match coin_opt {
        None => Ok(JsValue::NULL),
        Some(coin) => serde_wasm_bindgen::to_value(&serde_json::json!({
            "parentCoinIdHex": format!("0x{}", hex::encode(coin.parent_coin_info)),
            "amount": coin.amount,
        }))
        .map_err(|e| JsError::new(&format!("encode voucher coin: {e}"))),
    }
}

/// FN: recover_ceremony_bootstrap_js
/// WHAT: Cross-browser bootstrap recovery — fetches the launcher
///       coin's `key_value_list` from chain and decodes it as a
///       `CeremonyLauncherMemo`. Lets a dApp running on a fresh
///       browser populate the /ceremony page from the URL alone.
/// JS NAME: `recoverCeremonyBootstrap`.
/// RETURNS: JSON string `{startBlockHeight, ceremonyLengthBlocks,
///   minParticipants, vkSeedHex, label}` or `null` if the launcher
///   has not been spent / the memo is missing or doesn't carry the
///   schema tag (legacy ceremonies deployed before D6).
#[wasm_bindgen(js_name = "recoverCeremonyBootstrap")]
pub async fn recover_ceremony_bootstrap_js(
    backend: JsChainBackend,
    launcher_id_hex: String,
) -> Result<JsValue, JsError> {
    let launcher_id = parse_hex32(&launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcher_id_hex: {e}")))?;
    let chain = JsChainReader::new(backend);
    let memo =
        chip_voting_sdk::actors::ceremony::read_ceremony_launcher_memo(&chain, launcher_id)
            .await
            .map_err(|e| JsError::new(&format!("read_ceremony_launcher_memo: {e:?}")))?;
    let memo = match memo {
        Some(m) => m,
        None => return Ok(JsValue::NULL),
    };
    // `label_bytes` is empty for unset labels; surface as `null` to JS.
    let label_str = if memo.label_bytes.as_ref().is_empty() {
        serde_json::Value::Null
    } else {
        match std::str::from_utf8(memo.label_bytes.as_ref()) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::Value::Null,
        }
    };
    let json = serde_json::json!({
        "startBlockHeight": memo.start_block_height,
        "ceremonyLengthBlocks": memo.ceremony_length_blocks,
        "minParticipants": memo.min_participants,
        "maxVoters": memo.max_voters,
        "vkSeedHex": format!("0x{}", hex::encode(memo.vk_seed)),
        "label": label_str,
    });
    let s = serde_json::to_string(&json)
        .map_err(|e| JsError::new(&format!("encode ceremony bootstrap: {e}")))?;
    Ok(JsValue::from_str(&s))
}

/// FN: list_ceremony_contributions_js
/// WHAT: Chain-walk the Ceremony Singleton lineage and return every
///       accepted contribution as a JSON array of records. Mirrors
///       `listBallots`'s shape: takes a JsChainBackend + launcher id,
///       returns the JSON-encoded `Vec<ContributionRecord>` (with each
///       BLS pubkey + Bytes32 + payload field hex-encoded for JS).
/// JS NAME: `listCeremonyContributions`.
/// DOWNSTREAM: dApp passes the parsed array back into
///       `validateCeremonyContributions` / `deriveVkFromCeremony`.
#[wasm_bindgen(js_name = "listCeremonyContributions")]
pub async fn list_ceremony_contributions_js(
    backend: JsChainBackend,
    launcher_id_hex: String,
) -> Result<String, JsError> {
    use chip_voting_sdk::actors::ceremony::CeremonyReader;

    let launcher_id = parse_hex32(&launcher_id_hex)
        .map_err(|e| JsError::new(&format!("launcher_id_hex: {e}")))?;
    let chain = JsChainReader::new(backend);
    let records = CeremonyReader::list_contributions_via_chain(&chain, launcher_id)
        .await
        .map_err(|e| JsError::new(&format!("list_contributions_via_chain: {e:?}")))?;

    // Hand-encode JSON (PublicKey lacks Serialize).
    let json_records: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "participantPkHex": format!("0x{}", hex::encode(r.participant_pubkey.to_bytes())),
                "contributionHashHex": format!("0x{}", hex::encode(r.contribution_hash)),
                "prevContributionHashHex": format!("0x{}", hex::encode(r.prev_contribution_hash)),
                "coinIdHex": format!("0x{}", hex::encode(r.coin_id)),
                "blockHeight": r.block_height,
                "entropyHex": format!("0x{}", hex::encode(r.entropy_hex.as_ref())),
                "payloadHex": format!("0x{}", hex::encode(&r.payload)),
            })
        })
        .collect();
    serde_json::to_string(&json_records)
        .map_err(|e| JsError::new(&format!("encode contributions: {e}")))
}

/// FN: validate_ceremony_contributions_js
/// WHAT: Run the cheap precondition gates on a JS-collected list of
///       contribution records — `validate_lineage` + `check_threshold`
///       from `CeremonyReader`. Lets the dApp UI surface a meaningful
///       "ceremony incomplete / lineage broken" error BEFORE it asks
///       wasm to do expensive VK derivation.
/// JS NAME: `validateCeremonyContributions`.
/// CONTRACT (JS shape):
///   contributions = [
///     {
///       participantPkHex: string,   // 48-byte BLS G1 hex
///       contributionHashHex: string,
///       prevContributionHashHex: string,
///       coinIdHex: string,
///       blockHeight: number,
///     },
///     ...
///   ]                                // chain-ordered, oldest first
///   vkSeedHex: string                // 32-byte hex
///   minParticipants: number
/// RETURNS: `{ ok: true, count: <records.length> }` on pass, or a
///   `JsError` with the exact rule violation on fail.
#[wasm_bindgen(js_name = "validateCeremonyContributions")]
pub fn validate_ceremony_contributions_js(
    contributions: JsValue,
    vk_seed_hex: &str,
    min_participants: u64,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::ceremony::{CeremonyReader, ContributionRecord};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsContributionRecord {
        participant_pk_hex: String,
        contribution_hash_hex: String,
        prev_contribution_hash_hex: String,
        coin_id_hex: String,
        block_height: u32,
        #[serde(default)]
        entropy_hex: String,
    }

    let records_js: Vec<JsContributionRecord> = serde_wasm_bindgen::from_value(contributions)
        .map_err(|e| JsError::new(&format!("contributions decode: {e}")))?;

    let mut records = Vec::with_capacity(records_js.len());
    for (idx, r) in records_js.into_iter().enumerate() {
        let pk_bytes = hex::decode(r.participant_pk_hex.trim_start_matches("0x"))
            .map_err(|e| JsError::new(&format!("contributions[{idx}].participantPkHex: {e}")))?;
        let pk_arr: [u8; 48] = pk_bytes.try_into().map_err(|_| {
            JsError::new(&format!(
                "contributions[{idx}].participantPkHex must be 48 bytes"
            ))
        })?;
        let pk = PublicKey::from_bytes(&pk_arr)
            .map_err(|e| JsError::new(&format!("contributions[{idx}] PublicKey: {e:?}")))?;
        let contribution_hash = parse_hex32(&r.contribution_hash_hex)
            .map_err(|e| JsError::new(&format!("contributions[{idx}].contributionHashHex: {e:?}")))?;
        let prev_contribution_hash = parse_hex32(&r.prev_contribution_hash_hex).map_err(|e| {
            JsError::new(&format!(
                "contributions[{idx}].prevContributionHashHex: {e:?}"
            ))
        })?;
        let coin_id = parse_hex32(&r.coin_id_hex)
            .map_err(|e| JsError::new(&format!("contributions[{idx}].coinIdHex: {e:?}")))?;
        let entropy_bytes = if r.entropy_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(r.entropy_hex.trim_start_matches("0x"))
                .map_err(|e| JsError::new(&format!("contributions[{idx}].entropyHex: {e:?}")))?
        };
        records.push(ContributionRecord {
            participant_pubkey: pk,
            contribution_hash,
            prev_contribution_hash,
            coin_id,
            block_height: r.block_height,
            entropy_hex: chia_protocol::Bytes::new(entropy_bytes),
            payload: vec![],
        });
    }

    let vk_seed = parse_hex32(vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vk_seed_hex: {e:?}")))?;

    CeremonyReader::check_threshold(&records, vk_seed, min_participants)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "ok": true,
        "count": records.len() as u64,
    }))
    .map_err(|e| JsError::new(&format!("result encode: {e}")))?;
    Ok(result)
}

/// FN: derive_vk_from_ceremony_js
/// WHAT: Phase-5-pending VK derivation. Currently runs the gates and
///       surfaces the bridge-pending message. Wired into the dApp UI
///       so "Create election" stays disabled until either the gates
///       pass AND the Phase 5 bridge ships.
/// JS NAME: `deriveVkFromCeremony`.
/// CONTRACT: same `contributions` shape as
///   `validateCeremonyContributions`, plus `vkSeedHex` +
///   `minParticipants`. Each contribution should also carry
///   `payloadHex` (Groth16 contribution bytes recovered from
///   `puzzle_and_solution`); the gate-only check ignores it for now.
#[wasm_bindgen(js_name = "deriveVkFromCeremony")]
pub fn derive_vk_from_ceremony_js(
    contributions: JsValue,
    vk_seed_hex: &str,
    min_participants: u64,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::ceremony::{CeremonyReader, ContributionRecord};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JsContributionRecord {
        participant_pk_hex: String,
        contribution_hash_hex: String,
        prev_contribution_hash_hex: String,
        coin_id_hex: String,
        block_height: u32,
        #[serde(default)]
        entropy_hex: String,
        #[serde(default)]
        payload_hex: String,
    }

    let records_js: Vec<JsContributionRecord> = serde_wasm_bindgen::from_value(contributions)
        .map_err(|e| JsError::new(&format!("contributions decode: {e}")))?;

    let mut records = Vec::with_capacity(records_js.len());
    for (idx, r) in records_js.into_iter().enumerate() {
        let pk_bytes = hex::decode(r.participant_pk_hex.trim_start_matches("0x"))
            .map_err(|e| JsError::new(&format!("contributions[{idx}].participantPkHex: {e}")))?;
        let pk_arr: [u8; 48] = pk_bytes.try_into().map_err(|_| {
            JsError::new(&format!(
                "contributions[{idx}].participantPkHex must be 48 bytes"
            ))
        })?;
        let pk = PublicKey::from_bytes(&pk_arr)
            .map_err(|e| JsError::new(&format!("contributions[{idx}] PublicKey: {e:?}")))?;
        let contribution_hash = parse_hex32(&r.contribution_hash_hex)
            .map_err(|e| JsError::new(&format!("contributions[{idx}].contributionHashHex: {e:?}")))?;
        let prev_contribution_hash = parse_hex32(&r.prev_contribution_hash_hex).map_err(|e| {
            JsError::new(&format!(
                "contributions[{idx}].prevContributionHashHex: {e:?}"
            ))
        })?;
        let coin_id = parse_hex32(&r.coin_id_hex)
            .map_err(|e| JsError::new(&format!("contributions[{idx}].coinIdHex: {e:?}")))?;
        let payload = if r.payload_hex.is_empty() {
            vec![]
        } else {
            hex::decode(r.payload_hex.trim_start_matches("0x"))
                .map_err(|e| JsError::new(&format!("contributions[{idx}].payloadHex: {e}")))?
        };
        let entropy_bytes = if r.entropy_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(r.entropy_hex.trim_start_matches("0x"))
                .map_err(|e| JsError::new(&format!("contributions[{idx}].entropyHex: {e:?}")))?
        };
        records.push(ContributionRecord {
            participant_pubkey: pk,
            contribution_hash,
            prev_contribution_hash,
            coin_id,
            block_height: r.block_height,
            entropy_hex: chia_protocol::Bytes::new(entropy_bytes),
            payload,
        });
    }

    let vk_seed = parse_hex32(vk_seed_hex)
        .map_err(|e| JsError::new(&format!("vk_seed_hex: {e:?}")))?;

    let vk = CeremonyReader::derive_vk(&records, vk_seed, min_participants)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    serde_wasm_bindgen::to_value(&serde_json::json!({
        "rawBytes": vk.raw_bytes,
    }))
    .map_err(|e| JsError::new(&format!("vk encode: {e}")))
}

// ============================================================================
// SECTION 7 — Pure puzzle-hash helpers
// ============================================================================

/// FN: sign_participant_unsafe_js
/// WHAT: BLS-sign an UNAUGMENTED 32-byte message with a JS-supplied
///       32-byte secret-key SEED. Mirrors `chia_bls::sign` with no
///       augmentation prefix.
/// USE: ceremony participants create a fresh BLS keypair locally
///      (not from Sage) and need to satisfy the contribute action's
///      AGG_SIG_UNSAFE condition. The dApp computes
///      `ceremony_contribution_msg(launcher, contrib_hash, prev_hash)`
///      and calls this to produce the 96-byte G2 signature.
/// JS NAME: `signParticipantUnsafe`.
/// SK DERIVATION: input 32 bytes are passed through
///   `SecretKey::from_seed` (HKDF-Mod-R per IETF BLS draft v4) so
///   any 32-byte random value lands in-group. `from_bytes` would
///   reject ~half of `crypto.getRandomValues(32)` outputs because
///   they are ≥ the BLS12-381 scalar order. MUST match the
///   derivation in `publicKeyFromSecretKeyBytes`.
/// CONTRACT:
///   * `secret_key_hex` — 32-byte hex (with or without `0x`).
///   * `message_hex`    — 32-byte hex (the digest to sign).
///   * RETURNS: `0x`-prefixed 96-byte hex G2 signature.
#[wasm_bindgen(js_name = "signParticipantUnsafe")]
pub fn sign_participant_unsafe_js(
    secret_key_hex: &str,
    message_hex: &str,
) -> Result<String, JsError> {
    let sk_bytes = hex::decode(secret_key_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("secret_key_hex decode: {e}")))?;
    if sk_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "secret_key_hex must be 32 bytes (got {})",
            sk_bytes.len()
        )));
    }
    let sk = SecretKey::from_seed(&sk_bytes);
    let msg_bytes = hex::decode(message_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("message_hex decode: {e}")))?;
    if msg_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "message_hex must be 32 bytes (got {})",
            msg_bytes.len()
        )));
    }
    let sig = chia_bls::sign(&sk, &msg_bytes);
    Ok(format!("0x{}", hex::encode(sig.to_bytes())))
}

/// FN: public_key_from_secret_key_bytes_js
/// WHAT: Derive the BLS G1 public key from a 32-byte secret-key SEED.
/// USE: ceremony participants generate a fresh client-side keypair
///      via crypto.getRandomValues(32 bytes), then need the matching
///      pk to populate the contribute action's curry args (the
///      marker CeremonyCoin's puzzle hash binds participant_pubkey).
/// JS NAME: `publicKeyFromSecretKeyBytes`.
/// SK DERIVATION: see `signParticipantUnsafe` — both use
///   `SecretKey::from_seed` so the seed→pk and seed→sig paths
///   share the same in-group SK.
/// CONTRACT:
///   * `secret_key_hex` — 32-byte hex (with or without `0x`).
///   * RETURNS: `0x`-prefixed 48-byte hex G1 pubkey.
#[wasm_bindgen(js_name = "publicKeyFromSecretKeyBytes")]
pub fn public_key_from_secret_key_bytes_js(
    secret_key_hex: &str,
) -> Result<String, JsError> {
    let sk_bytes = hex::decode(secret_key_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("secret_key_hex decode: {e}")))?;
    if sk_bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "secret_key_hex must be 32 bytes (got {})",
            sk_bytes.len()
        )));
    }
    let sk = SecretKey::from_seed(&sk_bytes);
    let pk = sk.public_key();
    Ok(format!("0x{}", hex::encode(pk.to_bytes())))
}

/// FN: aggregate_signatures_g2_js
/// WHAT: Aggregate N BLS G2 signatures into a single 96-byte
///       signature. Mirrors `chia_bls::aggregate`.
/// USE: combine the funder's Sage-signed AGG_SIG_ME signature with
///      the participant's locally-signed AGG_SIG_UNSAFE signature
///      into the final bundle signature. Standard BLS aggregate is
///      addition in G2; the order of inputs does not matter.
/// JS NAME: `aggregateSignaturesG2`.
/// CONTRACT:
///   * `sigs_concat_hex` — concatenation of N×96 byte hex sigs
///     (with or without `0x`). Empty input → BLS identity (zero
///     signature, decoded as `Signature::default()`).
///   * RETURNS: `0x`-prefixed 96-byte hex aggregate signature.
#[wasm_bindgen(js_name = "aggregateSignaturesG2")]
pub fn aggregate_signatures_g2_js(
    sigs_concat_hex: &str,
) -> Result<String, JsError> {
    use chia_bls::Signature;
    let bytes = hex::decode(sigs_concat_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("sigs_concat_hex decode: {e}")))?;
    if bytes.len() % 96 != 0 {
        return Err(JsError::new(&format!(
            "sigs_concat_hex must be a multiple of 96 bytes (got {})",
            bytes.len()
        )));
    }
    let mut agg = Signature::default();
    for chunk in bytes.chunks_exact(96) {
        let arr: [u8; 96] = chunk
            .try_into()
            .expect("chunks_exact(96) yields 96-byte slices");
        let sig = Signature::from_bytes(&arr)
            .map_err(|e| JsError::new(&format!("Signature::from_bytes: {e:?}")))?;
        agg += &sig;
    }
    Ok(format!("0x{}", hex::encode(agg.to_bytes())))
}

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
/// which takes `(cat_tail_hash, &voter_pubkey, election_launcher_id,
/// locked_weight)`. SEC-F2: `locked_weight` is bound into the
/// registration state, so the predicted hash is taken with the
/// election's `collateral_amount` (the weight the coin must hold).
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
        chip_voting_sdk::puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail,
            &pk,
            election_id,
            cfg.collateral_amount,
        );
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
// SECTION 8b — Voter / network helpers (param structs + key parsing)
// ============================================================================
//
// Wire-format mirrors of [`chip_voting_sdk::actors::voter::CastVoteParams`]
// and [`UpdateVoteParams`] with all `Bytes32` fields encoded as bare
// (or `0x`-prefixed) 64-char hex strings. JSON keys are camelCase per
// the rest of this crate's JS surface.

/// JS-side input mirror of [`chip_voting_sdk::actors::voter::CastVoteParams`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCastVoteParams {
    pub ballot_launcher_id_hex: String,
    pub vote_data_hex: String,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot_hex: String,
    pub registration_vote_weight_snapshot: u64,
    pub voting_coin_amount: u64,
    /// M5r-merkle-e: per-ballot vote-mode commitment.
    /// None / empty / "0x00…00" = Mode1Free.
    #[serde(default)]
    pub vote_options_root_hex: Option<String>,
    /// M5r-merkle-e: leaf index of vote_data in the sorted-options
    /// merkle tree (Mode2Restricted only).
    #[serde(default)]
    pub vote_option_leaf_index: Option<u64>,
    /// M5r-merkle-e: HashCons sibling proof (level-order, leaf→root).
    /// Each entry is 32-byte hex. Empty / None for Mode1Free.
    #[serde(default)]
    pub vote_option_proof_hex: Option<Vec<String>>,
}

impl WasmCastVoteParams {
    fn into_sdk(self) -> VotingResult<chip_voting_sdk::actors::voter::CastVoteParams> {
        let vote_options_root = match self
            .vote_options_root_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => parse_hex32(s)?,
            None => chia_protocol::Bytes32::default(),
        };
        let vote_option_proof = match (self.vote_option_proof_hex, self.vote_option_leaf_index) {
            (Some(siblings), Some(idx)) if !siblings.is_empty() => {
                let mut proof: Vec<chia_protocol::Bytes32> = Vec::with_capacity(siblings.len());
                for s in siblings {
                    proof.push(parse_hex32(&s)?);
                }
                Some((idx as usize, proof))
            }
            _ => None,
        };
        Ok(chip_voting_sdk::actors::voter::CastVoteParams {
            ballot_launcher_id: parse_hex32(&self.ballot_launcher_id_hex)?,
            vote_data: parse_hex32(&self.vote_data_hex)?,
            vote_close_height: self.vote_close_height,
            vote_threshold_num: self.vote_threshold_num,
            vote_threshold_den: self.vote_threshold_den,
            registration_merkle_root_snapshot: parse_hex32(
                &self.registration_merkle_root_snapshot_hex,
            )?,
            registration_vote_weight_snapshot: self.registration_vote_weight_snapshot,
            voting_coin_amount: self.voting_coin_amount,
            vote_options_root,
            vote_option_proof,
        })
    }
}

/// JS-side input mirror of [`chip_voting_sdk::actors::voter::UpdateVoteParams`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmUpdateVoteParams {
    pub voting_coin_id_hex: String,
    pub old_vote_data_hex: String,
    pub new_vote_data_hex: String,
    pub registration_coin_id_hex: String,
    pub ballot_launcher_id_hex: String,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot_hex: String,
    pub registration_vote_weight_snapshot: u64,
    /// M5r-merkle-c: the Ballot Coin's curried `vote_options_root`.
    /// Empty / None / "0x00…00" = Mode1Free; any other 32-byte hex
    /// = Mode2Restricted (caller MUST also supply
    /// `voteOptionLeafIndex` + `voteOptionProofHex`).
    #[serde(default)]
    pub vote_options_root_hex: Option<String>,
    /// M5r-merkle-c: leaf index of `new_vote_data` in the sorted-options
    /// merkle tree. Required for Mode2Restricted; defaulted to 0 for
    /// Mode1Free (the puzzle's gate short-circuits).
    #[serde(default)]
    pub vote_option_leaf_index: Option<u64>,
    /// M5r-merkle-c: HashCons sibling proof (level-order, leaf→root).
    /// Each entry is 32-byte hex. Empty / None for Mode1Free.
    #[serde(default)]
    pub vote_option_proof_hex: Option<Vec<String>>,
}

impl WasmUpdateVoteParams {
    fn into_sdk(self) -> VotingResult<chip_voting_sdk::actors::voter::UpdateVoteParams> {
        let vote_options_root = match self
            .vote_options_root_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => parse_hex32(s)?,
            None => chia_protocol::Bytes32::default(),
        };
        let vote_option_proof = match (self.vote_option_proof_hex, self.vote_option_leaf_index) {
            (Some(siblings), Some(idx)) if !siblings.is_empty() => {
                let mut proof: Vec<chia_protocol::Bytes32> = Vec::with_capacity(siblings.len());
                for s in siblings {
                    proof.push(parse_hex32(&s)?);
                }
                Some((idx as usize, proof))
            }
            _ => None,
        };
        Ok(chip_voting_sdk::actors::voter::UpdateVoteParams {
            voting_coin_id: parse_hex32(&self.voting_coin_id_hex)?,
            old_vote_data: parse_hex32(&self.old_vote_data_hex)?,
            new_vote_data: parse_hex32(&self.new_vote_data_hex)?,
            registration_coin_id: parse_hex32(&self.registration_coin_id_hex)?,
            ballot_launcher_id: parse_hex32(&self.ballot_launcher_id_hex)?,
            vote_close_height: self.vote_close_height,
            vote_threshold_num: self.vote_threshold_num,
            vote_threshold_den: self.vote_threshold_den,
            registration_merkle_root_snapshot: parse_hex32(
                &self.registration_merkle_root_snapshot_hex,
            )?,
            registration_vote_weight_snapshot: self.registration_vote_weight_snapshot,
            vote_options_root,
            vote_option_proof,
        })
    }
}

/// JS-side input mirror of [`chip_voting_sdk::actors::ballot::CreateBallotParams`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCreateBallotParams {
    pub ballot_seed_hex: String,
    pub vote_close_height: u64,
    pub outcome_domain_hash_hex: String,
    /// M10: optional 32-byte hex of the per-ballot vote-mode commitment.
    /// `None` / empty / `"00…00"` = Mode1Free (any 32-byte vote_data
    /// accepted). Otherwise = sorted-options merkle root the Ballot
    /// Coin's oracle will commit to (Mode2Restricted).
    #[serde(default)]
    pub vote_options_root_hex: Option<String>,
}

impl WasmCreateBallotParams {
    fn into_sdk(self) -> VotingResult<chip_voting_sdk::actors::ballot::CreateBallotParams> {
        let vote_options_root = match self
            .vote_options_root_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => parse_hex32(s)?,
            None => chia_protocol::Bytes32::default(),
        };
        Ok(chip_voting_sdk::actors::ballot::CreateBallotParams {
            ballot_seed: parse_hex32(&self.ballot_seed_hex)?,
            vote_close_height: self.vote_close_height,
            outcome_domain_hash: parse_hex32(&self.outcome_domain_hash_hex)?,
            vote_options_root,
        })
    }
}

/// JS-side input mirror of [`chip_voting_sdk::actors::ballot::LaunchBallotParams`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmLaunchBallotParams {
    pub vote_close_height: u64,
    pub outcome_domain_hash_hex: String,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    /// M10: optional 32-byte hex of the per-ballot vote-mode commitment.
    /// MUST equal the value passed in the matching create_ballot call
    /// (the SDK enforces this — predicted ballot puzzle hash will
    /// mismatch on chain otherwise).
    #[serde(default)]
    pub vote_options_root_hex: Option<String>,
}

impl WasmLaunchBallotParams {
    fn into_sdk(self) -> VotingResult<chip_voting_sdk::actors::ballot::LaunchBallotParams> {
        let vote_options_root = match self
            .vote_options_root_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => parse_hex32(s)?,
            None => chia_protocol::Bytes32::default(),
        };
        Ok(chip_voting_sdk::actors::ballot::LaunchBallotParams {
            vote_close_height: self.vote_close_height,
            outcome_domain_hash: parse_hex32(&self.outcome_domain_hash_hex)?,
            vote_threshold_num: self.vote_threshold_num,
            vote_threshold_den: self.vote_threshold_den,
            vote_options_root,
        })
    }
}

/// JS-side input for `buildBallotFinalizeBundle`. Mirrors the
/// non-list / non-PK fields of
/// [`chip_voting_sdk::actors::aggregator::BuildFinalizeForBallotParams`].
/// `votes` and `proving_key` are passed as separate wasm args (a JSON
/// array of [`VoteRecordWire`](chip_voting_sdk::state::VoteRecordWire)
/// and arkworks-compressed PK bytes, respectively).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmFinalizeParams {
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot_hex: String,
    pub registration_vote_weight_snapshot: u64,
}

/// Lift a [`VoteRecordWire`](chip_voting_sdk::state::VoteRecordWire)
/// (from `collectVotesForBallot`) back into a typed
/// [`VoteRecord`](chip_voting_sdk::state::VoteRecord) — the inverse
/// direction the SDK doesn't expose (it has only
/// `From<&VoteRecord> for VoteRecordWire`).
fn vote_record_wire_to_sdk(
    w: &chip_voting_sdk::state::VoteRecordWire,
) -> VotingResult<chip_voting_sdk::state::VoteRecord> {
    Ok(chip_voting_sdk::state::VoteRecord {
        voter_pubkey: parse_pubkey_hex(&w.voter_pubkey_hex, "voter_pubkey_hex")?,
        vote_data: parse_hex32(&w.vote_data_hex)?,
        vote_signature_hex: w.vote_signature_hex.clone(),
        registration_coin_id: parse_hex32(&w.registration_coin_id_hex)?,
        ballot_launcher_id: parse_hex32(&w.ballot_launcher_id_hex)?,
        voting_coin_id: parse_hex32(&w.voting_coin_id_hex)?,
    })
}

/// JSON-friendly result of a `createBallotBundle` call. Mirrors
/// [`chip_voting_sdk::actors::ballot::CreatedBallot`] with hex
/// strings for the on-chain ids and the SpendBundle as Streamable bytes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmCreatedBallot {
    pub ballot_launcher_id_hex: String,
    pub ballot_coin_id_hex: String,
    pub spend_bundle_hex: String,
}

/// JSON-friendly result of a `launchBallotBundle` call. Mirrors
/// [`chip_voting_sdk::actors::ballot::LaunchedBallot`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmLaunchedBallot {
    pub ballot_launcher_id_hex: String,
    pub eve_ballot_coin_id_hex: String,
    pub eve_ballot_puzzle_hash_hex: String,
    pub spend_bundle_hex: String,
}

/// JSON-friendly result of a cast/update-vote build call. The
/// SpendBundle is encoded as length-prefixed Streamable bytes (the
/// canonical chia wire form, identical to what `encodeBundle` /
/// `assembleSpendBundle` produce). dApps push it as-is via WalletConnect.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmVoteResult {
    /// Coin id of the (re-)created Voting Coin: for `cast_vote` this
    /// is the freshly-minted Voting Coin; for `update_vote` it's the
    /// new Voting Coin singleton id (the prior one is spent).
    pub voting_coin_id_hex: String,
    /// Pushable `SpendBundle` as Streamable bytes, hex-encoded.
    pub spend_bundle_hex: String,
    /// Voter's `sign_unsafe` BLS signature over the canonical vote
    /// message. Used by the off-chain aggregator to build the
    /// per-ballot finalize witness.
    pub vote_signature_hex: String,
}

/// Decode a 48-byte BLS G1 public key from hex (with or without
/// `0x` prefix). Used by the chain-walking exports to deserialise
/// voter pubkey lists from the dApp.
fn parse_pubkey_hex(s: &str, label: &str) -> VotingResult<PublicKey> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: hex decode: {e}").into(),
        ))
    })?;
    let arr: [u8; 48] = bytes.as_slice().try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: expected 48-byte G1 pubkey, got {}", bytes.len()).into(),
        ))
    })?;
    PublicKey::from_bytes(&arr).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: PublicKey::from_bytes: {e:?}").into(),
        ))
    })
}

/// Build a [`SparseMerkleTree`](chip_voting_sdk::merkle::SparseMerkleTree)
/// from a JSON array of voter pubkey hex strings.
///
/// Used by `registerBuildSpends` (caller passes the SMT WITHOUT the
/// new voter — proving non-membership) and
/// `releaseCollateralBuildSpends` (caller passes the SMT WITH the
/// voter — proving membership). The dApp obtains the appropriate
/// pubkey list from a prior aggregator/indexer pass.
/// Sync the Election Singleton's SMT from chain. Replaces the legacy
/// `build_smt_from_pubkey_json` helper — under the weighted-voting
/// revision the SMT root depends on each voter's per-leaf locked
/// amount, which the dApp can no longer reconstruct from a flat
/// pubkey list. Internally drives `Aggregator::sync` (whose chain
/// walker brute-forces the announce_register CCA preimage to recover
/// each voter's REAL `locked_cat_mojos` — see
/// `apply_singleton_spend`), then takes the populated `smt` field.
async fn sync_smt_via_chain(
    chain: &JsChainReader,
    cfg: chip_voting_sdk::ElectionConfig,
    network: chip_voting_sdk::NetworkType,
    election_start_height: u64,
) -> VotingResult<chip_voting_sdk::merkle::SparseMerkleTree> {
    let mut aggregator = chip_voting_sdk::actors::aggregator::Aggregator::new(
        cfg,
        chain.clone(),
        network,
    )
    .with_election_start_height(election_start_height);
    let _ = aggregator.sync().await?;
    aggregator
        .merkle_tree()
        .cloned()
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("sync_smt: {e:?}").into())))
}

/// Decode a 32-byte BLS secret key from hex (with or without `0x`
/// prefix). Used by the cast / update wrappers to sign the spend
/// bundle inside wasm.
fn parse_secret_hex(s: &str, label: &str) -> VotingResult<SecretKey> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: hex decode: {e}").into(),
        ))
    })?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: expected 32-byte secret, got {}", bytes.len()).into(),
        ))
    })?;
    SecretKey::from_bytes(&arr).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(
            format!("{label}: SecretKey::from_bytes: {e:?}").into(),
        ))
    })
}

/// Convert the JS-side `WasmNetwork` enum into the SDK's
/// `NetworkType`. The SDK's `NetworkType` is wasm-friendly post
/// commit 31e42ae4 (no longer `pub use chia_query::NetworkType`).
fn wasm_network_to_sdk(n: WasmNetwork) -> chip_voting_sdk::NetworkType {
    match n {
        WasmNetwork::Mainnet => chip_voting_sdk::NetworkType::Mainnet,
        WasmNetwork::Testnet11 => chip_voting_sdk::NetworkType::Testnet11,
    }
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

/// Build the register spend bundle for a voter. Wraps
/// [`chip_voting_sdk::actors::voter::Voter::register`]. Mirrors
/// `phase_register_voter` in the live integration test.
///
/// Per CHIP rev 2026-05-02: NO `registration_fee_coin_spend` argument
/// (CHIP §191 forbids the curry). Caller may still attach a mempool
/// fee separately if desired.
///
/// `voter_pubkeys_hex_json` is a JSON array of currently-registered
/// voter pubkeys (NOT including the voter being registered now —
/// register's non-membership proof requires the slot to be empty
/// in the supplied SMT).
///
/// `cat_parent_spend_bytes` is the Streamable-encoded `CoinSpend`
/// the dApp pre-builds (and externally signs if necessary) to mint
/// the Registration Coin at its predicted CAT-wrapped puzzle hash.
///
/// Returns the Streamable-encoded SpendBundle as a hex string.
#[wasm_bindgen(js_name = "registerBuildSpends")]
pub async fn register_build_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_secret_hex: String,
    cat_parent_spend_bytes: Vec<u8>,
    lock_amount: u64,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let secret = parse_secret_hex(&voter_secret_hex, "voter_secret_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let keys = chip_voting_sdk::actors::voter::VoterKeys::new(secret);
    let cat_parent_spend: chia_protocol::CoinSpend = decode_streamable(&cat_parent_spend_bytes)?;
    let chain = JsChainReader::new(backend);
    let smt = sync_smt_via_chain(
        &chain,
        cfg.clone(),
        wasm_network_to_sdk(network),
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_smt_via_chain: {e}")))?;
    let voter = chip_voting_sdk::actors::voter::Voter::new(cfg, keys, wasm_network_to_sdk(network))
        .with_election_start_height(election_start_height);
    let bundle = voter
        .register(&smt, cat_parent_spend, &chain, lock_amount)
        .await
        .map_err(|e| JsError::new(&format!("register: {e}")))?;
    let bundle_bytes = encode_streamable(&bundle)?;
    Ok(hex::encode(&bundle_bytes))
}

/// Sage-friendly variant of [`registerBuildSpends`]. Takes the
/// voter's PUBLIC key (Sage holds the secret) and returns the unsigned
/// register coin_spends in wallet RPC shape. The dApp signs externally
/// with chip0002_signCoinSpends partial. Mirrors the
/// release_collateral / cast_vote unsigned-builder pattern.
///
/// Returns JSON `{ coinSpends: WalletCoinSpend[] }`.
#[wasm_bindgen(js_name = "registerBuildUnsignedCoinSpends")]
pub async fn register_build_unsigned_coin_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_pk_hex: String,
    cat_parent_spend_bytes: Vec<u8>,
    lock_amount: u64,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let cat_parent_spend: chia_protocol::CoinSpend = decode_streamable(&cat_parent_spend_bytes)?;

    let chain = JsChainReader::new(backend);
    let smt = sync_smt_via_chain(
        &chain,
        cfg.clone(),
        wasm_network_to_sdk(network),
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_smt_via_chain: {e}")))?;

    let voter = build_voter_for_external_signing(cfg, voter_pk, network, election_start_height)?;
    let coin_spends = voter
        .register_build_coin_spends(&smt, cat_parent_spend, &chain, lock_amount)
        .await
        .map_err(|e| JsError::new(&format!("register_build_coin_spends: {e}")))?;
    let wallet_spends: Vec<WalletCoinSpend> =
        coin_spends.iter().map(coin_spend_to_wallet).collect();
    let out = serde_json::json!({ "coinSpends": wallet_spends });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode result: {e}")))
}

/// Mint a fresh Ballot Coin launcher (per CHIP rev §211-253). Wraps
/// [`chip_voting_sdk::actors::ballot::BallotIssuer::create_ballot`].
/// Mirrors `phase_create_ballot` in the live integration test.
///
/// `funder_spend_bytes` is a Streamable-encoded `CoinSpend` the
/// dApp pre-builds (and externally signs if its puzzle requires it)
/// to provide the 2 mojos the Ballot Coin launcher eve needs. The
/// returned bundle's aggregated signature only covers AGG_SIG
/// conditions emitted by the singleton spend itself; the funder's
/// signature must be aggregated in JS-side via `assembleSpendBundle`
/// before pushing.
///
/// Returns a JSON-serialised [`WasmCreatedBallot`].
#[wasm_bindgen(js_name = "createBallotBundle")]
pub async fn create_ballot_bundle_js(
    backend: JsChainBackend,
    election_config_json: String,
    funder_spend_bytes: Vec<u8>,
    params_json: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let funder_spend: chia_protocol::CoinSpend = decode_streamable(&funder_spend_bytes)?;
    let wasm_params: WasmCreateBallotParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("CreateBallotParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("CreateBallotParams decode: {e}")))?;
    let issuer = chip_voting_sdk::actors::ballot::BallotIssuer::new(
        cfg,
        wasm_network_to_sdk(network),
    )
    .with_election_start_height(election_start_height);
    let chain = JsChainReader::new(backend);
    let result = issuer
        .create_ballot(&chain, sdk_params, funder_spend)
        .await
        .map_err(|e| JsError::new(&format!("create_ballot: {e}")))?;
    let bundle_bytes = encode_streamable(&result.spend_bundle)?;
    let out = WasmCreatedBallot {
        ballot_launcher_id_hex: hex::encode(result.ballot_launcher_id),
        ballot_coin_id_hex: hex::encode(result.ballot_coin_id),
        spend_bundle_hex: hex::encode(&bundle_bytes),
    };
    serde_json::to_string(&out)
        .map_err(|e| JsError::new(&format!("encode WasmCreatedBallot: {e}")))
}

/// Second-spend the ballot launcher → eve Ballot Coin (per CHIP
/// rev §211-253). Wraps
/// [`chip_voting_sdk::actors::ballot::BallotIssuer::launch_ballot`].
/// Mirrors `phase_launch_ballot` in the live integration test.
///
/// The `launcher_coin_id_hex` is the `ballot_launcher_id` returned
/// by an earlier `createBallotBundle` call.
///
/// Returns a JSON-serialised [`WasmLaunchedBallot`].
#[wasm_bindgen(js_name = "launchBallotBundle")]
pub async fn launch_ballot_bundle_js(
    backend: JsChainBackend,
    election_config_json: String,
    launcher_coin_id_hex: String,
    params_json: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let launcher_coin_id = parse_hex32(&launcher_coin_id_hex)
        .map_err(|e| JsError::new(&format!("launcher_coin_id_hex: {e}")))?;
    let wasm_params: WasmLaunchBallotParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("LaunchBallotParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("LaunchBallotParams decode: {e}")))?;
    let issuer = chip_voting_sdk::actors::ballot::BallotIssuer::new(
        cfg,
        wasm_network_to_sdk(network),
    )
    .with_election_start_height(election_start_height);
    let chain = JsChainReader::new(backend);
    let result = issuer
        .launch_ballot(&chain, launcher_coin_id, sdk_params)
        .await
        .map_err(|e| JsError::new(&format!("launch_ballot: {e}")))?;
    let bundle_bytes = encode_streamable(&result.spend_bundle)?;
    let out = WasmLaunchedBallot {
        ballot_launcher_id_hex: hex::encode(result.ballot_launcher_id),
        eve_ballot_coin_id_hex: hex::encode(result.eve_ballot_coin_id),
        eve_ballot_puzzle_hash_hex: hex::encode(result.eve_ballot_puzzle_hash),
        spend_bundle_hex: hex::encode(&bundle_bytes),
    };
    serde_json::to_string(&out)
        .map_err(|e| JsError::new(&format!("encode WasmLaunchedBallot: {e}")))
}

/// Build a one-condition shim spend that lets a chip0002 wallet produce
/// the unaugmented `sign_unsafe(vote_message)` BLS signature without the
/// dApp ever holding the voter's secret. The returned spend has a single
/// `(50 voter_pk vote_message)` condition (= `AGG_SIG_UNSAFE`); when the
/// dApp passes it to `chip0002_signCoinSpends` in PARTIAL mode, the
/// wallet's returned aggregate IS that single sig — byte-for-byte equal
/// to what `Voter::keys.sign_unsafe(vote_message)` would compute.
///
/// FLOW (browser dApp):
///   1. `castVoteBuildPreviewSpend(...)` → `{ coinSpends, voteMessageHex }`.
///   2. `walletConnect.signCoinSpends(coinSpends, partial=true)` →
///      96-byte aggregate hex = `sign_unsafe(vote_message)`.
///   3. `castVoteBuildUnsignedCoinSpends(..., voteSignatureHex=…)` →
///      the real cast_vote coin_spends with the sig embedded.
///   4. `walletConnect.signCoinSpends(coinSpends, partial=true)` →
///      bundle aggregate (covers AGG_SIG_ME conditions across all coins).
///   5. `assembleSpendBundleFromWalletCoinSpends(coinSpends, agg)` →
///      pushable bundle bytes.
///
/// Returns a JSON string the dApp parses into
/// `{ coinSpends: WalletCoinSpend[]; voteMessageHex: string }`.
#[wasm_bindgen(js_name = "castVoteBuildPreviewSpend")]
pub fn cast_vote_build_preview_spend_js(
    _backend: JsChainBackend,
    election_config_json: &str,
    voter_pk_hex: &str,
    params_json: &str,
) -> Result<String, JsError> {
    use chip_voting_sdk::clvm_traits::ToClvm;
    use chip_voting_sdk::clvmr::Allocator;
    use clvm_utils::tree_hash;

    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let election_id = cfg
        .election_launcher_id()
        .map_err(|e| JsError::new(&format!("election_launcher_id: {e}")))?;
    let voter_pk = parse_pubkey_hex(voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let wasm_params: WasmCastVoteParams = serde_json::from_str(params_json)
        .map_err(|e| JsError::new(&format!("CastVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("CastVoteParams decode: {e}")))?;

    let vote_message = chip_voting_sdk::puzzles::vote_message(
        sdk_params.vote_data,
        sdk_params.ballot_launcher_id,
        election_id,
    );

    // Build (q . ((50 voter_pk vote_message))) — a puzzle that returns
    // a single AGG_SIG_UNSAFE condition. Coin amount=1 keeps wallets
    // that validate amount>0 happy; parent_coin_info=0 because the
    // shim never goes on-chain.
    let mut allocator = Allocator::new();
    let pk_bytes = chia_protocol::Bytes::new(voter_pk.to_bytes().to_vec());
    let msg_bytes = chia_protocol::Bytes::new(vote_message.to_vec());
    let condition: (u8, (chia_protocol::Bytes, (chia_protocol::Bytes, ()))) =
        (50, (pk_bytes, (msg_bytes, ())));
    let conditions_value = vec![condition];
    let conditions_node = conditions_value
        .to_clvm(&mut allocator)
        .map_err(|e| JsError::new(&format!("conditions to_clvm: {e}")))?;
    let one_node = allocator
        .new_atom(&[1])
        .map_err(|e| JsError::new(&format!("alloc quote atom: {e:?}")))?;
    let puzzle_node = allocator
        .new_pair(one_node, conditions_node)
        .map_err(|e| JsError::new(&format!("alloc puzzle pair: {e:?}")))?;
    let solution_node = chip_voting_sdk::clvmr::NodePtr::NIL;

    let puzzle_bytes = chip_voting_sdk::clvmr::serde::node_to_bytes(&allocator, puzzle_node)
        .map_err(|e| JsError::new(&format!("serialize puzzle: {e:?}")))?;
    let solution_bytes = chip_voting_sdk::clvmr::serde::node_to_bytes(&allocator, solution_node)
        .map_err(|e| JsError::new(&format!("serialize solution: {e:?}")))?;
    let puzzle_th = tree_hash(&allocator, puzzle_node);
    let coin_ph = chia_protocol::Bytes32::new(puzzle_th.to_bytes());

    let shim_coin_spend = chia_protocol::CoinSpend {
        coin: chia_protocol::Coin::new(
            chia_protocol::Bytes32::new([0u8; 32]),
            coin_ph,
            1,
        ),
        puzzle_reveal: chia_protocol::Program::from(puzzle_bytes),
        solution: chia_protocol::Program::from(solution_bytes),
    };

    let wallet_spend = coin_spend_to_wallet(&shim_coin_spend);
    let out = serde_json::json!({
        "coinSpends": [wallet_spend],
        "voteMessageHex": format!("0x{}", hex::encode(vote_message)),
    });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode preview: {e}")))
}

/// Sage-friendly counterpart to [`castVoteBuildFinalBundle`]: takes a
/// pre-computed `voter_vote_signature_hex` (the dApp obtains it via
/// [`castVoteBuildPreviewSpend`] + chip0002_signCoinSpends partial)
/// and returns the UNSIGNED cast_vote coin_spends in wallet RPC shape,
/// ready for a second chip0002_signCoinSpends pass to produce the
/// bundle aggregate.
///
/// Returns a JSON string the dApp parses into
/// `{ coinSpends: WalletCoinSpend[]; votingCoinIdHex: string;
///    voteSignatureHex: string; voteMessageHex: string }`.
#[wasm_bindgen(js_name = "castVoteBuildUnsignedCoinSpends")]
pub async fn cast_vote_build_unsigned_coin_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_pk_hex: String,
    params_json: String,
    voter_vote_signature_hex: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let wasm_params: WasmCastVoteParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("CastVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("CastVoteParams decode: {e}")))?;
    let sig_bytes = hex::decode(voter_vote_signature_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("voter_vote_signature_hex decode: {e}")))?;
    if sig_bytes.len() != 96 {
        return Err(JsError::new(
            "voter_vote_signature_hex must decode to 96 bytes (BLS G2)",
        ));
    }
    let initial_signature = chia_protocol::Bytes::new(sig_bytes);

    // VoterKeys::new requires a SecretKey; for the no-secret browser
    // path we synthesise a placeholder keypair and override the pubkey
    // we actually want via the SDK's external-sig builder. The
    // placeholder secret never signs anything in this code path —
    // only `cast_vote_build_coin_spends` runs, and it consumes
    // `initial_signature` directly, never touching `self.keys.secret`.
    let voter = build_voter_for_external_signing(cfg, voter_pk, network, election_start_height)?;
    let chain = JsChainReader::new(backend);
    let result = voter
        .cast_vote_build_coin_spends(&chain, &sdk_params, initial_signature)
        .await
        .map_err(|e| JsError::new(&format!("cast_vote_build_coin_spends: {e}")))?;

    let wallet_spends: Vec<WalletCoinSpend> = result
        .coin_spends
        .iter()
        .map(coin_spend_to_wallet)
        .collect();
    let out = serde_json::json!({
        "coinSpends": wallet_spends,
        "votingCoinIdHex": format!("0x{}", hex::encode(result.voting_coin_id)),
        "voteSignatureHex": format!("0x{}", hex::encode(result.vote_signature.as_ref())),
        "voteMessageHex": format!("0x{}", hex::encode(result.vote_message)),
    });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode result: {e}")))
}

/// Construct a `Voter` whose `keys.pubkey` matches the supplied
/// hardware-wallet pubkey, but whose `keys.secret` is a deterministic
/// placeholder that NEVER signs anything (the external-signing path
/// hands its caller's signature directly into the SDK, bypassing
/// `keys.sign_unsafe` and the bundle aggregator). Used by the
/// browser-held-pubkey wasm exports.
fn build_voter_for_external_signing(
    cfg: chip_voting_sdk::ElectionConfig,
    voter_pk: chia_bls::PublicKey,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<chip_voting_sdk::actors::voter::Voter, JsError> {
    // Placeholder secret bytes — any 32-byte value parseable by
    // SecretKey::from_bytes works because we never sign with it.
    let placeholder_secret_bytes = [1u8; 32];
    let placeholder_secret = SecretKey::from_bytes(&placeholder_secret_bytes)
        .map_err(|e| JsError::new(&format!("placeholder secret: {e:?}")))?;
    let mut keys = chip_voting_sdk::actors::voter::VoterKeys::new(placeholder_secret);
    // Overwrite the auto-derived pubkey with the wallet's actual one.
    keys.pubkey = voter_pk;
    let voter = chip_voting_sdk::actors::voter::Voter::new(cfg, keys, wasm_network_to_sdk(network))
        .with_election_start_height(election_start_height);
    Ok(voter)
}

/// Finalise a cast-vote spend with the voter's BLS signature and
/// produce a pushable `SpendBundle`. Wraps
/// [`chip_voting_sdk::actors::voter::Voter::cast_vote`]. Mirrors
/// `phase_vote` in the live integration test.
///
/// Returns a JSON-serialised [`WasmVoteResult`].
#[wasm_bindgen(js_name = "castVoteBuildFinalBundle")]
pub async fn cast_vote_build_final_bundle_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_secret_hex: String,
    params_json: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let secret = parse_secret_hex(&voter_secret_hex, "voter_secret_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let keys = chip_voting_sdk::actors::voter::VoterKeys::new(secret);
    let wasm_params: WasmCastVoteParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("CastVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("CastVoteParams decode: {e}")))?;
    let voter = chip_voting_sdk::actors::voter::Voter::new(cfg, keys, wasm_network_to_sdk(network))
        .with_election_start_height(election_start_height);
    let chain = JsChainReader::new(backend);
    let result = voter
        .cast_vote(&chain, sdk_params)
        .await
        .map_err(|e| JsError::new(&format!("cast_vote: {e}")))?;
    let bundle_bytes = encode_streamable(&result.spend_bundle)?;
    let out = WasmVoteResult {
        voting_coin_id_hex: hex::encode(result.voting_coin_id),
        spend_bundle_hex: hex::encode(&bundle_bytes),
        vote_signature_hex: hex::encode(result.vote_signature.as_ref()),
    };
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode WasmVoteResult: {e}")))
}

/// Sage-friendly preview variant of [`updateVoteBuildFinalBundle`].
/// Builds a one-condition shim spend with `AGG_SIG_UNSAFE(voter_pk,
/// new_vote_message)` so a chip0002 wallet's partial signCoinSpends
/// returns `sign_unsafe(new_vote_message)` byte-for-byte. Mirrors
/// [`castVoteBuildPreviewSpend`] but for the update flow.
///
/// Returns JSON `{ coinSpends: WalletCoinSpend[]; voteMessageHex: string }`.
#[wasm_bindgen(js_name = "updateVoteBuildPreviewSpend")]
pub fn update_vote_build_preview_spend_js(
    _backend: JsChainBackend,
    election_config_json: &str,
    voter_pk_hex: &str,
    params_json: &str,
) -> Result<String, JsError> {
    use chip_voting_sdk::clvm_traits::ToClvm;
    use chip_voting_sdk::clvmr::Allocator;
    use clvm_utils::tree_hash;

    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let election_id = cfg
        .election_launcher_id()
        .map_err(|e| JsError::new(&format!("election_launcher_id: {e}")))?;
    let voter_pk = parse_pubkey_hex(voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let wasm_params: WasmUpdateVoteParams = serde_json::from_str(params_json)
        .map_err(|e| JsError::new(&format!("UpdateVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("UpdateVoteParams decode: {e}")))?;

    let new_vote_message = chip_voting_sdk::puzzles::vote_message(
        sdk_params.new_vote_data,
        sdk_params.ballot_launcher_id,
        election_id,
    );

    // Same shim shape as cast_vote preview: (q . ((50 voter_pk msg))).
    let mut allocator = Allocator::new();
    let pk_bytes = chia_protocol::Bytes::new(voter_pk.to_bytes().to_vec());
    let msg_bytes = chia_protocol::Bytes::new(new_vote_message.to_vec());
    let condition: (u8, (chia_protocol::Bytes, (chia_protocol::Bytes, ()))) =
        (50, (pk_bytes, (msg_bytes, ())));
    let conditions_value = vec![condition];
    let conditions_node = conditions_value
        .to_clvm(&mut allocator)
        .map_err(|e| JsError::new(&format!("conditions to_clvm: {e}")))?;
    let one_node = allocator
        .new_atom(&[1])
        .map_err(|e| JsError::new(&format!("alloc quote atom: {e:?}")))?;
    let puzzle_node = allocator
        .new_pair(one_node, conditions_node)
        .map_err(|e| JsError::new(&format!("alloc puzzle pair: {e:?}")))?;
    let solution_node = chip_voting_sdk::clvmr::NodePtr::NIL;
    let puzzle_bytes = chip_voting_sdk::clvmr::serde::node_to_bytes(&allocator, puzzle_node)
        .map_err(|e| JsError::new(&format!("serialize puzzle: {e:?}")))?;
    let solution_bytes = chip_voting_sdk::clvmr::serde::node_to_bytes(&allocator, solution_node)
        .map_err(|e| JsError::new(&format!("serialize solution: {e:?}")))?;
    let puzzle_th = tree_hash(&allocator, puzzle_node);
    let coin_ph = chia_protocol::Bytes32::new(puzzle_th.to_bytes());

    let shim_coin_spend = chia_protocol::CoinSpend {
        coin: chia_protocol::Coin::new(
            chia_protocol::Bytes32::new([0u8; 32]),
            coin_ph,
            1,
        ),
        puzzle_reveal: chia_protocol::Program::from(puzzle_bytes),
        solution: chia_protocol::Program::from(solution_bytes),
    };
    let wallet_spend = coin_spend_to_wallet(&shim_coin_spend);
    let out = serde_json::json!({
        "coinSpends": [wallet_spend],
        "voteMessageHex": format!("0x{}", hex::encode(new_vote_message)),
    });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode preview: {e}")))
}

/// Sage-friendly counterpart to [`updateVoteBuildFinalBundle`]. Takes
/// the wallet-supplied `new_vote_signature_hex` (from
/// [`updateVoteBuildPreviewSpend`] + chip0002_signCoinSpends partial)
/// and returns the unsigned update_vote coin_spends in wallet RPC
/// shape. Mirrors [`castVoteBuildUnsignedCoinSpends`].
///
/// Returns JSON `{ coinSpends: WalletCoinSpend[]; recreatedVotingCoinIdHex: string;
///                 newVoteSignatureHex: string; newVoteMessageHex: string }`.
#[wasm_bindgen(js_name = "updateVoteBuildUnsignedCoinSpends")]
pub async fn update_vote_build_unsigned_coin_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_pk_hex: String,
    params_json: String,
    new_vote_signature_hex: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let wasm_params: WasmUpdateVoteParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("UpdateVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("UpdateVoteParams decode: {e}")))?;
    let sig_bytes = hex::decode(new_vote_signature_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("new_vote_signature_hex decode: {e}")))?;
    if sig_bytes.len() != 96 {
        return Err(JsError::new(
            "new_vote_signature_hex must decode to 96 bytes (BLS G2)",
        ));
    }
    let new_signature = chia_protocol::Bytes::new(sig_bytes);

    let voter = build_voter_for_external_signing(cfg, voter_pk, network, election_start_height)?;
    let chain = JsChainReader::new(backend);
    let result = voter
        .update_vote_build_coin_spends(&chain, &sdk_params, new_signature)
        .await
        .map_err(|e| JsError::new(&format!("update_vote_build_coin_spends: {e}")))?;

    let wallet_spends: Vec<WalletCoinSpend> = result
        .coin_spends
        .iter()
        .map(coin_spend_to_wallet)
        .collect();
    let out = serde_json::json!({
        "coinSpends": wallet_spends,
        "recreatedVotingCoinIdHex": format!("0x{}", hex::encode(result.recreated_voting_coin_id)),
        "newVoteSignatureHex": format!("0x{}", hex::encode(result.new_vote_signature.as_ref())),
        "newVoteMessageHex": format!("0x{}", hex::encode(result.new_vote_message)),
    });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode result: {e}")))
}

/// Finalise an update-vote spend with the voter's BLS signature.
/// Wraps [`chip_voting_sdk::actors::voter::Voter::update_vote`].
///
/// Returns a JSON-serialised [`WasmVoteResult`] whose
/// `votingCoinIdHex` is the *recreated* Voting Coin id (the prior
/// one is spent in this transaction).
#[wasm_bindgen(js_name = "updateVoteBuildFinalBundle")]
pub async fn update_vote_build_final_bundle_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_secret_hex: String,
    params_json: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let secret = parse_secret_hex(&voter_secret_hex, "voter_secret_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let keys = chip_voting_sdk::actors::voter::VoterKeys::new(secret);
    let wasm_params: WasmUpdateVoteParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("UpdateVoteParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("UpdateVoteParams decode: {e}")))?;
    let voter = chip_voting_sdk::actors::voter::Voter::new(cfg, keys, wasm_network_to_sdk(network))
        .with_election_start_height(election_start_height);
    let chain = JsChainReader::new(backend);
    let result = voter
        .update_vote(&chain, sdk_params)
        .await
        .map_err(|e| JsError::new(&format!("update_vote: {e}")))?;
    let bundle_bytes = encode_streamable(&result.spend_bundle)?;
    let out = WasmVoteResult {
        voting_coin_id_hex: hex::encode(result.recreated_voting_coin_id),
        spend_bundle_hex: hex::encode(&bundle_bytes),
        vote_signature_hex: hex::encode(result.new_vote_signature.as_ref()),
    };
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode WasmVoteResult: {e}")))
}

/// Build the per-Ballot-Coin finalize bundle (Groth16 proof +
/// finalize action solution). Wraps
/// [`chip_voting_sdk::actors::aggregator::Aggregator::build_finalize_for_ballot`].
/// Mirrors `phase_finalize` in the live integration test.
///
/// Inputs:
///   * `votes_json` — JSON array of
///     [`VoteRecordWire`](chip_voting_sdk::state::VoteRecordWire)
///     (typically the output of an earlier `collectVotesForBallot`).
///   * `proving_key_bytes` — arkworks compressed `ProvingKey<Bls12_381>`
///     bytes (see `ArkProvingKey::serialize_compressed`). The dApp
///     fetches this once from a CDN and caches in IndexedDB; it can
///     be 1–10 MB depending on circuit size.
///   * `params_json` — [`WasmFinalizeParams`].
///   * `vote_outcome_hex` — the canonical 32-byte outcome.
///
/// The Groth16 prover runs inside wasm via `ark-groth16` (already a
/// non-feature-gated dep of this crate); a single proof on a
/// reference circuit takes a few seconds in modern browsers.
///
/// Returns the Streamable-encoded SpendBundle as a hex string.
#[wasm_bindgen(js_name = "buildBallotFinalizeBundle")]
pub async fn build_ballot_finalize_bundle_js(
    backend: JsChainBackend,
    election_config_json: String,
    ballot_launcher_id_hex: String,
    vote_outcome_hex: String,
    params_json: String,
    votes_json: String,
    proving_key_bytes: Vec<u8>,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let ballot_launcher_id = parse_hex32(&ballot_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("ballot_launcher_id_hex: {e}")))?;
    let vote_outcome = parse_hex32(&vote_outcome_hex)
        .map_err(|e| JsError::new(&format!("vote_outcome_hex: {e}")))?;
    let wasm_params: WasmFinalizeParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("WasmFinalizeParams parse: {e}")))?;
    let registration_merkle_root_snapshot =
        parse_hex32(&wasm_params.registration_merkle_root_snapshot_hex)
            .map_err(|e| JsError::new(&format!("registration_merkle_root_snapshot_hex: {e}")))?;

    let votes_wire: Vec<chip_voting_sdk::state::VoteRecordWire> =
        serde_json::from_str(&votes_json)
            .map_err(|e| JsError::new(&format!("votes_json parse: {e}")))?;
    let votes: Vec<chip_voting_sdk::state::VoteRecord> = votes_wire
        .iter()
        .map(vote_record_wire_to_sdk)
        .collect::<VotingResult<Vec<_>>>()
        .map_err(|e| JsError::new(&format!("VoteRecord decode: {e}")))?;

    let proving_key = chip_voting_sdk::ArkProvingKey::deserialize_compressed(&proving_key_bytes)
        .map_err(|e| JsError::new(&format!("ArkProvingKey::deserialize_compressed: {e}")))?;

    let chain = JsChainReader::new(backend);
    let mut aggregator =
        chip_voting_sdk::actors::aggregator::Aggregator::new(cfg, chain, wasm_network_to_sdk(network))
            .with_election_start_height(election_start_height);
    // Aggregator::build_finalize_for_ballot reads synced state
    // (`voter_set`, `merkle_tree`, `state`); without `sync()` those
    // accessors return `NotDeployed`. The dApp / harness can't easily
    // call `.sync()` itself because the Aggregator is created here and
    // `Aggregator::sync` requires `&mut self` — so call it inline.
    aggregator
        .sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e}")))?;

    let params = chip_voting_sdk::actors::aggregator::BuildFinalizeForBallotParams {
        ballot_launcher_id,
        vote_outcome,
        votes: &votes,
        vote_close_height: wasm_params.vote_close_height,
        vote_threshold_num: wasm_params.vote_threshold_num,
        vote_threshold_den: wasm_params.vote_threshold_den,
        registration_merkle_root_snapshot,
        registration_vote_weight_snapshot: wasm_params.registration_vote_weight_snapshot,
        proving_key: &proving_key,
    };
    let bundle = aggregator
        .build_finalize_for_ballot(params)
        .await
        .map_err(|e| JsError::new(&format!("build_finalize_for_ballot: {e}")))?;
    let bundle_bytes = encode_streamable(&bundle)?;
    Ok(hex::encode(&bundle_bytes))
}

/// Walk the chain to collect every Voting Coin that targets the
/// supplied ballot. Wraps
/// [`chip_voting_sdk::actors::aggregator::collect_votes_for_ballot_via_chain`].
///
/// `voter_pubkeys_hex_json` is a JSON array of 48-byte BLS G1
/// pubkeys as hex strings (with or without `0x` prefix). The dApp
/// typically obtains this list from a prior `Aggregator::sync` /
/// indexer pass over the Election Singleton's registration history.
///
/// Returns a JSON-serialised array of [`VoteRecordWire`] (each entry
/// has `voterPubkeyHex`, `voteDataHex`, `voteSignatureHex`,
/// `registrationCoinIdHex`, `ballotLauncherIdHex`, `votingCoinIdHex`).
#[wasm_bindgen(js_name = "collectVotesForBallot")]
pub async fn collect_votes_for_ballot_js(
    backend: JsChainBackend,
    election_config_json: String,
    ballot_launcher_id_hex: String,
    voter_pubkeys_hex_json: String,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let ballot_launcher_id = parse_hex32(&ballot_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("ballot_launcher_id_hex: {e}")))?;
    let voter_hex_list: Vec<String> = serde_json::from_str(&voter_pubkeys_hex_json)
        .map_err(|e| JsError::new(&format!("voter_pubkeys_hex_json parse: {e}")))?;
    let mut voters: Vec<PublicKey> = Vec::with_capacity(voter_hex_list.len());
    for (idx, h) in voter_hex_list.iter().enumerate() {
        let pk = parse_pubkey_hex(h, &format!("voter_pubkeys[{idx}]"))
            .map_err(|e| JsError::new(&format!("{e}")))?;
        voters.push(pk);
    }
    let voter_set = chip_voting_sdk::state::VoterSet {
        registration_merkle_root: chia_protocol::Bytes32::default(),
        registration_count: voters.len() as u64,
        voters,
    };
    let chain = JsChainReader::new(backend);
    let records = chip_voting_sdk::actors::aggregator::collect_votes_for_ballot_via_chain(
        &cfg,
        &chain,
        ballot_launcher_id,
        &voter_set,
    )
    .await
    .map_err(|e| JsError::new(&format!("collect_votes_for_ballot: {e}")))?;
    let wire: Vec<chip_voting_sdk::state::VoteRecordWire> =
        records.iter().map(Into::into).collect();
    serde_json::to_string(&wire)
        .map_err(|e| JsError::new(&format!("encode VoteRecordWire list: {e}")))
}

/// Enumerate every Ballot Coin minted under this election. Wraps
/// [`chip_voting_sdk::actors::ballot::list_ballots_via_chain`].
///
/// Returns the snapshot list as JSON-serialized text (each entry has
/// `ballot_launcher_id`, `election_launcher_id`, `vote_close_height`,
/// `outcome_domain_hash`, `state`, `coin_id`). Caller does
/// `JSON.parse(result)` on the JS side.
#[wasm_bindgen(js_name = "listBallots")]
pub async fn list_ballots_js(
    backend: JsChainBackend,
    election_config_json: String,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let chain = JsChainReader::new(backend);
    let snapshots = chip_voting_sdk::actors::ballot::list_ballots_via_chain(&cfg, &chain)
        .await
        .map_err(|e| JsError::new(&format!("list_ballots: {e}")))?;
    serde_json::to_string(&snapshots)
        .map_err(|e| JsError::new(&format!("encode snapshots: {e}")))
}

/// Look up a single Ballot Coin by its launcher id. Wraps
/// [`chip_voting_sdk::actors::ballot::get_ballot_via_chain`]. Returns
/// the JSON-serialized snapshot (or the literal string `"null"` when
/// no ballot with that launcher id exists under the election).
#[wasm_bindgen(js_name = "getBallot")]
pub async fn get_ballot_js(
    backend: JsChainBackend,
    election_config_json: String,
    ballot_launcher_id_hex: String,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let ballot_launcher_id = parse_hex32(&ballot_launcher_id_hex)
        .map_err(|e| JsError::new(&format!("ballot_launcher_id_hex: {e}")))?;
    let chain = JsChainReader::new(backend);
    let snapshot = chip_voting_sdk::actors::ballot::get_ballot_via_chain(
        &cfg,
        &chain,
        ballot_launcher_id,
    )
    .await
    .map_err(|e| JsError::new(&format!("get_ballot: {e}")))?;
    serde_json::to_string(&snapshot)
        .map_err(|e| JsError::new(&format!("encode snapshot: {e}")))
}

/// Read the current Election Singleton's state from chain by walking
/// the launcher lineage. Returns JSON with `coinIdHex`,
/// `registrationMerkleRootHex`, `registrationCount`,
/// `registrationVoteWeight`, `electionStartHeight`.
///
/// dApp callers should snapshot this state right before
/// `launchBallotBundle` and persist the registration root + vote
/// weight alongside the ballot's other curry data — every later phase
/// (`castVoteBuildFinalBundle`, `updateVoteBuildFinalBundle`,
/// `buildBallotFinalizeBundle`, `announceBallotFinalization`) MUST
/// pass the matching snapshot or the eve Ballot Coin's curried puzzle
/// hash won't agree with what the chain mints.
#[wasm_bindgen(js_name = "readElectionSingletonState")]
pub async fn read_election_singleton_state_js(
    backend: JsChainBackend,
    election_config_json: String,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let chain = JsChainReader::new(backend);
    let cs = chip_voting_sdk::actors::aggregator::find_current_singleton(
        &chain,
        &cfg,
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("find_current_singleton: {e:?}")))?;
    let out = serde_json::json!({
        "coinIdHex": format!("0x{}", hex::encode(cs.coin.coin_id())),
        "registrationMerkleRootHex": format!("0x{}", hex::encode(cs.state.registration_merkle_root)),
        "registrationCount": cs.state.registration_count,
        "registrationVoteWeight": cs.state.registration_vote_weight,
        "electionStartHeight": cs.state.election_start_height,
        // M12: per-election ballot-mode lock. Sentinel 0xFF…FF = "no
        // lock"; 0x00…00 = lock to Mode1Free; any other value = lock to
        // that exact sorted-options merkle root. /create-ballot UI
        // honors this when minting fresh ballots.
        "voteModeLockHex": format!("0x{}", hex::encode(cs.state.vote_mode_lock)),
    });
    Ok(out.to_string())
}

/// Recover `election_start_height` from chain by matching the eve
/// singleton's actual puzzle hash against candidates derived from the
/// launcher's confirmed height. The deployer signs the launcher with
/// `electionStartHeight = peak` at submission time; the launcher
/// confirms 1-N blocks later. Without the value in the bootstrap, the
/// dApp can't predict the eve_ph (and every subsequent spend's
/// declared puzzle hash diverges from chain). This walks a window of
/// candidate heights and finds the unique value whose computed eve_ph
/// matches the launcher's actual on-chain child.
///
/// Returns the recovered height as a number, or null if no candidate
/// in the window matches (caller should widen the window or fall back
/// to share-bundle re-import).
#[wasm_bindgen(js_name = "recoverElectionStartHeight")]
pub async fn recover_election_start_height_js(
    backend: JsChainBackend,
    election_config_json: String,
    window_blocks: u32,
) -> Result<JsValue, JsError> {
    use chip_voting_sdk::actors::aggregator::compute_eve_singleton_puzzle_hash;

    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let launcher_id = cfg
        .election_launcher_id()
        .map_err(|e| JsError::new(&format!("election_launcher_id: {e}")))?;

    let chain = JsChainReader::new(backend);

    // 1. Fetch the launcher's confirmed_height — gives us the search center.
    let launcher_record = chain
        .coin_record_by_id(launcher_id)
        .await
        .map_err(|e| JsError::new(&format!("launcher coin_record_by_id: {e}")))?
        .ok_or_else(|| JsError::new("launcher coin not found on chain"))?;
    let center: u64 = launcher_record.confirmed_height as u64;
    if center == 0 {
        return Err(JsError::new(
            "launcher coin has no confirmed_height — not yet on chain",
        ));
    }

    // 2. Get the actual eve coin (the launcher's only valid child).
    let children = chain
        .coin_records_by_parent_ids(&[launcher_id])
        .await
        .map_err(|e| JsError::new(&format!("launcher children query: {e}")))?;
    let eve = children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
        .ok_or_else(|| {
            JsError::new(
                "launcher has no valid singleton child — election not deployed yet",
            )
        })?;
    let actual_eve_ph = eve.coin.puzzle_hash;

    // 3. Scan candidate heights. The deployer's `peak` ≤ launcher's
    //    confirmed_height, but we widen on both sides for robustness
    //    (e.g. clock-skew between dApp + node).
    let lo = center.saturating_sub(window_blocks as u64);
    let hi = center.saturating_add(window_blocks as u64);
    for candidate in lo..=hi {
        let predicted = compute_eve_singleton_puzzle_hash(&cfg, candidate);
        if predicted == actual_eve_ph {
            return Ok(JsValue::from_f64(candidate as f64));
        }
    }
    Ok(JsValue::NULL)
}

/// Walk the Election Singleton's lineage and return EVERY registered
/// voter's pubkey + locked amount as a JSON array. Drives finalize +
/// tally flows on browsers that didn't witness register actions
/// directly (share-bundle imports, second-device finalize, etc) so
/// they can pass `voter_pubkeys` to `collectVotesForBallot` /
/// `buildBallotFinalizeBundle` without depending on
/// session-storage-tracked lists.
///
/// JSON shape: `[{ "pubkeyHex": "0x...", "lockedAmount": 1000 }, ...]`
#[wasm_bindgen(js_name = "listRegisteredVoters")]
pub async fn list_registered_voters_js(
    backend: JsChainBackend,
    election_config_json: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let chain = JsChainReader::new(backend);
    let mut aggregator = chip_voting_sdk::actors::aggregator::Aggregator::new(
        cfg,
        chain,
        wasm_network_to_sdk(network),
    )
    .with_election_start_height(election_start_height);
    aggregator
        .sync()
        .await
        .map_err(|e| JsError::new(&format!("Aggregator::sync: {e}")))?;
    let voter_set = aggregator
        .voter_set()
        .map_err(|e| JsError::new(&format!("voter_set: {e:?}")))?;
    let smt = aggregator
        .merkle_tree()
        .map_err(|e| JsError::new(&format!("merkle_tree: {e:?}")))?;
    let entries: Vec<serde_json::Value> = voter_set
        .voters
        .iter()
        .map(|pk| {
            let amount = smt.locked_amount(pk).unwrap_or(0);
            serde_json::json!({
                "pubkeyHex": format!("0x{}", hex::encode(pk.to_bytes())),
                "lockedAmount": amount,
            })
        })
        .collect();
    serde_json::to_string(&entries)
        .map_err(|e| JsError::new(&format!("encode listRegisteredVoters: {e}")))
}

/// Look up a specific voter's `locked_cat_mojos` from the on-chain SMT.
/// Returns `null` if the voter isn't currently registered (not in the
/// SMT). Drives the dApp's "Your weight = N CAT" stat without exposing
/// the full per-voter mapping (which would require listing every
/// registered voter on-chain — possible but heavier).
#[wasm_bindgen(js_name = "getVoterLockedAmount")]
pub async fn get_voter_locked_amount_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_pk_hex: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<JsValue, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;

    let chain = JsChainReader::new(backend);
    let smt = sync_smt_via_chain(
        &chain,
        cfg,
        wasm_network_to_sdk(network),
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_smt_via_chain: {e}")))?;

    Ok(match smt.locked_amount(&voter_pk) {
        Some(amount) => JsValue::from_f64(amount as f64),
        None => JsValue::NULL,
    })
}

/// JS-side input mirror of
/// [`chip_voting_sdk::actors::ballot::AnnounceFinalizationParams`].
/// The `voteOutcomeHex` and `aggSignersHex` are the FINALIZED state
/// values (returned by an earlier `buildBallotFinalizeBundle` call);
/// the per-ballot curry data must match what was used at
/// `launchBallotBundle` time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmAnnounceFinalizationParams {
    pub ballot_launcher_id_hex: String,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot_hex: String,
    pub registration_vote_weight_snapshot: u64,
    pub vote_outcome_hex: String,
    pub agg_signers_hex: String,
}

impl WasmAnnounceFinalizationParams {
    fn into_sdk(self) -> VotingResult<chip_voting_sdk::actors::ballot::AnnounceFinalizationParams> {
        Ok(chip_voting_sdk::actors::ballot::AnnounceFinalizationParams {
            ballot_launcher_id: parse_hex32(&self.ballot_launcher_id_hex)?,
            vote_close_height: self.vote_close_height,
            vote_threshold_num: self.vote_threshold_num,
            vote_threshold_den: self.vote_threshold_den,
            registration_merkle_root_snapshot: parse_hex32(
                &self.registration_merkle_root_snapshot_hex,
            )?,
            registration_vote_weight_snapshot: self.registration_vote_weight_snapshot,
            vote_outcome: parse_hex32(&self.vote_outcome_hex)?,
            agg_signers: parse_hex32(&self.agg_signers_hex)?,
        })
    }
}

/// Announce a ballot finalization (the Ballot Coin's
/// `announce_finalization` action). Per CHIP rev §211-253 this is
/// the on-chain trigger for downstream consumers (treasuries, etc.)
/// to read the finalized vote outcome.
///
/// PRE: the ballot must already have been finalized via
/// `buildBallotFinalizeBundle` (the action puzzle traps if the
/// curried `BallotState.finalized` is `false`).
///
/// Wraps
/// [`chip_voting_sdk::actors::ballot::build_announce_finalization_bundle`].
/// Returns the Streamable-encoded `SpendBundle` as a hex string.
#[wasm_bindgen(js_name = "announceBallotFinalization")]
pub async fn announce_ballot_finalization_js(
    backend: JsChainBackend,
    election_config_json: String,
    params_json: String,
    network: WasmNetwork,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let wasm_params: WasmAnnounceFinalizationParams = serde_json::from_str(&params_json)
        .map_err(|e| JsError::new(&format!("AnnounceFinalizationParams parse: {e}")))?;
    let sdk_params = wasm_params
        .into_sdk()
        .map_err(|e| JsError::new(&format!("AnnounceFinalizationParams decode: {e}")))?;
    let chain = JsChainReader::new(backend);
    let bundle = chip_voting_sdk::actors::ballot::build_announce_finalization_bundle(
        &cfg,
        &chain,
        wasm_network_to_sdk(network),
        sdk_params,
    )
    .await
    .map_err(|e| JsError::new(&format!("build_announce_finalization_bundle: {e}")))?;
    let bundle_bytes = encode_streamable(&bundle)?;
    Ok(hex::encode(&bundle_bytes))
}

/// Build the release-collateral spend bundle for a voter. Wraps
/// [`chip_voting_sdk::actors::voter::Voter::release_collateral`].
/// Mirrors `phase_release` in the live integration test.
///
/// Per CHIP rev 2026-05-02 the SDK's `release_collateral` requires a
/// `registration_coin_id` arg (the lineage walker needs it to find
/// the voter's actual on-chain registration coin).
///
/// `voter_pubkeys_hex_json` is a JSON array of currently-registered
/// voter pubkeys INCLUDING this voter — release's deregister
/// membership proof requires the voter to be present in the supplied
/// SMT, and the SMT's root must match the on-chain
/// `registration_merkle_root` (otherwise the SDK errors early with a
/// clear "re-sync" message).
///
/// Returns the Streamable-encoded SpendBundle as a hex string.
#[wasm_bindgen(js_name = "releaseCollateralBuildSpends")]
pub async fn release_collateral_build_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_secret_hex: String,
    registration_coin_id_hex: String,
    destination_puzzle_hash_hex: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let secret = parse_secret_hex(&voter_secret_hex, "voter_secret_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let keys = chip_voting_sdk::actors::voter::VoterKeys::new(secret);
    let registration_coin_id = parse_hex32(&registration_coin_id_hex)
        .map_err(|e| JsError::new(&format!("registration_coin_id_hex: {e}")))?;
    let destination = parse_hex32(&destination_puzzle_hash_hex)
        .map_err(|e| JsError::new(&format!("destination_puzzle_hash_hex: {e}")))?;
    let chain = JsChainReader::new(backend);
    let smt = sync_smt_via_chain(
        &chain,
        cfg.clone(),
        wasm_network_to_sdk(network),
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_smt_via_chain: {e}")))?;
    let voter = chip_voting_sdk::actors::voter::Voter::new(cfg, keys, wasm_network_to_sdk(network))
        .with_election_start_height(election_start_height);
    let bundle = voter
        .release_collateral(&chain, &smt, registration_coin_id, destination)
        .await
        .map_err(|e| JsError::new(&format!("release_collateral: {e}")))?;
    let bundle_bytes = encode_streamable(&bundle)?;
    Ok(hex::encode(&bundle_bytes))
}

/// Sage-friendly variant of [`releaseCollateralBuildSpends`]. Takes
/// the voter's PUBLIC key (Sage holds the secret) plus the same SMT /
/// reg-coin-id / destination args, returns the unsigned coin_spends
/// in wallet RPC shape. The dApp calls chip0002_signCoinSpends in
/// partial mode to produce the bundle aggregate, then
/// [`assembleSpendBundleFromWalletCoinSpends`].
///
/// Returns JSON `{ coinSpends: WalletCoinSpend[] }`.
#[wasm_bindgen(js_name = "releaseCollateralBuildUnsignedCoinSpends")]
pub async fn release_collateral_build_unsigned_coin_spends_js(
    backend: JsChainBackend,
    election_config_json: String,
    voter_pk_hex: String,
    registration_coin_id_hex: String,
    destination_puzzle_hash_hex: String,
    network: WasmNetwork,
    election_start_height: u64,
) -> Result<String, JsError> {
    let cfg: chip_voting_sdk::ElectionConfig = serde_json::from_str(&election_config_json)
        .map_err(|e| JsError::new(&format!("ElectionConfig parse: {e}")))?;
    cfg.validate()
        .map_err(|e| JsError::new(&format!("ElectionConfig.validate(): {e:?}")))?;
    let voter_pk = parse_pubkey_hex(&voter_pk_hex, "voter_pk_hex")
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let registration_coin_id = parse_hex32(&registration_coin_id_hex)
        .map_err(|e| JsError::new(&format!("registration_coin_id_hex: {e}")))?;
    let destination = parse_hex32(&destination_puzzle_hash_hex)
        .map_err(|e| JsError::new(&format!("destination_puzzle_hash_hex: {e}")))?;

    let chain = JsChainReader::new(backend);
    let smt = sync_smt_via_chain(
        &chain,
        cfg.clone(),
        wasm_network_to_sdk(network),
        election_start_height,
    )
    .await
    .map_err(|e| JsError::new(&format!("sync_smt_via_chain: {e}")))?;
    let voter = build_voter_for_external_signing(cfg, voter_pk, network, election_start_height)?;
    let coin_spends = voter
        .release_collateral_build_coin_spends(&chain, &smt, registration_coin_id, destination)
        .await
        .map_err(|e| JsError::new(&format!("release_collateral_build_coin_spends: {e}")))?;

    let wallet_spends: Vec<WalletCoinSpend> =
        coin_spends.iter().map(coin_spend_to_wallet).collect();
    let out = serde_json::json!({ "coinSpends": wallet_spends });
    serde_json::to_string(&out).map_err(|e| JsError::new(&format!("encode result: {e}")))
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

// ─────────────────────────────────────────────────────────────────────
// Sage-bundle conversion helpers
// ─────────────────────────────────────────────────────────────────────
//
// The dApp's WalletConnect surface (`chip0002_signCoinSpends`,
// `chip0002_sendTransaction`) expects bundles in the wallet RPC JSON
// shape (`{ coin: { parent_coin_info, puzzle_hash, amount },
// puzzle_reveal, solution }` per coin spend; `aggregated_signature`
// at the top level). Wasm callers usually hold a `chia_protocol`
// Streamable byte form. These three helpers do the (de)serialization
// without pulling `chia_query` (which has native-only deps and won't
// compile to wasm).
//
// SHAPE: matches `chia_query::SpendBundle` field-for-field — so the
// dApp can `JSON.parse(...)` the result and hand it straight to Sage
// or to coinset.org's `/push_tx`.

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletCoin {
    parent_coin_info: String,
    puzzle_hash: String,
    amount: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletCoinSpend {
    coin: WalletCoin,
    puzzle_reveal: String,
    solution: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletSpendBundle {
    coin_spends: Vec<WalletCoinSpend>,
    aggregated_signature: String,
}

fn coin_spend_to_wallet(cs: &chia_protocol::CoinSpend) -> WalletCoinSpend {
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

fn wallet_to_coin_spend(w: &WalletCoinSpend) -> Result<chia_protocol::CoinSpend, JsError> {
    let parent = parse_hex32(&w.coin.parent_coin_info)
        .map_err(|e| JsError::new(&format!("coin.parent_coin_info: {e}")))?;
    let ph = parse_hex32(&w.coin.puzzle_hash)
        .map_err(|e| JsError::new(&format!("coin.puzzle_hash: {e}")))?;
    let coin = chia_protocol::Coin::new(parent, ph, w.coin.amount);
    let puzzle_reveal_bytes = hex::decode(w.puzzle_reveal.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("puzzle_reveal hex decode: {e}")))?;
    let solution_bytes = hex::decode(w.solution.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("solution hex decode: {e}")))?;
    Ok(chia_protocol::CoinSpend {
        coin,
        puzzle_reveal: chia_protocol::Program::from(puzzle_reveal_bytes),
        solution: chia_protocol::Program::from(solution_bytes),
    })
}

/// Decode a Streamable `SpendBundle` byte string into the wallet RPC
/// JSON shape — the format Sage's `chip0002_sendTransaction` and
/// coinset.org's `/push_tx` accept. Returns a JSON string the JS side
/// can `JSON.parse(...)` directly into a `SpendBundleJson`.
#[wasm_bindgen(js_name = "bundleBytesToWalletJson")]
pub fn bundle_bytes_to_wallet_json_js(bundle_bytes: &[u8]) -> Result<String, JsError> {
    let bundle: SpendBundle = decode_streamable(bundle_bytes)?;
    let out = WalletSpendBundle {
        coin_spends: bundle.coin_spends.iter().map(coin_spend_to_wallet).collect(),
        aggregated_signature: format!(
            "0x{}",
            hex::encode(bundle.aggregated_signature.to_bytes())
        ),
    };
    serde_json::to_string(&out)
        .map_err(|e| JsError::new(&format!("encode WalletSpendBundle: {e}")))
}

/// Decode a Streamable `SpendBundle` byte string and emit ONLY its
/// coin_spends, in the wallet RPC JSON shape — for handing to Sage's
/// `chip0002_signCoinSpends`. Drops the `aggregated_signature` (Sage
/// produces a fresh one).
#[wasm_bindgen(js_name = "extractWalletCoinSpendsFromBundle")]
pub fn extract_wallet_coin_spends_from_bundle_js(
    bundle_bytes: &[u8],
) -> Result<String, JsError> {
    let bundle: SpendBundle = decode_streamable(bundle_bytes)?;
    let coin_spends: Vec<WalletCoinSpend> =
        bundle.coin_spends.iter().map(coin_spend_to_wallet).collect();
    serde_json::to_string(&coin_spends)
        .map_err(|e| JsError::new(&format!("encode WalletCoinSpend list: {e}")))
}

/// Decode a length-prefixed Streamable coin_spends list (the
/// pre-bundle shape returned by `buildDeployBundle`,
/// `extractCoinSpendsFromBundle`, etc.) and emit it in wallet RPC
/// JSON. Equivalent to assembling a placeholder-sig bundle and then
/// `extractWalletCoinSpendsFromBundle`, but skips the sig step.
#[wasm_bindgen(js_name = "coinSpendsBytesToWalletJson")]
pub fn coin_spends_bytes_to_wallet_json_js(
    coin_spends_bytes: &[u8],
) -> Result<String, JsError> {
    let coin_spends = decode_coin_spends(coin_spends_bytes)?;
    let wallet_spends: Vec<WalletCoinSpend> =
        coin_spends.iter().map(coin_spend_to_wallet).collect();
    serde_json::to_string(&wallet_spends)
        .map_err(|e| JsError::new(&format!("encode WalletCoinSpend list: {e}")))
}

/// Re-assemble a Streamable `SpendBundle` from wallet-format
/// coin_spends (Sage's `chip0002_signCoinSpends` input shape) plus
/// the aggregated signature Sage returns. Inverse of
/// `bundleBytesToWalletJson` paired with `extractWalletCoinSpendsFromBundle`.
#[wasm_bindgen(js_name = "assembleSpendBundleFromWalletCoinSpends")]
pub fn assemble_spend_bundle_from_wallet_coin_spends_js(
    coin_spends_json: &str,
    aggregated_signature_hex: &str,
) -> Result<Box<[u8]>, JsError> {
    let wallet_spends: Vec<WalletCoinSpend> =
        serde_json::from_str(coin_spends_json)
            .map_err(|e| JsError::new(&format!("coin_spends_json parse: {e}")))?;
    let coin_spends: Vec<chia_protocol::CoinSpend> = wallet_spends
        .iter()
        .map(wallet_to_coin_spend)
        .collect::<Result<Vec<_>, _>>()?;
    let sig_bytes = hex::decode(aggregated_signature_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&format!("aggregated_signature hex decode: {e}")))?;
    if sig_bytes.len() != 96 {
        return Err(JsError::new(
            "aggregated_signature must be 96 bytes (BLS G2)",
        ));
    }
    let arr: [u8; 96] = sig_bytes.as_slice().try_into().expect("checked above");
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
