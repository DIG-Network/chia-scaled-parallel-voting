// ============================================================================
// config.rs — immutable per-election configuration constants
// ============================================================================
//
// MODULE: config
// PURPOSE: Hold the deployment-time parameters that get curried into
//          the Election Singleton's puzzle hash, plus protocol-wide
//          constants (TREE_DEPTH, MAX_SIGNERS, EMPTY_LEAF_HASH).
//
// SHARED MODEL: every participant (deployer, voter, aggregator,
//               indexer) loads an identical `ElectionConfig` JSON.
//               The config is public information — no secrets.
//
// SERDE STRATEGY: chia-protocol's `Bytes32` and `chia-bls::PublicKey`
//                 don't expose serde derives, so all 32-byte fields are
//                 stored as hex strings (`*_hex`) with typed accessors
//                 (`*_bytes32()`) that parse on demand.

use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

/// ENUM: NetworkType
/// WHAT: SDK-native network selector. Identifies which Chia network the
///       election runs against — selects the `agg_sig_me_additional_data`
///       (genesis challenge) used when augmenting AGG_SIG conditions
///       at signing time, and the network_id ("mainnet" / "testnet11")
///       for RPC endpoints.
/// USAGE: held by every actor (`Voter`, `Aggregator`, `BallotIssuer`,
///        `ElectionDeployer`); travels through the chain-IO boundary as-is.
/// PORTABILITY: deliberately wasm-buildable — does NOT depend on
///              `dig_l1_wallet` or `chia_query`. Bidirectional `From`
///              conversions to/from `dig_l1_wallet::NetworkType` /
///              `chia_query::NetworkType` are provided behind the
///              `native` feature so callers can interop with the
///              upstream signing / RPC libraries on the host target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet11,
}

impl NetworkType {
    /// Network identifier string used by Chia node RPCs.
    pub fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet11 => "testnet11",
        }
    }
}

// `dig_l1_wallet::NetworkType` is a re-export of `chia_query::NetworkType`,
// so a single pair of From impls covers both upstream callers.
#[cfg(feature = "native")]
impl From<chia_query::NetworkType> for NetworkType {
    fn from(n: chia_query::NetworkType) -> Self {
        match n {
            chia_query::NetworkType::Mainnet => Self::Mainnet,
            chia_query::NetworkType::Testnet11 => Self::Testnet11,
        }
    }
}

#[cfg(feature = "native")]
impl From<NetworkType> for chia_query::NetworkType {
    fn from(n: NetworkType) -> Self {
        match n {
            NetworkType::Mainnet => Self::Mainnet,
            NetworkType::Testnet11 => Self::Testnet11,
        }
    }
}

/// FN: parse_bytes32 (file-private)
/// WHAT: hex string → `Bytes32` with sane error reporting.
/// TRIM: strips surrounding whitespace for ergonomic JSON.
fn parse_bytes32(s: &str) -> Result<Bytes32, &'static str> {
    let bytes = hex::decode(s.trim()).map_err(|_| "invalid hex")?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "expected 32 bytes")?;
    Ok(Bytes32::new(arr))
}

/// CONST: TREE_DEPTH
/// WHAT: SPT depth (= ceil(log2(MAX_VOTERS))). Fixed at 32 → ~4B slots.
/// MIRROR: must equal the curried `TREE_DEPTH` in
///         `puzzles/election/register.rue` and the Groth16 circuit.
pub const TREE_DEPTH: u32 = 32;

/// CONST: MAX_SIGNERS
/// WHAT: hard cap on how many BLS signatures the Groth16 circuit can
///       aggregate per `finalize` proof.
/// IMMUTABLE: baked into the trusted setup. Changing it requires a
///            full new MPC ceremony + redeployment.
pub const MAX_SIGNERS: usize = 20_000;

/// CONST: PUBLIC_INPUT_COUNT
/// WHAT: number of public inputs to the Groth16 circuit. Each input
///       contributes one IC point to the verification key.
/// ORDER: registration_merkle_root, registration_vote_weight,
///        agg_signers, vote_message, threshold_pack,
///        ballot_launcher_id, vote_threshold_num, vote_threshold_den —
///        must match `prover/circuit.rs::Scalars`. The 7th and 8th
///        inputs (`vote_threshold_num` / `vote_threshold_den`) were
///        added under the CHIP rev that promotes (num, den) from
///        compile-time R1CS coefficients to first-class public inputs,
///        so a single VK verifies any (num, den). threshold_pack stays
///        at input #5 as belt-and-suspenders hash binding.
pub const PUBLIC_INPUT_COUNT: usize = 8;

/// CONST: EMPTY_LEAF_HASH
/// WHAT: SHA256(0x00 ⨯ 48) — the canonical empty-leaf marker for the
///       SPT. This is what `sha256(zero_pubkey)` would yield, so the
///       Rue side and SDK side agree on what "no voter here" hashes to.
/// USAGE: passed to the deployer as the curried `EMPTY_LEAF_HASH` arg
///        of `puzzles/election/register.rue`.
pub const EMPTY_LEAF_HASH: [u8; 32] =
    hex_literal::hex!("17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1");

/// FN: cat_mod_hash
/// WHAT: standard CAT v2 outer puzzle hash.
/// SOURCE: `chia_puzzles::CAT_PUZZLE_HASH` — the same constant the
///         rest of the Chia ecosystem uses.
pub fn cat_mod_hash() -> chia_protocol::Bytes32 {
    chia_protocol::Bytes32::new(chia_puzzles::CAT_PUZZLE_HASH)
}

/// STRUCT: ElectionConfig
/// PURPOSE: serialisable election parameters. One file per election.
/// LIFECYCLE: written by the deployer at launch, distributed to all
///            participants, then immutable for the life of the
///            election.
/// SERDE: hex-string fields are serde-friendly; use the typed
///        accessors (`election_launcher_id`, `cat_tail_hash`) for
///        chia-protocol APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionConfig {
    /// Singleton launcher ID. Identifies this election uniquely
    /// across the chain — used in voter hints and AggSigMe messages.
    pub election_launcher_id_hex: String,

    /// CAT TAIL hash of the governance token. Every Registration Coin
    /// is CAT-wrapped with this asset ID, so the tail enforces the
    /// asset's supply rules independent of our SDK.
    pub cat_tail_hash_hex: String,

    /// Per-voter collateral, in CAT mojos.
    pub collateral_amount: u64,

    /// Per-election registration tree depth. Sourced at deploy time
    /// from the chosen ceremony's `max_voters` (depth = ceil(log2)).
    /// Must be in `1..=32`.
    pub tree_depth: u32,

    /// Per-election maximum number of registrations. Sourced at
    /// deploy time from the chosen ceremony's `max_voters`. Must be
    /// `>= 1` and `<= 1 << tree_depth`.
    pub max_signers: usize,

    /// Hex-encoded Groth16 verification key (768 bytes for our
    /// 8-input circuit: 336 base + 9 IC * 48). Produced by the MPC
    /// ceremony.
    pub verification_key_hex: String,

    /// Launcher ID of the trusted-setup ceremony singleton this
    /// election is bound to (V6, ceremony→election link). Defaults
    /// to all-zeros for legacy configs that predate the link;
    /// downstream code treats default as "unlinked".
    #[serde(default)]
    pub ceremony_launcher_id_hex: String,

    /// sha256 of the ceremony's derived Groth16 verifying key (V6).
    /// Defaults to all-zeros for legacy configs.
    #[serde(default)]
    pub vk_hash_hex: String,

    /// Optional UI label.
    #[serde(default)]
    pub label: Option<String>,
}

impl ElectionConfig {
    /// FN: to_json
    /// WHAT: pretty-JSON serialisation for sharing with participants.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("ElectionConfig is always serialisable")
    }

    /// FN: from_json
    /// WHAT: parse a JSON config produced by `to_json`. Round-trip safe.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// FN: election_launcher_id
    /// WHAT: typed accessor for the launcher ID.
    /// ERRORS: hex-decode or length errors in the underlying field.
    pub fn election_launcher_id(&self) -> Result<Bytes32, &'static str> {
        parse_bytes32(&self.election_launcher_id_hex)
    }

    /// FN: cat_tail_hash
    /// WHAT: typed accessor for the CAT TAIL hash.
    pub fn cat_tail_hash(&self) -> Result<Bytes32, &'static str> {
        parse_bytes32(&self.cat_tail_hash_hex)
    }

    /// FN: ceremony_launcher_id
    /// WHAT: typed accessor for the bound ceremony's launcher_id.
    /// FALLBACK: empty hex (legacy configs) → all-zeros sentinel,
    ///           preserving the V6 "unlinked election" semantics.
    pub fn ceremony_launcher_id(&self) -> Bytes32 {
        if self.ceremony_launcher_id_hex.is_empty() {
            Bytes32::default()
        } else {
            parse_bytes32(&self.ceremony_launcher_id_hex).unwrap_or_default()
        }
    }

    /// FN: vk_hash
    /// WHAT: typed accessor for the bound ceremony's vk_hash.
    /// FALLBACK: empty hex → all-zeros sentinel.
    pub fn vk_hash(&self) -> Bytes32 {
        if self.vk_hash_hex.is_empty() {
            Bytes32::default()
        } else {
            parse_bytes32(&self.vk_hash_hex).unwrap_or_default()
        }
    }

    /// FN: validate
    /// WHAT: structural sanity check before using the config.
    /// CHECKS:
    ///   * tree_depth in `1..=32` (the SDK's circuit + EMPTY_LEAF_HASH
    ///     cache support up to 32; depths beyond that aren't compiled)
    ///   * max_signers in `1..=(1 << tree_depth)` (so every registrant
    ///     fits in the tree)
    ///   * launcher / tail hex are decodable Bytes32
    ///   * verification key has the exact length our circuit needs
    ///     (768 bytes = 336 base + (PUBLIC_INPUT_COUNT + 1) * 48 IC,
    ///     i.e. 9 * 48 for our 8-input circuit)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.tree_depth == 0 || self.tree_depth > 32 {
            return Err("ElectionConfig.tree_depth must be in 1..=32");
        }
        if self.max_signers == 0 {
            return Err("ElectionConfig.max_signers must be at least 1");
        }
        let capacity: u64 = 1u64 << self.tree_depth;
        if (self.max_signers as u64) > capacity {
            return Err("ElectionConfig.max_signers exceeds 1 << tree_depth");
        }
        let _ = self.election_launcher_id()?;
        let _ = self.cat_tail_hash()?;
        let expected_vk_bytes = 336 + (PUBLIC_INPUT_COUNT + 1) * 48;
        let vk_bytes = self.verification_key_hex.len() / 2;
        if vk_bytes != expected_vk_bytes {
            return Err(
                "ElectionConfig.verification_key_hex has unexpected length for our circuit",
            );
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn good_config() -> ElectionConfig {
        ElectionConfig {
            election_launcher_id_hex: "11".repeat(32),
            cat_tail_hash_hex: "22".repeat(32),
            collateral_amount: 1_000,
            tree_depth: TREE_DEPTH,
            max_signers: MAX_SIGNERS,
            verification_key_hex: "00".repeat(336 + (PUBLIC_INPUT_COUNT + 1) * 48),
            ceremony_launcher_id_hex: String::new(),
            vk_hash_hex: String::new(),
            label: Some("test".into()),
        }
    }

    /// WHAT: a fully-populated, well-formed config passes
    ///       `.validate()`.
    /// HOW:  build the canonical `good_config()` (using SDK
    ///       constants) and call `.validate().unwrap()`.
    /// WHY:  validates the validator itself — if the canonical good
    ///       case ever started rejecting, every other test below
    ///       (which mutates from this baseline) would be meaningless.
    #[test]
    fn validate_good_config_succeeds() {
        good_config().validate().unwrap();
    }

    /// WHAT: `.validate()` rejects a config whose `tree_depth` is
    ///       outside the supported range `1..=32`.
    /// HOW:  start from `good_config`, set tree_depth = 0 (and
    ///       separately 33), expect `Err` for each.
    /// WHY:  the SDK's circuit + EMPTY_LEAF_HASH cache only support
    ///       depths in 1..=32; values outside that range would corrupt
    ///       every downstream merkle / proof check.
    #[test]
    fn validate_rejects_out_of_range_tree_depth() {
        let mut c = good_config();
        c.tree_depth = 0;
        assert!(c.validate().is_err());
        let mut c = good_config();
        c.tree_depth = 33;
        assert!(c.validate().is_err());
    }

    /// WHAT: a non-default `tree_depth` within `1..=32` validates so
    ///       long as `max_signers` fits in the tree.
    /// HOW:  set tree_depth = 16, max_signers = 1000 (≤ 1<<16), expect
    ///       Ok.
    /// WHY:  E6 makes tree_depth a per-election deploy parameter
    ///       sourced from the ceremony's max_voters — validation must
    ///       accept any depth the SDK's circuit supports, not just 32.
    #[test]
    fn validate_accepts_smaller_tree_depth() {
        let mut c = good_config();
        c.tree_depth = 16;
        c.max_signers = 1000;
        c.validate().unwrap();
    }

    /// WHAT: `.validate()` rejects a config whose `max_signers` is
    ///       zero.
    /// HOW:  set max_signers = 0, expect `Err`.
    /// WHY:  an election with zero allowed registrants is meaningless
    ///       and would divide by zero in downstream tree math.
    #[test]
    fn validate_rejects_zero_max_signers() {
        let mut c = good_config();
        c.max_signers = 0;
        assert!(c.validate().is_err());
    }

    /// WHAT: `.validate()` rejects a config whose `max_signers`
    ///       exceeds `1 << tree_depth` (i.e. won't fit in the tree).
    /// HOW:  set tree_depth = 4 (capacity 16), max_signers = 17,
    ///       expect `Err`.
    /// WHY:  registering more participants than the tree can hold
    ///       would silently overflow leaf indices.
    #[test]
    fn validate_rejects_max_signers_exceeding_tree_capacity() {
        let mut c = good_config();
        c.tree_depth = 4;
        c.max_signers = 17;
        assert!(c.validate().is_err());
    }

    /// WHAT: `.validate()` rejects a non-hex launcher id.
    /// HOW:  set election_launcher_id_hex to literal "not-hex" and
    ///       expect an `Err`.
    /// WHY:  one of the most common manual-edit mistakes in the
    ///       config JSON; failing fast here avoids cryptic errors
    ///       when the typed accessor is later called.
    #[test]
    fn validate_rejects_bad_launcher_hex() {
        let mut c = good_config();
        c.election_launcher_id_hex = "not-hex".into();
        assert!(c.validate().is_err());
    }

    /// WHAT: `.validate()` rejects a launcher id whose hex length
    ///       isn't exactly 64 chars (32 bytes).
    /// HOW:  set election_launcher_id_hex to a 32-char string,
    ///       expect an `Err`.
    /// WHY:  size mismatches sneak past hex-decode but corrupt all
    ///       downstream `Bytes32` arithmetic — must reject early.
    #[test]
    fn validate_rejects_short_launcher_hex() {
        let mut c = good_config();
        c.election_launcher_id_hex = "11".repeat(16);
        assert!(c.validate().is_err());
    }

    /// WHAT: `.validate()` rejects a verification key whose byte
    ///       length doesn't match the circuit's expected layout
    ///       (768 = 336 base + 9 IC * 48 bytes for our 8-input
    ///       circuit).
    /// HOW:  set verification_key_hex to 100-byte zero-buffer, expect
    ///       an `Err`.
    /// WHY:  passing the wrong-size VK to the on-chain finalize
    ///       action would corrupt every Groth16 verification; we
    ///       must catch it at config-load time.
    #[test]
    fn validate_rejects_wrong_vk_length() {
        let mut c = good_config();
        c.verification_key_hex = "00".repeat(100);
        assert!(c.validate().is_err());
    }

    /// WHAT: `to_json` → `from_json` is a lossless round-trip for
    ///       every field of the config.
    /// HOW:  serialise a populated good_config, parse it back, and
    ///       compare every public field individually.
    /// WHY:  the config travels between machines as JSON; field-by-
    ///       field comparison catches accidental field drops or
    ///       rename-induced silent data loss.
    #[test]
    fn json_roundtrip_preserves_all_fields() {
        let c = good_config();
        let json = c.to_json();
        let parsed = ElectionConfig::from_json(&json).unwrap();
        assert_eq!(parsed.election_launcher_id_hex, c.election_launcher_id_hex);
        assert_eq!(parsed.cat_tail_hash_hex, c.cat_tail_hash_hex);
        assert_eq!(parsed.collateral_amount, c.collateral_amount);
        assert_eq!(parsed.tree_depth, c.tree_depth);
        assert_eq!(parsed.max_signers, c.max_signers);
        assert_eq!(parsed.verification_key_hex, c.verification_key_hex);
        assert_eq!(parsed.label, c.label);
    }

    /// WHAT: `election_launcher_id()` and `cat_tail_hash()` return
    ///       byte-exact `Bytes32` values matching the hex source.
    /// HOW:  good_config uses `0x11..11` and `0x22..22` as fixed
    ///       hex strings; assert the typed accessors yield the
    ///       expected `[0x11; 32]` and `[0x22; 32]`.
    /// WHY:  these accessors are how every downstream consumer
    ///       converts JSON → typed Chia primitives. A subtle
    ///       endianness or trim bug would break currying.
    #[test]
    fn typed_accessors_return_correct_bytes32() {
        let c = good_config();
        assert_eq!(c.election_launcher_id().unwrap(), Bytes32::new([0x11; 32]));
        assert_eq!(c.cat_tail_hash().unwrap(), Bytes32::new([0x22; 32]));
    }

    /// WHAT: a config JSON that omits the `label` field still parses
    ///       successfully (label defaults to `None`).
    /// HOW:  hand-craft a minimal JSON without a `label` key, parse,
    ///       assert `label == None`.
    /// WHY:  label is purely cosmetic; parsing must not require it
    ///       so older / programmatically-generated configs work.
    #[test]
    fn label_is_optional_in_json() {
        let json = format!(
            r#"{{
                "election_launcher_id_hex": "{}",
                "cat_tail_hash_hex": "{}",
                "collateral_amount": 1,
                "tree_depth": {TREE_DEPTH},
                "max_signers": {MAX_SIGNERS},
                "verification_key_hex": "{}"
            }}"#,
            "11".repeat(32),
            "22".repeat(32),
            "00".repeat(336 + (PUBLIC_INPUT_COUNT + 1) * 48),
        );
        let parsed = ElectionConfig::from_json(&json).unwrap();
        assert_eq!(parsed.label, None);
    }

    /// WHAT: `cat_mod_hash()` is identical to
    ///       `chia_puzzles::CAT_PUZZLE_HASH`.
    /// HOW:  direct equality assertion.
    /// WHY:  one source of truth for the CAT v2 outer puzzle hash,
    ///       across our SDK and every other Chia tool.
    #[test]
    fn cat_mod_hash_matches_upstream() {
        assert_eq!(cat_mod_hash(), Bytes32::new(chia_puzzles::CAT_PUZZLE_HASH));
    }

    /// WHAT: `EMPTY_LEAF_HASH` actually equals `sha256(0x00 ⨯ 48)`.
    /// HOW:  recompute the sha256 inline and assert equality with
    ///       the const.
    /// WHY:  this is the single most safety-critical constant in the
    ///       SDK — it's what the on-chain register action uses to
    ///       check empty-slot proofs. A previous iteration shipped
    ///       a wrong value here; this test catches that regression.
    #[test]
    fn empty_leaf_hash_is_sha256_of_48_zero_bytes() {
        use sha2::{Digest, Sha256};
        let zero_pk = [0u8; 48];
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&Sha256::digest(zero_pk));
        assert_eq!(arr, EMPTY_LEAF_HASH);
    }
}
