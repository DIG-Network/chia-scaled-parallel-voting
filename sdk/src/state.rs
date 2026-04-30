// ============================================================================
// state.rs — typed mirrors of on-chain Rue state structs
// ============================================================================
//
// MODULE: state
// PURPOSE: Rust-side counterparts to the Rue puzzles' `ElectionState`,
//          `RegistrationState`, plus aggregator/indexer view types
//          (`VoteRecord`, `VoterSet`).
//
// SERDE NOTE: `chia_bls::PublicKey` and `chia_protocol::Bytes32` lack
//             public Serialize/Deserialize impls, so any type that
//             needs to cross a JSON boundary has a `*Wire` companion
//             with hex-encoded fields and a `From<&T>` impl.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

/// STRUCT: ElectionState
/// PURPOSE: state curried into the Election Singleton's action layer.
///          Updated on every spend (`register`, `finalize`,
///          `announce_finalization`).
/// MIRROR: `ElectionState` in `puzzles/election/shared.rue` — the
///         field order here mirrors the Rue tuple layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionState {
    /// SPT root over the set of registered voter pubkeys.
    pub registration_merkle_root: Bytes32,
    /// Count of registered voters.
    pub registration_count: u64,
    /// XCH (mojos) collected from `registration_fee` payments. Paid
    /// out to the finalizer at finalize time.
    pub accumulated_fees: u64,
    /// True after `finalize` runs successfully. Once true, the
    /// singleton can no longer accept registrations or finalize again.
    pub finalized: bool,
    /// Outcome bytes committed at finalization. `0x00..00` until
    /// `finalized == true`.
    pub vote_outcome: Bytes32,
}

impl ElectionState {
    /// FN: genesis
    /// WHAT: state at deployment — empty SPT, nothing accumulated,
    ///       not finalized.
    /// USAGE: passed to `Deployer::build_deploy_bundle` to compute the
    ///        Election Singleton's launch puzzle hash.
    pub fn genesis(empty_root: Bytes32) -> Self {
        Self {
            registration_merkle_root: empty_root,
            registration_count: 0,
            accumulated_fees: 0,
            finalized: false,
            vote_outcome: Bytes32::default(),
        }
    }
}

/// STRUCT: RegistrationState
/// PURPOSE: state curried into a Registration Coin's action layer.
///          Persisted on-chain (in the puzzle hash) so any third
///          party can prove what a given voter has done.
/// MIRROR: `RegistrationState` in `puzzles/registration_coin/shared.rue`.
/// SERDE: not derived because of `PublicKey`. Use
///        [`RegistrationStateWire`] for JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationState {
    /// BLS pubkey of the voter (also drives the SPT slot).
    pub voter_pubkey: PublicKey,
    /// Election this registration belongs to. Binds the coin to a
    /// single election so it can't be replayed elsewhere.
    pub election_launcher_id: Bytes32,
    /// True after the `vote` action runs.
    pub has_voted: bool,
    /// 32-byte vote payload chosen by the voter (raw bytes — voting
    /// schema layered on top is application-specific).
    pub vote_data: Bytes32,
    /// Set by the `release` action. Until then, the CAT collateral
    /// stays locked. Once set, the next finalize on the registration
    /// coin sends the CAT to this destination.
    pub release_destination: Option<Bytes32>,
}

impl RegistrationState {
    /// FN: fresh
    /// WHAT: initial state for a brand-new registration coin.
    /// USAGE: passed to `Voter::register` (and to puzzle-hash predictors
    ///        like `puzzles::fresh_registration_state_tree_hash`).
    pub fn fresh(voter_pubkey: PublicKey, election_launcher_id: Bytes32) -> Self {
        Self {
            voter_pubkey,
            election_launcher_id,
            has_voted: false,
            vote_data: Bytes32::default(),
            release_destination: None,
        }
    }
}

/// STRUCT: RegistrationStateWire
/// PURPOSE: JSON-portable view of `RegistrationState`. Every binary
///          field is hex-encoded.
/// USAGE: persisted to disk by indexers; serialised over HTTP between
///        voter UI and aggregator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationStateWire {
    pub voter_pubkey_hex: String,
    pub election_launcher_id_hex: String,
    pub has_voted: bool,
    pub vote_data_hex: String,
    pub release_destination_hex: Option<String>,
}

impl From<&RegistrationState> for RegistrationStateWire {
    fn from(s: &RegistrationState) -> Self {
        Self {
            voter_pubkey_hex: hex::encode(s.voter_pubkey.to_bytes()),
            election_launcher_id_hex: hex::encode(s.election_launcher_id),
            has_voted: s.has_voted,
            vote_data_hex: hex::encode(s.vote_data),
            release_destination_hex: s.release_destination.map(hex::encode),
        }
    }
}

impl RegistrationStateWire {
    /// FN: into_state
    /// WHAT: parse back to a typed `RegistrationState`.
    /// ERRORS: hex-decode + length errors. Centralised here so call
    ///         sites don't repeat the boilerplate.
    pub fn into_state(self) -> Result<RegistrationState, &'static str> {
        let pk_bytes = hex::decode(&self.voter_pubkey_hex).map_err(|_| "bad voter_pubkey hex")?;
        let pk_arr: [u8; 48] = pk_bytes
            .try_into()
            .map_err(|_| "voter_pubkey must be 48 bytes")?;
        let voter_pubkey = PublicKey::from_bytes(&pk_arr).map_err(|_| "bad BLS pubkey")?;

        let election_id =
            hex::decode(&self.election_launcher_id_hex).map_err(|_| "bad launcher hex")?;
        let election_arr: [u8; 32] = election_id
            .try_into()
            .map_err(|_| "election_launcher_id must be 32 bytes")?;

        let vd = hex::decode(&self.vote_data_hex).map_err(|_| "bad vote_data hex")?;
        let vd_arr: [u8; 32] = vd
            .try_into()
            .map_err(|_| "vote_data must be 32 bytes")?;

        let release = match self.release_destination_hex {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(|_| "bad release_destination hex")?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "release_destination must be 32 bytes")?;
                Some(Bytes32::new(arr))
            }
            None => None,
        };

        Ok(RegistrationState {
            voter_pubkey,
            election_launcher_id: Bytes32::new(election_arr),
            has_voted: self.has_voted,
            vote_data: Bytes32::new(vd_arr),
            release_destination: release,
        })
    }
}

/// STRUCT: VoteRecord
/// PURPOSE: a single voter's tally entry, reconstructed off-chain by
///          the aggregator/indexer from a post-vote Registration Coin's
///          memos (vote_data + vote_signature).
/// SOURCE: produced by `Aggregator::collect_votes`. Memo layout is
///         defined by `puzzles/registration_coin/finalizer.rue`.
#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub voter_pubkey: PublicKey,
    pub vote_data: Bytes32,
    /// 96-byte BLS G2 signature over the canonical vote message
    /// (see `actors::voter::vote_message`).
    pub vote_signature_hex: String,
    /// Coin ID of the post-vote Registration Coin — useful for
    /// proof construction and audit.
    pub registration_coin_id: Bytes32,
}

/// STRUCT: VoteRecordWire
/// PURPOSE: JSON view of `VoteRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteRecordWire {
    pub voter_pubkey_hex: String,
    pub vote_data_hex: String,
    pub vote_signature_hex: String,
    pub registration_coin_id_hex: String,
}

impl From<&VoteRecord> for VoteRecordWire {
    fn from(v: &VoteRecord) -> Self {
        Self {
            voter_pubkey_hex: hex::encode(v.voter_pubkey.to_bytes()),
            vote_data_hex: hex::encode(v.vote_data),
            vote_signature_hex: v.vote_signature_hex.clone(),
            registration_coin_id_hex: hex::encode(v.registration_coin_id),
        }
    }
}

/// STRUCT: VoterSet
/// PURPOSE: snapshot of all registered voters + the SPT root they
///          produce, taken at a single Election Singleton state.
/// USAGE: produced by `Aggregator::sync`, consumed by
///        `prover::VotingCircuit` as private witness.
#[derive(Debug, Clone)]
pub struct VoterSet {
    pub registration_merkle_root: Bytes32,
    pub registration_count: u64,
    pub voters: Vec<PublicKey>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;

    fn pk_at(i: u32) -> PublicKey {
        let root = SecretKey::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root.public_key(), i).derive_synthetic()
    }

    /// WHAT: `ElectionState::genesis` produces a state with all
    ///       counters at 0, `finalized = false`, vote_outcome = zero,
    ///       and the supplied root.
    /// HOW:  call genesis with a recognisable root (`0xAA..AA`) and
    ///       assert every field individually.
    /// WHY:  the deployer curries this exact state into the eve
    ///       singleton's puzzle hash. Any wrong-default field would
    ///       produce a different inner puzzle hash than every other
    ///       SDK consumer expects.
    #[test]
    fn election_genesis_has_zero_counters() {
        let g = ElectionState::genesis(Bytes32::new([0xAA; 32]));
        assert_eq!(g.registration_count, 0);
        assert_eq!(g.accumulated_fees, 0);
        assert!(!g.finalized);
        assert_eq!(g.vote_outcome, Bytes32::default());
        assert_eq!(g.registration_merkle_root, Bytes32::new([0xAA; 32]));
    }

    /// WHAT: `RegistrationState::fresh` sets `has_voted = false`,
    ///       `vote_data = zero`, `release_destination = None`.
    /// HOW:  construct via `fresh`, assert every transient field is
    ///       in its initial state.
    /// WHY:  the registration coin's puzzle hash depends on these
    ///       defaults. The `Voter::register` driver uses this exact
    ///       state to predict the coin's landing puzzle hash.
    #[test]
    fn registration_fresh_has_no_vote_or_release() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]));
        assert!(!s.has_voted);
        assert_eq!(s.vote_data, Bytes32::default());
        assert_eq!(s.release_destination, None);
    }

    /// WHAT: `RegistrationState` → `RegistrationStateWire` →
    ///       `RegistrationState` round-trips losslessly for a fresh
    ///       state.
    /// HOW:  build a fresh state, convert via `From<&_>`, parse via
    ///       `into_state`, assert equality.
    /// WHY:  the wire form crosses JSON / network boundaries; a
    ///       lossy round-trip would corrupt persisted state.
    #[test]
    fn registration_state_wire_roundtrips() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]));
        let wire: RegistrationStateWire = (&s).into();
        let parsed = wire.into_state().unwrap();
        assert_eq!(parsed, s);
    }

    /// WHAT: the wire round-trip preserves `has_voted = true`,
    ///       `vote_data`, AND `release_destination = Some(_)`.
    /// HOW:  mutate every variable field on a fresh state, run the
    ///       round-trip, compare.
    /// WHY:  exercises the non-default code paths in `From<&_>` and
    ///       `into_state` (release_destination_hex = Some/None
    ///       branches). The fresh round-trip alone wouldn't catch
    ///       a bug in the Some-branch.
    #[test]
    fn registration_state_wire_with_release_roundtrips() {
        let mut s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]));
        s.has_voted = true;
        s.vote_data = Bytes32::new([0x42; 32]);
        s.release_destination = Some(Bytes32::new([0xCC; 32]));

        let wire: RegistrationStateWire = (&s).into();
        let parsed = wire.into_state().unwrap();
        assert_eq!(parsed, s);
    }

    /// WHAT: `RegistrationStateWire` is fully JSON-portable —
    ///       `serde_json::to_string` then `from_str` returns an
    ///       equal value.
    /// HOW:  serialise via serde, deserialise, compare.
    /// WHY:  proves the wire form uses only JSON-native types
    ///       (strings, booleans, null) — which is the whole reason
    ///       the wire layer exists, since `PublicKey` and `Bytes32`
    ///       have no native serde impls.
    #[test]
    fn registration_state_wire_json_roundtrip() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]));
        let wire: RegistrationStateWire = (&s).into();
        let json = serde_json::to_string(&wire).unwrap();
        let back: RegistrationStateWire = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wire);
    }

    /// WHAT: `into_state` rejects a wire object whose
    ///       `voter_pubkey_hex` isn't valid hex.
    /// HOW:  hand-craft a wire object with `voter_pubkey_hex =
    ///       "not-hex"`, call `into_state`, assert error.
    /// WHY:  fail-fast on malformed external input — better than
    ///       carrying an invalid pubkey downstream where it would
    ///       cause cryptic BLS verification failures.
    #[test]
    fn registration_state_wire_rejects_bad_pubkey_hex() {
        let bad = RegistrationStateWire {
            voter_pubkey_hex: "not-hex".into(),
            election_launcher_id_hex: "11".repeat(32),
            has_voted: false,
            vote_data_hex: "00".repeat(32),
            release_destination_hex: None,
        };
        assert!(bad.into_state().is_err());
    }

    /// WHAT: `into_state` rejects a wire object whose
    ///       `voter_pubkey_hex` isn't exactly 96 chars (48 bytes).
    /// HOW:  use a 32-char string (well-formed hex, wrong length),
    ///       expect an error.
    /// WHY:  size validation gap is a common bug — hex decoding
    ///       succeeds but the resulting buffer is the wrong size
    ///       for `PublicKey::from_bytes`. Pin the error path here.
    #[test]
    fn registration_state_wire_rejects_short_pubkey() {
        let bad = RegistrationStateWire {
            voter_pubkey_hex: "11".repeat(16),
            election_launcher_id_hex: "11".repeat(32),
            has_voted: false,
            vote_data_hex: "00".repeat(32),
            release_destination_hex: None,
        };
        assert!(bad.into_state().is_err());
    }

    /// WHAT: `VoteRecord` → `VoteRecordWire` round-trips through
    ///       JSON serde without loss.
    /// HOW:  build a populated `VoteRecord`, convert to wire,
    ///       serialise, parse, compare.
    /// WHY:  vote records are exchanged off-chain between voter UI,
    ///       aggregator, and indexer; lossy serialisation would
    ///       silently drop signatures or vote data.
    #[test]
    fn vote_record_wire_roundtrips() {
        let v = VoteRecord {
            voter_pubkey: pk_at(0),
            vote_data: Bytes32::new([0x42; 32]),
            vote_signature_hex: "ab".repeat(96),
            registration_coin_id: Bytes32::new([0x99; 32]),
        };
        let wire: VoteRecordWire = (&v).into();
        let json = serde_json::to_string(&wire).unwrap();
        let back: VoteRecordWire = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wire);
    }

    /// WHAT: `VoterSet` correctly carries `registration_count` and
    ///       a `Vec<PublicKey>` of arbitrary length.
    /// HOW:  build a `VoterSet` with two voters, assert length and
    ///       count fields.
    /// WHY:  basic shape sanity — `VoterSet` is the atom of
    ///       aggregator output, and fields out of sync would mean
    ///       the registration_count differs from `voters.len()`.
    #[test]
    fn voter_set_holds_pubkeys() {
        let vs = VoterSet {
            registration_merkle_root: Bytes32::new([0x11; 32]),
            registration_count: 2,
            voters: vec![pk_at(0), pk_at(1)],
        };
        assert_eq!(vs.voters.len(), 2);
        assert_eq!(vs.registration_count, 2);
    }
}
