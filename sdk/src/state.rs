// ============================================================================
// state.rs — typed mirrors of on-chain Rue state structs
// ============================================================================
//
// MODULE: state
// PURPOSE: Rust-side counterparts to the Rue puzzles' `ElectionState`,
//          `RegistrationState`, `BallotState`, `VotingCoinState`, plus
//          aggregator/indexer view types (`VoteRecord`, `VoterSet`,
//          `BallotCoinSnapshot`, `VotingCoinSnapshot`).
//
// MULTI-BALLOT NOTE: in the multi-ballot architecture (CHIP rev
//                    2026-05-02) the Election Singleton no longer
//                    tracks finalization, vote_outcome, or
//                    accumulated_fees — those fields move to per-ballot
//                    `BallotState`. The Registration Coin no longer
//                    carries a single `vote_data` flag/value — it
//                    carries an SPT root over the ballots the voter
//                    has voted on (`voted_ballots_root`).
//
// SERDE NOTE: `chia_bls::PublicKey` and `chia_protocol::Bytes32` lack
//             public Serialize/Deserialize impls, so any type that
//             needs to cross a JSON boundary has a `*Wire` companion
//             with hex-encoded fields and a `From<&T>` impl.

use chia_bls::PublicKey;
use chia_protocol::{Bytes, Bytes32};
use clvm_traits::{FromClvm, ToClvm};
use serde::{Deserialize, Serialize};

use crate::puzzles;

// ----------------------------------------------------------------------------
// CLVM atom encoding helpers (file-private)
// ----------------------------------------------------------------------------

/// FN: uint_atom_hash
/// WHAT: tree hash of an unsigned integer encoded as a canonical
///       CLVM int atom (minimal big-endian, sign-extended to keep
///       MSB clear).
/// WHY:  Rue `Int` fields hash as variable-length atoms. We need
///       this both for `ElectionState` (count / weight / start_height)
///       and for `BallotState.finalized` (Bool encoded as 0/1 int).
/// USAGE: file-private; reused by the `clvm_tree_hash` methods below.
fn uint_atom_hash(n: u64) -> Bytes32 {
    if n == 0 {
        return puzzles::hash_atom(&[]);
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let mut payload = bytes[first_nonzero..].to_vec();
    if !payload.is_empty() && payload[0] & 0x80 != 0 {
        payload.insert(0, 0);
    }
    puzzles::hash_atom(&payload)
}

// ----------------------------------------------------------------------------
// ElectionState
// ----------------------------------------------------------------------------

/// STRUCT: ElectionState
/// PURPOSE: state curried into the Election Singleton's action layer.
///          Updated on every spend (`register`, `deregister`).
/// MIRROR: `ElectionState` in `puzzles/election/shared.rue`.
///         Field order matches the Rue tuple layout. The last field
///         (`vk_hash`, post-V5) is declared with the rest-arg `...`
///         prefix in Rue, so the on-chain cons tree shape is
///         `(root . (count . (weight . (start_height . (ceremony_launcher_id . (max_voters . vk_hash))))))`
///         — no trailing nil pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionState {
    /// SPT root over the set of registered voter pubkeys.
    pub registration_merkle_root: Bytes32,
    /// Count of registered voters.
    pub registration_count: u64,
    /// Total vote weight contributed by registered voters (sum of
    /// CAT collateral amounts; ballots use this to weight votes).
    pub registration_vote_weight: u64,
    /// Block height at which this election was launched. Curried-
    /// equivalent constants (epoch lengths, etc.) are computed
    /// relative to this anchor.
    pub election_start_height: u64,
    /// Launcher ID of the trusted-setup ceremony singleton this
    /// election is bound to. Set at genesis from DeployParams,
    /// propagated unchanged by every action.
    pub ceremony_launcher_id: Bytes32,
    /// Registration capacity (= 1 << TREE_DEPTH of the curried SPT).
    /// Sourced from the chosen ceremony's `max_voters` via the
    /// co-spent voucher's canonical announcement.
    pub max_voters: u64,
    /// sha256 of the ceremony's derived Groth16 verifying key.
    /// Committed in state so on-chain consumers can verify the
    /// election uses the exact VK the bound ceremony produced.
    pub vk_hash: Bytes32,
    /// M2: per-election ballot-mode lock. Sentinel
    /// `crate::vote_mode::VOTE_MODE_LOCK_NONE` (= 0xFF…FF) means
    /// "no lock" (each ballot picks its own vote_options_root). Any
    /// other value forces every ballot's curried VOTE_OPTIONS_ROOT
    /// to equal this value byte-for-byte. Propagated unchanged by
    /// register/deregister.
    pub vote_mode_lock: Bytes32,
}

impl ElectionState {
    /// FN: genesis
    /// WHAT: state at deployment — empty SPT, zero registration
    ///       count and weight, anchored to a launch height with the
    ///       full ceremony back-reference triple.
    /// USAGE: passed to `Deployer::build_deploy_bundle` to compute
    ///        the Election Singleton's launch puzzle hash. Note:
    ///        callers that don't yet know the start height (e.g.
    ///        unit tests that pre-compute hashes) can pass 0.
    pub fn genesis(
        empty_root: Bytes32,
        election_start_height: u64,
        ceremony_launcher_id: Bytes32,
        max_voters: u64,
        vk_hash: Bytes32,
        vote_mode_lock: Bytes32,
    ) -> Self {
        Self {
            registration_merkle_root: empty_root,
            registration_count: 0,
            registration_vote_weight: 0,
            election_start_height,
            ceremony_launcher_id,
            max_voters,
            vk_hash,
            vote_mode_lock,
        }
    }

    /// FN: genesis_from_config
    /// WHAT: convenience constructor that pulls the V6 ceremony
    ///       back-reference triple (ceremony_launcher_id, max_voters,
    ///       vk_hash) from an `ElectionConfig`. Used by every actor
    ///       that needs to predict the deployer's committed genesis
    ///       state hash from the public config alone (voter,
    ///       aggregator, indexer).
    pub fn genesis_from_config(
        empty_root: Bytes32,
        election_start_height: u64,
        config: &crate::config::ElectionConfig,
    ) -> Self {
        Self::genesis(
            empty_root,
            election_start_height,
            config.ceremony_launcher_id(),
            config.max_signers as u64,
            config.vk_hash(),
            // M2 defaults to no-lock for legacy/empty-config callers;
            // the deployer overrides via `genesis_state_tree_hash`.
            crate::vote_mode::VOTE_MODE_LOCK_NONE,
        )
    }

    /// FN: clvm_tree_hash
    /// WHAT: tree hash of the on-chain cons tree for this state.
    /// SHAPE: `(root . (count . (weight . (start_height . (
    ///        ceremony_launcher_id . (max_voters . vk_hash))))))`
    ///        — the trailing-tail layout produced by Rue's
    ///        `...vk_hash` syntax in `puzzles/election/shared.rue`.
    /// USAGE: backbone of singleton-state puzzle-hash prediction —
    ///        every singleton spend's lineage proof needs the
    ///        previous coin's exact inner puzzle hash, which depends
    ///        on the state at THAT coin.
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        let root_h = puzzles::hash_atom_b32(&self.registration_merkle_root);
        let count_h = uint_atom_hash(self.registration_count);
        let weight_h = uint_atom_hash(self.registration_vote_weight);
        let start_h = uint_atom_hash(self.election_start_height);
        let cer_h = puzzles::hash_atom_b32(&self.ceremony_launcher_id);
        let max_h = uint_atom_hash(self.max_voters);
        let vk_h = puzzles::hash_atom_b32(&self.vk_hash);
        let lock_h = puzzles::hash_atom_b32(&self.vote_mode_lock);

        // M2 rest-arg shape:
        // (root . (count . (weight . (start . (cer . (max . (vk . lock)))))))
        let pair = puzzles::hash_pair(vk_h, lock_h);
        let pair = puzzles::hash_pair(max_h, pair);
        let pair = puzzles::hash_pair(cer_h, pair);
        let pair = puzzles::hash_pair(start_h, pair);
        let pair = puzzles::hash_pair(weight_h, pair);
        let pair = puzzles::hash_pair(count_h, pair);
        puzzles::hash_pair(root_h, pair)
    }
}

// ----------------------------------------------------------------------------
// RegistrationState
// ----------------------------------------------------------------------------

/// STRUCT: RegistrationState
/// PURPOSE: state curried into a Registration Coin's action layer.
///          Persisted on-chain (in the puzzle hash) so any third
///          party can prove what a given voter has done.
/// MIRROR: `RegistrationState` in
///         `puzzles/registration_coin/shared.rue`. Field order
///         matches the Rue struct: `(voter_pubkey,
///         election_launcher_id, voted_ballots_root,
///         ...release_destination)` — `release_destination` is the
///         rest-arg field.
/// SERDE: not derived because of `PublicKey`. Use
///        [`RegistrationStateWire`] for JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationState {
    /// BLS pubkey of the voter (also drives the SPT slot).
    pub voter_pubkey: PublicKey,
    /// Election this registration belongs to. Binds the coin to a
    /// single election so it can't be replayed elsewhere.
    pub election_launcher_id: Bytes32,
    /// SPT root over the ballots this voter has voted on.
    /// Initialised to `puzzles::empty_ballot_root()` at registration
    /// time and updated by the vote action.
    pub voted_ballots_root: Bytes32,
    /// SEC-F2: CAT mojos the voter actually locked at register time
    /// (== the registration SMT leaf weight finalize counts). The
    /// registration-coin actions `AssertMyAmount(locked_weight)`, so the
    /// coin must really hold this many CAT — a forged leaf weight cannot
    /// cast a counted vote nor release more than was staked.
    pub locked_weight: u64,
    /// Set by the `release` action. Until then, the CAT collateral
    /// stays locked. Once set, the next finalize on the registration
    /// coin sends the CAT to this destination.
    pub release_destination: Option<Bytes32>,
}

impl RegistrationState {
    /// FN: fresh
    /// WHAT: initial state for a brand-new registration coin.
    ///       `voted_ballots_root = empty_ballot_root()` — the
    ///       all-empty per-voter ballot SPT — and
    ///       `release_destination = None`.
    /// USAGE: passed to `Voter::register` (and to puzzle-hash
    ///        predictors like
    ///        `puzzles::fresh_registration_state_tree_hash`).
    pub fn fresh(
        voter_pubkey: PublicKey,
        election_launcher_id: Bytes32,
        locked_weight: u64,
    ) -> Self {
        Self {
            voter_pubkey,
            election_launcher_id,
            voted_ballots_root: puzzles::empty_ballot_root(),
            locked_weight,
            release_destination: None,
        }
    }

    /// FN: clvm_tree_hash
    /// WHAT: tree hash of the on-chain cons tree for this state.
    /// IMPL: delegates to
    ///       `puzzles::fresh_registration_state_tree_hash` so the
    ///       hash composition has a single source of truth.
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        puzzles::fresh_registration_state_tree_hash(
            &self.voter_pubkey,
            self.election_launcher_id,
            self.voted_ballots_root,
            self.locked_weight,
            self.release_destination,
        )
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
    pub voted_ballots_root_hex: String,
    pub locked_weight: u64,
    pub release_destination_hex: Option<String>,
}

impl From<&RegistrationState> for RegistrationStateWire {
    fn from(s: &RegistrationState) -> Self {
        Self {
            voter_pubkey_hex: hex::encode(s.voter_pubkey.to_bytes()),
            election_launcher_id_hex: hex::encode(s.election_launcher_id),
            voted_ballots_root_hex: hex::encode(s.voted_ballots_root),
            locked_weight: s.locked_weight,
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

        let vbr =
            hex::decode(&self.voted_ballots_root_hex).map_err(|_| "bad voted_ballots_root hex")?;
        let vbr_arr: [u8; 32] = vbr
            .try_into()
            .map_err(|_| "voted_ballots_root must be 32 bytes")?;

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
            voted_ballots_root: Bytes32::new(vbr_arr),
            locked_weight: self.locked_weight,
            release_destination: release,
        })
    }
}

// ----------------------------------------------------------------------------
// BallotState
// ----------------------------------------------------------------------------

/// STRUCT: BallotState
/// PURPOSE: state curried into a Ballot Coin's action layer.
///          Holds the running tally and, after finalization, the
///          committed outcome plus the aggregated signer set that
///          endorsed it.
/// MIRROR: `BallotState` in `puzzles/ballot_coin/shared.rue`.
///         The trailing field (`agg_signers`) uses Rue's `...`
///         rest-arg prefix, so the cons tree shape is
///         `(finalized . (vote_outcome . agg_signers))`.
/// SERDE: derived directly — every field is JSON-friendly (`bool`
///        and `Bytes32` via the existing helpers Bytes32
///        deserialises from a length-32 byte array, but we keep
///        non-serde derives here; if a JSON form is needed callers
///        should add a `*Wire` variant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotState {
    /// `false` until the finalize action runs; `true` after.
    pub finalized: bool,
    /// Zero (32 bytes of `0x00`) until finalized; the committed
    /// outcome bytes once finalized.
    pub vote_outcome: Bytes32,
    /// Zero until finalized; commitment to the set of registered
    /// voters who contributed to the aggregate signature for this
    /// ballot. Encoding (e.g. packed-bitvector hash, Merkle root)
    /// MUST match `circuit.rs` and `ballot_coin/finalize.rue`.
    pub agg_signers: Bytes32,
}

impl BallotState {
    /// FN: fresh
    /// WHAT: initial state for a brand-new Ballot Coin: not
    ///       finalized, zero outcome, zero signer set.
    pub fn fresh() -> Self {
        Self {
            finalized: false,
            vote_outcome: Bytes32::default(),
            agg_signers: Bytes32::default(),
        }
    }

    /// FN: clvm_tree_hash
    /// WHAT: tree hash of the on-chain cons tree for this state.
    /// SHAPE: `(finalized . (vote_outcome . agg_signers))` — the
    ///        rest-arg layout from
    ///        `puzzles/ballot_coin/shared.rue`.
    /// BOOL ENCODING: Rue `Bool` is the integer atom — `false` is
    ///                the empty atom (canonical zero), `true` is the
    ///                atom containing the single byte `0x01`.
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        let finalized_h = uint_atom_hash(self.finalized as u64);
        let outcome_h = puzzles::hash_atom_b32(&self.vote_outcome);
        let signers_h = puzzles::hash_atom_b32(&self.agg_signers);

        // Rest-arg shape: (finalized . (vote_outcome . agg_signers))
        let pair = puzzles::hash_pair(outcome_h, signers_h);
        puzzles::hash_pair(finalized_h, pair)
    }
}

// ----------------------------------------------------------------------------
// BallotCoinSnapshot
// ----------------------------------------------------------------------------

/// STRUCT: BallotCoinSnapshot
/// PURPOSE: Rust-side aggregate view of an observed Ballot Coin —
///          its launch parameters (curried constants) plus its
///          current `BallotState` and on-chain coin id.
/// SOURCE: produced by indexer/aggregator code that walks the chain
///         for a given ballot launcher id. NOT an on-chain struct —
///         hence no `clvm_tree_hash` method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BallotCoinSnapshot {
    /// Singleton launcher id of this Ballot Coin. Curried into
    /// every action and used as the per-ballot identity.
    pub ballot_launcher_id: Bytes32,
    /// Election this ballot belongs to (curried).
    pub election_launcher_id: Bytes32,
    /// Block height at which voting closes (curried).
    pub vote_close_height: u64,
    /// Curried domain-separation hash for the outcome encoding —
    /// pins down what `vote_outcome` actually represents for this
    /// ballot.
    pub outcome_domain_hash: Bytes32,
    /// Current ballot state (`finalized`, `vote_outcome`,
    /// `agg_signers`).
    pub state: BallotState,
    /// Observed coin id of the latest Ballot Coin singleton.
    pub coin_id: Bytes32,
    /// Curried into the `finalize` action — numerator of the ballot's
    /// quorum threshold. `None` for legacy ballots minted before the
    /// launcher curry-memo was added (pre-CHIP rev 2026-05-07).
    /// Cross-browser observers should fall back to bootstrap when
    /// this is `None`.
    pub vote_threshold_num: Option<u64>,
    /// Curried into the `finalize` action — denominator of the ballot's
    /// quorum threshold. `None` for legacy ballots; see
    /// `vote_threshold_num`.
    pub vote_threshold_den: Option<u64>,
    /// Curried into the `finalize` action — Election Singleton's
    /// `registration_merkle_root` snapshotted at launch time. `None`
    /// for legacy ballots.
    pub registration_merkle_root_snapshot: Option<Bytes32>,
    /// Curried into the `finalize` action — sum of locked CAT
    /// collateral (per-voter weight) snapshotted at launch time.
    /// Drives the threshold computation:
    ///   required_signed_weight =
    ///       ceil(registration_vote_weight_snapshot
    ///            * vote_threshold_num / vote_threshold_den)
    /// `None` for legacy ballots.
    pub registration_vote_weight_snapshot: Option<u64>,
    /// M8: per-ballot vote-mode commitment recovered from the launcher
    /// memo. `Bytes32::default()` (= 0x00…00) means Mode1Free; any
    /// other value is the sorted-options merkle root the Ballot Coin
    /// is curried with (Mode2Restricted). `None` for legacy ballots
    /// (pre-M8 launcher-memo schema v1) — same fallback rule as the
    /// other Option fields above.
    pub vote_options_root: Option<Bytes32>,
}

// ----------------------------------------------------------------------------
// BallotLauncherMemo
// ----------------------------------------------------------------------------

/// Magic schema tag prefix written into the launcher second-spend's
/// `key_value_list` so chain readers can recognize a CHIP ballot
/// curry memo and version-gate future schema changes.
///
/// v2 (M8): adds `vote_options_root` after `registration_vote_weight_snapshot`
/// so cross-browser readers can recover the per-ballot vote-mode
/// commitment from chain alone. v1 readers see the v2 tag and
/// gracefully return None (different schema_tag bytes); v2 readers
/// reject v1 the same way. The change is intentional —
/// the layout grew, so a v1 decode would silently mis-bind the new field.
pub const BALLOT_LAUNCHER_MEMO_TAG: &[u8] = b"chip:ballot:v2";

/// STRUCT: BallotLauncherMemo
/// PURPOSE: on-chain commitment to the per-ballot curry params,
///          written as the launcher second-spend's `key_value_list`.
///          Lets ANY chain reader (cross-browser observer,
///          share-bundle importer, third-party indexer) recover the
///          full ballot curry directly from chain — no off-chain
///          metadata needed. Mirrors the inputs to
///          `BallotIssuer::launch_ballot`.
/// SOURCE: written by `BallotIssuer::launch_ballot`; read by
///         `read_ballot_launcher_memo` in `actors/ballot.rs`, which is
///         called by `list_ballots_via_chain` and
///         `get_ballot_via_chain` to populate `BallotCoinSnapshot`'s
///         optional curry fields.
/// LAYOUT: tagged CLVM list. First field is `BALLOT_LAUNCHER_MEMO_TAG`
///         for forward-compat schema versioning; remaining fields are
///         the curry params in stable order (matches the order curried
///         into the `finalize` action puzzle).
#[derive(Clone, Debug, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct BallotLauncherMemo {
    pub schema_tag: Bytes,
    pub vote_close_height: u64,
    pub outcome_domain_hash: Bytes32,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot: Bytes32,
    pub registration_vote_weight_snapshot: u64,
    /// M8: per-ballot vote-mode commitment. `Bytes32::default()`
    /// (= 0x00…00) for Mode1Free; otherwise a sorted-options merkle
    /// root for Mode2Restricted. Curried into the Ballot Coin's
    /// oracle action so cross-browser dApps recover it from chain.
    pub vote_options_root: Bytes32,
}

/// SCHEMA TAG: prefix the on-chain ceremony launcher memo with this
/// constant so future readers can identify the schema version. Bumped
/// when the memo layout changes incompatibly. v2 (E3) adds
/// `max_voters` so cross-browser readers can recover the circuit's
/// SPT depth from chain alone.
pub const CEREMONY_LAUNCHER_MEMO_TAG: &[u8] = b"chip:ceremony:v2";

/// STRUCT: CeremonyLauncherMemo
/// PURPOSE: on-chain commitment to the per-ceremony curry params,
///          written as the launcher second-spend's `key_value_list`.
///          Lets ANY chain reader (cross-browser dApp, third-party
///          indexer, redeploy after losing localStorage) recover the
///          full ceremony bootstrap from chain alone — no off-chain
///          metadata needed.
/// SOURCE: written by `CeremonyDeployer::build_deploy_bundle`; read by
///         `recover_ceremony_bootstrap_via_chain` in `actors/ceremony.rs`.
/// LAYOUT: tagged CLVM list. First field is `CEREMONY_LAUNCHER_MEMO_TAG`
///         for forward-compat schema versioning; remaining fields are
///         the deployment params in stable order (matches the inputs
///         to `CeremonyParams`). `label_bytes` is empty when no label
///         was supplied (label is dApp-only display metadata).
///
/// v2 (E3): adds `max_voters` after `min_participants`. v1 readers
/// see the v2 tag and gracefully return None (different schema_tag
/// bytes); v2 readers reject v1 the same way. This is intentional —
/// the layout grew so a v1 decode would silently mis-bind the new
/// field.
#[derive(Clone, Debug, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct CeremonyLauncherMemo {
    pub schema_tag: Bytes,
    pub start_block_height: u64,
    pub ceremony_length_blocks: u64,
    pub min_participants: u64,
    pub max_voters: u64,
    pub vk_seed: Bytes32,
    pub label_bytes: Bytes,
}

// ----------------------------------------------------------------------------
// VotingCoinState
// ----------------------------------------------------------------------------

/// STRUCT: VotingCoinState
/// PURPOSE: state curried into a Voting Coin — the ephemeral bridge
///          coin that carries a vote from a Registration Coin to a
///          Ballot Coin in a single spend bundle.
/// MIRROR: `VotingCoinState` in
///         `puzzles/voting_coin/shared.rue`. Field order:
///         `(voter_pubkey, ballot_launcher_id, vote_data,
///         ...registration_coin_id)` — `registration_coin_id` is
///         the rest-arg field.
/// PUBKEY ENCODING: `voter_pubkey` is `Bytes` here (mirroring the
///                  historical Rust convention) even though Rue
///                  declares it as `PublicKey`. Callers serialise
///                  the 48-byte BLS G1 encoding into this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingCoinState {
    /// 48-byte BLS G1 pubkey of the voter (raw bytes — see note).
    pub voter_pubkey: Bytes,
    /// Launcher id of the Ballot Coin this vote targets (curried so
    /// the on-chain coin id is unforgeably bound to the ballot).
    pub ballot_launcher_id: Bytes32,
    /// 32-byte hash the voter commits to. Synonymous with
    /// `vote_outcome` in `vote_message(...)` and the Groth16 public
    /// input — kept under two names for legacy / ergonomic reasons.
    pub vote_data: Bytes32,
    /// Coin id of the spending Registration Coin — lets the Ballot
    /// Coin assert participation without re-deriving the
    /// Registration Coin's puzzle hash.
    pub registration_coin_id: Bytes32,
}

impl VotingCoinState {
    /// FN: clvm_tree_hash
    /// WHAT: tree hash of the on-chain cons tree for this state.
    /// SHAPE: `(voter_pubkey . (ballot_launcher_id . (vote_data .
    ///         registration_coin_id)))` — the rest-arg layout from
    ///        `puzzles/voting_coin/shared.rue`.
    /// IMPL: composes directly via the file-local helpers (rather
    ///       than delegating to `puzzles::voting_coin_state_tree_hash`,
    ///       which takes a typed `&PublicKey`) — this method works
    ///       with the raw-bytes `voter_pubkey` representation we
    ///       use here.
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        let pk_h = puzzles::hash_atom(self.voter_pubkey.as_ref());
        let bli_h = puzzles::hash_atom_b32(&self.ballot_launcher_id);
        let vd_h = puzzles::hash_atom_b32(&self.vote_data);
        let rci_h = puzzles::hash_atom_b32(&self.registration_coin_id);

        // Rest-arg shape: (pk . (bli . (vd . rci)))
        let pair = puzzles::hash_pair(vd_h, rci_h);
        let pair = puzzles::hash_pair(bli_h, pair);
        puzzles::hash_pair(pk_h, pair)
    }
}

// ----------------------------------------------------------------------------
// CeremonyState
// ----------------------------------------------------------------------------

/// STRUCT: CeremonyState
/// PURPOSE: state curried into the Ceremony Singleton — tracks the
///          linear lineage of accepted Groth16 contributions.
/// MIRROR: `CeremonyState` in
///         `puzzles/ceremony_singleton/shared.rue`. Field order:
///         `(contribution_count, ...last_contribution_hash)` —
///         `last_contribution_hash` is the rest-arg field.
/// SEMANTICS:
///   * `contribution_count` — number of accepted contributions; 0
///                            before the genesis contributor lands.
///   * `last_contribution_hash` — CONTRIBUTION_HASH of the most-recent
///                                accepted contribution; equals the
///                                deployer's curried `vk_seed` before
///                                any contribution lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyState {
    pub contribution_count: u64,
    pub last_contribution_hash: Bytes32,
    /// Set true by the finalize action once the threshold is met and
    /// the window has closed. Blocks further contribute spends.
    pub finalized: bool,
    /// SHA-256 hash of the derived Groth16 VK bytes. Bytes32::default()
    /// pre-finalize.
    pub vk_hash: Bytes32,
    /// SHA-256 binary-tree merkle root over the sorted marker coin ids
    /// of every accepted contribution. Bytes32::default() pre-finalize.
    pub marker_root: Bytes32,
}

impl CeremonyState {
    /// FN: genesis
    /// WHAT: initial state for a brand-new Ceremony Singleton:
    ///       count=0, last_contribution_hash=`vk_seed`,
    ///       finalized=false, vk_hash + marker_root zeroed.
    pub fn genesis(vk_seed: Bytes32) -> Self {
        Self {
            contribution_count: 0,
            last_contribution_hash: vk_seed,
            finalized: false,
            vk_hash: Bytes32::default(),
            marker_root: Bytes32::default(),
        }
    }

    /// FN: clvm_tree_hash
    /// WHAT: tree hash of the on-chain cons tree for this state.
    /// SHAPE: `(count . (last_hash . (finalized . (vk_hash . marker_root))))`
    ///        — rest-arg nested cons matching
    ///        `puzzles/ceremony_singleton/shared.rue`.
    /// BOOL ENCODING: `finalized` hashes as `uint_atom_hash(0|1)` —
    ///        Rue's `Int` field with values {0, 1}.
    pub fn clvm_tree_hash(&self) -> Bytes32 {
        let count_h = uint_atom_hash(self.contribution_count);
        let last_h = puzzles::hash_atom_b32(&self.last_contribution_hash);
        let finalized_h = uint_atom_hash(if self.finalized { 1 } else { 0 });
        let vk_hash_h = puzzles::hash_atom_b32(&self.vk_hash);
        let marker_root_h = puzzles::hash_atom_b32(&self.marker_root);
        // Inside-out cons assembly: (vk_hash . marker_root) first.
        let pair4 = puzzles::hash_pair(vk_hash_h, marker_root_h);
        let pair3 = puzzles::hash_pair(finalized_h, pair4);
        let pair2 = puzzles::hash_pair(last_h, pair3);
        puzzles::hash_pair(count_h, pair2)
    }
}

// ----------------------------------------------------------------------------
// VotingCoinSnapshot
// ----------------------------------------------------------------------------

/// STRUCT: VotingCoinSnapshot
/// PURPOSE: Rust-side aggregate view of an observed Voting Coin —
///          its identity (coin id), curried state, and the BLS G2
///          signature emitted alongside the spend.
/// SOURCE: produced by aggregator/indexer code that observes a
///         vote bundle on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingCoinSnapshot {
    /// Observed coin id of the Voting Coin.
    pub coin_id: Bytes32,
    /// Curried state of the Voting Coin.
    pub state: VotingCoinState,
    /// 96-byte BLS G2 signature over `vote_message(vote_outcome,
    /// ballot_launcher_id, election_launcher_id)` — verified by the
    /// Ballot Coin's vote action.
    pub latest_signature: Bytes,
}

// ----------------------------------------------------------------------------
// VoteRecord / VoteRecordWire
// ----------------------------------------------------------------------------

/// STRUCT: VoteRecord
/// PURPOSE: a single voter's tally entry, reconstructed off-chain by
///          the aggregator/indexer from a vote bundle's memos and
///          signature.
/// SOURCE: produced by `Aggregator::collect_votes`. Memo layout is
///         defined by the relevant Ballot/Voting Coin actions.
#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub voter_pubkey: PublicKey,
    pub vote_data: Bytes32,
    /// 96-byte BLS G2 signature over the canonical vote message
    /// (see `actors::voter::vote_message` /
    /// `puzzles/voting_coin/shared.rue::vote_message`).
    pub vote_signature_hex: String,
    /// Coin id of the Registration Coin whose vote action created
    /// the Voting Coin — useful for proof construction and audit.
    pub registration_coin_id: Bytes32,
    /// Launcher id of the Ballot Coin this vote was cast on.
    /// Multiple vote records per voter are now possible (one per
    /// ballot), so the ballot id is part of the record's identity.
    pub ballot_launcher_id: Bytes32,
    /// Coin id of the Voting Coin produced and consumed in the
    /// vote bundle — primary anchor when reconciling votes against
    /// observed on-chain spends.
    pub voting_coin_id: Bytes32,
}

/// STRUCT: VoteRecordWire
/// PURPOSE: JSON view of `VoteRecord`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteRecordWire {
    pub voter_pubkey_hex: String,
    pub vote_data_hex: String,
    pub vote_signature_hex: String,
    pub registration_coin_id_hex: String,
    pub ballot_launcher_id_hex: String,
    pub voting_coin_id_hex: String,
}

impl From<&VoteRecord> for VoteRecordWire {
    fn from(v: &VoteRecord) -> Self {
        Self {
            voter_pubkey_hex: hex::encode(v.voter_pubkey.to_bytes()),
            vote_data_hex: hex::encode(v.vote_data),
            vote_signature_hex: v.vote_signature_hex.clone(),
            registration_coin_id_hex: hex::encode(v.registration_coin_id),
            ballot_launcher_id_hex: hex::encode(v.ballot_launcher_id),
            voting_coin_id_hex: hex::encode(v.voting_coin_id),
        }
    }
}

// ----------------------------------------------------------------------------
// VoterSet
// ----------------------------------------------------------------------------

/// STRUCT: VoterSet
/// PURPOSE: snapshot of all registered voters + the SPT root they
///          produce, taken at a single Election Singleton state.
/// USAGE: produced by `Aggregator::sync`, consumed by
///        `prover::VotingCircuit` as private witness. Unaffected
///        by ballot semantics — this is purely a registration-set
///        SPT snapshot.
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
    ///       counters at 0, the supplied root, and the supplied
    ///       start height.
    /// HOW:  call genesis with a recognisable root (`0xAA..AA`) and
    ///       a start height of `1234`, assert every field
    ///       individually.
    /// WHY:  the deployer curries this exact state into the eve
    ///       singleton's puzzle hash. Any wrong-default field would
    ///       produce a different inner puzzle hash than every other
    ///       SDK consumer expects.
    #[test]
    fn election_genesis_has_zero_counters() {
        let g = ElectionState::genesis(Bytes32::new([0xAA; 32]), 1234, Bytes32::default(), 0u64, Bytes32::default(), crate::vote_mode::VOTE_MODE_LOCK_NONE);
        assert_eq!(g.registration_count, 0);
        assert_eq!(g.registration_vote_weight, 0);
        assert_eq!(g.election_start_height, 1234);
        assert_eq!(g.registration_merkle_root, Bytes32::new([0xAA; 32]));
    }

    /// WHAT: `ElectionState::clvm_tree_hash` is deterministic —
    ///       equal states produce equal hashes, and a single field
    ///       perturbation flips the hash.
    /// HOW:  compute the hash for two equal genesis states and
    ///       assert equality; compute again with a bumped count and
    ///       assert inequality.
    /// WHY:  this hash drives every singleton lineage proof.
    ///       Determinism + sensitivity to every field is the
    ///       minimum correctness contract.
    #[test]
    fn election_state_tree_hash_is_deterministic_and_field_sensitive() {
        let a = ElectionState::genesis(Bytes32::new([0xAA; 32]), 1234, Bytes32::default(), 0u64, Bytes32::default(), crate::vote_mode::VOTE_MODE_LOCK_NONE);
        let b = ElectionState::genesis(Bytes32::new([0xAA; 32]), 1234, Bytes32::default(), 0u64, Bytes32::default(), crate::vote_mode::VOTE_MODE_LOCK_NONE);
        assert_eq!(a.clvm_tree_hash(), b.clvm_tree_hash());

        let mut c = a.clone();
        c.registration_count = 1;
        assert_ne!(a.clvm_tree_hash(), c.clvm_tree_hash());
    }

    /// WHAT: `RegistrationState::fresh` sets `voted_ballots_root`
    ///       to the all-empty root and `release_destination` to
    ///       `None`.
    /// HOW:  construct via `fresh`, assert every transient field is
    ///       in its initial state.
    /// WHY:  the registration coin's puzzle hash depends on these
    ///       defaults. The `Voter::register` driver uses this exact
    ///       state to predict the coin's landing puzzle hash.
    #[test]
    fn registration_fresh_starts_with_empty_ballot_root_and_no_release() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]), 1_000);
        assert_eq!(s.voted_ballots_root, puzzles::empty_ballot_root());
        assert_eq!(s.release_destination, None);
    }

    /// WHAT: `RegistrationState::clvm_tree_hash` agrees with
    ///       `puzzles::fresh_registration_state_tree_hash` —
    ///       guaranteeing a single source of truth.
    /// HOW:  build a fresh state, compute both ways, compare.
    /// WHY:  deployer / voter / aggregator drivers all reach for
    ///       one or the other; if they ever drifted, lineage proofs
    ///       would silently desync.
    #[test]
    fn registration_state_tree_hash_matches_puzzles_helper() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]), 1_000);
        let via_method = s.clvm_tree_hash();
        let via_helper = puzzles::fresh_registration_state_tree_hash(
            &s.voter_pubkey,
            s.election_launcher_id,
            s.voted_ballots_root,
            s.locked_weight,
            s.release_destination,
        );
        assert_eq!(via_method, via_helper);
    }

    /// WHAT: `RegistrationState` ↔ `RegistrationStateWire` round-trips
    ///       losslessly for a fresh state.
    /// HOW:  build a fresh state, convert via `From<&_>`, parse via
    ///       `into_state`, assert equality.
    /// WHY:  the wire form crosses JSON / network boundaries; a
    ///       lossy round-trip would corrupt persisted state.
    #[test]
    fn registration_state_wire_roundtrips() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]), 1_000);
        let wire: RegistrationStateWire = (&s).into();
        let parsed = wire.into_state().unwrap();
        assert_eq!(parsed, s);
    }

    /// WHAT: the wire round-trip preserves a custom
    ///       `voted_ballots_root` AND `release_destination =
    ///       Some(_)`.
    /// HOW:  mutate every variable field on a fresh state, run the
    ///       round-trip, compare.
    /// WHY:  exercises the non-default code paths in `From<&_>` and
    ///       `into_state` (release_destination_hex = Some/None
    ///       branches). The fresh round-trip alone wouldn't catch
    ///       a bug in the Some-branch.
    #[test]
    fn registration_state_wire_with_release_roundtrips() {
        let mut s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]), 1_000);
        s.voted_ballots_root = Bytes32::new([0x42; 32]);
        s.release_destination = Some(Bytes32::new([0xCC; 32]));

        let wire: RegistrationStateWire = (&s).into();
        let parsed = wire.into_state().unwrap();
        assert_eq!(parsed, s);
    }

    /// WHAT: `RegistrationStateWire` is fully JSON-portable.
    /// HOW:  serialise via serde, deserialise, compare.
    /// WHY:  proves the wire form uses only JSON-native types
    ///       (strings, null) — which is the whole reason the wire
    ///       layer exists, since `PublicKey` and `Bytes32` have no
    ///       native serde impls.
    #[test]
    fn registration_state_wire_json_roundtrip() {
        let s = RegistrationState::fresh(pk_at(0), Bytes32::new([0x11; 32]), 1_000);
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
            voted_ballots_root_hex: "00".repeat(32),
            locked_weight: 0,
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
            voted_ballots_root_hex: "00".repeat(32),
            locked_weight: 0,
            release_destination_hex: None,
        };
        assert!(bad.into_state().is_err());
    }

    /// WHAT: `BallotState::fresh` is unfinalized with zero outcome
    ///       and zero signer set.
    /// HOW:  construct via `fresh`, assert each field.
    /// WHY:  the ballot deployer curries this exact state into the
    ///       Ballot Coin's eve puzzle hash; mismatched defaults
    ///       break the lineage proof from spend #1 onwards.
    #[test]
    fn ballot_state_fresh_is_zero() {
        let s = BallotState::fresh();
        assert!(!s.finalized);
        assert_eq!(s.vote_outcome, Bytes32::default());
        assert_eq!(s.agg_signers, Bytes32::default());
    }

    /// WHAT: `BallotState::clvm_tree_hash` is deterministic and
    ///       sensitive to every field.
    /// HOW:  build two equal `fresh` states, compare hashes; flip
    ///       `finalized` on a clone, assert hash differs; bump
    ///       `vote_outcome`, assert hash differs again.
    /// WHY:  this hash drives the Ballot Coin's lineage proof
    ///       chain. A field-insensitive composition would let a
    ///       finalized ballot pose as unfinalized.
    #[test]
    fn ballot_state_tree_hash_field_sensitive() {
        let a = BallotState::fresh();
        let b = BallotState::fresh();
        assert_eq!(a.clvm_tree_hash(), b.clvm_tree_hash());

        let mut c = a.clone();
        c.finalized = true;
        assert_ne!(a.clvm_tree_hash(), c.clvm_tree_hash());

        let mut d = a.clone();
        d.vote_outcome = Bytes32::new([0x42; 32]);
        assert_ne!(a.clvm_tree_hash(), d.clvm_tree_hash());
    }

    /// WHAT: `BallotState` JSON-serialises via the derived serde
    ///       impls when `Bytes32` is treated as a length-32 array.
    /// HOW:  serialise with `serde_json::to_string`, deserialise,
    ///       compare.
    /// WHY:  the indexer and aggregator may persist `BallotState`
    ///       directly to disk; the derive must produce a working
    ///       round-trip.
    #[test]
    fn ballot_state_serde_roundtrips() {
        let s = BallotState {
            finalized: true,
            vote_outcome: Bytes32::new([0x42; 32]),
            agg_signers: Bytes32::new([0x99; 32]),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: BallotState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    /// WHAT: `VotingCoinState::clvm_tree_hash` agrees with
    ///       `puzzles::voting_coin_state_tree_hash` when the
    ///       `voter_pubkey` field carries a valid 48-byte BLS G1
    ///       encoding.
    /// HOW:  build a state from a real `PublicKey`, compute both
    ///       hashes, assert equality.
    /// WHY:  the Rust-side `Bytes` field must hash identically to
    ///       the typed `&PublicKey` form used in the puzzle helper —
    ///       otherwise vote drivers and indexers would compute
    ///       diverging coin ids.
    #[test]
    fn voting_coin_state_tree_hash_matches_puzzles_helper() {
        let pk = pk_at(0);
        let bli = Bytes32::new([0x11; 32]);
        let vd = Bytes32::new([0x42; 32]);
        let rci = Bytes32::new([0x99; 32]);

        let st = VotingCoinState {
            voter_pubkey: Bytes::new(pk.to_bytes().to_vec()),
            ballot_launcher_id: bli,
            vote_data: vd,
            registration_coin_id: rci,
        };

        let via_method = st.clvm_tree_hash();
        let via_helper = puzzles::voting_coin_state_tree_hash(&pk, bli, vd, rci);
        assert_eq!(via_method, via_helper);
    }

    /// WHAT: `VoteRecord` → `VoteRecordWire` round-trips through
    ///       JSON serde without loss, including the new
    ///       `ballot_launcher_id` and `voting_coin_id` fields.
    /// HOW:  build a populated `VoteRecord`, convert to wire,
    ///       serialise, parse, compare.
    /// WHY:  vote records are exchanged off-chain between voter UI,
    ///       aggregator, and indexer; lossy serialisation would
    ///       silently drop signatures, vote data, or ballot
    ///       references.
    #[test]
    fn vote_record_wire_roundtrips() {
        let v = VoteRecord {
            voter_pubkey: pk_at(0),
            vote_data: Bytes32::new([0x42; 32]),
            vote_signature_hex: "ab".repeat(96),
            registration_coin_id: Bytes32::new([0x99; 32]),
            ballot_launcher_id: Bytes32::new([0x77; 32]),
            voting_coin_id: Bytes32::new([0x88; 32]),
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
