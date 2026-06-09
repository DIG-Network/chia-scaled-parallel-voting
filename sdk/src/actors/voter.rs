// ============================================================================
// actors/voter.rs — single-voter spend driver
// ============================================================================
//
// MODULE: actors::voter
// PURPOSE: Stateful actor representing one voter. Owns:
//          * the voter's BLS keys
//          * the shared ElectionConfig
//          * the network type (selects mainnet/testnet AGG_SIG additional data)
//
// SUPPORTED FLOWS (CHIP rev 2026-05-02 — all fully implemented and
// proven end-to-end by sdk/tests/voter_*_e2e.rs and confirmed on
// mainnet by cli/src/bin/live_integration_test.rs run #11):
//   * register          — register-action spend on the Election
//                         Singleton. Mints a CAT-wrapped Registration
//                         Coin at the voter's predicted puzzle hash.
//                         No XCH fee output (fees were dropped in
//                         this revision).
//   * cast_vote         — Mints the per-(voter, ballot) Voting Coin
//                         via the Registration Coin's
//                         `mint_voting_coin` action. Co-spends the
//                         Ballot Coin's oracle action so the new
//                         Voting Coin is bound to a specific ballot
//                         identity + close height. Recreates the
//                         Registration Coin with `voted_ballots_root`
//                         updated to mark the ballot as voted.
//   * update_vote       — Updates a Voting Coin's vote payload via
//                         its `update_vote` action; co-spends the
//                         Ballot Coin's oracle action to re-affirm
//                         the ballot is still open. Re-emits the BLS
//                         signature memo over the new vote message.
//   * release_collateral — Co-spends the Election Singleton's
//                         `deregister` action with the (post-cast)
//                         Registration Coin's `release` action,
//                         sending the CAT collateral to a destination
//                         chosen by the voter. Walks the registration
//                         coin's lineage forward from the supplied id
//                         so callers can pass the post-cast tip.
//
// SIGNING: every spend bundle is signed via the upstream
//   `dig_l1_wallet::transaction::sign_coin_spends`
//   → `chia_sdk_signer::RequiredSignature::from_coin_spends` chain.
//   That function walks every AGG_SIG condition, augments under the
//   configured network's `agg_sig_me_additional_data`, and produces
//   one aggregated BLS signature.
//
// CHIA-QUERY BRIDGE: the SDK uses `chia_protocol::Bytes32` everywhere,
//   but `chia_query` returns hex-encoded strings. `convert_coin` and
//   `parse_hex32` (file-private) bridge the two.

use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use crate::config::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_election_finalizer_full,
    build_singleton_spend, build_voting_coin_finalizer_full, load_action_puzzle, ActionSpend,
};
use crate::actors::deployer::sign_bundle_signature;
use crate::chain::ChainReader;
use crate::config::ElectionConfig;
use crate::error::{anyhow_compat, VotingError, VotingResult};
use crate::puzzles::{self, PuzzleHashes};

/// STRUCT: VoterKeys
/// PURPOSE: voter's BLS identity. Distinct from the wallet's standard
///          p2 / synthetic key — a voter MAY use any L1 wallet to fund
///          their registration.
/// IMMUTABLE: pubkey is derived from secret on construction; both
///            travel together for ergonomic signing.
pub struct VoterKeys {
    pub pubkey: PublicKey,
    pub secret: SecretKey,
    /// SEC-F1: the voter's Jubjub signing key (secret scalar). This is the
    /// SNARK-friendly key the finalize circuit (`prover::circuit_v2`) verifies
    /// a Schnorr signature for, and whose `(x, y)` the Poseidon registration
    /// leaf commits. Derived deterministically from the BLS secret.
    pub jubjub_secret: ark_ed_on_bls12_381::Fr,
    /// SEC-F1: Jubjub public key `P = jubjub_secret · G` (the leaf identity).
    pub jubjub_pubkey: ark_ed_on_bls12_381::EdwardsAffine,
}

impl VoterKeys {
    /// FN: new
    /// WHAT: build VoterKeys from a raw secret. Pubkey computed lazily.
    ///       The Jubjub signing key is derived deterministically from the
    ///       BLS secret (SEC-F1) so a voter's identity is a single seed.
    pub fn new(secret: SecretKey) -> Self {
        use ark_ec::{CurveGroup, Group};
        use ark_ed_on_bls12_381::{EdwardsProjective as Jub, Fr as JubScalar};
        use ark_ff::PrimeField;
        use sha2::Digest;
        let pubkey = secret.public_key();
        let mut h = sha2::Sha256::new();
        h.update(b"CHIP/jubjub-signing-key/v1");
        h.update(secret.to_bytes());
        let seed: [u8; 32] = h.finalize().into();
        let jubjub_secret = JubScalar::from_le_bytes_mod_order(&seed);
        let jubjub_pubkey = (Jub::generator() * jubjub_secret).into_affine();
        Self {
            pubkey,
            secret,
            jubjub_secret,
            jubjub_pubkey,
        }
    }

    /// FN: sign_unsafe
    /// WHAT: BLS-sign `message` verbatim — the same shape an on-chain
    ///       `AggSigUnsafe(VOTER_PUBKEY, vote_message)` condition
    ///       requires (no augmentation). Used for the per-(voter,
    ///       ballot) memo signature on the Voting Coin's
    ///       `update_vote` action (CHIP rev 2026-05-02).
    pub fn sign_unsafe(&self, message: &[u8]) -> Signature {
        chia_bls::sign_raw(&self.secret, message)
    }

    /// SEC-F1 (step 6 building block): produce a Jubjub Schnorr signature
    /// over `vote_message` (an Fr field element) with this voter's Jubjub
    /// key — the signature the finalize circuit (`prover::circuit_v2`)
    /// verifies in-circuit. The nonce `k` is derived DETERMINISTICALLY from
    /// the secret + message (RFC6979/EdDSA-style) so two signatures over the
    /// same message never reuse `k` with a different message (which would
    /// leak the key), and signing needs no RNG.
    ///
    /// Returns `(R, s)` with `R = k·G`, `s = k + challenge_to_inner(c)·x`,
    /// `c = Poseidon(R.x, P.x, vote_message)` — exactly what `SignerV2`
    /// carries into the circuit.
    pub fn jubjub_schnorr_sign(
        &self,
        vote_message: ark_bls12_381::Fr,
    ) -> (ark_ed_on_bls12_381::EdwardsAffine, ark_ed_on_bls12_381::Fr) {
        use ark_ed_on_bls12_381::Fr as JubScalar;
        use ark_ff::{BigInteger, PrimeField};
        use sha2::Digest;
        let cfg = crate::prover::circuit_v2::poseidon_config();
        // Deterministic nonce k = H("CHIP/jubjub-nonce/v1" || x_le || m_le).
        let mut h = sha2::Sha256::new();
        h.update(b"CHIP/jubjub-nonce/v1");
        h.update(self.jubjub_secret.into_bigint().to_bytes_le());
        h.update(vote_message.into_bigint().to_bytes_le());
        let seed: [u8; 32] = h.finalize().into();
        let k = JubScalar::from_le_bytes_mod_order(&seed);
        crate::prover::circuit_v2::schnorr_sign(&cfg, self.jubjub_secret, k, vote_message)
    }
}

/// STRUCT: Voter
/// PURPOSE: top-level voter actor.
/// FIELDS:
///   * config  — shared ElectionConfig
///   * keys    — voter BLS keys
///   * network — selects mainnet vs testnet AGG_SIG additional data
///
/// XCH/CAT funding is the CALLER's responsibility — they construct
/// any required CAT issuance / fee spends and pass them in (see
/// `Voter::register`'s `cat_parent_spend` parameter). Keeping the
/// actor wallet-free makes it network-agnostic + trivially
/// testable in a Simulator.
pub struct Voter {
    pub config: ElectionConfig,
    pub keys: VoterKeys,
    pub network: NetworkType,
    /// Height curried into the eve singleton's genesis state by the
    /// deployer. Defaults to `0` for backwards compatibility, but EVERY
    /// real chain (mainnet, testnet11) uses the chain peak observed at
    /// `phase_deploy` time — failing to plumb that real value here makes
    /// every launcher-lineage walker predict the wrong eve puzzle hash
    /// and silently retry until timeout. Use [`Voter::with_election_start_height`].
    pub election_start_height: u64,
}

/// STRUCT: CastVoteParams
/// PURPOSE: typed bundle for [`Voter::cast_vote`] arguments. Holds the
///          per-ballot context that the voter MUST reproduce so the
///          on-chain Ballot Coin's curried args (which the voter
///          spends via the `oracle` action) match what
///          `BallotIssuer::launch_ballot` actually committed to.
/// PUBLISHING: in production the BallotIssuer emits these values via
///          the `create_ballot` + launcher-second-spend announcements
///          and any out-of-band publication (web UI, JSON config); the
///          voter assembles them into this struct before calling
///          `cast_vote`. None of them can be derived from the on-chain
///          Ballot Coin alone — its puzzle hash is a one-way function
///          of these inputs.
/// FIELDS:
///   * `ballot_launcher_id` — singleton launcher id of the Ballot
///     Coin this voter is voting on. Binds the Voting Coin to a
///     single ballot so the SPT slot in `voted_ballots_root` can't
///     be reused across ballots.
///   * `vote_data` — the 32-byte payload the voter is committing
///     to. Typically `sha256(application-specific outcome)`. Sent
///     as a memo on the Voting Coin so the off-chain aggregator
///     can read it back without re-running the puzzle.
///   * `vote_close_height` — block height at which the ballot stops
///     accepting vote edits. Must match what the BallotIssuer
///     curried into the on-chain Ballot Coin's `oracle` and
///     `finalize` actions; the SDK uses it to (a) reconstruct the
///     same per-ballot actions Merkle root for the oracle co-spend
///     and (b) hand it to `mint_voting_coin`'s solution as a
///     value-binding.
///   * `vote_threshold_num` / `vote_threshold_den` — quorum
///     threshold for finalize. Curried into the Ballot Coin's
///     `finalize` action; the voter needs them only because
///     `finalize`'s curried hash is one of three leaves of the
///     per-ballot merkle root the oracle proof verifies against.
///   * `registration_merkle_root_snapshot` /
///     `registration_vote_weight_snapshot` — Election Singleton
///     state at the moment `launch_ballot` ran. Same role as the
///     threshold pair — needed only to reconstruct the Ballot Coin's
///     curried `finalize` hash for the oracle proof.
///   * `voting_coin_amount` — CAT mojos minted into the new Voting
///     Coin. The CAT outer enforces conservation, so the
///     Registration Coin's recreated amount is
///     `collateral_amount - voting_coin_amount`. Pick `1` for a
///     minimal-amount marker coin.
#[derive(Clone, Debug)]
pub struct CastVoteParams {
    pub ballot_launcher_id: Bytes32,
    pub vote_data: Bytes32,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot: Bytes32,
    pub registration_vote_weight_snapshot: u64,
    pub voting_coin_amount: u64,
    /// M5r-merkle-e: per-ballot vote-mode commitment. `Bytes32::default()`
    /// (= 0x00…00) for Mode1Free; otherwise must equal the Ballot
    /// Coin's curried `vote_options_root` (the AssertCoinAnnouncement
    /// over the oracle preimage enforces matching).
    pub vote_options_root: Bytes32,
    /// M5r-merkle-e: optional `(leaf_index, proof_siblings)` for
    /// Mode2Restricted. `None` for Mode1Free — the puzzle's
    /// short-circuit gate accepts any vote_data when
    /// `vote_options_root == 0x00…00`. Build via
    /// `chip_voting_sdk::vote_mode::BallotVoteMode::merkle_proof_for_option`.
    pub vote_option_proof: Option<(usize, Vec<Bytes32>)>,
}

/// STRUCT: UpdateVoteParams
/// PURPOSE: typed bundle for [`Voter::update_vote`] arguments. Same
///          per-ballot fields as [`CastVoteParams`] (the voter must
///          mirror the on-chain Ballot Coin's curried args to spend
///          its `oracle` action) plus the previously-cast Voting
///          Coin's identifying state (so the SDK can predict its
///          on-chain ph and refuse to spend something else).
/// FIELDS:
///   * `voting_coin_id` — coin id of the Voting Coin to update,
///     returned by an earlier `Voter::cast_vote` call.
///   * `old_vote_data` — the `vote_data` that was cast at
///     `cast_vote` time. Curried into the on-chain Voting Coin's
///     state — the SDK uses it to verify the on-chain ph matches.
///   * `new_vote_data` — the replacement vote payload.
///   * `registration_coin_id` — the Registration Coin's id at
///     `cast_vote` time (also curried into the Voting Coin's state).
///   * `ballot_launcher_id`, `vote_close_height`,
///     `vote_threshold_num`, `vote_threshold_den`,
///     `registration_merkle_root_snapshot`,
///     `registration_vote_weight_snapshot` — same as
///     [`CastVoteParams`]; needed for the Ballot Coin oracle co-spend.
#[derive(Clone, Debug)]
pub struct UpdateVoteParams {
    pub voting_coin_id: Bytes32,
    pub old_vote_data: Bytes32,
    pub new_vote_data: Bytes32,
    pub registration_coin_id: Bytes32,
    pub ballot_launcher_id: Bytes32,
    pub vote_close_height: u64,
    pub vote_threshold_num: u64,
    pub vote_threshold_den: u64,
    pub registration_merkle_root_snapshot: Bytes32,
    pub registration_vote_weight_snapshot: u64,
    /// M5r-merkle: per-ballot vote-mode commitment. `Bytes32::default()`
    /// (= 0x00…00) for Mode1Free; otherwise must equal the Ballot
    /// Coin's curried `vote_options_root` (the puzzle's
    /// AssertCoinAnnouncement on the oracle preimage enforces this).
    pub vote_options_root: Bytes32,
    /// M5r-merkle: optional `(leaf_index, proof_siblings)` for
    /// Mode2Restricted. `None` for Mode1Free — the on-chain gate
    /// short-circuits when `vote_options_root == 0x00…00`. Build via
    /// `chip_voting_sdk::vote_mode::BallotVoteMode::merkle_proof_for_option`.
    pub vote_option_proof: Option<(usize, Vec<Bytes32>)>,
}

/// STRUCT: UpdateVoteCoinSpends
/// PURPOSE: return shape of [`Voter::update_vote_build_coin_spends`] —
///          unsigned coin_spends + auxiliary data a Sage-backed dApp
///          consumes to finalize the spend externally. Mirrors
///          [`CastVoteCoinSpends`] for the update flow.
pub struct UpdateVoteCoinSpends {
    pub coin_spends: Vec<CoinSpend>,
    pub recreated_voting_coin_id: Bytes32,
    /// The voter's `sign_unsafe` BLS signature over `new_vote_message`,
    /// echoed back from the caller's input. Embedded into the
    /// update_vote action solution.
    pub new_vote_signature: chia_protocol::Bytes,
    /// `sha256(new_vote_data || ballot_launcher_id || election_launcher_id)`
    /// — the bytes the caller signed with `sign_unsafe`. Returned for
    /// the dApp to cross-check its preview shim.
    pub new_vote_message: Bytes32,
}

/// STRUCT: UpdateVoteResult
/// PURPOSE: outputs from `Voter::update_vote`.
#[derive(Clone, Debug)]
pub struct UpdateVoteResult {
    /// Coin id of the recreated Voting Coin (the original is spent;
    /// the new one carries the updated `vote_data`).
    pub recreated_voting_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
    /// The voter's BLS signature over the new canonical vote_message
    /// (`puzzles::vote_message(new_vote_data, ballot_launcher_id,
    /// election_launcher_id)`) using `sign_unsafe`. Mirrors
    /// [`CastVoteResult::vote_signature`] for the off-chain
    /// aggregator's collection.
    pub new_vote_signature: chia_protocol::Bytes,
}

/// STRUCT: CastVoteResult
/// PURPOSE: outputs from `Voter::cast_vote`.
/// FIELDS:
///   * `voting_coin_id` — coin id of the freshly-minted Voting Coin.
///     Stable for any subsequent `update_vote` / aggregator lookup.
///   * `spend_bundle` — fully-signed spend bundle pushable to the
///     mempool.
///   * `vote_signature` — BLS signature over the canonical
///     vote-message (`puzzles::vote_message(vote_data,
///     ballot_launcher_id, election_launcher_id)`) using
///     `sign_unsafe`. Written into the Voting Coin's memos; the
///     off-chain aggregator BLS-aggregates these per-ballot to
///     produce the finalize witness.
/// STRUCT: CastVoteCoinSpends
/// PURPOSE: return shape of [`Voter::cast_vote_build_coin_spends`] —
///          the unsigned coin_spends a Sage-backed dApp gets to sign
///          externally via chip0002. Mirrors the fields a hardware-
///          wallet flow needs to:
///   1. Push the bundle (after the wallet provides the aggregate sig).
///   2. Echo `vote_signature` to the off-chain aggregator.
///   3. Cross-check the canonical `vote_message` against what the
///      dApp computed before requesting the wallet signature.
pub struct CastVoteCoinSpends {
    pub coin_spends: Vec<CoinSpend>,
    pub voting_coin_id: Bytes32,
    /// The voter's `sign_unsafe` BLS signature over `vote_message`,
    /// echoed back unchanged from the caller's input. Embedded into
    /// the mint_voting_coin solution and surfaced to off-chain
    /// aggregators.
    pub vote_signature: chia_protocol::Bytes,
    /// `sha256(vote_data || ballot_launcher_id || election_launcher_id)`
    /// — the bytes the caller signed with `sign_unsafe` to produce
    /// `vote_signature`. Returned for the dApp to cross-check.
    pub vote_message: Bytes32,
}

pub struct CastVoteResult {
    pub voting_coin_id: Bytes32,
    pub spend_bundle: SpendBundle,
    pub vote_signature: chia_protocol::Bytes,
}

impl Voter {
    pub fn new(config: ElectionConfig, keys: VoterKeys, network: NetworkType) -> Self {
        Self {
            config,
            keys,
            network,
            election_start_height: 0,
        }
    }

    /// Bind the deployer's curried `election_start_height` so launcher-
    /// lineage walks compute the correct eve singleton puzzle hash.
    /// MUST be called for any deployment that used a non-zero start
    /// height — otherwise `register`, `cast_vote`, `update_vote`,
    /// `release_collateral` will fail to resolve the singleton.
    pub fn with_election_start_height(mut self, h: u64) -> Self {
        self.election_start_height = h;
        self
    }

    /// FN: slot
    /// WHAT: this voter's canonical SPT slot.
    /// FORMULA (SEC-F1): `sha256(jub_x_be32 || jub_y_be32)[0..4]` — see
    ///          `PoseidonSmt::slot_for_jubjub`. The slot is keyed by the
    ///          voter's Jubjub pubkey coords, matching register.rue.
    pub fn slot(&self) -> u32 {
        crate::merkle::PoseidonSmt::slot_for_jubjub(
            self.keys.jubjub_pubkey.x,
            self.keys.jubjub_pubkey.y,
        )
    }

    /// FN: registration_coin_puzzle_hash
    /// WHAT: the CAT-wrapped puzzle hash this voter's Registration
    ///       Coin will land on.
    /// USAGE:
    ///   * voter pre-funds the right amount into this puzzle hash
    ///   * aggregator/indexer use it as a filter against
    ///     `chain.get_coin_records_by_hint`
    pub fn registration_coin_puzzle_hash(&self) -> VotingResult<Bytes32> {
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        Ok(puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
            self.config.collateral_amount,
        ))
    }

    /// FN: voter_hint
    /// WHAT: stable coin-state hint for tracking this voter's
    ///       Registration Coin lineage across mint_voting_coin /
    ///       release spends.
    /// USAGE: `chain.get_coin_records_by_hint(voter_hint_hex(), ..)`.
    pub fn voter_hint(&self) -> VotingResult<Bytes32> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        Ok(puzzles::voter_hint(
            election_id,
            cat_tail_hash,
            &self.keys.pubkey,
        ))
    }

    /// FN: voter_hint_hex
    /// WHAT: `0x`-prefixed hex form of `voter_hint` — the wire shape
    ///       the `chia-query` HTTP API expects.
    pub fn voter_hint_hex(&self) -> VotingResult<String> {
        Ok(format!("0x{}", hex::encode(self.voter_hint()?)))
    }

    /// Build a registration spend bundle.
    ///
    /// The full implementation composes:
    ///
    ///   1. **CAT collateral spend** — the caller pre-builds a CAT
    ///      issuance / spend that creates the Registration Coin at
    ///      its expected puzzle hash with `COLLATERAL_AMOUNT`. The
    ///      CAT spend's inner conditions emit the `create_reg`
    ///      `CreateCoinAnnouncement` that the Election Singleton's
    ///      register action asserts.
    ///   2. **Election Singleton spend** — wraps the action layer
    ///      with the `register` action selected. The action's
    ///      solution carries `(new_voter_pubkey, register_leaf_index,
    ///      register_siblings, ...cat_parent_coin_id)`.
    ///
    /// Per CHIP rev 2026-05-02 there is **no XCH registration fee**;
    /// callers that want to attach a fee output build it externally.
    ///
    /// Final signing uses [`sign_bundle_signature`], which calls
    /// `RequiredSignature::from_coin_spends` to walk every AGG_SIG_*
    /// condition (the voter's `AggSigMe(VOTER_PUBKEY,
    /// registration_message)`).
    /// Sage-friendly variant of [`Voter::register`]. Returns the
    /// unsigned coin_spends; caller signs the bundle aggregate
    /// externally (no `sign_unsafe` step — register has no off-chain
    /// aggregator sig like cast_vote / update_vote, just AGG_SIG_ME
    /// conditions Sage's chip0002_signCoinSpends covers in one pass).
    pub async fn register_build_coin_spends<C: ChainReader>(
        &self,
        smt: &crate::merkle::PoseidonSmt,
        cat_parent_spend: CoinSpend,
        chain: &C,
        lock_amount: u64,
    ) -> VotingResult<Vec<CoinSpend>> {
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::CurriedProgram;

        // Per-CHIP-rev weighted voting: voters choose their own lock
        // amount, bounded below by the curried `COLLATERAL_AMOUNT`
        // minimum. The puzzle re-asserts both `lock_amount >=
        // COLLATERAL_AMOUNT` AND `cat_child_amount == lock_amount`
        // — the SDK pre-checks the minimum here so callers see a
        // clear Rust error before the CLVM dry-run trap.
        if lock_amount < self.config.collateral_amount {
            return Err(voting_other(format!(
                "Voter::register: lock_amount {} below curried COLLATERAL_AMOUNT minimum {}",
                lock_amount, self.config.collateral_amount,
            )));
        }

        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;

        // ── 1. Find the current Election Singleton ──────────────
        // After CHIP rev 2026-05-02 the launcher walker requires an
        // `election_start_height` to predict the eve singleton's
        // puzzle hash. Both fast path and slow path filter children by
        // that hash — using 0 when the deployer used a non-zero peak
        // (e.g. mainnet) makes both lookups silently miss the on-chain
        // coin. Always plumb `self.election_start_height` (set via
        // `Voter::with_election_start_height`).
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            self.election_start_height,
            "Election Singleton (launcher lineage)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        let crate::actors::aggregator::CurrentSingleton {
            coin: singleton_coin,
            lineage_proof: singleton_lineage_proof,
            state: on_chain_state,
            ..
        } = current;

        // ── 2. Build the action layer's outer puzzle ────────────
        let mut ctx = SpendContext::new();
        let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id)?;
        let merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&self.config);
        // Inner puzzle MUST match what's curried into the singleton
        // on-chain (`on_chain_state` from the launcher lineage walk).
        // SEC-F1: the Poseidon SPT root is the 32-byte BE of the Fr root.
        let smt_root = Bytes32::new(smt.root_be32());
        if on_chain_state.registration_merkle_root != smt_root {
            return Err(voting_other(format!(
                "Voter::register: aggregator SMT root {} does not match on-chain {} — re-sync",
                hex::encode(smt_root),
                hex::encode(on_chain_state.registration_merkle_root),
            )));
        }
        let election_state_node = self.election_state_node(&mut ctx, &on_chain_state)?;
        let action_layer_node =
            build_action_layer_puzzle(&mut ctx, elect_finalizer, merkle_root, election_state_node)?;

        // ── 3. Build the curried register action puzzle ─────────
        // CURRY ORDER (post-CHIP rev 2026-05-02):
        //   (TREE_DEPTH, EMPTY_LEAF_HASH, CAT_MOD_HASH, CAT_TAIL_HASH,
        //    ACTION_LAYER_MOD_HASH, REGISTRATION_FINALIZER_MOD_HASH,
        //    REGISTRATION_MERKLE_ROOT, COLLATERAL_AMOUNT,
        //    ELECTION_LAUNCHER_ID, EMPTY_BALLOT_ROOT)
        // (No `registration_fee` — fees were dropped in this revision.)
        let register_program_node = load_action_puzzle(&mut ctx, puzzles::ELECTION_REGISTER_HEX)?;
        let register_curried = CurriedProgram {
            program: register_program_node,
            args: clvm_curried_args!(
                crate::config::TREE_DEPTH,
                Bytes32::new(crate::config::EMPTY_LEAF_HASH),
                PuzzleHashes::cat_outer(),
                cat_tail_hash,
                PuzzleHashes::action_layer(),
                PuzzleHashes::registration_finalizer(),
                puzzles::registration_actions_merkle_root(cat_tail_hash),
                self.config.collateral_amount,
                election_id,
                puzzles::empty_ballot_root()
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // ── 4. Build the register action solution ───────────────
        // Solution shape (per register.rue, SEC-F1 Poseidon/Jubjub rev):
        //   (new_voter_pubkey, jub_x, jub_y, register_leaf_index,
        //    register_siblings, locked_cat_mojos, ...cat_parent_coin_id)
        //
        // The BLS `new_voter_pubkey` stays first (register.rue still uses
        // it for the `create_reg` announcement + AggSigMe). The voter's
        // Jubjub pubkey coords follow — the SPT leaf and slot are keyed
        // by them.
        //
        // SLOT ENCODING: register.rue's `slot_from_jubjub` builds
        //   `0x00 || sha256(jub_x_be32 || jub_y_be32)[0..4]` and casts to
        //   Int. We pass the slot as the EXACT 5-byte sequence the puzzle
        //   constructs so `==` always succeeds.
        let slot = self.slot();
        let proof = smt.prove(slot);
        // register.rue's `compute_root` walks siblings as `Int`s by index
        // parity (not direction bits), so we pass only the sibling list as
        // 32-byte BE Fr values; the bits are implicit in the slot index.
        let siblings: Vec<Bytes32> = proof
            .siblings
            .iter()
            .map(|f| Bytes32::new(crate::merkle::fr_to_be32(*f)))
            .collect();
        let voter_pk_bytes = chia_protocol::Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let jub_x = Bytes32::new(crate::merkle::fr_to_be32(self.keys.jubjub_pubkey.x));
        let jub_y = Bytes32::new(crate::merkle::fr_to_be32(self.keys.jubjub_pubkey.y));
        let cat_parent_coin_id = cat_parent_spend.coin.coin_id();
        let slot_bytes = {
            let mut buf = Vec::with_capacity(5);
            buf.push(0x00);
            buf.extend_from_slice(&slot.to_be_bytes());
            chia_protocol::Bytes::new(buf)
        };
        let register_solution_value = (
            voter_pk_bytes,
            (
                jub_x,
                (jub_y, (slot_bytes, (siblings, (lock_amount, cat_parent_coin_id)))),
            ),
        );
        let register_solution = register_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let action_spends = vec![ActionSpend {
            puzzle: register_curried,
            solution: register_solution,
        }];
        // Election finalizer takes `..._my_solution: Any` — pass nil.
        let elect_finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &crate::actors::aggregator::compute_election_action_root_leaves(&self.config),
            &action_spends,
            elect_finalizer_solution,
        )?;

        // ── 5. Wrap with the singleton outer ────────────────────
        let register_singleton_spend = build_singleton_spend(
            &mut ctx,
            singleton_coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            singleton_lineage_proof,
        )?;

        // ── 6. Sign + bundle ────────────────────────────────────
        // Voter's AggSigMe over the registration message
        // (sha256("register" || pk || election_id)) is automatically
        // collected from the emitted condition by
        // RequiredSignature::from_coin_spends.
        let coin_spends = vec![cat_parent_spend, register_singleton_spend];
        // Pre-flight: dry-run every coin spend's puzzle so a CLVM
        // `raise` surfaces with the EXACT coin id that failed,
        // instead of being buried inside the signer's opaque
        // "sign_coin_spends failed: clvm raise" error message.
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            // Dump the failing bundle to a file so the operator can
            // re-run individual coin spends through `clvm` /
            // `cdv` / a debugger to diagnose the trap.
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "voter-register-failed-{}.json",
                    chrono_compat_now()
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
                    "coin_spends": coin_spends.iter().map(|cs| serde_json::json!({
                        "coin": {
                            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                            "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                            "amount": cs.coin.amount,
                        },
                        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                        "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                    })).collect::<Vec<_>>(),
                })).unwrap_or_else(|_| "<json serialise failed>".into());
                let _ = std::fs::write(&path, json);
                tracing::warn!(dump_path = %path.display(), "wrote failing bundle to disk");
            }
            return Err(voting_other(format!("Voter::register dry-run: {e:?}")));
        }

        Ok(coin_spends)
    }

    /// Build a `register` SpendBundle using `self.keys.secret` for
    /// signing — secret-key path for native CLI / integration test.
    /// Browser dApps that don't hold the secret should use
    /// [`Voter::register_build_coin_spends`].
    pub async fn register<C: ChainReader>(
        &self,
        smt: &crate::merkle::PoseidonSmt,
        cat_parent_spend: CoinSpend,
        chain: &C,
        lock_amount: u64,
    ) -> VotingResult<SpendBundle> {
        let coin_spends = self
            .register_build_coin_spends(smt, cat_parent_spend, chain, lock_amount)
            .await?;
        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Build a `cast_vote` spend bundle.
    ///
    /// FLOW (CHIP rev 2026-05-02):
    ///   1. Locate the voter's current Registration Coin (must be
    ///      at the fresh-state CAT-wrapped puzzle hash — the driver
    ///      assumes the voter has not yet voted on any ballot).
    ///   2. Reconstruct the Registration Coin's CAT lineage proof
    ///      from its parent's on-chain spend (same path as
    ///      `release_collateral`).
    ///   3. Locate the eve Ballot Coin singleton as a child of the
    ///      ballot launcher coin (post `BallotIssuer::launch_ballot`).
    ///   4. Reconstruct the per-ballot action curries (finalize,
    ///      oracle, announce_finalization) using the values in
    ///      [`CastVoteParams`] and verify the resulting Ballot Coin
    ///      puzzle hash matches what's on chain — defense against
    ///      a caller passing wrong per-ballot params.
    ///   5. Build the Ballot Coin spend running its `oracle` action
    ///      (open variant). Its only effect is emitting the
    ///      "ballot_oracle_open" announcement that
    ///      `mint_voting_coin` asserts.
    ///   6. Build the Registration Coin spend running its
    ///      `mint_voting_coin` action with the 8-field solution:
    ///        * ballot_launcher_id, vote_close_height, vote_data,
    ///          ballot_coin_id, registration_coin_id, initial_signature,
    ///          ballot_membership_witness, ...voting_coin_amount
    ///      where `initial_signature` is the voter's `sign_unsafe`
    ///      BLS signature over `vote_message =
    ///      sha256(vote_outcome || ballot_launcher_id ||
    ///      election_launcher_id)` for the off-chain aggregator's
    ///      collection. The action ALSO emits an `AggSigMe` over the
    ///      same `vote_message`, which the bundle signer collects
    ///      separately — both sigs cover the same preimage.
    ///   7. Wrap the Registration Coin spend with the CAT outer (using
    ///      the lineage proof from step 2) and the Ballot Coin spend
    ///      with the Singleton outer (using an Eve lineage proof).
    ///   8. Sign + bundle.
    ///
    /// FRESH-STATE ASSUMPTION: the SDK currently assumes the
    /// Registration Coin is at the fresh-state ph (no votes yet) so
    /// `voted_ballots_root == empty_ballot_root()` and the
    /// non-membership witness is the canonical empty-SPT siblings.
    /// Multi-vote support (rebuilding the BallotMembership witness
    /// from prior cast_vote / update_vote spends) is future work.
    /// Sage / hardware-wallet-friendly variant of [`Voter::cast_vote`].
    ///
    /// SHAPE: takes a pre-computed `initial_signature` (the voter's
    /// `sign_unsafe(vote_message)` BLS sig) instead of holding the
    /// secret. Returns the unsigned coin_spends; the caller (typically
    /// a browser dApp via WalletConnect / chip0002) then signs the
    /// bundle's aggregated signature externally.
    ///
    /// This is the lower half of the split documented at
    /// `wasm/src/lib.rs::cast_vote_build_preview_spend_js`. The upper
    /// half — obtaining `initial_signature` — is the dApp's job: build
    /// a one-condition shim spend with `AggSigUnsafe(voter_pk,
    /// vote_message)` and have the wallet sign it in partial mode;
    /// the returned aggregate IS that single sig, byte-for-byte equal
    /// to what `keys.sign_unsafe(vm.as_ref())` would produce.
    pub async fn cast_vote_build_coin_spends<C: ChainReader>(
        &self,
        chain: &C,
        params: &CastVoteParams,
        initial_signature: chia_protocol::Bytes,
    ) -> VotingResult<CastVoteCoinSpends> {
        use chia_protocol::{Bytes, Coin};
        use chia_puzzle_types::singleton::SingletonArgs;
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::{tree_hash, CurriedProgram, TreeHash};

        if initial_signature.len() != 96 {
            return Err(voting_other(format!(
                "Voter::cast_vote_build_coin_spends: initial_signature must be 96 bytes \
                 (BLS G2), got {}",
                initial_signature.len(),
            )));
        }
        let initial_signature_bytes: Bytes = initial_signature;

        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;

        // Phase 2b: chain-walk override of caller-supplied per-ballot
        // curry params. With Option A's launcher memo, vote_close_height,
        // threshold, and registration snapshot fields are all readable
        // from chain — overriding caller params here removes
        // off-chain-metadata drift as a failure mode. Falls back to
        // caller params for legacy ballots minted before the memo was
        // added.
        let memo = crate::actors::ballot::read_ballot_launcher_memo(
            chain,
            params.ballot_launcher_id,
        )
        .await?;
        let mut effective_params = params.clone();
        if let Some(m) = &memo {
            effective_params.vote_close_height = m.vote_close_height;
            effective_params.vote_threshold_num = m.vote_threshold_num;
            effective_params.vote_threshold_den = m.vote_threshold_den;
            effective_params.registration_merkle_root_snapshot = m.registration_merkle_root_snapshot;
            effective_params.registration_vote_weight_snapshot = m.registration_vote_weight_snapshot;
        }
        let params = &effective_params;

        // ── 1. Locate the voter's Registration Coin ──────────────
        let predicted_reg_ph = puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
            self.config.collateral_amount,
        );
        let reg_records = chain.coin_records_by_puzzle_hash(predicted_reg_ph).await?;
        let reg_record = reg_records
            .into_iter()
            .find(|r| r.is_unspent())
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::cast_vote: no unspent Registration Coin at predicted ph {} \
                     (voter not registered or already voted; SDK currently requires a \
                     fresh-state Registration Coin)",
                    hex::encode(predicted_reg_ph),
                ))
            })?;
        let registration_coin = reg_record.coin;
        let registration_coin_id = registration_coin.coin_id();
        let cat_lineage_proof = self.reconstruct_cat_lineage(chain, registration_coin).await?;

        // ── 2. Verify the ballot launcher exists and is spent ─────
        // (launch_ballot must have run; the singleton lineage walk
        // below resolves the CURRENT unspent Ballot Coin tip — which
        // may be past the eve after prior cast_vote / update_vote
        // oracle co-spends from other voters.)
        let launcher_record = chain
            .coin_record_by_id(params.ballot_launcher_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::cast_vote: ballot launcher coin {} not found on chain",
                    hex::encode(params.ballot_launcher_id),
                ))
            })?;
        if launcher_record.is_unspent() {
            return Err(voting_other(format!(
                "Voter::cast_vote: ballot launcher coin {} is unspent — \
                 BallotIssuer::launch_ballot must run before cast_vote",
                hex::encode(params.ballot_launcher_id),
            )));
        }
        let _ = launcher_record; // launcher visited; helper below walks the lineage

        // ── 3. Reconstruct per-ballot Ballot Coin curry layout ───
        let mut ctx = SpendContext::new();
        let (vk_node, ic_node) =
            crate::actors::ballot::build_vk_ic_nodes(&mut ctx, &self.config)?;

        // finalize curry order MUST match
        // `puzzles/ballot_coin/finalize.rue` (SEC-F3+F5 added the trailing
        // ELECTION_VK_HASH + VOTE_OPTIONS_ROOT):
        //   (VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID,
        //    VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN,
        //    REGISTRATION_MERKLE_ROOT_SNAPSHOT,
        //    REGISTRATION_VOTE_WEIGHT_SNAPSHOT, ELECTION_VK_HASH,
        //    VOTE_OPTIONS_ROOT)
        // These MUST match `ballot.rs::launch_ballot` exactly or the
        // predicted Ballot Coin puzzle hash won't equal the on-chain one.
        let finalize_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_FINALIZE_HEX)?;
        let finalize_curried = CurriedProgram {
            program: finalize_program_node,
            args: clvm_curried_args!(
                vk_node,
                ic_node,
                params.ballot_launcher_id,
                election_id,
                params.vote_close_height,
                params.vote_threshold_num,
                params.vote_threshold_den,
                params.registration_merkle_root_snapshot,
                params.registration_vote_weight_snapshot,
                self.config.vk_hash(),
                params.vote_options_root,
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let finalize_full_hash = Bytes32::new(tree_hash(&ctx, finalize_curried).to_bytes());

        // oracle curry order (M4-revised): (BALLOT_LAUNCHER_ID,
        // VOTE_CLOSE_HEIGHT, VOTE_OPTIONS_ROOT). Default to Mode1Free
        // sentinel until M7e wires the chain-walked value through.
        let vote_options_root_curry: Bytes32 = Bytes32::default();
        let oracle_program_node = load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ORACLE_HEX)?;
        let oracle_curried = CurriedProgram {
            program: oracle_program_node,
            args: clvm_curried_args!(
                params.ballot_launcher_id,
                params.vote_close_height,
                vote_options_root_curry
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let oracle_full_hash = Bytes32::new(tree_hash(&ctx, oracle_curried).to_bytes());

        // announce_finalization curry order: (BALLOT_LAUNCHER_ID)
        let announce_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX)?;
        let announce_curried = CurriedProgram {
            program: announce_program_node,
            args: clvm_curried_args!(params.ballot_launcher_id),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let announce_full_hash =
            Bytes32::new(tree_hash(&ctx, announce_curried).to_bytes());

        let ballot_actions_root = puzzles::per_ballot_actions_merkle_root(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );
        let ballot_root_leaves = puzzles::per_ballot_action_root_leaves(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );

        // ── 4. Verify Ballot Coin's on-chain ph matches our prediction ─
        let ballot_finalizer_node =
            crate::action_spends::build_ballot_finalizer_full(&mut ctx, params.ballot_launcher_id)?;
        // SEC-F1: BallotState = (finalized . (vote_outcome . agg_signers));
        // `finalized` MUST be nil (Rue `false`), not Bytes32::default().
        let fresh_ballot_state_value: ((), (Bytes32, Bytes32)) =
            ((), (Bytes32::default(), Bytes32::default()));
        let ballot_state_node = fresh_ballot_state_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let ballot_inner_node = build_action_layer_puzzle(
            &mut ctx,
            ballot_finalizer_node,
            ballot_actions_root,
            ballot_state_node,
        )?;
        let ballot_inner_ph = Bytes32::new(tree_hash(&ctx, ballot_inner_node).to_bytes());
        let ballot_inner_th = TreeHash::new(ballot_inner_ph.to_bytes());
        let predicted_ballot_full_ph = Bytes32::new(
            SingletonArgs::curry_tree_hash(params.ballot_launcher_id, ballot_inner_th).to_bytes(),
        );

        // Walk the Ballot Coin singleton lineage from launcher to its
        // CURRENT unspent tip. Pre-finalize, every recreated Ballot
        // Coin shares `ballot_inner_ph` (BallotState.finalized=false
        // is invariant across oracle / update_vote co-spends), so the
        // walker uses that as `expected_inner_ph`. After other voters'
        // cast_vote / update_vote have already co-spent the eve, this
        // hops past the eve to the latest recreation. Mirrors
        // `Aggregator::find_current_ballot_singleton_via_chain`.
        let (ballot_coin, ballot_singleton_lineage_proof) = find_current_ballot_singleton(
            chain,
            params.ballot_launcher_id,
            ballot_inner_ph,
        )
        .await?;
        let ballot_coin_id = ballot_coin.coin_id();
        if ballot_coin.puzzle_hash != predicted_ballot_full_ph {
            return Err(voting_other(format!(
                "Voter::cast_vote: Ballot Coin on-chain ph {} doesn't match predicted {} \
                 from CastVoteParams — params (vote_close_height, threshold, registration \
                 snapshot) don't match what BallotIssuer::launch_ballot used",
                hex::encode(ballot_coin.puzzle_hash),
                hex::encode(predicted_ballot_full_ph),
            )));
        }

        // ── 5. Build the Ballot Coin oracle action spend ──────────
        // oracle takes no solution args.
        let oracle_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let ballot_action_spends = vec![ActionSpend {
            puzzle: oracle_curried,
            solution: oracle_solution,
        }];
        // Ballot finalizer takes `..._my_solution: Any` — pass nil.
        let ballot_finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let ballot_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &ballot_root_leaves,
            &ballot_action_spends,
            ballot_finalizer_solution,
        )?;

        let ballot_singleton_spend = build_singleton_spend(
            &mut ctx,
            ballot_coin,
            params.ballot_launcher_id,
            ballot_inner_node,
            ballot_action_layer_solution,
            ballot_singleton_lineage_proof,
        )?;

        // ── 6. Build the Registration Coin's mint_voting_coin spend ─
        let voter_hint = puzzles::voter_hint(election_id, cat_tail_hash, &self.keys.pubkey);
        let reg_finalizer = crate::action_spends::build_registration_finalizer_full(
            &mut ctx,
            voter_hint,
        )?;
        let reg_merkle_root = puzzles::registration_actions_merkle_root(cat_tail_hash);
        let reg_state = crate::state::RegistrationState::fresh(self.keys.pubkey, election_id, self.config.collateral_amount);
        let reg_state_node = self.registration_state_node(&mut ctx, &reg_state)?;
        let reg_action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            reg_finalizer,
            reg_merkle_root,
            reg_state_node,
        )?;

        // mint_voting_coin curry order (per
        // `puzzles/registration_coin/mint_voting_coin.rue`):
        //   (CAT_MOD_HASH, CAT_TAIL_HASH, ACTION_LAYER_MOD_HASH,
        //    VOTING_COIN_FINALIZER_MOD_HASH,
        //    VOTING_COIN_ACTIONS_MERKLE_ROOT)
        let mint_voting_coin_program_node =
            load_action_puzzle(&mut ctx, puzzles::REGISTRATION_MINT_VOTING_COIN_HEX)?;
        let mint_voting_coin_curried = CurriedProgram {
            program: mint_voting_coin_program_node,
            args: clvm_curried_args!(
                PuzzleHashes::cat_outer(),
                cat_tail_hash,
                PuzzleHashes::action_layer(),
                PuzzleHashes::voting_coin_finalizer(),
                puzzles::voting_coin_actions_merkle_root(),
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // The voter signs the canonical vote_message UNAUGMENTED so
        // the off-chain aggregator can verify against the published
        // pubkey directly. The on-chain action ALSO emits an AggSigMe
        // over the same preimage; the bundle signer below collects
        // that one (augmented) automatically. In this builder the
        // unaugmented sig is passed in as `initial_signature` (vs the
        // Voter::cast_vote wrapper, which computes it from
        // self.keys.sign_unsafe).
        let vm = puzzles::vote_message(
            params.vote_data,
            params.ballot_launcher_id,
            election_id,
        );

        // BallotMembership witness for the empty SPT (genesis state):
        //   (ballot_launcher_id . (s0 . (s1 . ... (s31 . ()))))
        // Encoded via Rust as `(ballot_launcher_id, Vec<Bytes32>)`
        // where Vec serialises with the trailing nil terminator.
        let siblings = puzzles::empty_ballot_membership_siblings();
        let ballot_membership_value: (Bytes32, Vec<Bytes32>) =
            (params.ballot_launcher_id, siblings);

        // mint_voting_coin solution shape (per the puzzle,
        // M5r-merkle-e — voting_coin_amount moved from rest-arg to
        // regular, trailing rest is now ...vote_option_proof):
        //   (ballot_launcher_id, vote_close_height, vote_options_root,
        //    vote_data, ballot_coin_id, registration_coin_id,
        //    initial_signature, ballot_membership_witness,
        //    voting_coin_amount, vote_option_leaf_index,
        //    vote_option_proof_depth, ...vote_option_proof)
        // Caller-supplied vote_options_root + (leaf_index, proof) come
        // from CastVoteParams. Mode1Free → root=0x00…00, idx=0,
        // depth=0, proof=nil; the puzzle's gate short-circuits.
        let vote_options_root_for_solution: Bytes32 = params.vote_options_root;
        let (vote_option_leaf_index, vote_option_proof_depth, vote_option_proof_cons) =
            match &params.vote_option_proof {
                Some((idx, proof)) => {
                    let cons: Vec<Bytes32> = proof.clone();
                    (*idx as u64, cons.len() as u64, cons)
                }
                None => (0u64, 0u64, Vec::<Bytes32>::new()),
            };
        let mint_solution_value = (
            params.ballot_launcher_id,
            (
                params.vote_close_height,
                (
                    vote_options_root_for_solution,
                    (
                        params.vote_data,
                        (
                            ballot_coin_id,
                            (
                                registration_coin_id,
                                (
                                    initial_signature_bytes.clone(),
                                    (
                                        ballot_membership_value,
                                        (
                                            params.voting_coin_amount,
                                            (
                                                vote_option_leaf_index,
                                                (
                                                    vote_option_proof_depth,
                                                    vote_option_proof_cons,
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        );
        let mint_solution = mint_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let reg_action_spends = vec![ActionSpend {
            puzzle: mint_voting_coin_curried,
            solution: mint_solution,
        }];
        // Registration finalizer takes `..._my_amount: Int` — pass
        // (collateral_amount - voting_coin_amount) so the recreated
        // Registration Coin gets the residual CAT amount and the CAT
        // outer's conservation rule is satisfied (input ==
        // recreated + voting_coin).
        if params.voting_coin_amount > self.config.collateral_amount {
            return Err(voting_other(format!(
                "Voter::cast_vote: voting_coin_amount {} exceeds collateral_amount {}",
                params.voting_coin_amount, self.config.collateral_amount,
            )));
        }
        let recreated_amount = self.config.collateral_amount - params.voting_coin_amount;
        let reg_finalizer_solution = recreated_amount.to_clvm(&mut *ctx).map_err(driver_err)?;
        let reg_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &puzzles::registration_action_root_leaves(cat_tail_hash),
            &reg_action_spends,
            reg_finalizer_solution,
        )?;

        // CAT outer wrap. prev/next coin id = self for a single-CAT
        // ring (we don't co-spend any other CAT in this bundle).
        let reg_coin_id_for_ring = registration_coin.coin_id();
        let cat_mint_spend = crate::action_spends::build_cat_spend(
            &mut ctx,
            registration_coin,
            cat_tail_hash,
            reg_action_layer_node,
            reg_action_layer_solution,
            cat_lineage_proof,
            reg_coin_id_for_ring,
            reg_coin_id_for_ring,
            0,
        )?;

        // ── 7. Compute the Voting Coin's coin id ─────────────────
        // The Voting Coin's full puzzle hash is the CAT-wrapped
        // action layer over its (voter_pubkey, ballot_launcher_id,
        // vote_data, registration_coin_id) state.
        let voting_coin_full_ph = puzzles::voting_coin_puzzle_hash(
            PuzzleHashes::cat_outer(),
            cat_tail_hash,
            PuzzleHashes::action_layer(),
            PuzzleHashes::voting_coin_finalizer(),
            puzzles::voting_coin_actions_merkle_root(),
            &self.keys.pubkey,
            params.ballot_launcher_id,
            election_id,
            params.vote_data,
            registration_coin_id,
        );
        let voting_coin = Coin::new(
            registration_coin_id,
            voting_coin_full_ph,
            params.voting_coin_amount,
        );
        let voting_coin_id = voting_coin.coin_id();

        // ── 8. Dry-run + return unsigned coin_spends ─────────────
        // The bundle aggregate signature is the caller's job — for the
        // secret-key path that's `Voter::cast_vote`'s wrapper below;
        // for the Sage path it's a second `chip0002_signCoinSpends`.
        let coin_spends = vec![ballot_singleton_spend, cat_mint_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "voter-cast_vote-failed-{}.json",
                    chrono_compat_now()
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
                    "coin_spends": coin_spends.iter().map(|cs| serde_json::json!({
                        "coin": {
                            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                            "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                            "amount": cs.coin.amount,
                        },
                        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                        "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                    })).collect::<Vec<_>>(),
                })).unwrap_or_else(|_| "<json serialise failed>".into());
                let _ = std::fs::write(&path, json);
                tracing::warn!(dump_path = %path.display(), "wrote failing bundle to disk");
            }
            return Err(voting_other(format!("Voter::cast_vote dry-run: {e:?}")));
        }

        Ok(CastVoteCoinSpends {
            coin_spends,
            voting_coin_id,
            vote_signature: initial_signature_bytes,
            vote_message: vm,
        })
    }

    /// Build a `cast_vote` spend bundle using `self.keys.secret` for
    /// signing — the secret-key path for native CLI / integration test
    /// callers. Browser dApps that don't hold the secret should use
    /// [`Voter::cast_vote_build_coin_spends`] + an external
    /// chip0002 signer.
    pub async fn cast_vote<C: ChainReader>(
        &self,
        chain: &C,
        params: CastVoteParams,
    ) -> VotingResult<CastVoteResult> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let vm = puzzles::vote_message(
            params.vote_data,
            params.ballot_launcher_id,
            election_id,
        );
        let initial_signature = self.keys.sign_unsafe(vm.as_ref());
        let initial_signature_bytes =
            chia_protocol::Bytes::new(initial_signature.to_bytes().to_vec());

        let CastVoteCoinSpends {
            coin_spends,
            voting_coin_id,
            vote_signature,
            ..
        } = self
            .cast_vote_build_coin_spends(chain, &params, initial_signature_bytes)
            .await?;

        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;

        Ok(CastVoteResult {
            voting_coin_id,
            spend_bundle: SpendBundle::new(coin_spends, signature),
            vote_signature,
        })
    }

    /// Build an `update_vote` spend bundle.
    ///
    /// FLOW (CHIP rev 2026-05-02):
    ///   1. Locate the voter's existing Voting Coin (by
    ///      `voting_coin_id`) and verify its on-chain ph matches the
    ///      SDK's prediction from `(old_vote_data, registration_coin_id)`
    ///      — otherwise the params don't match the coin we're trying
    ///      to spend.
    ///   2. Reconstruct the CAT lineage proof from the Voting Coin's
    ///      parent on-chain spend (the CAT-wrapped mint_voting_coin
    ///      spend that minted it).
    ///   3. Find the current unspent Ballot Coin singleton (post any
    ///      prior oracle co-spends). The Ballot Coin's BallotState
    ///      is unchanged across oracle spends, so its inner ph
    ///      stays the same; the lineage proof advances on each spend.
    ///   4. Build the Ballot Coin oracle co-spend (same shape as in
    ///      `cast_vote`, but with a `Lineage` proof instead of `Eve`).
    ///   5. Build the Voting Coin's `update_vote` action spend. Its
    ///      6-field solution carries
    ///      `(ballot_launcher_id, election_launcher_id,
    ///        vote_close_height, new_vote_data, new_signature,
    ///        ...ballot_coin_id)`. The action emits AggSigMe over
    ///      the new vote_message which the bundle signer collects.
    ///   6. Wrap the Voting Coin spend with the CAT outer (same TAIL
    ///      as the Registration Coin) and the Ballot Coin spend with
    ///      the Singleton outer. Sign + bundle.
    ///
    /// **NO singleton co-spend on the Election Singleton.** Vote
    /// edits live entirely on the Ballot Coin / Voting Coin lane.
    /// Sage-friendly variant of [`Voter::update_vote`]. Takes a
    /// pre-computed `new_signature` (the voter's
    /// `sign_unsafe(new_vote_message)` BLS sig). Returns unsigned
    /// coin_spends; caller signs the bundle aggregate externally.
    /// Mirrors [`Voter::cast_vote_build_coin_spends`].
    pub async fn update_vote_build_coin_spends<C: ChainReader>(
        &self,
        chain: &C,
        params: &UpdateVoteParams,
        new_signature: chia_protocol::Bytes,
    ) -> VotingResult<UpdateVoteCoinSpends> {
        use chia_protocol::Bytes;
        use chia_puzzle_types::singleton::SingletonArgs;
        // (chia_puzzle_types::Proof types only used inside
        // find_current_ballot_singleton — not needed here.)
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::{tree_hash, CurriedProgram, TreeHash};

        if new_signature.len() != 96 {
            return Err(voting_other(format!(
                "Voter::update_vote_build_coin_spends: new_signature must be 96 bytes \
                 (BLS G2), got {}",
                new_signature.len(),
            )));
        }
        let new_signature_bytes: Bytes = new_signature;

        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;

        // Phase 2b: chain-walk override of caller-supplied per-ballot
        // curry params (see cast_vote_build_coin_spends for rationale).
        let memo = crate::actors::ballot::read_ballot_launcher_memo(
            chain,
            params.ballot_launcher_id,
        )
        .await?;
        let mut effective_params = params.clone();
        if let Some(m) = &memo {
            effective_params.vote_close_height = m.vote_close_height;
            effective_params.vote_threshold_num = m.vote_threshold_num;
            effective_params.vote_threshold_den = m.vote_threshold_den;
            effective_params.registration_merkle_root_snapshot = m.registration_merkle_root_snapshot;
            effective_params.registration_vote_weight_snapshot = m.registration_vote_weight_snapshot;
        }
        let params = &effective_params;

        // ── 1. Locate the Voting Coin + verify its predicted ph ──
        let voting_coin_record = chain
            .coin_record_by_id(params.voting_coin_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::update_vote: voting coin {} not found on chain",
                    hex::encode(params.voting_coin_id),
                ))
            })?;
        if !voting_coin_record.is_unspent() {
            return Err(voting_other(format!(
                "Voter::update_vote: voting coin {} already spent",
                hex::encode(params.voting_coin_id),
            )));
        }
        let voting_coin = voting_coin_record.coin;
        let predicted_voting_coin_ph = puzzles::voting_coin_puzzle_hash(
            PuzzleHashes::cat_outer(),
            cat_tail_hash,
            PuzzleHashes::action_layer(),
            PuzzleHashes::voting_coin_finalizer(),
            puzzles::voting_coin_actions_merkle_root(),
            &self.keys.pubkey,
            params.ballot_launcher_id,
            election_id,
            params.old_vote_data,
            params.registration_coin_id,
        );
        if voting_coin.puzzle_hash != predicted_voting_coin_ph {
            return Err(voting_other(format!(
                "Voter::update_vote: on-chain voting coin ph {} doesn't match predicted {} \
                 — UpdateVoteParams (old_vote_data, registration_coin_id) don't match the \
                 coin's curried state",
                hex::encode(voting_coin.puzzle_hash),
                hex::encode(predicted_voting_coin_ph),
            )));
        }
        let voting_cat_lineage_proof = self
            .reconstruct_cat_lineage(chain, voting_coin)
            .await?;

        // ── 2. Reconstruct per-ballot Ballot Coin curry layout ───
        // We need the inner_ph BEFORE walking the singleton lineage
        // so the walker can build Lineage proofs.
        let mut ctx = SpendContext::new();
        let (vk_node, ic_node) =
            crate::actors::ballot::build_vk_ic_nodes(&mut ctx, &self.config)?;

        let finalize_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_FINALIZE_HEX)?;
        let finalize_curried = CurriedProgram {
            program: finalize_program_node,
            args: clvm_curried_args!(
                vk_node,
                ic_node,
                params.ballot_launcher_id,
                election_id,
                params.vote_close_height,
                params.vote_threshold_num,
                params.vote_threshold_den,
                params.registration_merkle_root_snapshot,
                params.registration_vote_weight_snapshot,
                // SEC-F3+F5: MUST match launch_ballot's 11-arg finalize curry.
                self.config.vk_hash(),
                params.vote_options_root,
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let finalize_full_hash = Bytes32::new(tree_hash(&ctx, finalize_curried).to_bytes());

        // M4-revised oracle curry adds VOTE_OPTIONS_ROOT (Mode1Free
        // sentinel default until M7e wires the real value).
        let vote_options_root_curry: Bytes32 = Bytes32::default();
        let oracle_program_node = load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ORACLE_HEX)?;
        let oracle_curried = CurriedProgram {
            program: oracle_program_node,
            args: clvm_curried_args!(
                params.ballot_launcher_id,
                params.vote_close_height,
                vote_options_root_curry
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let oracle_full_hash = Bytes32::new(tree_hash(&ctx, oracle_curried).to_bytes());

        let announce_program_node =
            load_action_puzzle(&mut ctx, puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX)?;
        let announce_curried = CurriedProgram {
            program: announce_program_node,
            args: clvm_curried_args!(params.ballot_launcher_id),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;
        let announce_full_hash =
            Bytes32::new(tree_hash(&ctx, announce_curried).to_bytes());

        let ballot_actions_root = puzzles::per_ballot_actions_merkle_root(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );
        let ballot_root_leaves = puzzles::per_ballot_action_root_leaves(
            finalize_full_hash,
            oracle_full_hash,
            announce_full_hash,
        );

        // The BallotState is `fresh` until finalize runs, so the
        // inner ph is the same as what launch_ballot computed.
        let ballot_finalizer_node =
            crate::action_spends::build_ballot_finalizer_full(&mut ctx, params.ballot_launcher_id)?;
        // SEC-F1: BallotState = (finalized . (vote_outcome . agg_signers));
        // `finalized` MUST be nil (Rue `false`), not Bytes32::default().
        let fresh_ballot_state_value: ((), (Bytes32, Bytes32)) =
            ((), (Bytes32::default(), Bytes32::default()));
        let ballot_state_node = fresh_ballot_state_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let ballot_inner_node = build_action_layer_puzzle(
            &mut ctx,
            ballot_finalizer_node,
            ballot_actions_root,
            ballot_state_node,
        )?;
        let ballot_inner_ph = Bytes32::new(tree_hash(&ctx, ballot_inner_node).to_bytes());
        let ballot_inner_th = TreeHash::new(ballot_inner_ph.to_bytes());
        let predicted_ballot_full_ph = Bytes32::new(
            SingletonArgs::curry_tree_hash(params.ballot_launcher_id, ballot_inner_th).to_bytes(),
        );

        // ── 3. Find the current unspent Ballot Coin singleton ────
        // (post any prior oracle co-spends from cast_vote /
        // update_vote / announce_finalization).
        let (ballot_coin, ballot_lineage_proof) = find_current_ballot_singleton(
            chain,
            params.ballot_launcher_id,
            ballot_inner_ph,
        )
        .await?;
        let ballot_coin_id = ballot_coin.coin_id();

        if ballot_coin.puzzle_hash != predicted_ballot_full_ph {
            return Err(voting_other(format!(
                "Voter::update_vote: Ballot Coin on-chain ph {} doesn't match predicted {} \
                 — UpdateVoteParams's per-ballot fields don't match what BallotIssuer used",
                hex::encode(ballot_coin.puzzle_hash),
                hex::encode(predicted_ballot_full_ph),
            )));
        }

        // ── 4. Ballot Coin oracle (open) co-spend ────────────────
        let oracle_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let ballot_action_spends = vec![ActionSpend {
            puzzle: oracle_curried,
            solution: oracle_solution,
        }];
        let ballot_finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let ballot_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &ballot_root_leaves,
            &ballot_action_spends,
            ballot_finalizer_solution,
        )?;

        let ballot_singleton_spend = build_singleton_spend(
            &mut ctx,
            ballot_coin,
            params.ballot_launcher_id,
            ballot_inner_node,
            ballot_action_layer_solution,
            ballot_lineage_proof,
        )?;

        // ── 5. Voting Coin update_vote spend ─────────────────────
        // Voting Coin's action layer is curried with VC finalizer
        // (HINT = voting_coin_hint), VC actions merkle root (= the
        // uncurried update_vote tree hash, post our update_vote.rue
        // change), and the curried state matching the coin we're
        // spending.
        let voting_coin_hint = puzzles::voting_coin_hint(
            election_id,
            cat_tail_hash,
            &self.keys.pubkey,
            params.ballot_launcher_id,
        );
        let vc_finalizer = build_voting_coin_finalizer_full(&mut ctx, voting_coin_hint)?;
        let vc_merkle_root = puzzles::voting_coin_actions_merkle_root();
        // VotingCoinState shape (3 normal fields + 1 rest-arg on last):
        //   `(voter_pubkey . (ballot_launcher_id . (vote_data .
        //     registration_coin_id)))`
        let pk_bytes = Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let voting_state_value = (
            pk_bytes,
            (
                params.ballot_launcher_id,
                (params.old_vote_data, params.registration_coin_id),
            ),
        );
        let voting_state_node = voting_state_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let vc_action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            vc_finalizer,
            vc_merkle_root,
            voting_state_node,
        )?;

        // update_vote takes NO curry args (post CHIP rev 2026-05-02
        // — see puzzles/voting_coin/update_vote.rue header). Solution
        // shape (M5r-merkle-a — adds the on-chain merkle-inclusion
        // gate's args at the tail):
        //   `(ballot_launcher_id, election_launcher_id,
        //     vote_close_height, vote_options_root, new_vote_data,
        //     new_signature, ballot_coin_id, vote_option_leaf_index,
        //     vote_option_proof_depth, ...vote_option_proof)`
        // Mode1Free → leaf_index=0, depth=0, proof=nil (the rue gate
        // skips the merkle check). Mode2Restricted → caller-supplied.
        let update_vote_program_node =
            load_action_puzzle(&mut ctx, puzzles::VOTING_COIN_UPDATE_VOTE_HEX)?;

        // The voter signs new_vote_message UNAUGMENTED so the
        // off-chain aggregator can verify against the published
        // pubkey directly. In this builder the signature is passed in
        // (the secret-key wrapper below computes it from self.keys).
        let new_vm = puzzles::vote_message(
            params.new_vote_data,
            params.ballot_launcher_id,
            election_id,
        );

        // M5-revised: vote_options_root that the Ballot Coin's oracle
        // is curried with. Threaded from UpdateVoteParams so the SDK
        // emits the matching value into both the oracle preimage and
        // (when non-zero) the merkle proof check.
        let vote_options_root_for_solution: Bytes32 = params.vote_options_root;
        // M5r-merkle-b: caller-supplied (leaf_index, proof) for
        // Mode2Restricted, or Mode1Free defaults `(0, 0, nil)`.
        let (vote_option_leaf_index, vote_option_proof_depth, vote_option_proof_cons) =
            match &params.vote_option_proof {
                Some((idx, proof)) => {
                    let cons: Vec<Bytes32> = proof.clone();
                    (*idx as u64, cons.len() as u64, cons)
                }
                None => (0u64, 0u64, Vec::<Bytes32>::new()),
            };
        let update_vote_solution_value = (
            params.ballot_launcher_id,
            (
                election_id,
                (
                    params.vote_close_height,
                    (
                        vote_options_root_for_solution,
                        (
                            params.new_vote_data,
                            (
                                new_signature_bytes.clone(),
                                (
                                    ballot_coin_id,
                                    (
                                        vote_option_leaf_index,
                                        (vote_option_proof_depth, vote_option_proof_cons),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        );
        let update_vote_solution = update_vote_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let vc_action_spends = vec![ActionSpend {
            puzzle: update_vote_program_node,
            solution: update_vote_solution,
        }];
        // VC finalizer takes `..._my_amount: Int` (mirrors the
        // Registration Coin finalizer); pass the voting coin's amount
        // so the recreated VC gets the same CAT amount.
        let vc_finalizer_solution = voting_coin
            .amount
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let vc_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            std::slice::from_ref(&PuzzleHashes::voting_coin_update_vote()),
            &vc_action_spends,
            vc_finalizer_solution,
        )?;

        // CAT outer wrap. Single-CAT ring (we don't co-spend any
        // other CAT in this bundle).
        let voting_coin_id_for_ring = voting_coin.coin_id();
        let cat_update_spend = crate::action_spends::build_cat_spend(
            &mut ctx,
            voting_coin,
            cat_tail_hash,
            vc_action_layer_node,
            vc_action_layer_solution,
            voting_cat_lineage_proof,
            voting_coin_id_for_ring,
            voting_coin_id_for_ring,
            0,
        )?;

        // ── 6. Compute the recreated Voting Coin's coin id ──────
        let recreated_voting_coin_ph = puzzles::voting_coin_puzzle_hash(
            PuzzleHashes::cat_outer(),
            cat_tail_hash,
            PuzzleHashes::action_layer(),
            PuzzleHashes::voting_coin_finalizer(),
            puzzles::voting_coin_actions_merkle_root(),
            &self.keys.pubkey,
            params.ballot_launcher_id,
            election_id,
            params.new_vote_data,
            params.registration_coin_id,
        );
        let recreated_voting_coin = chia_protocol::Coin::new(
            voting_coin_id_for_ring,
            recreated_voting_coin_ph,
            voting_coin.amount,
        );
        let recreated_voting_coin_id = recreated_voting_coin.coin_id();

        // ── 7. Sign + bundle ─────────────────────────────────────
        let coin_spends = vec![ballot_singleton_spend, cat_update_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "voter-update_vote-failed-{}.json",
                    chrono_compat_now()
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
                    "coin_spends": coin_spends.iter().map(|cs| serde_json::json!({
                        "coin": {
                            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                            "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                            "amount": cs.coin.amount,
                        },
                        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                        "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                    })).collect::<Vec<_>>(),
                })).unwrap_or_else(|_| "<json serialise failed>".into());
                let _ = std::fs::write(&path, json);
                tracing::warn!(dump_path = %path.display(), "wrote failing bundle to disk");
            }
            return Err(voting_other(format!(
                "Voter::update_vote dry-run: {e:?}"
            )));
        }

        Ok(UpdateVoteCoinSpends {
            coin_spends,
            recreated_voting_coin_id,
            new_vote_signature: new_signature_bytes,
            new_vote_message: new_vm,
        })
    }

    /// Build an `update_vote` spend bundle using `self.keys.secret`
    /// for signing — the secret-key path for native CLI / integration
    /// test callers. Browser dApps that don't hold the secret should
    /// use [`Voter::update_vote_build_coin_spends`].
    pub async fn update_vote<C: ChainReader>(
        &self,
        chain: &C,
        params: UpdateVoteParams,
    ) -> VotingResult<UpdateVoteResult> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let new_vm = puzzles::vote_message(
            params.new_vote_data,
            params.ballot_launcher_id,
            election_id,
        );
        let new_signature = self.keys.sign_unsafe(new_vm.as_ref());
        let new_signature_bytes =
            chia_protocol::Bytes::new(new_signature.to_bytes().to_vec());

        let UpdateVoteCoinSpends {
            coin_spends,
            recreated_voting_coin_id,
            new_vote_signature,
            ..
        } = self
            .update_vote_build_coin_spends(chain, &params, new_signature_bytes)
            .await?;

        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;
        Ok(UpdateVoteResult {
            recreated_voting_coin_id,
            spend_bundle: SpendBundle::new(coin_spends, signature),
            new_vote_signature,
        })
    }

    /// Build a collateral release spend bundle.
    ///
    /// FLOW (CHIP rev 2026-05-02):
    ///   1. Locate the current Election Singleton via the launcher
    ///      lineage walker (same path as `Voter::register`).
    ///   2. Build the curried `deregister` action puzzle and its
    ///      solution `(voter_pubkey, leaf_index, ...siblings)` — the
    ///      SPT membership proof that wipes this voter's leaf.
    ///   3. Wrap with the action layer + singleton outer.
    ///   4. Look up the voter's Registration Coin by id; verify it
    ///      sits at the predicted CAT-wrapped puzzle hash for the
    ///      voter's CURRENT `RegistrationState` (this driver currently
    ///      assumes a `fresh` state — i.e., the voter has not yet
    ///      cast any votes nor previously called release).
    ///   5. Build the `release` action solution
    ///      `(collateral_destination, ...singleton_coin_id)`. The
    ///      action asserts the singleton's deregister announcement
    ///      via the supplied `singleton_coin_id`.
    ///   6. Wrap with the registration-coin action layer and the
    ///      CAT outer. Reconstruct the CAT lineage proof from the
    ///      Registration Coin's on-chain parent spend.
    ///   7. Sign with the voter's BLS key (both `deregister` and
    ///      `release` emit `AggSigMe` conditions covered by
    ///      `RequiredSignature::from_coin_spends`).
    ///
    /// API NOTE: takes a `&SparseMerkleTree` snapshot mirroring the
    /// singleton's current SPT root so the deregister proof can be
    /// computed; callers should sync via `Aggregator::sync_with_chain`
    /// or maintain their own SMT before calling.
    /// Sage-friendly variant of [`Voter::release_collateral`].
    /// Returns the unsigned coin_spends; the caller (typically a
    /// browser dApp via chip0002_signCoinSpends) signs the bundle's
    /// AGG_SIG_ME conditions externally. release_collateral has no
    /// `sign_unsafe` step (no off-chain aggregator sig like
    /// cast_vote / update_vote) — Sage signs everything in one pass.
    pub async fn release_collateral_build_coin_spends<C: ChainReader>(
        &self,
        chain: &C,
        smt: &crate::merkle::PoseidonSmt,
        registration_coin_id: Bytes32,
        destination: Bytes32,
    ) -> VotingResult<Vec<CoinSpend>> {
        use clvm_traits::{clvm_curried_args, ToClvm};
        use clvm_utils::CurriedProgram;

        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;

        // ── 1. Find the current Election Singleton ──────────────
        // See Voter::register for why `self.election_start_height`
        // (not 0) MUST be plumbed through to the launcher walker.
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            self.election_start_height,
            "Election Singleton (release_collateral)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        let crate::actors::aggregator::CurrentSingleton {
            coin: singleton_coin,
            lineage_proof: singleton_lineage_proof,
            state: on_chain_state,
            ..
        } = current;

        // The voter MUST be in the on-chain SMT; this is what the
        // deregister action's membership proof asserts. Surface the
        // mismatch early instead of as an opaque CLVM raise.
        // SEC-F1: the Poseidon SPT root is the 32-byte BE of the Fr root.
        let smt_root = Bytes32::new(smt.root_be32());
        if smt_root != on_chain_state.registration_merkle_root {
            return Err(voting_other(format!(
                "Voter::release_collateral: SMT root {} doesn't match on-chain {} — re-sync",
                hex::encode(smt_root),
                hex::encode(on_chain_state.registration_merkle_root),
            )));
        }
        // ── 2. Build the deregister action layer + solution ──────
        let mut ctx = SpendContext::new();
        let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id)?;
        let merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&self.config);
        let election_state_node = self.election_state_node(&mut ctx, &on_chain_state)?;
        let action_layer_node =
            build_action_layer_puzzle(&mut ctx, elect_finalizer, merkle_root, election_state_node)?;
        // SEC-F4: release.rue re-derives the genuine Election Singleton's
        // puzzle hash from election_launcher_id (unforgeable state) + this
        // inner puzzle hash, and commits it as the CHIP-0025 message
        // SENDER. It equals `SingletonArgs::curry_tree_hash(election_id,
        // singleton_inner_ph)` = `singleton_coin.puzzle_hash`.
        let singleton_inner_ph =
            Bytes32::new(clvm_utils::tree_hash(&ctx, action_layer_node).to_bytes());

        // CURRY ORDER (per `puzzles/election/deregister.rue`):
        //   (TREE_DEPTH, EMPTY_LEAF_HASH, COLLATERAL_AMOUNT,
        //    REGISTRATION_MERKLE_ROOT)
        // where REGISTRATION_MERKLE_ROOT here is the inner-coin action
        // root (registration_actions_merkle_root) — see deployer.rs.
        let deregister_program_node =
            load_action_puzzle(&mut ctx, puzzles::ELECTION_DEREGISTER_HEX)?;
        let deregister_curried = CurriedProgram {
            program: deregister_program_node,
            args: clvm_curried_args!(
                crate::config::TREE_DEPTH,
                Bytes32::new(crate::config::EMPTY_LEAF_HASH),
                self.config.collateral_amount,
                puzzles::registration_actions_merkle_root(cat_tail_hash)
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // Solution shape (per deregister.rue, SEC-F1 Poseidon/Jubjub rev):
        //   `(voter_pubkey, jub_x, jub_y, deregister_leaf_index,
        //     locked_cat_mojos, ...deregister_siblings)`
        // The BLS `voter_pubkey` stays first (deregister.rue uses it for
        // the CHIP-0025 SEND_MESSAGE + AggSigMe). The Jubjub coords key
        // the SPT leaf + slot. Same 5-byte `0x00 || sha256(...)[0..4]`
        // slot encoding register.rue uses.
        //
        // `locked_cat_mojos` is recovered from the SMT — the membership
        // proof verifies only for the same value the voter registered
        // with, so we pass exactly what the SMT has on file.
        let slot = self.slot();
        let proof = smt.prove(slot);
        let siblings: Vec<Bytes32> = proof
            .siblings
            .iter()
            .map(|f| Bytes32::new(crate::merkle::fr_to_be32(*f)))
            .collect();
        let lock_amount = smt.locked_amount(self.keys.jubjub_pubkey).ok_or_else(|| {
            voting_other(
                "Voter::release_collateral: SMT has no locked amount for this voter — \
                 was the SMT synced from chain?",
            )
        })?;
        let voter_pk_bytes = chia_protocol::Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let jub_x = Bytes32::new(crate::merkle::fr_to_be32(self.keys.jubjub_pubkey.x));
        let jub_y = Bytes32::new(crate::merkle::fr_to_be32(self.keys.jubjub_pubkey.y));
        let slot_bytes = {
            let mut buf = Vec::with_capacity(5);
            buf.push(0x00);
            buf.extend_from_slice(&slot.to_be_bytes());
            chia_protocol::Bytes::new(buf)
        };
        let deregister_solution_value = (
            voter_pk_bytes,
            (jub_x, (jub_y, (slot_bytes, (lock_amount, siblings)))),
        );
        let deregister_solution = deregister_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let deregister_action_spends = vec![ActionSpend {
            puzzle: deregister_curried,
            solution: deregister_solution,
        }];
        let elect_finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &crate::actors::aggregator::compute_election_action_root_leaves(&self.config),
            &deregister_action_spends,
            elect_finalizer_solution,
        )?;

        let deregister_singleton_spend = build_singleton_spend(
            &mut ctx,
            singleton_coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            singleton_lineage_proof,
        )?;

        // ── 3. Locate + reconstruct the Registration Coin ────────
        let reg_record = chain
            .coin_record_by_id(registration_coin_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::release_collateral: registration coin {} not found on chain",
                    hex::encode(registration_coin_id),
                ))
            })?;
        if !reg_record.is_unspent() {
            return Err(voting_other(format!(
                "Voter::release_collateral: registration coin {} already spent",
                hex::encode(registration_coin_id),
            )));
        }
        // Walk the registration coin's CAT lineage backward to recover
        // the list of ballot_launcher_ids the voter has cast on. Each
        // parent spend's `mint_voting_coin` solution carries a
        // `ballot_launcher_id` atom; if the parent is the eve CAT
        // (issuance), we stop. The resulting `voted_ballots_root`
        // matches the on-chain coin's actual state — fresh
        // (no votes) maps to `empty_ballot_root()`; post-cast inserts
        // each ballot id at its `ballot_slot_from_id` slot.
        let cast_ballot_ids = self
            .walk_voted_ballots_history(chain, reg_record.coin)
            .await?;
        let voted_ballots_root = puzzles::voted_ballots_root_after_inserts(&cast_ballot_ids);

        // SEC-F2: `locked_weight` is decremented by each cast's
        // `voting_coin_amount` (mint_voting_coin.rue), so it always equals
        // the registration coin's CURRENT CAT balance — use the on-chain
        // coin amount, not the deployment-wide collateral floor.
        let predicted_reg_inner_ph = puzzles::registration_inner_hash_for_state(
            &self.keys.pubkey,
            election_id,
            cat_tail_hash,
            voted_ballots_root,
            reg_record.coin.amount,
            None,
        );
        let predicted_reg_outer_ph = puzzles::cat_outer_for_inner_hash(
            cat_tail_hash,
            predicted_reg_inner_ph,
        );
        if reg_record.coin.puzzle_hash != predicted_reg_outer_ph {
            return Err(voting_other(format!(
                "Voter::release_collateral: registration coin puzzle hash {} doesn't match \
                 predicted CAT-wrapped ph {} for the voter's recovered state \
                 (voted_ballots_root = {}; cast_ballot_ids = [{}]) — \
                 the lineage walk likely missed a cast or update_vote spend; \
                 ensure all ancestor spends are queryable on the supplied chain reader",
                hex::encode(reg_record.coin.puzzle_hash),
                hex::encode(predicted_reg_outer_ph),
                hex::encode(voted_ballots_root),
                cast_ballot_ids
                    .iter()
                    .map(|b| hex::encode(b))
                    .collect::<Vec<_>>()
                    .join(", "),
            )));
        }

        let cat_lineage_proof = self
            .reconstruct_cat_lineage(chain, reg_record.coin)
            .await?;

        // ── 4. Build the release action layer + solution ─────────
        let voter_hint = puzzles::voter_hint(election_id, cat_tail_hash, &self.keys.pubkey);
        let reg_finalizer = crate::action_spends::build_registration_finalizer_full(
            &mut ctx,
            voter_hint,
        )?;
        // Registration coin's action layer is curried with the
        // REGISTRATION action root (NOT the election action root).
        let reg_merkle_root = puzzles::registration_actions_merkle_root(cat_tail_hash);
        let reg_state = crate::state::RegistrationState {
            voter_pubkey: self.keys.pubkey,
            election_launcher_id: election_id,
            voted_ballots_root,
            // SEC-F2: current CAT balance == current locked_weight (see above).
            locked_weight: reg_record.coin.amount,
            release_destination: None,
        };
        let reg_state_node = self.registration_state_node(&mut ctx, &reg_state)?;
        let reg_action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            reg_finalizer,
            reg_merkle_root,
            reg_state_node,
        )?;

        // The release action takes NO curried params (per release.rue
        // header — voter_pubkey + election_launcher_id are read from
        // state, not curried).
        let release_program_node = load_action_puzzle(&mut ctx, puzzles::REGISTRATION_RELEASE_HEX)?;

        // Solution shape (per release.rue):
        //   `(collateral_destination, ...singleton_inner_puzzle_hash)`
        let release_solution_value = (destination, singleton_inner_ph);
        let release_solution = release_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let release_action_spends = vec![ActionSpend {
            puzzle: release_program_node,
            solution: release_solution,
        }];
        // Registration finalizer takes `..._my_amount: Int` — pass
        // the on-chain registration coin's CURRENT amount, which
        // equals `collateral_amount` for a never-cast coin and
        // `collateral_amount - sum(voting_coin_amounts)` once one or
        // more cast_vote spends have peeled off voting-coin mojos.
        let reg_finalizer_solution = reg_record
            .coin
            .amount
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let reg_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &puzzles::registration_action_root_leaves(cat_tail_hash),
            &release_action_spends,
            reg_finalizer_solution,
        )?;

        // ── 5. Wrap with CAT outer ──────────────────────────────
        let reg_coin_id = reg_record.coin.coin_id();
        let cat_release_spend = crate::action_spends::build_cat_spend(
            &mut ctx,
            reg_record.coin,
            cat_tail_hash,
            reg_action_layer_node,
            reg_action_layer_solution,
            cat_lineage_proof,
            reg_coin_id, // single-CAT ring: prev = self
            reg_coin_id, // single-CAT ring: next = self
            0,
        )?;

        // ── 6. Sign + bundle ────────────────────────────────────
        let coin_spends = vec![deregister_singleton_spend, cat_release_spend];
        if let Err(e) = crate::dry_run_coin_spends(&coin_spends) {
            if let Ok(dir) = std::env::var("CHIP_VOTING_DUMP_DIR") {
                let path = std::path::Path::new(&dir).join(format!(
                    "release_collateral-failed-{}.json",
                    chrono_compat_now()
                ));
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "error": format!("{e:?}"),
                    "coin_spends": coin_spends.iter().map(|cs| serde_json::json!({
                        "coin": {
                            "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                            "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                            "amount": cs.coin.amount,
                        },
                        "puzzle_reveal_hex": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                        "solution_hex": format!("0x{}", hex::encode(cs.solution.as_ref())),
                    })).collect::<Vec<_>>(),
                })).unwrap_or_else(|_| "<json serialise failed>".into());
                let _ = std::fs::write(&path, json);
                tracing::warn!(dump_path = %path.display(), "wrote failing bundle to disk");
            }
            return Err(voting_other(format!(
                "Voter::release_collateral dry-run: {e:?}"
            )));
        }

        Ok(coin_spends)
    }

    /// Build a release-collateral SpendBundle using `self.keys.secret`
    /// for signing — the secret-key path for native CLI / integration
    /// test callers. Browser dApps that don't hold the secret should
    /// use [`Voter::release_collateral_build_coin_spends`].
    pub async fn release_collateral<C: ChainReader>(
        &self,
        chain: &C,
        smt: &crate::merkle::PoseidonSmt,
        registration_coin_id: Bytes32,
        destination: Bytes32,
    ) -> VotingResult<SpendBundle> {
        let coin_spends = self
            .release_collateral_build_coin_spends(chain, smt, registration_coin_id, destination)
            .await?;
        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Build the RegistrationState CLVM tree node.
    ///
    /// SHAPE: matches `puzzles/registration_coin/shared.rue`:
    ///   `(voter_pubkey . (election_launcher_id . (voted_ballots_root .
    ///    release_destination)))`
    /// — `release_destination` is the trailing tail (`Bytes32 | nil`),
    /// NOT wrapped in `(_ . NIL)`. For `release_destination = None`
    /// the trailing field is the empty atom (nil); for `Some(dest)`
    /// it's the destination bytes32.
    fn registration_state_node(
        &self,
        ctx: &mut SpendContext,
        state: &crate::state::RegistrationState,
    ) -> VotingResult<clvmr::NodePtr> {
        let pk_bytes = chia_protocol::Bytes::new(state.voter_pubkey.to_bytes().to_vec());
        // SEC-F2: on-chain `RegistrationState` carries `locked_weight`
        // between `voted_ballots_root` and `release_destination`:
        //   (pk . (el . (vbr . (locked_weight . release_destination))))
        // This MUST match `puzzles::registration_inner_hash_for_state`
        // and the `register.rue` finalizer's recreated state, or the
        // built spend's puzzle hash diverges from the on-chain coin.
        match state.release_destination {
            None => (
                pk_bytes,
                (
                    state.election_launcher_id,
                    (state.voted_ballots_root, (state.locked_weight, ())),
                ),
            )
                .to_clvm(&mut **ctx)
                .map_err(driver_err),
            Some(dest) => (
                pk_bytes,
                (
                    state.election_launcher_id,
                    (
                        state.voted_ballots_root,
                        (state.locked_weight, dest),
                    ),
                ),
            )
                .to_clvm(&mut **ctx)
                .map_err(driver_err),
        }
    }

    // ── Internal helpers for spend assembly ─────────────────────

    /// Walk the registration coin's CAT lineage backward and recover
    /// the list of `ballot_launcher_id`s the voter has cast on. The
    /// resulting `voted_ballots_root_after_inserts(...)` matches the
    /// on-chain registration coin's actual `voted_ballots_root`.
    ///
    /// IMPL: starts at `reg_coin` (the unspent registration coin) and
    /// walks each spent ancestor by parent_coin_info. At each step:
    ///   1. Fetch the parent's puzzle + solution.
    ///   2. If the parent is the eve CAT (a non-CAT spend or a
    ///      `genesis_by_coin_id` issuance), stop — registration is
    ///      fresh up to here.
    ///   3. If the parent is a CAT-wrapped registration coin spend,
    ///      scan the inner action-layer solution for a 32-byte atom
    ///      that, when treated as a candidate `ballot_launcher_id`,
    ///      yields a recreated registration coin ph matching the
    ///      child we walked from. Append to the recovered ballot
    ///      list and recurse.
    ///   4. Continue until the parent is no longer a CAT
    ///      registration spend (we've hit the eve CAT).
    ///
    /// SHAPE: returns the ballots in REGISTRATION-OLDEST-FIRST order
    /// (chronological cast order). Order doesn't actually matter for
    /// `voted_ballots_root_after_inserts` (slot-based SPT inserts
    /// are commutative for distinct slots), but stable order is
    /// useful for diagnostic output.
    async fn walk_voted_ballots_history<C: ChainReader>(
        &self,
        chain: &C,
        reg_coin: Coin,
    ) -> VotingResult<Vec<Bytes32>> {
        use chia_sdk_driver::{Cat as DriverCat, Puzzle};
        use clvm_traits::ToClvm;
        use clvmr::Allocator;

        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let fresh_outer_ph = puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
            self.config.collateral_amount,
        );

        // Cap the walk at a reasonable depth — voters realistically
        // cast on at most a few dozen ballots per election.
        const MAX_LINEAGE_DEPTH: usize = 256;

        let mut ballots: Vec<Bytes32> = Vec::new();
        let mut current_coin: Coin = reg_coin;

        for _step in 0..MAX_LINEAGE_DEPTH {
            // If the current coin's ph IS the fresh ph, we've reached
            // the original (newly-registered) coin — no more cast
            // votes to recover.
            if current_coin.puzzle_hash == fresh_outer_ph {
                ballots.reverse();
                return Ok(ballots);
            }

            // Fetch parent record + spend. If parent isn't a CAT spend
            // (e.g., the eve CAT genesis), `Cat::parse_children` returns
            // None — meaning we've walked past the cast lineage; the
            // current coin is the eve registration coin and there are
            // no more inserts to recover.
            let parent_id = current_coin.parent_coin_info;
            let parent_record = chain
                .coin_record_by_id(parent_id)
                .await?
                .ok_or_else(|| {
                    voting_other(format!(
                        "Voter::walk_voted_ballots_history: parent coin {} not found",
                        hex::encode(parent_id),
                    ))
                })?;
            let (puzzle_program, solution_program) = chain
                .puzzle_and_solution(parent_id)
                .await?
                .ok_or_else(|| {
                    voting_other(format!(
                        "Voter::walk_voted_ballots_history: parent coin {} unspent",
                        hex::encode(parent_id),
                    ))
                })?;

            let mut allocator = Allocator::new();
            let parent_puzzle_node = puzzle_program.to_clvm(&mut allocator).map_err(|e| {
                voting_other(format!(
                    "walk_voted_ballots_history: parent puzzle to_clvm: {e}",
                ))
            })?;
            let parent_solution_node = solution_program.to_clvm(&mut allocator).map_err(|e| {
                voting_other(format!(
                    "walk_voted_ballots_history: parent solution to_clvm: {e}",
                ))
            })?;
            let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);

            let cat_children_opt = DriverCat::parse_children(
                &mut allocator,
                parent_record.coin,
                parent_puzzle,
                parent_solution_node,
            )
            .map_err(|e| {
                voting_other(format!(
                    "walk_voted_ballots_history: parse_children for parent {}: {e:?}",
                    hex::encode(parent_id),
                ))
            })?;

            let _cat_children = match cat_children_opt {
                Some(cs) => cs,
                None => {
                    // Parent is not a CAT spend — we've walked past the
                    // CAT registration lineage. Done.
                    ballots.reverse();
                    return Ok(ballots);
                }
            };

            // Scan the parent solution for any 32-byte atom that, when
            // used as a candidate ballot_launcher_id, produces a
            // recreated registration coin ph matching `current_coin`'s
            // outer ph (combining with the ballots already recovered
            // for any DEEPER ancestors). The order we walk is reverse
            // chronological, so `current_coin`'s ph reflects ALL
            // ballots cast up through that point — but we only need
            // ONE more (the most recent cast); the rest will be
            // recovered as we walk further back.
            let mut inserted_so_far = ballots.clone();
            inserted_so_far.reverse(); // chronological order
            let candidates = collect_32_byte_atoms(&allocator, parent_solution_node);

            let mut found_ballot: Option<Bytes32> = None;
            for candidate in &candidates {
                // Build candidate state: previously-recovered ballots
                // PLUS this candidate (the cast performed at this
                // parent step).
                let mut trial = inserted_so_far.clone();
                trial.push(*candidate);
                let trial_root = puzzles::voted_ballots_root_after_inserts(&trial);
                // SEC-F2: `locked_weight` tracks the coin's CAT balance
                // (decremented per cast), so reconstruct each lineage step's
                // ph with that step's own amount, not the collateral floor.
                let trial_inner_ph = puzzles::registration_inner_hash_for_state(
                    &self.keys.pubkey,
                    election_id,
                    cat_tail_hash,
                    trial_root,
                    current_coin.amount,
                    None,
                );
                let trial_outer_ph = puzzles::cat_outer_for_inner_hash(
                    cat_tail_hash,
                    trial_inner_ph,
                );
                if trial_outer_ph == current_coin.puzzle_hash {
                    found_ballot = Some(*candidate);
                    break;
                }
            }

            let ballot = found_ballot.ok_or_else(|| {
                voting_other(format!(
                    "Voter::walk_voted_ballots_history: could not match a \
                     ballot_launcher_id candidate from parent {} solution to recreated \
                     registration coin ph {} (scanned {} candidates)",
                    hex::encode(parent_id),
                    hex::encode(current_coin.puzzle_hash),
                    candidates.len(),
                ))
            })?;
            ballots.push(ballot);

            // Move to the parent and continue.
            current_coin = parent_record.coin;
        }

        Err(voting_other(format!(
            "Voter::walk_voted_ballots_history: exceeded MAX_LINEAGE_DEPTH ({}) — \
             registration coin lineage too deep",
            MAX_LINEAGE_DEPTH,
        )))
    }

    /// Reconstruct the CAT lineage proof for `cat_coin` by parsing
    /// its parent's actual on-chain spend.
    ///
    /// Salvaged from the pre-CHIP rev 2026-05-02 implementation —
    /// kept here for the eventual Phase 6 implementations of
    /// `cast_vote` / `update_vote` / `release_collateral`, all of
    /// which still need to derive a CAT lineage proof from the
    /// parent spend.
    #[allow(dead_code)]
    async fn reconstruct_cat_lineage<C: ChainReader>(
        &self,
        chain: &C,
        cat_coin: Coin,
    ) -> VotingResult<Option<chia_puzzle_types::LineageProof>> {
        use chia_sdk_driver::{Cat as DriverCat, Puzzle};
        use clvm_traits::ToClvm;
        use clvmr::Allocator;

        let parent_id = cat_coin.parent_coin_info;
        let parent_record = chain.coin_record_by_id(parent_id).await?.ok_or_else(|| {
            voting_other(format!(
                "Voter::reconstruct_cat_lineage: parent coin {} not found on chain",
                hex::encode(parent_id),
            ))
        })?;
        let (puzzle_program, solution_program) =
            chain.puzzle_and_solution(parent_id).await?.ok_or_else(|| {
                voting_other(format!(
                    "Voter::reconstruct_cat_lineage: parent coin {} is unspent — \
                     cannot derive lineage proof until it has been spent",
                    hex::encode(parent_id),
                ))
            })?;

        let mut allocator = Allocator::new();
        let parent_puzzle_node = puzzle_program.to_clvm(&mut allocator).map_err(|e| {
            voting_other(format!(
                "reconstruct_cat_lineage: parent puzzle to_clvm: {e}",
            ))
        })?;
        let parent_solution_node = solution_program.to_clvm(&mut allocator).map_err(|e| {
            voting_other(format!(
                "reconstruct_cat_lineage: parent solution to_clvm: {e}",
            ))
        })?;
        let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);

        let children = DriverCat::parse_children(
            &mut allocator,
            parent_record.coin,
            parent_puzzle,
            parent_solution_node,
        )
        .map_err(|e| {
            voting_other(format!(
                "reconstruct_cat_lineage: Cat::parse_children failed for parent {}: {e:?}",
                hex::encode(parent_id),
            ))
        })?
        .ok_or_else(|| {
            voting_other(format!(
                "reconstruct_cat_lineage: parent coin {} is not a CAT spend — \
                 unexpected on this voter's lineage",
                hex::encode(parent_id),
            ))
        })?;

        let target_id = cat_coin.coin_id();
        let child = children
            .into_iter()
            .find(|c| c.coin.coin_id() == target_id)
            .ok_or_else(|| {
                voting_other(format!(
                    "reconstruct_cat_lineage: child coin {} not found among CAT children of parent {}",
                    hex::encode(target_id),
                    hex::encode(parent_id),
                ))
            })?;

        Ok(child.lineage_proof)
    }

    /// Build the ElectionState CLVM tree node.
    ///
    /// SHAPE: matches the post-CHIP rev 2026-05-02 layout from
    /// `puzzles/election/shared.rue`:
    ///   `(root . (count . (vote_weight . election_start_height)))`
    /// — `election_start_height` is the trailing tail (a `u64`
    /// directly), NOT wrapped in `(_ . NIL)`. The deployer's
    /// `genesis_state_tree_hash` predicts the puzzle hash assuming
    /// this exact shape; an extra NIL terminator here would make
    /// the action layer's curried state-hash diverge from the
    /// launcher's commitment and the singleton outer would reject
    /// every spend.
    fn election_state_node(
        &self,
        ctx: &mut SpendContext,
        state: &crate::state::ElectionState,
    ) -> VotingResult<clvmr::NodePtr> {
        // M2: 8-field cons tree
        // (root . (count . (weight . (start . (cer . (max . (vk . lock))))))).
        let value = (
            state.registration_merkle_root,
            (
                state.registration_count,
                (
                    state.registration_vote_weight,
                    (
                        state.election_start_height,
                        (
                            state.ceremony_launcher_id,
                            (
                                state.max_voters,
                                (state.vk_hash, state.vote_mode_lock),
                            ),
                        ),
                    ),
                ),
            ),
        );
        value.to_clvm(&mut **ctx).map_err(driver_err)
    }

    /// Sign a list of coin spends using the recommended upstream
    /// `RequiredSignature::from_coin_spends` chain. The signing pool
    /// includes both the wallet's payment key and this voter's secret
    /// — so any combination of `AggSigMe(wallet_pk, ...)` and
    /// `AggSigMe(voter_pk, ...)` / `AggSigUnsafe(voter_pk, ...)`
    /// conditions in the bundle gets signed automatically.
    pub fn sign_with_voter_and_wallet_keys(
        &self,
        coin_spends: &[CoinSpend],
        wallet_sk: &SecretKey,
    ) -> VotingResult<Signature> {
        sign_bundle_signature(
            coin_spends,
            &[self.keys.secret.clone(), wallet_sk.clone()],
            self.network,
        )
    }

    /// The bare release message — `AggSigMe` augmentation is computed
    /// by `RequiredSignature::from_coin_spends` at signing time.
    ///
    /// SHAPE: `sha256("release" || election_id || pubkey || destination)`.
    /// The post-CHIP rev 2026-05-02 release flow keeps the same
    /// preimage shape; only the gating (Ballot Coin oracle vs the
    /// singleton's deregister announcement) changed.
    pub fn release_message(&self, destination: Bytes32) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let election_id = self
            .config
            .election_launcher_id()
            .expect("config validated");
        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(self.keys.pubkey.to_bytes());
        h.update(destination.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        Bytes32::new(arr)
    }
}

/// FN: voting_other (file-private)
/// WHAT: shorthand for `VotingError::Other` with a string message.
fn voting_other(msg: impl Into<String>) -> VotingError {
    VotingError::Other(anyhow_compat::Error(msg.into().into()))
}

/// Tiny helper that returns a filename-safe ISO-8601-ish timestamp
/// without pulling chrono into the SDK (we already use it in CLI).
fn chrono_compat_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// FN: driver_err (file-private)
/// WHAT: shorthand for converting a chia_sdk_driver / clvm_traits
///       error into a VotingError.
fn driver_err<E: std::fmt::Debug>(e: E) -> VotingError {
    voting_other(format!("clvm/driver: {e:?}"))
}

/// FN: convert_coin
/// WHAT: bridge a `chia_query::Coin` (hex-encoded JSON shape) to a
///       canonical `chia_protocol::Coin`.
/// USAGE: chain-walk paths that consume `chain.get_coin_records_by_hint`
///        results and feed them into `chia_sdk_driver::Cat::parse_children`.
/// ACCEPTS: both `0x`-prefixed and bare hex strings (chia-query has
///          historically been inconsistent about this).
#[cfg(feature = "native")]
pub fn convert_coin(c: &chia_query::Coin) -> VotingResult<chia_protocol::Coin> {
    let parent_coin_info = parse_hex32(&c.parent_coin_info)?;
    let puzzle_hash = parse_hex32(&c.puzzle_hash)?;
    Ok(chia_protocol::Coin::new(
        parent_coin_info,
        puzzle_hash,
        c.amount,
    ))
}

/// FN: parse_hex32 (file-private)
/// WHAT: parse a hex string (with or without `0x` prefix) into a
///       `Bytes32`. Returns `VotingError::Other` on malformed input
///       so callers can propagate without unwrapping.
fn parse_hex32(s: &str) -> VotingResult<Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(format!("hex decode {s}: {e}").into()))
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(
            format!("expected 32 bytes from {s}").into(),
        ))
    })?;
    Ok(Bytes32::new(arr))
}

/// FN: collect_32_byte_atoms (file-private)
/// WHAT: walk a CLVM tree (`node` rooted in `allocator`) and return
///       every 32-byte atom encountered, in pre-order. Used by
///       `Voter::walk_voted_ballots_history` to enumerate candidate
///       `ballot_launcher_id`s in a parent registration coin spend's
///       solution.
/// SHAPE: returns a Vec — the caller doesn't deduplicate (a 32-byte
///        atom appearing twice in the tree appears twice here).
/// PERF:  bounded by the depth of the action-layer solution tree,
///        which is O(actions × per-action-arg-count) — small.
fn collect_32_byte_atoms(
    allocator: &clvmr::Allocator,
    node: clvmr::NodePtr,
) -> Vec<Bytes32> {
    use clvmr::SExp;
    let mut out: Vec<Bytes32> = Vec::new();
    let mut stack: Vec<clvmr::NodePtr> = vec![node];
    while let Some(n) = stack.pop() {
        match allocator.sexp(n) {
            SExp::Atom => {
                let atom = allocator.atom(n);
                let bytes = atom.as_ref();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    out.push(Bytes32::new(arr));
                }
            }
            SExp::Pair(left, right) => {
                stack.push(right);
                stack.push(left);
            }
        }
    }
    out
}

/// FN: find_current_ballot_singleton (file-private)
/// WHAT: walk a Ballot Coin's singleton lineage starting from its
///       launcher coin and return the latest unspent Ballot Coin
///       singleton + the lineage proof needed to spend it.
/// IMPL: launcher → odd-amount child = eve Ballot Coin (lineage_proof
///       = `Eve`). If eve is unspent, return it. Otherwise walk to
///       its odd-amount child (lineage_proof = `Lineage` referencing
///       the prior coin's parent + the constant inner_ph) and repeat.
/// STATE INVARIANT: the BallotState transitions only on `finalize`;
///       `oracle` and `announce_finalization` recreate at the same
///       state. This walker assumes an as-yet-unfinalized ballot, so
///       every recreated coin's inner ph equals `expected_inner_ph`.
///       Once finalize has run, the inner ph changes — callers
///       hitting that case should re-derive per-spend.
async fn find_current_ballot_singleton<C: ChainReader>(
    chain: &C,
    ballot_launcher_id: Bytes32,
    expected_inner_ph: Bytes32,
) -> VotingResult<(chia_protocol::Coin, chia_puzzle_types::Proof)> {
    use chia_puzzle_types::{EveProof, LineageProof, Proof};

    let launcher_record = chain
        .coin_record_by_id(ballot_launcher_id)
        .await?
        .ok_or_else(|| {
            voting_other(format!(
                "find_current_ballot_singleton: launcher coin {} not found",
                hex::encode(ballot_launcher_id),
            ))
        })?;
    let launcher_coin = launcher_record.coin;

    // Step 1: locate the eve Ballot Coin singleton (child of the
    // launcher coin, odd amount).
    let eve_children = chain
        .coin_records_by_parent_ids(&[ballot_launcher_id])
        .await?;
    let mut current = eve_children
        .into_iter()
        .find(|r| r.coin.amount % 2 == 1)
        .ok_or_else(|| {
            voting_other(
                "find_current_ballot_singleton: no eve Ballot Coin singleton \
                 (launch_ballot bundle never submitted?)",
            )
        })?;

    let mut lineage_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: launcher_coin.parent_coin_info,
        parent_amount: launcher_coin.amount,
    });

    // Walk forward. Each pre-finalize Ballot Coin recreation has the
    // SAME inner_ph (`expected_inner_ph`); the lineage proof updates
    // each step.
    loop {
        if current.is_unspent() {
            return Ok((current.coin, lineage_proof));
        }

        let parent_coin_for_proof = current.coin;
        let parent_amount = parent_coin_for_proof.amount;
        let parent_parent = parent_coin_for_proof.parent_coin_info;
        let parent_id = parent_coin_for_proof.coin_id();
        let children = chain.coin_records_by_parent_ids(&[parent_id]).await?;
        let next = children
            .into_iter()
            .find(|r| r.coin.amount % 2 == 1)
            .ok_or_else(|| {
                voting_other(format!(
                    "find_current_ballot_singleton: no singleton child found for \
                     spent Ballot Coin {}",
                    hex::encode(parent_id),
                ))
            })?;
        lineage_proof = Proof::Lineage(LineageProof {
            parent_parent_coin_info: parent_parent,
            parent_inner_puzzle_hash: expected_inner_ph,
            parent_amount,
        });
        current = next;
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// These tests exercise the synchronous, pure helpers — message
// derivation, hint computation, coin conversion. The `register`,
// `cast_vote`, `update_vote`, and `release_collateral` async methods
// need a Simulator and live in the integration tests once Phase 6
// stands up.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey as Sk};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    /// SEC-F1: `VoterKeys::jubjub_schnorr_sign` produces a signature that
    /// satisfies the Schnorr verification equation the finalize circuit
    /// checks: `s·G == R + challenge_to_inner(c)·P`,
    /// `c = Poseidon(R.x, P.x, vote_message)`.
    #[test]
    fn jubjub_schnorr_sign_produces_valid_signature() {
        use crate::prover::circuit_v2::{challenge_to_inner, poseidon_config};
        use crate::prover::poseidon_perm::hash3;
        use ark_bls12_381::Fr;
        use ark_ec::{CurveGroup, Group};
        use ark_ed_on_bls12_381::EdwardsProjective as Jub;
        use chia_bls::SecretKey;

        let keys = VoterKeys::new(SecretKey::from_seed(&[3u8; 32]));
        let vote_message = Fr::from(0xDEAD_BEEFu64);
        let (r, s) = keys.jubjub_schnorr_sign(vote_message);
        let p = keys.jubjub_pubkey;

        let cfg = poseidon_config();
        let c = hash3(&cfg, r.x, p.x, vote_message);
        let c_inner = challenge_to_inner(c);
        let lhs = (Jub::generator() * s).into_affine();
        let rhs = (Jub::from(r) + Jub::from(p) * c_inner).into_affine();
        assert_eq!(lhs, rhs, "Schnorr signature must verify: s·G == R + c·P");

        // Determinism: same message ⇒ same signature (no RNG).
        let (r2, s2) = keys.jubjub_schnorr_sign(vote_message);
        assert_eq!((r, s), (r2, s2), "signing must be deterministic");
    }

    fn test_voter_pk() -> PublicKey {
        let root = Sk::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root.public_key(), 0).derive_synthetic()
    }

    fn good_config() -> ElectionConfig {
        ElectionConfig {
            election_launcher_id_hex: "11".repeat(32),
            cat_tail_hash_hex: "22".repeat(32),
            collateral_amount: 1_000,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: "00".repeat(336 + (crate::config::PUBLIC_INPUT_COUNT + 1) * 48),
            ceremony_launcher_id_hex: String::new(),
            vk_hash_hex: String::new(),
            label: None,
        }
    }

    fn voter_keys() -> VoterKeys {
        // A deterministic test voter SK + matching pk derived the same
        // way `test_voter_pk` would derive — but for this test the SK
        // is only used to verify VoterKeys::new copies pubkey through
        // correctly, not that it matches `test_voter_pk`.
        let sk = Sk::from_seed(&[0u8; 32]);
        VoterKeys::new(sk)
    }

    /// WHAT: `VoterKeys::new(sk)` stores the pubkey derived from
    ///       `sk` (so `keys.pubkey == sk.public_key()`).
    /// HOW:  build VoterKeys from a deterministic seed, compare
    ///       `pubkey` to a direct derivation.
    /// WHY:  every signing path assumes the bundled pubkey IS the
    ///       one that the secret signs against. A drift here would
    ///       mean signatures verify against a key the SDK never
    ///       reports.
    #[test]
    fn voter_keys_pubkey_matches_secret() {
        let v = voter_keys();
        assert_eq!(v.pubkey, v.secret.public_key());
    }

    /// WHAT: `release_message(destination)` equals
    ///       `sha256("release" || election_id || pubkey || destination)`
    ///       byte-exact.
    /// HOW:  hand-compute the sha256 inline against the same inputs,
    ///       compare.
    /// WHY:  the on-chain release action emits an
    ///       `AggSigMe(VOTER_PUBKEY, release_message)` and any drift
    ///       would prevent the voter from ever reclaiming their CAT
    ///       collateral.
    #[test]
    fn release_message_is_deterministic_and_correct() {
        let _voter_pk = test_voter_pk();
        let _config = good_config();
        // Reproduce the formula independently and compare against
        // the public helper.
        let voter = Voter {
            config: good_config(),
            keys: voter_keys(),
            network: NetworkType::Testnet11,
            election_start_height: 0,
        };
        let election_id = voter.config.election_launcher_id().unwrap();
        let destination = Bytes32::new([0xCC; 32]);

        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(voter.keys.pubkey.to_bytes());
        h.update(destination.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let expected = Bytes32::new(arr);

        assert_eq!(voter.release_message(destination), expected);
    }

    /// WHAT: `puzzles::vote_message(outcome, ballot_id, election_id)`
    ///       is byte-identical to `sha256(outcome || ballot_id ||
    ///       election_id)`.
    /// HOW:  hand-compute the sha256 inline and compare.
    /// WHY:  the on-chain Voting Coin's `update_vote` action emits
    ///       an `AggSigUnsafe(VOTER_PUBKEY, vote_message)` over
    ///       these exact bytes. Any drift would mean voter
    ///       signatures can't be verified on-chain or aggregated
    ///       off-chain.
    #[test]
    fn vote_message_three_arg_form_is_deterministic_and_correct() {
        let outcome = Bytes32::new([0x42; 32]);
        let ballot_id = Bytes32::new([0xAB; 32]);
        let election_id = Bytes32::new([0x11; 32]);

        let mut h = Sha256::new();
        h.update(outcome.as_ref());
        h.update(ballot_id.as_ref());
        h.update(election_id.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let expected = Bytes32::new(arr);

        assert_eq!(
            puzzles::vote_message(outcome, ballot_id, election_id),
            expected
        );
    }

    /// WHAT: signing `puzzles::vote_message(...)` with
    ///       `sign_unsafe` (== unaugmented `chia_bls::sign_raw`)
    ///       produces a signature that satisfies the textbook
    ///       PoP-style BLS aggregate pairing identity
    ///         e(pk, H(msg)) == e(G1_GENERATOR, sig).
    /// HOW:  build a deterministic voter, compute the canonical
    ///       message via the public helper, sign it with
    ///       `sign_unsafe`, hash the message to G2 via
    ///       `chia_bls::hash_to_g2` (default DST), and call
    ///       `chia_bls::aggregate_pairing` with the two (G1, G2)
    ///       pairs the on-chain identity expects.
    /// WHY:  pins that the SDK is on the unaugmented (sign_raw /
    ///       sign_unsafe) path — switching to augmented `sign()`
    ///       would silently break the off-chain aggregator's BLS
    ///       sum (the pre-CHIP-rev mainnet symptom).
    #[test]
    fn voter_canonical_signature_pop_pairing_verifies() {
        use chia_bls::{hash_to_g2, PublicKey as Pk};
        let v = voter_keys();
        let outcome = Bytes32::new([0xA5; 32]);
        let ballot_id = Bytes32::new([0xBB; 32]);
        let election_id = Bytes32::new([0x77; 32]);
        let msg = puzzles::vote_message(outcome, ballot_id, election_id);

        // Voter side: sign UNAUGMENTED.
        let sig = v.sign_unsafe(msg.as_ref());

        // On-chain side: e(pk, H(msg)) * e(-G1_GENERATOR, sig) == 1
        let h_msg = hash_to_g2(msg.as_ref());
        let neg_g1 = -Pk::generator();
        assert!(
            chia_bls::aggregate_pairing([(&v.pubkey, &h_msg), (&neg_g1, &sig)]),
            "unaugmented sign_raw signature must satisfy the PoP-style \
             single-pair pairing identity (mirrors finalize.rue on-chain check)",
        );

        // And for safety: the AUGMENTED variant (chia_bls::sign)
        // must NOT satisfy this identity — the two schemes are
        // mutually exclusive.
        let aug_sig = chia_bls::sign(&v.secret, msg.as_ref());
        assert!(
            !chia_bls::aggregate_pairing([(&v.pubkey, &h_msg), (&neg_g1, &aug_sig)]),
            "augmented sign() output must NOT satisfy the PoP-style identity — \
             pins that the SDK is on the unaugmented (sign_raw / sign_unsafe) path",
        );
    }

    /// WHAT: `convert_coin` correctly parses `0x`-prefixed hex
    ///       strings into `Bytes32` fields.
    /// HOW:  build a `chia_query::Coin` with `0x11..11` /
    ///       `0x22..22`, convert, assert the resulting
    ///       `chia_protocol::Coin` carries the expected bytes.
    /// WHY:  `chia-query` JSON responses use `0x`-prefixed hex; if
    ///       the prefix were treated as data, every hash would be
    ///       off by 2 bytes and silently corrupt downstream lookups.
    #[test]
    fn convert_coin_accepts_0x_prefix() {
        let qc = chia_query::Coin {
            parent_coin_info: format!("0x{}", "11".repeat(32)),
            puzzle_hash: format!("0x{}", "22".repeat(32)),
            amount: 1_000,
        };
        let pc = convert_coin(&qc).unwrap();
        assert_eq!(pc.parent_coin_info, Bytes32::new([0x11; 32]));
        assert_eq!(pc.puzzle_hash, Bytes32::new([0x22; 32]));
        assert_eq!(pc.amount, 1_000);
    }

    /// WHAT: `convert_coin` also accepts bare (no-prefix) hex
    ///       strings.
    /// HOW:  build a coin with bare hex, convert, assert the
    ///       amount round-trips (smoke test for the bare path).
    /// WHY:  some `chia-query` versions / endpoints have shipped
    ///       responses without the `0x` prefix. Tolerating both
    ///       avoids a brittle dependency on remote behaviour.
    #[test]
    fn convert_coin_accepts_bare_hex() {
        let qc = chia_query::Coin {
            parent_coin_info: "11".repeat(32),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        let pc = convert_coin(&qc).unwrap();
        assert_eq!(pc.amount, 5);
    }

    /// WHAT: `convert_coin` returns an error for non-hex input.
    /// HOW:  pass `parent_coin_info = "not-hex"`, expect an Err.
    /// WHY:  a malformed coin from a remote peer must surface as a
    ///       typed error rather than panic or silent garbage data.
    #[test]
    fn convert_coin_rejects_bad_hex() {
        let qc = chia_query::Coin {
            parent_coin_info: "not-hex".into(),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        assert!(convert_coin(&qc).is_err());
    }

    /// WHAT: `convert_coin` returns an error if any hash hex is the
    ///       wrong length (≠ 32 bytes).
    /// HOW:  use a 32-char (16-byte) parent_coin_info, expect Err.
    /// WHY:  hex-decode succeeds but the result is the wrong size
    ///       for `Bytes32`. Catching it explicitly avoids a generic
    ///       panic deep in `try_into`.
    #[test]
    fn convert_coin_rejects_short_hash() {
        let qc = chia_query::Coin {
            parent_coin_info: "11".repeat(16),
            puzzle_hash: "22".repeat(32),
            amount: 5,
        };
        assert!(convert_coin(&qc).is_err());
    }
}
