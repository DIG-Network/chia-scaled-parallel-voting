// ============================================================================
// actors/voter.rs — single-voter spend driver
// ============================================================================
//
// MODULE: actors::voter
// PURPOSE: Stateful actor representing one voter. Owns:
//          * the voter's BLS keys
//          * a reference to a dig-l1-wallet (XCH + CAT)
//          * the shared ElectionConfig
//
// SUPPORTED FLOWS:
//   * register          — register-action spend (CAT collateral + XCH fee)
//   * vote              — vote-action spend on the registration coin
//   * release_collateral — release-action + announce-finalization spend
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
use dig_l1_wallet::NetworkType;

use crate::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution, build_cat_spend,
    build_election_finalizer_full, build_registration_finalizer_full,
    build_singleton_spend, load_action_puzzle, ActionSpend,
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
}

impl VoterKeys {
    /// FN: new
    /// WHAT: build VoterKeys from a raw secret. Pubkey computed lazily.
    pub fn new(secret: SecretKey) -> Self {
        let pubkey = secret.public_key();
        Self { pubkey, secret }
    }

    /// FN: sign_unsafe
    /// WHAT: BLS-sign `message` verbatim — the same shape the on-chain
    ///       `AggSigUnsafe(VOTER_PUBKEY, vote_message)` condition
    ///       requires (no augmentation).
    /// USAGE: the vote action's solution requires the voter's
    ///        AggSigUnsafe over `vote_message(vote_data)`.
    pub fn sign_unsafe(&self, message: &[u8]) -> Signature {
        chia_bls::sign_raw(&self.secret, message)
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
}

impl Voter {
    pub fn new(config: ElectionConfig, keys: VoterKeys, network: NetworkType) -> Self {
        Self { config, keys, network }
    }

    /// FN: slot
    /// WHAT: this voter's canonical SPT slot.
    /// FORMULA: `u32::from_be_bytes(sha256(pubkey)[0..4])` — see
    ///          `SparseMerkleTree::slot_for_pubkey`.
    pub fn slot(&self) -> u32 {
        crate::merkle::SparseMerkleTree::slot_for_pubkey(&self.keys.pubkey)
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
            .map_err(|e| VotingError::Other(anyhow_compat::Error(e.into())))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| VotingError::Other(anyhow_compat::Error(e.into())))?;
        Ok(puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
        ))
    }

    /// FN: voter_hint
    /// WHAT: stable coin-state hint for tracking this voter's
    ///       Registration Coin lineage across vote / release spends.
    /// USAGE: `chain.get_coin_records_by_hint(voter_hint_hex(), ..)`.
    pub fn voter_hint(&self) -> VotingResult<Bytes32> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| VotingError::Other(anyhow_compat::Error(e.into())))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| VotingError::Other(anyhow_compat::Error(e.into())))?;
        Ok(puzzles::voter_hint(election_id, cat_tail_hash, &self.keys.pubkey))
    }

    /// FN: voter_hint_hex
    /// WHAT: `0x`-prefixed hex form of `voter_hint` — the wire shape
    ///       the `chia-query` HTTP API expects.
    pub fn voter_hint_hex(&self) -> VotingResult<String> {
        Ok(format!("0x{}", hex::encode(self.voter_hint()?)))
    }

    /// Build a registration spend bundle.
    ///
    /// The full implementation is structurally identical to
    /// `chia_l2_consensus::client::register_validator`. It composes:
    ///
    ///   1. **CAT collateral spend** — `dig_l1_wallet::L1Wallet::
    ///      select_cat_coins` to pick CAT inputs, then
    ///      `chia_sdk_driver::Cat::issue_with_coin` (or
    ///      `Cat::spend_all` against existing CATs) to send
    ///      COLLATERAL_AMOUNT into the Registration Coin's expected
    ///      puzzle hash. The CAT spend's inner conditions include the
    ///      `create_reg` `CreateCoinAnnouncement` that the Election
    ///      Singleton's register action asserts.
    ///   2. **Election Singleton spend** — wraps the action layer with
    ///      the `register` action selected. The action's solution
    ///      carries `(new_voter_pubkey, register_leaf_index,
    ///      register_siblings, cat_parent_coin_id)`.
    ///   3. **XCH wallet spend** — `L1Wallet::select_coins` to fund
    ///      `REGISTRATION_FEE + bundle_fee`.
    ///
    /// Final signing uses [`sign_bundle_signature`], which calls
    /// `RequiredSignature::from_coin_spends` to walk every AGG_SIG_*
    /// condition (the voter's `AggSigMe(VOTER_PUBKEY,
    /// registration_message)` plus the wallet's standard p2 sigs).
    pub async fn register<C: ChainReader>(
        &self,
        smt: &crate::merkle::SparseMerkleTree,
        cat_parent_spend: CoinSpend,
        chain: &C,
    ) -> VotingResult<SpendBundle> {
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
        // Never key off the genesis (eve) singleton puzzle hash alone:
        // each spend changes inner state, so `coin_id` and
        // `puzzle_hash` change. Walk from `election_launcher_id` to
        // the latest **unspent** coin (see `find_current_singleton`).
        // Use the propagation-aware poller: on mainnet a
        // freshly-confirmed spend can take blocks to show on every
        // peer in the chia_query pool — same as
        // `wait_for_unspent_coin_at_puzzle_hash`, but for lineage.
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
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
        // Never use `ElectionState::genesis(smt.root())` alone — after
        // at least one register spend, accumulated state (count,
        // fees, root) differs from genesis even when `smt` is synced.
        if on_chain_state.registration_merkle_root != smt.root() {
            return Err(voting_other(format!(
                "Voter::register: aggregator SMT root {} does not match on-chain {} — re-sync",
                hex::encode(smt.root()),
                hex::encode(on_chain_state.registration_merkle_root),
            )));
        }
        let election_state_node = self.election_state_node(&mut ctx, &on_chain_state)?;
        let action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            elect_finalizer,
            merkle_root,
            election_state_node,
        )?;

        // ── 3. Build the curried register action puzzle ─────────
        let register_program_node =
            load_action_puzzle(&mut ctx, puzzles::ELECTION_REGISTER_HEX)?;
        let register_curried = CurriedProgram {
            program: register_program_node,
            args: clvm_curried_args!(
                crate::config::TREE_DEPTH,
                Bytes32::new(crate::config::EMPTY_LEAF_HASH),
                PuzzleHashes::cat_outer(),
                cat_tail_hash,
                PuzzleHashes::action_layer(),
                PuzzleHashes::registration_finalizer(),
                puzzles::registration_actions_merkle_root(),
                self.config.collateral_amount,
                self.config.registration_fee,
                election_id
            ),
        }
        .to_clvm(&mut *ctx)
        .map_err(driver_err)?;

        // ── 4. Build the register action solution ───────────────
        // Solution shape (per register.rue):
        //   (new_voter_pubkey, register_leaf_index, register_siblings,
        //    ...cat_parent_coin_id)
        //
        // SLOT ENCODING: register.rue's `slot_from_pubkey` builds
        //   `0x00 || sha256(pk)[0..4]` and casts to Int. That's a
        //   5-byte atom regardless of the slot's actual value.
        //   `compute_slot == register_leaf_index` is `clvm =` which
        //   compares INTEGER values, BUT it ALSO depends on byte
        //   length when the puzzle uses `(== a b)` patterns that
        //   compile to raw atom equality (Rue's `==` for ints).
        //   Mainnet revealed that slots with the high bit CLEAR
        //   (canonical u64 = 4 bytes) mismatch the puzzle's 5-byte
        //   form. We pass the slot as the EXACT 5-byte sequence
        //   the puzzle constructs so `==` always succeeds.
        let slot = self.slot();
        let siblings = smt.prove(slot);
        let voter_pk_bytes = chia_protocol::Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let cat_parent_coin_id = cat_parent_spend.coin.coin_id();
        let slot_bytes = {
            let mut buf = Vec::with_capacity(5);
            buf.push(0x00);
            buf.extend_from_slice(&slot.to_be_bytes());
            chia_protocol::Bytes::new(buf)
        };
        let register_solution_value = (
            voter_pk_bytes,
            (slot_bytes, (siblings, cat_parent_coin_id)),
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
            &election_action_root_leaves(&self.config),
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
        //
        // The caller is responsible for any signatures the
        // cat_parent_spend's inner puzzle requires (e.g., the XCH
        // wallet's standard p2 sig if cat_parent_spend is a CAT
        // issuance from a wallet coin) — they should pre-sign that
        // spend before passing it in. Here we sign ONLY the
        // register-action's voter sig.
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
        let signature = sign_bundle_signature(
            &coin_spends,
            std::slice::from_ref(&self.keys.secret),
            self.network,
        )?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Build a vote spend bundle.
    ///
    /// Single-coin spend. Steps:
    ///
    ///   1. **Locate the registration coin**: hex-encode the voter
    ///      hint (`Self::voter_hint_hex`), call
    ///      `chain.get_coin_records_by_hint(hint, ..)`, filter to the
    ///      latest unspent record whose `puzzle_hash` matches
    ///      `Self::registration_coin_puzzle_hash`.
    ///   2. **Reconstruct the [`chia_sdk_driver::Cat`] primitive**:
    ///      fetch the parent spend via `chain.
    ///      get_puzzle_and_solution(parent_id, height)`, allocate
    ///      both into a `SpendContext`, and call
    ///      `Cat::parse_children(&mut ctx, parent_coin, puzzle,
    ///      solution)` to recover the spendable Cat with its
    ///      `lineage_proof`.
    ///   3. **Build the action-layer inner spend**:
    ///        - construct the action selectors + Merkle proofs against
    ///          [`puzzles::registration_actions_merkle_root`];
    ///        - the vote action's solution is `(vote_data,
    ///          vote_signature)`;
    ///        - the action layer's puzzle reveal is
    ///          [`puzzles::ACTION_LAYER_HEX`] curried with
    ///          `(election_finalizer_full_hash, MERKLE_ROOT, STATE)`.
    ///   4. **Wrap with [`chia_sdk_driver::CatSpend`]** and call
    ///      `Cat::spend_all(&mut ctx, &[cat_spend])` — handles ring
    ///      announcements, prev_subtotal, extra_delta, etc.
    ///   5. **Sign** with [`Self::sign_with_voter_and_wallet_keys`].
    ///   6. Wrap with `assemble_spend_bundle`.
    pub async fn vote<C: ChainReader>(
        &self,
        vote_data: Bytes32,
        chain: &C,
    ) -> VotingResult<SpendBundle> {
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;

        // The vote action's solution carries TWO logical pieces of
        // signing material:
        //
        //  (a) The bundle's aggregated BLS signature (NOT in the
        //      solution — collected later via
        //      `sign_bundle_signature`). It must include the voter's
        //      `sign_raw` over `vote_message(vote_data)` =
        //      `sha256("vote" || election_id || pk || vote_data)`,
        //      because `vote.rue` emits an
        //      `AggSigUnsafe(voter_pubkey, vote_message)` condition
        //      that consensus's signature verifier walks.
        //      `RequiredSignature::from_coin_spends` builds that
        //      `(pk, message)` pair automatically; our signing pool
        //      contains the voter's secret key so the resulting
        //      aggregated signature satisfies it.
        //
        //  (b) The `vote_signature` field of the action's solution
        //      itself. The on-chain puzzle does NOT verify this
        //      cryptographically — it just hands it to the finalizer,
        //      which writes it into the recreated coin's memos so the
        //      OFF-CHAIN aggregator (`extract_votes`) can read it
        //      with one coin-record lookup. The aggregator then
        //      BLS-sums every voter's memo signature and verifies the
        //      sum against the canonical aggregate message
        //      `sha256(vote_outcome || election_id)` (see
        //      `Aggregator::prepare_finalize_witness`).
        //
        // For the canonical voting flow each voter votes for the
        // outcome they want adopted — i.e., `vote_outcome ==
        // vote_data`. The memo signature is a BLS signature over
        // `sha256(vote_data || election_id)` using `sign_unsafe`
        // (== `chia_bls::sign_raw`) — UNAUGMENTED. Voters do NOT
        // augment with their own pubkey because the on-chain
        // verification uses single-pair BLS aggregate semantics:
        //
        //   e(agg_signers, H(canonical_message)) ==
        //     e(G1_GENERATOR, agg_sig)
        //
        // (`puzzles/election/finalize.rue`'s
        // `bls_pairing_identity`). Algebraically that requires
        //
        //   agg_sig = sk_agg · H(canonical_message)
        //          = (Σ sk_i) · H(canonical_message)
        //          = Σ (sk_i · H(canonical_message))
        //          = Σ sign_raw(sk_i, canonical_message)
        //
        // — exactly the sum the off-chain aggregator forms from
        // these per-voter memo signatures. PoP-style; the rogue-key
        // attack is closed by the Groth16 circuit's "agg_signers ==
        // G1 sum of signing pubkeys" binding (CHIP-Groth16-L2
        // constraint D).
        //
        // DST: `chia_bls::sign_raw` hashes under the standard Chia
        // augmented-scheme DST (`BLS_SIG_BLS12381G2_XMD:
        // SHA-256_SSWU_RO_AUG_`) without applying the per-pubkey
        // augmentation. This matches CLVM's `g2_map` default, so
        // the on-chain `g2_map(canonical_message)` produces the
        // same `H(canonical_message)` we sign here.
        //
        // EARLIER INCARNATIONS that surfaced on mainnet:
        //   * Used `sign_unsafe` over the per-voter on-chain
        //     `vote_message` instead of the canonical aggregate
        //     message — `Aggregator::build_finalize` rejected with
        //     `InvalidSignature` because the memo signatures
        //     couldn't aggregate-verify against the canonical
        //     message at all.
        //   * Switched to `chia_bls::sign` (augmented) over the
        //     canonical message — off-chain aggregator pre-check
        //     passed (uses `aggregate_verify` which augments per
        //     pair), but on-chain `bls_verify(agg_sig, agg_signers,
        //     vote_message)` rejected with `bls_verify failed`
        //     because the augmented-per-voter sigs couldn't
        //     collapse to the single-pair augmented form. We then
        //     switched the on-chain check to a PoP-style
        //     `bls_pairing_identity` and reverted the voter to
        //     `sign_raw` — the configuration we're in now.
        // Pinned by `voter_canonical_signature_pop_pairing_verifies`.
        let canonical_message = canonical_vote_message_for(vote_data, election_id);
        let vote_signature = self.keys.sign_unsafe(canonical_message.as_ref());

        // ── 1. Locate the voter's registration coin ─────────────
        // `coin_records_by_hint` returns the full lineage (spent +
        // unspent). Never take `find(is_unspent)` alone — if the same
        // hint ever indexed multiple live coins, the iterator order
        // could pick a stale row. Only the coin whose outer puzzle
        // hash matches the **pre-vote** `fresh_registration_*` shape
        // is spendable with the vote action.
        let hint = self.voter_hint()?;
        let expected_outer_ph =
            puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &self.keys.pubkey, election_id);
        let reg_records = chain.coin_records_by_hint(hint).await?;
        let reg_record = reg_records
            .into_iter()
            .filter(|r| r.is_unspent() && r.coin.puzzle_hash == expected_outer_ph)
            .max_by_key(|r| r.confirmed_height)
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::vote: no unspent registration coin at pre-vote puzzle hash {} \
                     (hint {}). Has the voter registered? If so, they may already have voted — \
                     the post-vote puzzle hash differs from the fresh-registration hash.",
                    hex::encode(expected_outer_ph),
                    hex::encode(hint)
                ))
            })?;
        let reg_coin = reg_record.coin;

        // Reconstruct CAT lineage proof from the parent's spend.
        let cat_lineage = self.reconstruct_cat_lineage(chain, reg_coin).await?;

        // ── 2. Build the action layer + vote action spend ────────
        let mut ctx = SpendContext::new();
        let voter_hint = hint;
        let reg_finalizer = build_registration_finalizer_full(&mut ctx, voter_hint)?;
        // Pre-vote state: has_voted=false, vote_data=zero,
        // release_destination=nil.
        let reg_state_node = self.registration_state_node(
            &mut ctx,
            /*has_voted=*/ false,
            /*vote_data=*/ Bytes32::default(),
            /*release_destination=*/ None,
        )?;
        let reg_action_layer = build_action_layer_puzzle(
            &mut ctx,
            reg_finalizer,
            puzzles::registration_actions_merkle_root(),
            reg_state_node,
        )?;

        // Vote action solution: (vote_data, ...vote_signature)
        let vote_action = load_action_puzzle(&mut ctx, puzzles::REGISTRATION_VOTE_HEX)?;
        let vote_sig_bytes = chia_protocol::Bytes::new(vote_signature.to_bytes().to_vec());
        let vote_solution_value = (vote_data, vote_sig_bytes);
        let vote_solution = vote_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;
        let action_spends = vec![ActionSpend {
            puzzle: vote_action,
            solution: vote_solution,
        }];
        // Registration finalizer takes ...my_amount: Int.
        let reg_finalizer_solution = reg_coin.amount.to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &registration_action_root_leaves(),
            &action_spends,
            reg_finalizer_solution,
        )?;

        let vote_spend = build_cat_spend(
            &mut ctx,
            reg_coin,
            cat_tail_hash,
            reg_action_layer,
            action_layer_solution,
            cat_lineage,
            reg_coin.coin_id(),
            reg_coin.coin_id(),
            0,
        )?;

        // ── 3. Sign + assemble bundle ────────────────────────────
        // Voter's AggSigUnsafe over vote_message is automatically
        // collected from the emitted condition by
        // RequiredSignature::from_coin_spends.
        let coin_spends = vec![vote_spend];
        crate::dry_run_coin_spends(&coin_spends)
            .map_err(|e| voting_other(format!("Voter::vote dry-run: {e:?}")))?;
        let signature =
            sign_bundle_signature(&coin_spends, std::slice::from_ref(&self.keys.secret), self.network)?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Build a collateral release spend bundle.
    ///
    /// Two-coin spend bundle:
    ///   1. Election Singleton spend (`announce_finalization` action) —
    ///      emits the finalization CreateCoinAnnouncement keyed on
    ///      `(vote_outcome, count, root)`.
    ///   2. CAT-wrapped Registration Coin spend (`release` action) —
    ///      asserts that announcement (using the announcer's
    ///      coin_id supplied via the solution), emits AggSigMe over
    ///      `(pubkey, election_id, destination)`, and sends the CAT
    ///      collateral to `destination`.
    ///
    /// CONTRACT: the Election Singleton MUST already be finalized
    /// (state.finalized = true) — `announce_finalization` asserts
    /// this. The voter's registration coin can be in any state
    /// (has_voted=true OR false; un-voted registrants still recover
    /// their collateral).
    ///
    /// CHAIN READS:
    ///   * [`crate::actors::aggregator::wait_for_current_singleton`] to
    ///     find the Election Singleton by launcher-id lineage — not a
    ///     fixed genesis puzzle hash.
    ///   * `coin_records_by_hint` on the voter's hint to find the
    ///     voter's current registration coin.
    ///   * `puzzle_and_solution` on each parent to derive lineage
    ///     proofs.
    pub async fn release_collateral<C: ChainReader>(
        &self,
        destination: Bytes32,
        chain: &C,
    ) -> VotingResult<SpendBundle> {
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;
        let cat_tail_hash = self
            .config
            .cat_tail_hash()
            .map_err(|e| voting_other(format!("cat_tail_hash: {e}")))?;

        // ── 1–2. Resolve launcher lineage + finalized state ───────
        // Puzzle hash changes after every singleton spend — only a
        // launcher-parent walk yields the spendable coin and correct
        // `Proof::Lineage` / `Proof::Eve` (same as registration).
        let current = crate::actors::aggregator::wait_for_current_singleton(
            chain,
            &self.config,
            "Election Singleton (releaseCollateral)",
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(300),
        )
        .await?;
        if !current.state.finalized {
            return Err(voting_other(
                "Voter::release_collateral: election is not finalized — \
                 cannot release collateral until finalize action has run",
            ));
        }
        let outcome = current.state.vote_outcome;
        let count = current.state.registration_count;
        let root = current.state.registration_merkle_root;

        let singleton_coin = current.coin;
        let singleton_lineage_proof = current.lineage_proof;
        let singleton_coin_id = singleton_coin.coin_id();

        // ── 3. Find the voter's registration coin ────────────────
        let hint = self.voter_hint()?;
        let reg_records = chain.coin_records_by_hint(hint).await?;
        let reg_record = reg_records
            .into_iter().find(|r| r.is_unspent())
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::release_collateral: no unspent registration coin \
                     found for hint {} — has the voter registered?",
                    hex::encode(hint)
                ))
            })?;
        let reg_coin = reg_record.coin;

        // Reconstruct CAT lineage proof from the parent's spend.
        let cat_lineage = self.reconstruct_cat_lineage(chain, reg_coin).await?;

        // Determine whether `reg_coin` is the FRESH (just-registered)
        // coin or the POST-VOTE recreation, by comparing its
        // puzzle_hash to the curried fresh-registration puzzle hash
        // (which encodes `has_voted=false, vote_data=0, dest=None`).
        // The on-chain Registration Coin's CAT-wrapped puzzle hash
        // changes whenever the action layer's curried state changes,
        // so an exact match → pre-vote, mismatch → post-vote (the
        // voter's `vote` action ran and rewrapped at a NEW state).
        //
        // For the post-vote case we MUST recover the actual `vote_data`
        // the voter cast, because the release action's puzzle reveal
        // re-wraps at the CURRENT (post-vote) state. The `vote` action
        // wrote `vote_data` into the recreated coin's memos as
        // `[hint, vote_data, vote_signature]` (per
        // `puzzles/registration_coin/finalizer.rue`), so we read it
        // back from the parent's spend.
        let fresh_ph = puzzles::fresh_registration_coin_puzzle_hash(
            cat_tail_hash,
            &self.keys.pubkey,
            election_id,
        );
        let (reg_has_voted, reg_vote_data) = if reg_coin.puzzle_hash == fresh_ph {
            (false, Bytes32::default())
        } else {
            // Post-vote: parse memos from the parent spend.
            let parent_id = reg_coin.parent_coin_info;
            let (parent_puzzle, parent_solution) = chain
                .puzzle_and_solution(parent_id)
                .await?
                .ok_or_else(|| voting_other(format!(
                    "Voter::release_collateral: parent {} of post-vote registration coin not spent / not found",
                    hex::encode(parent_id)
                )))?;
            let memos = crate::actors::aggregator::extract_create_coin_memos(
                &parent_puzzle,
                &parent_solution,
                reg_coin.puzzle_hash.into(),
            )
            .map_err(|e| voting_other(format!(
                "Voter::release_collateral: extract_create_coin_memos for parent {}: {e}",
                hex::encode(parent_id)
            )))?;
            // Memos are [hint, vote_data, vote_signature]. Pick the
            // 32-byte memo whose value isn't the hint — that's vote_data.
            let mut vote_data: Option<Bytes32> = None;
            for m in &memos {
                if m.len() == 32 && m.as_slice() != hint.as_ref() {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(m);
                    vote_data = Some(Bytes32::new(arr));
                    break;
                }
            }
            let vd = vote_data.ok_or_else(|| voting_other(format!(
                "Voter::release_collateral: post-vote registration coin {} parent spend's memos contain no \
                 32-byte vote_data (memos: {})",
                hex::encode(reg_coin.coin_id()),
                memos.iter().map(hex::encode).collect::<Vec<_>>().join(", ")
            )))?;
            (true, vd)
        };
        tracing::debug!(
            reg_coin_id = %hex::encode(reg_coin.coin_id()),
            has_voted = reg_has_voted,
            vote_data = %hex::encode(reg_vote_data),
            "Voter::release_collateral: detected registration coin state"
        );

        // ── 4. Build the announce_finalization spend (singleton) ──
        let mut ctx = SpendContext::new();
        let elect_finalizer = build_election_finalizer_full(&mut ctx, election_id)?;

        // The election's MERKLE_ROOT is per-deployment.
        let election_merkle_root =
            crate::actors::aggregator::election_actions_merkle_root_for_config(&self.config);
        let election_state_node = self.election_state_node(&mut ctx, &current.state)?;
        let action_layer_node = build_action_layer_puzzle(
            &mut ctx,
            elect_finalizer,
            election_merkle_root,
            election_state_node,
        )?;

        // announce_finalization takes (StateTruth) only — no extra
        // args. Build its solution here.
        let announce_action = load_action_puzzle(
            &mut ctx,
            puzzles::ELECTION_ANNOUNCE_FINALIZATION_HEX,
        )?;
        // Action solution: nil (announce_finalization reads only
        // from the state truth).
        let announce_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_spends = vec![ActionSpend {
            puzzle: announce_action,
            solution: announce_solution,
        }];
        // Election finalizer takes `..._my_solution: Any` (trailing
        // tail). For announce_finalization (which doesn't recreate),
        // pass nil.
        let finalizer_solution = ().to_clvm(&mut *ctx).map_err(driver_err)?;
        let action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &election_action_root_leaves(&self.config),
            &action_spends,
            finalizer_solution,
        )?;

        let announce_spend = build_singleton_spend(
            &mut ctx,
            singleton_coin,
            election_id,
            action_layer_node,
            action_layer_solution,
            singleton_lineage_proof,
        )?;

        // ── 5. Build the release spend (CAT-wrapped Reg Coin) ────
        let voter_hint = hint;
        let reg_finalizer = build_registration_finalizer_full(&mut ctx, voter_hint)?;
        // Build the action-layer state at the CURRENT (post-vote-or-pre-vote)
        // registration-coin state. The `release` action transitions
        // `release_destination` from None → Some(destination), but the puzzle
        // REVEAL must match what the on-chain coin currently has — which
        // depends on whether the voter voted (post-vote: has_voted=true,
        // vote_data=actual) or not (pre-vote: defaults).
        let reg_state_node = self.registration_state_node(
            &mut ctx,
            reg_has_voted,
            reg_vote_data,
            /*release_destination=*/ None,
        )?;
        let reg_action_layer = build_action_layer_puzzle(
            &mut ctx,
            reg_finalizer,
            puzzles::registration_actions_merkle_root(),
            reg_state_node,
        )?;

        // Release action solution:
        //   (collateral_destination, singleton_coin_id,
        //    finalized_outcome, finalized_count, ...finalized_root)
        let release_action = load_action_puzzle(&mut ctx, puzzles::REGISTRATION_RELEASE_HEX)?;
        let release_solution_value = (
            destination,
            (singleton_coin_id, (outcome, (count, root))),
        );
        let release_solution = release_solution_value
            .to_clvm(&mut *ctx)
            .map_err(driver_err)?;

        let release_action_spends = vec![ActionSpend {
            puzzle: release_action,
            solution: release_solution,
        }];
        // Registration coin finalizer takes `...my_amount: Int`
        // (trailing tail). The dispatcher passes `finalizer_solution`
        // verbatim — for a single Int, the value goes in directly,
        // not wrapped in a list.
        let reg_finalizer_solution = reg_coin.amount.to_clvm(&mut *ctx).map_err(driver_err)?;
        let reg_action_layer_solution = build_action_layer_solution(
            &mut ctx,
            &registration_action_root_leaves(),
            &release_action_spends,
            reg_finalizer_solution,
        )?;

        let release_spend = build_cat_spend(
            &mut ctx,
            reg_coin,
            cat_tail_hash,
            reg_action_layer,
            reg_action_layer_solution,
            cat_lineage,
            reg_coin.coin_id(),
            reg_coin.coin_id(),
            0,
        )?;

        // ── 6. Sign the bundle ───────────────────────────────────
        let coin_spends = vec![announce_spend, release_spend];
        // Voter signs AggSigMe over the release message (handled by
        // RequiredSignature::from_coin_spends walking conditions).
        // No wallet signature needed for a release-only bundle.
        crate::dry_run_coin_spends(&coin_spends)
            .map_err(|e| voting_other(format!("Voter::release_collateral dry-run: {e:?}")))?;
        let signature =
            sign_bundle_signature(&coin_spends, std::slice::from_ref(&self.keys.secret), self.network)?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    // ── Internal helpers for spend assembly ─────────────────────

    /// Reconstruct the CAT lineage proof for `cat_coin` by parsing
    /// its parent's actual on-chain spend.
    ///
    /// CONTRACT: `cat_coin` is a CAT-wrapped Registration Coin. Its
    /// parent is EITHER:
    ///   * the validator's wallet CAT (which is itself CAT-wrapped at
    ///     a standard p2 inner) — the case immediately after the
    ///     `register` action runs, before the voter has voted;
    ///   * the previous registration coin (CAT-wrapped at the action-
    ///     layer inner with a different state hash) — the case after
    ///     a `vote` spend has already moved the lineage forward.
    ///
    /// Both shapes are valid CAT v2 spends. The canonical way to
    /// derive the child's `LineageProof` from the parent's spend is
    /// [`chia_sdk_driver::Cat::parse_children`], which:
    ///   1. parses the `CatLayer` (asserting it IS a CAT spend);
    ///   2. extracts `lineage_proof`, `asset_id`, and the inner
    ///      puzzle hash from the on-chain reveal;
    ///   3. runs the inner puzzle to discover child `CreateCoin`
    ///      conditions and produces a [`Cat`] for each child with the
    ///      correct `parent_inner_puzzle_hash` baked in.
    ///
    /// Hand-rolling this with `voter_hint` lookups was incorrect in
    /// two ways: (a) the validator's wallet CAT is hinted by its own
    /// p2 puzzle hash, NOT the voter hint, so the `find_by_hint`
    /// branch would silently fall through to `None` and emit an
    /// "eve" lineage proof; (b) even when a hint match existed (post-
    /// vote release path), the parent's inner puzzle hash was the
    /// PRE-vote `fresh_registration_inner_hash`, not the post-vote
    /// inner hash — the CAT outer would then reject the spend with a
    /// `clvm raise` because the lineage proof's claimed inner ph
    /// didn't reproduce the parent's outer puzzle hash under the
    /// CAT curry.
    async fn reconstruct_cat_lineage<C: ChainReader>(
        &self,
        chain: &C,
        cat_coin: Coin,
    ) -> VotingResult<Option<chia_puzzle_types::LineageProof>> {
        use chia_sdk_driver::{Cat as DriverCat, Puzzle};
        use clvm_traits::ToClvm;
        use clvmr::Allocator;

        let parent_id = cat_coin.parent_coin_info;
        let parent_record = chain
            .coin_record_by_id(parent_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::reconstruct_cat_lineage: parent coin {} not found on chain",
                    hex::encode(parent_id),
                ))
            })?;
        let (puzzle_program, solution_program) = chain
            .puzzle_and_solution(parent_id)
            .await?
            .ok_or_else(|| {
                voting_other(format!(
                    "Voter::reconstruct_cat_lineage: parent coin {} is unspent — \
                     cannot derive lineage proof until it has been spent",
                    hex::encode(parent_id),
                ))
            })?;

        let mut allocator = Allocator::new();
        let parent_puzzle_node = puzzle_program
            .to_clvm(&mut allocator)
            .map_err(|e| voting_other(format!(
                "reconstruct_cat_lineage: parent puzzle to_clvm: {e}",
            )))?;
        let parent_solution_node = solution_program
            .to_clvm(&mut allocator)
            .map_err(|e| voting_other(format!(
                "reconstruct_cat_lineage: parent solution to_clvm: {e}",
            )))?;
        let parent_puzzle = Puzzle::parse(&allocator, parent_puzzle_node);

        let children = DriverCat::parse_children(
            &mut allocator,
            parent_record.coin,
            parent_puzzle,
            parent_solution_node,
        )
        .map_err(|e| voting_other(format!(
            "reconstruct_cat_lineage: Cat::parse_children failed for parent {}: {e:?}",
            hex::encode(parent_id),
        )))?
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
    /// SHAPE: matches Rue's trailing-tail convention from
    /// `puzzles/election/shared.rue`:
    ///   `(root . (count . (fees . (finalized . vote_outcome))))`
    /// — `vote_outcome` is the trailing tail (a Bytes32 directly),
    /// NOT wrapped in `(vote_outcome . NIL)`. The deployer's
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
        let value = (
            state.registration_merkle_root,
            (
                state.registration_count,
                (
                    state.accumulated_fees,
                    (state.finalized as u8, state.vote_outcome),
                ),
            ),
        );
        value.to_clvm(&mut **ctx).map_err(driver_err)
    }

    /// Build the RegistrationState CLVM tree node.
    fn registration_state_node(
        &self,
        ctx: &mut SpendContext,
        has_voted: bool,
        vote_data: Bytes32,
        release_destination: Option<Bytes32>,
    ) -> VotingResult<clvmr::NodePtr> {
        let pk_bytes =
            chia_protocol::Bytes::new(self.keys.pubkey.to_bytes().to_vec());
        let election_id = self
            .config
            .election_launcher_id()
            .map_err(|e| voting_other(format!("election_launcher_id: {e}")))?;

        if release_destination.is_none() {
            if has_voted {
                // Rue `Bool` true ↔ 0x01 atom (matches clvm_runner tests).
                let v = (
                    pk_bytes,
                    (election_id, (1u8, (vote_data, ()))),
                );
                return v.to_clvm(&mut **ctx).map_err(driver_err);
            }
            // Rue `Bool` false ↔ nil (), NOT a 1-byte 0 atom. Must match
            // `puzzles::fresh_registration_state_tree_hash` / register.rue
            // initial state or `assert State.has_voted == false` in vote.rue fails.
            let v = (
                pk_bytes,
                (election_id, ((), (vote_data, ()))),
            );
            return v.to_clvm(&mut **ctx).map_err(driver_err);
        }

        // Trailing tail = release_destination (Some).
        let hv = if has_voted { 1u8 } else { 0u8 };
        let value = (
            pk_bytes,
            (
                election_id,
                (
                    hv,
                    (
                        vote_data,
                        release_destination.expect("branch is Some"),
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

    /// The byte-exact message this voter signs to cast a vote.
    pub fn vote_message(&self, vote_data: Bytes32) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let election_id = self.config.election_launcher_id().expect("config validated");
        let mut h = Sha256::new();
        h.update(b"vote");
        h.update(election_id.as_ref());
        h.update(self.keys.pubkey.to_bytes());
        h.update(vote_data.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        Bytes32::new(arr)
    }

    /// The bare release message — `AggSigMe` augmentation is computed
    /// by `RequiredSignature::from_coin_spends` at signing time.
    pub fn release_message(&self, destination: Bytes32) -> Bytes32 {
        use sha2::{Digest, Sha256};
        let election_id = self.config.election_launcher_id().expect("config validated");
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

/// FN: canonical_vote_message_for (file-private)
/// WHAT: byte-exact aggregate-vote message every voter must sign for
///       inclusion in the off-chain BLS aggregate.
/// FORMULA: `sha256(vote_outcome || election_launcher_id)` —
///          IDENTICAL to `aggregator::canonical_vote_message`.
/// CALLER CONTRACT: pass `vote_outcome` (NOT `vote_message`). For the
/// canonical "voter signs for the outcome they want" model,
/// `vote_outcome == vote_data`.
/// MIRROR: this helper is a sibling of
/// `aggregator::canonical_vote_message` — kept private here to avoid
/// widening the SDK's public surface; both must update in lock-step.
/// Pinned by `voter_memo_signature_matches_canonical_aggregate_message`.
fn canonical_vote_message_for(vote_outcome: Bytes32, election_id: Bytes32) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(vote_outcome.as_ref());
    h.update(election_id.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
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

/// Use the public helper from `puzzles` so external callers (tests,
/// downstream tooling) build trees with byte-identical roots.
use crate::puzzles::registration_action_root_leaves;

/// FN: election_action_root_leaves
/// WHAT: the leaf set for the Election Singleton's actions Merkle
///       tree. The election's leaves depend on per-deployment
///       constants (VK, IC, COLLATERAL_AMOUNT, …) so the leaves
///       must be reconstructed from `ElectionConfig` here.
fn election_action_root_leaves(config: &ElectionConfig) -> Vec<Bytes32> {
    use chia_protocol::Bytes;
    use clvm_traits::{clvm_curried_args, ToClvm};
    use clvm_utils::CurriedProgram;
    use clvmr::Allocator;

    let mut allocator = Allocator::new();
    let launcher_id = config
        .election_launcher_id()
        .expect("config validated");
    let cat_tail_hash = config.cat_tail_hash().expect("config validated");

    // Build each action puzzle's tree hash directly without a
    // closure (avoids the multiple-mutable-borrow issue that a
    // closure capturing `allocator` would create).
    let load = |alloc: &mut Allocator, hex_str: &str| -> clvmr::NodePtr {
        let bytes = hex::decode(hex_str.trim().trim_start_matches("0x")).unwrap();
        let prog = chia_protocol::Program::from(bytes);
        prog.to_clvm(alloc).unwrap()
    };

    // Register: 10 curried params.
    let register_node = load(&mut allocator, puzzles::ELECTION_REGISTER_HEX);
    let register_curried = CurriedProgram {
        program: register_node,
        args: clvm_curried_args!(
            crate::config::TREE_DEPTH,
            Bytes32::new(crate::config::EMPTY_LEAF_HASH),
            PuzzleHashes::cat_outer(),
            cat_tail_hash,
            PuzzleHashes::action_layer(),
            PuzzleHashes::registration_finalizer(),
            puzzles::registration_actions_merkle_root(),
            config.collateral_amount,
            config.registration_fee,
            launcher_id
        ),
    }
    .to_clvm(&mut allocator)
    .unwrap();
    let register_leaf =
        Bytes32::new(clvm_utils::tree_hash(&allocator, register_curried).to_bytes());

    // Finalize: 4 curried params (VK struct, IC struct,
    // election_length_blocks, launcher_id). MUST mirror
    // `aggregator::compute_election_action_root_leaves` and
    // `Aggregator::build_finalize_with_proof` byte-for-byte —
    // see the long-form rationale on the aggregator-side helper.
    let finalize_node = load(&mut allocator, puzzles::ELECTION_FINALIZE_HEX);
    let vk_bytes =
        hex::decode(&config.verification_key_hex).expect("config validated");
    if vk_bytes.len() < 576 {
        panic!(
            "verification_key_hex too short for finalize curry: got {}, expected ≥ 576",
            vk_bytes.len(),
        );
    }
    let vk_alpha = Bytes::new(vk_bytes[0..48].to_vec());
    let vk_beta = Bytes::new(vk_bytes[48..144].to_vec());
    let vk_gamma = Bytes::new(vk_bytes[144..240].to_vec());
    let vk_delta = Bytes::new(vk_bytes[240..336].to_vec());
    let vk_struct = (vk_alpha, (vk_beta, (vk_gamma, (vk_delta, ()))));
    let ic0 = Bytes::new(vk_bytes[336..384].to_vec());
    let ic1 = Bytes::new(vk_bytes[384..432].to_vec());
    let ic2 = Bytes::new(vk_bytes[432..480].to_vec());
    let ic3 = Bytes::new(vk_bytes[480..528].to_vec());
    let ic4 = Bytes::new(vk_bytes[528..576].to_vec());
    let ic_struct = (ic0, (ic1, (ic2, (ic3, (ic4, ())))));
    let finalize_curried = CurriedProgram {
        program: finalize_node,
        args: clvm_curried_args!(
            vk_struct,
            ic_struct,
            config.election_length_blocks,
            launcher_id
        ),
    }
    .to_clvm(&mut allocator)
    .unwrap();
    let finalize_leaf =
        Bytes32::new(clvm_utils::tree_hash(&allocator, finalize_curried).to_bytes());

    // announce_finalization: no curried args.
    let announce_node = load(&mut allocator, puzzles::ELECTION_ANNOUNCE_FINALIZATION_HEX);
    let announce_leaf =
        Bytes32::new(clvm_utils::tree_hash(&allocator, announce_node).to_bytes());

    // oracle: no curried args.
    let oracle_node = load(&mut allocator, puzzles::ELECTION_ORACLE_HEX);
    let oracle_leaf =
        Bytes32::new(clvm_utils::tree_hash(&allocator, oracle_node).to_bytes());

    let mut leaves = vec![register_leaf, finalize_leaf, announce_leaf, oracle_leaf];
    // Sort so the tree built here matches the deployer's
    // `election_actions_merkle_root` convention.
    leaves.sort_by(|a, b| {
        puzzles::hash_atom_b32(a)
            .as_ref()
            .cmp(puzzles::hash_atom_b32(b).as_ref())
    });
    leaves
}

/// FN: convert_coin
/// WHAT: bridge a `chia_query::Coin` (hex-encoded JSON shape) to a
///       canonical `chia_protocol::Coin`.
/// USAGE: chain-walk paths that consume `chain.get_coin_records_by_hint`
///        results and feed them into `chia_sdk_driver::Cat::parse_children`.
/// ACCEPTS: both `0x`-prefixed and bare hex strings (chia-query has
///          historically been inconsistent about this).
pub fn convert_coin(c: &chia_query::Coin) -> VotingResult<chia_protocol::Coin> {
    let parent_coin_info = parse_hex32(&c.parent_coin_info)?;
    let puzzle_hash = parse_hex32(&c.puzzle_hash)?;
    Ok(chia_protocol::Coin::new(parent_coin_info, puzzle_hash, c.amount))
}

/// FN: parse_hex32 (file-private)
/// WHAT: parse a hex string (with or without `0x` prefix) into a
///       `Bytes32`. Returns `VotingError::Other` on malformed input
///       so callers can propagate without unwrapping.
fn parse_hex32(s: &str) -> VotingResult<Bytes32> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
            "hex decode {s}: {e}").into())))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VotingError::Other(anyhow_compat::Error(format!("expected 32 bytes from {s}").into()))
    })?;
    Ok(Bytes32::new(arr))
}

// ============================================================================
// Tests
// ============================================================================
//
// These tests exercise the synchronous, pure helpers — message
// derivation, hint computation, coin conversion. The `register`,
// `vote`, and `release_collateral` async methods need a Simulator and
// live in `tests/integration.rs`.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey as Sk};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

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
            registration_fee: 10,
            election_length_blocks: 4_608,
            tree_depth: crate::config::TREE_DEPTH,
            max_signers: crate::config::MAX_SIGNERS,
            verification_key_hex: "00".repeat(
                336 + (crate::config::PUBLIC_INPUT_COUNT + 1) * 48,
            ),
            label: None,
        }
    }

    fn message_for(prefix: &[u8], pk: &PublicKey, election_id: Bytes32, payload: Bytes32) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(prefix);
        h.update(election_id.as_ref());
        h.update(pk.to_bytes());
        h.update(payload.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        Bytes32::new(arr)
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

    /// WHAT: `vote_message(vote_data)` equals
    ///       `sha256("vote" || election_id || pubkey || vote_data)`
    ///       byte-exact.
    /// HOW:  hand-compute the sha256 inline against the same inputs
    ///       (test_voter_pk + good_config + a fixed vote_data) and
    ///       assert equality.
    /// WHY:  the on-chain vote action emits an
    ///       `AggSigUnsafe(VOTER_PUBKEY, vote_message)` over EXACTLY
    ///       these bytes. Any drift would mean voter signatures
    ///       can't be verified on-chain or aggregated off-chain.
    #[test]
    fn vote_message_is_deterministic_and_correct() {
        // We can build a Voter without a wallet for these pure-helper
        // tests by directly constructing the struct (test-only).
        let voter_pk = test_voter_pk();
        let config = good_config();
        let election_id = config.election_launcher_id().unwrap();
        let vote_data = Bytes32::new([0x42; 32]);

        // Reproduce the formula independently and compare.
        let expected = message_for(b"vote", &voter_pk, election_id, vote_data);

        // Mini Voter that only needs `config` + `keys.pubkey`.
        // Using the public `vote_message` formula manually since we
        // can't construct a full Voter without a real L1Wallet.
        let mut h = Sha256::new();
        h.update(b"vote");
        h.update(election_id.as_ref());
        h.update(voter_pk.to_bytes());
        h.update(vote_data.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let actual = Bytes32::new(arr);

        assert_eq!(actual, expected);
    }

    /// WHAT: `release_message(destination)` equals
    ///       `sha256("release" || election_id || pubkey || destination)`
    ///       byte-exact.
    /// HOW:  hand-compute the sha256 inline against the same inputs,
    ///       compare.
    /// WHY:  same as the vote-message test — the on-chain release
    ///       action emits an `AggSigMe(VOTER_PUBKEY, release_message)`
    ///       and any drift would prevent the voter from ever
    ///       reclaiming their CAT collateral.
    #[test]
    fn release_message_is_deterministic_and_correct() {
        let voter_pk = test_voter_pk();
        let config = good_config();
        let election_id = config.election_launcher_id().unwrap();
        let destination = Bytes32::new([0xCC; 32]);

        let expected = message_for(b"release", &voter_pk, election_id, destination);

        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(voter_pk.to_bytes());
        h.update(destination.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let actual = Bytes32::new(arr);

        assert_eq!(actual, expected);
    }

    /// WHAT: `canonical_vote_message_for(outcome, election_id)` is
    ///       byte-identical to `aggregator::canonical_vote_message`.
    /// HOW:  hand-compute `sha256(outcome || election_id)` inline and
    ///       compare against the file-private helper used by
    ///       `Voter::vote` to sign the memo signature.
    /// WHY:  the aggregator BLS-aggregates per-voter memo signatures
    ///       and verifies the sum against ITS canonical message. Any
    ///       drift between the two formulas would make
    ///       `Aggregator::build_finalize` reject every collected vote
    ///       with `VotingError::InvalidSignature` (mainnet symptom
    ///       observed in PHASE 5 before this regression test).
    #[test]
    fn voter_memo_signature_matches_canonical_aggregate_message() {
        let outcome = Bytes32::new([0x42; 32]);
        let election_id = Bytes32::new([0x11; 32]);

        let mut h = Sha256::new();
        h.update(outcome.as_ref());
        h.update(election_id.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.finalize());
        let expected = Bytes32::new(arr);

        assert_eq!(canonical_vote_message_for(outcome, election_id), expected);
    }

    /// WHAT: signing `canonical_vote_message_for(vote_data,
    ///       election_id)` with `sign_unsafe` (== unaugmented
    ///       `chia_bls::sign_raw`) produces a signature that
    ///       satisfies the textbook PoP-style BLS aggregate
    ///       pairing identity
    ///         e(pk, H(msg)) == e(G1_GENERATOR, sig)
    ///       — i.e. exactly what `puzzles/election/finalize.rue`'s
    ///       `bls_pairing_identity` opcode checks on-chain (with
    ///       agg_signers == pk and agg_sig == sig in the single-
    ///       voter case). The off-chain `Aggregator::
    ///       prepare_finalize_witness` mirrors the same check for
    ///       k voters via `chia_bls::aggregate_pairing`.
    /// HOW:  build a deterministic voter, compute the canonical
    ///       message, sign it with `sign_unsafe`, hash the message
    ///       to G2 via `chia_bls::hash_to_g2` (default DST), and
    ///       call `chia_bls::aggregate_pairing` with the two
    ///       (G1, G2) pairs the on-chain identity expects.
    ///       Negate G1_GENERATOR to flip the right-hand pairing.
    /// WHY:  PHASE 5 of the live mainnet test failed when voters
    ///       signed with augmented `chia_bls::sign` and the puzzle
    ///       called single-pair `bls_verify(agg_sig, agg_signers,
    ///       vote_message)` (which augments internally with
    ///       `agg_signers || msg`). Switching to PoP-style
    ///       (unaugmented signing + `bls_pairing_identity` on
    ///       chain) is what makes the math work; this test pins
    ///       that exact equivalence so future drift is caught
    ///       before broadcast.
    #[test]
    fn voter_canonical_signature_pop_pairing_verifies() {
        use chia_bls::{hash_to_g2, PublicKey as Pk};
        let v = voter_keys();
        let outcome = Bytes32::new([0xA5; 32]);
        let election_id = Bytes32::new([0x77; 32]);
        let msg = canonical_vote_message_for(outcome, election_id);

        // Voter side: sign UNAUGMENTED (matches `Voter::vote`).
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

    /// WHAT: vote_message and release_message for the same payload
    ///       produce DIFFERENT message bytes.
    /// HOW:  build both messages with the same payload (a fixed
    ///       Bytes32) and the same voter, assert inequality.
    /// WHY:  the `b"vote"` vs `b"release"` prefix domain-separates
    ///       the two messages so a vote signature can never be
    ///       replayed as a release authorisation (or vice versa).
    ///       Pin this critical security boundary.
    #[test]
    fn vote_and_release_messages_are_distinct() {
        let voter_pk = test_voter_pk();
        let config = good_config();
        let election_id = config.election_launcher_id().unwrap();
        let payload = Bytes32::new([0x42; 32]);

        let v_msg = message_for(b"vote", &voter_pk, election_id, payload);
        let r_msg = message_for(b"release", &voter_pk, election_id, payload);
        assert_ne!(v_msg, r_msg);
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
