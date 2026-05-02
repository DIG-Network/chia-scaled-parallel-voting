// ============================================================================
// tests/action_layer_e2e.rs — full-action-layer end-to-end CLVM tests
// ============================================================================
//
// SCOPE: validate the complete action-layer composition (action.rue +
//        custom finalizer + per-action puzzle) on the chia simulator.
//        Distinct from the action-puzzle-only tests in
//        `voter_actions_e2e.rs` and `register_action_e2e.rs` — those
//        bypass the action layer dispatcher with a multi-arg adapter.
//        These tests exercise EVERY layer the on-chain spend goes
//        through:
//            1. action.rue's selector + Merkle proof verification
//            2. action.rue's per-action dispatch + state threading
//            3. The custom finalizer's CreateCoin recreation
//            4. The on-chain AggSig / AssertCoinAnnouncement validation
//
// CONVENTION: each test is named after the actor method it validates
// (`voter_vote_through_full_action_layer_*`, etc.) so the connection
// between SDK code and on-chain validation is unambiguous.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
// CLVM tuple types in this file express on-chain puzzle tree
// shapes verbatim; factoring into `type` aliases would obscure the
// 1:1 mapping with the Rue struct definitions.
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes, Bytes32, Coin};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chip_voting_sdk::action_spends::{
    build_action_layer_puzzle, build_action_layer_solution,
    build_registration_finalizer_full, load_action_puzzle, ActionSpend,
};
use chip_voting_sdk::puzzles::{self, registration_action_root_leaves};

// CHIP rev 2026-05-02: REGISTRATION_VOTE_HEX replaced by
// REGISTRATION_MINT_VOTING_COIN_HEX, ELECTION_FINALIZE_HEX moved to
// BALLOT_COIN_FINALIZE_HEX. Aliased so existing test bodies still
// compile while their assertions are pinned by `#[ignore]` until
// rewritten in Phase 6.
#[allow(non_upper_case_globals)]
mod legacy_puzzle_aliases {
    pub use chip_voting_sdk::puzzles::BALLOT_COIN_FINALIZE_HEX as ELECTION_FINALIZE_HEX;
    pub use chip_voting_sdk::puzzles::REGISTRATION_MINT_VOTING_COIN_HEX as REGISTRATION_VOTE_HEX;
}
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: the Registration Coin's `vote` action, run through the
///       FULL action-layer composition, executes cleanly on the
///       chia simulator.
/// HOW:
///   1. Build the registration finalizer (1st curry: ACTION_LAYER +
///      HINT; 2nd curry: self-hash).
///   2. Build the FRESH RegistrationState
///      `(pk, election_id, false, 0, nil)` as a CLVM tree.
///   3. Curry `action.rue` with `(finalizer, merkle_root, state)`
///      — this is the inner puzzle of the (CAT-wrapped, in
///      production) Registration Coin.
///   4. Insert a coin at the inner puzzle's hash on the simulator
///      (no CAT outer — this test isolates the action-layer
///      composition from CAT amount-preservation).
///   5. Build the action-layer SOLUTION via the SDK's
///      `build_action_layer_solution` helper:
///        - puzzles = [vote_action_puzzle]
///        - selectors_and_proofs = [(2, Some(merkle_proof))]
///        - solutions = [(vote_data, vote_signature)]
///        - finalizer_solution = my_amount (the coin's amount)
///   6. Sign the AggSigUnsafe over the canonical vote message.
///   7. Submit. The simulator must accept the spend, mark the coin
///      as spent, and the recreated coin should land at the
///      predicted post-vote puzzle hash.
/// WHY: this is the END-TO-END proof that the action-layer
///      composition the actor methods rely on actually works on a
///      consensus-validated chain. Any mismatch between our
///      `build_action_layer_*` helpers and on-chain expectations
///      surfaces here as a simulator rejection.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (registration_coin's `vote` action replaced by `mint_voting_coin`)"]
fn voter_vote_through_full_action_layer_executes_on_simulator() {
    let mut sim = Simulator::new();
    let (voter_sk, voter_pk) = common::test_voter(0xAB);
    let election_id = Bytes32::new([0xAB; 32]);
    let coin_amount: u64 = 1_000;

    // ── Build the registration coin's INNER puzzle ──────────────
    let mut ctx = SpendContext::new();
    let cat_tail_hash = Bytes32::new([0x33; 32]);
    let voter_hint = puzzles::voter_hint(election_id, cat_tail_hash, &voter_pk);
    let reg_finalizer = build_registration_finalizer_full(&mut ctx, voter_hint).unwrap();

    // Fresh state CLVM: Rue `Bool false` is nil `()`, not `0u8` — matches
    // `Voter::registration_state_node` / `fresh_registration_state_tree_hash`
    // and on-chain `register.rue` initial state (slot-machine curry convention).
    let pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let state_value: (Bytes, (Bytes32, ((), (Bytes32, ())))) =
        (pk_bytes, (election_id, ((), (Bytes32::default(), ()))));
    let state_node = state_value.to_clvm(&mut *ctx).unwrap();

    let merkle_root = puzzles::registration_actions_merkle_root();
    let action_layer_node =
        build_action_layer_puzzle(&mut ctx, reg_finalizer, merkle_root, state_node).unwrap();
    let action_layer_ph = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());

    // Insert a synthetic coin at this puzzle hash. In production
    // this coin would be CAT-wrapped (our action_layer_node would be
    // the inner puzzle); for this isolated test we treat it as a
    // bare standard coin so we can observe the action layer's
    // behaviour without the CAT outer's amount-preservation gating.
    let parent_id = Bytes32::new([0xCC; 32]);
    let coin = Coin::new(parent_id, action_layer_ph, coin_amount);
    sim.insert_coin(coin);

    // ── Build the vote action spend ─────────────────────────────
    let vote_data = Bytes32::new([0x42; 32]);
    let vote_msg = common::vote_message(election_id, &voter_pk, vote_data);
    // AggSigUnsafe in our vote.rue uses chia_bls::sign (augmented).
    let vote_sig = chia_bls::sign(&voter_sk, vote_msg.as_ref());

    let vote_action = load_action_puzzle(&mut ctx, legacy_puzzle_aliases::REGISTRATION_VOTE_HEX).unwrap();
    let vote_sig_bytes = Bytes::new(vote_sig.to_bytes().to_vec());
    let vote_solution_value = (vote_data, vote_sig_bytes);
    let vote_solution = vote_solution_value.to_clvm(&mut *ctx).unwrap();

    let action_spends = vec![ActionSpend {
        puzzle: vote_action,
        solution: vote_solution,
    }];
    // Registration finalizer takes `...my_amount: Int` — pass the
    // coin's amount so the recreated coin gets the same amount
    // (matches the CAT preservation rule in production).
    let finalizer_solution = coin_amount.to_clvm(&mut *ctx).unwrap();
    let leaves = registration_action_root_leaves();
    let action_layer_solution =
        build_action_layer_solution(&mut ctx, &leaves, &action_spends, finalizer_solution)
            .unwrap();

    let spend = common::coin_spend_from_nodes(&ctx, coin, action_layer_node, action_layer_solution);
    let bundle = common::make_bundle(vec![spend], vote_sig);

    // ── Submit to the simulator ─────────────────────────────────
    sim.new_transaction(bundle).unwrap_or_else(|e| {
        panic!(
            "simulator must accept the vote action layer spend; got: {:?}",
            e
        )
    });

    // The original coin should be spent; the recreated coin (at
    // the post-vote puzzle hash) should be present.
    assert!(
        sim.coin_state(coin.coin_id())
            .expect("coin state present")
            .spent_height
            .is_some(),
        "the registration coin should have been spent"
    );
}

/// WHAT: the Registration Coin's `release` action, paired with the
///       Election Singleton's `announce_finalization` action,
///       executes cleanly through the FULL action-layer composition
///       on the chia simulator.
/// HOW:
///   1. Build the FRESH RegistrationState wrapped in the action
///      layer + custom registration finalizer; insert a coin at
///      that puzzle hash.
///   2. Build a synthetic "announcer" coin that emits the exact
///      finalization CreateCoinAnnouncement the release puzzle
///      will assert (sim doesn't have a real Election Singleton
///      yet — we use a quoted-message announcer to isolate the
///      release-action validation).
///   3. Build the release action solution: (Truth, dest,
///      announcer_coin_id, outcome, count, ...root). The
///      announcer's coin_id lets release.rue compute the FULL
///      announcement_id consensus expects.
///   4. Sign the AggSigMe condition release.rue emits.
///   5. Submit the paired bundle (announcer + release). Both must
///      be marked spent.
/// WHY: this exercises (a) action-layer composition with the
///      release action, (b) custom finalizer's release-branch
///      (CreateCoin to dest instead of recreate), (c) the
///      AssertCoinAnnouncement plumbing all the way to consensus.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (release pairs with Ballot Coin announce_finalization, not the singleton's)"]
fn voter_release_through_full_action_layer_executes_on_simulator() {
    let mut sim = Simulator::new();
    let (voter_sk, voter_pk) = common::test_voter(0xCD);
    let election_id = Bytes32::new([0xAB; 32]);
    let coin_amount: u64 = 1_000;
    let dest = Bytes32::new([0xEE; 32]);

    // ── Build the registration coin's INNER puzzle (FRESH state) ──
    let mut ctx = SpendContext::new();
    let cat_tail_hash = Bytes32::new([0x33; 32]);
    let voter_hint = puzzles::voter_hint(election_id, cat_tail_hash, &voter_pk);
    let reg_finalizer = build_registration_finalizer_full(&mut ctx, voter_hint).unwrap();
    let pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let state_value: (Bytes, (Bytes32, ((), (Bytes32, ())))) =
        (pk_bytes, (election_id, ((), (Bytes32::default(), ()))));
    let state_node = state_value.to_clvm(&mut *ctx).unwrap();
    let merkle_root = puzzles::registration_actions_merkle_root();
    let reg_action_layer =
        build_action_layer_puzzle(&mut ctx, reg_finalizer, merkle_root, state_node).unwrap();
    let reg_ph = Bytes32::new(tree_hash(&ctx, reg_action_layer).to_bytes());
    let reg_coin = Coin::new(Bytes32::new([0xCC; 32]), reg_ph, coin_amount);
    sim.insert_coin(reg_coin);

    // ── Build a synthetic announcer coin ────────────────────────
    // Quoted puzzle that always emits exactly one
    // CreateCoinAnnouncement carrying the finalization message.
    let outcome = Bytes32::new([0x42; 32]);
    let count: u64 = 0;
    let root = Bytes32::new(chip_voting_sdk::config::EMPTY_LEAF_HASH);
    let finalization_msg = common::finalization_announcement_msg(outcome, count, root);
    // (q . ((60 finalization_msg))) — quoted conditions list.
    let condition: (u8, (Bytes32, ())) = (60u8, (finalization_msg, ()));
    let conditions_list: ((u8, (Bytes32, ())), ()) = (condition, ());
    let announcer_puzzle: (u8, ((u8, (Bytes32, ())), ())) = (1u8, conditions_list);
    let announcer_node = announcer_puzzle.to_clvm(&mut *ctx).unwrap();
    let announcer_ph = Bytes32::new(tree_hash(&ctx, announcer_node).to_bytes());
    let announcer_coin = Coin::new(Bytes32::new([0xBB; 32]), announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_id = announcer_coin.coin_id();
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let announcer_spend = common::coin_spend_from_nodes(
        &ctx,
        announcer_coin,
        announcer_node,
        announcer_solution,
    );

    // ── Build the release action spend (action-layer wrapped) ──
    let release_action = load_action_puzzle(&mut ctx, puzzles::REGISTRATION_RELEASE_HEX).unwrap();
    // Solution: (dest, announcer_id, outcome, count, ...root)
    let release_solution_value =
        (dest, (announcer_id, (outcome, (count, root))));
    let release_solution = release_solution_value.to_clvm(&mut *ctx).unwrap();
    let action_spends = vec![ActionSpend {
        puzzle: release_action,
        solution: release_solution,
    }];
    let finalizer_solution = coin_amount.to_clvm(&mut *ctx).unwrap();
    let leaves = registration_action_root_leaves();
    let action_layer_solution =
        build_action_layer_solution(&mut ctx, &leaves, &action_spends, finalizer_solution)
            .unwrap();
    let release_spend =
        common::coin_spend_from_nodes(&ctx, reg_coin, reg_action_layer, action_layer_solution);

    // ── Sign the AggSigMe over the release message ─────────────
    let release_msg = common::release_message(election_id, &voter_pk, dest);
    let release_sig = common::sign_aggsig_me(&voter_sk, release_msg, &reg_coin);

    let bundle = common::make_bundle(vec![announcer_spend, release_spend], release_sig);
    sim.new_transaction(bundle).unwrap_or_else(|e| {
        panic!(
            "simulator must accept the release+announcer paired bundle; got: {:?}",
            e
        )
    });

    assert!(
        sim.coin_state(reg_coin.coin_id())
            .unwrap()
            .spent_height
            .is_some(),
        "registration coin must be spent"
    );
    assert!(
        sim.coin_state(announcer_coin.coin_id())
            .unwrap()
            .spent_height
            .is_some(),
        "announcer coin must be spent"
    );
}

/// WHAT: the Election Singleton's `finalize` action — including a
///       REAL Groth16 proof + REAL BLS aggregate signature — runs
///       through the FULL action-layer composition end-to-end on
///       the chia simulator.
/// HOW:
///   1. Generate a real test Groth16 proving key + verification
///      key via `VotingCircuit::generate_test_setup`.
///   2. Build the FINALIZE action puzzle, curried with VK + IC +
///      ELECTION_LENGTH_BLOCKS=0 + ELECTION_LAUNCHER_ID.
///   3. Build a single-leaf Merkle root over just the curried
///      finalize action (production deployments use a 3-leaf root
///      for register/finalize/announce_finalization).
///   4. Build the election finalizer (1st curry + 2nd curry).
///   5. Build the FRESH ElectionState (count=1, fees=0, root=any).
///   6. Curry the action layer with (election_finalizer,
///      single_action_root, state).
///   7. Insert a coin at the resulting puzzle hash.
///   8. Construct a `VotingCircuit` with one signer, run
///      `prove(&pk)` to produce a real Groth16 proof.
///   9. Build the BLS aggregate signature off-chain (single
///      signer's UNAUGMENTED signature over the canonical vote
///      message `sha256(outcome || launcher_id)`).
///  10. Build the action layer solution with the finalize action
///      selected. Submit. Consensus must accept — every constraint
///      runs (Groth16 pairing, BLS aggregate verify, scalar binds,
///      time lock, state assertion, finalizer payout).
///
/// WHY: this is the FULL end-to-end proof that the entire on-chain
///      finalize path — including the Groth16 verifier the SDK's
///      `Aggregator::build_finalize_with_proof` constructs spend
///      bundles for — works on a consensus-validated chain. ANY
///      drift between our prover, our scalar derivation, our VK/IC
///      serialisation, and the on-chain Rue puzzle would surface
///      here as a simulator rejection.
#[test]
#[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
            (finalize moved to Ballot Coin with 6-input circuit; rewrite required)"]
fn finalize_action_through_full_action_layer_executes_on_simulator() {
    use ark_std::rand::SeedableRng;
    use chip_voting_sdk::prover::{
        circuit::{generate_test_setup, SignerWitness, VotingCircuit},
        Scalars,
    };
    use clvm_traits::clvm_curried_args;
    use clvm_utils::CurriedProgram;

    let mut sim = Simulator::new();
    let (voter_sk, voter_pk) = common::test_voter(0xEF);
    let election_id = Bytes32::new([0xAB; 32]);

    // ── 1. Trusted setup (test backend; not cryptographically sound) ─
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let (pk_ark, vk_ark) = generate_test_setup(&mut rng).expect("generate_test_setup");

    // ── 2. Curry the FINALIZE action puzzle with VK + IC ───────
    let mut ctx = SpendContext::new();
    let finalize_program_node =
        load_action_puzzle(&mut ctx, legacy_puzzle_aliases::ELECTION_FINALIZE_HEX).unwrap();

    // The Rue puzzle declares VK as `struct VK { alpha (G1), beta
    // (G2), gamma (G2), delta (G2) }` — a 4-element CLVM list
    // serialised as `(alpha . (beta . (gamma . (delta . ()))))`.
    // For the 6-public-input voting circuit (CHIP rev 2026-05-02),
    // IC is a 7-element list of G1 points (ic0 + ic1..ic6).
    //
    // `chia_chunked_bytes` produces the FLAT layout
    //   alpha(48) || beta(96) || gamma(96) || delta(96)
    //     || ic0..ic6 (48 each)
    // = 672 bytes. Split into the typed fields and curry as proper
    // CLVM lists.
    let vk_full_bytes = vk_ark.chia_chunked_bytes().expect("vk chunked bytes");
    let vk_alpha = Bytes::new(vk_full_bytes[0..48].to_vec());
    let vk_beta = Bytes::new(vk_full_bytes[48..144].to_vec());
    let vk_gamma = Bytes::new(vk_full_bytes[144..240].to_vec());
    let vk_delta = Bytes::new(vk_full_bytes[240..336].to_vec());
    let vk_struct = (vk_alpha, (vk_beta, (vk_gamma, (vk_delta, ()))));

    let ic0 = Bytes::new(vk_full_bytes[336..384].to_vec());
    let ic1 = Bytes::new(vk_full_bytes[384..432].to_vec());
    let ic2 = Bytes::new(vk_full_bytes[432..480].to_vec());
    let ic3 = Bytes::new(vk_full_bytes[480..528].to_vec());
    let ic4 = Bytes::new(vk_full_bytes[528..576].to_vec());
    let ic5 = Bytes::new(vk_full_bytes[576..624].to_vec());
    let ic6 = Bytes::new(vk_full_bytes[624..672].to_vec());
    let ic_struct = (ic0, (ic1, (ic2, (ic3, (ic4, (ic5, (ic6, ())))))));

    let election_length_blocks: u64 = 0; // immediate finalize for the test
    let finalize_curried = CurriedProgram {
        program: finalize_program_node,
        args: clvm_curried_args!(vk_struct, ic_struct, election_length_blocks, election_id),
    }
    .to_clvm(&mut *ctx)
    .unwrap();
    let finalize_ph = Bytes32::new(tree_hash(&ctx, finalize_curried).to_bytes());

    // ── 3. Build a single-leaf Merkle root over finalize ──────
    let action_leaves = vec![finalize_ph];

    // ── 4. Build the election finalizer ──────────────────────
    let election_finalizer =
        chip_voting_sdk::action_spends::build_election_finalizer_full(&mut ctx, election_id)
            .unwrap();

    // ── 5. Build the FRESH ElectionState (pre-finalize) ──────
    let registration_merkle_root = Bytes32::new([0x55; 32]);
    let registration_count: u64 = 1;
    let accumulated_fees: u64 = 0;
    let pre_state_value: (Bytes32, (u64, (u64, (u8, Bytes32)))) = (
        registration_merkle_root,
        (
            registration_count,
            (accumulated_fees, (0u8, Bytes32::default())),
        ),
    );
    let state_node = pre_state_value.to_clvm(&mut *ctx).unwrap();

    // ── 6. Build the action layer ───────────────────────────
    use chia_sdk_types::MerkleTree;
    let single_action_root = MerkleTree::new(&action_leaves).root();
    let action_layer_node = build_action_layer_puzzle(
        &mut ctx,
        election_finalizer,
        single_action_root,
        state_node,
    )
    .unwrap();
    let inner_ph = Bytes32::new(tree_hash(&ctx, action_layer_node).to_bytes());

    // ── 7. Insert a coin at the inner puzzle hash ───────────
    // For this test we use the action-layer puzzle directly (no
    // singleton outer) — same isolation as the vote test. The
    // finalize action emits CreateCoin (pay finalizer) +
    // CreateCoinAnnouncement; both are well-formed conditions
    // against a standard coin spend.
    let coin_amount: u64 = 1;
    let coin = Coin::new(Bytes32::new([0xCC; 32]), inner_ph, coin_amount);
    sim.insert_coin(coin);

    // ── 8. Construct the witness + run the prover ───────────
    // The on-chain vote message is sha256(outcome || launcher_id)
    // (per finalize.rue line 83).
    let vote_outcome = Bytes32::new([0x42; 32]);
    let vote_message = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(vote_outcome.as_ref());
        h.update(election_id.as_ref());
        let mut a = [0u8; 32];
        a.copy_from_slice(&h.finalize());
        Bytes32::new(a)
    };

    // Single signer = the test voter; agg_signers = voter's pubkey.
    let signers = vec![SignerWitness {
        pubkey: voter_pk,
        leaf_index: 0,
        merkle_proof: vec![Bytes32::default(); chip_voting_sdk::config::TREE_DEPTH as usize],
    }];
    let circuit = VotingCircuit {
        registration_merkle_root,
        // CHIP rev 2026-05-02: 6-input circuit (renamed registration_count
        // → registration_vote_weight; added threshold + ballot_launcher_id).
        registration_vote_weight: registration_count,
        agg_signers: voter_pk,
        vote_message,
        vote_threshold_num: 1,
        vote_threshold_den: 2,
        ballot_launcher_id: Bytes32::default(),
        signers,
    };
    let proof = circuit.prove(&pk_ark).expect("prove");
    // Sanity: the same proof MUST verify off-chain via arkworks.
    let scalars_for_verify = Scalars::compute(
        registration_merkle_root,
        registration_count,
        &voter_pk,
        vote_message,
        1,
        2,
        Bytes32::default(),
    );
    let off_chain_ok = chip_voting_sdk::prover::circuit::VotingCircuit::verify_offchain(
        &vk_ark,
        &proof,
        &scalars_for_verify.as_array(),
    )
    .expect("verify_offchain");
    assert!(off_chain_ok, "off-chain Groth16 verification must succeed");

    // Sanity: post-mod-r reduction, every scalar's high bit MUST be 0
    // (since r < 2^254). CLVM's signed/unsigned interpretations
    // therefore match, and bls_g1_multiply produces the same G1
    // point off-chain and on-chain.
    for (i, s) in scalars_for_verify.as_array().iter().enumerate() {
        assert!(
            s.as_ref()[0] & 0x80 == 0,
            "scalar s{} high bit set after mod-r reduction (sha256_mod_r bug?): {}",
            i + 1,
            hex::encode(s)
        );
    }

    // ── 9. Build the BLS aggregate signature ────────────────
    // Single signer's UNAUGMENTED signature over the canonical
    // vote message — matches the on-chain `bls_pairing_identity`
    // opcode in finalize.rue, which validates the textbook
    // PoP-style identity
    //   e(agg_signers, H(vote_message)) ==
    //     e(G1_GENERATOR, agg_sig).
    // For `agg_sig = sk_agg · H(vote_message)` to satisfy that
    // identity, the per-voter signatures must be unaugmented
    // (`chia_bls::sign_raw`), so they algebraically sum to
    // `sk_agg · H(msg)`. Using the AUGMENTED `chia_bls::sign`
    // would prepend each signer's pubkey before hashing-to-G2,
    // breaking the single-pair pairing identity for k > 1 and
    // (in this 1-signer test) requiring augmentation with `pk`
    // instead of identity — which the puzzle's pairing equation
    // doesn't add.
    let agg_sig = chia_bls::sign_raw(&voter_sk, vote_message.as_ref());

    // ── 10. Build the finalize action solution ─────────────
    let scalars = Scalars::compute(
        registration_merkle_root,
        registration_count,
        &voter_pk,
        vote_message,
        1,
        2,
        Bytes32::default(),
    );
    let scalars_arr = scalars.as_array();
    let finalizer_destination = Bytes32::new([0xDD; 32]);

    // proof = (a . (b . (c . nil))) — 3-elt proper list of typed pts
    let proof_a_bytes = Bytes::new(hex::decode(&proof.a_hex).unwrap());
    let proof_b_bytes = Bytes::new(hex::decode(&proof.b_hex).unwrap());
    let proof_c_bytes = Bytes::new(hex::decode(&proof.c_hex).unwrap());
    let proof_value = (proof_a_bytes, (proof_b_bytes, (proof_c_bytes, ())));

    // Finalize ACTION solution shape:
    //   (proof, vote_outcome, agg_signers, agg_sig, scalars,
    //    ...finalizer_destination)
    // No nil after finalizer_destination — it's the trailing tail.
    let agg_signers_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
    let agg_sig_bytes = Bytes::new(agg_sig.to_bytes().to_vec());
    let finalize_solution_value = (
        proof_value,
        (
            vote_outcome,
            (
                agg_signers_bytes,
                (agg_sig_bytes, (scalars_arr, finalizer_destination)),
            ),
        ),
    );
    let finalize_solution = finalize_solution_value.to_clvm(&mut *ctx).unwrap();

    let action_spends = vec![ActionSpend {
        puzzle: finalize_curried,
        solution: finalize_solution,
    }];
    // Election finalizer takes `..._my_solution: Any` — pass nil.
    let elect_finalizer_solution = ().to_clvm(&mut *ctx).unwrap();
    let action_layer_solution = build_action_layer_solution(
        &mut ctx,
        &action_leaves,
        &action_spends,
        elect_finalizer_solution,
    )
    .unwrap();

    let spend = common::coin_spend_from_nodes(&ctx, coin, action_layer_node, action_layer_solution);
    // finalize emits no AggSig conditions — bundle signature is empty.
    let bundle = common::make_bundle(vec![spend], chia_bls::Signature::default());
    sim.new_transaction(bundle).unwrap_or_else(|e| {
        panic!(
            "simulator must accept the finalize action layer spend (real Groth16); got: {:?}",
            e
        )
    });

    assert!(
        sim.coin_state(coin.coin_id())
            .unwrap()
            .spent_height
            .is_some(),
        "Election Singleton coin must be spent after finalize"
    );
}
