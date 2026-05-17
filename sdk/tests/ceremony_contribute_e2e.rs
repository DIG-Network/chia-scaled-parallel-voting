// ============================================================================
// tests/ceremony_contribute_e2e.rs — CeremonyContributor simulator flow
// ============================================================================
//
// SCOPE: drives `CeremonyContributor::build_contribute_bundle`
// end-to-end against `chia_sdk_test::Simulator`:
//   1. Deploy a Ceremony Singleton on a fresh simulator.
//   2. Locate the eve singleton + reconstruct its lineage proof.
//   3. Build a contribute spend bundle with a synthetic participant
//      key + a funder coin for the marker's +1 mojo.
//   4. Sign the bundle (participant AGG_SIG_UNSAFE + funder AGG_SIG_ME).
//   5. Submit via `sim.new_transaction` and assert acceptance.
//
// SCOPE NOTE: this test surfaces the merkle-root convention,
// finalizer_solution shape, and action-layer dispatch correctness for
// the contribute action. Failures here are real puzzle/SDK bugs to
// fix; passing here unblocks `list_contributions_via_chain` and
// `derive_vk` work.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_bls::SecretKey;
use chia_protocol::{Bytes, Bytes32, Coin};
use chia_puzzle_types::{EveProof, Proof};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ceremony::{
    CeremonyContributor, CeremonyDeployer, CeremonyParams, ContributeParams,
};
use chip_voting_sdk::state::CeremonyState;
use clvm_utils::tree_hash;

/// Full contribute simulator smoke. Resolved bug (Phase 5 sub-step 11):
/// the marker CeremonyCoin's amount must be EVEN (2) — the singleton
/// outer's `check_and_morph_conditions_for_singleton` rejects more
/// than one ODD-amount CreateCoin per spend, and the finalizer's
/// recreation already claims the odd slot at amount 1. Bisecting the
/// `clvm raise` trap by progressively restoring contribute.rue's body
/// localised it to the marker; switching to amount=2 (mirrors
/// create_ballot.rue's launcher mint) fixed it.
#[tokio::test(flavor = "current_thread")]
async fn ceremony_contribute_against_simulator_smoke() {
    // ── 1. Deploy the ceremony ────────────────────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000);

    let vk_seed = Bytes32::new([0x42; 32]);
    let params = CeremonyParams {
        start_block_height: 0,
        ceremony_length_blocks: 1_000,
        min_participants: 1,
        max_voters: 20_000,
        vk_seed,
        label: None,
    };
    let deployer = CeremonyDeployer::new(params.clone());
    let (deploy_spends, launcher_id) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts ceremony deploy bundle");

    // ── 2. Locate the eve singleton ──────────────────────────
    // After deploy, the eve singleton is at
    //   puzzle_hash = singleton_outer(launcher_id, genesis_inner_ph)
    //   parent      = launcher_coin_id
    //   amount      = 1
    let genesis_inner_ph = deployer.genesis_inner_puzzle_hash(launcher_id);
    let eve_outer_ph = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
        launcher_id,
        genesis_inner_ph,
    );
    let eve_coin_states =
        sim.lookup_puzzle_hashes(indexmap::indexset![eve_outer_ph], false);
    assert_eq!(
        eve_coin_states.len(),
        1,
        "expected exactly one eve singleton at predicted puzzle hash {}",
        hex::encode(eve_outer_ph)
    );
    let eve = eve_coin_states[0].coin;
    // Eve proof: the launcher's PARENT (= funder.coin.coin_id()) +
    // the launcher's amount (1). Mirrors what build_singleton_spend
    // expects for the first spend after the launcher.
    let lineage_proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funder.coin.coin_id(),
        parent_amount: 1,
    });

    // ── 3. Build a separate funder coin for the marker's +1 mojo
    // ── using the quoted-empty-conditions trick from create_ballot_e2e.
    let mut ctx = SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let marker_funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let marker_funder_coin = Coin::new(Bytes32::new([0xEE; 32]), marker_funder_ph, 1);
    sim.insert_coin(marker_funder_coin);
    drop(ctx);

    // ── 4. Build a contribute bundle ─────────────────────────
    let participant_sk = SecretKey::from_seed(&[0x77u8; 32]);
    let participant_pk = participant_sk.public_key();

    // For the quoted-empty-conditions funder, the StandardLayer path
    // doesn't apply — the funder's puzzle is the literal `(q . ())`,
    // not the standard p2 puzzle. CeremonyContributor's funder spend
    // uses StandardLayer; for this smoke test we need a StandardLayer
    // funder. Use a fresh BLS wallet.
    let marker_funder = sim.bls(10);
    let contributor = CeremonyContributor::new(launcher_id, params.clone());
    // Use the JSON payload format that `derive_vk` expects so the
    // chain-walk → SimulatedBackend bridge works end-to-end below.
    let alice_entropy_hex = hex::encode(vec![0x01u8; 32]);
    let alice_payload = format!(
        r#"{{"entropy_hex":"{alice_entropy_hex}","name":"alice"}}"#
    )
    .into_bytes();
    let contrib_params = ContributeParams {
        participant_pubkey: participant_pk,
        contribution_hash: ContributeParams::compute_contribution_hash(&alice_payload),
        prev_contribution_hash: vk_seed,
        entropy_hex: Bytes::new(vec![0xA1; 32]),
        payload: alice_payload.clone(),
    };
    let coin_spends = contributor
        .build_contribute_bundle(
            eve,
            lineage_proof,
            CeremonyState::genesis(vk_seed),
            marker_funder.coin,
            marker_funder.pk,
            contrib_params,
        )
        .expect("build_contribute_bundle");

    // ── 5. Dry-run the bundle FIRST for a clearer error than the
    //       simulator signer's generic "clvm raise". This runs each
    //       coin spend's puzzle through clvmr and dumps the trap
    //       location if any.
    chip_voting_sdk::dry_run_coin_spends(&coin_spends)
        .expect("dry_run_coin_spends");

    // ── 6. Sign + submit ─────────────────────────────────────
    sim.spend_coins(coin_spends, &[marker_funder.sk, participant_sk])
        .expect("simulator accepts contribute bundle");

    // ── 7. Verify on-chain artifacts ─────────────────────────
    // The marker CeremonyCoin landed at its predicted puzzle hash,
    // hinted with launcher_id and at amount=2 (singleton-outer
    // single-odd-CreateCoin invariant).
    let predicted_marker_ph =
        chip_voting_sdk::actors::ceremony::ceremony_coin_marker_puzzle_hash(
            launcher_id,
            &participant_pk,
            ContributeParams::compute_contribution_hash(&alice_payload),
            vk_seed,
        );
    let marker_records =
        sim.lookup_puzzle_hashes(indexmap::indexset![predicted_marker_ph], false);
    assert_eq!(
        marker_records.len(),
        1,
        "expected exactly one marker CeremonyCoin at predicted ph {}",
        hex::encode(predicted_marker_ph)
    );
    assert_eq!(
        marker_records[0].coin.amount, 2,
        "marker amount must be 2 (even, per singleton outer invariant)"
    );
    assert_eq!(
        marker_records[0].coin.parent_coin_info, eve.coin_id(),
        "marker parent must be the eve singleton coin id"
    );

    // ── 8. Chain a 2nd contribution from a different participant.
    //       Verifies state advancement (count: 1 → 2, last_hash threading)
    //       and the Eve → Lineage proof transition.
    let contrib1_hash = ContributeParams::compute_contribution_hash(&alice_payload);
    let state_after_first = CeremonyState {
        contribution_count: 1,
        last_contribution_hash: contrib1_hash,
        finalized: false,
        vk_hash: Bytes32::default(),
        marker_root: Bytes32::default(),
    };
    let advanced_inner_ph = {
        // Re-use deployer logic for the same recurrence at the new state.
        // CeremonyState's clvm_tree_hash + the same finalizer/merkle-root
        // currying; only the state slot changes.
        use chip_voting_sdk::puzzles::{self as ps, PuzzleHashes};
        let action_layer_mod = PuzzleHashes::action_layer();
        let finalizer_mod = PuzzleHashes::ceremony_singleton_finalizer();
        let finalizer_first = ps::curry_tree_hash(
            finalizer_mod,
            &[
                ps::hash_atom_b32(&action_layer_mod),
                ps::hash_atom_b32(&launcher_id),
            ],
        );
        let finalizer_full = ps::curry_tree_hash(
            finalizer_first,
            &[ps::hash_atom_b32(&finalizer_first)],
        );
        let merkle_root = deployer.ceremony_actions_merkle_root(launcher_id);
        let state_hash = state_after_first.clvm_tree_hash();
        ps::curry_tree_hash(
            action_layer_mod,
            &[
                finalizer_full,
                ps::hash_atom_b32(&merkle_root),
                state_hash,
            ],
        )
    };
    let new_singleton_outer_ph = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
        launcher_id,
        advanced_inner_ph,
    );
    let new_singleton_records =
        sim.lookup_puzzle_hashes(indexmap::indexset![new_singleton_outer_ph], false);
    assert_eq!(
        new_singleton_records.len(),
        1,
        "expected the recreated singleton at predicted advanced inner ph"
    );
    let new_singleton = new_singleton_records[0].coin;

    let lineage_proof_2 = Proof::Lineage(chia_puzzle_types::LineageProof {
        parent_parent_coin_info: eve.parent_coin_info,
        parent_inner_puzzle_hash: genesis_inner_ph,
        parent_amount: eve.amount,
    });

    let participant_sk_2 = SecretKey::from_seed(&[0xCCu8; 32]);
    let participant_pk_2 = participant_sk_2.public_key();
    let funder_2 = sim.bls(10);

    let bob_entropy_hex = hex::encode(vec![0x02u8; 32]);
    let bob_payload = format!(
        r#"{{"entropy_hex":"{bob_entropy_hex}","name":"bob"}}"#
    )
    .into_bytes();
    let contrib2_hash = ContributeParams::compute_contribution_hash(&bob_payload);
    let contrib_params_2 = ContributeParams {
        participant_pubkey: participant_pk_2.clone(),
        contribution_hash: contrib2_hash,
        prev_contribution_hash: contrib1_hash,
        entropy_hex: Bytes::new(vec![0xB2; 32]),
        payload: bob_payload.clone(),
    };
    let coin_spends_2 = contributor
        .build_contribute_bundle(
            new_singleton,
            lineage_proof_2,
            state_after_first,
            funder_2.coin,
            funder_2.pk,
            contrib_params_2,
        )
        .expect("build_contribute_bundle (second)");
    sim.spend_coins(coin_spends_2, &[funder_2.sk, participant_sk_2])
        .expect("simulator accepts second contribute bundle");

    // Verify the 2nd marker landed on chain.
    let predicted_marker_2_ph =
        chip_voting_sdk::actors::ceremony::ceremony_coin_marker_puzzle_hash(
            launcher_id,
            &participant_pk_2,
            contrib2_hash,
            contrib1_hash,
        );
    let marker_2_records =
        sim.lookup_puzzle_hashes(indexmap::indexset![predicted_marker_2_ph], false);
    assert_eq!(
        marker_2_records.len(),
        1,
        "expected exactly one second marker CeremonyCoin"
    );

    // ── 8b. Chain a 3rd contribution from a different participant.
    //        Confirms the lineage advances cleanly past the 2-record
    //        boundary. The singleton tip after the 2nd contribute is
    //        a child of `new_singleton` at amount=1.
    let state_after_second = CeremonyState {
        contribution_count: 2,
        last_contribution_hash: contrib2_hash,
        finalized: false,
        vk_hash: Bytes32::default(),
        marker_root: Bytes32::default(),
    };
    let advanced_inner_ph_2 = {
        use chip_voting_sdk::puzzles::{self as ps, PuzzleHashes};
        let action_layer_mod = PuzzleHashes::action_layer();
        let finalizer_mod = PuzzleHashes::ceremony_singleton_finalizer();
        let finalizer_first = ps::curry_tree_hash(
            finalizer_mod,
            &[
                ps::hash_atom_b32(&action_layer_mod),
                ps::hash_atom_b32(&launcher_id),
            ],
        );
        let finalizer_full = ps::curry_tree_hash(
            finalizer_first,
            &[ps::hash_atom_b32(&finalizer_first)],
        );
        let merkle_root = deployer.ceremony_actions_merkle_root(launcher_id);
        let state_hash = state_after_second.clvm_tree_hash();
        ps::curry_tree_hash(
            action_layer_mod,
            &[
                finalizer_full,
                ps::hash_atom_b32(&merkle_root),
                state_hash,
            ],
        )
    };
    let new_singleton_2_outer_ph = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
        launcher_id,
        advanced_inner_ph_2,
    );
    let new_singleton_2_records = sim.lookup_puzzle_hashes(
        indexmap::indexset![new_singleton_2_outer_ph],
        false,
    );
    let new_singleton_2 = new_singleton_2_records[0].coin;
    let lineage_proof_3 = Proof::Lineage(chia_puzzle_types::LineageProof {
        parent_parent_coin_info: new_singleton.parent_coin_info,
        parent_inner_puzzle_hash: advanced_inner_ph,
        parent_amount: new_singleton.amount,
    });

    let participant_sk_3 = SecretKey::from_seed(&[0xDDu8; 32]);
    let participant_pk_3 = participant_sk_3.public_key();
    let funder_3 = sim.bls(10);
    let carol_payload =
        format!(r#"{{"entropy_hex":"{}","name":"carol"}}"#, hex::encode(vec![0x03u8; 32]))
            .into_bytes();
    let contrib3_hash = ContributeParams::compute_contribution_hash(&carol_payload);
    let contrib_params_3 = ContributeParams {
        participant_pubkey: participant_pk_3.clone(),
        contribution_hash: contrib3_hash,
        prev_contribution_hash: contrib2_hash,
        entropy_hex: Bytes::new(vec![0xC3; 32]),
        payload: carol_payload.clone(),
    };
    let coin_spends_3 = contributor
        .build_contribute_bundle(
            new_singleton_2,
            lineage_proof_3,
            state_after_second,
            funder_3.coin,
            funder_3.pk,
            contrib_params_3,
        )
        .expect("build_contribute_bundle (third)");
    sim.spend_coins(coin_spends_3, &[funder_3.sk, participant_sk_3])
        .expect("simulator accepts third contribute bundle");

    // ── 9. Round-trip: fetch the SPENT eve singleton's solution and
    //       parse it back through the SDK helpers — verifies that
    //       `extract_contribute_action_solution` +
    //       `parse_action_solution_node` correctly recover the inputs
    //       to the contribute action from the on-chain spend.
    use chip_voting_sdk::actors::ceremony::CeremonyContributor as CC;
    use clvm_traits::ToClvm;
    let (eve_puzzle, eve_solution) = sim
        .puzzle_and_solution(eve.coin_id())
        .expect("eve singleton should be spent")
        .clone();
    let mut ctx_parse = SpendContext::new();
    let solution_node = chia_protocol::Program::from(eve_solution.as_ref().to_vec())
        .to_clvm(&mut *ctx_parse)
        .unwrap();
    let _puzzle_node = chia_protocol::Program::from(eve_puzzle.as_ref().to_vec())
        .to_clvm(&mut *ctx_parse)
        .unwrap();
    let allocator: &clvmr::Allocator = &*ctx_parse;
    let action_sol = CC::extract_contribute_action_solution(allocator, solution_node)
        .expect("extract contribute action solution");
    let (pk_bytes_recovered, contrib_recovered, prev_recovered, _entropy_recovered, payload_recovered) =
        CC::parse_action_solution_node(allocator, action_sol)
            .expect("parse action solution");
    assert_eq!(
        pk_bytes_recovered,
        participant_pk.to_bytes().as_ref(),
        "recovered pk should match original participant"
    );
    assert_eq!(contrib_recovered, contrib1_hash);
    assert_eq!(prev_recovered, vk_seed);
    assert_eq!(payload_recovered, alice_payload);

    // ── 10. Chain-walk via list_contributions_via_chain. After two
    //        contributions, the walker should return both records in
    //        chain order with the correct linear lineage anchored at
    //        vk_seed.
    use chip_voting_sdk::actors::ceremony::CeremonyReader;
    let chain = common::SharedSim::new(&mut sim);
    let records = CeremonyReader::list_contributions_via_chain(&chain, launcher_id)
        .await
        .expect("list_contributions_via_chain");
    drop(chain);
    assert_eq!(records.len(), 3, "should chain-walk all three contributions");
    assert_eq!(records[0].prev_contribution_hash, vk_seed);
    assert_eq!(records[0].contribution_hash, contrib1_hash);
    assert_eq!(records[1].prev_contribution_hash, contrib1_hash);
    assert_eq!(records[1].contribution_hash, contrib2_hash);
    assert_eq!(records[2].prev_contribution_hash, contrib2_hash);
    assert_eq!(records[2].contribution_hash, contrib3_hash);
    assert_eq!(records[0].payload, alice_payload);
    assert_eq!(records[1].payload, bob_payload);
    assert_eq!(records[2].payload, carol_payload);

    // Validate the lineage in one shot via the gate helper.
    CeremonyReader::validate_lineage(&records, vk_seed)
        .expect("chain-walked records form a valid lineage");
    CeremonyReader::check_threshold(&records, vk_seed, 3)
        .expect("chain-walked records meet min_participants=3 threshold");

    // ── 11. derive_vk: end-to-end bridge from chain-walked records
    //        through the SimulatedBackend to a real Groth16 VK.
    let vk = CeremonyReader::derive_vk(&records, vk_seed, 3)
        .expect("derive_vk on chain-walked records");
    assert!(
        !vk.raw_bytes.is_empty(),
        "derived VK must have non-empty raw_bytes"
    );
    // Sanity check: VK length matches the canonical Groth16 layout
    // (alpha_g1 + 3 g2 + (PUBLIC_INPUT_COUNT+1) ic points).
    let expected_len = 336 + (chip_voting_sdk::config::PUBLIC_INPUT_COUNT + 1) * 48;
    assert_eq!(
        vk.raw_bytes.len(),
        expected_len,
        "derived VK byte length should match canonical Groth16 layout"
    );
}
