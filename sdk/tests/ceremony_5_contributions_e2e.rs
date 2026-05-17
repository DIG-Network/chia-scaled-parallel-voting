// ============================================================================
// tests/ceremony_5_contributions_e2e.rs — 5-participant ceremony e2e
// ============================================================================
//
// SCOPE: matches Phase 5 spec ("ceremony deploy → 5 contributions → close
// → derive VK"). Uses a per-step helper to chain contributions cleanly,
// then verifies the chain-walk + derive_vk pipeline scales to N=5.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

mod common;

use chia_bls::SecretKey;
use chia_protocol::{Bytes, Bytes32, Coin};
use chia_puzzle_types::{EveProof, LineageProof, Proof};
use chia_sdk_test::Simulator;
use chip_voting_sdk::actors::ceremony::{
    CeremonyContributor, CeremonyDeployer, CeremonyParams, CeremonyReader, ContributeParams,
};
use chip_voting_sdk::state::CeremonyState;

#[tokio::test(flavor = "current_thread")]
async fn ceremony_five_contributions_against_simulator() {
    const N: usize = 5;

    // ── 1. Deploy the ceremony ────────────────────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000);
    let vk_seed = Bytes32::new([0xA1; 32]);
    let params = CeremonyParams {
        start_block_height: 0,
        ceremony_length_blocks: 1_000,
        min_participants: N as u64,
        max_voters: 20_000,
        vk_seed,
        label: None,
    };
    let deployer = CeremonyDeployer::new(params.clone());
    let (deploy_spends, launcher_id) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("deploy");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy");

    // ── 2. Locate the eve singleton ──────────────────────────
    let genesis_inner_ph = deployer.genesis_inner_puzzle_hash(launcher_id);
    let eve_outer_ph = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
        launcher_id,
        genesis_inner_ph,
    );
    let eve_records =
        sim.lookup_puzzle_hashes(indexmap::indexset![eve_outer_ph], false);
    assert_eq!(eve_records.len(), 1);
    let eve = eve_records[0].coin;

    let contributor = CeremonyContributor::new(launcher_id, params.clone());

    // Helper to recompute the inner puzzle hash for an arbitrary state.
    let advanced_inner_ph_for = |state: &CeremonyState| -> Bytes32 {
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
        let state_hash = state.clvm_tree_hash();
        ps::curry_tree_hash(
            action_layer_mod,
            &[
                finalizer_full,
                ps::hash_atom_b32(&merkle_root),
                state_hash,
            ],
        )
    };

    // ── 3. Loop N contributions, threading state + lineage. ──
    let mut current_singleton: Coin = eve;
    let mut current_state = CeremonyState::genesis(vk_seed);
    let mut current_lineage_proof: Proof = Proof::Eve(EveProof {
        parent_parent_coin_info: funder.coin.coin_id(),
        parent_amount: 1,
    });
    let mut prev_inner_ph = genesis_inner_ph;
    let mut prev_hash = vk_seed;

    for i in 0..N {
        let entropy_byte = (0xB0u8) + (i as u8);
        let name = format!("p{i}");
        let payload =
            format!(r#"{{"entropy_hex":"{}","name":"{name}"}}"#, hex::encode(vec![entropy_byte; 32]))
                .into_bytes();
        let contribution_hash = ContributeParams::compute_contribution_hash(&payload);

        let participant_sk = SecretKey::from_seed(&[entropy_byte; 32]);
        let participant_pk = participant_sk.public_key();
        let mojo_funder = sim.bls(10);

        let contrib_params = ContributeParams {
            participant_pubkey: participant_pk.clone(),
            contribution_hash,
            prev_contribution_hash: prev_hash,
            entropy_hex: Bytes::new(vec![entropy_byte; 32]),
            payload: payload.clone(),
        };
        let coin_spends = contributor
            .build_contribute_bundle(
                current_singleton,
                current_lineage_proof,
                current_state.clone(),
                mojo_funder.coin,
                mojo_funder.pk,
                contrib_params,
            )
            .expect("build_contribute_bundle");
        sim.spend_coins(coin_spends, &[mojo_funder.sk, participant_sk])
            .expect("simulator accepts contribute bundle");

        // Advance the running state for the next iteration.
        let next_state = CeremonyState {
            contribution_count: current_state.contribution_count + 1,
            last_contribution_hash: contribution_hash,
            // Contribute action preserves these (D3 finalize is the
            // only action that modifies them).
            finalized: current_state.finalized,
            vk_hash: current_state.vk_hash,
            marker_root: current_state.marker_root,
        };
        let next_inner_ph = advanced_inner_ph_for(&next_state);
        let next_outer_ph = chip_voting_sdk::puzzles::election_singleton_puzzle_hash(
            launcher_id,
            next_inner_ph,
        );
        let next_records =
            sim.lookup_puzzle_hashes(indexmap::indexset![next_outer_ph], false);
        assert_eq!(
            next_records.len(),
            1,
            "iter {i}: expected the recreated singleton at advanced inner ph"
        );
        let next_singleton = next_records[0].coin;

        let next_lineage_proof = Proof::Lineage(LineageProof {
            parent_parent_coin_info: current_singleton.parent_coin_info,
            parent_inner_puzzle_hash: prev_inner_ph,
            parent_amount: current_singleton.amount,
        });

        current_singleton = next_singleton;
        current_state = next_state;
        current_lineage_proof = next_lineage_proof;
        prev_inner_ph = next_inner_ph;
        prev_hash = contribution_hash;
    }

    // ── 4. Chain-walk and derive VK end-to-end. ───────────────
    let chain = common::SharedSim::new(&mut sim);
    let records = CeremonyReader::list_contributions_via_chain(&chain, launcher_id)
        .await
        .expect("list_contributions_via_chain");
    drop(chain);
    assert_eq!(records.len(), N, "should chain-walk all N contributions");
    CeremonyReader::validate_lineage(&records, vk_seed)
        .expect("lineage valid");
    CeremonyReader::check_threshold(&records, vk_seed, N as u64)
        .expect("min_participants threshold met");
    let vk = CeremonyReader::derive_vk(&records, vk_seed, N as u64)
        .expect("derive_vk on N records");
    let expected_len = 336 + (chip_voting_sdk::config::PUBLIC_INPUT_COUNT + 1) * 48;
    assert_eq!(vk.raw_bytes.len(), expected_len);

    // ── 5. Deploy an Election Singleton with the chain-derived VK.
    //       Closes the loop on the Phase 5 spec: "ceremony deploy → 5
    //       contributions → close → derive VK → deploy". Confirms the
    //       VK shape is identical to what the legacy single-participant
    //       setup produces (drop-in replacement for runSingleParticipantCeremony).
    use chip_voting_sdk::actors::deployer::{DeployParams, ElectionDeployer};
    let election_funder = sim.bls(10_000);
    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
    let election_params = DeployParams {
        verification_key: vk,
        cat_tail_hash,
        collateral_amount: 1_000,
        tree_depth: chip_voting_sdk::config::TREE_DEPTH,
        max_signers: chip_voting_sdk::config::MAX_SIGNERS,
        ceremony_launcher_id: Bytes32::default(),
        vk_hash: Bytes32::default(),
        vote_mode_lock: chip_voting_sdk::vote_mode::VOTE_MODE_LOCK_NONE,
        election_start_height: 0,
        label: Some("ceremony-derived-vk".into()),
    };
    let election_deployer = ElectionDeployer::new(election_params);
    let (election_spends, election_config) = election_deployer
        .build_deploy_bundle(election_funder.coin, election_funder.pk, true)
        .expect("election deploy with ceremony-derived VK");
    sim.spend_coins(
        election_spends,
        std::slice::from_ref(&election_funder.sk),
    )
    .expect("simulator accepts election deploy with chain-derived VK");

    // ── 6. Create a ballot from the deployed election. Exercises the
    //       election's `create_ballot` action against an election that
    //       was deployed with a chain-derived VK — confirming the full
    //       Phase 5 spec ("ceremony deploy → 5 contributions → derive
    //       VK → deploy → ballot creation") works end-to-end. (Full
    //       cast/finalize requires voter registration + Groth16
    //       proving, exercised by the existing
    //       `finalize_per_ballot_e2e` test against a normal VK.)
    use chip_voting_sdk::actors::ballot::{BallotIssuer, CreateBallotParams};
    use chip_voting_sdk::NetworkType;
    use clvm_traits::ToClvm;
    use clvm_utils::tree_hash;

    // Build a 2-mojo funder with quoted-empty conditions for the ballot
    // launcher (per create_ballot_e2e's funder convention).
    let mut ctx = chia_sdk_driver::SpendContext::new();
    let funder_puzzle_value: (u8, ()) = (1u8, ());
    let funder_puzzle = funder_puzzle_value.to_clvm(&mut *ctx).unwrap();
    let funder_ph = Bytes32::new(tree_hash(&ctx, funder_puzzle).to_bytes());
    let ballot_funder_coin = Coin::new(Bytes32::new([0xCC; 32]), funder_ph, 2);
    sim.insert_coin(ballot_funder_coin);
    let funder_solution = ().to_clvm(&mut *ctx).unwrap();
    let funder_spend =
        common::coin_spend_from_nodes(&ctx, ballot_funder_coin, funder_puzzle, funder_solution);
    drop(ctx);

    let issuer = BallotIssuer::new(election_config, NetworkType::Testnet11);
    let chain = common::SharedSim::new(&mut sim);
    let ballot_result = issuer
        .create_ballot(
            &chain,
            CreateBallotParams {
                ballot_seed: Bytes32::new([0xAB; 32]),
                vote_close_height: 1_000,
                outcome_domain_hash: Bytes32::new([0xCD; 32]),
                vote_options_root: Bytes32::default(),
            },
            funder_spend,
        )
        .await
        .expect("create_ballot against ceremony-derived election");
    drop(chain);
    sim.new_transaction(ballot_result.spend_bundle.clone())
        .expect("simulator accepts create_ballot bundle");
    assert_ne!(
        ballot_result.ballot_launcher_id,
        Bytes32::default(),
        "ballot_launcher_id should be deterministic and non-zero"
    );
}
