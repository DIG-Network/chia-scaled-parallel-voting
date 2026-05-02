// ============================================================================
// tests/voter_register_full_flow.rs — Voter::register against the simulator
// ============================================================================
//
// SCOPE: drives `Voter::register` with the EXACT same code path the live
// integration test uses (chain reader → wait_for_current_singleton /
// find_current_singleton lineage →
// build action layer + singleton wrap → sign).
//
// PREVIOUS DEBUGGING: the action layer + singleton outer wrap each work
// in isolation (`register_action_layer_isolated.rs`). This test exercises
// the FULL Voter::register code path so a CLVM raise here pins down the
// remaining drift between the isolated reconstruction and the SDK's
// internal assembly.

#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::type_complexity)]

mod common;

use chia_protocol::{Bytes, Bytes32, Coin};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::Simulator;
use chia_sdk_types::conditions::Conditions;
use chip_voting_sdk::actors::deployer::ElectionDeployer;
use chip_voting_sdk::ceremony::VerificationKey;
use chip_voting_sdk::config::PUBLIC_INPUT_COUNT;
use chip_voting_sdk::merkle::SparseMerkleTree;
use chip_voting_sdk::{puzzles, DeployParams, NetworkType, Voter, VoterKeys};
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;

/// WHAT: Voter::register builds a spend bundle that the simulator
///       accepts, given a real eve singleton on chain + a synthetic
///       CAT parent spend that emits the right announcement.
/// HOW:
///   1. Deploy via ElectionDeployer.deploy_signed (real eve singleton
///      lands on chain).
///   2. Synthesize a "CAT parent" coin with a quoted-conditions
///      puzzle that emits the `create_reg` announcement at the
///      expected reg_outer_ph. We use this as `cat_parent_spend`.
///   3. Wrap chain in SharedSim ChainReader.
///   4. Call `voter.register(&smt, cat_parent_spend, &chain).await`.
///   5. Submit the resulting bundle. Assert success.
/// WHY: this pins down the FULL live flow against the simulator
///      so any bug in the SDK's register pipeline surfaces locally
///      before it fails on mainnet.
#[tokio::test(flavor = "current_thread")]
async fn voter_register_against_simulator_full_flow() {
    // ── 1. Deploy ────────────────────────────────────────────
    let mut sim = Simulator::new();
    let funder = sim.bls(10_000); // odd amount > 1 so deploy creates change

    // Use the SAME params as the live mainnet test so this
    // simulator test catches drift between the two before the
    // operator has to spend real XCH to discover it.
    let cat_tail_hash = Bytes32::new(hex_literal::hex!(
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81"
    ));
    let collateral_amount: u64 = 1_000;
    let params = DeployParams {
        verification_key: VerificationKey {
            // Live test uses real ceremony VK; for the simulator we
            // can use zeros — the VK only affects the finalize
            // action's curry hash (one of 4 leaves in the merkle
            // root), and the register action doesn't reference it.
            raw_bytes: vec![0u8; 336 + (PUBLIC_INPUT_COUNT + 1) * 48],
        },
        cat_tail_hash,
        collateral_amount,
        // CHIP rev 2026-05-02: registration_fee + election_length_blocks dropped.
        election_start_height: 0,
        label: None,
    };
    let deployer = ElectionDeployer::new(params);
    let (deploy_spends, config) = deployer
        .build_deploy_bundle(funder.coin, funder.pk)
        .expect("build_deploy_bundle");
    sim.spend_coins(deploy_spends, std::slice::from_ref(&funder.sk))
        .expect("simulator accepts deploy bundle");

    let launcher_id = parse_b32(&config.election_launcher_id_hex);

    // ── 2. Build the synthetic "CAT parent" announcer coin ───
    //
    // The register action asserts an announcement with the message
    // `sha256("create_reg" || launcher_id || pk || reg_outer_ph
    //   || amount_be8)` from the cat_parent_coin (the coin id we
    // pass via the action's solution).
    //
    // We construct a quoted-conditions puzzle that emits exactly
    // that announcement, then place it on the chain so it can be
    // spent as the cat_parent_spend.
    // Seed 0x03 produces a slot whose CANONICAL CLVM u64 encoding
    // differs from the puzzle's `slot_from_pubkey` output (4 bytes
    // vs 5 bytes) — the live mainnet failure that surfaced this
    // class of bug. Pinning that seed here is the regression guard
    // that catches any future drift in the slot serialisation
    // convention between the SDK and `puzzles/election/register.rue`.
    let voter_keys = test_voter_keys(0x03u8);
    let voter_pk = voter_keys.pubkey;
    let slot = chip_voting_sdk::merkle::SparseMerkleTree::slot_for_pubkey(&voter_pk);
    eprintln!("voter slot = {} (0x{:08x})", slot, slot);
    assert!(
        slot < 0x8000_0000,
        "regression seed 0x03 must produce a high-bit-clear slot; got 0x{:08x}",
        slot
    );
    let reg_outer_ph =
        puzzles::fresh_registration_coin_puzzle_hash(cat_tail_hash, &voter_pk, launcher_id);
    let create_reg_msg =
        compute_create_reg_msg(launcher_id, &voter_pk, reg_outer_ph, collateral_amount);

    let mut ctx = SpendContext::new();
    let condition: (u8, (Bytes32, ())) = (60u8, (create_reg_msg, ()));
    let conditions_list: ((u8, (Bytes32, ())), ()) = (condition, ());
    let announcer_puzzle: (u8, ((u8, (Bytes32, ())), ())) = (1u8, conditions_list);
    let announcer_node = announcer_puzzle.to_clvm(&mut *ctx).unwrap();
    let announcer_ph = Bytes32::new(tree_hash(&ctx, announcer_node).to_bytes());
    let announcer_coin = Coin::new(Bytes32::new([0xBB; 32]), announcer_ph, 1);
    sim.insert_coin(announcer_coin);
    let announcer_solution = ().to_clvm(&mut *ctx).unwrap();
    let cat_parent_spend =
        common::coin_spend_from_nodes(&ctx, announcer_coin, announcer_node, announcer_solution);
    let _ = ctx; // we hand the spends off to Voter::register

    // ── 3. Sanity: predicted eve_ph matches what's on chain ──
    // CHIP rev 2026-05-02: compute_eve_*_puzzle_hash now takes the
    // election_start_height as a separate arg (it's no longer baked into
    // ElectionConfig). Use 0 to match the deployer's `election_start_height: 0`.
    let predicted_eve_ph =
        chip_voting_sdk::actors::aggregator::compute_eve_singleton_puzzle_hash(&config, 0);
    let predicted_inner =
        chip_voting_sdk::actors::aggregator::compute_eve_inner_puzzle_hash(&config, 0);
    let predicted_singleton = puzzles::election_singleton_puzzle_hash(launcher_id, predicted_inner);
    println!(
        "predicted eve_ph (compute_eve_singleton_puzzle_hash): {}",
        hex::encode(predicted_eve_ph)
    );
    println!("predicted inner_ph: {}", hex::encode(predicted_inner));
    println!(
        "predicted singleton via inner: {}",
        hex::encode(predicted_singleton)
    );
    println!(
        "deployer genesis_inner_puzzle_hash: {}",
        hex::encode(deployer.genesis_inner_puzzle_hash(launcher_id))
    );

    // Find the singleton coin on chain.
    let coin_records: Vec<_> = sim
        .lookup_puzzle_hashes(indexmap::indexset![predicted_eve_ph], false)
        .into_iter()
        .filter(|cs| cs.spent_height.is_none())
        .collect();
    println!("coins at predicted eve_ph: {}", coin_records.len());
    for cs in &coin_records {
        println!(
            "  coin {}, ph {}",
            hex::encode(cs.coin.coin_id()),
            hex::encode(cs.coin.puzzle_hash)
        );
    }

    // ── 4. Build voter + chain reader ─────────────────────────
    // chia_sdk_test::Simulator uses Testnet11 AGG_SIG constants;
    // Voter::register's signature must use the matching network
    // for `RequiredSignature::from_coin_spends` augmentation.
    let voter = Voter::new(config.clone(), voter_keys, NetworkType::Testnet11);
    let smt = SparseMerkleTree::new();

    let chain = common::SharedSim::new(&mut sim);
    let bundle = voter
        .register(&smt, cat_parent_spend, &chain)
        .await
        .unwrap_or_else(|e| panic!("Voter::register failed: {:?}", e));

    // Inspect what Voter::register built. The 2nd coin spend is the
    // singleton-wrapped register spend; its puzzle reveal must hash
    // to its coin's puzzle hash.
    println!("bundle has {} coin spends:", bundle.coin_spends.len());
    for (i, cs) in bundle.coin_spends.iter().enumerate() {
        let mut a = clvmr::Allocator::new();
        let prog_node = cs.puzzle_reveal.to_clvm(&mut a).unwrap();
        let actual_ph = clvm_utils::tree_hash(&a, prog_node);
        println!(
            "  spend[{i}] coin={} declared_ph={} actual_reveal_ph={}",
            hex::encode(cs.coin.coin_id()),
            hex::encode(cs.coin.puzzle_hash),
            hex::encode(actual_ph),
        );
    }

    // ── 5. Submit via the simulator's `new_transaction` path ──
    // Drop the SharedSim borrow first.
    drop(chain);
    sim.new_transaction(bundle)
        .unwrap_or_else(|e| panic!("simulator must accept Voter::register bundle; got: {:?}", e));
}

// ─── Helpers ───────────────────────────────────────────────────────

fn test_voter_keys(seed: u8) -> VoterKeys {
    use chia_bls::SecretKey;
    let sk = SecretKey::from_seed(&[seed; 32]);
    VoterKeys::new(sk)
}

fn parse_b32(hex_str: &str) -> Bytes32 {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x")).expect("hex");
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    Bytes32::new(arr)
}

fn compute_create_reg_msg(
    election_launcher_id: Bytes32,
    voter_pk: &chia_bls::PublicKey,
    reg_outer_ph: Bytes32,
    amount: u64,
) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"create_reg");
    h.update(election_launcher_id.as_ref());
    h.update(voter_pk.to_bytes());
    h.update(reg_outer_ph.as_ref());
    h.update(amount.to_be_bytes());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Bytes32::new(arr)
}

// Suppress unused-import warning when only some helpers are needed.
#[allow(dead_code)]
fn _unused() {
    let _ = Bytes::new(vec![]);
    let _: Conditions = Conditions::new();
}
