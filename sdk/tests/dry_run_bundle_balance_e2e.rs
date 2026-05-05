//! Regression: `dry_run_coin_spends` MUST detect the bundle-imbalance
//! class (MINTING_COIN consensus error) at SDK level, before broadcast.
//!
//! Failure mode this guards against (mainnet 2026-05-05 run #5): the
//! live test's `phase_create_ballot` had its 39998931-mojo XCH funder
//! spend emit `CreateCoin(SINGLETON_LAUNCHER_HASH, 2)` AND `CreateCoin(
//! funder_p2_ph, 39998929)`. The createBallot puzzle's singleton spend
//! ALSO emits `CreateCoin(SINGLETON_LAUNCHER_HASH, 2)` (with parent =
//! singleton_coin_id). That meant the bundle's total output was 2 mojos
//! greater than its total input — consensus rejected with `MINTING_COIN`.
//! `dry_run_coin_spends` (which is the SDK's last sanity check before
//! `push_tx`) didn't catch it because it only validated CLVM execution
//! per-spend, not bundle-wide accounting.
//!
//! The fix sums every CreateCoin (opcode 51) amount across every spend
//! and rejects if the total exceeds the sum of input coin amounts.
//!
//! This test constructs a deliberately imbalanced bundle (one spend
//! whose puzzle outputs MORE in CreateCoins than its input has)
//! directly via run_program and asserts `dry_run_coin_spends` returns
//! a MINTING_COIN-class error.

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chip_voting_sdk::dry_run_coin_spends;
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;
use clvmr::{serde::node_to_bytes, Allocator};

/// Build a coin spend whose puzzle returns the conditions list passed in.
/// `(q . conditions)` quotes the conditions tuple verbatim — the puzzle
/// ignores its solution and returns those conditions every time.
fn quote_conditions_spend<C>(parent: Bytes32, amount: u64, conditions: C) -> CoinSpend
where
    C: ToClvm<Allocator>,
{
    let mut allocator = Allocator::new();
    let conditions_node = conditions.to_clvm(&mut allocator).unwrap();
    let puzzle_node = (1u8, conditions_node).to_clvm(&mut allocator).unwrap();
    let puzzle_ph = Bytes32::new(tree_hash(&allocator, puzzle_node).to_bytes());
    let puzzle_program = Program::new(node_to_bytes(&allocator, puzzle_node).unwrap().into());
    let solution_node = ().to_clvm(&mut allocator).unwrap();
    let solution_program = Program::new(node_to_bytes(&allocator, solution_node).unwrap().into());
    CoinSpend::new(
        Coin::new(parent, puzzle_ph, amount),
        puzzle_program,
        solution_program,
    )
}

/// Tuple shape for a single CreateCoin condition `(51 ph amount)`.
type CreateCoinCond<'a> = (u8, (&'a Bytes32, (u64, ())));

#[test]
fn dry_run_rejects_bundle_minting_two_mojos_via_extra_create_coin() {
    // Setup that mirrors the mainnet run #5 bug:
    //   spend_a (input 10 mojos) → emits CreateCoin(target_ph, 2)
    //                                AND CreateCoin(change_ph, 8)   (= 10 out, balanced)
    //   spend_b (input 1 mojo)   → emits CreateCoin(target_ph, 2)   (= 2 out, MINT 1)
    // Bundle total: 11 in, 12 out → MINTING_COIN class.
    let target_ph = Bytes32::new([0xAA; 32]);
    let change_ph = Bytes32::new([0xBB; 32]);

    let spend_a_conditions: (CreateCoinCond<'_>, (CreateCoinCond<'_>, ())) = (
        (51, (&target_ph, (2, ()))),
        ((51, (&change_ph, (8, ()))), ()),
    );
    let spend_a = quote_conditions_spend(Bytes32::new([0xCC; 32]), 10, spend_a_conditions);

    let spend_b_conditions: (CreateCoinCond<'_>, ()) = ((51, (&target_ph, (2, ()))), ());
    let spend_b = quote_conditions_spend(Bytes32::new([0xDD; 32]), 1, spend_b_conditions);

    let result = dry_run_coin_spends(&[spend_a, spend_b]);
    let err = result.expect_err("dry_run MUST reject a bundle whose outputs exceed inputs");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("BUNDLE IMBALANCE") && msg.contains("MINTING_COIN"),
        "error must surface MINTING_COIN class with breakdown — got: {msg}"
    );
    // The error must report the actual numbers so the operator can
    // localise the imbalance immediately.
    assert!(
        msg.contains("12") && msg.contains("11"),
        "error must include in/out totals — got: {msg}"
    );
}

#[test]
fn dry_run_accepts_bundle_with_fee_input_exceeds_output() {
    // Net positive (input > output) is a fee — consensus allows it,
    // dry_run must too.
    let change_ph = Bytes32::new([0xBB; 32]);
    let conds: (CreateCoinCond<'_>, ()) = ((51, (&change_ph, (90, ()))), ());
    let spend = quote_conditions_spend(Bytes32::new([0xEE; 32]), 100, conds);
    dry_run_coin_spends(&[spend]).expect("fee-paying bundle (90 out / 100 in) MUST be accepted");
}

#[test]
fn dry_run_accepts_balanced_bundle() {
    // Exactly balanced: in == out.
    let change_ph = Bytes32::new([0xBB; 32]);
    let conds: (CreateCoinCond<'_>, ()) = ((51, (&change_ph, (100, ()))), ());
    let spend = quote_conditions_spend(Bytes32::new([0xEF; 32]), 100, conds);
    dry_run_coin_spends(&[spend]).expect("balanced bundle (100 out / 100 in) MUST be accepted");
}
