// ============================================================================
// puzzle_constants.rs — integration test
// ============================================================================
//
// PURPOSE: assert that every embedded `*_HEX` puzzle artefact's
//          tree-hash matches its sibling `*_HASH_HEX` constant.
//
// WHY: the SDK ships pairs of artefacts (puzzle bytecode + its tree
//      hash) that are produced together by `build.sh`. If the two
//      ever drift — e.g. a hex file is updated but its hash file is
//      stale, or vice versa — every downstream curry / coin-prediction
//      computation silently uses inconsistent inputs and the resulting
//      coins are unspendable. This test pins the consistency at the
//      bottom of the SDK's dependency graph.
//
// HOW: parse each `*_HEX` constant into a `Program`, run it through the
//      `clvm_utils::tree_hash` walker, and compare against
//      `decode_hash(*_HASH_HEX)`.

use chia_protocol::Program;
use chip_voting_sdk::puzzles::*;
use clvm_traits::ToClvm;
use clvm_utils::tree_hash;
use clvmr::Allocator;

/// Decode an embedded `_HEX` constant (whitespace-tolerant) into raw
/// CLVM bytecode bytes.
fn decode_hex_program(label: &str, hex_str: &str) -> Vec<u8> {
    let trimmed = hex_str.trim().trim_start_matches("0x");
    hex::decode(trimmed).unwrap_or_else(|e| panic!("{label}: invalid hex: {e}"))
}

/// Tree-hash an embedded `_HEX` artefact and compare to the embedded
/// `_HASH_HEX` value. Panics with a descriptive message on mismatch.
fn assert_hex_matches_hash(label: &str, hex_str: &str, hash_hex: &str) {
    let bytes = decode_hex_program(label, hex_str);
    // `chia_protocol::Program::from(Vec<u8>)` wraps the serialised
    // CLVM bytecode; `to_clvm(&mut allocator)` deserialises into a
    // `NodePtr`, and `clvm_utils::tree_hash` walks the resulting tree
    // — exactly the path used by `dry_run_coin_spends` in the SDK to
    // verify on-chain puzzle hashes against their bytecode.
    let mut allocator = Allocator::new();
    let program = Program::from(bytes);
    let node = program
        .to_clvm(&mut allocator)
        .unwrap_or_else(|e| panic!("{label}: program.to_clvm: {e}"));
    let computed = tree_hash(&allocator, node);
    let expected = decode_hash(hash_hex);
    assert_eq!(
        computed.to_bytes().as_ref(),
        expected.as_ref(),
        "{label}: tree_hash mismatch — bytecode and hash artefacts disagree",
    );
}

/// WHAT: every embedded puzzle's `*_HEX` deserialises into a CLVM
///       tree whose `tree_hash` exactly equals `decode_hash(*_HASH_HEX)`.
/// HOW:  for each artefact pair, parse the hex bytes, run them through
///       `clvm_utils::tree_hash`, and assert equality with the
///       embedded hash.
/// WHY:  pairs are produced together by `build.sh` from the same
///       source `.rue` file. If they ever drift (re-emit one without
///       the other), the SDK silently produces nonsense puzzle hashes
///       — this test surfaces that as a build-time failure rather
///       than a runtime mystery on mainnet.
#[test]
fn all_puzzle_hex_artifacts_match_their_hashes() {
    assert_hex_matches_hash("ACTION_LAYER", ACTION_LAYER_HEX, ACTION_LAYER_HASH_HEX);

    // Election Singleton
    assert_hex_matches_hash(
        "ELECTION_FINALIZER",
        ELECTION_FINALIZER_HEX,
        ELECTION_FINALIZER_HASH_HEX,
    );
    assert_hex_matches_hash(
        "ELECTION_REGISTER",
        ELECTION_REGISTER_HEX,
        ELECTION_REGISTER_HASH_HEX,
    );
    assert_hex_matches_hash(
        "ELECTION_CREATE_BALLOT",
        ELECTION_CREATE_BALLOT_HEX,
        ELECTION_CREATE_BALLOT_HASH_HEX,
    );
    assert_hex_matches_hash(
        "ELECTION_DEREGISTER",
        ELECTION_DEREGISTER_HEX,
        ELECTION_DEREGISTER_HASH_HEX,
    );

    // Ballot Coin
    assert_hex_matches_hash(
        "BALLOT_COIN_FINALIZE",
        BALLOT_COIN_FINALIZE_HEX,
        BALLOT_COIN_FINALIZE_HASH_HEX,
    );
    assert_hex_matches_hash(
        "BALLOT_COIN_ORACLE",
        BALLOT_COIN_ORACLE_HEX,
        BALLOT_COIN_ORACLE_HASH_HEX,
    );
    assert_hex_matches_hash(
        "BALLOT_COIN_ANNOUNCE_FINALIZATION",
        BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX,
        BALLOT_COIN_ANNOUNCE_FINALIZATION_HASH_HEX,
    );
    assert_hex_matches_hash(
        "BALLOT_COIN_FINALIZER",
        BALLOT_COIN_FINALIZER_HEX,
        BALLOT_COIN_FINALIZER_HASH_HEX,
    );

    // Registration Coin
    assert_hex_matches_hash(
        "REGISTRATION_FINALIZER",
        REGISTRATION_FINALIZER_HEX,
        REGISTRATION_FINALIZER_HASH_HEX,
    );
    assert_hex_matches_hash(
        "REGISTRATION_MINT_VOTING_COIN",
        REGISTRATION_MINT_VOTING_COIN_HEX,
        REGISTRATION_MINT_VOTING_COIN_HASH_HEX,
    );
    assert_hex_matches_hash(
        "REGISTRATION_RELEASE",
        REGISTRATION_RELEASE_HEX,
        REGISTRATION_RELEASE_HASH_HEX,
    );

    // Voting Coin
    assert_hex_matches_hash(
        "VOTING_COIN_UPDATE_VOTE",
        VOTING_COIN_UPDATE_VOTE_HEX,
        VOTING_COIN_UPDATE_VOTE_HASH_HEX,
    );
    assert_hex_matches_hash(
        "VOTING_COIN_FINALIZER",
        VOTING_COIN_FINALIZER_HEX,
        VOTING_COIN_FINALIZER_HASH_HEX,
    );
}
