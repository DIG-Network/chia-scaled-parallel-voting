// ============================================================================
// clvm_runner.rs — direct CLVM execution helper for puzzle-correctness tests
// ============================================================================
//
// MODULE: clvm_runner (test-only)
// PURPOSE: thin layer over `chia_sdk_types::run_puzzle` that lets tests
//          load one of our compiled `.rue.hex` puzzles, allocate a
//          structured solution from typed Rust data, run the puzzle,
//          and parse the resulting condition list.
//
// SCOPE: this is a *unit-test* facility — it executes one CLVM puzzle
//        in isolation. For multi-coin spend bundles run against a
//        full Chia node fake, use `chain::SharedSimulator` +
//        `Simulator::spend_coins`.
//
// KEY PRIMITIVES used here:
//   * `chia_protocol::Program` — owns the raw CLVM bytecode loaded
//     from disk
//   * `clvmr::Allocator` + `NodePtr` — the in-memory CLVM tree
//   * `clvm_traits::ToClvm` — type → CLVM serialisation for the
//     solution
//   * `chia_sdk_types::run_puzzle` — runs the puzzle (matches the
//     consensus dialect / cost limits chia uses)
//   * `chia_sdk_types::Condition<NodePtr>` — typed view of the output
//     condition list
//
// ENABLE: the whole module is `#[cfg(test)]` because it's only useful
//         to driver tests. No production code imports from here.

#![cfg(test)]

use chia_protocol::{Bytes32, Program};
use chia_sdk_types::run_puzzle;
use clvm_traits::{FromClvm, ToClvm};
use clvmr::{
    reduction::{EvalErr, Reduction},
    Allocator, ChiaDialect, NodePtr,
};

use crate::error::{anyhow_compat, VotingError, VotingResult};

/// STRUCT: PuzzleRunner
/// PURPOSE: bundle an `Allocator` + a loaded CLVM puzzle into a tiny
///          re-usable harness. One instance per puzzle-under-test.
///
/// USAGE:
/// ```text
/// let mut r = PuzzleRunner::from_hex(REGISTRATION_RELEASE_HEX)?;
/// let conds = r.run(&truth_value)?;
/// ```
pub struct PuzzleRunner {
    pub allocator: Allocator,
    pub puzzle: NodePtr,
}

impl PuzzleRunner {
    /// FN: from_hex
    /// WHAT: parse a hex CLVM bytecode string (typically one of our
    ///       embedded `*_HEX` constants from `puzzles.rs`) into a
    ///       runnable `PuzzleRunner`.
    /// USAGE: the embedded hex constants may have a leading `0x` or
    ///        trailing whitespace from the build script — both are
    ///        tolerated.
    pub fn from_hex(hex_str: &str) -> VotingResult<Self> {
        let trimmed = hex_str.trim().trim_start_matches("0x");
        let bytes = hex::decode(trimmed).map_err(VotingError::HexDecode)?;
        let program = Program::from(bytes);
        let mut allocator = Allocator::new();
        let puzzle = node_from_program(&mut allocator, &program)?;
        Ok(Self { allocator, puzzle })
    }

    /// FN: run
    /// WHAT: serialise `solution` to CLVM, run the puzzle against it,
    ///       return the raw output `NodePtr`.
    /// CONTRACT: caller knows the output's CLVM shape and parses it
    ///           via `extract::<T>`. For the action puzzles in this
    ///           SDK the typical output is `(StateTruth, conditions)`.
    pub fn run<S>(&mut self, solution: &S) -> VotingResult<NodePtr>
    where
        S: ToClvm<Allocator>,
    {
        let solution_node = solution.to_clvm(&mut self.allocator).map_err(|e| {
            VotingError::Other(anyhow_compat::Error(
                format!("solution serialise: {e}").into(),
            ))
        })?;
        run_puzzle(&mut self.allocator, self.puzzle, solution_node)
            .map_err(eval_err_to_voting_error)
    }

    /// FN: run_expecting_failure
    /// WHAT: run the puzzle, expecting a CLVM exception.
    /// USAGE: tests that prove an invariant (`assert State.finalized
    ///        == true`, etc.) by asserting the puzzle PANICS when the
    ///        invariant is violated.
    /// RETURNS: `Ok(())` if the puzzle errored, `Err(_)` if it
    ///          unexpectedly succeeded (carrying the parsed conditions
    ///          for diagnostics).
    pub fn run_expecting_failure<S>(&mut self, solution: &S) -> Result<(), Vec<u8>>
    where
        S: ToClvm<Allocator>,
    {
        let solution_node = solution
            .to_clvm(&mut self.allocator)
            .expect("solution must serialise");
        match run_puzzle(&mut self.allocator, self.puzzle, solution_node) {
            Err(_eval_err) => Ok(()),
            Ok(out) => {
                // Round-trip the unexpected output through serialisation
                // for the failure message.
                let bytes = node_to_bytes(&self.allocator, out)
                    .unwrap_or_else(|_| b"<unparsable>".to_vec());
                Err(bytes)
            }
        }
    }

    /// FN: extract
    /// WHAT: typed extract a CLVM `NodePtr` into a Rust value via
    ///       `clvm_traits::FromClvm`.
    /// USAGE: parse the run output. E.g., for an action puzzle:
    ///        `r.extract::<(NodePtr /* truth */, Vec<Condition<NodePtr>>)>(out)?`
    pub fn extract<T>(&self, ptr: NodePtr) -> VotingResult<T>
    where
        T: FromClvm<Allocator>,
    {
        T::from_clvm(&self.allocator, ptr)
            .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("extract: {e}").into())))
    }

    /// FN: tree_hash
    /// WHAT: tree-hash an arbitrary `NodePtr` via clvm_utils.
    /// USAGE: assert the output's structural hash, e.g., for
    ///        verifying a puzzle's recreation tree hash. Currently
    ///        unused by the live tests but kept as part of the
    ///        runner's public API for future puzzle assertions.
    #[allow(dead_code)]
    pub fn tree_hash(&self, ptr: NodePtr) -> Bytes32 {
        Bytes32::new(clvm_utils::tree_hash(&self.allocator, ptr).to_bytes())
    }

    /// FN: curry_with
    /// WHAT: produce a NEW puzzle that is `self.puzzle` curried with
    ///       the given args. Replaces `self.puzzle` in place so
    ///       subsequent `.run()` calls invoke the curried form.
    /// USAGE: pass args via `clvm_traits::clvm_curried_args!(...)`
    ///        to get the proper curry envelope (the macro wraps each
    ///        arg in `(c (q . arg) <rest>)` so the user solution is
    ///        preserved as the env tail).
    /// MIRROR: identical to `chia_sdk_driver::SpendContext::curry`'s
    ///         tree-hash arithmetic; built directly via
    ///         `clvm_utils::CurriedProgram` so we don't drag the
    ///         driver's `Mod` trait into the test surface.
    /// STATUS: kept as part of the runner's public API; finalizer
    ///         tests that exercised it are deferred (they require
    ///         CHIP-0050 last_action_output shape construction —
    ///         see comments in the test module).
    #[allow(dead_code)]
    pub fn curry_with<A>(&mut self, args: A) -> VotingResult<&mut Self>
    where
        A: ToClvm<Allocator>,
    {
        let curried = clvm_utils::CurriedProgram {
            program: self.puzzle,
            args,
        }
        .to_clvm(&mut self.allocator)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("curry: {e}").into())))?;
        self.puzzle = curried;
        Ok(self)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────

fn node_from_program(allocator: &mut Allocator, program: &Program) -> VotingResult<NodePtr> {
    program
        .to_clvm(allocator)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("program load: {e}").into())))
}

fn node_to_bytes(allocator: &Allocator, node: NodePtr) -> VotingResult<Vec<u8>> {
    clvmr::serde::node_to_bytes(allocator, node)
        .map_err(|e| VotingError::Other(anyhow_compat::Error(format!("encode: {e}").into())))
}

fn eval_err_to_voting_error(e: EvalErr) -> VotingError {
    VotingError::Other(anyhow_compat::Error(format!("CLVM eval: {e}").into()))
}

// ============================================================================
// Tests
// ============================================================================
//
// CONVENTION: every test carries a WHAT / HOW / WHY block.
//
// COVERAGE GROUPS:
//   * Smoke      — runner mechanics (hex load, run + extract).
//   * Action puzzles — direct execution of the per-CHIP-rev-2026-05-02
//                       action puzzles with constructed solutions.
//
// Tests for the CHIP-rev-2026-05-02 puzzles that depend on full Ballot
// Coin / Voting Coin lineage (oracle co-spends, finalize with 6-input
// Groth16, mint_voting_coin against a per-registration ballot SPT)
// live in the higher-level `tests/` integration suite rather than this
// per-puzzle runner: their setup needs more than a single `run_puzzle`
// call. See `app/docs/superpowers/plans/2026-05-02-chip-migration.md`.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes;
    use chia_sdk_types::Condition;
    use clvm_traits::clvm_quote;

    /// WHAT: `PuzzleRunner::from_hex` successfully parses every
    ///       embedded `.rue.hex` constant in `puzzles.rs`.
    /// HOW:  call `PuzzleRunner::from_hex` on each one; reaching the
    ///       end means none of them is truncated or malformed hex.
    /// WHY:  if the build script ever ships a corrupted artefact,
    ///       every CLVM execution test below fails with a misleading
    ///       error. This smoke test pinpoints the exact failure.
    #[test]
    fn loads_every_embedded_puzzle() {
        // CHIP rev 2026-05-02: singleton lost finalize/announce/oracle
        // (moved to Ballot Coin); registration_coin's `vote` action was
        // replaced by `mint_voting_coin`. Kept constants verified below.
        use crate::puzzles::*;
        let _ = PuzzleRunner::from_hex(ACTION_LAYER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(ELECTION_FINALIZER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(ELECTION_REGISTER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(ELECTION_DEREGISTER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(ELECTION_CREATE_BALLOT_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(BALLOT_COIN_FINALIZER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(BALLOT_COIN_FINALIZE_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(BALLOT_COIN_ORACLE_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(REGISTRATION_FINALIZER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(REGISTRATION_MINT_VOTING_COIN_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(REGISTRATION_RELEASE_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(VOTING_COIN_FINALIZER_HEX).unwrap();
        let _ = PuzzleRunner::from_hex(VOTING_COIN_UPDATE_VOTE_HEX).unwrap();
    }

    /// WHAT: a quoted-nil CLVM puzzle round-trips through the
    ///       low-level `run_program` + `from_clvm` path.
    /// HOW:  build `(q . 42)` via `clvm_quote!`, run it with nil
    ///       solution, parse the output back as `i32`.
    /// WHY:  baseline check that the underlying CLVM machinery
    ///       (allocator, dialect, cost limit) is wired correctly. If
    ///       this fails, every higher-level test is meaningless.
    #[test]
    fn run_and_extract_roundtrip() {
        let mut allocator = Allocator::new();
        let puzzle = clvm_quote!(42).to_clvm(&mut allocator).unwrap();
        let solution = clvmr::Allocator::nil(&allocator);
        let Reduction(_cost, output) = clvmr::run_program(
            &mut allocator,
            &ChiaDialect::new(0),
            puzzle,
            solution,
            11_000_000_000,
        )
        .unwrap();
        let value: i32 = i32::from_clvm(&allocator, output).unwrap();
        assert_eq!(value, 42);
    }

    // ─────────────────────────────────────────────────────────────────
    // registration_coin/release action — CHIP rev 2026-05-02 shape
    // ─────────────────────────────────────────────────────────────────
    //
    // RegistrationState (post-migration) shape:
    //   `(pk . (eid . (voted_ballots_root . release_destination)))`
    // = `(Bytes /*48*/, (Bytes32, (Bytes32, ReleaseDest)))`
    //
    // `release_destination` is the trailing rest field, so the cdr of
    // the third cons IS the destination directly (no nil terminator).
    //
    // Truth shape (matches Election Truth):
    //   `(ephemeral . state)` — release writes Ephemeral_State: nil.
    //
    // Release action solution shape (per `release.rue`):
    //   `(Truth, collateral_destination, ...singleton_coin_id)`
    //   = `(Truth, (Bytes32, Bytes32))`
    // The trailing `...singleton_coin_id` makes the coin id the cdr of
    // the outer cons (no nil terminator).

    use chia_bls::PublicKey;

    // SEC-F2: state now carries `locked_weight` between `voted_ballots_root`
    // and `release_destination`:
    //   (pk . (el . (vbr . (locked_weight . release_destination))))
    type RegistrationStateClvm<R> = (Bytes, (Bytes32, (Bytes32, (u64, R))));
    /// Locked weight used by the release unit tests (matches the honest
    /// minimum collateral; the value the coin must actually hold).
    const TEST_LOCKED_WEIGHT: u64 = 1_000;
    type RegistrationStateTruthClvm<R> = ((), RegistrationStateClvm<R>);
    type ReleaseSolution<R> = (RegistrationStateTruthClvm<R>, (Bytes32, Bytes32));

    fn build_registration_state_pre_release(
        voter_pk: &PublicKey,
        election_id: Bytes32,
        voted_ballots_root: Bytes32,
    ) -> RegistrationStateClvm<()> {
        let pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
        (
            pk_bytes,
            (election_id, (voted_ballots_root, (TEST_LOCKED_WEIGHT, ()))),
        )
    }

    fn deterministic_voter() -> PublicKey {
        let sk = chia_bls::SecretKey::from_seed(&[7u8; 32]);
        sk.public_key()
    }

    /// WHAT: with a pre-release state and matching deregister args,
    ///       the release action emits exactly THREE conditions:
    ///       AssertCoinAnnouncement (the singleton's deregister
    ///       announcement), AggSigMe (the voter's release
    ///       authorisation), and AssertMyAmount (SEC-F2: the coin must
    ///       hold exactly `locked_weight`).
    /// HOW:  build a fresh registration state (release_destination =
    ///       nil), supply destination + an arbitrary singleton coin
    ///       id; run the release puzzle; assert two conditions of
    ///       the expected kinds with byte-exact messages.
    /// WHY:  these are the two conditions that bind the collateral
    ///       release to (a) the singleton's deregister action having
    ///       run in the same bundle, and (b) the voter authorising
    ///       the destination. Drift in either message format would
    ///       either lock the collateral forever (assertion mismatch)
    ///       or let an attacker hijack the collateral (sig over wrong
    ///       message).
    #[test]
    fn release_emits_assert_announcement_and_aggsigme() {
        use sha2::{Digest, Sha256};

        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let dest = Bytes32::new([0xCD; 32]);
        let voted_ballots_root = Bytes32::new([0x77; 32]);

        // Pick an arbitrary singleton_coin_id for the test — the
        // unit test only checks that the puzzle's emitted assertion
        // id matches sha256(this || deregister_message).
        let singleton_coin_id = Bytes32::new([0x42; 32]);

        let state = build_registration_state_pre_release(&voter, election_id, voted_ballots_root);
        let truth: RegistrationStateTruthClvm<()> = ((), state);
        let solution: ReleaseSolution<()> = (truth, (dest, singleton_coin_id));

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_RELEASE_HEX).unwrap();
        let output = runner.run(&solution).expect("release should execute");

        // Output: (new_truth . conditions). new_truth's
        // release_destination is now `dest`, so its R is `Bytes32`.
        // Ephemeral remains `()` (release sets Ephemeral_State: nil).
        let (_new_truth, conds): (
            RegistrationStateTruthClvm<Bytes32>,
            Vec<Condition<NodePtr>>,
        ) = runner.extract(output).expect("output parses");
        assert_eq!(
            conds.len(),
            3,
            "release emits exactly 3 conditions (incl. SEC-F2 AssertMyAmount)"
        );

        // Recompute expected deregister announcement message
        // (matches puzzles/registration_coin/release.rue):
        //   sha256("deregister" || voter_pubkey).
        let mut h = Sha256::new();
        h.update(b"deregister");
        h.update(voter.to_bytes());
        let deregister_message: [u8; 32] = h.finalize().into();
        // Compute the FULL announcement_id the puzzle emits:
        //   sha256(singleton_coin_id || deregister_message).
        let mut h = Sha256::new();
        h.update(singleton_coin_id.as_ref());
        h.update(deregister_message);
        let expected_announce: [u8; 32] = h.finalize().into();

        // Recompute expected release message (sha256("release" ||
        // election_id || voter_pubkey || destination)).
        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(voter.to_bytes());
        h.update(dest.as_ref());
        let expected_release: [u8; 32] = h.finalize().into();

        // The three conditions are AssertCoinAnnouncement + AggSigMe +
        // AssertMyAmount (SEC-F2).
        let mut saw_assert = false;
        let mut saw_sig = false;
        let mut saw_amount = false;
        for c in &conds {
            match c {
                Condition::AssertCoinAnnouncement(a) => {
                    assert_eq!(
                        a.announcement_id.as_ref(),
                        &expected_announce[..],
                        "deregister announcement id mismatch"
                    );
                    saw_assert = true;
                }
                Condition::AggSigMe(s) => {
                    assert_eq!(s.public_key, voter, "AggSigMe pubkey must be the voter");
                    assert_eq!(
                        s.message.as_ref(),
                        &expected_release[..],
                        "release message mismatch"
                    );
                    saw_sig = true;
                }
                Condition::AssertMyAmount(a) => {
                    // SEC-F2: the released coin must hold exactly the weight
                    // it claimed to lock, so a forged-weight registration
                    // cannot release more collateral than it staked.
                    assert_eq!(
                        a.amount, TEST_LOCKED_WEIGHT,
                        "AssertMyAmount must equal locked_weight"
                    );
                    saw_amount = true;
                }
                other => panic!("unexpected condition: {other:?}"),
            }
        }
        assert!(
            saw_assert && saw_sig && saw_amount,
            "expected AssertCoinAnnouncement, AggSigMe, and AssertMyAmount"
        );
    }

    /// WHAT: with a state whose `release_destination` is already set
    ///       (post-release replay attempt), the release action traps.
    /// HOW:  build a state with release_destination = `Bytes32::new([0x99; 32])`
    ///       (non-nil), run, expect a CLVM error.
    /// WHY:  `assert State.release_destination is nil` in the puzzle
    ///       prevents a registration coin from releasing twice. Pin
    ///       this so a refactor doesn't accidentally remove the guard.
    #[test]
    fn release_traps_when_already_released() {
        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let voted_ballots_root = Bytes32::new([0x77; 32]);

        // Build a post-release state (release_destination = some Bytes32).
        let pk_bytes = Bytes::new(voter.to_bytes().to_vec());
        let post_release_state: RegistrationStateClvm<Bytes32> = (
            pk_bytes,
            (
                election_id,
                (
                    voted_ballots_root,
                    (TEST_LOCKED_WEIGHT, Bytes32::new([0x99; 32])),
                ),
            ),
        );
        let truth: RegistrationStateTruthClvm<Bytes32> = ((), post_release_state);
        let solution: ReleaseSolution<Bytes32> = (
            truth,
            (
                Bytes32::new([0xCD; 32]),
                Bytes32::default(), // singleton_coin_id (unused — puzzle traps before assertion)
            ),
        );

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_RELEASE_HEX).unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("must trap when release_destination already set");
    }

    /// WHAT: with a finalized BallotState, the
    ///       `ballot_coin/announce_finalization` action recreates the
    ///       Ballot Coin unchanged and emits exactly ONE
    ///       CreateCoinAnnouncement whose message equals
    ///       `sha256("ballot_finalized" || ballot_launcher_id ||
    ///       vote_outcome || agg_signers)`.
    /// HOW:  build a finalized BallotState, wrap as Truth, curry the
    ///       puzzle with BALLOT_LAUNCHER_ID, run; parse output.
    /// WHY:  outcome-gated downstream contracts assert this exact
    ///       announcement (potentially blocks after finalize ran), so
    ///       drift would silently break those contracts.
    #[test]
    fn ballot_announce_finalization_emits_correct_announcement() {
        use clvm_traits::clvm_curried_args;
        use sha2::{Digest, Sha256};

        let ballot_launcher_id = Bytes32::new([0x33; 32]);
        let vote_outcome = Bytes32::new([0x42; 32]);
        let agg_signers = Bytes32::new([0x55; 32]);

        // BallotState: `(finalized . (vote_outcome . agg_signers))`.
        // Encoded: `(u8, (Bytes32, Bytes32))`.
        type BallotStateClvm = (u8, (Bytes32, Bytes32));
        type BallotStateTruthClvm = ((), BallotStateClvm);
        type ActionSolution = (BallotStateTruthClvm, ());

        let state: BallotStateClvm = (1u8, (vote_outcome, agg_signers));
        let truth: BallotStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        // Curry BALLOT_LAUNCHER_ID into the action puzzle.
        runner
            .curry_with(clvm_curried_args!(ballot_launcher_id))
            .unwrap();
        let output = runner.run(&solution).expect("puzzle should execute");

        let (_new_truth, conds): (BallotStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");

        assert_eq!(conds.len(), 1, "expected exactly one condition emitted");

        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        // Recompute expected message:
        //   sha256("ballot_finalized" || ballot_launcher_id ||
        //          vote_outcome || agg_signers).
        let mut h = Sha256::new();
        h.update(b"ballot_finalized");
        h.update(ballot_launcher_id.as_ref());
        h.update(vote_outcome.as_ref());
        h.update(agg_signers.as_ref());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(msg.as_ref(), &expected[..], "announcement message mismatch");
    }

    /// WHAT: with `finalized = false`, `announce_finalization` traps.
    /// HOW:  build a non-finalized BallotState, run, expect a CLVM
    ///       error.
    /// WHY:  guards against premature re-announcement before finalize
    ///       has actually run.
    #[test]
    fn ballot_announce_finalization_traps_when_not_finalized() {
        use clvm_traits::clvm_curried_args;

        let ballot_launcher_id = Bytes32::new([0x33; 32]);
        type BallotStateClvm = (u8, (Bytes32, Bytes32));
        type BallotStateTruthClvm = ((), BallotStateClvm);
        type ActionSolution = (BallotStateTruthClvm, ());

        let state: BallotStateClvm = (0u8, (Bytes32::default(), Bytes32::default()));
        let truth: BallotStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        runner
            .curry_with(clvm_curried_args!(ballot_launcher_id))
            .unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("must trap when finalized==false");
    }

    /// WHAT: with `finalized=false`, `ballot_coin/oracle` emits the
    ///       open-variant announcement
    ///       `sha256("ballot_oracle_open" || ballot_launcher_id ||
    ///       vote_close_height_be8)`.
    /// HOW:  build a not-finalized BallotState, curry with
    ///       (BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT), run; parse output.
    /// WHY:  this announcement is what `mint_voting_coin` and
    ///       `update_vote` assert to pin (ballot_id, close_height) on
    ///       chain — drift would let an attacker forge close heights.
    #[test]
    fn ballot_oracle_emits_open_announcement_when_unfinalized() {
        use clvm_traits::clvm_curried_args;
        use sha2::{Digest, Sha256};

        let ballot_launcher_id = Bytes32::new([0x33; 32]);
        let vote_close_height: u64 = 12345;
        // M4-revised: VOTE_OPTIONS_ROOT now flows through oracle's curry.
        let vote_options_root = Bytes32::new([0xEE; 32]);

        type BallotStateClvm = (u8, (Bytes32, Bytes32));
        type BallotStateTruthClvm = ((), BallotStateClvm);
        type ActionSolution = (BallotStateTruthClvm, ());

        let state: BallotStateClvm = (0u8, (Bytes32::default(), Bytes32::default()));
        let truth: BallotStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        runner
            .curry_with(clvm_curried_args!(
                ballot_launcher_id,
                vote_close_height,
                vote_options_root
            ))
            .unwrap();
        let output = runner.run(&solution).expect("puzzle should execute");

        let (_new_truth, conds): (BallotStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");
        assert_eq!(conds.len(), 1, "oracle emits exactly 1 condition");

        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        // Recompute expected message (M4-revised, 3-field preimage):
        //   sha256("ballot_oracle_open" || ballot_launcher_id ||
        //          vote_close_height_be8 || vote_options_root).
        let mut h = Sha256::new();
        h.update(b"ballot_oracle_open");
        h.update(ballot_launcher_id.as_ref());
        h.update(vote_close_height.to_be_bytes());
        h.update(vote_options_root.as_ref());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            msg.as_ref(),
            &expected[..],
            "oracle open announcement mismatch"
        );
    }

    /// WHAT: with `finalized=true`, `ballot_coin/oracle` emits the
    ///       closed-variant announcement
    ///       `sha256("ballot_oracle_closed" || ballot_launcher_id ||
    ///       vote_close_height_be8 || vote_outcome || agg_signers)`.
    /// WHY:  closed-variant prefix keeps the closed/open announcement
    ///       families distinguishable so an asserter cannot replay an
    ///       open announcement post-close.
    #[test]
    fn ballot_oracle_emits_closed_announcement_when_finalized() {
        use clvm_traits::clvm_curried_args;
        use sha2::{Digest, Sha256};

        let ballot_launcher_id = Bytes32::new([0x33; 32]);
        let vote_close_height: u64 = 12345;
        let vote_options_root = Bytes32::new([0xEE; 32]);
        let vote_outcome = Bytes32::new([0x42; 32]);
        let agg_signers = Bytes32::new([0x55; 32]);

        type BallotStateClvm = (u8, (Bytes32, Bytes32));
        type BallotStateTruthClvm = ((), BallotStateClvm);
        type ActionSolution = (BallotStateTruthClvm, ());

        let state: BallotStateClvm = (1u8, (vote_outcome, agg_signers));
        let truth: BallotStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        runner
            .curry_with(clvm_curried_args!(
                ballot_launcher_id,
                vote_close_height,
                vote_options_root
            ))
            .unwrap();
        let output = runner.run(&solution).expect("puzzle should execute");

        let (_new_truth, conds): (BallotStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");
        assert_eq!(conds.len(), 1, "oracle emits exactly 1 condition");

        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        // Recompute expected message (M4-revised, 5-field preimage):
        //   sha256("ballot_oracle_closed" || ballot_launcher_id ||
        //          vote_close_height_be8 || vote_options_root ||
        //          vote_outcome || agg_signers).
        let mut h = Sha256::new();
        h.update(b"ballot_oracle_closed");
        h.update(ballot_launcher_id.as_ref());
        h.update(vote_close_height.to_be_bytes());
        h.update(vote_options_root.as_ref());
        h.update(vote_outcome.as_ref());
        h.update(agg_signers.as_ref());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            msg.as_ref(),
            &expected[..],
            "oracle closed announcement mismatch"
        );
    }

    /// WHAT: open-variant and closed-variant oracle announcements
    ///       have distinct domain prefixes so an asserter cannot
    ///       replay one as the other.
    /// HOW:  hash the leading tags only, assert they differ.
    #[test]
    fn ballot_oracle_open_and_closed_messages_are_distinct() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ballot_oracle_open");
        let open: [u8; 32] = h.finalize().into();
        let mut h = Sha256::new();
        h.update(b"ballot_oracle_closed");
        let closed: [u8; 32] = h.finalize().into();
        assert_ne!(open, closed);
    }
}
