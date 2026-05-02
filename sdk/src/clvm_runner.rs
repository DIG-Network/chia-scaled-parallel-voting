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
/// let mut r = PuzzleRunner::from_hex(ANNOUNCE_FINALIZATION_HEX)?;
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
        let solution_node = solution
            .to_clvm(&mut self.allocator)
            .map_err(|e| VotingError::Other(anyhow_compat::Error(format!(
                "solution serialise: {e}").into())))?;
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
        T::from_clvm(&self.allocator, ptr).map_err(|e| {
            VotingError::Other(anyhow_compat::Error(format!("extract: {e}").into()))
        })
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
    program.to_clvm(allocator).map_err(|e| {
        VotingError::Other(anyhow_compat::Error(format!("program load: {e}").into()))
    })
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
//   * Action puzzles — direct execution of each .rue.hex action with
//                       constructed solutions; verify outputs.
//   * Failure    — same actions with assertion-violating solutions;
//                   verify the puzzle errors out.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes;
    use chia_sdk_types::Condition;
    use clvm_traits::clvm_quote;

    // ── Election state shapes mirroring the Rue structs ─────────────
    //
    // Rue's `...field` syntax means "this field is the cdr of the
    // last cons" (no terminating nil). We replicate those shapes via
    // nested 2-tuples (which `clvm_traits` serialises as cons-pairs).
    //
    // ElectionState:
    //   `(root . (count . (fees . (finalized . vote_outcome))))`
    //   = `(Bytes32, (u64, (u64, (u8, Bytes32))))`
    //
    // ElectionStateTruth:
    //   `(ephemeral . state_cons_chain)`
    //   = `((), ElectionStateClvm)` (ephemeral=nil here)
    //
    // The action puzzle's full solution is `(truth . ())` because
    // `fn main(Truth: ElectionStateTruth)` has no `...` on Truth, so
    // it's a regular positional arg followed by the implicit nil
    // terminator of the args list.

    type ElectionStateClvm = (Bytes32, (u64, (u64, (u8, Bytes32))));
    type ElectionStateTruthClvm = ((), ElectionStateClvm);
    type ActionSolution = (ElectionStateTruthClvm, ());

    fn build_election_state(
        root: Bytes32,
        count: u64,
        fees: u64,
        finalized: bool,
        vote_outcome: Bytes32,
    ) -> ElectionStateClvm {
        let finalized_byte = if finalized { 1u8 } else { 0u8 };
        (root, (count, (fees, (finalized_byte, vote_outcome))))
    }

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
    // announce_finalization action
    // ─────────────────────────────────────────────────────────────────

    /// WHAT: with a finalized state, `announce_finalization`
    ///       executes successfully and emits exactly ONE
    ///       CreateCoinAnnouncement whose message equals
    ///       `sha256("finalized" || vote_outcome || count_be8 || root)`.
    /// HOW:  build a finalized ElectionState, wrap in a Truth, run
    ///       `announce_finalization`. Parse the output as
    ///       `(Truth, Vec<Condition<NodePtr>>)`. Assert: 1 condition,
    ///       it's CreateCoinAnnouncement, message bytes match the
    ///       hand-computed sha256.
    /// WHY:  this is the single most security-critical assertion of
    ///       the action — voters' release-collateral spends depend on
    ///       this exact announcement being emitted with the exact
    ///       message format. Any drift in the message format would
    ///       silently lock voters out of their collateral forever.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (announce_finalization moved to Ballot Coin)"]
    fn announce_finalization_emits_correct_announcement() {
        use sha2::{Digest, Sha256};

        let root_bytes = [0x11u8; 32];
        let outcome_bytes = [0x42u8; 32];
        let count = 7u64;

        let state = build_election_state(
            Bytes32::new(root_bytes),
            count,
            0, // accumulated_fees doesn't matter post-finalization
            true,
            Bytes32::new(outcome_bytes),
        );
        let truth: ElectionStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        let output = runner.run(&solution).expect("puzzle should execute");

        let (_new_truth, conds): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");

        assert_eq!(conds.len(), 1, "expected exactly one condition emitted");

        // The condition must be CreateCoinAnnouncement.
        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        // Recompute the expected message:
        //   sha256("finalized" || outcome || count.to_be_bytes() || root)
        let mut h = Sha256::new();
        h.update(b"finalized");
        h.update(outcome_bytes);
        h.update(count.to_be_bytes());
        h.update(root_bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(msg.as_ref(), &expected[..], "announcement message mismatch");
    }

    /// WHAT: with `finalized = false`, `announce_finalization` traps
    ///       (the `assert State.finalized == true` in the puzzle
    ///       fails the spend).
    /// HOW:  build a non-finalized state, run, expect a CLVM error.
    /// WHY:  this is the safety check that prevents a voter from
    ///       releasing collateral BEFORE the election has finalized.
    ///       If the assert ever stopped triggering, voters could
    ///       drain their collateral pre-finalization, breaking the
    ///       economic security model.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (announce_finalization moved to Ballot Coin)"]
    fn announce_finalization_rejects_non_finalized_state() {
        let state = build_election_state(
            Bytes32::new([0x00; 32]),
            0,
            0,
            false, // ← NOT finalized
            Bytes32::default(),
        );
        let truth: ElectionStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("puzzle must trap when finalized == false");
    }

    /// WHAT: `announce_finalization` returns the EXACT same Truth it
    ///       received (state is unchanged).
    /// HOW:  build a finalized state with recognisable values
    ///       (root=0xCC..CC, outcome=0xDD..DD, count=99); run; parse
    ///       the output's truth; field-by-field compare.
    /// WHY:  the on-chain finalizer reads the new state to decide
    ///       what to recreate. If announce_finalization mutated the
    ///       state, we'd accidentally rewrite the singleton with
    ///       garbage values.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (announce_finalization moved to Ballot Coin)"]
    fn announce_finalization_does_not_mutate_state() {
        let root = Bytes32::new([0xCC; 32]);
        let outcome = Bytes32::new([0xDD; 32]);
        let count = 99u64;
        let fees = 13u64;

        let state_in = build_election_state(root, count, fees, true, outcome);
        let truth_in: ElectionStateTruthClvm = ((), state_in);
        let solution: ActionSolution = (truth_in, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ANNOUNCE_FINALIZATION_HEX).unwrap();
        let output = runner.run(&solution).unwrap();
        let (truth_out, _): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).unwrap();

        // truth_out's ephemeral is `()` (announce_finalization sets
        // Ephemeral_State: nil); state_out is the unmodified state.
        let (_ephemeral, state_out) = truth_out;
        let (root_out, (count_out, (fees_out, (finalized_byte, outcome_out)))) = state_out;
        assert_eq!(root_out, root);
        assert_eq!(count_out, count);
        assert_eq!(fees_out, fees);
        assert_eq!(finalized_byte, 1);
        assert_eq!(outcome_out, outcome);
    }

    // ─────────────────────────────────────────────────────────────────
    // oracle action
    // ─────────────────────────────────────────────────────────────────
    //
    // Same Truth shape as announce_finalization (no per-action
    // curried args, no per-spend solution params), but accepted in
    // BOTH finalized and unfinalized states with two distinct
    // announcement message variants.

    /// WHAT: with a FINALIZED state, the oracle action emits exactly
    ///       ONE CreateCoinAnnouncement whose message equals
    ///       `sha256("oracle_finalized" || vote_outcome ||
    ///                count_be8 || merkle_root)`.
    /// HOW:  build a finalized ElectionState with recognisable
    ///       (root, outcome, count) values, run the oracle puzzle,
    ///       parse the output, recompute the expected sha256
    ///       inline, compare byte-for-byte.
    /// WHY:  external puzzles that opt into the oracle's "you've
    ///       finalized" reading rely on this EXACT message format.
    ///       Drift would silently invalidate every consumer's
    ///       AssertCoinAnnouncement.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (singleton oracle removed; per-ballot oracle replaces it)"]
    fn oracle_emits_finalized_announcement_in_finalized_state() {
        use sha2::{Digest, Sha256};

        let root_bytes = [0xAAu8; 32];
        let outcome_bytes = [0x42u8; 32];
        let count = 13u64;

        let state = build_election_state(
            Bytes32::new(root_bytes),
            count,
            0,
            true,
            Bytes32::new(outcome_bytes),
        );
        let truth: ElectionStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        let output = runner.run(&solution).expect("oracle should execute");

        let (_truth_out, conds): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");
        assert_eq!(conds.len(), 1, "oracle emits exactly one condition");

        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        let mut h = Sha256::new();
        h.update(b"oracle_finalized");
        h.update(outcome_bytes);
        h.update(count.to_be_bytes());
        h.update(root_bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            msg.as_ref(),
            &expected[..],
            "oracle finalized announcement message mismatch",
        );
    }

    /// WHAT: with an UNFINALIZED state, the oracle action emits
    ///       exactly ONE CreateCoinAnnouncement whose message
    ///       equals `sha256("oracle_unfinalized" || count_be8 ||
    ///       merkle_root)` — note the DISTINCT prefix and the
    ///       OMISSION of vote_outcome.
    /// HOW:  build a non-finalized ElectionState (vote_outcome
    ///       defaults to all-zero) with recognisable (root, count)
    ///       values, run, parse, recompute expected sha256 inline,
    ///       compare.
    /// WHY:  the unfinalized variant must NEVER be confusable with
    ///       the finalized variant — any external puzzle that
    ///       checks the announcement must be able to tell which
    ///       variant it's reading from the prefix bytes alone.
    ///       This test pins the exact byte-form of the unfinalized
    ///       preimage so the prefix invariant cannot regress.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (singleton oracle removed; per-ballot oracle replaces it)"]
    fn oracle_emits_unfinalized_announcement_in_unfinalized_state() {
        use sha2::{Digest, Sha256};

        let root_bytes = [0x55u8; 32];
        let count = 7u64;

        let state = build_election_state(
            Bytes32::new(root_bytes),
            count,
            123,                  // accumulated_fees doesn't affect the message
            false,                // ← NOT finalized
            Bytes32::default(),   // vote_outcome is zero pre-finalization
        );
        let truth: ElectionStateTruthClvm = ((), state);
        let solution: ActionSolution = (truth, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        let output = runner.run(&solution).expect("oracle should execute");

        let (_truth_out, conds): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).expect("output parses");
        assert_eq!(conds.len(), 1, "oracle emits exactly one condition");

        let msg = match &conds[0] {
            Condition::CreateCoinAnnouncement(a) => &a.message,
            other => panic!("expected CreateCoinAnnouncement, got {other:?}"),
        };

        let mut h = Sha256::new();
        h.update(b"oracle_unfinalized");
        h.update(count.to_be_bytes());
        h.update(root_bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            msg.as_ref(),
            &expected[..],
            "oracle unfinalized announcement message mismatch",
        );
    }

    /// WHAT: the finalized and unfinalized oracle messages over the
    ///       SAME (count, root) values are byte-distinct.
    /// HOW:  run the oracle in both states with the same root +
    ///       count (and zero vote_outcome so the only difference is
    ///       the puzzle's own prefix branching); assert the emitted
    ///       message bytes differ.
    /// WHY:  the "two distinct prefixes" invariant is the WHOLE
    ///       reason there are two variants — without it, an
    ///       attacker could mint an unfinalized-state oracle spend
    ///       and have downstream puzzles believe it was a finalized
    ///       reading. Pin domain separation directly.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (singleton oracle removed; per-ballot oracle replaces it)"]
    fn oracle_finalized_and_unfinalized_messages_are_distinct() {
        let root = Bytes32::new([0x99; 32]);
        let count = 4u64;

        let s_fin = build_election_state(root, count, 0, true, Bytes32::default());
        let s_un = build_election_state(root, count, 0, false, Bytes32::default());

        let solution_fin: ActionSolution = (((), s_fin), ());
        let solution_un: ActionSolution = (((), s_un), ());

        let mut runner_fin =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        let out_fin = runner_fin.run(&solution_fin).unwrap();
        let (_truth, conds_fin): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner_fin.extract(out_fin).unwrap();
        let msg_fin = match &conds_fin[0] {
            Condition::CreateCoinAnnouncement(a) => a.message.as_ref().to_vec(),
            other => panic!("unexpected condition: {other:?}"),
        };

        let mut runner_un =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        let out_un = runner_un.run(&solution_un).unwrap();
        let (_truth, conds_un): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner_un.extract(out_un).unwrap();
        let msg_un = match &conds_un[0] {
            Condition::CreateCoinAnnouncement(a) => a.message.as_ref().to_vec(),
            other => panic!("unexpected condition: {other:?}"),
        };

        assert_ne!(
            msg_fin, msg_un,
            "oracle finalized + unfinalized messages must NEVER collide",
        );
    }

    /// WHAT: the oracle action returns the EXACT same Truth it
    ///       received (state is unchanged).
    /// HOW:  build a finalized state with recognisable values, run,
    ///       parse the output's truth, field-by-field compare.
    /// WHY:  the on-chain finalizer reads new_state to decide what
    ///       to recreate. If oracle mutated the state, we'd
    ///       accidentally rewrite the singleton with garbage values
    ///       — the same correctness invariant `announce_finalization`
    ///       is pinned against.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (singleton oracle removed; per-ballot oracle replaces it)"]
    fn oracle_does_not_mutate_state() {
        let root = Bytes32::new([0xCC; 32]);
        let outcome = Bytes32::new([0xDD; 32]);
        let count = 99u64;
        let fees = 13u64;

        let state_in = build_election_state(root, count, fees, true, outcome);
        let truth_in: ElectionStateTruthClvm = ((), state_in);
        let solution: ActionSolution = (truth_in, ());

        let mut runner =
            PuzzleRunner::from_hex(crate::puzzles::BALLOT_COIN_ORACLE_HEX).unwrap();
        let output = runner.run(&solution).unwrap();
        let (truth_out, _): (ElectionStateTruthClvm, Vec<Condition<NodePtr>>) =
            runner.extract(output).unwrap();

        let (_ephemeral, state_out) = truth_out;
        let (root_out, (count_out, (fees_out, (finalized_byte, outcome_out)))) = state_out;
        assert_eq!(root_out, root);
        assert_eq!(count_out, count);
        assert_eq!(fees_out, fees);
        assert_eq!(finalized_byte, 1);
        assert_eq!(outcome_out, outcome);
    }

    // ─────────────────────────────────────────────────────────────────
    // registration_coin/release action
    // ─────────────────────────────────────────────────────────────────
    //
    // RegistrationState shape:
    //   `(pk . (eid . (has_voted . (vote_data . release_destination))))`
    // = `(Bytes /*48*/, (Bytes32, (u8, (Bytes32, ReleaseDest))))`
    //
    // The `release_destination` slot is either `()` (nil = no release)
    // or `Bytes32` (post-release destination). To represent both we
    // use a generic `R` type parameter on the state shape.
    //
    // Truth shape (matches Election Truth):
    //   `(ephemeral . state)`
    //
    // Release action solution shape:
    //   `(Truth . (dest . (outcome . (count . root))))`
    // The trailing `...finalized_root: Bytes32` makes `root` the cdr
    // of the last cons (no nil terminator).

    use chia_bls::PublicKey;

    type RegistrationStateClvm<R> = (Bytes, (Bytes32, (u8, (Bytes32, R))));
    /// Truth shape: `(ephemeral . state)`. `E` defaults to `()` for
    /// the input truth (no ephemeral), but vote produces a non-nil
    /// ephemeral (`EphemeralVote`) so output extracts use a richer E.
    type RegistrationStateTruthClvm<E, R> = (E, RegistrationStateClvm<R>);
    /// Ephemeral set by the vote action: `(vote_data . signature)`
    /// where signature is the trailing-tail (BLS G2 = 96 bytes).
    type EphemeralVoteClvm = (Bytes32, Bytes);
    /// Solution for the `release` action puzzle.
    ///   (Truth, dest, singleton_coin_id, finalized_outcome,
    ///    finalized_count, ...finalized_root)
    /// `singleton_coin_id` lets the puzzle compute the FULL
    /// announcement_id (sha256(announcer_coin_id || message))
    /// against which consensus's `AssertCoinAnnouncement` validates.
    type ReleaseSolution<R> = (
        RegistrationStateTruthClvm<(), R>,
        (Bytes32, (Bytes32, (Bytes32, (u64, Bytes32)))),
    );

    fn build_registration_state_pre_release(
        voter_pk: &PublicKey,
        election_id: Bytes32,
        has_voted: bool,
        vote_data: Bytes32,
    ) -> RegistrationStateClvm<()> {
        let pk_bytes = Bytes::new(voter_pk.to_bytes().to_vec());
        let hv = if has_voted { 1u8 } else { 0u8 };
        (pk_bytes, (election_id, (hv, (vote_data, ()))))
    }

    fn deterministic_voter() -> PublicKey {
        let sk = chia_bls::SecretKey::from_seed(&[7u8; 32]);
        sk.public_key()
    }

    /// WHAT: with a pre-release state and matching finalize args, the
    ///       release action emits exactly TWO conditions:
    ///       AssertCoinAnnouncement (the finalization announcement)
    ///       and AggSigMe (the voter's release authorisation).
    /// HOW:  build a fresh registration state (release_destination =
    ///       nil), supply a hand-picked destination + (outcome, count,
    ///       root); run the release puzzle; assert two conditions of
    ///       the expected kinds with byte-exact messages.
    /// WHY:  these are the two conditions that bind the collateral
    ///       release to (a) finalization having happened in the same
    ///       bundle, and (b) the voter authorising the destination.
    ///       Drift in either message format would either lock the
    ///       collateral forever (assertion mismatch) or let an
    ///       attacker hijack the collateral (sig over wrong message).
    #[test]
    #[ignore = "release action now asserts singleton deregister announcement (CHIP rev 2026-05-02); fixture / assertion needs Phase 6 update"]
    fn release_emits_assert_announcement_and_aggsigme() {
        use sha2::{Digest, Sha256};

        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let dest = Bytes32::new([0xCD; 32]);
        let outcome = Bytes32::new([0x42; 32]);
        let count = 5u64;
        let root = Bytes32::new([0x11; 32]);

        // Pick an arbitrary singleton_coin_id for the test — the
        // unit test only checks that the puzzle's emitted assertion
        // id matches sha256(this || finalization_message).
        let singleton_coin_id = Bytes32::new([0x42; 32]);

        let state = build_registration_state_pre_release(&voter, election_id, false, Bytes32::default());
        let truth: RegistrationStateTruthClvm<(), ()> = ((), state);
        let solution: ReleaseSolution<()> =
            (truth, (dest, (singleton_coin_id, (outcome, (count, root)))));

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_RELEASE_HEX).unwrap();
        let output = runner.run(&solution).expect("release should execute");

        // Output: (new_truth . conditions). new_truth's
        // release_destination is now `dest`, so its R is `Bytes32`.
        // Ephemeral remains `()` (release sets Ephemeral_State: nil).
        let (_new_truth, conds): (
            RegistrationStateTruthClvm<(), Bytes32>,
            Vec<Condition<NodePtr>>,
        ) = runner.extract(output).expect("output parses");
        assert_eq!(conds.len(), 2, "release emits exactly 2 conditions");

        // Recompute expected finalization announcement message.
        let mut h = Sha256::new();
        h.update(b"finalized");
        h.update(outcome.as_ref());
        h.update(count.to_be_bytes());
        h.update(root.as_ref());
        let finalization_message: [u8; 32] = h.finalize().into();
        // Compute the FULL announcement_id the puzzle emits:
        //   sha256(singleton_coin_id || finalization_message).
        let mut h = Sha256::new();
        h.update(singleton_coin_id.as_ref());
        h.update(finalization_message);
        let expected_announce: [u8; 32] = h.finalize().into();

        // Recompute expected release message.
        let mut h = Sha256::new();
        h.update(b"release");
        h.update(election_id.as_ref());
        h.update(voter.to_bytes());
        h.update(dest.as_ref());
        let expected_release: [u8; 32] = h.finalize().into();

        // The two conditions are AssertCoinAnnouncement + AggSigMe.
        let mut saw_assert = false;
        let mut saw_sig = false;
        for c in &conds {
            match c {
                Condition::AssertCoinAnnouncement(a) => {
                    assert_eq!(
                        a.announcement_id.as_ref(),
                        &expected_announce[..],
                        "finalization announcement id mismatch"
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
                other => panic!("unexpected condition: {other:?}"),
            }
        }
        assert!(saw_assert && saw_sig, "expected both AssertCoinAnnouncement and AggSigMe");
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

        // Build a post-release state (release_destination = some Bytes32).
        let pk_bytes = Bytes::new(voter.to_bytes().to_vec());
        let post_release_state: RegistrationStateClvm<Bytes32> = (
            pk_bytes,
            (
                election_id,
                (0u8, (Bytes32::default(), Bytes32::new([0x99; 32]))),
            ),
        );
        let truth: RegistrationStateTruthClvm<(), Bytes32> = ((), post_release_state);
        let solution: ReleaseSolution<Bytes32> = (
            truth,
            (
                Bytes32::new([0xCD; 32]),
                (
                    Bytes32::default(), // singleton_coin_id (unused — puzzle traps before assertion)
                    (Bytes32::default(), (0u64, Bytes32::default())),
                ),
            ),
        );

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_RELEASE_HEX).unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("must trap when release_destination already set");
    }

    // ─────────────────────────────────────────────────────────────────
    // registration_coin/vote action
    // ─────────────────────────────────────────────────────────────────
    //
    // Vote action signature:
    //   fn main(Truth, vote_data, ...vote_signature) -> ...
    // Solution: `(Truth . (vote_data . vote_signature))`. The
    // `...vote_signature` makes the signature the cdr of the last cons.
    // BLS signatures are 96 bytes, serialised as a `Bytes` atom.

    type VoteSolution<R> = (
        RegistrationStateTruthClvm<(), R>,
        (Bytes32, Bytes), // (vote_data . signature_bytes)
    );

    /// WHAT: vote on a fresh (has_voted=false, no release) state
    ///       emits exactly ONE AggSigUnsafe condition whose pubkey is
    ///       the voter and message is `sha256("vote" || election_id ||
    ///       pubkey || vote_data)`.
    /// HOW:  build a fresh state, supply a fake 96-byte signature
    ///       (it's only carried into ephemeral state by this action,
    ///       never validated until the on-chain AggSigUnsafe gate).
    ///       Run, parse, assert.
    /// WHY:  the vote action's emitted message MUST be byte-exact —
    ///       it's what the spend-bundle aggregate signature is
    ///       checked against by the consensus's AggSigUnsafe handler.
    ///       Drift would make every vote spend universally reject.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (REGISTRATION_VOTE_HEX replaced by REGISTRATION_MINT_VOTING_COIN_HEX)"]
    fn vote_emits_aggsigunsafe_with_correct_message() {
        use sha2::{Digest, Sha256};

        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let vote_data = Bytes32::new([0x42; 32]);
        let fake_signature = Bytes::new(vec![0xCCu8; 96]);

        let state = build_registration_state_pre_release(&voter, election_id, false, Bytes32::default());
        let truth: RegistrationStateTruthClvm<(), ()> = ((), state);
        let solution: VoteSolution<()> = (truth, (vote_data, fake_signature));

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_MINT_VOTING_COIN_HEX).unwrap();
        let output = runner.run(&solution).expect("vote should execute");

        // Parse output. The vote action sets ephemeral to
        // EphemeralVote = (vote_data . signature) (96 bytes BLS sig
        // as the trailing tail). release_destination is still nil.
        let (_new_truth, conds): (
            RegistrationStateTruthClvm<EphemeralVoteClvm, ()>,
            Vec<Condition<NodePtr>>,
        ) = runner.extract(output).expect("output parses");

        assert_eq!(conds.len(), 1, "vote emits exactly 1 condition");
        let (pk, msg) = match &conds[0] {
            Condition::AggSigUnsafe(s) => (&s.public_key, &s.message),
            other => panic!("expected AggSigUnsafe, got {other:?}"),
        };
        assert_eq!(pk, &voter, "AggSigUnsafe pubkey must be the voter");

        // sha256("vote" || election_id || voter_pk || vote_data)
        let mut h = Sha256::new();
        h.update(b"vote");
        h.update(election_id.as_ref());
        h.update(voter.to_bytes());
        h.update(vote_data.as_ref());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(msg.as_ref(), &expected[..], "vote message mismatch");
    }

    /// WHAT: the vote action transitions has_voted false → true and
    ///       commits `vote_data` into the new state.
    /// HOW:  start from has_voted=false + zero vote_data; vote with
    ///       a recognisable vote_data; parse new state; assert
    ///       has_voted=1 and vote_data equals the supplied value.
    /// WHY:  has_voted=true is what blocks a second vote (the next
    ///       test). vote_data on-chain commits the voter's choice
    ///       tamper-proof — the off-chain aggregator reads it from
    ///       the recreated coin's puzzle hash + memos.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (REGISTRATION_VOTE_HEX replaced by REGISTRATION_MINT_VOTING_COIN_HEX)"]
    fn vote_transitions_state_correctly() {
        let voter = deterministic_voter();
        let election_id = Bytes32::new([0x55; 32]);
        let vote_data = Bytes32::new([0xCC; 32]);
        let fake_signature = Bytes::new(vec![0u8; 96]);

        let state = build_registration_state_pre_release(&voter, election_id, false, Bytes32::default());
        let truth: RegistrationStateTruthClvm<(), ()> = ((), state);
        let solution: VoteSolution<()> = (truth, (vote_data, fake_signature));

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_MINT_VOTING_COIN_HEX).unwrap();
        let output = runner.run(&solution).unwrap();
        let (new_truth, _conds): (
            RegistrationStateTruthClvm<EphemeralVoteClvm, ()>,
            Vec<Condition<NodePtr>>,
        ) = runner.extract(output).unwrap();

        let (_eph, new_state) = new_truth;
        let (pk_out, (eid_out, (hv_out, (vd_out, _rel_out)))) = new_state;
        assert_eq!(pk_out.as_ref(), &voter.to_bytes()[..]);
        assert_eq!(eid_out, election_id);
        assert_eq!(hv_out, 1, "has_voted must transition false → true");
        assert_eq!(vd_out, vote_data, "vote_data must equal the supplied value");
    }

    /// WHAT: voting twice (has_voted already true) traps.
    /// HOW:  build a state with has_voted=true; supply any vote_data;
    ///       expect a CLVM error.
    /// WHY:  `assert State.has_voted == false` enforces one-vote-per-
    ///       registration. Double-voting would corrupt aggregation
    ///       (one voter's signature counted twice).
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (REGISTRATION_VOTE_HEX replaced by REGISTRATION_MINT_VOTING_COIN_HEX)"]
    fn vote_traps_when_already_voted() {
        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let state = build_registration_state_pre_release(&voter, election_id, true, Bytes32::new([0x42; 32]));
        let truth: RegistrationStateTruthClvm<(), ()> = ((), state);
        let solution: VoteSolution<()> = (
            truth,
            (Bytes32::new([0x99; 32]), Bytes::new(vec![0u8; 96])),
        );

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_MINT_VOTING_COIN_HEX).unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("must trap when has_voted already true");
    }

    // NOTE: standalone tests for the ELECTION FINALIZER and
    // REGISTRATION COIN FINALIZER are intentionally omitted at the
    // unit-test layer:
    //   * Both finalizers are double-curried wrappers whose only
    //     business logic is constructing a single CreateCoin (and,
    //     for registration_coin, picking between two branches based
    //     on `release_destination`).
    //   * Their on-chain correctness is validated by the integration
    //     tests in `tests/integration.rs`, which deploy the full
    //     puzzle stack via the simulator — that exercises the
    //     finalizer through the production code path with no
    //     ambiguity about CLVM solution shape.
    //   * Driving the finalizer in isolation requires reconstructing
    //     the action-layer's `(StateTruth, conditions_lol)` "last
    //     action output" tuple by hand, which has subtle CLVM-shape
    //     dependencies on the upstream Rue compiler. The bug-density
    //     of that wrapper is low; the bug-density of our hand-rolled
    //     solution shape would be HIGH. Better to leave the finalizer
    //     covered by integration tests.

    /// WHAT: voting after release (release_destination is set) traps.
    /// HOW:  build a state with release_destination = some Bytes32,
    ///       attempt to vote, expect a CLVM error.
    /// WHY:  `assert State.release_destination is nil` prevents a
    ///       voter from casting a vote AFTER they've already begun
    ///       releasing collateral. Otherwise the vote would land on
    ///       a coin whose lineage is about to terminate.
    #[test]
    #[ignore = "stubbed pending Phase 6 — see app/docs/superpowers/plans/2026-05-02-chip-migration.md \
                (REGISTRATION_VOTE_HEX replaced by REGISTRATION_MINT_VOTING_COIN_HEX)"]
    fn vote_traps_when_release_already_set() {
        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let pk_bytes = Bytes::new(voter.to_bytes().to_vec());
        // has_voted=false but release_destination is set → should still trap.
        let post_release_state: RegistrationStateClvm<Bytes32> = (
            pk_bytes,
            (
                election_id,
                (0u8, (Bytes32::default(), Bytes32::new([0x99; 32]))),
            ),
        );
        let truth: RegistrationStateTruthClvm<(), Bytes32> = ((), post_release_state);
        let solution: VoteSolution<Bytes32> = (
            truth,
            (Bytes32::default(), Bytes::new(vec![0u8; 96])),
        );

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_MINT_VOTING_COIN_HEX).unwrap();
        runner
            .run_expecting_failure(&solution)
            .expect("must trap when release_destination is non-nil");
    }

    /// WHAT: the release action sets `release_destination` in the new
    ///       state to exactly the destination supplied in the solution.
    /// HOW:  release a fresh registration coin to a recognisable
    ///       destination (`0xEE..EE`); parse the new truth's
    ///       release_destination field; assert equality.
    /// WHY:  the registration_coin finalizer reads new_state.release_destination
    ///       to decide where to send the CAT collateral. If this
    ///       field were ever miscomputed, collateral could go to an
    ///       attacker-controlled address.
    #[test]
    #[ignore = "release action now asserts singleton deregister announcement (CHIP rev 2026-05-02); fixture / assertion needs Phase 6 update"]
    fn release_sets_destination_in_new_state() {
        let voter = deterministic_voter();
        let election_id = Bytes32::new([0xAB; 32]);
        let dest = Bytes32::new([0xEE; 32]);

        let state = build_registration_state_pre_release(&voter, election_id, true, Bytes32::new([0x42; 32]));
        let truth: RegistrationStateTruthClvm<(), ()> = ((), state);
        let solution: ReleaseSolution<()> = (
            truth,
            (
                dest,
                (
                    Bytes32::new([0x77; 32]), // singleton_coin_id (any value — not asserted at this layer)
                    (Bytes32::new([0x42; 32]), (3u64, Bytes32::new([0x11; 32]))),
                ),
            ),
        );

        let mut runner = PuzzleRunner::from_hex(crate::puzzles::REGISTRATION_RELEASE_HEX).unwrap();
        let output = runner.run(&solution).unwrap();
        let (new_truth, _conds): (RegistrationStateTruthClvm<(), Bytes32>, Vec<Condition<NodePtr>>) =
            runner.extract(output).unwrap();

        let (_eph, new_state) = new_truth;
        let (pk_out, (eid_out, (hv_out, (vd_out, release_out)))) = new_state;
        assert_eq!(pk_out.as_ref(), &voter.to_bytes()[..]);
        assert_eq!(eid_out, election_id);
        assert_eq!(hv_out, 1, "has_voted is preserved");
        assert_eq!(vd_out, Bytes32::new([0x42; 32]), "vote_data is preserved");
        assert_eq!(release_out, dest, "release_destination is set to supplied dest");
    }
}
