# CHIP.md ↔ implementation 100% compliance — design

**Date:** 2026-05-04
**Owner:** michael@berkeleycompute.com
**Status:** Approved (approach 2, delete stale gap section after alignment)

## Goal

Every normative claim in `CHIP.md` (MUST / MUST NOT / SHOULD / "this revision pins" /
"MUST be present and concatenated in this exact order" / etc.) is provably enforced
by an executing test that exercises real CLVM via the simulator or `run_program`.
Every implementation divergence from spec is corrected. Lines 335-343 of `CHIP.md`
(the "Implementation alignment (this revision)" snapshot) are deleted at the end and
replaced by a one-line pointer at `docs/chip-compliance.md`.

## Non-goals

- No new product features.
- No performance work.
- No spec edits except deleting lines 335-343 and adding the pointer.
- The "Document revision: removed and changed vs. prior CHIP text" section
  (lines 345-364) stays — it is historical context for migration, not a status
  snapshot.

## Approach (chosen: option 2 — strict-normative)

`CHIP.md` is the source of truth for **normative** content (Definitions, Specification,
SPT, Circuit public inputs, Vote-message preimage, Inner-action tables for each coin
type, Security). Implementation is brought to match these.

The "Implementation alignment (this revision)" section at lines 335-343 is treated as
a dated status snapshot, not normative — and is deleted at the end of this work, so
no future drift between snapshot and reality is possible.

## Three artifacts

1. **`docs/chip-compliance.md`** — the normative-claim registry (load-bearing).
2. **`sdk/tests/chip_spec_compliance.rs`** — one integration test file holding the
   matrix's positive and negative tests. Existing e2e tests in `voter_*`,
   `create_ballot_e2e.rs`, `finalize_per_ballot_e2e.rs` etc. stay; the matrix points
   at them where they already prove a claim.
3. **`chip_md_compliance_matrix_complete`** — a CI gate test in
   `chip_spec_compliance.rs` that parses `docs/chip-compliance.md` at runtime and
   asserts:
   - every row has non-empty `impl_locus` and `positive_test`;
   - every MUST / MUST NOT row has a non-empty `negative_test`;
   - every `claim` field is a literal substring of `CHIP.md` (so spec edits force
     matrix re-alignment).

## Compliance matrix shape

`docs/chip-compliance.md` is a Markdown table:

| id | chip_md_lines | claim | category | impl_locus | positive_test | negative_test | status |
|---|---|---|---|---|---|---|---|

- `id`: stable, e.g. `SPT-LEAF-FORMAT`, `CIRCUIT-6-INPUTS`, `BALLOT-FINALIZE-CURRY`.
- `claim`: verbatim substring of `CHIP.md`.
- `category`: one of `data-layout`, `action-set`, `circuit-input`, `coin-state`,
  `lineage`, `timing`, `security-invariant`, `puzzle-curry`, `cross-coin-protocol`.
- `positive_test` / `negative_test`: fully-qualified Rust test path
  (`crate::module::fn_name`) or a citation of an existing test
  (`sdk/tests/voter_cast_vote_e2e.rs::voter_cast_vote_against_simulator_full_flow`).
- `status`: one of `aligned` / `divergent` / `untested`. Goal is `aligned` on every
  row by completion.

Granularity target: 40-60 rows. Coarser where one CLVM path naturally covers a
cluster (e.g., all six public-input scalars are bound by `finalize.rue` running a
real Groth16 proof — one row). Finer where divergence risk is real (SPT leaf format
gets its own row).

## Test taxonomy

1. **Simulator e2e** — `chia-sdk-test::Simulator`, real CAT/singleton/action wraps.
   Used for lineage, multi-spend, cross-coin protocol claims.
2. **CLVM-isolated puzzle run** — `clvmr::run_program` on the compiled `.hex` artifact
   from `puzzles/compiled/`, hand-crafted curry+solution. Used for puzzle-local
   invariants (slot derivation, leaf format, scalar encoding, threshold-pack curry
   binding). Negative tests prefer this flavor — pinpoint trap.
3. **Pure SDK property test** — Rust only, no CLVM. Used only for things `CHIP.md`
   defines purely off-chain (`vote_message` preimage byte order, Scalars canonical
   encoding, VK byte-length math). Always paired with a flavor-2 test that confirms
   on-chain agreement.

## Divergence remediation order

The audit pass produces the full divergence list before any code change. Then,
in this order to minimize cascade churn:

1. **Phase-a revert (SPT leaf format).** `CHIP.md §88-89, 143-146` says occupied leaf
   = `sha256(pubkey)` for this revision. `puzzles/election/register.rue:188-194` and
   `deregister.rue:78-82`, `sdk/src/merkle.rs`, and `aggregator.rs` callsites use
   `sha256(pubkey || COLLATERAL_AMOUNT_be8)`. Revert. Recompile puzzle hex artifacts.
   Update `puzzle_constants.rs` hash assertions. Update every test that constructs
   SPT leaves or siblings.

2. **All other divergences**, one per commit, each commit of the form
   `compliance(<claim_id>): align <area> with CHIP.md §<lines>` plus the regression
   test for that claim.

3. **Final commit:** delete `CHIP.md` lines 335-343, add a one-line pointer to
   `docs/chip-compliance.md`.

## Done criteria

All four must hold:

- `cargo test --release` in `sdk/`: every test passes, 0 ignored, total count matches
  the matrix's expected test count.
- `chip_md_compliance_matrix_complete` passes (every claim has both loci, every MUST
  has a negative test, every `claim` field is a verbatim CHIP.md substring).
- No row in `docs/chip-compliance.md` has `status != aligned`.
- `git diff CHIP.md` shows lines 335-343 removed and replaced by the pointer.

## Risks

- **Hex artifact churn.** Reverting phase a regenerates every puzzle whose curry
  transitively depends on the SPT puzzle hash. `puzzle_constants.rs` and any test
  asserting deterministic puzzle hashes will need their pinned hashes updated. This
  is bookkeeping, not a design risk, but it's bulk work and easy to miss a callsite.
- **Circuit witness alignment.** If phase a also changed the circuit's per-voter
  leaf-witness shape (e.g., consuming `locked_cat_mojos` as a witness scalar), the
  revert must also restore the circuit's leaf reconstruction to `sha256(pubkey)`.
  Audit pass must explicitly verify this in `sdk/src/prover/circuit.rs`.
- **Existing 211 tests assume the divergent leaf.** Several `voter_*_e2e.rs` tests
  build SPT siblings using the wrong leaf formula, so they pass against the
  divergent puzzle. After revert, those tests must rebuild their siblings using
  `sha256(pubkey)` — they should still pass, just against the corrected puzzle.

## Out-of-scope cleanup observations (not blockers)

`app/docs/chip-migration-gap-analysis.md:28` and
`app/docs/superpowers/plans/2026-05-02-chip-migration.md:183-186` describe leaf as
`sha256(pubkey || locked_cat_mojos_be8)`. These are migration-era documents under
`app/docs/`, not the spec. They are stale relative to CHIP.md but outside this
work's scope; flag for owner.
