# CHIP.md ↔ implementation 100% compliance — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the chip-voting-sdk implementation into 100% compliance with the
normative content of `CHIP.md`, with simulator + CLVM-executing tests proving each
normative claim, and delete the now-stale "Implementation alignment (this revision)"
status snapshot from `CHIP.md`.

**Architecture:** Three artifacts: (1) a normative-claim registry at
`docs/chip-compliance.md`; (2) a single integration test file
`sdk/tests/chip_spec_compliance.rs` that pairs every claim row with positive +
(for MUST) negative tests, executing real CLVM via `chia-sdk-test::Simulator` or
`clvmr::run_program` on compiled puzzle hex; (3) a CI gate test
`chip_md_compliance_matrix_complete` that parses the registry at runtime and
asserts every row links to existing tests, every MUST has a negative test, and
every claim is a verbatim substring of `CHIP.md`. Implementation divergences
(known: SPT leaf format) are remediated commit-per-divergence.

**Tech Stack:** Rust (chip-voting-sdk), `.rue` puzzles compiled to CLVM hex,
`chia-sdk-test::Simulator` for e2e, `clvmr::run_program` for puzzle-isolated runs.

---

## Phase A — Build the compliance matrix (audit pass)

### Task A1: Scaffold registry file with the schema header

**Files:**
- Create: `docs/chip-compliance.md`

- [ ] **Step 1: Write the registry header and empty table**

````markdown
# CHIP.md compliance matrix

> **Source of truth:** [`CHIP.md`](../CHIP.md). Every `claim` field below MUST be a
> verbatim substring of `CHIP.md`. Every row MUST link to a positive test that
> exercises real CLVM via the simulator or `clvmr::run_program`. Every row whose
> normative force is MUST or MUST NOT MUST link to a negative test. The CI gate
> `chip_md_compliance_matrix_complete` enforces these rules at every test run.

| id | chip_md_lines | claim | category | impl_locus | positive_test | negative_test | status |
|---|---|---|---|---|---|---|---|
````

- [ ] **Step 2: Commit**

```bash
git add docs/chip-compliance.md
git commit -m "compliance: scaffold normative-claim registry"
```

### Task A2: Walk CHIP.md sections and emit one row per normative claim

**Approach for each section:** read the section, extract every sentence containing
`MUST`, `MUST NOT`, `SHALL`, `SHALL NOT`, `pinned`, `pins`, `MUST be`, "exact
order", "fixed", or a forward-compatibility / present-tense structural assertion
("Occupied leaf:", "VK byte length is therefore fixed at"). For each, append a
row to the matrix. Reference line numbers in column 2 (`chip_md_lines`).

**Files:**
- Modify: `docs/chip-compliance.md`

The sections to walk, in order, with the claim categories likely to surface:

1. **Definitions (lines 73-97)** — coin-state shapes, SPT structure, leaf format,
   internal-node hash, slot derivation, lineage three-link chain.
2. **Sparse Merkle Tree (lines 139-146)** — depth=32, slot, occupied leaf, empty
   leaf, internal-node hash.
3. **Circuit public inputs (lines 148-159)** — exactly 6 scalars, exact order, IC
   layout, VK byte length = 672.
4. **Vote message preimage (lines 161-174)** — `sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`,
   that exact order, all three components present.
5. **Election Singleton actions (lines 187-208)** — only `register | createBallot |
   deregister`, no `finalize` / `announce_finalization` / `oracle` / `vote` /
   `change_vote`, no `REGISTRATION_FEE`.
6. **Ballot Coin (lines 211-253)** — state shape, finalize curry, oracle curry,
   announce_finalization curry, the rationale for both `oracle` and
   `announce_finalization` existing.
7. **Registration Coin (lines 256-272)** — state shape (no `has_voted`, no
   `vote_data`), `mint_voting_coin` non-membership proof + insertion, `release`
   asserts singleton's `deregister` announcement.
8. **Voting Coin (lines 274-285)** — state shape, `update_vote` co-spends Ballot
   Coin oracle, BLS memo over `vote_message`.
9. **Full data flow (lines 287-298)** — never spends election singleton during
   vote/finalize.
10. **Security (lines 311-331)** — single-vote-per-ballot via SPT non-membership,
    `bls_verify` + Groth16 binding, threshold-pack on-chain assertion,
    per-ballot `vote_close_height`.

For each emitted row at this stage:
- `impl_locus` may be `?` (filled by Task A3).
- `positive_test` and `negative_test` may be `?` (filled by Task A4).
- `status` defaults to `untested`.

- [ ] **Step 1: Open `CHIP.md` and emit rows for sections 1-3**

Append rows to `docs/chip-compliance.md`. Example skeleton for the SPT leaf row
(this row is fully concrete because the divergence is known):

```markdown
| SPT-LEAF-FORMAT | 88-91 | Occupied leaf: `sha256(pubkey)` | data-layout | puzzles/election/register.rue:188-194; sdk/src/merkle.rs::occupied_leaf | ? | ? | divergent |
| SPT-EMPTY-LEAF | 90 | EMPTY_LEAF_HASH = sha256(0x00 × 48) | data-layout | sdk/src/config.rs::EMPTY_LEAF_HASH | ? | ? | untested |
| SPT-INTERNAL-NODE | 91 | plain `sha256(left \|\| right)` (no CLVM tree-hash prefix) | data-layout | sdk/src/merkle.rs::sha256_concat; puzzles/election/register.rue::compute_root | ? | ? | untested |
| SPT-SLOT | 88 | `u32::from_be_bytes(sha256(pubkey)[0..4])` | data-layout | sdk/src/actors/voter.rs::slot_from_pubkey; puzzles/election/register.rue | ? | ? | untested |
| SPT-DEPTH | 87, 144 | Fixed depth 32 | data-layout | sdk/src/config.rs::TREE_DEPTH | ? | ? | untested |
```

- [ ] **Step 2: Emit rows for sections 4-6**

Vote message preimage, Election Singleton actions, Ballot Coin curries.

- [ ] **Step 3: Emit rows for sections 7-10**

Registration / Voting Coin invariants, full data flow, Security section.

- [ ] **Step 4: Verify count**

Aim for 40-60 rows. If under 40, sections were under-walked. If over 60, granularity
is too fine — coalesce rows that one CLVM execution naturally proves together
(e.g., all 6 public-input scalars belong to one row "circuit public inputs ordered
correctly," because `finalize.rue` running a real Groth16 proof binds all six at
once).

- [ ] **Step 5: Commit**

```bash
git add docs/chip-compliance.md
git commit -m "compliance: enumerate normative claims from CHIP.md"
```

### Task A3: Fill `impl_locus` for every row

For each row, search the implementation for the file:line range where the claim
is enforced. Use Grep on canonical identifiers (`EMPTY_LEAF_HASH`, `MAX_SIGNERS`,
`PUBLIC_INPUT_COUNT`, action names, struct field names). When a claim is enforced
across multiple files (e.g., SPT leaf format is in both Rust and `.rue`), list
both, semicolon-separated.

**Files:**
- Modify: `docs/chip-compliance.md`

- [ ] **Step 1: Sweep Rust loci**

```bash
# Examples — each row gets its own grep pass
rg -n 'EMPTY_LEAF_HASH' sdk/src/
rg -n 'MAX_SIGNERS' sdk/src/
rg -n 'PUBLIC_INPUT_COUNT' sdk/src/
rg -n 'fn slot' sdk/src/actors/voter.rs
```

For each, write the resulting `path:line_range` into the matching row's
`impl_locus`.

- [ ] **Step 2: Sweep `.rue` loci**

```bash
rg -n 'sha256\(pubkey' puzzles/
rg -n 'compute_root' puzzles/
rg -n 'createBallot' puzzles/
```

- [ ] **Step 3: Mark `impl_locus = MISSING` for any row whose locus cannot be found**

A `MISSING` here means the spec claim is **not** implemented. This is a hard
divergence. Status becomes `divergent`.

- [ ] **Step 4: Commit**

```bash
git add docs/chip-compliance.md
git commit -m "compliance: link impl_locus for every claim row"
```

### Task A4: Fill `positive_test` and `negative_test` from existing tests

For each row, search the existing test files for code that exercises the claim.

**Files:**
- Modify: `docs/chip-compliance.md`

- [ ] **Step 1: Sweep existing tests for each claim**

```bash
rg -n 'EMPTY_LEAF_HASH' sdk/tests/
rg -n 'create_ballot' sdk/tests/
rg -n 'finalize' sdk/tests/
rg -n 'update_vote' sdk/tests/
rg -n 'mint_voting_coin' sdk/tests/
```

For each match, decide whether the test **actively** exercises the claim — i.e.,
would the test fail if the implementation stopped enforcing the claim? If yes,
write `sdk/tests/<file>.rs::<fn_name>` into `positive_test`.

- [ ] **Step 2: Identify negative test gaps**

For every row whose category in `CHIP.md` is MUST or MUST NOT (i.e., the verb
"MUST" or "MUST NOT" appears in the cited line range), check whether a test
constructs a bundle violating the claim and asserts the simulator/CLVM rejects
it. If yes, fill `negative_test`. If no, leave `negative_test = MISSING` and set
`status = untested`.

- [ ] **Step 3: Commit**

```bash
git add docs/chip-compliance.md
git commit -m "compliance: cross-walk existing tests; mark MISSING gaps"
```

### Task A5: Produce divergence and gap worklists

**Files:**
- Create: `docs/chip-compliance-worklist.md`

- [ ] **Step 1: Generate the divergence worklist**

```bash
# Filter rows where status == divergent
awk -F'|' '/divergent/ { print $2, $3 }' docs/chip-compliance.md > /tmp/divergent.txt
cat /tmp/divergent.txt
```

For each row, append to `docs/chip-compliance-worklist.md`:

```markdown
## Divergences (implementation must change)

- **<id>** (CHIP.md §<lines>): <claim>
  - Implementation: <impl_locus>
  - Required change: <one-line description>
```

- [ ] **Step 2: Generate the test-gap worklist**

For each row where `status = untested` (positive or negative test missing),
append:

```markdown
## Test gaps (test must be added)

- **<id>** (CHIP.md §<lines>): <claim>
  - Implementation locus: <impl_locus>
  - Missing: positive / negative / both
  - Test plan: <one-line — what construction proves this?>
```

- [ ] **Step 3: Commit**

```bash
git add docs/chip-compliance-worklist.md
git commit -m "compliance: produce divergence + test-gap worklists"
```

---

## Phase B — Phase-a revert: SPT leaf format `sha256(pubkey)`

This is the one fully-known divergence. CHIP.md §88-89, 143-146 says occupied
leaf = `sha256(pubkey)` for this revision. Implementation has
`sha256(pubkey || locked_cat_mojos_be8)` (introduced by commit `1f7f96e`, which
miscited CHIP.md). Revert.

### Task B1: Negative test first — assert spec-violating leaf is rejected

**Files:**
- Create: `sdk/tests/chip_spec_compliance.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! CHIP.md compliance suite. Each test cites the CHIP.md line range of the
//! normative claim it enforces. The CI gate
//! `chip_md_compliance_matrix_complete` (in this same file) ensures the matrix
//! at `docs/chip-compliance.md` stays in sync with both spec and tests.

mod common;

use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};

/// CHIP.md §88-89: Occupied leaf: `sha256(pubkey)`.
///
/// Negative test: an SPT membership witness whose leaf is
/// `sha256(pubkey || locked_cat_mojos_be8)` (the prior implementation's leaf
/// formula) MUST be rejected by `register.rue`.
#[test]
fn chip_spt_leaf_format_rejects_appended_weight_leaf() {
    use clvmr::Allocator;
    // Construct a register-action curry with EMPTY root.
    // Build a witness using leaf = sha256(pubkey || COLLATERAL_AMOUNT.to_be_bytes())
    // (the prior, divergent formula). Run the action. Expect CLVM trap on the
    // root-mismatch assertion in compute_root.
    //
    // Test details follow the pattern in tests/register_action_e2e.rs::register_rejects_wrong_slot_index.

    // ... (full test code in execution; this stub fixes the function name and
    //      pinning so the matrix CI gate has a stable target).
    panic!("not yet implemented — Task B3 fills body");
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd sdk && cargo test --test chip_spec_compliance chip_spt_leaf_format_rejects_appended_weight_leaf
```

Expected: FAIL with "not yet implemented".

- [ ] **Step 3: Commit**

```bash
git add sdk/tests/chip_spec_compliance.rs
git commit -m "compliance(SPT-LEAF-FORMAT): pin negative test (red)"
```

### Task B2: Update the puzzle source `register.rue` to spec leaf

**Files:**
- Modify: `puzzles/election/register.rue` (lines around the `compute_root` /
  leaf construction; located by Grep `sha256(pubkey || locked_cat_mojos_be8)`)
- Modify: `puzzles/election/deregister.rue` (lines around the matching leaf).

- [ ] **Step 1: Read the current `register.rue`**

```bash
rg -n 'locked_cat_mojos_be8' puzzles/election/register.rue
```

- [ ] **Step 2: Replace leaf computation**

For each leaf-construction site, change

```clvm
let leaf = sha256(concat(pubkey, locked_cat_mojos_be8))
```

(or its `.rue` syntactic equivalent) to

```clvm
let leaf = sha256(pubkey)
```

Comments referencing CHIP.md must also be corrected to cite the new line range
and the spec quote.

- [ ] **Step 3: Repeat for `deregister.rue`**

Same change.

- [ ] **Step 4: Recompile to hex**

```bash
cd puzzles && rue build --all
```

Expected: `puzzles/compiled/election/register.hex` and `register.hash` (and
`deregister.*`) update on disk.

- [ ] **Step 5: Commit**

```bash
git add puzzles/election/register.rue puzzles/election/deregister.rue puzzles/compiled/election/
git commit -m "compliance(SPT-LEAF-FORMAT): align register/deregister leaf to sha256(pubkey)"
```

### Task B3: Update SDK Merkle helpers

**Files:**
- Modify: `sdk/src/merkle.rs` (functions `occupied_leaf`, doc comments at lines
  71, 146, 281)
- Modify: `sdk/src/actors/aggregator.rs` (comments + any leaf-rebuild code at
  lines 715, 1278, 1315; locate via `rg -n 'COLLATERAL_AMOUNT_be8' sdk/src/`)
- Modify: `sdk/src/actors/voter.rs` (any leaf-rebuild for siblings construction)
- Modify: `sdk/src/actors/deployer.rs` (any leaf-rebuild for genesis)

- [ ] **Step 1: Read current `occupied_leaf`**

```bash
rg -n 'fn occupied_leaf|locked_cat_mojos' sdk/src/
```

- [ ] **Step 2: Replace `occupied_leaf` body**

```rust
/// CHIP.md §88-89: occupied leaf = `sha256(pubkey)`. Per-voter weight is tracked
/// on Election Singleton state, NOT in the leaf, in this revision.
pub fn occupied_leaf(pubkey: &PublicKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey.to_bytes());
    h.finalize().into()
}
```

- [ ] **Step 3: Remove the `locked_cat_mojos` parameter at every call site**

Compile errors will guide the sweep. Every caller of `occupied_leaf` will need
its `locked_cat_mojos` argument removed. If a caller previously plumbed
`COLLATERAL_AMOUNT.to_be_bytes()` into the leaf, that plumbing is now dead and
must be removed.

- [ ] **Step 4: Update doc comments to cite spec**

Replace stale doc comments referencing the old leaf formula with the spec quote
plus line citation.

- [ ] **Step 5: Run `cargo check`**

```bash
cd sdk && cargo check --tests
```

Fix all compile errors by removing the `locked_cat_mojos` argument from each
call site.

- [ ] **Step 6: Commit**

```bash
git add sdk/src/
git commit -m "compliance(SPT-LEAF-FORMAT): align SDK Merkle helpers to sha256(pubkey)"
```

### Task B4: Update `puzzle_constants.rs` pinned hashes

**Files:**
- Modify: `sdk/tests/puzzle_constants.rs`

- [ ] **Step 1: Run the constants test, observe new expected hashes**

```bash
cd sdk && cargo test --test puzzle_constants 2>&1 | tail -40
```

The test will fail with a hash mismatch for `register.rue.hash` and
`deregister.rue.hash`. The output prints the actual hash.

- [ ] **Step 2: Update the pinned constants**

Replace the old hashes in `puzzle_constants.rs` with the actual hashes printed
by the failing test. Add a comment citing CHIP.md §88-91.

- [ ] **Step 3: Re-run constants test**

```bash
cd sdk && cargo test --test puzzle_constants
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add sdk/tests/puzzle_constants.rs
git commit -m "compliance(SPT-LEAF-FORMAT): update pinned puzzle hashes"
```

### Task B5: Update existing e2e tests' SPT siblings

**Files:**
- Modify: `sdk/tests/voter_register_full_flow.rs`
- Modify: `sdk/tests/register_action_e2e.rs`
- Modify: `sdk/tests/voter_cast_vote_e2e.rs`
- Modify: `sdk/tests/voter_revote_e2e.rs`
- Modify: `sdk/tests/voter_release_collateral_e2e.rs`
- Modify: `sdk/tests/finalize_per_ballot_e2e.rs`

- [ ] **Step 1: Run each e2e**

```bash
cd sdk && cargo test --test voter_register_full_flow 2>&1 | tail -20
```

Each test will fail at the SPT root assertion because it built siblings using
the divergent leaf.

- [ ] **Step 2: Replace local leaf computations in the test helper**

In each test that contains `sha256_pubkey_collateral` or similar local
leaf-builder, replace with the spec leaf. If tests use `merkle::occupied_leaf`,
the SDK fix from Task B3 carries through.

- [ ] **Step 3: Re-run all e2e tests**

```bash
cd sdk && cargo test --release
```

Expected: all 211 (now 211 + 1 new from Task B1) pass.

- [ ] **Step 4: Commit**

```bash
git add sdk/tests/
git commit -m "compliance(SPT-LEAF-FORMAT): update e2e siblings to spec leaf"
```

### Task B6: Fill the negative test body, run green

**Files:**
- Modify: `sdk/tests/chip_spec_compliance.rs`

- [ ] **Step 1: Replace the `panic!` stub with the real test body**

```rust
#[test]
fn chip_spt_leaf_format_rejects_appended_weight_leaf() {
    use clvmr::{Allocator, run_program, NodePtr, ChiaDialect};
    use chia_bls::PublicKey;
    use sha2::{Digest, Sha256};

    let mut allocator = Allocator::new();
    let pubkey = test_voter_keys(0).public;

    // Build the wrong leaf the prior implementation would have used.
    let mut wrong_leaf = Sha256::new();
    wrong_leaf.update(pubkey.to_bytes());
    wrong_leaf.update(crate::common::COLLATERAL_AMOUNT.to_be_bytes());
    let wrong_leaf: [u8; 32] = wrong_leaf.finalize().into();

    // Build a register action curry with EMPTY root and a witness whose siblings
    // are correct for `wrong_leaf` (32 zero leaves at all levels except where
    // `wrong_leaf` is inserted at the slot-derived index).
    let curry_args = build_register_curry(EMPTY_REGISTRATION_ROOT);
    let solution = build_register_solution_with_leaf(&pubkey, wrong_leaf);
    let result = run_program(
        &mut allocator,
        &ChiaDialect::default(),
        load_register_program(&mut allocator),
        build_solution_node(&mut allocator, &curry_args, &solution),
        usize::MAX,
    );
    assert!(result.is_err(), "spec-violating leaf was accepted by register.rue");
}
```

- [ ] **Step 2: Run**

```bash
cd sdk && cargo test --test chip_spec_compliance chip_spt_leaf_format_rejects_appended_weight_leaf
```

Expected: PASS (CLVM rejects).

- [ ] **Step 3: Add the positive test**

```rust
/// CHIP.md §88-89: positive — `sha256(pubkey)` is accepted.
#[test]
fn chip_spt_leaf_format_accepts_spec_leaf() {
    use sha2::{Digest, Sha256};
    let pubkey = test_voter_keys(0).public;
    let mut h = Sha256::new();
    h.update(pubkey.to_bytes());
    let spec_leaf: [u8; 32] = h.finalize().into();
    // Build curry+solution with `spec_leaf` inserted at slot.
    // Run register.rue. Assert the run succeeds and the recreated singleton
    // state's `registration_merkle_root` equals the expected post-insert root.
    let result = run_register_with_leaf(&pubkey, spec_leaf);
    assert!(result.is_ok());
}
```

- [ ] **Step 4: Run both**

```bash
cd sdk && cargo test --test chip_spec_compliance chip_spt_leaf_format
```

Expected: both pass.

- [ ] **Step 5: Update matrix row**

In `docs/chip-compliance.md`, update the SPT-LEAF-FORMAT row:

```markdown
| SPT-LEAF-FORMAT | 88-91 | Occupied leaf: `sha256(pubkey)` | data-layout | puzzles/election/register.rue:188-194; sdk/src/merkle.rs::occupied_leaf | sdk/tests/chip_spec_compliance.rs::chip_spt_leaf_format_accepts_spec_leaf | sdk/tests/chip_spec_compliance.rs::chip_spt_leaf_format_rejects_appended_weight_leaf | aligned |
```

- [ ] **Step 6: Commit**

```bash
git add sdk/tests/chip_spec_compliance.rs docs/chip-compliance.md
git commit -m "compliance(SPT-LEAF-FORMAT): green positive + negative tests; matrix row aligned"
```

---

## Phase C — Per-divergence reconciliation (template)

For **each** row in `docs/chip-compliance-worklist.md` under "Divergences"
(produced by Task A5), execute this template as a single commit. Phase B is the
worked example; this phase iterates the pattern for any additional divergences
the audit surfaces.

### Task C-template: Reconcile divergence `<id>`

**Files:**
- Modify: `<impl_locus>` from the matrix row.
- Modify: `sdk/tests/chip_spec_compliance.rs`
- Modify: `docs/chip-compliance.md`

- [ ] **Step 1: Write the negative test**

Pin the spec quote in a doc comment with the line citation. The test constructs
a bundle / CLVM input that violates the claim. Assert simulator or
`run_program` rejects.

- [ ] **Step 2: Run, expect FAIL** (because implementation still diverges)

- [ ] **Step 3: Modify implementation to match spec**

Change the `impl_locus` code/puzzle minimally so that the spec is enforced.
Recompile hex if `.rue` changed; update `puzzle_constants.rs`.

- [ ] **Step 4: Run negative test, expect PASS**

- [ ] **Step 5: Add positive test**

Spec-conformant input is accepted.

- [ ] **Step 6: Run full suite, expect PASS**

```bash
cd sdk && cargo test --release
```

- [ ] **Step 7: Update matrix row to `aligned`**

- [ ] **Step 8: Commit**

```bash
git commit -m "compliance(<id>): align <area> with CHIP.md §<lines>"
```

---

## Phase D — Test-gap fills (negative tests for MUSTs already aligned)

For **each** row in `docs/chip-compliance-worklist.md` under "Test gaps" with
`Missing: negative` and `status = untested but aligned`, execute this template.

### Task D-template: Add negative test for `<id>`

**Files:**
- Modify: `sdk/tests/chip_spec_compliance.rs`
- Modify: `docs/chip-compliance.md`

- [ ] **Step 1: Write the negative test**

Pin the spec quote in a doc comment. Construct a bundle/input that violates the
claim. Assert rejection.

- [ ] **Step 2: Run, expect PASS** (implementation already enforces)

- [ ] **Step 3: Sanity check — temporarily relax the implementation**

In a scratch `git stash` branch, comment out the enforcing assertion in the
puzzle or SDK. Re-run the negative test. It MUST now FAIL. This proves the
test actually exercises the constraint, not just side-effects. Restore.

- [ ] **Step 4: Update matrix row's `negative_test` and `status = aligned`**

- [ ] **Step 5: Commit**

```bash
git commit -m "compliance(<id>): add negative test"
```

### Task D-template: Add positive test for `<id>`

**Files:**
- Modify: `sdk/tests/chip_spec_compliance.rs`
- Modify: `docs/chip-compliance.md`

- [ ] **Step 1: Write positive test**

If an existing e2e test already proves the claim, cite it instead of duplicating.
Otherwise write a focused CLVM-isolated or SDK-pure test.

- [ ] **Step 2: Run, expect PASS**

- [ ] **Step 3: Commit**

```bash
git commit -m "compliance(<id>): add positive test"
```

---

## Phase E — CI gate test

### Task E1: Implement `chip_md_compliance_matrix_complete`

**Files:**
- Modify: `sdk/tests/chip_spec_compliance.rs`

- [ ] **Step 1: Write the gate test**

```rust
/// CI gate. Parses `docs/chip-compliance.md` and `CHIP.md` at runtime and
/// enforces the registry's invariants. Failure here means the matrix has
/// drifted from spec or from the test suite.
#[test]
fn chip_md_compliance_matrix_complete() {
    let matrix = std::fs::read_to_string("../docs/chip-compliance.md")
        .expect("docs/chip-compliance.md must exist");
    let chip_md = std::fs::read_to_string("../CHIP.md")
        .expect("CHIP.md must exist");

    let rows = parse_compliance_table(&matrix);
    assert!(rows.len() >= 40, "matrix has too few rows ({}); did you finish Phase A?", rows.len());

    let mut errors: Vec<String> = vec![];
    for row in &rows {
        if row.impl_locus.is_empty() || row.impl_locus == "?" || row.impl_locus == "MISSING" {
            errors.push(format!("{}: impl_locus missing", row.id));
        }
        if row.positive_test.is_empty() || row.positive_test == "?" || row.positive_test == "MISSING" {
            errors.push(format!("{}: positive_test missing", row.id));
        }
        if !chip_md.contains(&row.claim) {
            errors.push(format!(
                "{}: claim is not a verbatim substring of CHIP.md (claim={:?})",
                row.id, row.claim
            ));
        }
        if row.is_must_or_must_not(&chip_md) && (row.negative_test.is_empty() || row.negative_test == "?" || row.negative_test == "MISSING") {
            errors.push(format!("{}: MUST claim has no negative_test", row.id));
        }
        if row.status != "aligned" {
            errors.push(format!("{}: status = {} (expected `aligned`)", row.id, row.status));
        }
    }

    if !errors.is_empty() {
        panic!("compliance matrix violations:\n{}", errors.join("\n"));
    }
}
```

Helpers `parse_compliance_table`, `Row`, `Row::is_must_or_must_not` are written
inline in the same test file (private to this test crate).

- [ ] **Step 2: Run**

```bash
cd sdk && cargo test --test chip_spec_compliance chip_md_compliance_matrix_complete
```

Expected: PASS (after Phases B-D close every divergence and gap).

- [ ] **Step 3: Commit**

```bash
git add sdk/tests/chip_spec_compliance.rs
git commit -m "compliance: CI gate test enforces matrix invariants"
```

---

## Phase F — Spec edit (delete stale status section)

### Task F1: Delete CHIP.md lines 335-343 and add a one-line pointer

**Files:**
- Modify: `CHIP.md`

- [ ] **Step 1: Open CHIP.md and remove the section**

Delete from the line `## Implementation alignment (this revision)` (currently
line 335) through the end of the section (currently line 343, the line ending
"...is fully implemented and pinned by simulator e2e tests."), inclusive.

- [ ] **Step 2: Replace with a pointer**

```markdown
## Compliance

The reference implementation is verified against this spec by the compliance
matrix at `docs/chip-compliance.md`. The CI gate
`chip_md_compliance_matrix_complete` enforces that every normative claim has a
positive test and (for MUST / MUST NOT) a negative test, all executing real
CLVM via simulator or `run_program`.
```

- [ ] **Step 3: Run the gate test once more**

```bash
cd sdk && cargo test --test chip_spec_compliance chip_md_compliance_matrix_complete
```

Expected: PASS. (Note: the gate's "verbatim substring" check operates on the
`claim` columns of the matrix, none of which cite the deleted lines, so the
deletion is safe.)

- [ ] **Step 4: Commit**

```bash
git add CHIP.md
git commit -m "spec: delete stale 'Implementation alignment' status section; cite compliance matrix"
```

---

## Phase G — Final verification

### Task G1: Full release-mode green suite

- [ ] **Step 1: Run**

```bash
cd sdk && cargo test --release 2>&1 | tail -50
```

- [ ] **Step 2: Confirm output**

Expected:
- Every binary reports `0 failed; 0 ignored`.
- Total test count = matrix size + existing e2e count (i.e., `chip_spec_compliance.rs`
  added rows match the matrix rows).

- [ ] **Step 3: Confirm no `#[ignore]`**

```bash
rg -n '#\[ignore' sdk/
```

Expected: no matches.

- [ ] **Step 4: Confirm matrix is fully aligned**

```bash
awk -F'|' '/divergent|untested|MISSING/' docs/chip-compliance.md
```

Expected: empty output.

- [ ] **Step 5: Final commit (if any cleanup)**

```bash
git status
```

If clean: done. If not: address remaining diffs and commit.

---

## Self-review

Spec coverage check (against `docs/superpowers/specs/2026-05-04-chip-spec-compliance-design.md`):

- ✅ "Every normative claim has an executing test" → Phases A + D.
- ✅ "Every implementation divergence is corrected" → Phases B (known) + C (audit-surfaced).
- ✅ "Lines 335-343 deleted" → Phase F.
- ✅ "Single integration test file `chip_spec_compliance.rs`" → Phase B onwards.
- ✅ "Verbatim quoting CI gate" → Phase E.
- ✅ "Negative test required for every MUST / MUST NOT" → Phase D + Phase E.
- ✅ "Simulator + CLVM execution, no mocks" → all Phase B/C/D tests pinned to
  `chia-sdk-test::Simulator` or `clvmr::run_program`.

Placeholder scan: Phase C and Phase D are templates (instantiated per matrix row
from Phase A's worklist). This is acceptable per the design — the template's
steps are concrete and the per-row instantiation is a fill-in-the-blank derived
from the matrix, not a TBD.

Type consistency: `Row`, `parse_compliance_table`, `is_must_or_must_not` are
defined in Phase E and used only there. `occupied_leaf` signature changes
(removes `locked_cat_mojos` arg) propagate consistently in Phase B's Steps 2-5.
