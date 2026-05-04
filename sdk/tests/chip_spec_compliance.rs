//! CHIP.md compliance suite. Each test cites the CHIP.md line range of the
//! normative claim it enforces. The CI gate
//! `chip_md_compliance_matrix_complete` (added in Phase E) ensures the matrix
//! at `app/docs/chip-compliance.md` stays in sync with both spec and tests.
//!
//! The body of the negative test below is filled in Task B6; for B1 the test
//! exists only to pin the function name and confirm the file compiles.

/// CHIP.md §88-91: `Occupied leaf: sha256(pubkey)`. Per-voter weight is
/// tracked on the Election Singleton state (`registration_vote_weight`),
/// NOT in the leaf, in this revision.
///
/// Negative test: an SPT membership witness whose leaf is
/// `sha256(pubkey || locked_cat_mojos_be8)` (the prior, divergent
/// implementation's leaf formula) MUST be rejected by `register.rue`.
#[test]
fn chip_spt_leaf_format_rejects_appended_weight_leaf() {
    panic!("not yet implemented — Task B6 fills body");
}
