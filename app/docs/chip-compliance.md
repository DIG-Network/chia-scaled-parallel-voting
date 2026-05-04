# CHIP.md compliance matrix

> **Source of truth:** [`../../CHIP.md`](../../CHIP.md). Every `claim` field below MUST be a
> verbatim substring of `CHIP.md`. Every row MUST link to a positive test that
> exercises real CLVM via the simulator or `clvmr::run_program`. Every row whose
> normative force is MUST or MUST NOT MUST link to a negative test. The CI gate
> `chip_md_compliance_matrix_complete` enforces these rules at every test run.

| id | chip_md_lines | claim | category | impl_locus | positive_test | negative_test | status |
|---|---|---|---|---|---|---|---|
