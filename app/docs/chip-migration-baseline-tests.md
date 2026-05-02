# CHIP Migration Baseline Test Results

Branch: `chip-rev-2026-05-02`
Worktree: `C:\Users\micha\workspace\dig-network\CHIP-migration`
Captured: 2026-05-02T16:28:46Z
Forked from main at commit: `c433e9a`
Spec commit on branch: `56418f5`

Toolchain: `rustc 1.95.0 (59807616e 2026-04-14)` / `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
Platform: Windows 11 (x86_64-pc-windows-msvc)

## Build (`cargo build --workspace --all-targets`)

Result: **PASS**

- Wall time: 1m 58s (warm Cargo cache; first/cold-cache run not measured here).
- Profile: `dev` (unoptimized + debuginfo).
- Compiler warnings: 0.
- Final crates compiled in workspace: `chip-voting-sdk` (sdk), `chip-voting-cli` (cli).
- Notable upstream crates pulled: `chia-wallet-sdk 0.30.0`, `chia 0.26.0`, `ark-groth16 0.4.0`, `ark-bls12-381 0.4.0`, `dig-l1-wallet 0.1.0`.

## Test compile (`cargo test --workspace --no-run`)

Result: **PASS**

- Wall time: 0.69s (test binaries were already up-to-date after the build step's `--all-targets` run; nothing to recompile).
- 11 test executables produced:
  - `chip_voting` (bin unittests)
  - `chip_voting_diagnose_bundle` (bin unittests)
  - `chip_voting_live_test` (bin unittests, `live_integration_test.rs`)
  - `chip_voting_sdk` (lib unittests)
  - `action_layer_e2e`
  - `actor_functions_e2e`
  - `integration`
  - `register_action_e2e`
  - `register_action_layer_isolated`
  - `voter_actions_e2e`
  - `voter_register_full_flow`

## Test run (`cargo test --workspace`)

Result: **PASS**

- Total tests: 228
- Passed: 228
- Failed: 0
- Ignored: 0
- Filtered out: 0
- Doc-tests: `chip_voting_sdk` ran (0 doc-tests defined).

### Per-binary breakdown (test result lines, in run order)

| Test binary | Passed | Time |
|---|---:|---:|
| `chip_voting` (bin) | 0 | 0.00s |
| `chip_voting_diagnose_bundle` (bin) | 0 | 0.00s |
| `chip_voting_live_test` (bin) | 5 | 0.03s |
| `chip_voting_sdk` (lib) | 165 | 0.73s |
| `action_layer_e2e` | 3 | 0.35s |
| `actor_functions_e2e` | 34 | 0.32s |
| `integration` | 10 | 0.33s |
| `register_action_e2e` | 3 | 0.02s |
| `register_action_layer_isolated` | 2 | 0.06s |
| `voter_actions_e2e` | 5 | 0.01s |
| `voter_register_full_flow` | 1 | 0.13s |
| Doc-tests `chip_voting_sdk` | 0 | 0.00s |

### Failing tests

None.

## Notes

- Cargo cache was warm before this baseline; build/test compile times above reflect incremental rebuilds, not a cold cache. The 20m / 10m / 30m caps from the plan were never approached (total wall time across all three steps: ~2 min).
- All test runs completed in well under their caps; no test was killed for hanging, none skipped.
- No compiler warnings emitted by the workspace (build log contains zero `warning:` lines). This is a clean baseline — any new warnings introduced during Phase 1+ will be straightforward to spot in diffs.
- `cargo test --workspace` exit code: 0. `cargo build --workspace --all-targets` exit code: 0. `cargo test --workspace --no-run` exit code: 0.
- Raw logs (source of truth) are in the sandbox at `/tmp/chip-baseline-build.log`, `/tmp/chip-baseline-test-compile.log`, `/tmp/chip-baseline-tests.log`. These are scratch artifacts, not committed.
- The `live_integration_test.rs` binary's 5 unit tests passed; this is the test the migration plan flags for likely Phase 7 attention. The pre-migration baseline is green, so any post-migration breakage there is attributable to the migration.

## Migration plan adjustments suggested by this baseline

- The plan budgets significant time for "first cargo build may take 20+ min." With a warm cache that's a non-issue; a fresh clone or `cargo clean` is the only scenario where the cap matters. Worth noting in Phase 0 prose that subsequent baselines (e.g. mid-migration sanity checks) will be fast.
- Because the baseline is fully green (228/228, zero warnings), Phase 1+ regression detection is binary: any failed test or new warning is a regression. No pre-existing flakes to filter out.
