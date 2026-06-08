# F3 + F5 binding design (ballot VK/snapshot/options substitution)

Status: design accepted; implementation in progress on `security/puzzle-attack-hardening`.

## Decisive constraint
CHIP-0025 `SEND_MESSAGE`/`RECEIVE_MESSAGE` pair ONLY within one spend bundle
(like coin announcements). `create_ballot` and `finalize` are blocks apart, so
a SEND at create_ballot cannot reach a RECEIVE at finalize. The binding MUST
fire at **finalize** by co-spending the **live Election Singleton** in the same
bundle via a new read-only election action `attest_ballot`.

## Mechanism (unforgeable, reuses the F4 sender-puzzle primitive)
Binding tuple:
```
binding_msg = sha256("ballot_binding" || ELECTION_LAUNCHER_ID || BALLOT_LAUNCHER_ID
    || vk_hash || REGISTRATION_MERKLE_ROOT_SNAPSHOT || be8(REGISTRATION_VOTE_WEIGHT_SNAPSHOT)
    || be8(VOTE_THRESHOLD_NUM) || be8(VOTE_THRESHOLD_DEN) || VOTE_OPTIONS_ROOT)
```
- **`attest_ballot` (new election action, read-only):** reads `vk_hash` /
  current `registration_merkle_root` / `vote_mode_lock` from UNFORGEABLE
  `ElectionState`; enforces snapshot + vote_mode_lock predicates; emits
  `SEND_MESSAGE { mode: SENDER_PUZZLE, message: binding_msg, receiver: [] }`.
  State unchanged (mirrors ballot oracle no-op; finalizer emits the amount-1
  recreation, attest_ballot emits no CreateCoin).
- **`finalize` (ballot):** gains curried `ELECTION_VK_HASH` + `VOTE_OPTIONS_ROOT`
  + singleton consts; asserts `sha256(VK||IC) == ELECTION_VK_HASH`; re-derives
  genuine election PH from curried `ELECTION_LAUNCHER_ID` + solution
  `election_inner_puzzle_hash` (release.rue:96-105 = `SingletonArgs::curry_tree_hash`);
  reconstructs the same `binding_msg` from its curried args; emits
  `RECEIVE_MESSAGE { mode: SENDER_PUZZLE, message: binding_msg, sender:[genuine_election_ph] }`.

Unforgeable because: RECEIVE sender = re-derived singleton PH (only the genuine
lineage can spend there); the payload's state-derived fields come from the
election's own state, the rest from finalize's curried args — consensus pairs
only on byte-identical messages. Forged VK / fabricated snapshot / wrong
options-root → messages differ or attest raises → no pairing → finalize fails.

## vk_hash canonical commitment — NO REDEFINITION NEEDED (risk eliminated)
VERIFIED: `vk_hash = sha256(chia_chunked_bytes)` (ceremony FinalizeParams.vk_hash
doc + backend.rs:225 vk_bytes = `ark_vk.chia_chunked_bytes()`), and
`chia_chunked_bytes` = `alpha(48)||beta(96)||gamma(96)||delta(96)||ic0..ic5(48 each)`
= EXACTLY the byte order of finalize.rue's curried `VK{alpha,beta,gamma,delta}` +
`IC{ic0..ic5}` structs. So finalize hashes the field concatenation:
```
assert sha256(VK.alpha + VK.beta + VK.gamma + VK.delta + IC.ic0 + ... + IC.ic5) == ELECTION_VK_HASH;
```
and `ELECTION_VK_HASH` (curried) == `State.vk_hash` is forced by the binding_msg
pairing. Together: the curried VK == the real election VK. NO change to the
ceremony/deployer vk_hash definition. `ELECTION_VK_HASH` curry value = `config.vk_hash()`.
BOTH checks are needed: the sha256 binds the curried VK bytes to ELECTION_VK_HASH;
the message pairing binds ELECTION_VK_HASH to the election's real State.vk_hash.

## Snapshot predicate
MVP: `snapshot == current State root/weight` (sound vs fabrication; couples
finalize timing to registration stability). Stronger: registration-root history
accumulator (defer; document residual).

## Execution order
1. deployer.rs + config.rs: redefine vk_hash to sha256(vk_clvm||ic_clvm); verify ceremony voucher. GATE on deploy/ceremony tests.
2. NEW puzzles/election/attest_ballot.rue; recompile (single-file rue build, not build.sh).
3. puzzles/ballot_coin/finalize.rue: ELECTION_VK_HASH + VOTE_OPTIONS_ROOT + singleton consts + VK/IC bind + election-PH re-derivation + RECEIVE_MESSAGE; recompile.
4. create_ballot.rue: downgrade mode_lock_ok to advisory.
5. sdk/src/puzzles.rs: ELECTION_ATTEST_BALLOT_HEX; election action root 3→4 leaves (re-sort) + fix pinned test; vk_ic_clvm_commitment helper.
6. ballot.rs launch_ballot: add ELECTION_VK_HASH + VOTE_OPTIONS_ROOT to finalize curry.
7. aggregator.rs build_finalize_with_proof_for_ballot_inner: mirror curry; FIX line-897 hardcoded vote_options_root (read memo); co-spend attest_ballot election singleton; supply election_inner_puzzle_hash.
8. NEW sdk/tests/exploit_ballot_substitution_e2e.rs (assertions: receive bound to genuine election; sender changes with election id; forged VK mismatch; fabricated snapshot raises; wrong options under lock raises; honest finalizes e2e).
9. SECURITY_FINDINGS.md F3+F5 → FIXED + residuals.
10. cargo test --no-fail-fast.

## Residuals to document
vk_hash redefinition crosses ceremony boundary (verify); snapshot historicity
(MVP = current-root equality); 4th action changes election inner PH (new
deployments only); finalize now contends for the singleton spend-lane
(liveness); clone-singleton impossible (F4 argument inherited); be8 range guard
on the tuple; aggregator line-897 options-root bug is a prerequisite fix.
