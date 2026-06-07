# Security audit — Chia parallel-voting puzzles

Adversarial audit of the non-ceremony puzzles (`puzzles/election/`,
`puzzles/registration_coin/`, `puzzles/ballot_coin/`,
`puzzles/voting_coin/`, `puzzles/action.rue`, `puzzles/merkle_utils.rue`,
`puzzles/common_types.rue`) and the SDK that builds their spends. The
ceremony lineage (`puzzles/ceremony_*`, `sdk/src/ceremony`) was
explicitly out of scope.

Threat model: an attacker hand-builds raw CLVM spend bundles. A finding
is an **exploit** only if Chia consensus would *accept* a bundle that
violates a protocol invariant (forge/redirect a vote, finalize an
outcome with no real backing, fake/withdraw locked CAT collateral,
double-vote, vote after close, replay). On-chain security must not
depend on the SDK building honest spends.

Every finding has a runnable proof-of-exploit or regression test under
`sdk/tests/exploit_*.rs`. Run with `cargo test -p chip-voting-sdk`.

## Status summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F1 | **Critical** | Finalize forgery — circuit never binds the claimed signer weight to the registered set | **Open** (needs circuit rewrite) |
| F2 | **Critical** | Register vote-weight forgery / fake CAT collateral | **Fixed** ✅ (numerator: forged weight unspendable via `AssertMyAmount(locked_weight)`); register-time denominator credit is a documented structural residual |
| F3 | **Critical** | Ballot VK/snapshot substitution — ballot curry not tied to election `vk_hash` | **Open** (needs createBallot→ballot binding) |
| F4 | **High** | Collateral release gated by a forgeable deregister announcement | **Fixed** ✅ (CHIP-0025 RECEIVE_MESSAGE binds the genuine Election Singleton's puzzle hash, re-derived from `election_launcher_id` in state) |
| F5 | **High** | `vote_mode_lock` is unenforceable | **Open** (needs eve-derivation binding) |
| F6 | **High** | `mint_voting_coin` had no close-height gate → vote after close | **Fixed** ✅ |
| F7 | **High** | `int_to_8_bytes_be` aliasing → inflate weight / bypass close gate via `X + 2^64` | **Fixed** ✅ |
| F8 | **Medium** | `deregister` had no collateral floor / underflow guard | **Fixed** ✅ |

The three Fixed items are landed as additive on-chain `assert`s that do
not change any solution shape (the SDK builders and all existing e2e
tests are unaffected). The five Open items each require a structural
redesign (a Groth16 circuit rewrite, a registration-coin amount-binding
protocol, a createBallot→ballot cryptographic binding, or CHIP-0025
message conditions) that cannot be landed safely as a localized patch;
they are demonstrated with runnable exploits and specified below.

> Note on the build toolchain: `puzzles/ballot_coin/finalize.rue` uses
> the CHIP-0011 `g2_map` builtin, which the publicly-available
> `rue-cli 0.8.4` does not provide (the committed hex was built with a
> patched/forked `rue`). The Fixed patches were therefore intentionally
> confined to the four puzzles that do **not** use `g2_map`
> (`election/register.rue`, `election/deregister.rue`,
> `registration_coin/mint_voting_coin.rue`, `voting_coin/update_vote.rue`)
> so they could be recompiled and verified end-to-end. `rue-cli 0.8.4`
> reproduces every unchanged puzzle's bytecode byte-for-byte, so the
> recompile diff is exactly the four patched puzzles.

---

## F1 — Finalize forgery (CRITICAL, open)

**Where:** `puzzles/ballot_coin/finalize.rue`, `sdk/src/prover/circuit.rs`
(`generate_constraints`).
**Test:** `sdk/tests/exploit_finalize_forgery_e2e.rs` (3 tests, passing).

The Groth16 circuit's quorum gadget enforces
`total_signer_weight * den >= num * registration_vote_weight`, but
`total_signer_weight` is a **free prover-chosen witness**
(`sum(self.signers[i].weight)`). The per-signer `pubkey`, `leaf_index`,
and `merkle_proof` witnesses are **never constrained** — the circuit does
not verify SPT membership, does not verify the leaf
`sha256(pubkey || weight_be8)`, and does not relate the signer set to
`agg_signers` (public input `s3`). On-chain `finalize.rue` only adds
`bls_verify(agg_signers, agg_sig, vote_message)`, which proves "the
holder of `agg_signers` signed `vote_message`" — not that `agg_signers`
decomposes into registered voters carrying real weight.

The circuit/`prover/mod.rs` comments assert these properties are
"deferred to on-chain validation", but `finalize.rue` performs no such
validation. The deferral lands nowhere.

**Exploit:** anyone with the proving key (necessarily public —
aggregation is permissionless; and SNARK soundness never depends on
proving-key secrecy) picks `agg_signers` = their own key, builds a
single fabricated `SignerWitness { weight: <whole electorate> }`,
proves (threshold trivially satisfied), and self-signs `vote_message`.
The proof verifies against the real VK and `finalize` accepts any
outcome. The three tests show this works even when the attacker is not
registered, even with zero registered voters, and with a claimed weight
1000× the registered total.

**Remediation:** move signer accounting into the circuit. For each
signer, allocate `(pubkey, weight, merkle_path)` as witnesses and
constrain in-circuit: (a) `sha256(pubkey || weight_be8)` is a leaf whose
depth-32 Merkle path reconstructs `registration_merkle_root` (public
input `s1`); (b) accumulate the verified weights into
`total_signer_weight`; (c) bind `agg_signers` (`s3`) to the G1 sum of
the verified signer pubkeys. This is the only place membership + weight
can be enforced; no on-chain patch to `finalize.rue` can substitute for
it because `agg_signers` is an opaque G1 sum on-chain.

---

## F2 — Register vote-weight forgery / fake CAT collateral (CRITICAL — numerator FIXED ✅; register-time denominator credit is a documented structural residual)

**Where:** `puzzles/election/register.rue` (`locked_cat_mojos` is a
solution field; the SMT leaf and `registration_vote_weight` increment
use it; the only binding is `AssertCoinAnnouncement` over a `create_reg`
message whose announcer `cat_parent_coin_id` is also solution-supplied).
**Tests:** `sdk/tests/exploit_register_weight_forgery_e2e.rs` —
`register_credits_forged_weight_with_no_real_collateral` pins the
residual; `forged_weight_registration_coin_cannot_be_spent` pins the fix.
Spend-time guard also pinned by
`clvm_runner::tests::release_emits_assert_announcement_and_aggsigme`.

**Original issue.** `register` credits the voter's solution-chosen
`locked_cat_mojos` into the SMT leaf `sha256(pubkey || locked_cat_mojos_be8)`
and into `ElectionState.registration_vote_weight`. Nothing verified that a
real CAT coin of that amount was created. The lone binding is an
`AssertCoinAnnouncement` of `create_reg` (which embeds `reg_full_hash` +
`locked_cat_mojos`), but consensus's `ASSERT_COIN_ANNOUNCEMENT` is
satisfied by **any** co-spent coin that emits the message — it never
inspects the announcer's puzzle, asset id, or amount. So a registration
could claim `1_000_000_000` units while a 1-mojo `(q . ((60 msg)))` dummy
emitted the announcement (zero governance CAT locked).

**Fix (NUMERATOR — the use of forged weight — CLOSED).**
`RegistrationState` now carries `locked_weight`, bound into the coin's
puzzle hash:

```
(pk . (el . (vbr . (locked_weight . release_destination))))
```

`register.rue` sets `locked_weight = locked_cat_mojos`, and **every**
registration-coin spend now emits `AssertMyAmount { amount: locked_weight }`:

- `mint_voting_coin.rue` — a Voting Coin can be minted only if the
  registration coin actually holds `locked_weight`.
- `release.rue` — collateral can be released only against a coin that
  actually holds `locked_weight`.

Consensus enforces `ASSERT_MY_AMOUNT` byte-exactly, so a registration that
claimed weight `W` but is backed by a coin holding `< W` can never mint a
Voting Coin nor release collateral — **the forged weight is unspendable**.
The gate that catches the forgery is the **first cast**: there
`locked_weight` is still the registered claim `W` and the coin must hold it.
Because casting peels `voting_coin_amount` mojos into the Voting Coin,
`mint_voting_coin.rue` **decrements `locked_weight` in lock-step**
(`new_state.locked_weight = State.locked_weight - voting_coin_amount`) so it
always equals the recreated Registration Coin's real CAT balance — keeping
`AssertMyAmount` satisfiable on every later spend (release / a further cast)
WITHOUT weakening the first-cast gate. The SDK ripples `locked_weight`
through `RegistrationState(Wire)`, all `puzzles.rs` predictors, the actual
spend-state builder (`Voter::registration_state_node`), the release / lineage
walker (which reconstruct each step's `locked_weight` from that coin's
on-chain amount), `aggregator.rs`, the CLI, and the WASM bindings; full
`chip-voting-sdk` suite is green (except the pre-existing
`chip_md_compliance_matrix_complete`, which needs a root `CHIP.md`).

**Residual (DENOMINATOR — register-time credit — STRUCTURAL, documented).**
The `register` action runs on the **Election Singleton** and does *not*
consume the registration coin (a separate CAT issuance creates it in the
same bundle). It therefore cannot `AssertMyAmount` on a coin it never
spends, and binding the real CAT amount in O(1) on the singleton is
structurally infeasible. So `register` still **credits the claimed weight
into `ElectionState.registration_vote_weight`** even when no real CAT is
locked. Impact of the residual is bounded to the **threshold denominator**:
a forger can *inflate* `registration_vote_weight` (making a quorum *harder*
to reach / a griefing/denial vector), but **cannot inflate the numerator**
— forged weight never becomes a counted vote, because casting requires
spending the registration coin through `mint_voting_coin`'s
`AssertMyAmount`. Closing the residual would require `register` to verify
the created coin's amount, e.g. a one-shot confirm spend of the new
registration coin in the same bundle (a CHIP-level redesign of the
register/issuance handshake), or moving registration-weight accounting to
finalize time over only spendable (amount-bound) coins.

---

## F3 — Ballot VK / snapshot substitution (CRITICAL, open)

**Where:** `puzzles/ballot_coin/finalize.rue` (curries VK, IC,
`REGISTRATION_MERKLE_ROOT_SNAPSHOT`, `REGISTRATION_VOTE_WEIGHT_SNAPSHOT`),
`puzzles/election/create_ballot.rue` (mints only a launcher; the
follow-up launch curries the ballot off-chain).

Nothing on-chain ties a Ballot Coin's curried VK/IC or its registration
snapshots to the election's `vk_hash` / real `ElectionState`.
`create_ballot` is permissionless and emits only a launcher eve coin; the
operator (or anyone, since the eve id is deterministic) curries the
Ballot Coin at launch. An attacker can launch a ballot whose
`ballot_launcher_id` traces to the real election but whose VK is one they
hold the trapdoor for (or whose snapshots are fabricated), then finalize
any outcome. Downstream consumers that trust `ballot_launcher_id` as
"belonging to the election" are fooled.

**Remediation:** have `create_ballot` derive and commit the canonical
Ballot Coin puzzle hash — with VK/IC = the election's curried VK/IC and
snapshots = the live `ElectionState.registration_merkle_root` /
`registration_vote_weight` — into the eve-coin derivation (or a
launcher memo the ballot's own puzzle re-asserts), so a ballot that
traces to the election provably uses the election's VK and a real
snapshot.

**Sequencing note.** This binding closes F5 too (the canonical ballot ph
also encodes `VOTE_OPTIONS_ROOT`). It must target the FINALIZE VK that F1
produces: F1 (see `docs/F1-finalize-redesign.md`) rewrites `finalize.rue`
and the verification key (Option B drops `agg_signers`/`bls_verify`/`g2_map`
and moves the registration accumulator to Poseidon-over-Jubjub). Committing
the *current* finalize VK now would be thrown away by F1's VK rebuild, so
**F3+F5's create_ballot binding should land WITH/AFTER F1 step 5** (finalize
+ VK rewrite). Until then F3/F5 remain open with this plan recorded.

---

## F4 — Collateral release via forgeable deregister announcement (HIGH, FIXED ✅)

**Where:** `puzzles/registration_coin/release.rue:44,60-73`,
`puzzles/election/shared.rue::deregister_announcement_msg`,
`puzzles/election/deregister.rue:124-126`.

`release` asserts `AssertCoinAnnouncement{ id: sha256(singleton_coin_id ||
sha256("deregister" || voter_pubkey)) }` where `singleton_coin_id` is a
**solution** field and the message binds only the (public) voter pubkey —
no election id, no merkle root, no singleton identity. As with F2, the
assertion is satisfied by any attacker-controlled co-spent coin emitting
that message. So a registered voter can run `release` (sending their CAT
to themselves) **without** spending the Election Singleton's `deregister`
at all — withdrawing their staked collateral while remaining in the
registration set and keeping their finalize vote-weight. (`release` is
gated by the voter's own `AggSigMe`, so it only affects their own coin —
but it defeats the "collateral locked while registered" invariant.)

**Fix (CHIP-0025 sender-puzzle binding).** The forgeable
`AssertCoinAnnouncement` (with a solution-supplied `singleton_coin_id`) is
replaced by a CHIP-0025 `RECEIVE_MESSAGE` in `release.rue`, paired with a
`SEND_MESSAGE` emitted by `deregister.rue` on the Election Singleton:

- `release.rue` re-derives the genuine singleton's puzzle hash IN-PUZZLE
  from `election_launcher_id` (read from UNFORGEABLE `RegistrationState`,
  never a solution atom) as
  `SingletonArgs::curry_tree_hash(election_launcher_id, inner_ph)` and
  emits `RECEIVE_MESSAGE { mode: SENDER_PUZZLE, message:
  sha256("deregister"||pk), sender: [singleton_ph] }`.
- `deregister.rue` emits the paired `SEND_MESSAGE { mode: SENDER_PUZZLE,
  message: sha256("deregister"||pk) }`.

Consensus pairs the two only if the actual `SEND_MESSAGE`-emitting coin's
puzzle hash equals the re-derived `singleton_ph`. A coin can only land and
SPEND at `curry(SINGLETON_TOP_LAYER, struct(launcher_id), inner)` via the
genuine singleton lineage (the launcher coin is unique and already spent;
`SINGLETON_TOP_LAYER` rejects any lineage proof that does not descend from
it), so a dummy/forged announcer can no longer authorize a release. The
SDK `Voter::release_collateral` supplies `singleton_inner_puzzle_hash =
tree_hash(election_action_layer)`; the `Aggregator` deregister detection
now recognises the `SEND_MESSAGE` (opcode 66) as well as the legacy CCA.

**Residual (documented):** `singleton_inner_puzzle_hash` is
solution-supplied, but that only selects which inner puzzle the committed
singleton hash is built around — no spendable coin exists at that hash
outside the genuine launcher lineage. A *clone* singleton sharing the same
`launcher_id` is impossible (a launcher coin is spent exactly once), so
there is no clone-singleton bypass.

**Tests:** `exploit_collateral_release_forgery_e2e.rs`
(`release_binds_to_genuine_singleton_attacker_cannot_forge`) pins (1) no
`AssertCoinAnnouncement` remains, (2) the committed sender equals
`SingletonArgs::curry_tree_hash(election_id, inner_ph)`, (3) the sender
changes with the in-state launcher id. The on-chain message pairing is
exercised by `voter_release_collateral_e2e.rs`,
`voter_release_after_cast_e2e.rs`, `aggregator_sync_after_deregister_e2e.rs`
and `live_orchestration_e2e.rs`.

---

## F5 — `vote_mode_lock` is unenforceable (HIGH, open)

**Where:** `puzzles/election/create_ballot.rue` (`mode_lock_ok` gates the
solution value `ballot_vote_options_root`), but the actual ballot's
`VOTE_OPTIONS_ROOT` is curried freely at launch, off-chain.

The election-level mode lock asserts a *throwaway* solution value rather
than the value the launched ballot is actually curried with, so a
mode-locked election can still have ballots created under any vote mode.

**Remediation:** commit the ballot's real `VOTE_OPTIONS_ROOT` into the
eve-coin derivation (or launcher memo the ballot's oracle re-asserts), so
`create_ballot`'s lock check binds the value the ballot will actually
use.

**Implementation note (shared with F3).** The clean fix is the SAME
launcher-binding redesign F3 needs: `create_ballot` computes the canonical
Ballot Coin puzzle hash (which already encodes `VOTE_OPTIONS_ROOT` via the
curried `oracle` action) and commits it so the permissionless launch cannot
deviate — closing F3 and F5 together. The cheaper-but-not-shared alternative
(enforce at the vote path) is rejected as too invasive: `mint_voting_coin`
would need `vote_mode_lock` in scope, which means threading it through
`RegistrationState` (or the `mint_voting_coin` curry) and therefore through
every reg-coin puzzle-hash predictor and ~41 test call sites — an
F2-`locked_weight`-scale ripple for a value that is already pinned to votes
by the `oracle` announcement. Prefer the create_ballot binding.

---

## F6 — `mint_voting_coin` had no close-height gate (HIGH, FIXED ✅)

**Where:** `puzzles/registration_coin/mint_voting_coin.rue`.
**Test:** `sdk/tests/exploit_vote_after_close_e2e.rs`.

`update_vote` gated edits with `AssertBeforeHeightAbsolute(vote_close_height)`,
but `mint_voting_coin` (the *first* vote on a ballot) had **no height
check**. So in the window `[vote_close_height, finalize)` a brand-new
vote could be minted and counted after the ballot closed.

**Fix:** `mint_voting_coin` now emits
`AssertBeforeHeightAbsolute { height: vote_close_height }`, mirroring
`update_vote`. `vote_close_height` is pinned to the ballot's real curried
value by the existing oracle `AssertCoinAnnouncement`, and F7's range
guard prevents aliasing it past `2^64` to defeat the gate.

---

## F7 — `int_to_8_bytes_be` aliasing (HIGH, FIXED ✅)

**Where:** `puzzles/common_types.rue::int_to_8_bytes_be` is the low 8
bytes of `n` (`n mod 2^64`) and is **not injective**: `enc(n) ==
enc(n + 2^64)`. Attacker-controlled solution values fed through it could
alias a forged value onto a legitimate one's bytes.
**Tests:** covered by `exploit_register_weight_forgery_e2e.rs` (range)
and `exploit_vote_after_close_e2e.rs`.

- `register`/`deregister`: supplying `locked_cat_mojos = X + 2^64`
  produced the same SMT leaf and `create_reg` announcement as `X` (the
  signed `>=` floor passes), while crediting/decrementing the tally by
  `X + 2^64`.
- `mint_voting_coin`/`update_vote`: supplying
  `vote_close_height = C + 2^64` matched the real ballot's oracle
  preimage (`enc(C)`) while making `AssertBeforeHeightAbsolute(C + 2^64)`
  accept any block height.

**Fix:** the four puzzles whose encoded value comes from
attacker-controlled solution input now assert `0 <= value < 2^64` before
use (`register.rue`, `deregister.rue`, `mint_voting_coin.rue`,
`update_vote.rue`), making each encoding unambiguous. (The shared helper
itself was left unchanged to avoid forcing a `finalize.rue` recompile;
`finalize`'s own encodings are curried operator constants, not attacker
inputs.)

---

## F8 — `deregister` collateral floor / underflow (MEDIUM, FIXED ✅)

**Where:** `puzzles/election/deregister.rue`.
**Test:** `sdk/tests/exploit_vote_after_close_e2e.rs` (deregister-guard
case) and the existing deregister e2e.

`deregister` took `locked_cat_mojos` as a free Int with no
`>= COLLATERAL_AMOUNT` floor (unlike `register`) and no guard against
`registration_vote_weight` / `registration_count` going negative.

**Fix:** `deregister` now asserts the collateral floor, the F7 range
bound, and `registration_vote_weight - locked_cat_mojos >= 0` and
`registration_count - 1 >= 0` before storing the new state.

---

## Items reviewed and found NOT exploitable

- **Action-layer / finalizer state injection** (`action.rue`,
  `finalizer.rue`): the dispatcher verifies each selected action against
  the curried `MERKLE_ROOT` and threads state through the action; a
  malicious solution cannot inject an arbitrary recreated state or run an
  action outside the root.
- **Double-vote per ballot** (`mint_voting_coin` non-membership SPT
  proof): once a ballot's slot is occupied the non-membership proof fails;
  covered by `voter_double_vote_e2e.rs`.
- **Redirecting another voter's collateral**: `release` requires the
  voter's `AggSigMe` over the destination, so an attacker cannot redirect
  someone else's CAT (F4 is the voter withdrawing their *own* stake
  early).
- **CAT mint/melt via the finalizer `my_amount`**: the CAT v2 outer
  enforces amount conservation, so `my_amount` cannot inflate supply.
