# F1 — Finalize-forgery fix: circuit/accumulator redesign

**Status:** design + started implementation (research-grade; multi-session).
**Scope:** close F1 (finalize forgery) by binding the signer set INSIDE the
Groth16 circuit, keeping on-chain `finalize` **O(1)** (constant cost
independent of voter count — the entire point of using Groth16). Do NOT
move per-signer verification on-chain (that blows CLVM cost at
`MAX_SIGNERS = 20_000`).

## The bug (recap)

`sdk/src/prover/circuit.rs::generate_constraints` enforces only a
weighted-quorum slack identity. Three things are unbound:

- **G1 — denominator.** `registration_vote_weight_var` is a free witness,
  not tied to public input `s2` (`= sha256(reg_weight_be8) mod r`). A
  prover can use a tiny denominator in-circuit while `s2` commits the real
  (large) snapshot, trivially clearing the threshold.
- **G2 — numerator / membership.** `total_signer_weight = Σ signer.weight`
  with the per-signer `merkle_proof` **never verified**. No SPT membership,
  no leaf-hash binding. The summed weight is fabricatable.
- **G3 — aggregate.** `agg_signers` (`s3`) is never constrained to be
  `Σ (signer pubkeys)`. On-chain `bls_verify(agg_signers, agg_sig,
  vote_message)` proves only "the holder of `agg_signers` signed", not
  that it decomposes into registered voters.

Demonstrated: `sdk/tests/exploit_finalize_forgery_e2e.rs` (3 passing
exploits — an unregistered key finalizes any outcome, even with zero real
voters). **All three of G1/G2/G3 must be bound in-circuit; G2 and G3 are
each load-bearing** (closing only a subset leaves the forgery open: with
G3 open, a forger proves membership of real voters to clear the threshold
yet sets `agg_signers` to their own key for `bls_verify`).

## Feasibility map (arkworks 0.4, BLS12-381, constraint field = `Fr`)

Verified against ark-crypto-primitives-0.4.0 / ark-r1cs-std-0.4.0 source:

| Need | In-circuit feasibility (ark 0.4) | Cost |
|------|----------------------------------|------|
| SHA256 gadget (`Sha256Gadget`) | ✅ native to Fr CS | ~25–30k constraints / 64-byte block → depth-32 SHA256 Merkle ≈ **~1M constraints/signer** (too expensive) |
| Poseidon CRH gadget (`TwoToOneCRHGadget`, `CRHParametersVar`) | ✅ native to Fr CS | ~250–300 constraints / 2-to-1 → depth-32 Poseidon Merkle ≈ **~8–10k constraints/signer** |
| In-circuit value↔`s_i` bindings (one SHA256 of an 8/32-byte value) | ✅ | ~1 SHA256 (one-shot, not per-signer) |
| **In-circuit BLS12-381 G1 add (for `agg_signers`)** | ❌ **structurally absent.** `ProjectiveVar<P, F>` pins `F: FieldVar<P::BaseField, <P::BaseField>::BasePrimeField>` → constraint field must equal the curve **base** field `Fq`, not `Fr`. No `NonNativeFieldVar<Fq,Fr>` substitution type-checks. (`bls12::G1Var = ProjectiveVar<.., FpVar<Fq>>`.) | hand-rolled non-native ≈ several **thousand** constraints/add |

**Consequence:** G1 and G2 are feasible in-circuit *if the registration
tree uses a SNARK-friendly hash (Poseidon)*. G3 has **no stock path** —
binding the BLS aggregate in-circuit needs hand-rolled non-native Fq
arithmetic, which is research-grade and does not scale to 20k signers.

## The two viable architectures for G3

### Option A — keep BLS, hand-roll non-native G1 in-circuit
- Voters keep signing BLS over `vote_message`; aggregator still sums G1.
- Circuit binds `agg_signers = Σ pubkeys` via hand-implemented
  Renes–Costello–Batina SW addition over `NonNativeFieldVar<Fq, Fr>`
  (~12 non-native muls/add; each non-native mul ~hundreds–thousands of
  constraints). Plus Poseidon membership (G2) + weight (G1).
- **Verdict:** preserves the current BLS scheme and on-chain `bls_verify`,
  but the gadget is weeks of security-critical work and the per-signer
  cost (membership + a non-native G1 add) caps practical `signers`-per-proof
  far below 20k. Recursion/batching would be needed for large electorates.

### Option B — SNARK-friendly signatures, drop BLS aggregation (RECOMMENDED)
- Voters additionally (or instead) sign `vote_message` with a
  **SNARK-friendly signature** (Schnorr/EdDSA over an embedded curve whose
  scalar field is `Fr`, or a Poseidon-based scheme) so the circuit verifies
  each signer's signature **natively + cheaply**.
- Circuit proves, for each present signer: (i) Poseidon-SPT membership of
  `leaf = Poseidon(pubkey, weight)` under the snapshot root (bound to `s1`);
  (ii) a valid signature on `vote_message` by `pubkey`; accumulates
  verified weight; binds the threshold to the real snapshot (G1).
- `agg_signers` / on-chain `bls_verify` / `g2_map` are **removed** — the
  proof alone attests "≥threshold weight of registered voters signed the
  outcome". `finalize` stays O(1): verify the Groth16 proof + commit the
  outcome. No non-native G1 anywhere.
- **Verdict:** architecturally clean, fully O(1), the standard design for
  scalable ZK voting. Cost: a protocol change — voters sign with the new
  scheme (`mint_voting_coin`/`update_vote` + SDK + wallet), and the
  aggregator/circuit consume it. The registration leaf moves to Poseidon
  (shared with Option A).

## Shared foundation (needed by BOTH options): Poseidon registration accumulator

The SHA256 SPT is the root cause of in-circuit infeasibility. Migrate the
registration tree leaf+node hash to **Poseidon over `Fr`**:

- `sdk/src/merkle.rs`: leaf `= Poseidon(pubkey_fr_limbs, weight)`, node
  `= Poseidon(left, right)`, depth 32.
- On-chain `election/register.rue` + `deregister.rue`: verify
  membership/emptiness with Poseidon. **No CLVM Poseidon builtin exists** →
  implement Poseidon-over-Fr in Rue (S-box `x^5`, MDS, ARK; ~per-register
  cost is acceptable: ~33 hashes/spend, NOT per-signer). This is itself a
  meaningful sub-project; budget + benchmark CLVM cost. (Alternative: a
  dual commitment — SHA256 tree for cheap on-chain register + a Poseidon
  tree whose root the singleton also tracks — avoids Poseidon-in-CLVM but
  doubles the accumulator bookkeeping.)
- Circuit: in-circuit Poseidon membership via `TwoToOneCRHGadget` (see
  `prover/circuit_v2.rs`).

## Public-input / VK impact

- Keep the public-input COUNT at 8 (so the IC layout stays 9) ONLY if the
  scalar derivations are unchanged; Option B removes `s3`(agg_signers) and
  may repurpose inputs — coordinate the VK/IC currying in `finalize.rue`
  + `prover/conversions.rs` + ceremony. Any input-set change ⇒ new VK ⇒
  ceremony re-run (test setup via `generate_test_setup`).
- The circuit shape becomes **fixed at a chosen `MAX_SIGNERS_PER_PROOF`**
  (pad absent slots). Groth16 needs a fixed QAP. Pick a cap that the
  prover can handle (Poseidon membership ~8–10k constraints/signer ⇒ e.g.
  1–2k signers ≈ 10–20M constraints; 20k ≈ 160–200M, heavy — likely
  needs proof-batching/recursion for full-electorate quorums).

## G3 decision: **Option B (SNARK-friendly signatures)** — CHOSEN

Voters sign `vote_message` with a **Schnorr signature over Jubjub**
(`ark-ed-on-bls12-381` — the embedded curve whose base field IS the
constraint field `Fr`, so EC ops are native `FpVar<Fr>`). The circuit
verifies each signer's signature in-circuit (`s·G == R + c·P`,
`c = Poseidon(R.x, P.x, vote_message)`); BLS / `agg_signers` / on-chain
`bls_verify` / `g2_map` are dropped. Measured cost ≈ **~5.5k constraints per
signature + ~8–10k per Poseidon membership ≈ ~14–16k constraints/signer**
⇒ a few hundred signers per ~1–2M-constraint proof; full-electorate
quorums need proof batching/recursion (future).

## Sequencing (resumable plan)

1. **[DONE]** `prover/circuit_v2.rs` — `VotingCircuitV2` proving, per present
   signer: Poseidon-SPT MEMBERSHIP (`leaf = Poseidon(P.x, P.y, weight)`,
   depth-`DEPTH` Poseidon path → public root) + in-circuit Jubjub-Schnorr
   SIGNATURE over `vote_message` + verified weight sum ≥ threshold.
   Fixed-shape (padded to `max_signers`). Built ALONGSIDE the live circuit
   (tree green). Tests (5, passing): honest membership+signatures verify
   (full Groth16 prove/verify); forged non-member, bad signature,
   wrong/replayed message, and weight-tamper each FAIL the constraints.
2. **[DONE]** G3 decided + implemented: Schnorr-over-Jubjub, hand-rolled
   in-circuit verify (arkworks 0.4 has no Schnorr verify gadget). Off-circuit
   `keygen`/`schnorr_sign` helpers included.
3. **[TODO]** Soundness hardening of `circuit_v2`: range-check the threshold
   `slack` (bit decomposition); constrain `s`/`c` to the 252-bit inner
   scalar width; cofactor/prime-order checks on witnessed `R`/`P`; feed
   `vote_message` as ≤254-bit (or split). Choose audited Poseidon params.
4. **[IN PROGRESS]** Migrate the registration accumulator to this Poseidon
   tree over voters' JUBJUB pubkeys: `sdk/src/merkle.rs`,
   `election/register.rue` + `deregister.rue` (Poseidon-in-Rue membership),
   SDK predictors. (Identity migration: voters register their Jubjub signing
   key; the leaf commits it.)
   - **[DONE] CLVM cost benchmark** (`sdk/tests/poseidon_clvm_cost_bench.rs`):
     a single 32-byte modular multiply `(a*b)%P` costs **4 494**; a width-3
     Poseidon permutation (≈909 modmul) ≈ **4.1M**; a depth-32 register
     membership (≈33 permutations) ≈ **135M** = **1.23 % of the 11e9 block
     cost cap**. **VERDICT: FEASIBLE** with large headroom — Poseidon-in-Rue
     is viable; the design-doc dual-commitment fallback is NOT needed. (This
     is a lower bound — modadds/round-loop/ARK-indexing add more — but even
     3–4× stays <5 % of the cap, and registers are infrequent O(1) spends.)
   - **[TODO]** Implement the width-3 Poseidon permutation in Rue (S-box x^5,
     MDS, ARK over Fr) with parameters matching `circuit_v2::poseidon_config`
     byte-for-byte; switch `circuit_v2` from the generic sponge to the same
     fixed-arity compression so the in-circuit, off-circuit (`merkle.rs`),
     and on-chain (Rue) hashes are identical; wire into register/deregister
     membership + emptiness; update SDK predictors.
5. **[TODO]** Rewrite `finalize.rue` for the new public-input set (drop
   `agg_signers`/`bls_verify`/`g2_map`; keep the Groth16 pairing + outcome
   commit). Rebuild VK / ceremony. Promote `VotingCircuitV2` to the live
   circuit; fix `MAX_SIGNERS_PER_PROOF`.
6. **[TODO]** Rewrite `sdk/src/actors/aggregator.rs` finalize builder +
   voter signing (Jubjub Schnorr) + `sdk/src/actors/voter.rs`; update all
   finalize e2e tests; flip `exploit_finalize_forgery_e2e.rs` to assert the
   forged proof is REJECTED.

## Why not the cheaper-looking shortcuts

- **On-chain per-signer verification** (membership + g1_sum in `finalize.rue`):
  sound but O(signers) → ~640k SHA256 + 20k G1 adds + ~20MB solution at
  `MAX_SIGNERS`. Blows CLVM cost + tx size. Rejected — defeats Groth16.
- **Bind only G1 (and/or cap `total_signer_weight ≤ reg_weight`):** cheap
  but does NOT close F1 (G2/G3 remain). Security theater. Rejected.
