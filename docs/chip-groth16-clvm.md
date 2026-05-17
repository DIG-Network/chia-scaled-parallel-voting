# Groth16, CLVM, and ballot finalization (companion to CHIP draft)

This document explains **how Groth16 is combined with Chia’s CLVM** for Ballot Coin `finalize`, **why the construction is sound**, and how the figures under `assets/` illustrate the *intuition* behind thresholds and proof anchoring. Normative bytecode ordering and public-input tables: [chip-witnesses-encoding.md](./chip-witnesses-encoding.md), `puzzles/ballot_coin/finalize.rue`, `sdk/src/prover/circuit.rs`. Protocol overview: [CHIP_DRAFT.md](./CHIP_DRAFT.md).

---

## What CLVM contributes

Chia’s CLVM is not a general “ZK verifier.” What it **does** provide (per [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md)) are **BLS12-381 curve operations** exposed as opcodes—enough to evaluate the **Groth16 verification equation** as a fixed product-of-pairings identity, and to run **`bls_verify`** for aggregate signatures.

In this CHIP, the Ballot Coin **`finalize`** puzzle:

1. Rebuilds the **Groth16 instance** from the proof \((A,B,C)\), the **verification key** \((\alpha,\beta,\gamma,\delta)\) and **input commitment** points **IC[0..8]** curried at deploy.
2. Derives eight **scalar inputs** \(s_1,\ldots,s_8\) from **on-chain-visible** data (registration snapshot, weights, `vote_message`, threshold pack, ballot id, num/den) and compares them to scalars supplied in the spend, so the proof cannot be replayed against a different ballot or election snapshot.
3. Computes **vk_input** \(= \mathrm{IC}_0 + \sum_{i=1}^{8} \mathrm{IC}_i \cdot s_i\) in G1 (same linear structure as standard Groth16 IC).
4. Uses **`bls_pairing_identity`** to assert the usual Groth16 pairing product holds for \((A,B,C)\), **vk_input**, and **VK**—i.e. the CLVM checks a **constant-size proof** in time that depends on **pairing cost**, not on the number of voters.
5. Separately runs **`bls_pairing_identity`** with **`g2_map`** on **`vote_message`** so the aggregate signature is bound to the same outcome message the circuit and announcements use.

So: **Groth16 proves (off-chain) that an R1CS instance for the voting circuit holds for those public inputs; CLVM reruns that proof’s verifier against the VK and the inputs reconstructed from chain state.**

---

## What the circuit proves (off-chain) vs what the chain checks (on-chain)

| Layer | Responsibility |
|--------|----------------|
| **R1CS + Groth16 (prover)** | Produces a proof that the circuit’s constraints are satisfied for the **committed** public inputs—e.g. that a **quorum / majority** relation over registered weight and the claimed signer set is consistent with the circuit definition (see comments in `sdk/src/prover/circuit.rs` for the exact relation encoded there). |
| **Ballot `finalize` (CLVM)** | Verifies the Groth16 proof with **CHIP-0011** pairings; **re-derives** \(s_1..s_8\) from curried and solution fields so tampering with roots, thresholds, or ballot id breaks verification; verifies **BLS aggregation** over **`vote_message`**. |
| **Registration / Voting puzzles** | Enroll voters in the registration SPT, pin per-ballot **oracle** (open height and vote options), and keep voting state off the Election singleton’s hot path. |

**Why both Groth16 and `bls_verify`?** BLS aggregation gives a compact signature over **`vote_message`** tied to **`agg_signers`**. It does not, by itself, prove statements about **global** registration roots, **weights**, or **threshold arithmetic** inside a single cheap opcode. The circuit is the place where those predicates are expressed as R1CS constraints; Groth16 compresses that check to **three curve points and a handful of pairings** on-chain. The **oracle** spend on the Ballot Coin is still needed where the proof does not encode every pin (e.g. **`VOTE_CLOSE_HEIGHT`** and **`VOTE_OPTIONS_ROOT`** for mint/update).

---

## Why the on-chain scalar bindings matter

Groth16’s **verification key** is tied to a **fixed circuit shape** and a **ceremony-produced** structured reference string. The **instance** for a specific finalize is the vector of **public inputs**. In `finalize.rue`, the prover supplies **Scalars** \(s_1,\ldots,s_8\); the puzzle **recomputes** the expected scalars from:

- `REGISTRATION_MERKLE_ROOT_SNAPSHOT`, `REGISTRATION_VOTE_WEIGHT_SNAPSHOT` (snapshotted at `createBallot`),
- `agg_signers`, `vote_message`, `threshold_pack(VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN)`, `BALLOT_LAUNCHER_ID`,
- and the raw field encodings for num/den,

and **asserts equality** with the proof’s public scalars (hashes mod \(r\) where specified in the puzzle). Any mismatch means **vk_input** does not match what the prover used, and **pairing verification fails**. That is what prevents **cross-ballot replay** or **changing** the registration commitment **after** the ballot was created.

---

## Trusted setup and `vk_hash`

Groth16 requires a **circuit-specific** trusted setup. This CHIP assumes a **multi-party ceremony** (see [chip-ceremony.md](./chip-ceremony.md)) yields a **verification key** whose **SHA-256** is **`vk_hash`** on the Election Singleton. Implementations **must** treat **`vk_hash`** and voucher binding as part of the trust model: a malicious VK would break soundness regardless of CLVM correctness.

---

## Figures (pedagogical intuition)

The PNGs in [`../assets/`](../assets/) are **not** literal diagrams of CLVM opcodes or of the Groth16 CRS. They illustrate **why a threshold can pin an outcome** before one talks about pairings: with **too few** contributions, many “curves” are still consistent with the observed data; with **enough** contributions, the aggregate constraint set can **lock** the relevant commitment. **τ** in the figures (“where the proof value is read”) is a visual stand-in for **evaluating a committed polynomial / SRS at a secret point**—the same *flavor* of idea that makes polynomial-based SNARKs possible—without replacing the formal definition of Groth16.

### Figure 1 — below threshold (ambiguous)

<figure>
  <img
    src="../assets/figure_1.png"
    alt="Diagram: Agreement curve — 2 of 5 signers, below threshold; V1 and V2 signed; dashed orange curves show ambiguous fits through the points; vertical dashed line at τ marks the proof anchor"
    width="880"
    style="max-width: 100%; height: auto; display: block; margin: 1em auto;"
  />
  <figcaption align="center"><em>Figure 1 — Too few signers leave the curve ambiguous (pedagogical).</em></figcaption>
</figure>

*Interpretation:* Until enough voters (by weight / quorum rule) are committed inside the proof’s statement, an adversary could still be consistent with **multiple** outcomes or weights—analogous to **many** degree-(\(n\)-1) curves through **too few** points.

### Figure 2 — threshold met (curve locked)

<figure>
  <img
    src="../assets/figure_2.png"
    alt="Diagram: Agreement curve — 4 of 5 signers, threshold met; solid blue curve locked through V1 V2 V3 V5; V4 silent; vertical dashed line at τ where proof value is read"
    width="880"
    style="max-width: 100%; height: auto; display: block; margin: 1em auto;"
  />
  <figcaption align="center"><em>Figure 2 — Enough signers lock a single curve; τ is where the proof value is read (pedagogical).</em></figcaption>
</figure>

*Interpretation:* Once the threshold relation enforced in the circuit holds, the **public inputs** Pin down the instance; Groth16 then proves that instance in zero knowledge (witness privacy is secondary here; **soundness** of the vote outcome + quorum claim is primary).

---

## Reference code

| Piece | Location |
|--------|-----------|
| On-chain finalize | `puzzles/ballot_coin/finalize.rue` (`bls_pairing_identity`, scalar checks, announcements) |
| Circuit + prove / verify helpers | `sdk/src/prover/circuit.rs`, `sdk/src/prover/proof.rs` |
| CHIP-0011 | [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md) — BLS / pairings used by the verifier |

Companion index: [README.md](./README.md).
