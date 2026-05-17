# Protocol flow (companion to CHIP draft)

This document expands the **end-to-end lifecycle** for [CHIP_DRAFT.md](./CHIP_DRAFT.md). The CHIP Specification gives a higher-level overview; use this page for **ordering, lanes, and who spends what**.

## Lanes (reminder)

| Lane | Spends | Role |
|------|--------|------|
| **Election singleton** | `register`, `createBallot`, `deregister` | Enrollment, ballot issuance, collateral release authorization. Serialized by design for registration. |
| **Parallel voting** | `mint_voting_coin`, `update_vote` | Do **not** require the Election Singleton; many voters can progress in the same block (within chain limits). |
| **Per-ballot** | Ballot Coin: `oracle`, `finalize`, `announce_finalization` | Vote mechanics and finality; does **not** spend the Election Singleton. |

## Phase 0 — Ceremony (trusted setup)

1. Deploy the **Ceremony Singleton** with window, `MIN_PARTICIPANTS`, `MAX_VOTERS`, `vk_seed`, and mod hashes for marker / voucher puzzles (see [chip-ceremony.md](./chip-ceremony.md)).
2. During `[start, start + length)`, participants submit **`contribute`** spends. Each accepted contribution creates a **Ceremony Marker Coin** and advances linear `last_contribution_hash` state.
3. After the window closes, **`finalize`** may run when `contribution_count ≥ MIN_PARTICIPANTS`. This seals `vk_hash`, `marker_root`, mints the **Ceremony Voucher** and summary outputs with VK material in memos.
4. Off-chain, verifiers walk markers / spends, verify contribution proofs, and derive the Groth16 VK. Before trusting an election, **independently check** `vk_hash` (and related) against chain data — `finalize` has no single designated signer.

## Phase 1 — Election deploy

5. Launch the **Election Singleton** with eight-field `ElectionState`, curried VK/IC, threshold pack, `MAX_SIGNERS`, CHIP-0050 action Merkle roots, etc.
6. **Recommended:** co-spend the **Ceremony Voucher** in the deploy bundle and assert its `CANONICAL_MSG` so the election is bound to `(vk_hash, max_voters, ceremony_launcher_id)` (see [chip-ceremony.md](./chip-ceremony.md)).

## Phase 2 — Registration and ballots(slow lane)

7. Voters call **`register`** on the Election Singleton (one registration coin per voter, CAT staked, registration SPT updated).
8. The operator calls **`createBallot`** to mint each **Ballot Coin** (2-mojo launcher pattern in reference). Ballots carry `vote_close_height`, `vote_options_root`, and **snapshots** of registration root + total weight for Groth16 public inputs at finalize.

## Phase 3 — Voting (parallel lane)

9. To cast or change a vote: **`mint_voting_coin`** (first time for that ballot from this registration) or **`update_vote`** on the **Voting Coin**. Both assert the Ballot Coin **`oracle`** (open) so close height and vote mode are pinned on-chain.
10. BLS signatures over the canonical **`vote_message`** are supplied for off-chain aggregation (e.g. memos); see [chip-witnesses-encoding.md](./chip-witnesses-encoding.md).

## Phase 4 — Finalize (per-ballot lane)

11. Off-chain: an **aggregator** collects Voting Coins and registrations, builds witness, runs **Groth16** prover, aggregates BLS.
12. On-chain: **`finalize`** on the Ballot Coin checks Groth16 and aggregate BLS via [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md) pairing opcodes, then commits `vote_outcome` and `agg_signers`. Rationale and figures: [chip-groth16-clvm.md](./chip-groth16-clvm.md).
13. Optionally **`announce_finalization`** (same ballot) so downstream logic can assert finality in a later block.

## Phase 5 — Exit (slow lane)

14. **`deregister`** on the Election Singleton clears the voter from the registration SPT and emits the deregister announcement.
15. **`release`** on the **Registration Coin** (typically same bundle) consumes that announcement and sets `release_destination`; collateral unlock follows puzzle finalizer rules — **not** tied to ballot finalization.

## Cross-reference

| Topic | Document |
|--------|----------|
| Ceremony puzzles, voucher, markers | [chip-ceremony.md](./chip-ceremony.md) |
| Election / Ballot / Registration / Voting coins and inner actions | [chip-election-coins.md](./chip-election-coins.md) |
| Merkle trees, vote modes, `vote_message`, public inputs, announcements | [chip-witnesses-encoding.md](./chip-witnesses-encoding.md) |
| Groth16 + CLVM / CHIP-0011, finalize soundness, `assets/` figures | [chip-groth16-clvm.md](./chip-groth16-clvm.md) |

Full index of companion docs: [README.md](./README.md).
