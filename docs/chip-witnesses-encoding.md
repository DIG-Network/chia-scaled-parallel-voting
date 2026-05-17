# Witnesses, Merkle trees, vote modes, and encodings (companion to CHIP draft)

Normative detail for trees, vote messages, Groth16 public inputs, and announcements. Overview: [CHIP_DRAFT.md](./CHIP_DRAFT.md) § Specification. **Conceptual:** how Groth16 is verified in CLVM and why the split with BLS works — [chip-groth16-clvm.md](./chip-groth16-clvm.md).

## Sparse Merkle trees

### Registration tree (reference `TREE_DEPTH = 32`)

- **Slot:** first four bytes of `sha256(pubkey)` as big-endian `u32`.
- **Occupied leaf:** `sha256(pubkey || locked_cat_mojos_be8)`.
- **Empty leaf:** `EMPTY_LEAF_HASH = sha256(0x00 × 48)` = **0x17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1**.
- **Internal node:** `sha256(left || right)` — **not** the CLVM `0x02` serialized-tree prefix.

### Per-registration ballot tree

- **Leaf:** `sha256(ballot_launcher_id)`.
- **Slot (reference):** `sha256(ballot_launcher_id) mod 2^32`.
- **Depth:** **32** in reference. Any change requires matching circuit and puzzle definitions.

## Vote modes

- **Unrestricted:** `vote_options_root` is 32 zero bytes; any `vote_data` subject to other checks.
- **Restricted:** `vote_options_root` is root of sorted Merkle tree of allowed outcomes; mint and update **MUST** include inclusion proofs.

If `vote_mode_lock` on the Election Singleton is not all `0xFF`, every ballot **MUST** use that locked root.

## Canonical vote message

`vote_message = sha256(vote_outcome || ballot_launcher_id || election_launcher_id)`

All implementations (puzzles, aggregator, circuit) **MUST** use this exact preimage order.

## Groth16 public inputs (ordered)

1. `registration_merkle_root` (witness-time)
2. `registration_vote_weight`
3. `agg_signers`
4. `vote_message`
5. `threshold_pack`
6. `ballot_launcher_id`
7. `vote_threshold_num` (field element)
8. `vote_threshold_den` (field element)

Threshold **num** / **den** as public inputs allow one VK (fixed `MAX_SIGNERS`) to support multiple rational quorum fractions.

**VK size (reference):** **768** bytes (`336 + 9 × 48`).

## Off-chain vs on-chain

- **Off-chain:** Enumerate registrations and Voting Coins; verify lineage; weighted quorum; BLS aggregation; Groth16 witness and proof.
- **On-chain:** Ballot `finalize` verifies Groth16 and `bls_verify`. Any actor may submit a valid finalize bundle; incentives are out of scope for this CHIP.

## Pinned constants (reference interop)

- `TREE_DEPTH = 32`
- `MAX_SIGNERS = 20_000`
- `PUBLIC_INPUT_COUNT = 8`
- `EMPTY_LEAF_HASH` as above

Bytecode source of truth: `puzzles/compiled/`, `sdk/src/puzzles.rs`.

Companion index: [README.md](./README.md).

## Announcement preimages

| Source | Preimage |
|--------|----------|
| Ballot oracle (open) | `"ballot_oracle_open" || ballot_launcher_id || vote_close_height_u32_be || vote_options_root` |
| Ballot oracle (closed) | open preimage || `vote_outcome || agg_signers` |
| Ballot finalized | `"ballot_finalized" || ballot_launcher_id || vote_outcome || agg_signers` |
| Deregister | `"deregister" || voter_pubkey` |
