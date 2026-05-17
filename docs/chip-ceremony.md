# Ceremony layer (companion to CHIP draft)

Normative detail for the **Ceremony Singleton** and auxiliary coins. Overview: [CHIP_DRAFT.md](./CHIP_DRAFT.md) § Specification. **Flow:** [chip-protocol-flow.md](./chip-protocol-flow.md) Phase 0.

## State (`CeremonyState`)

Five fields (see `puzzles/ceremony_singleton/shared.rue` and `sdk::CeremonyState`):

| Field | Meaning |
|--------|---------|
| `contribution_count` | Number of accepted `contribute` spends. |
| `last_contribution_hash` | Hash of latest public contribution payload; equals `vk_seed` before first contribution. |
| `finalized` | Set by `finalize`; further `contribute` rejected. |
| `vk_hash` | `sha256(VK bytes)`; zero until finalize. |
| `marker_root` | Merkle root over **sorted** per-contribution marker coin ids; zero until finalize. |

## Deploy curries (minimum)

Include at least: `START_BLOCK_HEIGHT`, `CEREMONY_LENGTH_BLOCKS`, `MIN_PARTICIPANTS`, `MAX_VOTERS`, `vk_seed`, `CEREMONY_COIN_MOD_HASH`, `CEREMONY_VOUCHER_MOD_HASH`. Exact layouts: `puzzles/ceremony_singleton/`.

## Inner actions

| Action | Requirements |
|--------|----------------|
| **`contribute`** | Rejected if `finalized` is set. Allowed only while `START_BLOCK_HEIGHT ≤ height < START_BLOCK_HEIGHT + CEREMONY_LENGTH_BLOCKS`. `prev_contribution_hash` **MUST** equal current `last_contribution_hash` (first contributor uses `vk_seed`). `AggSigUnsafe` **MUST** bind the domain-separated ceremony contribution message (string **MUST** match reference implementation). Creates a **Ceremony Marker Coin** with **even** output amount so the singleton outer has exactly one odd `CreateCoin` (recreation). Increments `contribution_count` and updates `last_contribution_hash`. Large parameters: committed by hash on-chain; payloads recovered off-chain from spends and memos. |
| **`finalize`** | Only after `height ≥ START_BLOCK_HEIGHT + CEREMONY_LENGTH_BLOCKS`. Requires `finalized` unset and `contribution_count ≥ MIN_PARTICIPANTS`. Sets `finalized`, `vk_hash`, `marker_root` from solution. Mints **Ceremony Voucher** and summary marker(s) with VK-related memos. **Not** authenticated by a designated key: first valid spend wins. Verifiers **SHOULD** independently derive or verify `vk_hash` and `marker_root` from marker chain before relying on an election. |

## Ceremony Marker Coin

- **Source:** `puzzles/ceremony_coin/marker.rue`.
- **Curried:** `CEREMONY_LAUNCHER_ID`, `PARTICIPANT_PUBKEY`, `CONTRIBUTION_HASH`, `PREV_CONTRIBUTION_HASH`.
- **Created by** Ceremony `contribute` only. Even amount (reference: 2 mojos) for singleton morph rules.
- **Spend:** may return no conditions; coin remains an on-chain commitment until removed.
- **Discovery:** launcher id as hint for indexers.

## Ceremony Voucher Coin

- **Source:** `puzzles/ceremony_singleton/ceremony_voucher.rue`.
- **Minted only** from ceremony `finalize`.
- Anyone-can-spend with self-recreation at same puzzle hash and amount so **many** election deploys can reuse one ceremony.
- **`CANONICAL_MSG`:**

`sha256("chip:ceremony:voucher" || vk_hash || max_voters_u64_be8 || ceremony_launcher_id)`

Election deploy **SHOULD** co-spend the voucher and assert this announcement.

**Contributions MUST NOT** be voucher-gated; the contribution window is **permissionless** at the puzzle level. Allow-lists are deployment policy only.

## Reference code paths

- Puzzles: `puzzles/ceremony_singleton/`, `puzzles/ceremony_coin/marker.rue`
- SDK: `sdk/src/actors/ceremony.rs`, `sdk/src/ceremony/`, `sdk/src/state.rs` (`CeremonyState`)

Companion index: [README.md](./README.md).
