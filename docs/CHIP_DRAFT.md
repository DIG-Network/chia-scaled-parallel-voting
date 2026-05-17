| CHIP Number | |
| :---------- | :---------- |
| Title | Parallel voting at scale: off-chain proofs, on-chain finality |
| Description | Standard for large-scale on-chain elections on Chia: an Election Singleton orchestrates registration and ballot issuance; Registration, Ballot, and Voting Coins separate enrollment from parallel votes and from per-ballot finalize (Groth16 + `bls_verify` on the Ballot Coin) with off-chain aggregation and proving. |
| Author | Michael Taylor (on behalf of [DIG Network](https://github.com/DIG-Network)) |
| Editor | |
| Comments-URI | |
| Status | |
| Category | Standards Track |
| Sub-Category | Primitive |
| Created | 2026-05-04 |
| Requires | [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md) (CLVM BLS / curve operations for Groth16 verification); [CHIP-0050](https://github.com/Yakuhito/chips/blob/b23ed49e00164cbc62b9b6ae4d48071930c5b1d2/CHIPs/chip-0050.md) (action layer — see [PR #165](https://github.com/Chia-Network/chips/pull/165)) |
| Replaces | None |
| Superseded-By | |


Structure follows [CHIP-0050](https://github.com/Yakuhito/chips/blob/b23ed49e00164cbc62b9b6ae4d48071930c5b1d2/CHIPs/chip-0050.md). Process: [CHIP-1](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0001.md). **Editor**, **Comments-URI**, and **Status** are assigned after you open a PR; **CHIP Number** is assigned by a CHIP Editor.

## Abstract

This CHIP provides a standard for decentralized and permissionless scalable voting on the Chia Blockchain. The standard is targeting supporting up to 20,000+ voters. Although their is no known theoretical upper bound, feasible upper bound is limited by offchain computation.  
  
BLS signatures are used to aggregate voter signatures, However BLS alone is not sufficent to agreggate votes in a trustless environment. BLS does not provide a signal for voter threshold, the number of voters for that vote result and it does not provide a signal for total registered voters. All 3 of these commitments, BLS Agg, voter threshold, max voters are required.   
  
The novel approach in this CHIP is built on the realization that GROTH16 circuits can create cryptographic commitments that current CLVM operators can verify. Groth16 is a type of ZK-Proof that allows the system to ensure that no matter who submits the voter aggregation for vote finalization, can not lie. As long as vote finalization is submitted to prove that the required threshold of voters voted and the correct BLS Agg Sig is submitted, the vote is finalized on chain.

## Motivation

Traditionally a voting mechanism on Chia is throttled by the Singleton Parrallelation problem. Eventually the votes need to aggregated into a single coin to be able to do use work on the vote result within CLVM. In a decentralized and permissionless voting scheme, this means that only 1 vote per block can be tallied since each vote requires a spend of the Ballot Box Singleton. The consequence of this, is a minimum of 20,000+ blocks need to pass to tally up the results of 20,000+ voters. The more voters required to reach consensus, the more unrealistic the vote becomes. The alternative scheme is a semi-permissioned scheme where there is a single permissioned pubkey that is responsible for aggregating the votes and submitting the result to the singleton. This scheme also has many structural issues. Not withstanding the trust that the central party must maintain, the system become entirely dependant on thier participation. Critical systems that may move high value as a result of concensus would be hard to maintain over time with such a single point of failure.  
  
By defining a standard solution that gets around these limitations, we enable more complex governance systems to be built on Chia Blockchain.   
  
This standard was conceptualized to power the DIG Network concensus protocal. DIG is aiming to be a L2 for the Chia Network and will required the ability for validators to attest (vote) on L2 blocks and anchor those blocks to the Chia Blockchain in a decentralized and permissionless scheme.   
  
This standard also provides a path to production ready DAO governance that could also one day control a Chia Vault, powered by CAT governance tokens. The Chia Vault puzzles would be able to incorporate a spend path that could accept a annoucement from the vote result that resolves to a Chia Vault spend.

## Backwards Compatibility

This CHIP does not propose any changes to CLVM. 

## Specification

This section defines the on-chain artifacts, state, and spend rules needed for interoperable implementations. Election and Ballot singletons **MUST** route inner actions through the [CHIP-0050](https://github.com/Yakuhito/chips/blob/b23ed49e00164cbc62b9b6ae4d48071930c5b1d2/CHIPs/chip-0050.md) action layer where applicable. Groth16 verification and `bls_verify` **MUST** use the capabilities and encodings described in [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md). **End-to-end phase ordering** (ceremony through exit): [chip-protocol-flow.md](chip-protocol-flow.md). **Puzzle tables and encodings** live in the companion documents linked under **Companion documents** below.

### Protocol partitioning

Throughput is preserved by separating three classes of spends:

1. **Election singleton** — Handles `register`, `createBallot`, and `deregister` only. Enrollment is intentionally singleton-bound; it occurs once per voter and is not on the hot path for each vote.
2. **Parallel voting** — `mint_voting_coin` (Registration Coin) and `update_vote` (Voting Coin) **MUST NOT** require spending the Election Singleton, so many voters can update distinct coins in the same block, within mempool and consensus limits.
3. **Ballot Coin** — Each ballot carries `finalize`, `oracle`, and `announce_finalization`. Ballot finalization **MUST NOT** spend the Election Singleton, so delayed or disputed finalization on one ballot does not block registration, ballot creation, or deregistration on the election.

### Coin roles

**Election-facing:**

- **Election Singleton** — Orchestrates voter registration, mints Ballot Coin lineages via `createBallot` only, and authorizes `deregister` for collateral release. It does not perform vote finalization; that responsibility is entirely on the Ballot Coin.
- **Registration Coin** — Escrows the voter’s CAT, represents membership in the election registration Merkle tree, and maintains a per-registration sparse tree of ballot launcher ids to enforce one Voting Coin lineage per ballot.
- **Ballot Coin** — Per ballot: `vote_close_height`, `vote_options_root`, inherited VK/IC and threshold parameters, and state `(finalized, vote_outcome, agg_signers)`.
- **Voting Coin** — Carries `vote_data` and BLS material for aggregation for one (voter, ballot) pair; it is created and updated without spending the Election Singleton.

**Ceremony-facing (separate lineage from elections):**

- **Ceremony Singleton** — Accepts `contribute` during a configured height window, then `finalize` after the window closes. On-chain state includes `vk_hash`, `marker_root` (Merkle root over sorted contribution marker coin ids), and `finalized`.
- **Ceremony Marker Coin** — Created per accepted `contribute`; curries launcher id, participant public key, contribution hash, and previous contribution hash. The puzzle may produce no conditions when spent, leaving an on-chain commitment until removed.
- **Ceremony Voucher Coin** — Created only in ceremony `finalize`; anyone-can-spend with self-recreation so multiple election deploys can anchor to the same ceremony. Election deploy **SHOULD** co-spend the voucher and assert its announcement to bind `vk_hash`, `max_voters`, and `ceremony_launcher_id`.
- **Finalize summary output** — Additional coin(s) or outputs with memos (including VK bytes) for indexers using launcher hints.

**Election lineage (normative):**

- Registration Coin **MUST** descend from `register` on the Election Singleton.
- Ballot Coin **MUST** descend from `createBallot` only. The reference implementation uses a 2-mojo launcher eve to satisfy singleton outer morph constraints; compatible implementations **SHOULD** match that pattern unless an equivalent approach is fully validated.
- Voting Coin **MUST** descend from `mint_voting_coin` on a Registration Coin that proves election membership.

The ceremony graph is independent. Elections reference it through `ceremony_launcher_id`, `vk_hash`, and (recommended) voucher co-spend at deploy.

### Companion documents (normative detail)

Tables of inner actions, Merkle slot and leaf rules, announcement preimages, Groth16 public-input ordering, and pinned constants are maintained as **companion** Markdown files alongside this CHIP so the Specification stays readable as a protocol overview:

| Document | Contents |
|----------|----------|
| [chip-protocol-flow.md](chip-protocol-flow.md) | Phases 0–5, lanes, ordering of spends |
| [chip-ceremony.md](chip-ceremony.md) | Ceremony Singleton, marker, voucher, `CANONICAL_MSG` |
| [chip-election-coins.md](chip-election-coins.md) | `ElectionState`, Election / Ballot / Registration / Voting puzzles |
| [chip-witnesses-encoding.md](chip-witnesses-encoding.md) | Sparse Merkle trees, vote modes, `vote_message`, eight public inputs, announcements, reference constants |
| [chip-groth16-clvm.md](chip-groth16-clvm.md) | How Groth16 pairs with CLVM / CHIP-0011, BLS + circuit split, figures in `../assets/` |

An implementation **MUST** conform to this Specification and to any **MUST** / **MUST NOT** requirement in those companions where the companion text is marked normative. Index: [README.md](README.md).

### Election and ballots (summary)

The **Election Singleton** stores eight fields (`registration_merkle_root`, `registration_count`, `registration_vote_weight`, `election_start_height`, `ceremony_launcher_id`, `max_voters`, `vk_hash`, `vote_mode_lock`). Deploy-time curries carry VK, IC, threshold pack, `MAX_SIGNERS`, launcher ids, and CHIP-0050 action roots and **MUST** stay consistent on every Ballot Coin minted by `createBallot`. Inner actions are **`register`**, **`createBallot`**, and **`deregister`** only; **`createBallot`** is the **only** valid ancestry for a Ballot Coin and snapshots registration root and total weight for finalize-time proofs. **`finalize`**, **`oracle`**, and **`announce_finalization`** belong on the Ballot Coin, not the Election singleton.

This CHIP does **not** specify an on-chain XCH registration fee on `register` or an `accumulated_fees` field on the singleton. Ballot end time is **`VOTE_CLOSE_HEIGHT`** on each Ballot Coin, not a single global election timer. Full state and action tables: [chip-election-coins.md](chip-election-coins.md).

### Ceremony (summary)

The **Ceremony Singleton** accepts **`contribute`** during a configured height window, then **`finalize`** after the window when enough participants have contributed. It seals **`vk_hash`** and **`marker_root`**, mints a **Ceremony Voucher** (and summary outputs with VK material for indexers), and forms a lineage **independent** of elections. Elections bind to the ceremony via **`ceremony_launcher_id`** and **`vk_hash`**; election deploy **SHOULD** co-spend the voucher and assert **`CANONICAL_MSG`**. Full tables and preimage: [chip-ceremony.md](chip-ceremony.md).

### Witnesses, proofs, and encodings (summary)

Off-chain actors enumerate registrations and Voting Coins, verify lineage, aggregate BLS over the canonical **`vote_message`**, and build a Groth16 witness. On-chain **`finalize`** on the Ballot Coin verifies Groth16 and BLS aggregate verification via [CHIP-0011](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0011.md) pairing opcodes; any actor may submit a valid bundle. **`mint_voting_coin`** and **`update_vote`** assert the Ballot **`oracle`** so close height and vote mode are pinned where Groth16 public inputs do not carry them. **Why Groth16 and CLVM fit together, and figures:** [chip-groth16-clvm.md](chip-groth16-clvm.md). Sparse tree definitions, restricted vs unrestricted vote mode, the eight ordered public inputs, VK byte length, and announcement strings: [chip-witnesses-encoding.md](chip-witnesses-encoding.md).

The keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** in this Specification and in the linked companion documents are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html).


> **Temporary drafting guide — remove before PR:** List **concrete tests**: happy paths, edge cases (empty, max size, boundary heights), and **negative** cases (must fail). Point to **fixture files** (hex, JSON, CLVM costs) and **automated tests** in the reference repo. For a Standard CHIP, more coverage improves Review; mark what is **in-scope vs aspirational**.

## Reference Implementation

> **Temporary drafting guide — remove before PR:** Point to **repos, branches, paths**, build instructions, and the **surface area** covered (puzzles, SDK, CLI, WASM). Say what is **explicitly out of scope**. Editors often expect a reference implementation **before** moving to **Review** for Standards Track–style CHIPs—state what exists today and what is planned.

## Security

> **Temporary drafting guide — remove before PR:** **Mandatory.** Spell out **threat model** and **trust boundaries** (aggregate off-chain, ceremony trust, honest/malicious roles, …). Cover abuse, censorship, replay, key handling, privacy, and interactions with **dependencies** (other CHIPs, third-party aggregators). List known **residual risks** and mitigations; this section will be scrutinized in Review.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
