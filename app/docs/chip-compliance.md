# CHIP.md compliance matrix

> **Source of truth:** [`../../CHIP.md`](../../CHIP.md). Every `claim` field below MUST be a
> verbatim substring of `CHIP.md`. Every row MUST link to a positive test that
> exercises real CLVM via the simulator or `clvmr::run_program`. Every row whose
> normative force is MUST or MUST NOT MUST link to a negative test. The CI gate
> `chip_md_compliance_matrix_complete` enforces these rules at every test run.
>
> Note on table escaping: literal pipe characters in CHIP.md (e.g. `sha256(left || right)`)
> would break Markdown table parsing, so for those rows the `claim` cites a different,
> still-verbatim substring of the same sentence (e.g. `no `0x02` CLVM tree-hash prefix`).
> The CI gate substring check is performed against the un-escaped `claim` text.

| id | chip_md_lines | claim | category | impl_locus | positive_test | negative_test | status |
|---|---|---|---|---|---|---|---|
| SPT-DEPTH | 87, 142 | Fixed depth 32 (must match `TREE_DEPTH` in config and puzzles) | data-layout | ? | ? | ? | untested |
| SPT-SLOT | 88, 143 | `u32::from_be_bytes(sha256(pubkey)[0..4])` | data-layout | ? | ? | ? | untested |
| SPT-LEAF-FORMAT | 89, 144 | Occupied leaf: `sha256(pubkey)` | data-layout | ? | ? | ? | divergent |
| SPT-EMPTY-LEAF | 90, 145 | `EMPTY_LEAF_HASH = sha256(0x00 × 48)` | data-layout | ? | ? | ? | untested |
| SPT-INTERNAL-NODE-NO-PREFIX | 146 | no `0x02` CLVM tree-hash prefix | data-layout | ? | ? | ? | untested |
| SPT-TRACKS-VOTERS | 93 | The SPT tracks **eligible voters**, not vote choices | data-layout | ? | ? | ? | untested |
| BALLOT-SPT-LEAF | 95 | leaves are `sha256(ballot_launcher_id)` | data-layout | ? | ? | ? | untested |
| BALLOT-SPT-NONMEMBERSHIP | 95 | Used by `mint_voting_coin` to prove non-membership before insertion | security-invariant | ? | ? | ? | untested |
| CIRCUIT-PUBLIC-INPUT-COUNT | 97, 150 | extended in this revision to **6 scalars** | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUTS-ORDER | 150 | This CHIP revision pins **6 public-input scalars**, in order | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-1-ROOT | 152 | `registration_merkle_root` — root of the registration SPT at the height the witness was built. | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-2-WEIGHT | 153 | `registration_vote_weight` — total weighted stake of all registered voters (scalar). | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-3-SIGNERS | 154 | `agg_signers` — packed bitvector / hash of which signers contributed to the aggregate. | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-4-VOTEMSG | 155 | `vote_message` — the canonical hash signed by each contributing voter (see preimage below). | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-5-THRESHOLD | 156 | `threshold_pack` — packed `(num, den)` quorum threshold; the on-chain Ballot Coin asserts this matches the curried threshold. | circuit-input | ? | ? | ? | untested |
| CIRCUIT-INPUT-6-BALLOT-LAUNCHER | 157 | `ballot_launcher_id` — 32-byte launcher id of the Ballot Coin being finalized; binds the proof to a single ballot and prevents cross-ballot replay. | circuit-input | ? | ? | ? | untested |
| CIRCUIT-VK-LENGTH | 159 | VK byte length is therefore fixed at `336 + (PUBLIC_INPUT_COUNT + 1) * 48 = 336 + 7 * 48 = 672` bytes for this revision. | circuit-input | ? | ? | ? | untested |
| CIRCUIT-IC-MATCH | 150 | Ordering and IC layout MUST match the Ballot Coin's **`finalize.rue`** and `circuit.rs` for that deployment exactly | circuit-input | ? | ? | ? | untested |
| VOTE-MSG-PREIMAGE | 163 | This CHIP **pins** the preimage | data-layout | ? | ? | ? | untested |
| VOTE-MSG-COMPONENTS-ORDER | 174 | All three components MUST be present and concatenated in this exact order | data-layout | ? | ? | ? | untested |
| VOTE-MSG-AGREE | 174 | Ballot Coin `finalize.rue`, Voting Coin `cast.rue` / `update.rue`, the off-chain aggregator, and the Groth16 circuit MUST all agree on this preimage | data-layout | ? | ? | ? | untested |
| ELECTION-NO-FEE | 191 | Implementations MUST NOT curry a `REGISTRATION_FEE` into the singleton's `register` action and MUST NOT track an `accumulated_fees` field in the singleton state | action-set | ? | ? | ? | untested |
| ELECTION-CHIP0050-DISPATCH | 197 | Each action is dispatched through the standard CHIP-0050 **action-layer puzzle**; the action-merkle-root is curried into the singleton at deploy. | action-set | ? | ? | ? | untested |
| ELECTION-NO-LEGACY-ACTIONS | 205 | The legacy singleton actions **`finalize`**, **`announce_finalization`**, and **`oracle`** MUST be omitted from the Election Singleton's action root in this revision. | action-set | ? | ? | ? | untested |
| ELECTION-REGISTER-ROLE | 201 | Empty-slot proof, new voter leaf + weight to SPT; mint Registration CAT lineage with empty per-registration ballot SPT. **No XCH registration fee.** | coin-state | ? | ? | ? | untested |
| ELECTION-CREATEBALLOT-ROLE | 202 | Mints Ballot Coin; passes through `election_launcher_id`, VK/IC, threshold pack, and ballot identity; sets `vote_close_height` and outcome domain. | coin-state | ? | ? | ? | untested |
| ELECTION-DEREGISTER-ROLE | 203 | Removes voter leaf from registration SPT; emits announcement that authorizes the matching Registration Coin's `release` action to unlock collateral. | coin-state | ? | ? | ? | untested |
| BALLOT-COIN-STATE | 215 | Ballot Coin state: `(finalized: bool, vote_outcome: Bytes32, agg_signers: Bytes32)`. | coin-state | ? | ? | ? | untested |
| BALLOT-FINALIZE-CURRY | 221 | `finalize`: `(VK, IC, BALLOT_LAUNCHER_ID, ELECTION_LAUNCHER_ID, VOTE_CLOSE_HEIGHT, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN, REGISTRATION_MERKLE_ROOT_SNAPSHOT, REGISTRATION_VOTE_WEIGHT_SNAPSHOT)` | puzzle-curry | ? | ? | ? | untested |
| BALLOT-ORACLE-CURRY | 222 | `oracle`: `(BALLOT_LAUNCHER_ID, VOTE_CLOSE_HEIGHT)`. | puzzle-curry | ? | ? | ? | untested |
| BALLOT-ANNOUNCE-CURRY | 223 | `announce_finalization`: `(BALLOT_LAUNCHER_ID)`. | puzzle-curry | ? | ? | ? | untested |
| BALLOT-FINALIZE-ROLE | 233 | Verifies Groth16 (6 public inputs including `ballot_launcher_id`) + `bls_verify`; asserts current height ≥ `VOTE_CLOSE_HEIGHT` | coin-state | ? | ? | ? | untested |
| BALLOT-FINALIZE-RECREATE | 233 | commits ballot outcome by recreating Ballot Coin with `finalized=true, vote_outcome=…, agg_signers=…` | coin-state | ? | ? | ? | untested |
| BALLOT-ORACLE-ROLE | 234 | Permissionless attestation that recreates the Ballot Coin unchanged and emits an announcement of `(ballot_launcher_id, vote_close_height, finalized)` | coin-state | ? | ? | ? | untested |
| BALLOT-ANNOUNCE-ROLE | 235 | Re-announce ballot finalization after `finalize` has run; permissionless and idempotent. | coin-state | ? | ? | ? | untested |
| BALLOT-FINALIZE-SNAPSHOTS | 221 | The two `*_SNAPSHOT` curries are the Election Singleton's state at `launch_ballot` time | security-invariant | ? | ? | ? | untested |
| REG-COIN-STATE | 258 | `RegistrationState`: `(voter_pubkey, election_launcher_id, voted_ballots_root, release_destination)`. | coin-state | ? | ? | ? | untested |
| REG-COIN-NO-HAS-VOTED | 270 | Registration Coin no longer carries `has_voted: bool` or `vote_data: Bytes32` directly. Both fields are removed. | coin-state | ? | ? | ? | untested |
| REG-MINT-VOTING-COIN-LINEAGE | 267 | Verifies the target Ballot Coin lineage (asserts the Ballot Coin's puzzle is reachable via `createBallot` from this election) | cross-coin-protocol | ? | ? | ? | untested |
| REG-MINT-VOTING-COIN-NONMEMBERSHIP | 267 | proves non-membership of `ballot_launcher_id` in `voted_ballots_root`; inserts into the per-registration ballot SPT | cross-coin-protocol | ? | ? | ? | untested |
| REG-MINT-VOTING-COIN-CURRY | 267 | mints a fresh Voting Coin curried with `ballot_launcher_id`, `voter_pubkey`, and initial `vote_data`. | cross-coin-protocol | ? | ? | ? | untested |
| REG-RELEASE-DEREGISTER | 268 | Asserts the Election Singleton's `deregister` announcement for this `voter_pubkey`; sends collateral to `release_destination`. | cross-coin-protocol | ? | ? | ? | untested |
| REG-RELEASE-NOT-FINALIZE | 268 | **Release is gated by deregistration, not by ballot finalization.** | security-invariant | ? | ? | ? | untested |
| VOTING-COIN-STATE | 276 | `VotingCoinState`: `(voter_pubkey, ballot_launcher_id, vote_data, registration_coin_id)`. | coin-state | ? | ? | ? | untested |
| VOTING-UPDATE-VOTE-ORACLE | 282 | Asserts the Ballot Coin's `oracle` announcement that the ballot is still open (current height < `VOTE_CLOSE_HEIGHT`) | cross-coin-protocol | ? | ? | ? | untested |
| VOTING-UPDATE-VOTE-RECREATE | 282 | recreates the Voting Coin with new `vote_data` | cross-coin-protocol | ? | ? | ? | untested |
| VOTING-NO-SINGLETON | 282 | **No Election Singleton co-spend is required.** | security-invariant | ? | ? | ? | untested |
| AGGREGATOR-LATEST-LINEAGE | 284 | The aggregator enumerates the latest Voting Coin per `(registration_coin_id, ballot_launcher_id)` pair (the lineage tip) when assembling the finalize witness. | cross-coin-protocol | ? | ? | ? | untested |
| FLOW-FINALIZE-NOT-SINGLETON | 296 | **Ballot Coin** `finalize` action verifies proof + **`bls_verify`** + commits ballot outcome by recreating the Ballot Coin. The Election Singleton is **not** spent. | security-invariant | ? | ? | ? | untested |
| FLOW-DEPLOY-GENESIS | 291 | genesis state (`registration_merkle_root=EMPTY`, `registration_count=0`, `registration_vote_weight=0`, `election_start_height`) | coin-state | ? | ? | ? | untested |
| LINEAGE-THREE-LINK | 83 | Three-link parent chain proving (a) Registration Coin from Election Singleton **`register`**, (b) Ballot Coin from Election Singleton **`createBallot`**, and (c) Voting Coin from Registration Coin **`mint_voting_coin`** path. | lineage | ? | ? | ? | untested |
| SEC-BALLOT-AUTHENTICITY | 315 | Voting Coins MUST reference a **`ballot_launcher_id`** whose lineage traces to **`createBallot`**, and Ballot Coin `finalize` asserts the same launcher id matches its public input | security-invariant | ? | ? | ? | untested |
| SEC-SINGLE-VOTE-PER-BALLOT | 317 | Enforced on Registration Coin via the per-registration ballot SPT — `mint_voting_coin` proves non-membership before inserting `ballot_launcher_id`. | security-invariant | ? | ? | ? | untested |
| SEC-TWO-CHECK | 319 | Groth16 + **`bls_verify`** as before, run on the Ballot Coin. | security-invariant | ? | ? | ? | untested |
| SEC-THRESHOLD-PRESERVED | 321 | `threshold_pack` remains a circuit public input AND the Ballot Coin's `finalize` action asserts the curried `(num, den)` matches the proof's threshold scalar—neither piece is removed in this revision. | security-invariant | ? | ? | ? | untested |
| SEC-COLLATERAL-RELEASE | 325 | Collateral is released only after the singleton's `deregister` action emits the matching announcement—not by ballot finalize. | security-invariant | ? | ? | ? | untested |
| SEC-TIMING | 327 | Per-ballot `vote_close_height` curried on the Ballot Coin freezes mutable **`vote_data`** on Voting Coins (enforced via the Ballot Coin `oracle` action that `update_vote` asserts) | timing | ? | ? | ? | untested |
| SEC-NO-SINGLETON-DOS | 329 | Because finalize spends the Ballot Coin and not the singleton, a stuck or contested finalize for ballot A cannot block registrations, new ballot creation, or deregistrations. | security-invariant | ? | ? | ? | untested |
