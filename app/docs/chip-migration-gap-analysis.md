# CHIP Migration Gap Analysis

**Date:** 2026-05-02
**Spec:** `C:\Users\micha\workspace\dig-network\CHIP\CHIP.md`
**Implementation under review:** `C:\Users\micha\workspace\dig-network\CHIP\sdk\` and `C:\Users\micha\workspace\dig-network\CHIP\puzzles\`

> The spec itself acknowledges: *"Historical puzzle filenames (`finalize.rue`, `register.rue`, etc.) may **not yet** reflect this CHIP revision in-tree; CHIP.md describes the intended architecture."* (`CHIP.md:245`). This document inventories that drift in detail.

---

## 1. CHIP spec summary

### 1.1 Abstract / Architecture (CHIP.md:1–22)

Four coin types; *votes do not spend the Election Singleton*:

1. **Election Singleton** — registration authority, **sole minter of Ballot Coins via `createBallot`**, finalize authority.
2. **Registration Coin** — CAT-wrapped, created via singleton `register`. Holds CAT collateral. *"Successful registration enrols that voter in **every ballot** minted while the registration remains active—it does **not** carry the substantive vote intent for specific ballots."* (`CHIP.md:11`)
3. **Ballot Coin** — *"created solely by an Election Singleton **`createBallot`** action."* Curries `ballot_launcher_id`, vote close height, outcome domain, policy hooks (`CHIP.md:13`, `CHIP.md:69`).
4. **Voting Coin** — *"created from the **Registration Coin** when the voter casts a vote for a **specific ballot**."* Curried state binds `ballot_launcher_id` and `vote_data`. *"One active vote lineage per (registration, ballot)"*. Owner *"may re-spend to change `vote_data` until the Ballot Coin's rules say the ballot has ended."* (`CHIP.md:15`, `CHIP.md:73`)

### 1.2 Definitions (CHIP.md:65–81)

- **Election Singleton state**: SPT root, `registration_vote_weight`, `election_start_height`, thresholds, Groth16 VK/IC. The phrase *"Typically one per **election deployment** spanning many ballots."* makes ballots first-class, not the singleton's terminal state.
- **Registration Coin**: *"Does **not** embed per-ballot `vote_data`; instead authorizes minting Voting Coins **per ballot** subject to uniqueness."*
- **Voting Coin**: Edits gated by ballot's end condition; memos expose BLS material for aggregators; *"One active vote lineage per (registration, ballot)—enforced on the Registration Coin."*
- **Lineage Proof**: Three-link chain: Election Singleton `register` → Registration Coin; Election Singleton `createBallot` → Ballot Coin; Registration Coin vote → Voting Coin.
- **SPT**: depth 32, slot from `sha256(pubkey)`, occupied leaf `sha256(pubkey)`, empty leaf `EMPTY_LEAF_HASH`. *(Updated 2026-05-04: CHIP.md §88-91 / §143-146 specify `sha256(pubkey)` for this revision; the appended-weight form `sha256(pubkey || locked_cat_mojos_be8)` is forward-compatible but not yet implemented. The 2026-05-03 phase-A change to the appended-weight form was reverted by the spec-compliance pass — see `chip-migration-handoff.md`'s "Spec compliance addendum".)*
- **Groth16 public inputs**: *"public inputs MAY be extended in implementations to bind **`ballot_launcher_id`** or ballot-specific roots if finalize is per-ballot."*

### 1.3 Inner actions of the singleton (CHIP.md:158–171)

Normative table:

| Action | Role |
|--------|------|
| `register` | Empty-slot proof, **no XCH registration fee** under recommended profile |
| `createBallot` | **NEW** — Mints Ballot Coin; defines ballot timing/identity for Voting Coins |
| `finalize` | Groth16 + `bls_verify` for **specific ballot outcome** |
| `announce_finalization` | Re-announce after finalize |

> *"The prior **`oracle`** action used solely to authorize **`change_vote`** on registrations **before ballots** may be omitted when **Voting Coins** absorb change-vote semantics—implementations SHOULD NOT require a synchronous Election Singleton spend for mid-ballot corrections."* (`CHIP.md:169`)

### 1.4 Registration Coin / Voting Coin layers (CHIP.md:175–183)

- *"`vote` (or renamed path) **mints or updates Voting Coins**, not substantive long-lived `vote_data` solely on self."*
- *"Registration refuses a second Voting Coin lineage for the same `ballot_launcher_id`."*
- *"Spending **own Voting Coin** may update **`vote_data`** until Ballot puzzles assert **ballot ended**—no oracle bundle from Election Singleton needed for edits."*
- Release rules unchanged.

### 1.5 Vote message preimage (CHIP.md:116, CHIP.md:242)

- Spec text 116: *"`vote_message`, typically `sha256(outcome_data || ballot_launcher_id)` or `sha256(outcome_data || ballot_launcher_id || election_launcher_id)` — **exact preimage is defined by `finalize` + circuit**."*
- Revision row 242: *"MUST include **ballot** identity (`ballot_launcher_id`, and optionally `election_launcher_id`) — exact preimage **must** match `finalize` and the circuit for the deployed tag."*

### 1.6 Circuit public inputs (CHIP.md:127–137)

Five conceptual limbs (legacy): `registration_merkle_root`, `registration_vote_weight`, `agg_signers`, `vote_message`, `threshold_pack`. *"Implementations pinning to the legacy five-input layout SHOULD add or substitute a `ballot_launcher_id` (or hash thereof) limb so proofs cannot be replayed across ballots."*

### 1.7 Full data flow (CHIP.md:188–197)

1. Deploy Election Singleton (genesis, thresholds, VK).
2. Register (singleton lane).
3. **`createBallot` (singleton lane, infrequent)** — `Ballot Coin(s)` lineage lives.
4. **Vote / change vote (parallel lane)** — Registration Coin spends mint or update Voting Coins per ballot.
5. Finalize prep — aggregator indexes Voting Coins for ballot `B`.
6. Finalize on-chain — verifies proof + `bls_verify` + commits ballot outcome.
7. Release collateral.

### 1.8 Deprecation / divergence checklist (CHIP.md:230–245)

| Removed/changed | Replacement |
|---|---|
| `vote`/`change_vote` rewriting `has_voted`/`vote_data` on Registration Coin | Voting Coins carry `vote_data`; mutation via Voting Coin spends |
| One coarse election tally | **Multiple ballots**, finalize targets ballot outcome |
| XCH `REGISTRATION_FEE` and accumulated-fee finalizer payout | **Dropped under recommended profile** |
| `oracle` singleton action | **Superseded** — Voting Coin mutability gated by ballot timing replaces it |
| Aggregator focus on registration memos | Enumerate **Voting Coins per `ballot_launcher_id`** + registration weight witnesses |
| `vote_message` keyed only on outcome+`election_launcher_id` | **MUST include `ballot_launcher_id`** |

### 1.9 Security (CHIP.md:210–226)

Five key properties: Registration gate (`register` binds CAT + SPT), Ballot authenticity (Voting Coins reference `ballot_launcher_id` traceable to `createBallot`), Single vote per ballot (enforced on Registration Coin), Two-check consensus (Groth16 + `bls_verify`), Ballot timing (Voting Coin `vote_data` frozen at ballot end).

---

## 2. Current SDK inventory (`C:\Users\micha\workspace\dig-network\CHIP\sdk\src`)

### 2.1 `lib.rs`
Public API surface re-exports `Aggregator`, `ElectionDeployer`, `Indexer`, `Oracle`, `Voter`, `VoterKeys`, `DeployParams`, `DeploymentArtifacts`, `OracleAnnouncement`, `OracleSpend`, `announcement_for_state`, `ElectionConfig`, `MAX_SIGNERS`, `PUBLIC_INPUT_COUNT`, `TREE_DEPTH`, `VotingError`, `VotingResult`, `ElectionState`, `RegistrationState`, `VoteRecord`, `VoteRecordWire`, `VoterSet`, ceremony types, `Groth16Proof`, `Scalars`, `VotingCircuit`, etc. **No ballot or voting-coin types are exported.**

### 2.2 `config.rs` (`ElectionConfig`)
Fields (`config.rs:78`): `election_launcher_id_hex`, `cat_tail_hash_hex`, `collateral_amount`, `registration_fee`, `election_length_blocks`, `election_start_height`, `tree_depth`, `max_signers`, `verification_key_hex`, `vote_threshold_num`, `vote_threshold_den`, `label`. Constants: `TREE_DEPTH=32`, `MAX_SIGNERS=20_000`, `PUBLIC_INPUT_COUNT=5`, `EMPTY_LEAF_HASH`. `validate()` rejects unless VK length = `336 + 6*48 = 624` bytes (5 public inputs). **No ballot-related fields.**

### 2.3 `state.rs`
- `ElectionState` (`state.rs:26`): `registration_merkle_root`, `registration_count`, `registration_vote_weight`, `accumulated_fees`, `finalized: bool`, `election_start_height`, `vote_outcome: Bytes32`. `clvm_tree_hash()` mirrors a single 7-tuple — no ballot list, no per-ballot outcome map.
- `RegistrationState` (`state.rs:112`): `voter_pubkey`, `election_launcher_id`, `has_voted: bool`, `vote_data: Bytes32`, `release_destination: Option<Bytes32>`. **Embeds `vote_data` directly — directly contradicts spec.**
- `VoteRecord` (`state.rs:222`): `voter_pubkey`, `vote_data`, `vote_signature_hex`, `registration_coin_id`, `vote_weight`. No `ballot_launcher_id` field.
- `VoterSet` (`state.rs:302`): SPT snapshot with `voters` and `voter_collateral` — usable as-is for per-ballot witnesses.

### 2.4 `actors/deployer.rs`
- `DeployParams` (`deployer.rs:47`): collateral, registration_fee, election_length_blocks, election_start_height, threshold num/den, VK, label. Builds eve singleton with the four-action root.
- `ElectionDeployer::build_deploy_bundle`, `deploy_signed`, `config_for_launcher`, `genesis_inner_puzzle_hash`, `election_actions_merkle_root`. Action root currently includes `register | finalize | announce_finalization | oracle` — no `createBallot`.

### 2.5 `actors/voter.rs` (~1700 lines)
- `Voter::register` (`voter.rs:184`) / `register_with_singleton[_unsigned]`: builds CAT collateral spend + XCH fee + singleton register-action spend.
- `Voter::vote` (`voter.rs:498`) / `build_vote_bundle_with_signature`: spends the Registration Coin via the `vote` action — **writes vote_data into the Registration Coin's puzzle hash** (no Voting Coin minted).
- `Voter::change_vote` (`voter.rs:696`): pairs the Registration Coin's `change_vote` action with the singleton `oracle` action — **the very dance the spec marks "superseded"**.
- `Voter::release_collateral` (`voter.rs:885`): release-action paired with `announce_finalization`.
- `vote_message(vote_data) = sha256(vote_data || election_launcher_id)` (`voter.rs:1399`, `voter.rs:1576`) — **does not include `ballot_launcher_id`**.
- No `cast_vote_for_ballot`, `change_vote_on_voting_coin`, or `mint_voting_coin` API.

### 2.6 `actors/aggregator.rs` (~3100 lines)
- `Aggregator::sync` (`aggregator.rs:154`), `collect_votes` (`aggregator.rs:198`), `prepare_finalize_witness` (`aggregator.rs:256`), `build_finalize`, `build_finalize_with_proof`, `build_finalize_with_proof_and_singleton`.
- `collect_votes` walks Registration Coin memos for `(vote_data, vote_signature)`. There is no Voting-Coin enumeration path.
- Helpers `compute_eve_inner_puzzle_hash`, `compute_election_inner_puzzle_hash_for_state`, `election_actions_merkle_root_for_config` all assume the legacy four-action set (register/finalize/announce_finalization/oracle).
- `canonical_vote_message(vote_outcome, election_id) = sha256(vote_outcome || election_id)` (`aggregator.rs:892`) — no ballot identity.
- `apply_singleton_spend` (`aggregator.rs:1427`) decodes register actions; no createBallot decoder.

### 2.7 `actors/indexer.rs`
Wraps `Aggregator::sync_with_chain` and `extract_votes`. Returns `ElectionState`, `VoterSet`, `is_finalized()`, `vote_outcome()`. **Single-outcome model** — no `ballots()`, `ballot_state(launcher)`, `voting_coins(ballot)` methods.

### 2.8 `actors/oracle.rs`
`Oracle<C>` actor whose `OracleSpend` builds an `oracle` action spend on the Election Singleton. `announcement_for_state(state) -> OracleAnnouncement` produces "oracle_finalized" or "oracle_unfinalized" messages. **The whole module exists to support `change_vote`'s required oracle co-spend — directly contradicts CHIP.md:169 which says implementations SHOULD NOT require a synchronous singleton spend for mid-ballot corrections.**

### 2.9 `prover/circuit.rs`
- `SignerWitness` (`circuit.rs:86`): `pubkey`, `leaf_index`, `merkle_proof`, `vote_weight`.
- `VotingCircuit` (`circuit.rs:100`): public inputs `registration_merkle_root`, `registration_vote_weight`, `agg_signers`, `vote_message`, `vote_threshold_num`, `vote_threshold_den`; private `signers: Vec<SignerWitness>`.
- `public_inputs_as_fr() -> [Fr; 5]` (`circuit.rs:118`) — fixed five inputs. Adding `ballot_launcher_id` is an array-shape change that ripples through `Scalars`, IC layout, and on-chain `finalize.rue`.
- `generate_constraints` (`circuit.rs:184`): only encodes weighted-quorum constraint; B/C/D deferred to on-chain.
- `generate_test_setup` (`circuit.rs:382`): produces `(ArkProvingKey, ArkVerifyingKey)`.

### 2.10 `prover/proof.rs` and `prover/conversions.rs`
`Groth16Proof` (compressed encoding), `Scalars` with five fields s1..s5, `bytes32_to_fr`, `scalars_to_fr_array`. **Five-scalar layout.**

### 2.11 `puzzles.rs`
Holds compiled hex/hash constants (`ELECTION_REGISTER_HEX`, `ELECTION_FINALIZE_HEX`, `ELECTION_ANNOUNCE_FINALIZATION_HEX`, `ELECTION_ORACLE_HEX`, `ELECTION_FINALIZER_HEX`, `REGISTRATION_VOTE_HEX`, `REGISTRATION_RELEASE_HEX`, `REGISTRATION_CHANGE_VOTE_HEX`, `REGISTRATION_FINALIZER_HEX`, `ACTION_LAYER_HEX`). No `CREATE_BALLOT_*`, no `VOTING_COIN_*`. Helpers: `voter_hint`, `fresh_registration_state_tree_hash`, `fresh_registration_inner_hash`, `fresh_registration_coin_puzzle_hash`, `oracle_finalized_message`, `oracle_unfinalized_message`, `oracle_announcement_id`, `election_singleton_puzzle_hash`, `registration_actions_merkle_root` (4-leaf), `election_actions_merkle_root` (4-leaf).

### 2.12 `merkle.rs`
`SparseMerkleTree` — depth 32, leaf binding `sha256(pk || vote_weight_be8)`. Spec-aligned, **needs no changes.**

### 2.13 `ceremony/*`
`CeremonyCoordinator`, `CeremonyParticipant`, `Transcript`, `ContributionAttestation`, `VerificationKey`, `MpcBackend`, `SimulatedBackend`, `verify_transcript`. Spec only mentions trusted setup unchanged; the transcript chain remains valid. **However the VK shape encodes `PUBLIC_INPUT_COUNT` — adding ballot identity to circuit will require a fresh ceremony.**

### 2.14 `signing.rs`, `wallet.rs`, `chain.rs`, `error.rs`, `action_spends.rs`
Plumbing — generally unaffected by spec. `VotingError::BelowThreshold` (`circuit.rs:`) is the threshold error. `error.rs` will need a few new variants (e.g. `BallotNotFound`, `BallotEnded`, `DuplicateVotingCoin`).

### 2.15 Stub / pending items
No literal `unimplemented!()` in src/. The TESTING.md coverage matrix flags as **pending**: `Voter::register` actor method, `Aggregator::sync` post-eve walk, `Aggregator::collect_votes`, `Aggregator::build_finalize` Groth16 path, `Indexer::sync`, `Indexer::vote_records`. Several of these have actually been implemented (per code grep) but are not yet wired into the canonical happy-path tests.

---

## 3. Current puzzles inventory (`C:\Users\micha\workspace\dig-network\CHIP\puzzles`)

### 3.1 `puzzles/election/shared.rue`
- `ElectionState { registration_merkle_root, registration_count, registration_vote_weight, accumulated_fees, finalized, election_start_height, vote_outcome }` — single-outcome scalar.
- `finalization_announcement_msg(vote_outcome, count, merkle_root) = sha256("finalized" || vote_outcome || count_be8 || merkle_root)`.
- `oracle_finalized_announcement_msg`, `oracle_unfinalized_announcement_msg`.
- **No ballot list, no `ballot_launcher_id` anywhere.**

### 3.2 `puzzles/election/register.rue`
Curries `(TREE_DEPTH, EMPTY_LEAF_HASH, CAT_MOD_HASH, CAT_TAIL_HASH, ACTION_LAYER_MOD_HASH, REGISTRATION_FINALIZER_MOD_HASH, REGISTRATION_MERKLE_ROOT, COLLATERAL_MIN_AMOUNT, REGISTRATION_FEE, ELECTION_LAUNCHER_ID)`. Solution: `(new_voter_pubkey, register_leaf_index, register_siblings, locked_amount, cat_parent_coin_id)`. **Includes `REGISTRATION_FEE` curry — spec drops this under recommended profile** (`CHIP.md:154`, `CHIP.md:239`).

### 3.3 `puzzles/election/finalize.rue`
Curries `VK, IC, ELECTION_LENGTH_BLOCKS, ELECTION_LAUNCHER_ID, VOTE_THRESHOLD_NUM, VOTE_THRESHOLD_DEN`. Solution: `(proof, vote_outcome_data, agg_signers, agg_sig, scalars, finalizer_destination)`. Six IC points (ic0..ic5) for **5 public-input scalars** (s1..s5). Computes `vote_message = sha256(outcome || ELECTION_LAUNCHER_ID)` — **no ballot id**. Pays `accumulated_fees` to finalizer. State transition flips `finalized → true`, sets `vote_outcome`. **One-shot**. Spec wants finalize "for a **specific ballot outcome**" (`CHIP.md:166`).

### 3.4 `puzzles/election/announce_finalization.rue`
Stateless re-announcement after `finalized == true`. Reusable as-is conceptually; in the new world, will need to be ballot-scoped (announce a specific ballot finalization).

### 3.5 `puzzles/election/oracle.rue`
Permissionless announcement of state (finalized or unfinalized variants). **Per CHIP.md:169 the oracle action SHOULD be removable** — but only if `change_vote` semantics move off the Registration Coin entirely, which requires Voting Coins.

### 3.6 `puzzles/election/finalizer.rue`
Action-layer finalizer for the singleton (recreates the singleton with new state and amount).

### 3.7 `puzzles/registration_coin/shared.rue`
- `RegistrationState { voter_pubkey, election_launcher_id, has_voted, vote_data, release_destination }`.
- `EphemeralVote { vote_data, vote_signature }`.
- **`vote_data` is a single 32-byte scalar carried *on the registration coin* — directly contradicts spec.**

### 3.8 `puzzles/registration_coin/vote.rue`
Records the voter's vote by recreating the coin with `has_voted=true, vote_data=…`. Emits AggSigUnsafe over `sha256(vote_data || election_launcher_id)`. **Should be replaced by a `cast_vote` (or `mint_voting_coin`) action that creates a Voting Coin lineage.**

### 3.9 `puzzles/registration_coin/change_vote.rue`
Updates `vote_data`. **Requires pairing with the Election Singleton `oracle` spend** in the same bundle (`AssertCoinAnnouncement` over the unfinalized oracle msg). Per CHIP.md:169 this whole pattern is superseded.

### 3.10 `puzzles/registration_coin/release.rue`
Asserts the singleton's `finalized` announcement, sets `release_destination`. Conceptually still valid; the announcement message it asserts is currently *single-outcome* — under per-ballot finalize, release rules need to be re-thought (when does collateral unlock — after any ballot? after all ballots? after the singleton's `sunset`? Spec is silent).

### 3.11 `puzzles/registration_coin/finalizer.rue`
Action-layer finalizer for the registration coin: writes vote ephemeral memos, sends collateral on release, etc.

### 3.12 Missing puzzles (per spec)
- `puzzles/election/create_ballot.rue` — **does not exist**.
- `puzzles/ballot_coin/shared.rue` and inner action puzzles — **do not exist**.
- `puzzles/voting_coin/{cast,update,freeze}.rue` — **do not exist**.

---

## 4. Gap matrix

Format: spec requirement → current state → files/lines requiring change.

### 4.1 Architecture-level gaps

| # | Spec requirement (CHIP.md ref) | Current state | Files / lines |
|---|---|---|---|
| A1 | Election Singleton has a `createBallot` action minting Ballot Coins (`CHIP.md:9, 165, 192`) | **Missing** | New: `puzzles/election/create_ballot.rue`; updated leaf list in `aggregator.rs:1840` `compute_election_action_root_leaves` and `compute_election_actions_merkle_root` (`aggregator.rs:2089`); puzzles.rs new constants; deployer must include createBallot in actions root |
| A2 | Ballot Coin type with `ballot_launcher_id`, `vote_close_height`, outcome domain (`CHIP.md:13, 69`) | **Missing** | New puzzle subtree `puzzles/ballot_coin/`; new SDK types `state::BallotState`, `state::BallotCoinSnapshot`, actor `actors/ballot.rs`; new lineage proof in aggregator |
| A3 | Voting Coin type carved from Registration Coin (`CHIP.md:15, 73, 175–183`) | **Missing** | New puzzle subtree `puzzles/voting_coin/`; new SDK actor methods `Voter::cast_vote`, `Voter::update_vote`; new state types `state::VotingCoinState`, `state::VoteRecord` extended with `ballot_launcher_id` and `voting_coin_id` |
| A4 | Vote does **not** spend Election Singleton (`CHIP.md:33, 41, 205`) | **Contradicted** — `Voter::vote` (`voter.rs:498`) spends Registration Coin, but `Voter::change_vote` (`voter.rs:696`) requires a singleton oracle co-spend (`actors/oracle.rs`, `puzzles/registration_coin/change_vote.rue`) | Remove oracle co-spend; replace with Voting-Coin self-spend |
| A5 | One vote lineage per (registration, ballot), enforced on Registration Coin (`CHIP.md:73, 179, 216`) | **Missing** — current registration coin only has a single `has_voted` flag | New per-ballot uniqueness check in registration coin (e.g., per-ballot SPT or sorted-set of consumed ballot ids) |
| A6 | Registration Coin does NOT embed per-ballot `vote_data` (`CHIP.md:71, 177`) | **Contradicts** — `RegistrationState.vote_data` carries it (`state.rs:112`, `puzzles/registration_coin/shared.rue:38`) | Drop `vote_data` from `RegistrationState`; add ballot-uniqueness witness instead |
| A7 | `oracle` action removable when Voting Coins absorb change-vote semantics (`CHIP.md:169`) | **Hard-wired** — `Oracle` actor and `change_vote.rue` depend on it (`actors/oracle.rs`, `puzzles/registration_coin/change_vote.rue`) | Delete oracle from actions-merkle-root once VC-based change_vote is wired; keep deprecation path in deployer for legacy configs |
| A8 | XCH `REGISTRATION_FEE` dropped under recommended profile (`CHIP.md:154, 239`) | **Present** — curried into `register.rue`; tracked in `ElectionState.accumulated_fees`; paid out at finalize | Remove `REGISTRATION_FEE` curry from `register.rue:633`; remove `accumulated_fees` from `ElectionState`; remove `registration_fee` from `ElectionConfig` (`config.rs:96`) and `DeployParams`; update finalize state transition |
| A9 | Finalize targets a specific ballot outcome, not the global election (`CHIP.md:166, 195`) | **Single-outcome** — `ElectionState.vote_outcome` and `finalized: bool` are scalars (`state.rs:39–46`, `shared.rue` ElectionState) | Restructure singleton state: replace `(finalized, vote_outcome)` with a per-ballot map or per-ballot finalize-on-Ballot-Coin pattern |

### 4.2 Cryptographic / circuit gaps

| # | Spec requirement | Current state | Files |
|---|---|---|---|
| C1 | `vote_message` MUST include `ballot_launcher_id` (`CHIP.md:116, 242`) | `sha256(vote_data \|\| election_launcher_id)` only | `puzzles/registration_coin/vote.rue:380`, `voter.rs:1399`, `voter.rs:1576`, `aggregator.rs:892` |
| C2 | Circuit public inputs SHOULD bind ballot identity (`CHIP.md:127–137`) | 5 inputs, no ballot id | `prover/circuit.rs:100`, `prover/proof.rs` `Scalars`, `prover/conversions.rs` `scalars_to_fr_array`, `puzzles/election/finalize.rue` `IC { ic0..ic5 }`, IC count in `config.rs:48` `PUBLIC_INPUT_COUNT=5`, VK length math `336 + (PUBLIC_INPUT_COUNT+1)*48` |
| C3 | Circuit + VK shape change requires fresh trusted setup ceremony | Existing `MpcBackend`, `SimulatedBackend` parameterised on circuit; transcript carries `circuit_id` | `ceremony/coordinator.rs:58` `start(circuit_id)`; ceremony does not pin specific circuit shape — but VK length validator in `config.rs:177` will reject old VKs |
| C4 | `bls_verify` over aggregate (already correct) | Implemented as pairing identity in finalize.rue (`puzzles/election/finalize.rue:160+`) | Need to update `vote_message` formula only |

### 4.3 Driver / SDK API gaps

| # | Spec requirement | Current state | Files |
|---|---|---|---|
| D1 | Caller can mint a Ballot Coin via `ElectionDeployer` or singleton operator API | **Missing** | New: `actors::ballot_issuer.rs` or `ElectionDeployer::create_ballot` |
| D2 | Voter API `cast_vote(ballot_launcher_id, vote_data) -> SpendBundle` that mints Voting Coin from Registration Coin | **Missing** | `voter.rs` — replace `vote`/`change_vote` |
| D3 | Voter API `update_vote(voting_coin_id, new_vote_data) -> SpendBundle` (no singleton co-spend) | **Missing**; `change_vote` exists but requires oracle | `voter.rs:696`, `actors/oracle.rs` |
| D4 | Aggregator enumerates Voting Coins by `ballot_launcher_id` (`CHIP.md:241`) | Walks Registration Coin memos | `aggregator.rs` `collect_votes` (`aggregator.rs:198`), `extract_votes`, `apply_singleton_spend` |
| D5 | Aggregator builds finalize bundle for a *specific ballot* | `build_finalize` finalizes the entire election | `aggregator.rs:456`, `:522`, `:556` |
| D6 | Indexer surfaces ballot list, per-ballot state, per-ballot votes | Single-outcome `is_finalized()`, `vote_outcome()` | `actors/indexer.rs` |
| D7 | `RegistrationState`/`VoteRecord` types include `ballot_launcher_id` | Absent | `state.rs:112`, `state.rs:222`, `state.rs:238` `VoteRecordWire` |
| D8 | `ElectionConfig` carries ballot defaults / validity windows or per-ballot policy hooks | Has only global `election_length_blocks` | `config.rs:78` |

### 4.4 Test gaps

| # | Coverage needed | Current | Files |
|---|---|---|---|
| T1 | Singleton `createBallot` action e2e on simulator | Absent | New test e.g. `tests/create_ballot_e2e.rs` |
| T2 | Voting Coin mint + update + freeze e2e | Absent | New `tests/voting_coin_e2e.rs` |
| T3 | Per-ballot finalize w/ Groth16 + ballot-scoped vote_message | Absent — current `groth16_proof_accepted_by_clvm_pairing_identity_opcode` (`tests/integration.rs:518`) tests no-ballot 5-input circuit | Update integration test |
| T4 | Aggregator enumerates Voting Coins by ballot, not Registration memos | Absent | Replace `voter_actions_e2e::vote_action_*` tests |
| T5 | Multiple ballots in flight on same singleton | Absent | New |
| T6 | Cross-ballot replay rejection (vote for ballot A cannot be reused for ballot B) | Absent | New |
| T7 | Old `oracle`-coupled `change_vote` tests | Currently exist (`actor_functions_e2e.rs`, `voter_actions_e2e.rs`) | Will need deletion or migration |

---

## 5. Migration impact ranking

Within each group, items are listed in the order they should be tackled (earlier = blocker for later).

### 5.1 (a) Puzzle changes — **earliest, source of truth**

1. **Define ballot data model in `puzzles/election/shared.rue`**: introduce `BallotEntry`, refactor `ElectionState` to a *list* of ballots or to a separate per-ballot state schema. Decide: does the singleton track all ballots, or do Ballot Coins carry their own state?
2. **Author `puzzles/election/create_ballot.rue`**: emits Ballot Coin launcher, possibly via standard CHIP-0039 launcher; updates singleton state with new ballot id + close height.
3. **Author `puzzles/ballot_coin/shared.rue` + inner actions** (e.g., `tally_close.rue`, `finalize_ballot.rue`).
4. **Author `puzzles/voting_coin/shared.rue`** with `VotingCoinState { voter_pubkey, ballot_launcher_id, vote_data, registration_coin_id }` plus actions `cast.rue`, `update.rue`, `freeze.rue`.
5. **Modify `puzzles/registration_coin/shared.rue`** to remove `vote_data`/`has_voted` scalars; add per-ballot uniqueness witness (e.g., a small SPT keyed by ballot id, or set of consumed ballot ids).
6. **Replace `puzzles/registration_coin/vote.rue`** with a `mint_voting_coin.rue` action that creates Voting Coin and asserts ballot-id uniqueness.
7. **Delete `puzzles/registration_coin/change_vote.rue`** (moved to Voting Coin update action) — and consequently `puzzles/election/oracle.rue` if no other consumer exists.
8. **Update `puzzles/election/finalize.rue`** to bind a ballot identity into `vote_message` and IC layout, AND/OR move finalize onto the Ballot Coin entirely (spec allows either pattern, see `CHIP.md:118`).
9. **Update `puzzles/election/register.rue`** to drop `REGISTRATION_FEE` curry and the `accumulated_fees` state delta.
10. **Update action layer roots** (election + registration coin + ballot coin + voting coin).
11. Recompile with `build.ps1` / `build.sh`; refresh `puzzles/compiled/**/*.{hex,hash}`.

### 5.2 (b) SDK type / data-model changes

1. `state::BallotState`, `state::VotingCoinState`, ` state::BallotIdentity` (alias for `Bytes32`).
2. Refactor `ElectionState` (`state.rs:26`) to drop `accumulated_fees`, `vote_outcome`, `finalized` (or repurpose). Add `ballots: Vec<BallotEntry>` or move per-ballot data to Ballot Coins entirely.
3. Refactor `RegistrationState` (`state.rs:112`) to drop `vote_data`/`has_voted`; add `consumed_ballots_root: Bytes32` (or analogous).
4. Extend `VoteRecord`/`VoteRecordWire` (`state.rs:222`) with `ballot_launcher_id`, `voting_coin_id`.
5. `config.rs`: drop `registration_fee`, perhaps drop `election_length_blocks` (move to per-ballot), bump `PUBLIC_INPUT_COUNT` if circuit gains ballot-id input; update `validate()` VK-length math.
6. New compiled-puzzle constants in `puzzles.rs` (`CREATE_BALLOT_*`, `BALLOT_COIN_*`, `VOTING_COIN_*`); new helpers `ballot_coin_puzzle_hash`, `voting_coin_puzzle_hash`, `voter_hint_for_ballot`.
7. Update `merkle.rs` only if a per-ballot tree shape is added; the registration SPT itself stays.
8. Adjust `error.rs` enum variants.

### 5.3 (c) Actor logic changes

1. `actors/deployer.rs`: include `createBallot` in `compute_election_action_root_leaves` (will appear at `aggregator.rs:1840` via shared helper); remove `oracle` leaf; update VK length validation via config.
2. New module `actors/ballot.rs` — issuer API: `create_ballot(close_height, outcome_domain, …) -> SpendBundle` (singleton spend) and reader API: `current_ballots()`.
3. Rewrite `actors/voter.rs`:
   - Replace `vote` (`voter.rs:498`) with `cast_vote(ballot_launcher_id, vote_data)` that builds a Registration-Coin spend creating a Voting Coin.
   - Replace `change_vote` (`voter.rs:696`) with `update_vote(voting_coin_id, new_vote_data)` (no singleton).
   - Update `vote_message` (`voter.rs:1399`) to include ballot id.
   - Adjust `release_collateral` (`voter.rs:885`) to assert per-ballot or per-deployment finalize as policy dictates.
4. `actors/aggregator.rs`:
   - Replace `collect_votes` to enumerate Voting Coins by `ballot_launcher_id`.
   - `prepare_finalize_witness` and `build_finalize` keyed by ballot id.
   - Update `compute_election_action_root_leaves` (`aggregator.rs:1840`) and `compute_election_actions_merkle_root` (`aggregator.rs:2089`) to include createBallot leaf.
   - Update `apply_singleton_spend` (`aggregator.rs:1427`) to decode `createBallot` action output.
   - `canonical_vote_message` (`aggregator.rs:892`) must include ballot id.
5. `actors/indexer.rs`: surface `ballots()`, `ballot_state(launcher) -> Option<BallotState>`, `votes_for_ballot(launcher) -> Vec<VoteRecord>`, `is_finalized_for(launcher)`.
6. **Delete `actors/oracle.rs`** once the change-vote dance is gone (or keep behind a `legacy-oracle` feature flag for already-deployed elections).

### 5.4 (d) Prover / ceremony / proof artifact changes

1. Decide: bind `ballot_launcher_id` as a 6th public input, or substitute it for `threshold_pack` (legacy 5-input shape preserved per spec line 137).
2. Update `prover::Scalars` (`prover/proof.rs`) — possibly `Scalars { s1..s6 }`; update `scalars_to_fr_array` and `bytes32_to_fr` callers.
3. Update `VotingCircuit` (`prover/circuit.rs:100`): add `ballot_launcher_id` field and 6th input.
4. Update `finalize.rue` IC struct to `IC { ic0..ic6 }` and the VK input linear combination.
5. Re-derive VK length: `336 + (NEW_PUBLIC_INPUT_COUNT + 1) * 48`. Update `config.rs:177`.
6. Re-run MPC ceremony to get a fresh VK matching the new circuit shape. Existing transcript chain in `ceremony/transcript.rs` is reusable; only the underlying constraint system changes.
7. Update `generate_test_setup` (`circuit.rs:382`) test scaffolding.

### 5.5 (e) Test changes

1. Update `tests/integration.rs:518` (`groth16_proof_accepted_by_clvm_pairing_identity_opcode`) to bind ballot id.
2. Replace `tests/voter_actions_e2e.rs::vote_action_*` with Voting-Coin mint tests.
3. Delete or quarantine `change_vote_*` tests that depend on oracle co-spend.
4. New `tests/create_ballot_e2e.rs`, `tests/voting_coin_lifecycle_e2e.rs`, `tests/finalize_per_ballot_e2e.rs`, `tests/cross_ballot_replay_rejected.rs`.
5. Update `tests/actor_functions_e2e.rs` API coverage matrix and individual test names.
6. `tests/voter_register_full_flow.rs` largely survives but needs to import the new (no-fee) register puzzle.
7. CLI integration tests (`cli/src/bin/live_integration_test.rs`, modified per gitStatus) need a parallel rewrite.

---

## 6. Open questions / ambiguities

1. **Where does ballot state live?** (`CHIP.md:69`, `:118`)
   - Spec says *"a finalize spend that consumes the Ballot Coin—**implementation selects one pattern per deployment** consistent with puzzles."*
   - Two valid patterns: (a) ballot state on Ballot Coin only, finalize spends Ballot Coin; (b) ballot state ALSO mirrored in Election Singleton, finalize spends Singleton parameterised by ballot. Choice has cascading effects on `ElectionState` shape and finalize.rue inputs. *Decision needed before any code change.*

2. **Per-ballot uniqueness on the Registration Coin** (`CHIP.md:73, 179`)
   - Spec demands enforcement but doesn't pick a witness shape. Candidates: a per-registration small SPT keyed by `ballot_launcher_id`; a sorted list with proof-of-non-membership; a Merkle proof against the singleton's known ballot set. Each has different on-chain cost and aggregator complexity. *Decision needed.*

3. **Vote message preimage exact form** (`CHIP.md:116, 242`)
   - Spec offers `sha256(outcome || ballot_launcher_id)` OR `sha256(outcome || ballot_launcher_id || election_launcher_id)`. Must be pinned for both `puzzles/voting_coin/cast.rue`, `actors/voter.rs:1399`, `actors/aggregator.rs:892`, and the circuit IC layout simultaneously.

4. **Ballot timing — global vs per-ballot.** `ElectionConfig.election_length_blocks` (`config.rs:101`) is currently global. Spec says *"ballots MAY have their own end heights carried on the Ballot Coin"* (`CHIP.md:156`) — does the SDK want a global default plus per-ballot override, or move timing entirely to `createBallot`?

5. **Release-collateral trigger under multi-ballot.** `puzzles/registration_coin/release.rue` asserts the singleton's `finalization_announcement_msg`. Under multi-ballot semantics, when does collateral unlock — when *any* ballot finalizes, when the *last scheduled* ballot finalizes, or after a deployment-level "sunset" event? **Spec is silent.** This may need a new `deployment_sunset` action on the singleton.

6. **Oracle action retirement.** `CHIP.md:169` says it MAY be omitted. Concretely: should the SDK ship a `legacy-oracle` Cargo feature so already-deployed elections can still finalize, while new deployments compute an action root without it? `actors/oracle.rs` and `puzzles/election/oracle.rue` are entangled with the old `change_vote.rue` AssertCoinAnnouncement contract.

7. **Registration fee removal — total or default-off?** `CHIP.md:154` says *"recommended profile"* — implying optional. Current `register.rue` requires it. Cleanest implementation drops it entirely; preserving it as opt-in costs additional curry args and special-case state transitions. *Decision needed.*

8. **Public-input count for the new circuit** — does the spec's "MAY add or substitute" wording (`CHIP.md:129`) mean we keep 5 inputs (substituting ballot id for threshold pack — losing the threshold-pack on-chain check), or move to 6? Each option has different VK size (`336 + 6*48 = 624` vs `336 + 7*48 = 672` bytes) and ripples through `config.rs:177`.

9. **Aggregator memo extraction location.** Spec `CHIP.md:73` says *"Memos (or equivalent) expose BLS material for aggregators"* on Voting Coins. Current code reads memos from Registration Coins (`aggregator.rs::extract_votes`). Decision: keep memo-on-VC pattern, or use hints + state introspection?

10. **Code in `aggregator.rs:3092`** — comment-only, refers to *"aggregator uses for spending, run it through"* — incomplete sentence; verify whether this hints at a partially implemented path before refactor.

---

## 7. Summary

The current implementation matches an **earlier draft of the CHIP** in which (a) votes mutate the Registration Coin in place, (b) `change_vote` requires an Election Singleton oracle co-spend, (c) there is one global outcome per election, (d) registration costs an XCH fee that the finalizer collects, and (e) there are no ballots. The current `CHIP.md` redesigns all five of these — explicitly per the changelog at `CHIP.md:230–245`. **The spec calls out, by name, that it expects puzzles/`sdk` constants to change.** Migration is therefore not a refactor but a coordinated rework of puzzles + SDK types + actor APIs + Groth16 circuit + ceremony VK + tests.

The rework's foundational decisions (ballot state location, per-ballot uniqueness witness, exact `vote_message` preimage, public-input count) are all spec-ambiguous and must be pinned **before** writing the migration plan.
