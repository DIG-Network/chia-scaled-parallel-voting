# UI migration to CHIP rev 2026-05-02 — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate the Next.js voting UI under `app/` from the pre-CHIP-rev
API (single-election finalize, registration fee, per-election vote
state) to the post-CHIP-rev architecture (one Election Singleton +
multiple Ballot Coins; per-ballot finalize; one registration shared
across all ballots). Use `cli/src/bin/live_integration_test.rs` as the
on-chain orchestration reference.

**Architecture:** Three-layer migration: (1) regenerate wasm bindings to
expose the post-CHIP-rev SDK actor APIs (BallotIssuer, per-ballot cast
vote, per-ballot finalize); (2) refactor data flow / page structure to
match the new mental model (Elections list → one Election detail →
many Ballots → per-ballot cast/finalize); (3) wire the new flows
through the existing wallet/coinset/sdk shims.

**Tech Stack:** Next.js 14 app router, Tailwind, Redux Toolkit (already
present in `app/redux/`), `chip-voting-wasm` (rebuilt), Sage wallet
connector (`@walletconnect`).

---

## Spec mental model (UI)

The CHIP rev 2026-05-02 architecture maps to these UI screens:

| Screen | Spec entity | What user does |
|--------|-------------|----------------|
| `/` (home) | Election directory | Browse all known Election Singletons. |
| `/create` | Deploy Election Singleton | One-time per deployment. Funds the launcher, runs MPC ceremony, broadcasts deploy bundle. |
| `/election/[launcher_id]` | Election detail | Sees Election state, list of registered voters (voter_set), list of all Ballot Coins under this Election. Has buttons: "Register" (if not registered), "Create new ballot" (deployer only), "Deregister + release" (if registered). |
| `/election/[launcher_id]/ballot/[ballot_launcher_id]` | Ballot detail | Sees ballot's vote_close_height, current outcome (if finalized), threshold, vote tally. Has buttons: "Cast vote" / "Update vote" (if registered + ballot still open), "Finalize" (if past close height + quorum met). |
| `/election/[launcher_id]/create-ballot` | createBallot | Deployer-only screen. Submits createBallot + launch_ballot bundles. |

Critically: **registration is per-Election, NOT per-ballot.** A single
register spend grants the voter the right to cast on every ballot
under that election. The UI must reflect this — a "Register" button on
the Election page (not the Ballot page); the Ballot page assumes the
viewer is already registered (or shows a hint pointing to Election).

---

## Stage 1 — Regenerate wasm bindings for post-CHIP-rev SDK

The current `wasm/pkg/` exports are pre-CHIP-rev (registerBuildSpends
takes a registration_fee_coin_spend; voteBuild* expects single-election
state; buildOracleBundle is the singleton oracle, not the Ballot Coin's).
Need new bindings.

### Task 1.1: Locate or recreate the wasm crate source

**Files:**
- Check: `wasm/Cargo.toml`, `wasm/src/lib.rs` (currently MISSING — only `wasm/pkg/` build output is in tree).

- [ ] **Step 1: Search git history for the wasm crate source.**

```bash
git log --all --oneline --diff-filter=A -- wasm/src/lib.rs wasm/Cargo.toml
git log --all --diff-filter=A --name-only --pretty=format: | grep '^wasm/src/' | sort -u
```

If found in a prior commit (analogous to how `app/src/` was found at
`aa33481c`), restore via `git checkout <sha> -- wasm/`.

If NOT found, recreate by mirroring `cli/src/bin/live_integration_test.rs`'s
SDK call sequence as wasm-bindgen functions. Each phase function in the
live test (phase_deploy, phase_register_voter, phase_create_ballot,
phase_launch_ballot, phase_vote, phase_finalize, phase_release) becomes
a `#[wasm_bindgen]` async function with the same arguments serialized
through JSON / Uint8Array.

### Task 1.2: Add new exports

The post-CHIP-rev SDK exposes these actor methods. Each needs a wasm
wrapper:

- [ ] `BallotIssuer::create_ballot` → `createBallotBundle(...)`
- [ ] `BallotIssuer::launch_ballot` → `launchBallotBundle(...)`
- [ ] `Voter::cast_vote` → `castVoteBuildPreviewSpend(...)` + `castVoteBuildFinalBundle(...)`
- [ ] `Voter::update_vote` → `updateVoteBuildPreviewSpend(...)` + `updateVoteBuildFinalBundle(...)`
- [ ] `Aggregator::build_finalize_for_ballot` → `buildBallotFinalizeBundle(...)`
- [ ] `Aggregator::collect_votes_for_ballot` → `collectVotesForBallot(...)`
- [ ] `BallotReader::list_ballots` → `listBallots(...)`
- [ ] `BallotReader::get_ballot` → `getBallot(...)`
- [ ] Remove: `buildRegistrationFeeXchSpend` (CHIP §191 forbids the curry).
- [ ] Remove: `buildOracleBundle` (singleton oracle is gone; Ballot Coin oracle is co-spent automatically by cast/update).

### Task 1.3: Rebuild + republish

```bash
cd wasm && wasm-pack build --target bundler --out-dir pkg
```

Verify `pkg/chip_voting_wasm.d.ts` exposes the new names; verify old
names are gone.

---

## Stage 2 — Update existing UI pages for the new mental model

### Task 2.1: `/create` page — drop registration fee

**File:** `app/app/create/page.tsx`

The deploy flow currently asks for a registration_fee mojo amount.
Per CHIP §191 ("Implementations MUST NOT curry a `REGISTRATION_FEE`"),
remove that input + remove the wasm call's registration_fee param.

### Task 2.2: `/election/[launcher_id]` page — make ballot-aware

**File:** `app/app/election/page.tsx` (likely needs to become `/election/[launcher_id]/page.tsx`)

Currently the page:
- Shows ONE election's state including a per-election finalize state and per-election vote tally.
- Has Register / Vote / Change vote / Release buttons.

Refactor to:
- Show Election state (registration_merkle_root, registration_count,
  registration_vote_weight, election_start_height) — no finalize state
  on the singleton; that lives on the Ballot Coins.
- Show a list of Ballot Coins under this Election (call `listBallots`).
- Register button → spends the singleton's `register` action, gives
  the voter a Registration Coin valid for ALL ballots.
- Per-ballot row: link to `/election/[launcher_id]/ballot/[ballot_launcher_id]`.
- "Create ballot" button (deployer-only): navigates to
  `/election/[launcher_id]/create-ballot`.
- "Deregister + release" button: spends the singleton's `deregister`
  action, releases collateral. Replaces the prior "Release" button
  which assumed post-finalize.

### Task 2.3: New `/election/[launcher_id]/ballot/[ballot_launcher_id]/page.tsx`

**Purpose:** show one ballot's state and let the viewer cast/update/finalize.

- Read Ballot Coin state via `getBallot(ballot_launcher_id)`.
- If not finalized AND viewer is registered AND chain peak < vote_close_height:
  - "Cast vote" or "Update vote" button (depending on whether the
    voter already has a Voting Coin lineage for this ballot).
- If chain peak ≥ vote_close_height AND not yet finalized:
  - "Finalize" button (anyone can run; spends the Ballot Coin's
    finalize action with a Groth16 proof aggregating the votes).
- If finalized:
  - Display vote_outcome, agg_signers count, who finalized.

### Task 2.4: New `/election/[launcher_id]/create-ballot/page.tsx`

**Purpose:** deployer creates a new ballot under this election.

- Inputs: vote_close_height (offset from current peak), threshold (num/den),
  outcome_domain_hash (or a proposal text field that hashes to it).
- Submits createBallot bundle + launch_ballot bundle (atomically, mirroring
  `cli/src/bin/live_integration_test.rs::phase_create_ballot` +
  `phase_launch_ballot`).

---

## Stage 3 — Backend / data layer changes

### Task 3.1: `app/app/lib/elections.ts` — handle multi-ballot per election

Currently treats one election as having one outcome. Refactor to:
- Election entity: launcher_id + state (no per-ballot fields).
- Ballot entity: ballot_launcher_id + per-ballot state.
- Index ballots by election_launcher_id (parent).

### Task 3.2: `app/app/lib/sdk.ts` — wire new wasm exports

Add typed wrappers around each new export. Pattern (copy from existing):

```ts
export async function createBallot(args: CreateBallotArgs): Promise<CreatedBallot> {
  const wasm = await getWasm();
  return wasm.createBallotBundle(...);
}
```

### Task 3.3: `app/app/lib/registrationFeeDiscovery.ts` — DELETE

This file discovers a 1-mojo registration fee XCH input. Per CHIP §191
the fee is removed entirely. Delete the file and remove all imports.

### Task 3.4: `app/app/lib/electionBootstrap.ts` — refactor

Bootstrap now creates Election Singleton (no per-ballot finalize state).
Ballot creation is a SEPARATE flow.

---

## Stage 4 — Components

### Task 4.1: `ElectionList.tsx` — show ballots count per election

Currently shows "X voters / finalized: yes/no". Refactor to:
"X voters / Y ballots, Z finalized".

### Task 4.2: New `BallotList.tsx` — list ballots under one election

Similar shape to ElectionList but scoped to one election; shows per-ballot
status (open / closed / finalized).

### Task 4.3: New `BallotCard.tsx` — single ballot summary tile

Shows ballot_launcher_id, vote_close_height, current outcome (if any),
threshold pack, vote tally so far.

### Task 4.4: `ElectionFinalizeQuietBanner.tsx` — relocate to Ballot screen

The "election is finalizing" banner makes no sense at election scope
anymore (election doesn't finalize; ballots do). Move to BallotCard /
ballot detail page.

---

## Stage 5 — Tests

The `app/app/probe-modal.mjs` is a Playwright/MCP browser test harness.
It currently exercises the legacy single-election finalize flow. Update
to match the new flow: deploy → register → createBallot → launchBallot →
cast → finalize. Mirror `live_orchestration_e2e.rs` step ordering.

---

## Done criteria

- `npm run build` (under `app/`) compiles cleanly.
- `npm run dev` runs the UI; pages render without runtime errors.
- Browser-driven happy-path test: can deploy + register + create ballot
  + cast + wait + finalize through the UI in a simulator (via the wasm
  shim that mocks the chain) or against testnet11.
- No references in `app/app/` to `registrationFee`, `change_vote`,
  `buildOracleBundle`, `buildFinalizeBundleFromCollectedVotes` (legacy
  names).

---

## Honest scope note

This is **multi-day work**. Stage 1 alone (wasm regen) can take a full
session — finding/restoring the wasm crate source is not guaranteed
since the search at `aa33481c` may not include `wasm/src/`. The UI
refactor (stages 2-4) touches every existing page. Stage 5 (tests) is
its own scope.

Suggested sequencing: Stage 1 first (smallest, blocks everything else),
then Stages 2.1 + 3.3 (low-risk legacy removals), then 2.2 + 2.3 + 2.4
(per-ballot flows), then Stages 4 + 5.
