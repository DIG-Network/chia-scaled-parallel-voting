// ============================================================================
// live_integration.mjs — Node.js port of cli/src/bin/live_integration_test.rs
// ============================================================================
//
// Exercises the wasm bindings against live mainnet via coinset.org
// + a JS-side JsChainBackend. Mirrors the Rust live test phase by
// phase, but every chain-touching SDK call goes through the
// `chip-voting-wasm` Node bindings instead of calling the SDK
// directly.
//
// USAGE:
//   cd wasm/integration-tests
//   npm install
//   node live_integration.mjs                          # default: read-side smoke
//   node live_integration.mjs --launcher-id 0x<hex>    # exercise listBallots / getBallot against an existing election
//   node live_integration.mjs --credentials ../../.test-credentials
//
// STAGE STATUS:
//   STAGE A — read-side smoke (DONE, this file): loads wasm, parses
//     a known ElectionConfig, hits coinset.org via JsChainBackend,
//     calls listBallots / getBallot. Validates the wasm-side wiring
//     end-to-end without spending any chia.
//
//   STAGE B — write-side phases (TODO): deploy → register →
//     create_ballot → launch_ballot → vote → finalize → release.
//     Each requires JS-side ceremony (BIP39 → BLS derivation,
//     pre-built CAT/funder spends, BLS signing). Pending in a
//     follow-up.

import wasm from "chip-voting-wasm";
import { createChainBackend } from "./chainBackend.mjs";
import { parseCredentials } from "./credentials.mjs";
import {
  coinRecordsByPuzzleHash,
  coinRecordByName,
  coinRecordsByHint,
  peakHeight,
} from "./coinset.mjs";
import {
  assertWalletMatchesAddress,
  deriveSyntheticFromMnemonic,
} from "./walletKeys.mjs";
import { pushSpendBundleBytes, pollUntilConfirmed } from "./push.mjs";
import {
  readDeployArtifacts,
  writeDeployArtifacts,
  readBallotArtifacts,
  writeBallotArtifacts,
} from "./artifacts.mjs";
import {
  encodeCoinSpendStreamable,
  encodeCoinSpendListLengthPrefixed,
} from "./encoding.mjs";

// ---------------------------------------------------------------------------
// Chain-discovery helpers — mirror what the dApp does on every page mount.
// The dApp can't trust prior-session state (fresh browser, share-bundle
// import, second device). The harness mirrors that: every write phase
// re-validates `electionStartHeight` against chain, and every read path
// pulls the voter list from chain instead of from a credentials file.
// ---------------------------------------------------------------------------

async function recoverElectionStartHeightOrFail(backend, configJson) {
  const recovered = await wasm.recoverElectionStartHeight(
    backend,
    configJson,
    60
  );
  if (recovered == null) {
    throw new Error(
      "recoverElectionStartHeight: no match in ±60 block window — " +
        "election was deployed with a different puzzle revision; " +
        "redeploy required."
    );
  }
  return BigInt(typeof recovered === "number" ? recovered : Number(recovered));
}

/**
 * Treat coinset's `push_tx` response as success when the bundle is
 * accepted into the mempool, even if it hasn't landed in a block yet.
 * Codes:
 *   - "SUCCESS" (1) — full-node accepted; included in next block.
 *   - "PENDING" (3) — accepted into mempool; awaiting confirmation.
 *   - error.includes("ALREADY_INCLUDING_TRANSACTION") — duplicate
 *     submit (e.g. retry after the first push went through but the
 *     reply didn't reach us). Equivalent to SUCCESS.
 * Anything else is a real failure (DOUBLE_SPEND, ASSERT_*, etc) and
 * gets thrown.
 */
function checkPushAccepted(response, where) {
  const isAlreadyIncluded =
    typeof response.error === "string" &&
    response.error.includes("ALREADY_INCLUDING_TRANSACTION");
  const isPending = response.status === "PENDING" || response.status === 3;
  const isSuccess =
    response.status === "SUCCESS" ||
    response.status === 1 ||
    isAlreadyIncluded ||
    isPending;
  if (!isSuccess) {
    throw new Error(
      `${where}: push_tx returned: ${response.status} (${response.error ?? "(none)"})`
    );
  }
  return {
    label: isAlreadyIncluded
      ? "ALREADY_IN_MEMPOOL"
      : isPending
        ? "PENDING_IN_MEMPOOL"
        : "SUCCESS",
  };
}

async function listRegisteredVoterPksFromChain(backend, configJson, esh) {
  const json = await wasm.listRegisteredVoters(
    backend,
    configJson,
    wasm.WasmNetwork.Mainnet,
    esh
  );
  const list = JSON.parse(json);
  return list.map((v) => v.pubkeyHex);
}

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    launcherId: null,
    credentials: null,
    verbose: false,
    configPath: null,
    runDeploy: false,
    pushDeploy: false,
    forceRedeploy: false,
    runCreateBallot: false,
    runRegister: false,
    runCastVote: false,
    voteChoice: "Yes",
    runFinalize: false,
    runRelease: false,
    runCeremonyDeploy: false,
    runCeremonyContribute: false,
    runCeremonyDeriveVk: false,
    // Default CAT TAIL: DIG token (per app/app/create/page.tsx default).
    // Voters will need a balance of this CAT to register. Override
    // with --cat-tail <hex> for a different election currency.
    catTailHashHex: "0xa406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81",
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--launcher-id") {
      out.launcherId = argv[++i];
    } else if (a === "--credentials") {
      out.credentials = argv[++i];
    } else if (a === "--config") {
      out.configPath = argv[++i];
    } else if (a === "--verbose" || a === "-v") {
      out.verbose = true;
    } else if (a === "--run-deploy") {
      out.runDeploy = true;
    } else if (a === "--push") {
      out.pushDeploy = true;
      out.runDeploy = true;
    } else if (a === "--cat-tail") {
      out.catTailHashHex = argv[++i];
    } else if (a === "--force-redeploy") {
      out.forceRedeploy = true;
    } else if (a === "--run-create-ballot") {
      out.runCreateBallot = true;
    } else if (a === "--run-register") {
      out.runRegister = true;
    } else if (a === "--run-cast-vote") {
      out.runCastVote = true;
    } else if (a === "--vote-choice") {
      out.voteChoice = argv[++i];
    } else if (a === "--run-finalize") {
      out.runFinalize = true;
    } else if (a === "--run-release") {
      out.runRelease = true;
    } else if (a === "--run-ceremony-deploy") {
      out.runCeremonyDeploy = true;
    } else if (a === "--run-ceremony-contribute") {
      out.runCeremonyContribute = true;
    } else if (a === "--run-ceremony-derive-vk") {
      out.runCeremonyDeriveVk = true;
    } else if (a === "--linked-ceremony-id") {
      // V12: optional ceremony→election link. When set, phaseDeploy
      // discovers the unspent voucher coin spawned by this finalized
      // ceremony and threads its parent_coin_info + amount into
      // deployElectionBundle so the election commits to the
      // (vk_hash, max_voters, ceremony_launcher_id) triple via
      // AssertCoinAnnouncement.
      out.linkedCeremonyId = argv[++i];
    } else if (a === "--ballot-vote-options-root") {
      // M15: per-ballot vote-mode commitment threaded into both
      // createBallotBundle and launchBallotBundle. 32-byte hex
      // (0x-prefix optional). Default 0x00…00 = Mode1Free. Set to a
      // sorted-options merkle root for Mode2Restricted (must match
      // the election's vote_mode_lock if the deploy was mode-locked).
      out.ballotVoteOptionsRootHex = argv[++i];
    } else if (a === "--ballot-options-csv") {
      // M5r-merkle-i: comma-separated label list for Mode2Restricted
      // ballots. phaseCastVote hashes each as sha256("vote:"+label),
      // builds the sorted-options merkle root (must match
      // --ballot-vote-options-root if also set), and computes the
      // inclusion proof for the cast vote_data so the on-chain
      // mint_voting_coin's M5r-merkle-e gate accepts.
      out.ballotOptionsCsv = argv[++i];
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

const COLOR = process.stdout.isTTY;
function fmt(prefix, msg) {
  if (!COLOR) return `${prefix} ${msg}`;
  const colors = { OK: 32, FAIL: 31, INFO: 36, STEP: 33, WAIT: 35 };
  const c = colors[prefix] ?? 0;
  return `\x1b[${c}m${prefix}\x1b[0m ${msg}`;
}
const ok = (m) => console.log(fmt("OK", m));
const fail = (m) => console.error(fmt("FAIL", m));
const info = (m) => console.log(fmt("INFO", m));
const step = (m) => console.log(fmt("STEP", m));

// ---------------------------------------------------------------------------
// Phase 0 — environment smoke
// ---------------------------------------------------------------------------

async function phaseEnvSmoke() {
  step("Phase 0: environment smoke");

  // Wasm load + init.
  if (typeof wasm.init !== "function") {
    throw new Error("wasm module missing `init` export — wasm-pack build mismatch?");
  }
  wasm.init();
  ok("wasm module loaded + init() called");

  // Pure-helper: sha256-style synchronous export. Validates the
  // wasm side responds even before we touch the chain.
  const electionId = "0x" + "11".repeat(32);
  const ballotId = "0x" + "22".repeat(32);
  const voteOutcome = "0x" + "33".repeat(32);
  const msg = wasm.canonicalVoteMessage(voteOutcome, ballotId, electionId);
  if (typeof msg !== "string" || !msg.startsWith("0x") || msg.length !== 66) {
    throw new Error(`canonicalVoteMessage returned unexpected shape: ${msg}`);
  }
  ok(`canonicalVoteMessage round-trip → ${msg.slice(0, 18)}…`);

  // Coinset reachability.
  const peak = await peakHeight();
  if (peak === null || peak < 1_000_000) {
    throw new Error(`peakHeight returned implausible value: ${peak}`);
  }
  ok(`coinset.org reachable, mainnet peak height = ${peak}`);
}

// ---------------------------------------------------------------------------
// Phase 1 — pure helpers (no chain)
// ---------------------------------------------------------------------------

function phasePureHelpers() {
  step("Phase 1: pure-helper exports (no chain)");

  // Real BLS12-381 G1 generator (compressed form) — a guaranteed
  // valid curve point for the round-trip exports below. The
  // generator's compressed encoding has 0x97 high bits set per the
  // chia-bls / blst convention.
  const G1_GEN_COMPRESSED =
    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

  // standardPuzzleHash: synthetic pubkey → p2 ph. Uses the G1
  // generator as a stand-in synthetic pubkey (correctness of the
  // hash output isn't asserted, just that the export doesn't throw).
  const ph = wasm.standardPuzzleHash(G1_GEN_COMPRESSED);
  if (typeof ph !== "string" || ph.length !== 66) {
    throw new Error(`standardPuzzleHash returned unexpected shape: ${ph}`);
  }
  ok(`standardPuzzleHash(G1_GEN) → ${ph.slice(0, 12)}…`);

  // voterHint: stable identity hash for SPT lineage tracking.
  const electionId = "0x" + "11".repeat(32);
  const catTail = "0x" + "44".repeat(32);
  const hint = wasm.voterHint(electionId, catTail, G1_GEN_COMPRESSED);
  if (typeof hint !== "string" || hint.length !== 66) {
    throw new Error(`voterHint returned unexpected shape: ${hint}`);
  }
  ok(`voterHint → ${hint.slice(0, 12)}…`);

  // catOuterPuzzleHash: predict the CAT outer puzzle wrapping a
  // standard p2 inner. Three-arg pure helper, no config needed.
  const innerPh = "0x" + "55".repeat(32);
  const catOuter = wasm.catOuterPuzzleHash(catTail, innerPh);
  if (typeof catOuter !== "string" || catOuter.length !== 66) {
    throw new Error(`catOuterPuzzleHash returned unexpected shape: ${catOuter}`);
  }
  ok(`catOuterPuzzleHash → ${catOuter.slice(0, 12)}…`);

  info("(freshRegistrationCoinPuzzleHash needs a full ElectionConfig — covered in Phase 2)");
}

// ---------------------------------------------------------------------------
// Phase 2 — ballot read-side (chain-walking)
// ---------------------------------------------------------------------------

/**
 * Synthesise a minimal valid ElectionConfig pointing at a launcher
 * that doesn't exist on chain. Lets Phase 2 always run: the chain
 * walker hits coinset.org for `coinRecordsByParentIds([launcher])`,
 * sees no eve singleton, and gracefully returns an empty ballot
 * list. This validates the JsChainBackend → wasm → coinset.org
 * round-trip without requiring a real on-chain election.
 *
 * Validation requires:
 *   - election_launcher_id_hex / cat_tail_hash_hex: 32-byte hex
 *   - tree_depth: 32, max_signers: 20000 (SDK constants)
 *   - verification_key_hex: 768 bytes = 1536 hex chars (336 + 9*48)
 *   - collateral_amount: any u64
 *   - label: any string or null
 */
function synthesiseMinimalConfig() {
  return JSON.stringify({
    election_launcher_id_hex: "11".repeat(32),
    cat_tail_hash_hex: "22".repeat(32),
    collateral_amount: 1000,
    tree_depth: 32,
    max_signers: 20000,
    verification_key_hex: "00".repeat(336 + 9 * 48),
    label: "wasm-integration-smoke",
  });
}

async function phaseBallotReads(opts) {
  step("Phase 2: ballot read-side exports (chain-walking)");

  let configJson;
  let configSource;
  if (opts.configPath) {
    const fs = await import("node:fs/promises");
    configJson = await fs.readFile(opts.configPath, "utf-8");
    configSource = opts.configPath;
    info(`Loaded ElectionConfig JSON from ${opts.configPath} (${configJson.length} bytes)`);
  } else {
    configJson = synthesiseMinimalConfig();
    configSource = "(synthesised minimal config — launcher 0x11…11 doesn't exist on chain)";
    info("No --config supplied; synthesising a minimal valid ElectionConfig");
    info("→ launcher_id is 0x11…11 (won't match anything on chain)");
    info("→ listBallots will return empty; chain backend round-trip still validates");
  }

  // Validate the config parses on the wasm side (catches malformed JSON early).
  const summary = wasm.parseElectionConfig(configJson);
  ok(`parseElectionConfig → launcher=${String(summary.launcherIdHex).slice(0, 18)}… cat_tail=${String(summary.catTailHashHex).slice(0, 18)}… collateral=${summary.collateralAmount}`);
  info(`(config source: ${configSource})`);

  const backend = createChainBackend({ verbose: opts.verbose });

  // listBallots
  step(" → listBallots(config)");
  const ballotsJson = await wasm.listBallots(backend, configJson);
  const ballots = JSON.parse(ballotsJson);
  ok(`listBallots returned ${ballots.length} ballot(s)`);
  for (const b of ballots) {
    const memo = b.vote_threshold_num != null ? "memo:✓" : "memo:✗";
    info(
      `   ballot ${String(b.ballot_launcher_id).slice(0, 18)}… closes_at=${b.vote_close_height} finalized=${b.state?.finalized} ${memo}`
    );
  }

  // getBallot for the first one (if any)
  if (ballots.length > 0) {
    const first = String(ballots[0].ballot_launcher_id);
    step(` → getBallot(${first.slice(0, 18)}…)`);
    const oneJson = await wasm.getBallot(backend, configJson, first);
    const one = JSON.parse(oneJson);
    if (one === null) {
      throw new Error(`getBallot returned null for a ballot that listBallots had just enumerated`);
    }
    // Curry params recovered from launcher memo (Option A). Legacy
    // ballots minted before the memo was added return null for these.
    const memoLine =
      one.vote_threshold_num != null
        ? `threshold=${one.vote_threshold_num}/${one.vote_threshold_den} reg_weight_snapshot=${one.registration_vote_weight_snapshot} reg_root_snapshot=${String(one.registration_merkle_root_snapshot).slice(0, 18)}…`
        : "(legacy: no curry memo on launcher)";
    ok(
      `getBallot round-trips: close_height=${one.vote_close_height} outcome_domain=${String(one.outcome_domain_hash).slice(0, 18)}… ${memoLine}`
    );
  } else {
    info("(No ballots to point-look-up; getBallot exercise skipped)");
  }
}

// ---------------------------------------------------------------------------
// Phase 3+ — write-side (TODO STAGE B)
// ---------------------------------------------------------------------------

async function phaseWalletCeremony(opts) {
  step("Phase 3: wallet ceremony (BIP39 → chia BLS synthetic → p2 ph)");

  if (!opts.credentials) {
    info("No --credentials supplied; skipping wallet ceremony");
    info("(Pass --credentials ../../.test-credentials to verify mnemonic→address derivation)");
    return;
  }

  const creds = await parseCredentials(opts.credentials);

  // Funder
  if (!creds.funding.mnemonic) {
    info(`Funder ${creds.funding.name} has no mnemonic comment — skipping derivation check`);
  } else {
    const { derived } = assertWalletMatchesAddress({
      mnemonic: creds.funding.mnemonic,
      address: creds.funding.address,
      label: `funder/${creds.funding.name}`,
    });
    ok(
      `funder ${creds.funding.name}: derived synthetic_pk=${derived.syntheticPkHex.slice(0, 18)}… ph=0x${derived.puzzleHashHex.slice(0, 16)}…`
    );
  }

  // Validators
  for (const v of creds.validators) {
    if (!v.mnemonic) {
      info(`validator ${v.name}: no mnemonic comment — skipping`);
      continue;
    }
    try {
      const { derived } = assertWalletMatchesAddress({
        mnemonic: v.mnemonic,
        address: v.address,
        label: `validator/${v.name}`,
      });
      ok(
        `validator ${v.name}: derived ph=0x${derived.puzzleHashHex.slice(0, 16)}… (matches address)`
      );
      // Cross-check: the credentials file's PUBKEY field should be the
      // RAW (non-synthetic) BLS pubkey at the unhardened account path,
      // i.e. what the SDK uses as voter_pubkey. NOT the synthetic key.
      // If the credentials file stores the raw pubkey, it won't equal
      // our derived syntheticPkHex — that's expected.
      if (v.pubkeyHex) {
        info(
          `   (.test-credentials VALIDATOR${v.name.match(/\d+/)?.[0] ?? "?"}_PUBKEY = ${v.pubkeyHex.slice(0, 18)}…; this is the raw BLS pk at m/12381'/8444'/2'/0 — voter identity for SPT slots)`
        );
      }
    } catch (e) {
      throw new Error(`Wallet ceremony failed for validator ${v.name}: ${e.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Phase 3.5 — phaseCeremonyDeploy (deploy Ceremony Singleton)
// ---------------------------------------------------------------------------
//
// Replaces the prior single-participant Groth16 trusted setup with the
// on-chain multi-participant ceremony. Invokes the new wasm export
// `deployCeremonyBundle` and (when --run-ceremony-deploy is set)
// pushes the bundle. Subsequent contributions and VK derivation run
// in `phaseContribute` and `phaseDeriveVk`.
//
// SCAFFOLD STATUS: bundle assembly is end-to-end; chain push is gated
// behind the explicit flag because the simulator-side coverage of the
// on-chain action layer dispatch lands in Phase 5 sub-step 3. Until
// then, --run-ceremony-deploy on mainnet is a "build-only" smoke test
// — the bundle round-trips through wasm and is dry-run-validated, but
// not pushed.
async function phaseCeremonyDeploy(opts) {
  step("Phase 3.5: deploy Ceremony Singleton");
  if (!opts.runCeremonyDeploy) {
    info("(skip — pass --run-ceremony-deploy to exercise the new on-chain ceremony deploy)");
    return null;
  }
  if (!opts.credentials) {
    throw new Error("phaseCeremonyDeploy requires --credentials <path-to-.test-credentials>");
  }
  const creds = await parseCredentials(opts.credentials);
  if (!creds.funding.mnemonic) {
    throw new Error(
      "phaseCeremonyDeploy: funder mnemonic missing from .test-credentials"
    );
  }
  const funder = deriveSyntheticFromMnemonic(creds.funding.mnemonic);
  const funderPh = "0x" + funder.puzzleHashHex;
  const coins = await coinRecordsByPuzzleHash(funderPh, false);
  const candidate = coins
    .filter((c) => c.spentHeight === 0 && c.amount >= 100)
    .sort((a, b) => b.amount - a.amount)[0];
  if (!candidate) {
    throw new Error(
      `phaseCeremonyDeploy: no unspent funder coins ≥100 mojos at ${funderPh}`
    );
  }

  const peak = await peakHeight();
  const params = {
    startBlockHeight: peak,
    ceremonyLengthBlocks: 1000,
    minParticipants: 1,
    vkSeedHex: "00".repeat(31) + "01", // canonical placeholder seed (bare hex, no 0x prefix)
    label: "harness-ceremony",
  };
  info(
    `Ceremony deploy params: startBlockHeight=${params.startBlockHeight} ` +
      `length=${params.ceremonyLengthBlocks} min=${params.minParticipants}`
  );
  // Match buildDeployBundle's coin shape: bare hex (no 0x), camelCase fields.
  const parentJs = {
    parentCoinInfo: candidate.parentCoinInfo,
    puzzleHash: candidate.puzzleHash,
    amount: candidate.amount,
    spentHeight: candidate.spentHeight,
    confirmedHeight: candidate.confirmedHeight,
  };
  const result = wasm.deployCeremonyBundle(params, parentJs, funder.syntheticPkHex);
  ok(`built ceremony deploy bundle, launcherId=${result.launcherIdHex.slice(0, 18)}…`);
  info(
    "(chain-push of the ceremony bundle is opt-in: not yet enabled even " +
      "with --push; flip the inner gate when ready to spend mainnet mojos)"
  );
  return result;
}

// ---------------------------------------------------------------------------
// Phase 3.6 — phaseContribute (loop N participant contributions)
// ---------------------------------------------------------------------------

async function phaseContribute(opts, ceremony) {
  step("Phase 3.6: submit ceremony contributions");
  if (!opts.runCeremonyContribute || !ceremony) {
    info("(skip — pass --run-ceremony-contribute and ensure phaseCeremonyDeploy ran)");
    return [];
  }
  // Operational model: contributions come from PARTICIPANTS (browsers
  // hitting /ceremony via Sage), not the harness operator. The
  // harness exercises the deploy + chain-walk + derive-vk paths;
  // the contribute path's correctness is covered by the SDK's
  // simulator e2e (`sdk/tests/ceremony_5_contributions_e2e.rs`)
  // which runs 5 chained contributions through the action layer.
  // To submit a real mainnet contribution, open
  //   http://localhost:3000/ceremony?id=<launcher_hex>
  // and use the "Generate contribution payload" button (Phase 4
  // sub-step 11+). Sage integration for the participant signing
  // path lands when chip0002_signMessageUnsafe ships (Task #26).
  info(
    "(intentionally deferred — contributions are submitted by " +
      "PARTICIPANTS via the /ceremony dApp UI, not the harness " +
      "operator. SDK simulator e2e covers the contribute path.)"
  );
  return [];
}

// ---------------------------------------------------------------------------
// Phase 3.7 — phaseDeriveVk (chain-walk + derive VK from contributions)
// ---------------------------------------------------------------------------

async function phaseDeriveVk(opts, ceremony) {
  step("Phase 3.7: derive VK from on-chain contributions");
  if (!opts.runCeremonyDeriveVk || !ceremony) {
    info("(skip — pass --run-ceremony-derive-vk after a ceremony deploy)");
    return null;
  }
  const backend = createChainBackend();
  const contributionsJson = await wasm.listCeremonyContributions(
    backend,
    ceremony.launcherIdHex
  );
  const contributions = JSON.parse(contributionsJson);
  ok(`chain-walked ${contributions.length} contribution(s)`);
  if (contributions.length === 0) {
    info("No contributions on chain yet; cannot derive a VK");
    return null;
  }
  // vk_seed is the canonical placeholder used by phaseCeremonyDeploy.
  const vkSeedHex = "00".repeat(31) + "01";
  // Min participants matches the deploy params; bump if the deploy
  // params change to keep this gate honest.
  const minParticipants = 1n;
  const vk = wasm.deriveVkFromCeremony(contributions, vkSeedHex, minParticipants);
  ok(
    `derived VK: ${(vk.raw_bytes ?? vk.rawBytes ?? []).length || "?"} bytes`
  );
  return vk;
}

// ---------------------------------------------------------------------------
// Phase 4 — phase_deploy (build + optionally push a fresh Election Singleton)
// ---------------------------------------------------------------------------

async function phaseDeploy(opts) {
  step("Phase 4: deploy a fresh Election Singleton");

  // Reuse a previously-deployed election if its launcher is still on chain.
  // Subsequent phases (register / vote / finalize / release) need this to
  // be stable across runs; redeploying every run would burn 10 mojos per
  // invocation and create stranded singletons.
  if (!opts.forceRedeploy) {
    const cached = await readDeployArtifacts();
    if (cached && cached.launcherIdHex) {
      const launcher = await coinRecordByName(cached.launcherIdHex);
      if (launcher) {
        ok(
          `Reusing cached election: launcher_id=${cached.launcherIdHex.slice(0, 18)}… ` +
            `(deployed at height ${cached.mainnetConfirmedHeight ?? "?"})`
        );
        info("(Pass --force-redeploy to deploy a fresh election anyway)");
        return cached;
      }
      info(`Cached launcher ${cached.launcherIdHex} no longer resolves on chain; redeploying`);
    }
  }

  if (!opts.runDeploy) {
    info("Skipping deploy (default). Pass --run-deploy to build the bundle");
    info("locally; pass --push to also push it to mainnet.");
    return null;
  }
  if (!opts.credentials) {
    throw new Error("phase_deploy requires --credentials <path-to-.test-credentials>");
  }

  const creds = await parseCredentials(opts.credentials);
  if (!creds.funding.mnemonic) {
    throw new Error(
      "phase_deploy: funder mnemonic missing from .test-credentials (expected `# Mnemonic: ...` after WALLET_*)"
    );
  }

  // ── 1. Derive funder synthetic secret + p2 puzzle hash ────────
  const funder = deriveSyntheticFromMnemonic(creds.funding.mnemonic);
  info(`funder p2 puzzle_hash = 0x${funder.puzzleHashHex}`);

  // ── 2. Find an unspent funder coin ────────────────────────────
  const funderPh = "0x" + funder.puzzleHashHex;
  const coins = await coinRecordsByPuzzleHash(funderPh, false);
  const candidates = coins
    .filter((c) => c.spentHeight === 0 && c.amount >= 100)
    .sort((a, b) => b.amount - a.amount); // largest first
  if (candidates.length === 0) {
    throw new Error(
      `phase_deploy: no unspent funder coins (≥100 mojos) at ${funderPh}. ` +
        `Funder may need topping up.`
    );
  }
  const parent = candidates[0];
  ok(
    `funder coin: amount=${parent.amount} mojos parent=${parent.parentCoinInfo.slice(0, 16)}…`
  );

  // ── 3. Run the trusted-setup ceremony ─────────────────────────
  step(" → trusted-setup ceremony (SimulatedBackend)");
  const ceremony = wasm.runSingleParticipantCeremony();
  ok(
    `ceremony complete: vk=${ceremony.verificationKeyHex.slice(0, 18)}… (${ceremony.verificationKeyHex.length / 2 - 1} bytes)`
  );

  // ── 4. Read peak height for election_start_height ─────────────
  const peak = await peakHeight();
  if (peak === null || peak < 1) throw new Error("could not read chain peak");
  info(`election_start_height = ${peak}`);

  // ── 5. Build the deploy bundle ────────────────────────────────
  step(" → buildDeployBundle");

  // V12: optional ceremony→election link. When --linked-ceremony-id
  // is supplied, discover the unspent voucher and thread the four
  // ceremony-link fields into params; otherwise stay on the legacy
  // unlinked path (params omits the optional fields). The wasm export
  // enforces an all-or-none rule (V10b) so partial population would
  // hard-fail at decode time.
  let linkedFields = {};
  if (opts.linkedCeremonyId) {
    step(` → V12 ceremony link discovery (id=${opts.linkedCeremonyId.slice(0, 18)}…)`);
    const backend = createChainBackend();
    const bootstrapJson = await wasm.recoverCeremonyBootstrap(
      backend,
      opts.linkedCeremonyId
    );
    if (!bootstrapJson) {
      throw new Error(
        `linked deploy: could not recover ceremony bootstrap for ${opts.linkedCeremonyId} ` +
          `(launcher unspent or memo schema mismatch)`
      );
    }
    const bootstrap = JSON.parse(bootstrapJson);
    const vkBytes = Buffer.from(
      ceremony.verificationKeyHex.replace(/^0x/, ""),
      "hex"
    );
    const { createHash } = await import("node:crypto");
    const vkHashHex = "0x" + createHash("sha256").update(vkBytes).digest("hex");
    info(`vk_hash=${vkHashHex.slice(0, 18)}… (sha256 of curried VK)`);
    const voucherRaw = await wasm.findCeremonyVoucherCoin(
      backend,
      opts.linkedCeremonyId,
      vkHashHex,
      BigInt(bootstrap.maxVoters)
    );
    if (voucherRaw == null) {
      throw new Error(
        `linked deploy: no unspent voucher found for ceremony ` +
          `${opts.linkedCeremonyId} (vk_hash=${vkHashHex}, ` +
          `max_voters=${bootstrap.maxVoters}). Verify the SimulatedBackend ` +
          `VK matches the ceremony's derived VK and that finalize has run.`
      );
    }
    const voucher = voucherRaw instanceof Map
      ? Object.fromEntries(voucherRaw)
      : voucherRaw;
    ok(
      `voucher coin: parent=${String(voucher.parentCoinIdHex).slice(0, 18)}… ` +
        `amount=${voucher.amount}`
    );
    linkedFields = {
      ceremonyLauncherIdHex: opts.linkedCeremonyId,
      vkHashHex,
      ceremonyVoucherCoinParentIdHex: voucher.parentCoinIdHex,
      ceremonyVoucherAmount: voucher.amount,
    };
  }

  const params = {
    verificationKeyHex: ceremony.verificationKeyHex,
    catTailHashHex: opts.catTailHashHex,
    collateralAmount: 1, // 1 CAT mojo per voter (placeholder; voters need actual CATs to register)
    electionStartHeight: peak,
    label: "wasm-integration-smoke",
    ...linkedFields,
  };
  // Pass parent coin in JsCoinRecord shape (bare hex, no 0x).
  const parentJs = {
    parentCoinInfo: parent.parentCoinInfo,
    puzzleHash: parent.puzzleHash,
    amount: parent.amount,
    spentHeight: parent.spentHeight,
    confirmedHeight: parent.confirmedHeight,
  };
  const artifactsRaw = wasm.buildDeployBundle(params, parentJs, funder.syntheticPkHex);
  // serde_wasm_bindgen::to_value emits a JS Map for #[serde(with = "serde_bytes")]-bearing
  // structs (camelCase field naming applies, but Map keys instead of object props).
  const artifacts = artifactsRaw instanceof Map
    ? Object.fromEntries(artifactsRaw)
    : artifactsRaw;
  ok(`launcher_id     = ${artifacts.launcherIdHex}`);
  ok(`eve_singleton   = ${artifacts.eveSingletonCoinIdHex}`);
  info(`coin_spends_bytes len = ${artifacts.coinSpendsBytes.length} (length-prefixed Streamable)`);
  info(`config_json len       = ${artifacts.configJson.length} chars`);

  // ── 6. Sign the coin_spends with the funder's synthetic secret ─
  step(" → signCoinSpends");
  const sigBytes = wasm.signCoinSpends(
    artifacts.coinSpendsBytes,
    funder.syntheticSecretBytes,
    wasm.WasmNetwork.Mainnet
  );
  ok(`signature: ${sigBytes.length} bytes (expected 96 = BLS G2)`);

  // ── 7. Assemble the SpendBundle ───────────────────────────────
  step(" → assembleSpendBundle");
  const bundleBytes = wasm.assembleSpendBundle(artifacts.coinSpendsBytes, sigBytes);
  ok(`bundle: ${bundleBytes.length} bytes (Streamable SpendBundle)`);

  // ── 8. Local validation (CLVM dry-run) ────────────────────────
  step(" → verifyBundleLocally (CLVM dry-run)");
  wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
  ok("bundle validates locally — CLVM run_program succeeded for every coin spend");

  // ── 9. Push (opt-in) ──────────────────────────────────────────
  if (opts.pushDeploy) {
    step(" → POST /push_tx (live mainnet — costs ~10 mojos)");
    const response = await pushSpendBundleBytes(bundleBytes, { network: "mainnet" });
    const status = response.status ?? "?";
    if (status !== "SUCCESS" && status !== 1) {
      throw new Error(
        `push_tx returned non-success status: ${status} (error: ${response.error ?? "(none)"})`
      );
    }
    ok(`push_tx accepted: status=${status}`);

    step(" → poll for eve singleton confirmation");
    const rec = await pollUntilConfirmed(artifacts.eveSingletonCoinIdHex, {
      label: "eveSingleton",
      pollIntervalMs: 30_000,
      timeoutMs: 600_000,
    });
    ok(
      `eve singleton confirmed at height ${rec.confirmedHeight} (parent=${rec.parentCoinInfo.slice(0, 16)}…)`
    );

    // Persist artifacts so register / vote / finalize phases can reuse
    // this election without redeploying.
    const persisted = {
      launcherIdHex: artifacts.launcherIdHex,
      eveSingletonCoinIdHex: artifacts.eveSingletonCoinIdHex,
      configJson: artifacts.configJson,
      electionStartHeight: peak,
      catTailHashHex: opts.catTailHashHex,
      mainnetConfirmedHeight: rec.confirmedHeight,
      provingKeyBytesB64: Buffer.from(ceremony.provingKeyBytes).toString("base64"),
    };
    await writeDeployArtifacts(persisted);
    ok("deploy artifacts saved to .artifacts/deploy.json");
  } else {
    info("Dry-run only (default). Re-run with --push to broadcast to mainnet.");
  }

  return {
    launcherIdHex: artifacts.launcherIdHex,
    configJson: artifacts.configJson,
    eveSingletonCoinIdHex: artifacts.eveSingletonCoinIdHex,
    electionStartHeight: peak,
    catTailHashHex: opts.catTailHashHex,
    ceremony,
    funder,
    // Threaded through so phaseFinalize can build the Groth16 proof
    // without re-reading the artifact file.
    provingKeyBytesB64: Buffer.from(ceremony.provingKeyBytes).toString(
      "base64"
    ),
  };
}

async function phaseVoterReadiness(opts, deploy) {
  step("Phase 5: voter readiness check (XCH + CAT balance per wallet)");

  if (!deploy?.configJson) {
    info("No deploy artifacts — skip readiness check");
    return;
  }
  if (!opts.credentials) {
    info("No --credentials supplied — skip readiness check");
    return;
  }

  const cfg = JSON.parse(deploy.configJson);
  const catTail = "0x" + cfg.cat_tail_hash_hex.replace(/^0x/, "");
  info(`election cat_tail_hash = ${catTail}`);
  info(`election collateral    = ${cfg.collateral_amount} CAT mojos / voter`);

  const creds = await parseCredentials(opts.credentials);

  // Funder
  if (creds.funding.mnemonic) {
    const f = deriveSyntheticFromMnemonic(creds.funding.mnemonic);
    const fp2 = "0x" + f.puzzleHashHex;
    const xch = await coinRecordsByPuzzleHash(fp2, false);
    const xchTotal = xch.reduce((s, c) => s + c.amount, 0);
    const catOuter = wasm.catOuterPuzzleHash(catTail, fp2);
    const catCoins = await coinRecordsByPuzzleHash(catOuter, false);
    const catTotal = catCoins.reduce((s, c) => s + c.amount, 0);
    ok(
      `funder ${creds.funding.name}: xch=${xchTotal} mojos (${xch.length} unspent), ` +
        `dig=${catTotal} CAT mojos (${catCoins.length} unspent)`
    );
  }

  // Validators
  const readyValidators = [];
  for (const v of creds.validators) {
    if (!v.mnemonic) continue;
    const d = deriveSyntheticFromMnemonic(v.mnemonic);
    const p2 = "0x" + d.puzzleHashHex;
    const [xch, catCoins] = await Promise.all([
      coinRecordsByPuzzleHash(p2, false),
      (async () => {
        const catOuter = wasm.catOuterPuzzleHash(catTail, p2);
        return coinRecordsByPuzzleHash(catOuter, false);
      })(),
    ]);
    const xchTotal = xch.reduce((s, c) => s + c.amount, 0);
    const catTotal = catCoins.reduce((s, c) => s + c.amount, 0);
    const canRegister = catTotal >= cfg.collateral_amount && xchTotal > 0;
    const status = canRegister ? "READY" : "NOT-READY";
    ok(
      `validator ${v.name}: xch=${xchTotal} mojos, dig=${catTotal} CAT mojos → ${status}`
    );
    if (canRegister) {
      readyValidators.push({ ...v, derived: d, catCoins });
    }
  }

  if (readyValidators.length === 0) {
    info("");
    info("No validators currently hold enough DIG CATs to register against this election.");
    info("To make register/vote/finalize work end-to-end, the funder must:");
    info(`  1. Mint or transfer DIG CATs (tail ${catTail}) to each validator`);
    info(`  2. Each validator needs ≥${cfg.collateral_amount} DIG mojos for collateral`);
    info(`  3. Each validator needs some XCH for the bundle's mempool fees`);
    info("phase_register_voter is wired but skipped without ready validators.");
  } else {
    ok(`${readyValidators.length} validator(s) ready to register`);
  }
  return readyValidators;
}

// ---------------------------------------------------------------------------
// Phase 6 — phase_create_ballot (operator creates a fresh Ballot Coin lineage)
// ---------------------------------------------------------------------------

async function phaseCreateBallot(opts, deploy) {
  step("Phase 6: create + launch a Ballot Coin");

  if (!opts.runCreateBallot) {
    info("Skipping create_ballot (default). Pass --run-create-ballot to attempt.");
    return null;
  }
  if (!deploy?.configJson) {
    throw new Error("create_ballot needs deploy artifacts (run phase_deploy first)");
  }
  if (!opts.credentials) {
    throw new Error("create_ballot needs --credentials");
  }

  const creds = await parseCredentials(opts.credentials);
  if (!creds.funding.mnemonic) {
    throw new Error("funder mnemonic missing");
  }
  const funder = deriveSyntheticFromMnemonic(creds.funding.mnemonic);

  // ── 1. Find an XCH funder coin (≥ 2 mojos for the launcher) ────
  const fp2Hex = "0x" + funder.puzzleHashHex;
  const xchCoins = await coinRecordsByPuzzleHash(fp2Hex, false);
  // Need a coin > 2 so change > 0 and the StandardLayer spend has a
  // condition to wrap (delegatedSpend([]) panics inside chia-wallet-
  // sdk-wasm). Picking the smallest >= 100 keeps the bundle tiny but
  // still has change.
  const candidates = xchCoins
    .filter((c) => c.spentHeight === 0 && c.amount >= 100)
    .sort((a, b) => a.amount - b.amount); // smallest viable first
  if (candidates.length === 0) {
    throw new Error("no funder XCH coin (≥ 100 mojos) for createBallot funding");
  }
  const funderCoin = candidates[0];
  ok(`funder XCH coin: amount=${funderCoin.amount} mojos`);

  // ── 2. Build the funder StandardLayer spend via wasm helper ─────
  const change = funderCoin.amount - 2;
  const funderSpendBytes = wasm.buildXchFunderSpend(
    "0x" + funderCoin.parentCoinInfo,
    funder.syntheticPkHex,
    BigInt(funderCoin.amount),
    BigInt(change)
  );
  ok(`funder spend assembled: ${funderSpendBytes.length} streamable bytes`);

  // ── 3. Pick ballot params ──────────────────────────────────────
  // ballot_seed: random 32 bytes for uniqueness across runs.
  const ballotSeed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(ballotSeed);
  const ballotSeedHex = "0x" + bytesToHex(ballotSeed);
  // outcome_domain_hash: arbitrary 32-byte hash binding the choices.
  // Using a known marker so this is identifiable on chain.
  const outcomeDomainHashHex = "0x" + "01".repeat(32);
  // vote_close_height: peak + ~50 blocks (~25 minutes mainnet).
  const peak = await peakHeight();
  const voteCloseHeight = peak + 50;
  info(`ballot_seed         = ${ballotSeedHex.slice(0, 18)}…`);
  info(`outcome_domain_hash = ${outcomeDomainHashHex.slice(0, 18)}…`);
  info(`vote_close_height   = ${voteCloseHeight} (peak ${peak} + 50)`);

  // M15: per-ballot vote-mode commitment. Default 0x00…00 = Mode1Free.
  const ballotVoteOptionsRootHex = (() => {
    const raw = opts.ballotVoteOptionsRootHex ?? ("0x" + "00".repeat(32));
    return raw.startsWith("0x") ? raw : "0x" + raw;
  })();
  info(
    `ballot vote_options_root = ${ballotVoteOptionsRootHex.slice(0, 18)}…` +
      (opts.ballotVoteOptionsRootHex ? " (Mode2Restricted)" : " (Mode1Free)")
  );

  const params = {
    ballotSeedHex,
    voteCloseHeight,
    outcomeDomainHashHex,
    voteOptionsRootHex: ballotVoteOptionsRootHex,
  };

  // ── 4. Call wasm.createBallotBundle ───────────────────────────
  step(" → wasm.createBallotBundle");
  const backend = createChainBackend({ verbose: opts.verbose });
  // Mirror the dApp: re-validate electionStartHeight against chain
  // before any write spend. Off-by-one in this value produces a
  // completely different eve_ph (sha cascade) and dry_run rejects.
  const chainEsh = await recoverElectionStartHeightOrFail(
    backend,
    deploy.configJson
  );
  const resultJson = await wasm.createBallotBundle(
    backend,
    deploy.configJson,
    funderSpendBytes,
    JSON.stringify(params),
    wasm.WasmNetwork.Mainnet,
    chainEsh
  );
  const created = JSON.parse(resultJson);
  ok(`ballot_launcher_id = ${created.ballotLauncherIdHex}`);
  ok(`ballot_coin_id     = ${created.ballotCoinIdHex}`);

  // ── 5. Re-sign the bundle with the funder's synthetic SK ──────
  // The createBallotBundle produces a bundle with identity sig (no
  // AGG_SIG inside the singleton spend), but the funder's
  // StandardLayer spend emits AGG_SIG_ME(synthPk, msg). Re-sign so
  // chia consensus accepts.
  step(" → re-sign bundle with funder synthetic SK");
  const bundleHex = created.spendBundleHex;
  const bundleBytes = hexToBytesU8(bundleHex);
  // Round-trip the bundle's coin_spends through wasm so the
  // length-prefixed list bytes are byte-identical to what wasm's
  // decode_coin_spends expects (avoids any JS encoding quirks
  // around chia_protocol::Program's Streamable form).
  const coinSpendsBytesLP = wasm.extractCoinSpendsFromBundle(bundleBytes);
  const sigBytes = wasm.signCoinSpends(
    coinSpendsBytesLP,
    funder.syntheticSecretBytes,
    wasm.WasmNetwork.Mainnet
  );
  ok(`re-signed: ${sigBytes.length}-byte aggregate`);
  const finalBundleBytes = wasm.assembleSpendBundle(coinSpendsBytesLP, sigBytes);
  step(" → verifyBundleLocally");
  wasm.verifyBundleLocally(finalBundleBytes, wasm.WasmNetwork.Mainnet);
  ok("create_ballot bundle validates locally");

  // ── 6. Push (opt-in) ──────────────────────────────────────────
  if (opts.pushDeploy) {
    step(" → push createBallot bundle");
    const response = await pushSpendBundleBytes(finalBundleBytes, { network: "mainnet" });
    if (response.status !== "SUCCESS" && response.status !== 1 && response.status !== "PENDING" && response.status !== 3) {
      throw new Error(`push_tx returned: ${response.status} (${response.error ?? "(none)"})`);
    }
    ok(`push_tx accepted: ${response.status}`);

    step(" → poll for ballot launcher confirmation");
    const rec = await pollUntilConfirmed(created.ballotLauncherIdHex, {
      label: "ballotLauncher",
      pollIntervalMs: 30_000,
      timeoutMs: 600_000,
    });
    ok(`ballot launcher confirmed at height ${rec.confirmedHeight}`);

    // Persist
    const ballots = await readBallotArtifacts();
    ballots.push({
      ballotLauncherIdHex: created.ballotLauncherIdHex,
      ballotCoinIdHex: created.ballotCoinIdHex,
      voteCloseHeight,
      outcomeDomainHashHex,
      ballotSeedHex,
      mainnetConfirmedHeight: rec.confirmedHeight,
    });
    await writeBallotArtifacts(ballots);
    ok("ballot artifact saved to .artifacts/ballots.json");
  } else {
    info("Dry-run only. Pass --push to broadcast.");
  }

  return {
    ...created,
    voteCloseHeight,
    outcomeDomainHashHex,
    ballotSeedHex,
  };
}

// Inline hex helpers (avoid pulling chia-wallet-sdk-wasm just for fromHex).
function hexToBytesU8(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Phase 7 — phase_launch_ballot (second-spend the ballot launcher → eve)
// ---------------------------------------------------------------------------

async function phaseLaunchBallot(opts, deploy, createdBallot) {
  step("Phase 7: launch the ballot eve singleton");

  if (!opts.runCreateBallot) {
    info("Skipping launch (default — paired with --run-create-ballot)");
    return null;
  }
  if (!createdBallot?.ballotLauncherIdHex) {
    info("Skipping launch — phase_create_ballot didn't produce a launcher");
    return null;
  }

  // Wait until the ballot launcher coin is itself spendable (it must
  // exist on chain). createBallot already polled for confirmation
  // when --push was used; in dry-run the coin doesn't exist so we
  // skip.
  if (!opts.pushDeploy) {
    info("(create_ballot wasn't pushed; skipping launch — re-run with --push)");
    return null;
  }

  const ballotLauncherIdHex = createdBallot.ballotLauncherIdHex.startsWith("0x")
    ? createdBallot.ballotLauncherIdHex
    : "0x" + createdBallot.ballotLauncherIdHex;
  info(`launching ballot ${ballotLauncherIdHex.slice(0, 18)}…`);

  // Per-ballot params: same vote_close_height + outcome_domain we used
  // at create. Threshold = 1/2 (strict majority of weight).
  // M15: vote_options_root MUST byte-equal what create_ballot used,
  // or the predicted eve Ballot Coin puzzle hash mismatches chain.
  const launchVoteOptionsRootHex = (() => {
    const raw = opts.ballotVoteOptionsRootHex ?? ("0x" + "00".repeat(32));
    return raw.startsWith("0x") ? raw : "0x" + raw;
  })();
  const params = {
    voteCloseHeight: createdBallot.voteCloseHeight ?? deploy.electionStartHeight + 50,
    outcomeDomainHashHex: createdBallot.outcomeDomainHashHex ?? "0x" + "01".repeat(32),
    voteThresholdNum: 1,
    voteThresholdDen: 2,
    voteOptionsRootHex: launchVoteOptionsRootHex,
  };

  // Capture the Election Singleton's state RIGHT BEFORE launch so the
  // ballot's curried snapshot can be persisted alongside ballot metadata
  // — every subsequent phase (cast_vote / update_vote / finalize /
  // announce) MUST pass these exact values or the eve Ballot Coin's
  // curry diverges from chain. The SDK reads its own copy inside
  // launchBallot; ours observe the same chain tip so they agree by
  // construction (modulo a concurrent register landing mid-phase).
  const snapshotBackend = createChainBackend({ verbose: opts.verbose });
  // Recover esh from chain (mirrors dApp behavior).
  const chainEsh = await recoverElectionStartHeightOrFail(
    snapshotBackend,
    deploy.configJson
  );
  step(" → wasm.readElectionSingletonState (snapshot pre-launch)");
  const stateJson = await wasm.readElectionSingletonState(
    snapshotBackend,
    deploy.configJson,
    chainEsh
  );
  const preLaunchState = JSON.parse(stateJson);
  ok(
    `pre-launch snapshot: count=${preLaunchState.registrationCount} ` +
      `vote_weight=${preLaunchState.registrationVoteWeight} ` +
      `root=${String(preLaunchState.registrationMerkleRootHex).slice(0, 18)}…`
  );

  const backend = createChainBackend({ verbose: opts.verbose });
  step(" → wasm.launchBallotBundle");
  const resultJson = await wasm.launchBallotBundle(
    backend,
    deploy.configJson,
    ballotLauncherIdHex,
    JSON.stringify(params),
    wasm.WasmNetwork.Mainnet,
    chainEsh
  );
  const launched = JSON.parse(resultJson);
  ok(`eve_ballot_coin_id    = ${launched.eveBallotCoinIdHex}`);
  ok(`eve_ballot_puzzle_hash = ${launched.eveBallotPuzzleHashHex}`);

  // The launcher spend has no AGG_SIG conditions — the bundle's
  // identity sig is sufficient. Just verify + push.
  step(" → verifyBundleLocally");
  const bundleBytes = hexToBytesU8(launched.spendBundleHex);
  wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
  ok("launch_ballot bundle validates locally");

  step(" → push launchBallot bundle");
  const response = await pushSpendBundleBytes(bundleBytes, { network: "mainnet" });
  if (response.status !== "SUCCESS" && response.status !== 1 && response.status !== "PENDING" && response.status !== 3) {
    throw new Error(`push_tx returned: ${response.status} (${response.error ?? "(none)"})`);
  }
  ok(`push_tx accepted: ${response.status}`);

  step(" → poll for eve ballot coin confirmation");
  const rec = await pollUntilConfirmed(launched.eveBallotCoinIdHex, {
    label: "eveBallotCoin",
    pollIntervalMs: 30_000,
    timeoutMs: 600_000,
  });
  ok(`eve ballot coin confirmed at height ${rec.confirmedHeight}`);

  // Persist the launched ballot's eve info alongside the createBallot record.
  const ballots = await readBallotArtifacts();
  const target = ballots.find(
    (b) => b.ballotLauncherIdHex === createdBallot.ballotLauncherIdHex
  );
  if (target) {
    target.eveBallotCoinIdHex = launched.eveBallotCoinIdHex;
    target.eveBallotPuzzleHashHex = launched.eveBallotPuzzleHashHex;
    target.launchedAtHeight = rec.confirmedHeight;
    target.voteThresholdNum = params.voteThresholdNum;
    target.voteThresholdDen = params.voteThresholdDen;
    target.registrationMerkleRootSnapshotHex = preLaunchState.registrationMerkleRootHex;
    target.registrationVoteWeightSnapshot = preLaunchState.registrationVoteWeight;
    target.registrationCountSnapshot = preLaunchState.registrationCount;
    await writeBallotArtifacts(ballots);
    ok("ballot artifact updated with launch info + snapshot");
  }
  return launched;
}

// ---------------------------------------------------------------------------
// Phase 8 — phase_register_voter (each ready validator joins the SPT)
// ---------------------------------------------------------------------------

async function phaseRegisterVoter(opts, deploy) {
  step("Phase 8: register validators against the deployed election");

  if (!opts.runRegister) {
    info("Skipping register (default). Pass --run-register to attempt.");
    return null;
  }
  if (!deploy?.configJson) throw new Error("register needs deploy artifacts");
  if (!opts.credentials) throw new Error("register needs --credentials");

  const cfg = JSON.parse(deploy.configJson);
  const catTail = "0x" + cfg.cat_tail_hash_hex.replace(/^0x/, "");
  const collateral = cfg.collateral_amount;
  const electionLauncherIdHex = "0x" + cfg.election_launcher_id_hex.replace(/^0x/, "");

  const creds = await parseCredentials(opts.credentials);
  const validatorsToRegister = [];

  // Collect raw pubkeys for the SMT — register's non-membership proof
  // requires the SMT NOT to include the voter being registered.
  const allValidatorPubkeysHex = [];
  for (const v of creds.validators) {
    if (!v.mnemonic) continue;
    const d = deriveSyntheticFromMnemonic(v.mnemonic);
    // The "voter pubkey" used for SPT slot derivation is the RAW BLS
    // pubkey at m/12381'/8444'/2'/0 (NOT the synthetic). Recompute
    // separately.
    const { Mnemonic, SecretKey } = await import("chia-wallet-sdk-wasm");
    const mn = new Mnemonic(v.mnemonic);
    const seed = mn.toSeed("");
    const master = SecretKey.fromSeed(seed);
    const account = master.deriveUnhardenedPath(new Uint32Array([12381, 8444, 2, 0]));
    const accountSk = account.toBytes();
    const accountPkHex = "0x" + bytesToHex(account.publicKey().toBytes());
    allValidatorPubkeysHex.push(accountPkHex);
    validatorsToRegister.push({
      v,
      derived: d,
      accountSecretBytes: accountSk,
      accountPkHex,
      p2: "0x" + d.puzzleHashHex,
    });
  }

  // Recover esh from chain ONCE before the loop (mirrors dApp's
  // self-heal in handleRegister — every write spend re-validates esh).
  const eshBackend = createChainBackend({ verbose: opts.verbose });
  const chainEsh = await recoverElectionStartHeightOrFail(
    eshBackend,
    deploy.configJson
  );

  const registered = [];
  for (const entry of validatorsToRegister) {
    info(`\n--- Registering ${entry.v.name} (${entry.accountPkHex.slice(0, 18)}…) ---`);

    // Weighted-voting revision: each voter chooses how much CAT to
    // lock, bounded below by the curried `collateral_amount`
    // minimum. For this harness every validator locks the floor —
    // varied amounts require pre-minted CAT coins at multiple sizes,
    // see harness setup. Locking 5x at one validator (whale) +
    // floor at others would prove non-uniform weights end-to-end.
    const lockAmount = collateral;

    // Find a CAT coin owned by this validator
    const catOuter = wasm.catOuterPuzzleHash(catTail, entry.p2);
    const catCoins = await coinRecordsByPuzzleHash(catOuter, false);
    const ready = catCoins
      .filter((c) => c.spentHeight === 0 && c.amount >= lockAmount)
      .sort((a, b) => a.amount - b.amount);
    if (ready.length === 0) {
      info(`  no CAT coin >= ${lockAmount} mojos for ${entry.v.name}; skipping`);
      continue;
    }
    const catCoin = ready[0];
    // Compute coin id manually: sha256(parent || ph || amount_be8)
    const catCoinIdHex = await computeCoinId(catCoin);
    ok(`  CAT input coin: amount=${catCoin.amount} id=${catCoinIdHex.slice(0, 18)}…`);

    // Build the CAT registration parent spend.
    // Final positional arg here is the voter's chosen `lock_amount`
    // (formerly `collateral_amount`) — what the on-chain register
    // action will assert against `int_to_8_bytes_be(locked_cat_mojos)`
    // in the create_reg announcement preimage.
    step("   → wasm.buildCatRegistrationSpend");
    const backend = createChainBackend({ verbose: opts.verbose });
    const catParentSpendBytes = await wasm.buildCatRegistrationSpend(
      backend,
      "0x" + bytesToHex(entry.accountSecretBytes),
      "0x" + catCoinIdHex,
      electionLauncherIdHex,
      catTail,
      BigInt(lockAmount)
    );
    ok(`  CAT parent spend: ${catParentSpendBytes.length} streamable bytes`);

    // Call wasm.registerBuildSpends
    step("   → wasm.registerBuildSpends");
    const backend2 = createChainBackend({ verbose: opts.verbose });
    const bundleHex = await wasm.registerBuildSpends(
      backend2,
      deploy.configJson,
      "0x" + bytesToHex(entry.accountSecretBytes),
      catParentSpendBytes,
      BigInt(lockAmount),
      wasm.WasmNetwork.Mainnet,
      chainEsh
    );
    const bundleBytes = hexToBytesU8(bundleHex);
    ok(`  register bundle: ${bundleBytes.length} bytes (SDK-signed: voter account_sk only)`);

    // SDK's Voter::register signs with the voter's account secret only;
    // the CAT spend's StandardLayer emits AGG_SIG_ME(synthetic_pk, …)
    // which needs synthetic_sk. Re-sign with both keys so the bundle's
    // aggregate covers every AGG_SIG condition. (Mirrors the rust
    // live_integration_test.rs::phase_register_voter re-sign step.)
    step("   → re-sign with [account_sk, synthetic_sk]");
    const coinSpendsBytesLP = wasm.extractCoinSpendsFromBundle(bundleBytes);
    const bothSecrets = new Uint8Array(64);
    bothSecrets.set(entry.accountSecretBytes, 0);
    bothSecrets.set(entry.derived.syntheticSecretBytes, 32);
    const sigBytes = wasm.signCoinSpends(
      coinSpendsBytesLP,
      bothSecrets,
      wasm.WasmNetwork.Mainnet
    );
    const finalBundleBytes = wasm.assembleSpendBundle(coinSpendsBytesLP, sigBytes);
    ok(`  re-signed: ${sigBytes.length}-byte aggregate, final bundle ${finalBundleBytes.length} bytes`);

    step("   → verifyBundleLocally");
    wasm.verifyBundleLocally(finalBundleBytes, wasm.WasmNetwork.Mainnet);
    ok("  bundle validates locally");

    if (opts.pushDeploy) {
      step("   → push register bundle");
      const response = await pushSpendBundleBytes(finalBundleBytes, { network: "mainnet" });
      // ALREADY_INCLUDING_TRANSACTION means the bundle is already in
      // mempool (e.g. from a prior attempt that lost the response) —
      // treat as success and proceed to poll for the reg coin.
      const isAlreadyIncluded =
        typeof response.error === "string" && response.error.includes("ALREADY_INCLUDING_TRANSACTION");
      if (response.status !== "SUCCESS" && response.status !== 1 && !isAlreadyIncluded && response.status !== "PENDING" && response.status !== 3) {
        throw new Error(`push: ${response.status} (${response.error ?? "(none)"})`);
      }
      ok(`  push_tx accepted: ${isAlreadyIncluded ? "ALREADY_IN_MEMPOOL" : response.status}`);

      // Poll for the registration coin to confirm: its predicted ph is
      // freshRegistrationCoinPuzzleHash(config, voter_pk).
      const regPh = wasm.freshRegistrationCoinPuzzleHash(
        deploy.configJson,
        entry.accountPkHex
      );
      info(`  predicted reg coin ph: ${regPh.slice(0, 18)}…`);
      // Wait for any unspent coin at this ph (the reg coin)
      const started = Date.now();
      let regCoin = null;
      while (Date.now() - started < 600_000) {
        const coins = await coinRecordsByPuzzleHash(regPh, false);
        const unspent = coins.find((c) => c.spentHeight === 0);
        if (unspent) {
          regCoin = unspent;
          break;
        }
        await new Promise((r) => setTimeout(r, 30_000));
      }
      if (!regCoin) {
        throw new Error(`reg coin for ${entry.v.name} not visible after 600s`);
      }
      ok(`  reg coin confirmed: amount=${regCoin.amount} (height ${regCoin.confirmedHeight})`);
      registered.push({ ...entry, regCoin, regPh });
    } else {
      info("  Dry-run only — pass --push to broadcast");
    }
  }

  return registered;
}

/** Compute coin id via chia-wallet-sdk-wasm's canonical Coin.coinId(). */
async function computeCoinId(coinRecord) {
  const { Coin } = await import("chia-wallet-sdk-wasm");
  const coin = new Coin(
    hexToBytesU8(coinRecord.parentCoinInfo),
    hexToBytesU8(coinRecord.puzzleHash),
    BigInt(coinRecord.amount)
  );
  return bytesToHex(coin.coinId());
}

// ---------------------------------------------------------------------------
// Phase 9 — phase_cast_vote (each registered validator casts a vote on the
// most recently-launched open ballot)
// ---------------------------------------------------------------------------

async function phaseCastVote(opts, deploy) {
  step("Phase 9: cast_vote against the most-recently-launched open ballot");

  if (!opts.runCastVote) {
    info("Skipping cast_vote (default). Pass --run-cast-vote to attempt.");
    return null;
  }
  if (!deploy?.configJson) throw new Error("cast_vote needs deploy artifacts");
  if (!opts.credentials) throw new Error("cast_vote needs --credentials");

  // Pick a launched ballot whose vote_close_height is still in the future
  // AND whose snapshot is non-empty (i.e. was launched after at least one
  // register). Old empty-snapshot ballots from earlier runs are ignored.
  const ballots = await readBallotArtifacts();
  const peak = await peakHeight();
  info(`current peak = ${peak}`);
  const candidate = ballots
    .filter(
      (b) =>
        b.eveBallotCoinIdHex &&
        b.voteCloseHeight > peak &&
        b.registrationMerkleRootSnapshotHex &&
        b.registrationVoteWeightSnapshot > 0
    )
    .sort((a, b) => b.launchedAtHeight - a.launchedAtHeight)[0];
  if (!candidate) {
    throw new Error(
      "phase_cast_vote: no open ballot with non-empty registration snapshot. " +
        "Run --run-create-ballot --run-register --run-cast-vote in one pass " +
        "so the new ballot is launched after the validators are registered."
    );
  }
  ok(
    `selected ballot ${candidate.ballotLauncherIdHex.slice(0, 18)}… ` +
      `(close_height=${candidate.voteCloseHeight}, vote_weight_snapshot=${candidate.registrationVoteWeightSnapshot})`
  );

  // vote_data per app/lib/elections.ts convention: sha256("vote:" + label).
  const choice = opts.voteChoice ?? "Yes";
  const voteDataBytes = await sha256Bytes(new TextEncoder().encode(`vote:${choice}`));
  const voteDataHex = "0x" + bytesToHex(voteDataBytes);
  info(`vote choice = "${choice}" → vote_data=${voteDataHex.slice(0, 18)}…`);

  const creds = await parseCredentials(opts.credentials);
  const cast = [];
  for (const v of creds.validators) {
    if (!v.mnemonic) continue;

    // Re-derive the validator's account-path BLS secret (the voter's
    // identity key — same one phase_register_voter used).
    const { Mnemonic, SecretKey } = await import("chia-wallet-sdk-wasm");
    const mn = new Mnemonic(v.mnemonic);
    const seed = mn.toSeed("");
    const master = SecretKey.fromSeed(seed);
    const account = master.deriveUnhardenedPath(new Uint32Array([12381, 8444, 2, 0]));
    const accountSecretBytes = account.toBytes();
    const accountPkHex = "0x" + bytesToHex(account.publicKey().toBytes());

    // Sanity: confirm this voter is in the SMT snapshot. The SDK's
    // cast_vote walks the chain to find the registration coin via hint;
    // if it's not there we skip rather than burn mojos on a doomed bundle.
    const regPh = wasm.freshRegistrationCoinPuzzleHash(deploy.configJson, accountPkHex);
    const regCoins = await coinRecordsByPuzzleHash(regPh, false);
    const unspentReg = regCoins.find((c) => c.spentHeight === 0);
    if (!unspentReg) {
      info(`  ${v.name}: no unspent registration coin at predicted ph — skipping`);
      continue;
    }
    info(
      `--- Casting ${v.name} (pk=${accountPkHex.slice(0, 18)}…, reg_coin amount=${unspentReg.amount}) ---`
    );

    // M5r-merkle-i: when --ballot-options-csv is set, derive the
    // (vote_options_root, leaf_index, proof) trio for the cast and
    // thread into params so the puzzle's M5r-merkle-e gate accepts.
    let modeRestrictedFields = {};
    if (opts.ballotOptionsCsv) {
      const labels = opts.ballotOptionsCsv
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      if (labels.length < 2) {
        throw new Error(
          `--ballot-options-csv must contain at least 2 labels (got ${labels.length})`
        );
      }
      const optionHashes = [];
      for (const label of labels) {
        const enc = new TextEncoder().encode("vote:" + label);
        const h = await sha256Bytes(enc);
        optionHashes.push(bytesToHex(h));
      }
      const concat = optionHashes.join("");
      const derivedRootRaw = await wasm.merkleRootOfSortedCoinIds(concat);
      const derivedRoot = derivedRootRaw.startsWith("0x")
        ? derivedRootRaw.toLowerCase()
        : "0x" + derivedRootRaw.toLowerCase();
      // Cross-check against --ballot-vote-options-root if non-zero.
      if (opts.ballotVoteOptionsRootHex) {
        const flagRoot = opts.ballotVoteOptionsRootHex.startsWith("0x")
          ? opts.ballotVoteOptionsRootHex.toLowerCase()
          : "0x" + opts.ballotVoteOptionsRootHex.toLowerCase();
        const FREE = "0x" + "00".repeat(32);
        if (flagRoot !== FREE && flagRoot !== derivedRoot) {
          throw new Error(
            `--ballot-options-csv derives ${derivedRoot} but ` +
              `--ballot-vote-options-root is ${flagRoot} — operator ` +
              `labels don't match the locked ballot`
          );
        }
      }
      const target = voteDataHex.startsWith("0x")
        ? voteDataHex
        : "0x" + voteDataHex;
      const proofRaw = await wasm.merkleProofForOption(concat, target);
      if (proofRaw == null) {
        throw new Error(
          `vote choice "${choice}" is NOT in --ballot-options-csv — cast ` +
            `would raise the M5r-merkle-e gate`
        );
      }
      const proof = proofRaw instanceof Map
        ? Object.fromEntries(proofRaw)
        : proofRaw;
      modeRestrictedFields = {
        voteOptionsRootHex: derivedRoot,
        voteOptionLeafIndex: Number(proof.leafIndex),
        voteOptionProofHex: proof.proofHex,
      };
      info(
        `Mode2Restricted: leaf_index=${modeRestrictedFields.voteOptionLeafIndex}, ` +
          `proof_depth=${modeRestrictedFields.voteOptionProofHex.length}`
      );
    }

    const params = {
      ballotLauncherIdHex: "0x" + candidate.ballotLauncherIdHex.replace(/^0x/, ""),
      voteDataHex,
      voteCloseHeight: candidate.voteCloseHeight,
      voteThresholdNum: candidate.voteThresholdNum ?? 1,
      voteThresholdDen: candidate.voteThresholdDen ?? 2,
      registrationMerkleRootSnapshotHex: candidate.registrationMerkleRootSnapshotHex,
      registrationVoteWeightSnapshot: candidate.registrationVoteWeightSnapshot,
      votingCoinAmount: 1,
      ...modeRestrictedFields,
    };

    step("   → wasm.castVoteBuildFinalBundle");
    const backend = createChainBackend({ verbose: opts.verbose });
    // Mirror dApp: re-validate esh against chain before each write.
    const chainEsh = await recoverElectionStartHeightOrFail(
      backend,
      deploy.configJson
    );
    const resultJson = await wasm.castVoteBuildFinalBundle(
      backend,
      deploy.configJson,
      "0x" + bytesToHex(accountSecretBytes),
      JSON.stringify(params),
      wasm.WasmNetwork.Mainnet,
      chainEsh
    );
    const result = JSON.parse(resultJson);
    ok(`  voting_coin_id  = ${result.votingCoinIdHex}`);
    ok(`  vote_signature  = ${result.voteSignatureHex.slice(0, 18)}…`);
    const bundleBytes = hexToBytesU8(result.spendBundleHex);
    ok(`  bundle: ${bundleBytes.length} bytes`);

    step("   → verifyBundleLocally");
    wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
    ok("  bundle validates locally");

    if (opts.pushDeploy) {
      step("   → push cast_vote bundle");
      const response = await pushSpendBundleBytes(bundleBytes, { network: "mainnet" });
      const isAlreadyIncluded =
        typeof response.error === "string" &&
        response.error.includes("ALREADY_INCLUDING_TRANSACTION");
      if (response.status !== "SUCCESS" && response.status !== 1 && !isAlreadyIncluded && response.status !== "PENDING" && response.status !== 3) {
        throw new Error(`push_tx returned: ${response.status} (${response.error ?? "(none)"})`);
      }
      ok(`  push_tx accepted: ${isAlreadyIncluded ? "ALREADY_IN_MEMPOOL" : response.status}`);

      step("   → poll for voting coin confirmation");
      const rec = await pollUntilConfirmed(result.votingCoinIdHex, {
        label: `votingCoin/${v.name}`,
        pollIntervalMs: 30_000,
        timeoutMs: 600_000,
      });
      ok(`  voting coin confirmed at height ${rec.confirmedHeight}`);

      // Chain-discovery: prove the voting coin is reachable through
      // BOTH paths the SDK + dApp use elsewhere — by hint
      // (voterHint + coinRecordsByHint) AND by pubkey
      // (collectVotesForBallot, which is itself hint-indexed but
      // exposes the wire-extracted vote_data so we can verify the
      // memo decoded correctly).
      step("   → discover by voter_hint + coinRecordsByHint");
      const _cfg = JSON.parse(deploy.configJson);
      const _electionLauncherIdHex =
        "0x" + String(_cfg.election_launcher_id_hex ?? "").replace(/^0x/, "");
      const _catTail =
        "0x" + String(_cfg.cat_tail_hash_hex ?? "").replace(/^0x/, "");
      const discoveryHintHex = String(
        wasm.voterHint(_electionLauncherIdHex, _catTail, accountPkHex)
      );
      const hintRecords = await coinRecordsByHint(discoveryHintHex, true);
      ok(
        `  voter_hint ${discoveryHintHex.slice(0, 18)}… returned ` +
          `${hintRecords.length} hint-indexed coin record(s) on chain`
      );

      step("   → discover by pubkey + wasm.collectVotesForBallot");
      const collectBackend = createChainBackend({ verbose: opts.verbose });
      const wireVotesJson = await wasm.collectVotesForBallot(
        collectBackend,
        deploy.configJson,
        "0x" + candidate.ballotLauncherIdHex.replace(/^0x/, ""),
        JSON.stringify([accountPkHex])
      );
      const wireVotes = JSON.parse(wireVotesJson);
      const myWireVote = wireVotes.find((row) => {
        const rowPk = String(
          row.voter_pubkey_hex ?? row.voterPubkeyHex ?? ""
        )
          .toLowerCase()
          .replace(/^0x/, "");
        return rowPk === accountPkHex.toLowerCase().replace(/^0x/, "");
      });
      if (!myWireVote) {
        throw new Error(
          `chain discovery: collectVotesForBallot did not surface a ` +
            `vote for ${v.name} (pk=${accountPkHex.slice(0, 18)}…) on ` +
            `ballot ${candidate.ballotLauncherIdHex.slice(0, 18)}…`
        );
      }
      const wireVoteData = String(
        myWireVote.vote_data_hex ?? myWireVote.voteDataHex ?? ""
      )
        .toLowerCase()
        .replace(/^0x/, "");
      const expectedVoteData = voteDataHex
        .toLowerCase()
        .replace(/^0x/, "");
      if (wireVoteData !== expectedVoteData) {
        throw new Error(
          `chain discovery: collectVotesForBallot reported vote_data ` +
            `${wireVoteData.slice(0, 18)}… for ${v.name} but expected ` +
            `${expectedVoteData.slice(0, 18)}… — walker/memo divergence`
        );
      }
      ok(
        `  ✓ vote reachable via collectVotesForBallot ` +
          `(vote_data ${wireVoteData.slice(0, 18)}… matches)`
      );

      cast.push({
        validator: v.name,
        accountPkHex,
        votingCoinIdHex: result.votingCoinIdHex,
        voteSignatureHex: result.voteSignatureHex,
        voteDataHex,
        confirmedHeight: rec.confirmedHeight,
      });
    } else {
      info("  Dry-run only — pass --push to broadcast");
    }
  }

  ok(`Phase 9 complete: ${cast.length} vote(s) cast on ballot ${candidate.ballotLauncherIdHex.slice(0, 18)}…`);
  return { ballot: candidate, cast };
}

async function sha256Bytes(buf) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

// ---------------------------------------------------------------------------
// Phase 10 — phase_finalize (close-window wait + Groth16-authenticated
// finalize spend that mints the next-generation Ballot Coin with
// `finalized=true`)
// ---------------------------------------------------------------------------

async function phaseWaitForCloseHeight(closeHeight) {
  step(`Phase 10a: wait for peak >= vote_close_height (${closeHeight})`);
  // Ballot Coin's `finalize` action gates on AssertHeightAbsolute(close).
  // We poll until peak crosses the line; mainnet block time ≈ 52s.
  const POLL_MS = 30_000;
  const TIMEOUT_MS = 60 * 60_000; // 60 min cap
  const started = Date.now();
  while (Date.now() - started < TIMEOUT_MS) {
    const peak = await peakHeight();
    if (peak >= closeHeight) {
      ok(`peak ${peak} >= close ${closeHeight} — window open`);
      return peak;
    }
    info(`  peak=${peak}, close=${closeHeight}, ${closeHeight - peak} blocks to go (sleeping ${POLL_MS / 1000}s)`);
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  throw new Error(`phaseWaitForCloseHeight: timed out after ${TIMEOUT_MS / 1000}s`);
}

async function phaseFinalize(opts, deploy) {
  step("Phase 10: finalize the cast-against ballot");

  if (!opts.runFinalize) {
    info("Skipping finalize (default). Pass --run-finalize to attempt.");
    return null;
  }
  if (!deploy?.configJson) throw new Error("finalize needs deploy artifacts");
  if (!opts.credentials) throw new Error("finalize needs --credentials");
  if (!deploy.provingKeyBytesB64) {
    throw new Error("finalize: deploy.json missing provingKeyBytesB64 — redeploy required");
  }

  // Pick the ballot we cast against — same selection rule as phaseCastVote
  // (most-recently-launched, snapshot non-empty, voting-coin lineage).
  const ballots = await readBallotArtifacts();
  const candidate = ballots
    .filter(
      (b) =>
        b.eveBallotCoinIdHex &&
        b.registrationMerkleRootSnapshotHex &&
        b.registrationVoteWeightSnapshot > 0
    )
    .sort((a, b) => b.launchedAtHeight - a.launchedAtHeight)[0];
  if (!candidate) {
    throw new Error("phase_finalize: no ballot eligible for finalize");
  }
  info(`finalizing ballot ${candidate.ballotLauncherIdHex.slice(0, 18)}…`);

  // Block until the close height passes.
  await phaseWaitForCloseHeight(candidate.voteCloseHeight);

  // Voter pubkey list for collectVotesForBallot — derived from .test-credentials.
  const creds = await parseCredentials(opts.credentials);
  const voterPubkeys = [];
  for (const v of creds.validators) {
    if (!v.mnemonic) continue;
    const { Mnemonic, SecretKey } = await import("chia-wallet-sdk-wasm");
    const mn = new Mnemonic(v.mnemonic);
    const seed = mn.toSeed("");
    const master = SecretKey.fromSeed(seed);
    const account = master.deriveUnhardenedPath(new Uint32Array([12381, 8444, 2, 0]));
    voterPubkeys.push("0x" + bytesToHex(account.publicKey().toBytes()));
  }
  ok(`voter pubkey list (${voterPubkeys.length}): ${voterPubkeys.map((p) => p.slice(0, 14)).join(", ")}…`);

  // Walk the chain to harvest every Voting Coin under this ballot.
  step(" → wasm.collectVotesForBallot");
  const collectBackend = createChainBackend({ verbose: opts.verbose });
  const votesJson = await wasm.collectVotesForBallot(
    collectBackend,
    deploy.configJson,
    "0x" + candidate.ballotLauncherIdHex.replace(/^0x/, ""),
    JSON.stringify(voterPubkeys)
  );
  const votes = JSON.parse(votesJson);
  ok(`collected ${votes.length} vote(s) on chain`);
  if (votes.length === 0) {
    throw new Error("phase_finalize: collectVotesForBallot returned no votes — finalize would underflow");
  }
  for (const v of votes) {
    // VoteRecordWire keys are snake_case (no #[serde(rename_all)]).
    info(
      `   voter=${String(v.voter_pubkey_hex).slice(0, 14)}… vote=${String(v.vote_data_hex).slice(0, 14)}…`
    );
  }

  // Determine vote_outcome — the message most signers signed. For our
  // yes/no test where every voter chose "Yes", this is sha256("vote:Yes").
  const choice = opts.voteChoice ?? "Yes";
  const outcomeBytes = await sha256Bytes(new TextEncoder().encode(`vote:${choice}`));
  const voteOutcomeHex = "0x" + bytesToHex(outcomeBytes);
  info(`vote_outcome (${choice}) = ${voteOutcomeHex.slice(0, 18)}…`);

  // Decode the cached arkworks proving key.
  const provingKeyBytes = Uint8Array.from(Buffer.from(deploy.provingKeyBytesB64, "base64"));
  ok(`proving key: ${provingKeyBytes.length} bytes`);

  const params = {
    voteCloseHeight: candidate.voteCloseHeight,
    voteThresholdNum: candidate.voteThresholdNum ?? 1,
    voteThresholdDen: candidate.voteThresholdDen ?? 2,
    registrationMerkleRootSnapshotHex: candidate.registrationMerkleRootSnapshotHex,
    registrationVoteWeightSnapshot: candidate.registrationVoteWeightSnapshot,
  };

  step(" → wasm.buildBallotFinalizeBundle (runs Groth16 prover — may take seconds)");
  const finalizeBackend = createChainBackend({ verbose: opts.verbose });
  // Mirror dApp: re-validate esh against chain before finalize.
  const chainEsh = await recoverElectionStartHeightOrFail(
    finalizeBackend,
    deploy.configJson
  );

  // Idempotency: a prior `PENDING` finalize bundle may have confirmed
  // on chain after the harness errored out. Walk the ballot's lineage
  // and detect a state-advanced (post-finalize) coin BEFORE rebuilding
  // the bundle — re-finalizing produces a "Ballot Coin ph doesn't
  // match predicted" trap from the SDK because the on-chain ballot's
  // inner state is no longer fresh `(0, 0, 0)`.
  step(" → check whether ballot is already finalized on chain");
  const eveBallotPh = "0x" + candidate.eveBallotPuzzleHashHex.replace(/^0x/, "");
  const recordsAtEvePh = await coinRecordsByPuzzleHash(eveBallotPh, true);
  const unspentAtEve = recordsAtEvePh.find((c) => c.spentHeight === 0);
  if (recordsAtEvePh.length > 0 && !unspentAtEve) {
    // Eve and any state-preserving co-spent (cast_vote oracle)
    // children all show as SPENT at this puzzle hash. The current
    // singleton coin is at a DIFFERENT puzzle hash — the only action
    // that changes the ballot inner state is finalize, so this is
    // proof that finalize already landed.
    ok(
      `ballot ${candidate.ballotLauncherIdHex.slice(0, 18)}… eve and ` +
        `${recordsAtEvePh.length} co-spent recreations are all spent at ` +
        `the eve ph; finalize must have landed in a prior run. Skipping.`
    );
    return;
  }

  const bundleHex = await wasm.buildBallotFinalizeBundle(
    finalizeBackend,
    deploy.configJson,
    "0x" + candidate.ballotLauncherIdHex.replace(/^0x/, ""),
    voteOutcomeHex,
    JSON.stringify(params),
    votesJson,
    provingKeyBytes,
    wasm.WasmNetwork.Mainnet,
    chainEsh
  );
  const bundleBytes = hexToBytesU8(bundleHex);
  ok(`finalize bundle: ${bundleBytes.length} bytes`);

  step(" → verifyBundleLocally");
  wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
  ok("bundle validates locally");

  if (opts.pushDeploy) {
    step(" → push finalize bundle (no AGG_SIG; Groth16-authenticated)");
    const response = await pushSpendBundleBytes(bundleBytes, { network: "mainnet" });
    const isAlreadyIncluded =
      typeof response.error === "string" &&
      response.error.includes("ALREADY_INCLUDING_TRANSACTION");
    // Coinset returns "PENDING" when the bundle is in the mempool
    // but not yet in a block — same as SUCCESS for our purposes.
    // Real failures surface as "FAILED" or other non-success codes
    // (DOUBLE_SPEND, ASSERT_HEIGHT, etc).
    const isPending =
      response.status === "PENDING" ||
      response.status === 3;
    const isSuccess =
      response.status === "SUCCESS" ||
      response.status === 1 ||
      isAlreadyIncluded ||
      isPending;
    if (!isSuccess) {
      throw new Error(`push_tx returned: ${response.status} (${response.error ?? "(none)"})`);
    }
    ok(
      `push_tx accepted: ${
        isAlreadyIncluded
          ? "ALREADY_IN_MEMPOOL"
          : isPending
            ? "PENDING_IN_MEMPOOL"
            : response.status
      }`
    );

    // Confirm by polling for the LATEST ballot coin (post-cast_vote)
    // to become spent — that's what the finalize bundle consumes. The
    // eve ballot coin was already spent earlier by the first cast_vote
    // (the oracle action consumes-and-recreates the singleton on every
    // cast), so polling the eve gives a false positive.
    step(" → locate latest ballot coin in lineage");
    const ballotPh = "0x" + candidate.eveBallotPuzzleHashHex.replace(/^0x/, "");
    const recordsAtPh = await coinRecordsByPuzzleHash(ballotPh, true);
    const unspentLatest = recordsAtPh.find((c) => c.spentHeight === 0);
    if (!unspentLatest) {
      throw new Error(
        `phase_finalize: no unspent ballot coin at ${ballotPh.slice(0, 18)}… ` +
          `before push — pre-existing finalize?`
      );
    }
    const latestCoinId = await computeCoinId(unspentLatest);
    info(`  latest ballot coin: id=${latestCoinId.slice(0, 18)}… amount=${unspentLatest.amount}`);

    step(" → poll for latest ballot coin to be spent (signal of finalize)");
    const startedPoll = Date.now();
    let spentRecord = null;
    while (Date.now() - startedPoll < 600_000) {
      const rec = await coinRecordByName("0x" + latestCoinId);
      if (rec && rec.spentHeight && rec.spentHeight !== 0) {
        spentRecord = rec;
        break;
      }
      await new Promise((r) => setTimeout(r, 30_000));
    }
    if (!spentRecord) {
      throw new Error(`latest ballot coin ${latestCoinId.slice(0, 18)}… not spent within 600s — finalize may have failed`);
    }
    ok(`latest ballot coin spent at height ${spentRecord.spentHeight} — finalize confirmed`);

    // Persist the finalize confirmation on the ballot artifact.
    const target = ballots.find(
      (b) => b.ballotLauncherIdHex === candidate.ballotLauncherIdHex
    );
    if (target) {
      target.finalizedAtHeight = spentRecord.spentHeight;
      target.voteOutcomeHex = voteOutcomeHex;
      await writeBallotArtifacts(ballots);
      ok("ballot artifact updated with finalize info");
    }
  } else {
    info("Dry-run only — pass --push to broadcast");
  }

  return { ballot: candidate, votes };
}

// ---------------------------------------------------------------------------
// Phase 11 — phase_release (each registered validator deregisters and gets
// their CAT collateral back at their own CAT-wrapped p2 puzzle hash)
// ---------------------------------------------------------------------------

async function phaseRelease(opts, deploy) {
  step("Phase 11: release collateral for each registered validator");

  if (!opts.runRelease) {
    info("Skipping release (default). Pass --run-release to attempt.");
    return null;
  }
  if (!deploy?.configJson) throw new Error("release needs deploy artifacts");
  if (!opts.credentials) throw new Error("release needs --credentials");

  const cfg = JSON.parse(deploy.configJson);
  const catTail = "0x" + cfg.cat_tail_hash_hex.replace(/^0x/, "");
  const creds = await parseCredentials(opts.credentials);

  // Build the FULL voter pubkey list for the SMT — release_collateral
  // asserts smt.root() matches the on-chain registration_merkle_root,
  // and the deregister action's membership proof requires the voter
  // being released to be IN the SMT (not non-membership like register).
  const voterEntries = [];
  for (const v of creds.validators) {
    if (!v.mnemonic) continue;
    const { Mnemonic, SecretKey } = await import("chia-wallet-sdk-wasm");
    const mn = new Mnemonic(v.mnemonic);
    const seed = mn.toSeed("");
    const master = SecretKey.fromSeed(seed);
    const account = master.deriveUnhardenedPath(new Uint32Array([12381, 8444, 2, 0]));
    voterEntries.push({
      v,
      derived: deriveSyntheticFromMnemonic(v.mnemonic),
      accountSecretBytes: account.toBytes(),
      accountPkHex: "0x" + bytesToHex(account.publicKey().toBytes()),
    });
  }
  // The SMT passed to releaseCollateralBuildSpends must match the
  // on-chain registration_merkle_root EXACTLY. That root drops a voter
  // when their release lands, so we must (a) initialise from the
  // CURRENT chain state (some voters may already be released from a
  // prior run) and (b) update the set after each successful release.
  // To detect "currently registered", we need an unspent coin at the
  // hint that is a REGISTRATION coin — not the released CAT collateral
  // (which lands at catOuter(tail, dest_p2_ph) and is also hinted with
  // voter_hint so the validator can find it). Compute each voter's
  // released-collateral CAT outer ph and exclude it from the filter.
  const electionLauncherIdHex = "0x" + cfg.election_launcher_id_hex.replace(/^0x/, "");
  const stillRegistered = new Set();
  for (const e of voterEntries) {
    const hint = wasm.voterHint(electionLauncherIdHex, catTail, e.accountPkHex);
    const releasedCatPh = String(
      wasm.catOuterPuzzleHash(catTail, "0x" + e.derived.puzzleHashHex)
    )
      .replace(/^0x/, "")
      .toLowerCase();
    const recs = await coinRecordsByHint(hint, true);
    const unspentRegLike = recs.some(
      (r) =>
        r.spentHeight === 0 &&
        String(r.puzzleHash).replace(/^0x/, "").toLowerCase() !== releasedCatPh
    );
    if (unspentRegLike) {
      stillRegistered.add(e.accountPkHex);
    }
  }
  if (stillRegistered.size === 0) {
    ok("No currently-registered validators (all already released?). Nothing to do.");
    return [];
  }
  ok(
    `Initial on-chain SMT voter list (${stillRegistered.size}): ` +
      `${[...stillRegistered].map((p) => p.slice(0, 14)).join(", ")}…`
  );

  const released = [];
  for (const entry of voterEntries) {
    info(`\n--- Releasing ${entry.v.name} (${entry.accountPkHex.slice(0, 18)}…) ---`);
    if (!stillRegistered.has(entry.accountPkHex)) {
      info("  already released (not in current on-chain SMT) — skipping");
      continue;
    }
    const allVoterPubkeysHex = [...stillRegistered];
    info(`  current SMT input (${allVoterPubkeysHex.length}): ${allVoterPubkeysHex.map((p) => p.slice(0, 14)).join(", ")}…`);

    // Find the CURRENT (unspent) registration coin for this voter.
    // After cast_vote, the recreated reg coin lands at a DIFFERENT
    // puzzle hash (state moved: e.g. last_voted_ballot is curried in),
    // so `freshRegistrationCoinPuzzleHash` no longer predicts it.
    // The voter_hint memo is state-independent — the SDK uses it for
    // exactly this lookup. Fetch by hint, filter unspent.
    const voterHintHex = wasm.voterHint(electionLauncherIdHex, catTail, entry.accountPkHex);
    info(`  voter_hint = ${String(voterHintHex).slice(0, 18)}…`);
    const releasedCatPh = String(
      wasm.catOuterPuzzleHash(catTail, "0x" + entry.derived.puzzleHashHex)
    )
      .replace(/^0x/, "")
      .toLowerCase();
    const hintRecords = await coinRecordsByHint(voterHintHex, true);
    const unspentReg = hintRecords.find(
      (c) =>
        c.spentHeight === 0 &&
        String(c.puzzleHash).replace(/^0x/, "").toLowerCase() !== releasedCatPh
    );
    if (!unspentReg) {
      info(
        `  no unspent registration coin via hint ${String(voterHintHex).slice(0, 18)}… ` +
          `(${hintRecords.length} hint-indexed records total) — skipping`
      );
      continue;
    }
    const regCoinIdHex = await computeCoinId(unspentReg);
    ok(`  current reg coin: id=${regCoinIdHex.slice(0, 18)}… amount=${unspentReg.amount} ph=${unspentReg.puzzleHash.slice(0, 18)}…`);

    // Destination = validator's standard p2 ph (the INNER ph; the CAT
    // outer wraps it on-chain, so the released collateral lands in the
    // validator's CAT-wrapped p2 wallet — recoverable by the same key
    // they used to register).
    const destinationPhHex = "0x" + entry.derived.puzzleHashHex;
    info(`  destination p2 ph = ${destinationPhHex.slice(0, 18)}… (CAT-wrapped on chain)`);
    const destCatOuter = wasm.catOuterPuzzleHash(catTail, destinationPhHex);
    info(`  expected CAT outer ph = ${String(destCatOuter).slice(0, 18)}…`);

    // Weighted-voting revision: wasm reconstructs the SMT from chain
    // (with each voter's real per-leaf locked_amount), so the dApp
    // / harness no longer threads the pubkey list. The deregister
    // membership proof recovers `locked_cat_mojos` from the SMT
    // entry — passing the wrong value here would produce a leaf
    // that doesn't match the on-chain root and the spend would
    // reject.
    step("   → wasm.releaseCollateralBuildSpends");
    const backend = createChainBackend({ verbose: opts.verbose });
    // Mirror dApp: re-validate esh against chain before release.
    const chainEsh = await recoverElectionStartHeightOrFail(
      backend,
      deploy.configJson
    );
    const bundleHex = await wasm.releaseCollateralBuildSpends(
      backend,
      deploy.configJson,
      "0x" + bytesToHex(entry.accountSecretBytes),
      "0x" + regCoinIdHex,
      destinationPhHex,
      wasm.WasmNetwork.Mainnet,
      chainEsh
    );
    const bundleBytes = hexToBytesU8(bundleHex);
    ok(`  release bundle: ${bundleBytes.length} bytes (SDK-signed: voter account_sk only)`);

    // Same as register: SDK signs with the voter's account secret only,
    // but the CAT spend's StandardLayer also requires synthetic_sk's
    // signature. Re-sign with both keys.
    step("   → re-sign with [account_sk, synthetic_sk]");
    const coinSpendsBytesLP = wasm.extractCoinSpendsFromBundle(bundleBytes);
    const bothSecrets = new Uint8Array(64);
    bothSecrets.set(entry.accountSecretBytes, 0);
    bothSecrets.set(entry.derived.syntheticSecretBytes, 32);
    const sigBytes = wasm.signCoinSpends(
      coinSpendsBytesLP,
      bothSecrets,
      wasm.WasmNetwork.Mainnet
    );
    const finalBundleBytes = wasm.assembleSpendBundle(coinSpendsBytesLP, sigBytes);
    ok(`  re-signed: ${sigBytes.length}-byte aggregate, final bundle ${finalBundleBytes.length} bytes`);

    step("   → verifyBundleLocally");
    wasm.verifyBundleLocally(finalBundleBytes, wasm.WasmNetwork.Mainnet);
    ok("  bundle validates locally");

    if (opts.pushDeploy) {
      step("   → push release bundle");
      const response = await pushSpendBundleBytes(finalBundleBytes, { network: "mainnet" });
      const isAlreadyIncluded =
        typeof response.error === "string" &&
        response.error.includes("ALREADY_INCLUDING_TRANSACTION");
      if (response.status !== "SUCCESS" && response.status !== 1 && !isAlreadyIncluded && response.status !== "PENDING" && response.status !== 3) {
        throw new Error(`push_tx returned: ${response.status} (${response.error ?? "(none)"})`);
      }
      ok(`  push_tx accepted: ${isAlreadyIncluded ? "ALREADY_IN_MEMPOOL" : response.status}`);

      // Poll for the reg coin to be spent — strongest signal that the
      // release deregister action ran on chain.
      step("   → poll for registration coin to be spent (signal of release)");
      const startedPoll = Date.now();
      let spent = null;
      while (Date.now() - startedPoll < 600_000) {
        const rec = await coinRecordByName("0x" + regCoinIdHex);
        if (rec && rec.spentHeight && rec.spentHeight !== 0) {
          spent = rec;
          break;
        }
        await new Promise((r) => setTimeout(r, 30_000));
      }
      if (!spent) {
        throw new Error(`reg coin ${regCoinIdHex.slice(0, 18)}… not spent within 600s — release failed`);
      }
      ok(`  reg coin spent at height ${spent.spentHeight} — release confirmed`);
      stillRegistered.delete(entry.accountPkHex);
      released.push({
        validator: entry.v.name,
        regCoinIdHex,
        destinationPhHex,
        destCatOuter: String(destCatOuter),
        spentAtHeight: spent.spentHeight,
      });
    } else {
      info("  Dry-run only — pass --push to broadcast");
    }
  }

  ok(`Phase 11 complete: ${released.length} validator(s) released`);
  return released;
}

function phaseWriteSideTodo() {
  step("=== All phases (deploy → register → ballot → vote → finalize → release) wired ===");
  info(
    "Phase 4 (deploy) builds + dry-runs end-to-end. The remaining write-side"
  );
  info("phases follow the same shape (build → sign → assemble → push):");
  info("  • register     — needs CAT issuance pre-spend (chia-sdk-driver Cat)");
  info("  • create/launch ballot — operator flow");
  info("  • cast/update vote — voter flow with their secret + Voting Coin");
  info("  • finalize     — Groth16 prove + ballot finalize");
  info("  • release      — voter deregister + collateral return");
  info("Each builds on phase_deploy's pattern (creds → derive → wasm export → sign → assemble).");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  console.log("");
  step("=== chip-voting-wasm live integration test ===");
  console.log("");

  try {
    await phaseEnvSmoke();
    console.log("");
    phasePureHelpers();
    console.log("");
    await phaseBallotReads(opts);
    console.log("");
    await phaseWalletCeremony(opts);
    console.log("");
    const deploy = await phaseDeploy(opts);
    console.log("");
    await phaseVoterReadiness(opts, deploy);
    console.log("");
    // CHIP rev 2026-05-02: register MUST run before create_ballot.
    // The ballot's curried snapshot freezes registration state at
    // launch time — if create_ballot runs first, the resulting
    // ballot has registration_vote_weight_snapshot = 0 and
    // cast_vote / finalize both reject it as below-threshold.
    await phaseRegisterVoter(opts, deploy);
    console.log("");
    const createdBallot = await phaseCreateBallot(opts, deploy);
    console.log("");
    await phaseLaunchBallot(opts, deploy, createdBallot);
    console.log("");
    await phaseCastVote(opts, deploy);
    console.log("");
    await phaseFinalize(opts, deploy);
    console.log("");
    await phaseRelease(opts, deploy);
    console.log("");
    phaseWriteSideTodo();
    console.log("");
    ok("ALL CONFIGURED PHASES PASSED");
  } catch (e) {
    console.log("");
    fail(`integration test failed: ${e?.stack ?? e}`);
    process.exit(1);
  }
}

main();
