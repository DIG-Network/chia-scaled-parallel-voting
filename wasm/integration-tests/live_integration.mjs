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
import { peakHeight } from "./coinset.mjs";
import { assertWalletMatchesAddress } from "./walletKeys.mjs";

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    launcherId: null,
    credentials: null,
    verbose: false,
    configPath: null,
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
    info(
      `   ballot ${String(b.ballot_launcher_id).slice(0, 18)}… closes_at=${b.vote_close_height} finalized=${b.state?.finalized}`
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
    ok(`getBallot round-trips: close_height=${one.vote_close_height}`);
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

function phaseWriteSideTodo() {
  step("Phase 4+: full write-side phases (deploy / register / vote / finalize)");
  info(
    "STAGE B — pending. With wallet ceremony (Phase 3) working, the remaining pieces are:"
  );
  info("  • XCH funder pre-spend construction (StandardLayer puzzle + sign)");
  info("  • CAT issuance/transfer pre-spend construction (chia-sdk-driver Cat)");
  info("  • SpendBundle assembly via wasm.assembleSpendBundle");
  info("  • Bundle push via coinset.org /push_tx");
  info("  • Confirmation polling via coinRecordByName");
  info("Wiring this mirrors live_integration_test.rs phase_deploy → phase_release.");
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
