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
import { coinRecordsByPuzzleHash, coinRecordByName, peakHeight } from "./coinset.mjs";
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
  const params = {
    verificationKeyHex: ceremony.verificationKeyHex,
    catTailHashHex: opts.catTailHashHex,
    collateralAmount: 1, // 1 CAT mojo per voter (placeholder; voters need actual CATs to register)
    electionStartHeight: peak,
    label: "wasm-integration-smoke",
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

  const params = {
    ballotSeedHex,
    voteCloseHeight,
    outcomeDomainHashHex,
  };

  // ── 4. Call wasm.createBallotBundle ───────────────────────────
  step(" → wasm.createBallotBundle");
  const backend = createChainBackend({ verbose: opts.verbose });
  const resultJson = await wasm.createBallotBundle(
    backend,
    deploy.configJson,
    funderSpendBytes,
    JSON.stringify(params),
    wasm.WasmNetwork.Mainnet,
    BigInt(deploy.electionStartHeight)
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
    if (response.status !== "SUCCESS" && response.status !== 1) {
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
  const params = {
    voteCloseHeight: createdBallot.voteCloseHeight ?? deploy.electionStartHeight + 50,
    outcomeDomainHashHex: createdBallot.outcomeDomainHashHex ?? "0x" + "01".repeat(32),
    voteThresholdNum: 1,
    voteThresholdDen: 2,
  };

  const backend = createChainBackend({ verbose: opts.verbose });
  step(" → wasm.launchBallotBundle");
  const resultJson = await wasm.launchBallotBundle(
    backend,
    deploy.configJson,
    ballotLauncherIdHex,
    JSON.stringify(params),
    wasm.WasmNetwork.Mainnet,
    BigInt(deploy.electionStartHeight)
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
  if (response.status !== "SUCCESS" && response.status !== 1) {
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
    await writeBallotArtifacts(ballots);
    ok("ballot artifact updated with launch info");
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

  const registered = [];
  for (const entry of validatorsToRegister) {
    info(`\n--- Registering ${entry.v.name} (${entry.accountPkHex.slice(0, 18)}…) ---`);
    // Find a CAT coin owned by this validator
    const catOuter = wasm.catOuterPuzzleHash(catTail, entry.p2);
    const catCoins = await coinRecordsByPuzzleHash(catOuter, false);
    const ready = catCoins
      .filter((c) => c.spentHeight === 0 && c.amount >= collateral)
      .sort((a, b) => a.amount - b.amount);
    if (ready.length === 0) {
      info(`  no CAT coin >= ${collateral} mojos for ${entry.v.name}; skipping`);
      continue;
    }
    const catCoin = ready[0];
    // Compute coin id manually: sha256(parent || ph || amount_be8)
    const catCoinIdHex = await computeCoinId(catCoin);
    ok(`  CAT input coin: amount=${catCoin.amount} id=${catCoinIdHex.slice(0, 18)}…`);

    // Build the CAT registration parent spend
    step("   → wasm.buildCatRegistrationSpend");
    const backend = createChainBackend({ verbose: opts.verbose });
    const catParentSpendBytes = await wasm.buildCatRegistrationSpend(
      backend,
      "0x" + bytesToHex(entry.accountSecretBytes),
      "0x" + catCoinIdHex,
      electionLauncherIdHex,
      catTail,
      BigInt(collateral)
    );
    ok(`  CAT parent spend: ${catParentSpendBytes.length} streamable bytes`);

    // Pubkeys for SMT — exclude the voter being registered (non-membership)
    const otherPubkeys = allValidatorPubkeysHex.filter((p) => p !== entry.accountPkHex);

    // Call wasm.registerBuildSpends
    step("   → wasm.registerBuildSpends");
    const backend2 = createChainBackend({ verbose: opts.verbose });
    const bundleHex = await wasm.registerBuildSpends(
      backend2,
      deploy.configJson,
      "0x" + bytesToHex(entry.accountSecretBytes),
      JSON.stringify(otherPubkeys),
      catParentSpendBytes,
      wasm.WasmNetwork.Mainnet,
      BigInt(deploy.electionStartHeight)
    );
    const bundleBytes = hexToBytesU8(bundleHex);
    ok(`  register bundle: ${bundleBytes.length} bytes`);

    step("   → verifyBundleLocally");
    wasm.verifyBundleLocally(bundleBytes, wasm.WasmNetwork.Mainnet);
    ok("  bundle validates locally");

    if (opts.pushDeploy) {
      step("   → push register bundle");
      const response = await pushSpendBundleBytes(bundleBytes, { network: "mainnet" });
      if (response.status !== "SUCCESS" && response.status !== 1) {
        throw new Error(`push: ${response.status} (${response.error ?? "(none)"})`);
      }
      ok(`  push_tx accepted: ${response.status}`);

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

function phaseWriteSideTodo() {
  step("Phase 9+: vote / finalize / release (TODO)");
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
    const createdBallot = await phaseCreateBallot(opts, deploy);
    console.log("");
    await phaseLaunchBallot(opts, deploy, createdBallot);
    console.log("");
    await phaseRegisterVoter(opts, deploy);
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
