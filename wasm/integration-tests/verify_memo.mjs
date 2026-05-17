// Verify that wasm.getBallot returns the chain-recovered curry memo
// fields for the most-recently-minted ballot. Used as the smoke test
// for Option A (chain-readable curry via launcher second-spend memo).
//
// Run from CHIP repo root:
//   node wasm/integration-tests/verify_memo.mjs
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as wasm from "../pkg-node/chip_voting_wasm.js";
import { createChainBackend } from "./chainBackend.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const deploy = JSON.parse(
  readFileSync(join(__dirname, ".artifacts/deploy.json"), "utf8")
);
const ballots = JSON.parse(
  readFileSync(join(__dirname, ".artifacts/ballots.json"), "utf8")
);

if (!Array.isArray(ballots) || ballots.length === 0) {
  console.error("ballots.json is empty — run a create-ballot first");
  process.exit(1);
}
const latest = ballots[ballots.length - 1];
const ballotLauncherId = latest.ballotLauncherIdHex || latest.ballot_launcher_id;
if (!ballotLauncherId) {
  console.error("Could not find ballot launcher id in ballots.json");
  process.exit(1);
}

console.log("Election launcher id:", deploy.launcherIdHex);
console.log("Ballot launcher id:  ", ballotLauncherId);

const backend = createChainBackend({ verbose: false });

console.log("\n→ wasm.getBallot");
const oneJson = await wasm.getBallot(
  backend,
  deploy.configJson,
  ballotLauncherId
);
const one = JSON.parse(oneJson);
if (one == null) {
  console.error("getBallot returned null — ballot not found on chain");
  process.exit(2);
}
console.log("getBallot result:");
console.log(JSON.stringify(one, null, 2));

const memoFields = [
  "vote_threshold_num",
  "vote_threshold_den",
  "registration_merkle_root_snapshot",
  "registration_vote_weight_snapshot",
];
const populated = memoFields.filter((k) => one[k] != null);
if (populated.length === memoFields.length) {
  console.log(
    `\n✅ MEMO READBACK SUCCESS: all ${memoFields.length} curry fields populated from chain`
  );
  console.log(
    `  threshold = ${one.vote_threshold_num}/${one.vote_threshold_den}`
  );
  console.log(
    `  registration_merkle_root_snapshot = ${one.registration_merkle_root_snapshot}`
  );
  console.log(
    `  registration_vote_weight_snapshot = ${one.registration_vote_weight_snapshot}`
  );
  console.log(`  vote_close_height = ${one.vote_close_height}`);
  console.log(`  outcome_domain_hash = ${one.outcome_domain_hash}`);
  process.exit(0);
} else {
  console.error(
    `\n❌ MEMO READBACK PARTIAL: only ${populated.length}/${memoFields.length} curry fields populated.`
  );
  console.error(`  populated: ${populated.join(", ") || "(none)"}`);
  process.exit(3);
}
