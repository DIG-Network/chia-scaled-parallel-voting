// ============================================================================
// artifacts.mjs — persist deploy/ballot artifacts between test runs
// ============================================================================
//
// phase_deploy is expensive (one mainnet broadcast costs ~10 mojos
// and creates a stranded Election Singleton). Cache its outputs to
// disk so subsequent register / vote / finalize phases reuse the
// same election.
//
// On-disk layout:
//   wasm/integration-tests/.artifacts/
//     deploy.json   — { launcherIdHex, eveSingletonCoinIdHex, configJson, electionStartHeight, mainnetConfirmedHeight }
//     ballots.json  — Array<{ ballotLauncherIdHex, ballotCoinIdHex, voteCloseHeight, ... }>
//
// The directory is gitignored.

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = path.join(__dirname, ".artifacts");
const DEPLOY_PATH = path.join(ARTIFACTS_DIR, "deploy.json");
const BALLOTS_PATH = path.join(ARTIFACTS_DIR, "ballots.json");

async function ensureDir() {
  await fs.mkdir(ARTIFACTS_DIR, { recursive: true });
}

export async function readDeployArtifacts() {
  try {
    const raw = await fs.readFile(DEPLOY_PATH, "utf-8");
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

export async function writeDeployArtifacts(artifacts) {
  await ensureDir();
  await fs.writeFile(DEPLOY_PATH, JSON.stringify(artifacts, null, 2), "utf-8");
}

export async function readBallotArtifacts() {
  try {
    const raw = await fs.readFile(BALLOTS_PATH, "utf-8");
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
}

export async function writeBallotArtifacts(ballots) {
  await ensureDir();
  await fs.writeFile(BALLOTS_PATH, JSON.stringify(ballots, null, 2), "utf-8");
}

export const ARTIFACT_PATHS = { ARTIFACTS_DIR, DEPLOY_PATH, BALLOTS_PATH };
