// ============================================================================
// credentials.mjs — parse `.test-credentials` (KEY=VALUE flat file)
// ============================================================================
//
// Mirrors `cli/src/bin/live_integration_test.rs::parse_credentials`.
// Each wallet has a NAME / ADDRESS / NETWORK / (optional) PUBKEY,
// plus a mnemonic in a comment line (`# Mnemonic: <words>`) so the
// JS side can derive secret keys when needed for write phases.
//
// Wallet naming convention from the existing test-credentials:
//   - The L2 funder uses bare `WALLET_*` keys (no prefix).
//   - Validators use `VALIDATOR1_*`, `VALIDATOR2_*`, etc.
// This parser surfaces the funder as `funding` and validators as
// `validatorN` so phase functions can look them up by role.

import fs from "node:fs/promises";

/**
 * Parse a `.test-credentials` file at `path`. Returns
 * `{ funding, validators: [validator1, validator2, ...] }`.
 *
 * Each entry has:
 *   { name, address, network, pubkeyHex?, mnemonic? }
 * `pubkeyHex` is omitted on the funder (no PUBKEY line in the
 * canonical format); `mnemonic` is omitted if no `# Mnemonic: ...`
 * comment was found for that wallet.
 */
export async function parseCredentials(path) {
  const raw = await fs.readFile(path, "utf-8");
  const lines = raw.split(/\r?\n/);

  const kv = new Map();
  // Mnemonic comments come AFTER the wallet's KEY=VALUE block; we
  // attribute each `# Mnemonic:` to the most recent wallet prefix
  // we've seen (tracked via `lastPrefix`).
  const mnemonics = new Map();
  let lastPrefix = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith("#")) {
      const m = trimmed.match(/^#\s*Mnemonic:\s*(.+)$/i);
      if (m && lastPrefix) {
        mnemonics.set(lastPrefix, m[1].trim());
      }
      continue;
    }

    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    kv.set(key, value);

    // Track the prefix so we can attribute the next `# Mnemonic:` line.
    // `WALLET_*` → funder, `VALIDATORN_*` → validatorN.
    if (key.startsWith("VALIDATOR")) {
      const nMatch = key.match(/^VALIDATOR(\d+)_/);
      if (nMatch) lastPrefix = `validator${nMatch[1]}`;
    } else if (key.startsWith("WALLET_")) {
      lastPrefix = "funding";
    }
  }

  function read(prefix, fields) {
    const out = {};
    for (const [outKey, kvKey] of Object.entries(fields)) {
      const v = kv.get(kvKey);
      if (v !== undefined) out[outKey] = v;
    }
    const mn = mnemonics.get(prefix);
    if (mn) out.mnemonic = mn;
    return out;
  }

  const funding = read("funding", {
    name: "WALLET_NAME",
    address: "WALLET_ADDRESS",
    network: "WALLET_NETWORK",
  });

  const validators = [];
  for (let i = 1; i <= 8; i++) {
    const v = read(`validator${i}`, {
      name: `VALIDATOR${i}_WALLET_NAME`,
      address: `VALIDATOR${i}_ADDRESS`,
      pubkeyHex: `VALIDATOR${i}_PUBKEY`,
    });
    if (v.address) validators.push(v);
  }

  if (!funding.address) {
    throw new Error(
      `parseCredentials: no WALLET_ADDRESS found in ${path}; expected the L2 funder's address`
    );
  }
  if (validators.length === 0) {
    throw new Error(
      `parseCredentials: no VALIDATORN_ADDRESS lines found in ${path}; expected at least one validator`
    );
  }

  return { funding, validators };
}
