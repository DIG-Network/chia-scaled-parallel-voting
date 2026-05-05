// ============================================================================
// walletKeys.mjs — Chia BIP39 mnemonic → synthetic secret/p2 puzzle hash
// ============================================================================
//
// Mirrors `cli/src/bin/live_integration_test.rs::derive_synthetic_secret`:
//
//   1. mnemonic → 64-byte seed (toSeed("")  — Chia uses an EMPTY passphrase).
//   2. seed → master SecretKey via BLS HKDF-mod-r (`SecretKey.fromSeed`).
//   3. master → account at `m/12381'/8444'/2'/0` UNHARDENED
//      (the canonical chia wallet path; all four steps are unhardened —
//      see `chia_bls::master_to_wallet_unhardened`).
//   4. account → synthetic via `deriveSynthetic()` (adds the standard
//      hidden-puzzle hash to the secret per chia's p2 layer).
//
// Returns the synthetic SecretKey + PublicKey + the standard p2 puzzle
// hash the wallet's coins land on. The puzzle hash should match
// `Address.decode(WALLET_ADDRESS).puzzleHash` for any mnemonic whose
// matching address is in `.test-credentials`.

import {
  Mnemonic,
  SecretKey,
  Address,
} from "chia-wallet-sdk-wasm";
import { standardPuzzleHash } from "chip-voting-wasm";

/** Bytes → 0x-hex helper. */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 0x-hex (with or without prefix) → Uint8Array. */
export function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Derive `(syntheticSecret, syntheticPubkeyBytes, puzzleHashHex)` from a
 * BIP39 mnemonic at chia wallet account index `idx`. Defaults to 0.
 *
 * The returned `puzzleHashHex` is bare (no `0x` prefix) — same shape
 * the chip-voting-wasm exports accept. Convert to bech32m via
 * `Address.encode` if you want to compare against `.test-credentials`'
 * `WALLET_ADDRESS` strings.
 */
export function deriveSyntheticFromMnemonic(mnemonicWords, idx = 0) {
  const mn = new Mnemonic(mnemonicWords);
  const seed = mn.toSeed(""); // Chia uses an empty passphrase
  const master = SecretKey.fromSeed(seed);
  const account = master.deriveUnhardenedPath(new Uint32Array([12381, 8444, 2, idx]));
  const synthetic = account.deriveSynthetic();
  const syntheticPk = synthetic.publicKey();
  const syntheticPkBytes = syntheticPk.toBytes();
  const syntheticPkHex = "0x" + bytesToHex(syntheticPkBytes);
  // chip_voting_wasm.standardPuzzleHash expects a 48-byte synthetic
  // pubkey hex string (with or without 0x prefix); returns 0x-hex.
  const puzzleHash0x = standardPuzzleHash(syntheticPkHex);
  return {
    syntheticSecretBytes: synthetic.toBytes(),
    syntheticPkBytes,
    syntheticPkHex,
    puzzleHashHex: puzzleHash0x.startsWith("0x") ? puzzleHash0x.slice(2) : puzzleHash0x,
  };
}

/**
 * Decode a bech32m address (`xch1...` or `txch1...`) into its 32-byte
 * puzzle hash + the address prefix. Mirrors
 * `puzzleHashHexFromWalletAddress` in `app/app/lib/chiaAddress.ts`.
 */
export function puzzleHashFromAddress(address) {
  const decoded = Address.decode(address);
  return {
    puzzleHashHex: bytesToHex(decoded.puzzleHash),
    prefix: decoded.prefix,
  };
}

/**
 * Sanity-check a derived wallet against an `.test-credentials` entry:
 * verifies `derive(mnemonic).puzzleHash === decode(address).puzzleHash`.
 * Throws with a clear message if they diverge (catches mnemonic
 * typos / wrong chia path before any chain interaction).
 */
export function assertWalletMatchesAddress({ mnemonic, address, label }) {
  const derived = deriveSyntheticFromMnemonic(mnemonic);
  const expected = puzzleHashFromAddress(address);
  if (derived.puzzleHashHex !== expected.puzzleHashHex) {
    throw new Error(
      `Wallet ceremony mismatch for ${label}: ` +
        `derived puzzle_hash=${derived.puzzleHashHex} ` +
        `but address ${address} decodes to ${expected.puzzleHashHex}. ` +
        `Possible causes: wrong mnemonic, wrong derivation path (expected ` +
        `m/12381'/8444'/2'/0 unhardened), wrong passphrase (expected empty).`
    );
  }
  return { derived, expected };
}
