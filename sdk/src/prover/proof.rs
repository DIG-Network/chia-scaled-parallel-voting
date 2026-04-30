// ============================================================================
// prover/proof.rs — Groth16 proof + pre-computed scalars (wire types)
// ============================================================================
//
// MODULE: prover::proof
// PURPOSE: Wire types for a Groth16 proof and the pre-computed scalars
//          the on-chain `finalize` action consumes.
//
// DESIGN:
//   * `Groth16Proof` is the JSON-portable form of an arkworks Groth16
//     proof — three BLS12-381 curve points (A in G1, B in G2, C in G1)
//     in IETF-compressed encoding, hex-encoded for transport. Bridges
//     to/from `ark_groth16::Proof<Bls12_381>` via `from_arkworks` /
//     `to_arkworks`.
//   * `Scalars` is the on-chain helper: 4 sha256 hashes of the public
//     inputs. The on-chain `finalize.rue` puzzle does
//     `assert sha256(input_i) == s_i` and then `vk_input = IC[0] +
//     Σ s_i * IC[i+1]`. Pre-computing the scalars off-chain saves CLVM
//     intermediate-state cost (the sha256 itself is unavoidable).
//
// SCALAR SEMANTICS:
//   * `s_i` is a 32-byte hash, stored as `Bytes32`.
//   * The Groth16 verifier uses `bytes32_to_fr(s_i)` (big-endian, mod r)
//     as the i-th public input scalar in the IC linear combination.
//   * The off-chain prover MUST commit to the same Fr values via
//     `VotingCircuit::public_inputs_as_fr`, which delegates to
//     `Scalars::compute` here for byte-exact agreement.
//
// CRATES USED:
//   * chia_bls           — PublicKey (input to scalar #3)
//   * chia_protocol      — Bytes32 (the wire form for each scalar)
//   * sha2               — sha256 itself
//   * ark_bls12_381      — only for the Groth16Proof <-> arkworks bridge
//   * ark_serialize      — compressed point (de)serialisation for the bridge
//   * serde / serde_json — JSON portability for `Groth16Proof`

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::error::{VotingError, VotingResult};

/// STRUCT: Groth16Proof
/// PURPOSE: serialised Groth16 proof — three BLS12-381 curve points
///          totalling 192 bytes (48 + 96 + 48).
/// USE FROM: Aggregator → finalize action solution; serialised over
///           JSON when the prover and broadcaster live in different
///           processes.
/// SERDE: hex-encoded for JSON portability (consistent with the rest
///        of the SDK's wire format).
/// CONVERSIONS: `from_arkworks` / `to_arkworks` bridge to the
///              `ark_groth16::Proof<Bls12_381>` typed form used
///              internally by `VotingCircuit::prove` /
///              `verify_offchain`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16Proof {
    /// G1 compressed (48 bytes), hex-encoded.
    pub a_hex: String,
    /// G2 compressed (96 bytes), hex-encoded.
    pub b_hex: String,
    /// G1 compressed (48 bytes), hex-encoded.
    pub c_hex: String,
}

impl Groth16Proof {
    /// FN: from_arkworks
    /// WHAT: serialise an `ark_groth16::Proof<Bls12_381>` to the
    ///       wire format.
    /// USAGE: every `VotingCircuit::prove` call internally produces an
    ///        arkworks proof; this is the canonical way to convert it
    ///        to the form callers receive.
    pub fn from_arkworks(proof: &Proof<Bls12_381>) -> VotingResult<Self> {
        let a = serialize_compressed_48(&proof.a)?;
        let b = serialize_compressed_96(&proof.b)?;
        let c = serialize_compressed_48(&proof.c)?;
        Ok(Self {
            a_hex: hex::encode(a),
            b_hex: hex::encode(b),
            c_hex: hex::encode(c),
        })
    }

    /// FN: to_arkworks
    /// WHAT: parse the wire format back to `ark_groth16::Proof<Bls12_381>`.
    /// USAGE: `verify_offchain` re-typed proofs received via JSON.
    /// ERRORS:
    ///   * `HexDecode` if any field isn't valid hex.
    ///   * `ProvingError` if any field doesn't decode as a valid
    ///     curve point (wrong length, off-curve, etc.).
    pub fn to_arkworks(&self) -> VotingResult<Proof<Bls12_381>> {
        let a_bytes = hex::decode(&self.a_hex).map_err(VotingError::HexDecode)?;
        let b_bytes = hex::decode(&self.b_hex).map_err(VotingError::HexDecode)?;
        let c_bytes = hex::decode(&self.c_hex).map_err(VotingError::HexDecode)?;
        let a = G1Affine::deserialize_compressed(&a_bytes[..])
            .map_err(|e| VotingError::ProvingError(format!("parse A: {e}")))?;
        let b = G2Affine::deserialize_compressed(&b_bytes[..])
            .map_err(|e| VotingError::ProvingError(format!("parse B: {e}")))?;
        let c = G1Affine::deserialize_compressed(&c_bytes[..])
            .map_err(|e| VotingError::ProvingError(format!("parse C: {e}")))?;
        Ok(Proof { a, b, c })
    }
}

/// STRUCT: Scalars
/// PURPOSE: pre-computed `sha256(public_input_i)` for each of the four
///          public inputs to our circuit.
///
/// LAYOUT: matches the on-chain `finalize.rue` `Scalars` struct order:
///   s1 = registration_merkle_root
///   s2 = registration_count (8-byte big-endian)
///   s3 = aggregated signers' G1-compressed bytes
///   s4 = vote_message
///
/// IMMUTABILITY: derived purely from the public inputs; recomputable
///               by anyone, no secret data.
///
/// CIRCUIT CONNECTION: convert via
/// [`crate::prover::conversions::scalars_to_fr_array`] to get the
/// `[Fr; 4]` form `VotingCircuit::generate_constraints` allocates as
/// public-input variables. The off-chain prover and the on-chain
/// `IC[0] + Σ s_i * IC[i+1]` linear combination MUST consume identical
/// scalars — this round-trip is the canonical contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalars {
    /// `sha256(registration_merkle_root)`
    pub s1: Bytes32,
    /// `sha256(registration_count_be8)` — big-endian 8-byte encoding,
    /// matching the on-chain `int_to_8_bytes_be` Rue helper.
    pub s2: Bytes32,
    /// `sha256(agg_signers_g1_compressed_48)`
    pub s3: Bytes32,
    /// `sha256(vote_message)`
    pub s4: Bytes32,
}

impl Scalars {
    /// FN: compute
    /// WHAT: derive all four scalars from the four public inputs.
    /// USAGE:
    ///   * `Aggregator::prepare_finalize_witness` — populates the
    ///     finalize-action solution.
    ///   * `VotingCircuit::public_inputs_as_fr` — derives the
    ///     [`Fr; 4`] form the circuit commits to via Groth16's IC.
    /// IDEMPOTENT: same inputs → same scalars; safe to call repeatedly.
    pub fn compute(
        registration_merkle_root: Bytes32,
        registration_count: u64,
        agg_signers: &PublicKey,
        vote_message: Bytes32,
    ) -> Self {
        // Each scalar = `sha256(input) mod r`, where r is the
        // BLS12-381 subgroup order. The mod-r reduction is REQUIRED
        // — without it, raw sha256 outputs whose high bit is set
        // would be interpreted as NEGATIVE numbers by CLVM's
        // `bls_g1_multiply` (which uses signed two's-complement
        // big-endian semantics), producing a different scalar than
        // the off-chain prover's `Fr::from_be_bytes_mod_order(...)`
        // commitment. After reducing mod r the value is < r < 2^254,
        // so the high bit is always 0 and signed/unsigned
        // interpretations agree.
        let s1 = sha256_mod_r(registration_merkle_root.as_ref());
        let s2 = sha256_mod_r(&registration_count.to_be_bytes());
        let s3 = sha256_mod_r(&agg_signers.to_bytes());
        let s4 = sha256_mod_r(vote_message.as_ref());
        Self { s1, s2, s3, s4 }
    }

    /// FN: as_array
    /// WHAT: return the 4 scalars as a `[Bytes32; 4]` in the canonical
    ///       `(s1, s2, s3, s4)` order.
    /// USAGE: convenient for off-chain serialisation in tests + for
    ///        `chip-voting-sdk` callers that want to feed the scalars
    ///        directly into `VotingCircuit::verify_offchain`'s
    ///        `&[Bytes32; 4]` parameter.
    pub fn as_array(&self) -> [Bytes32; 4] {
        [self.s1, self.s2, self.s3, self.s4]
    }
}

// ── Internal helpers ─────────────────────────────────────────────────

/// FN: sha256_mod_r (file-private)
/// WHAT: `Fr_to_be32(Fr::from_be_bytes_mod_order(sha256(bytes)))` —
///       the canonical mod-r reduced scalar. Always < r < 2^254
///       (high bit clear), so CLVM's signed-big-endian
///       interpretation matches arkworks' unsigned interpretation.
/// USAGE: solely by `Scalars::compute`.
fn sha256_mod_r(bytes: &[u8]) -> Bytes32 {
    use crate::prover::conversions::{bytes32_to_fr, fr_to_bytes32_be};
    let mut sha_out = [0u8; 32];
    sha_out.copy_from_slice(&{
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
    });
    let raw = Bytes32::new(sha_out);
    let fr = bytes32_to_fr(&raw);
    Bytes32::new(fr_to_bytes32_be(&fr))
}

/// FN: sha256_b32 (file-private; retained for tests)
/// WHAT: raw sha256 returning a `Bytes32`. Use `sha256_mod_r` for
///       Scalars::compute; this helper is kept so existing
///       round-trip tests over the raw hash still compile.
#[allow(dead_code)]
fn sha256_b32(bytes: &[u8]) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let out = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Bytes32::new(arr)
}

fn serialize_compressed_48(p: &G1Affine) -> VotingResult<[u8; 48]> {
    let mut buf = Vec::with_capacity(48);
    p.serialize_compressed(&mut buf)
        .map_err(|e| VotingError::ProvingError(format!("serialise G1: {e}")))?;
    buf.try_into()
        .map_err(|_| VotingError::ProvingError("G1 length != 48".into()))
}

fn serialize_compressed_96(p: &G2Affine) -> VotingResult<[u8; 96]> {
    let mut buf = Vec::with_capacity(96);
    p.serialize_compressed(&mut buf)
        .map_err(|e| VotingError::ProvingError(format!("serialise G2: {e}")))?;
    buf.try_into()
        .map_err(|_| VotingError::ProvingError("G2 length != 96".into()))
}

// ============================================================================
// Tests
// ============================================================================
//
// CONVENTION: every test below carries a `WHAT / HOW / WHY` block.

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{master_to_wallet_unhardened, SecretKey};
    use chia_puzzle_types::DeriveSynthetic;
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    fn pk_at(i: u32) -> PublicKey {
        let root = SecretKey::from_bytes(&hex!(
            "1b72f8ed55860ea5441729c8e36ce1d6f4c8be9bbcf658502a7a0169f55638b9"
        ))
        .unwrap();
        master_to_wallet_unhardened(&root.public_key(), i).derive_synthetic()
    }

    fn b32(byte: u8) -> Bytes32 { Bytes32::new([byte; 32]) }

    /// WHAT: `Scalars::compute` is deterministic.
    /// HOW:  call twice with the same inputs, assert equality.
    /// WHY:  the on-chain finalize action re-derives every scalar
    ///       and asserts it matches what we passed in. Non-
    ///       determinism on our side would always fail on-chain.
    #[test]
    fn scalars_are_deterministic() {
        let pk = pk_at(0);
        let a = Scalars::compute(b32(1), 5, &pk, b32(2));
        let b = Scalars::compute(b32(1), 5, &pk, b32(2));
        assert_eq!(a, b);
    }

    /// WHAT: each scalar depends only on its corresponding public
    ///       input and is unaffected by changes to other inputs.
    /// HOW:  fix a baseline, then vary each input independently and
    ///       assert that ONLY the corresponding scalar changes
    ///       (others remain equal).
    /// WHY:  the scalars feed the on-chain VK linear combination.
    ///       If a scalar accidentally mixed multiple inputs, the
    ///       Groth16 verification would silently miscompute and
    ///       accept invalid proofs.
    #[test]
    fn scalars_change_when_any_input_changes() {
        let pk = pk_at(0);
        let base = Scalars::compute(b32(1), 5, &pk, b32(2));

        // Vary registration_merkle_root.
        let v1 = Scalars::compute(b32(0xAA), 5, &pk, b32(2));
        assert_ne!(base.s1, v1.s1);
        assert_eq!(base.s2, v1.s2);

        // Vary registration_count.
        let v2 = Scalars::compute(b32(1), 6, &pk, b32(2));
        assert_eq!(base.s1, v2.s1);
        assert_ne!(base.s2, v2.s2);

        // Vary agg_signers.
        let v3 = Scalars::compute(b32(1), 5, &pk_at(1), b32(2));
        assert_eq!(base.s1, v3.s1);
        assert_eq!(base.s2, v3.s2);
        assert_ne!(base.s3, v3.s3);

        // Vary vote_message.
        let v4 = Scalars::compute(b32(1), 5, &pk, b32(0xCC));
        assert_ne!(base.s4, v4.s4);
    }

    /// WHAT: scalar `s2` is `sha256(count.to_be_bytes())`.
    /// HOW:  run scalars on a recognisable count (1234567890),
    ///       independently compute sha256 of its big-endian 8-byte
    ///       form, assert equality.
    /// WHY:  the Rue side uses `int_to_8_bytes_be` for the count
    ///       encoding. Any mismatch (e.g., little-endian, varint)
    ///       would mean the on-chain verifier sees a different scalar
    ///       than the prover used.
    #[test]
    fn s2_uses_be8_encoding_of_count() {
        let pk = pk_at(0);
        let scalars = Scalars::compute(b32(0), 1234567890u64, &pk, b32(0));

        // s2 = mod_r(sha256(count_be8)) per the on-chain
        // CLVM-compatible scalar encoding (see Scalars::compute
        // doc-comment for why the mod-r reduction is required).
        let mut h = Sha256::new();
        h.update(1234567890u64.to_be_bytes());
        let mut sha_out = [0u8; 32];
        sha_out.copy_from_slice(&h.finalize());
        let raw = Bytes32::new(sha_out);
        let fr = crate::prover::conversions::bytes32_to_fr(&raw);
        let expected_mod_r =
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&fr));
        assert_eq!(scalars.s2, expected_mod_r);
    }

    /// WHAT: scalar `s3` is `sha256(pk.to_bytes())` where
    ///       `pk.to_bytes()` is the 48-byte BLS12-381 G1 compressed
    ///       encoding.
    /// HOW:  recompute sha256 inline against the same 48-byte form
    ///       and compare.
    /// WHY:  the on-chain Groth16 verifier consumes the aggregated
    ///       signers' public key in compressed G1 form. A wrong
    ///       encoding (uncompressed, affine, etc.) would silently
    ///       break verification.
    #[test]
    fn s3_uses_compressed_g1_encoding() {
        let pk = pk_at(0);
        let scalars = Scalars::compute(b32(0), 0, &pk, b32(0));
        let mut h = Sha256::new();
        h.update(pk.to_bytes());
        let mut sha_out = [0u8; 32];
        sha_out.copy_from_slice(&h.finalize());
        let raw = Bytes32::new(sha_out);
        let fr = crate::prover::conversions::bytes32_to_fr(&raw);
        let expected_mod_r =
            Bytes32::new(crate::prover::conversions::fr_to_bytes32_be(&fr));
        assert_eq!(scalars.s3, expected_mod_r);
    }

    /// WHAT: `Scalars::as_array` returns the 4 scalars in the canonical
    ///       `(s1, s2, s3, s4)` order.
    /// HOW:  build a recognisable Scalars value and assert each entry.
    /// WHY:  this array is the form `VotingCircuit::verify_offchain`
    ///       takes. Any reordering would silently break verification
    ///       (and pin the wrong scalar to the wrong IC slot).
    #[test]
    fn scalars_as_array_preserves_order() {
        let s = Scalars {
            s1: b32(0x11),
            s2: b32(0x22),
            s3: b32(0x33),
            s4: b32(0x44),
        };
        let arr = s.as_array();
        assert_eq!(arr[0], b32(0x11));
        assert_eq!(arr[1], b32(0x22));
        assert_eq!(arr[2], b32(0x33));
        assert_eq!(arr[3], b32(0x44));
    }

    /// WHAT: `Groth16Proof` serialises through `serde_json` round-
    ///       trip without modification.
    /// HOW:  build a proof with deterministic test bytes, JSON-
    ///       roundtrip, compare.
    /// WHY:  proofs are serialised when an aggregator hands the
    ///       finalize spend bundle off to a broadcaster; lossy
    ///       serialisation would be silent on-chain rejection.
    #[test]
    fn groth16_proof_serde_roundtrip() {
        let p = Groth16Proof {
            a_hex: "01".repeat(48),
            b_hex: "02".repeat(96),
            c_hex: "03".repeat(48),
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: Groth16Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, p);
    }

    /// WHAT: `Groth16Proof::from_arkworks → to_arkworks` round-trips
    ///       a real arkworks-typed proof losslessly.
    /// HOW:  generate a real Groth16 proof via the test setup; convert
    ///       to wire form via `from_arkworks`; convert back via
    ///       `to_arkworks`; assert the round-tripped proof equals the
    ///       original.
    /// WHY:  this is the bridge between the off-chain arkworks prover
    ///       (typed `Proof<Bls12_381>`) and the on-chain wire form
    ///       (hex-encoded `Groth16Proof`). Drift breaks every proof.
    #[test]
    fn groth16_proof_arkworks_roundtrip() {
        use crate::prover::circuit::{generate_test_setup, SignerWitness, VotingCircuit};
        use ark_std::rand::SeedableRng;

        // Build a real proof to round-trip.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xBEEF);
        let (pk, _vk) = generate_test_setup(&mut rng).unwrap();
        let circuit = VotingCircuit {
            registration_merkle_root: b32(0x11),
            registration_count: 3,
            agg_signers: pk_at(0),
            vote_message: b32(0x42),
            signers: (0..2)
                .map(|i| SignerWitness {
                    pubkey: pk_at(i + 1),
                    leaf_index: i,
                    merkle_proof: vec![Bytes32::default(); 32],
                })
                .collect(),
        };
        let wire = circuit.prove(&pk).unwrap();
        let arkworks = wire.to_arkworks().unwrap();
        let wire2 = Groth16Proof::from_arkworks(&arkworks).unwrap();
        assert_eq!(wire, wire2);
    }

    /// WHAT: `Groth16Proof::to_arkworks` rejects malformed hex.
    /// HOW:  build a proof with `a_hex = "not-hex"`; expect HexDecode.
    /// WHY:  surface parse errors as TYPED errors so callers can
    ///       branch on them (e.g., a UI showing "proof corrupt" vs
    ///       a generic failure).
    #[test]
    fn groth16_proof_to_arkworks_rejects_bad_hex() {
        let p = Groth16Proof {
            a_hex: "not-hex".into(),
            b_hex: "02".repeat(96),
            c_hex: "03".repeat(48),
        };
        match p.to_arkworks() {
            Err(VotingError::HexDecode(_)) => {}
            other => panic!("expected HexDecode, got {other:?}"),
        }
    }

    /// WHAT: `Groth16Proof::to_arkworks` rejects bytes that hex-decode
    ///       fine but aren't a valid G1/G2 curve point.
    /// HOW:  build a proof whose `a_hex` is 48 bytes of `0xff` (well-
    ///       formed length, NOT a valid G1 point); expect ProvingError.
    /// WHY:  same defensive rationale as the bad-hex test, applied to
    ///       the byte-level cryptographic check.
    #[test]
    fn groth16_proof_to_arkworks_rejects_off_curve_point() {
        let p = Groth16Proof {
            a_hex: "ff".repeat(48),
            b_hex: "02".repeat(96),
            c_hex: "03".repeat(48),
        };
        assert!(matches!(p.to_arkworks(), Err(VotingError::ProvingError(_))));
    }
}
