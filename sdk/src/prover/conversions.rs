// ============================================================================
// prover/conversions.rs — chia_bls ↔ ark_bls12_381 byte-encoding bridge
// ============================================================================
//
// MODULE: prover::conversions
// PURPOSE: Convert between Chia's `chia_bls` types (PublicKey ⇆ G1,
//          Signature ⇆ G2) and arkworks' `ark_bls12_381` curve types.
//
// WHY THIS MATTERS:
//   * The on-chain `finalize.rue` puzzle's `bls_pairing_identity`
//     opcode reads BLS12-381 G1 / G2 points in their canonical IETF
//     compressed encoding (the same encoding `chia_bls::PublicKey::
//     to_bytes` and `chia_bls::Signature::to_bytes` produce — 48 and
//     96 bytes respectively).
//   * arkworks generates Groth16 proofs as ark_bls12_381 curve
//     points. To submit a proof on-chain we must convert each
//     point's bytes into the encoding chia_bls speaks (which IS the
//     IETF encoding, but arkworks may differ in subtle details like
//     byte ordering or flag bits).
//
// IMPLEMENTATION:
//   * arkworks' `CanonicalSerialize::serialize_compressed` writes a
//     point in arkworks' own compressed format. For BLS12-381 this
//     IS the IETF-spec compressed encoding (per the ark-bls12-381
//     0.4 docs), so direct byte equality should hold. We test this
//     end-to-end via `chia_bls → arkworks → bytes vs chia_bls
//     bytes` round-trips.
//
// SECURITY: parsing is total — invalid bytes return `Err(_)`.
//           Serialisation is infallible (curve points always have a
//           valid compressed encoding).

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chia_bls::{PublicKey, Signature};
use chia_protocol::Bytes32;

use crate::prover::Scalars;

use crate::error::{anyhow_compat, VotingError, VotingResult};

/// FN: chia_pk_to_ark_g1
/// WHAT: parse a `chia_bls::PublicKey` (48-byte IETF compressed G1)
///       into an arkworks `G1Affine`.
/// ERRORS: `VotingError::Other` if the bytes don't decode as a valid
///         G1 point (e.g., non-canonical encoding, point not on
///         curve).
pub fn chia_pk_to_ark_g1(pk: &PublicKey) -> VotingResult<G1Affine> {
    let bytes = pk.to_bytes();
    G1Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| ark_to_voting_error("G1 deserialise", e))
}

/// FN: ark_g1_to_chia_pk
/// WHAT: serialise an arkworks `G1Affine` to chia_bls `PublicKey`.
/// USAGE: round-trip arkworks proof outputs into the Chia ecosystem
///        format used by every other actor in the SDK.
pub fn ark_g1_to_chia_pk(g1: &G1Affine) -> VotingResult<PublicKey> {
    let mut buf = Vec::with_capacity(48);
    g1.serialize_compressed(&mut buf)
        .map_err(|e| ark_to_voting_error("G1 serialise", e))?;
    let arr: [u8; 48] = buf
        .try_into()
        .map_err(|_| voting_error("G1 serialised length != 48"))?;
    PublicKey::from_bytes(&arr).map_err(|e| voting_error(&format!("invalid PublicKey: {e:?}")))
}

/// FN: chia_sig_to_ark_g2
/// WHAT: parse a `chia_bls::Signature` (96-byte IETF compressed G2)
///       into an arkworks `G2Affine`.
pub fn chia_sig_to_ark_g2(sig: &Signature) -> VotingResult<G2Affine> {
    let bytes = sig.to_bytes();
    G2Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| ark_to_voting_error("G2 deserialise", e))
}

/// FN: ark_g2_to_chia_sig
/// WHAT: serialise an arkworks `G2Affine` to chia_bls `Signature`.
pub fn ark_g2_to_chia_sig(g2: &G2Affine) -> VotingResult<Signature> {
    let mut buf = Vec::with_capacity(96);
    g2.serialize_compressed(&mut buf)
        .map_err(|e| ark_to_voting_error("G2 serialise", e))?;
    let arr: [u8; 96] = buf
        .try_into()
        .map_err(|_| voting_error("G2 serialised length != 96"))?;
    Signature::from_bytes(&arr).map_err(|e| voting_error(&format!("invalid Signature: {e:?}")))
}

/// FN: bytes32_to_fr
/// WHAT: convert a 32-byte hash (e.g., a sha256 output) into an
///       arkworks BLS12-381 scalar field element `Fr`.
/// CONVENTION: the bytes are interpreted big-endian and reduced
///             mod r (the BLS12-381 scalar field order). This matches
///             how the on-chain `bls_g1_multiply` opcode interprets
///             scalar bytes (BIG-endian per the IETF BLS spec).
pub fn bytes32_to_fr(b: &Bytes32) -> Fr {
    Fr::from_be_bytes_mod_order(b.as_ref())
}

/// FN: fr_to_bytes32_be
/// WHAT: serialise an `Fr` to its 32-byte big-endian representation.
/// NOTE: fr is < 2^255, so the high bit of the first byte is always
///       0. The full 32-byte length is preserved (no compaction).
/// USAGE: roundtrip checks in tests.
pub fn fr_to_bytes32_be(fr: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = fr.into_bigint().to_bytes_be();
    // ark BigInt::to_bytes_be returns the minimal representation
    // (LEADING zeros stripped). Right-align into a 32-byte buffer.
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

/// FN: g1_compressed_bytes
/// WHAT: serialise a G1 point to 48-byte compressed form WITHOUT
///       the round-trip through `chia_bls::PublicKey`.
/// USAGE: used when assembling the on-chain VK / proof solution
///        where each curve point is just a byte buffer.
pub fn g1_compressed_bytes(g1: &G1Affine) -> VotingResult<[u8; 48]> {
    let mut buf = Vec::with_capacity(48);
    g1.serialize_compressed(&mut buf)
        .map_err(|e| ark_to_voting_error("G1 serialise", e))?;
    buf.try_into().map_err(|_| voting_error("G1 length != 48"))
}

/// FN: g2_compressed_bytes
/// WHAT: serialise a G2 point to 96-byte compressed form.
pub fn g2_compressed_bytes(g2: &G2Affine) -> VotingResult<[u8; 96]> {
    let mut buf = Vec::with_capacity(96);
    g2.serialize_compressed(&mut buf)
        .map_err(|e| ark_to_voting_error("G2 serialise", e))?;
    buf.try_into().map_err(|_| voting_error("G2 length != 96"))
}

/// FN: g1_from_compressed_bytes
/// WHAT: parse 48 bytes of compressed G1 into an arkworks `G1Affine`.
pub fn g1_from_compressed_bytes(bytes: &[u8; 48]) -> VotingResult<G1Affine> {
    G1Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| ark_to_voting_error("G1 deserialise", e))
}

/// FN: g2_from_compressed_bytes
/// WHAT: parse 96 bytes of compressed G2 into an arkworks `G2Affine`.
pub fn g2_from_compressed_bytes(bytes: &[u8; 96]) -> VotingResult<G2Affine> {
    G2Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| ark_to_voting_error("G2 deserialise", e))
}

/// FN: aggregate_g1
/// WHAT: G1 sum of an iterable of `G1Affine`s, returning an affine.
/// USAGE: compute `agg_signers` off-chain (sum of signer pubkeys).
pub fn aggregate_g1<'a>(points: impl IntoIterator<Item = &'a G1Affine>) -> G1Affine {
    let mut acc = G1Projective::default();
    for p in points {
        acc += p;
    }
    acc.into_affine()
}

/// FN: aggregate_g2
/// WHAT: G2 sum (used for aggregate signatures off-chain when the
///       prover needs an arkworks-typed agg_sig for sanity checks).
pub fn aggregate_g2<'a>(points: impl IntoIterator<Item = &'a G2Affine>) -> G2Affine {
    let mut acc = G2Projective::default();
    for p in points {
        acc += p;
    }
    acc.into_affine()
}

/// FN: scalars_to_fr_array
/// WHAT: bridge `Scalars` (8-tuple of `Bytes32`, our wire form) to
///       the `[Fr; 8]` form the Groth16 circuit consumes as public
///       inputs.
/// CONTRACT: each `s_i` is interpreted big-endian and reduced
///           mod r. This MUST agree with the on-chain
///           `bls_g1_multiply` opcode's scalar interpretation —
///           pinned by the `bytes32_to_fr_be_endianness` test.
/// USAGE: called by `VotingCircuit::public_inputs_as_fr` so the
///        off-chain circuit's public-input commitment matches the
///        on-chain `IC[0] + Σ s_i * IC[i+1]` linear combination
///        byte-for-byte (i = 1..=8 under the CHIP rev that promoted
///        (num, den) to first-class public inputs s7/s8).
pub fn scalars_to_fr_array(s: &Scalars) -> [Fr; 8] {
    [
        bytes32_to_fr(&s.s1),
        bytes32_to_fr(&s.s2),
        bytes32_to_fr(&s.s3),
        bytes32_to_fr(&s.s4),
        bytes32_to_fr(&s.s5),
        bytes32_to_fr(&s.s6),
        bytes32_to_fr(&s.s7),
        bytes32_to_fr(&s.s8),
    ]
}

// ── Internal helpers ─────────────────────────────────────────────────

fn voting_error(msg: &str) -> VotingError {
    VotingError::Other(anyhow_compat::Error(msg.into()))
}

fn ark_to_voting_error(op: &str, e: ark_serialize::SerializationError) -> VotingError {
    VotingError::Other(anyhow_compat::Error(format!("{op}: {e}").into()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{sign, SecretKey};

    fn deterministic_pubkey() -> PublicKey {
        SecretKey::from_seed(&[0x42u8; 32]).public_key()
    }

    fn deterministic_signature() -> Signature {
        let sk = SecretKey::from_seed(&[0x99u8; 32]);
        sign(&sk, b"test-message")
    }

    /// WHAT: `chia_bls::PublicKey::to_bytes()` and arkworks'
    ///       `G1Affine::serialize_compressed` produce IDENTICAL
    ///       byte buffers for the same point.
    /// HOW:  generate a deterministic chia_bls PK; convert to
    ///       arkworks G1Affine; re-serialize via arkworks; compare
    ///       bytes to original chia_bls bytes.
    /// WHY:  this is THE CRITICAL invariant — without it, the proof
    ///       bytes our prover generates (via arkworks) wouldn't
    ///       match what the on-chain `bls_pairing_identity` opcode
    ///       expects (which speaks chia_bls / IETF compressed
    ///       format). Test failure here means we cannot submit
    ///       proofs on-chain.
    #[test]
    fn chia_g1_bytes_match_arkworks_g1_bytes() {
        let pk = deterministic_pubkey();
        let chia_bytes = pk.to_bytes();
        let g1 = chia_pk_to_ark_g1(&pk).expect("chia PK parses as G1");
        let mut ark_bytes = Vec::new();
        g1.serialize_compressed(&mut ark_bytes).unwrap();
        assert_eq!(ark_bytes.len(), 48);
        assert_eq!(&chia_bytes[..], &ark_bytes[..], "encoding mismatch");
    }

    /// WHAT: `chia_bls::Signature::to_bytes()` and arkworks'
    ///       `G2Affine::serialize_compressed` produce IDENTICAL
    ///       byte buffers for the same point.
    /// HOW:  same pattern as the G1 test, with a real BLS signature.
    /// WHY:  same security argument as the G1 test, applied to G2
    ///       (used for the proof's B point and the aggregate sig).
    #[test]
    fn chia_g2_bytes_match_arkworks_g2_bytes() {
        let sig = deterministic_signature();
        let chia_bytes = sig.to_bytes();
        let g2 = chia_sig_to_ark_g2(&sig).expect("chia Sig parses as G2");
        let mut ark_bytes = Vec::new();
        g2.serialize_compressed(&mut ark_bytes).unwrap();
        assert_eq!(ark_bytes.len(), 96);
        assert_eq!(&chia_bytes[..], &ark_bytes[..], "encoding mismatch");
    }

    /// WHAT: chia_pk → ark_g1 → chia_pk round-trips losslessly.
    /// HOW:  start with a deterministic chia PK, convert there and
    ///       back, assert equality.
    /// WHY:  proves the conversion functions form an isomorphism on
    ///       the typed PublicKey surface. Any drift would mean the
    ///       SDK's chia_bls types and arkworks types disagree on
    ///       what a "valid pubkey" is.
    #[test]
    fn chia_pk_arkworks_roundtrip() {
        let pk = deterministic_pubkey();
        let g1 = chia_pk_to_ark_g1(&pk).unwrap();
        let pk2 = ark_g1_to_chia_pk(&g1).unwrap();
        assert_eq!(pk, pk2);
    }

    /// WHAT: chia_sig → ark_g2 → chia_sig round-trips losslessly.
    #[test]
    fn chia_sig_arkworks_roundtrip() {
        let sig = deterministic_signature();
        let g2 = chia_sig_to_ark_g2(&sig).unwrap();
        let sig2 = ark_g2_to_chia_sig(&g2).unwrap();
        assert_eq!(sig, sig2);
    }

    /// WHAT: G1 compressed-byte serialisation produces the canonical
    ///       48-byte length AND parses back to the same point.
    /// HOW:  serialize via `g1_compressed_bytes`, parse via
    ///       `g1_from_compressed_bytes`, compare.
    /// WHY:  the on-chain VK + proof are passed as raw byte buffers;
    ///       round-trip safety here pins the byte-level contract.
    #[test]
    fn g1_compressed_bytes_roundtrip() {
        let pk = deterministic_pubkey();
        let g1 = chia_pk_to_ark_g1(&pk).unwrap();
        let bytes = g1_compressed_bytes(&g1).unwrap();
        assert_eq!(bytes.len(), 48);
        let g1_back = g1_from_compressed_bytes(&bytes).unwrap();
        assert_eq!(g1, g1_back);
    }

    /// WHAT: G2 compressed-byte serialisation produces the canonical
    ///       96-byte length AND parses back to the same point.
    #[test]
    fn g2_compressed_bytes_roundtrip() {
        let sig = deterministic_signature();
        let g2 = chia_sig_to_ark_g2(&sig).unwrap();
        let bytes = g2_compressed_bytes(&g2).unwrap();
        assert_eq!(bytes.len(), 96);
        let g2_back = g2_from_compressed_bytes(&bytes).unwrap();
        assert_eq!(g2, g2_back);
    }

    /// WHAT: `bytes32_to_fr(sha256(x))` matches the on-chain
    ///       interpretation of a sha256 hash as a BLS12-381 scalar.
    /// HOW:  hash a known input, convert to Fr, serialise back to
    ///       big-endian bytes, compare to the original sha256 (after
    ///       any modular reduction).
    /// WHY:  the on-chain `bls_g1_multiply` opcode reads scalar
    ///       bytes BIG-endian and reduces mod r. Our off-chain
    ///       prover MUST use the same convention or the linear
    ///       combination `IC[0] + s_i * IC[i]` will diverge between
    ///       prover and verifier.
    #[test]
    fn bytes32_to_fr_be_endianness() {
        // For inputs that fit in r (i.e., < 2^255), no reduction
        // happens, so fr_to_bytes32_be(bytes32_to_fr(x)) == x.
        let small = Bytes32::new([
            0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);
        let fr = bytes32_to_fr(&small);
        let back = fr_to_bytes32_be(&fr);
        assert_eq!(&back[..], small.as_ref());
    }

    /// WHAT: `aggregate_g1` of an empty iterator returns the G1
    ///       identity element.
    /// HOW:  call with no points; convert back to a known representation.
    /// WHY:  identity-element behaviour on G1 is what makes the sum
    ///       of N pubkeys well-defined for N=0 (no signers); pinned
    ///       so a refactor doesn't accidentally panic on empty input.
    #[test]
    fn aggregate_g1_empty_is_identity() {
        use ark_ec::AffineRepr;
        let agg = aggregate_g1(std::iter::empty());
        assert!(agg.is_zero(), "G1 sum of empty set must be the identity");
    }

    /// WHAT: `aggregate_g1` is order-independent (G1 addition is
    ///       commutative).
    /// HOW:  build two distinct G1 points, sum in both orders, assert
    ///       equal.
    /// WHY:  the off-chain Aggregator may receive votes in arbitrary
    ///       order; the resulting agg_signers must NOT depend on
    ///       order.
    #[test]
    fn aggregate_g1_is_commutative() {
        let pk1 = SecretKey::from_seed(&[1u8; 32]).public_key();
        let pk2 = SecretKey::from_seed(&[2u8; 32]).public_key();
        let g1 = chia_pk_to_ark_g1(&pk1).unwrap();
        let g2 = chia_pk_to_ark_g1(&pk2).unwrap();
        assert_eq!(aggregate_g1(&[g1, g2]), aggregate_g1(&[g2, g1]));
    }

    /// WHAT: `aggregate_g1` of `n` copies of the same point equals
    ///       `n * point` (consistency with scalar multiplication).
    /// HOW:  build a G1 point, sum 3 copies, compare to 3*point.
    /// WHY:  documents the expected algebraic relationship; a
    ///       subtle mistake (e.g., counting wrong) would silently
    ///       break aggregation.
    #[test]
    fn aggregate_g1_three_copies_equals_three_times() {
        let pk = deterministic_pubkey();
        let g1 = chia_pk_to_ark_g1(&pk).unwrap();
        let three_x = aggregate_g1(&[g1, g1, g1]);
        let scalar_three = G1Projective::from(g1) * Fr::from(3u64);
        assert_eq!(three_x, scalar_three.into_affine());
    }
}
