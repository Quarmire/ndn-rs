//! Cross-implementation interop vectors for the F2 wire format
//! (`docs/notes/coding-f2-wire-spec-2026-05-23.md`). These pin the exact bytes
//! another NDN library implements against. True cross-impl validation awaits a
//! second implementation; until then these golden vectors + from-spec decode
//! are the contract.
//!
//! Gated by `f2-recode`.

#![cfg(feature = "f2-recode")]

use bytes::Bytes;

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, GenerationDescriptor, RecodePolicy, RecodeToken, SourceCommitment,
    row_hash,
};

/// Golden bytes for a coded-packet `CodedMetadata` head (wire spec §4):
/// generation_id=1, Role=2 (coded), Field=0 (GF(2^8)), K=2, CodingVector=[1,2].
///
///   C8 11                      FEC-METADATA, len 17
///     CA 01 01                 GenerationId = 1
///     CC 01 02                 Role = 2 (coded)
///     D4 01 00                 Field = 0 (GF(2^8))
///     D0 02 00 02              K = 2
///     E4 02 01 02              CodingVector = [1, 2]
const CODED_METADATA_GOLDEN: &[u8] = &[
    0xC8, 0x11, 0xCA, 0x01, 0x01, 0xCC, 0x01, 0x02, 0xD4, 0x01, 0x00, 0xD0, 0x02, 0x00, 0x02, 0xE4,
    0x02, 0x01, 0x02,
];

#[test]
fn coded_metadata_matches_golden_bytes() {
    let meta = CodedMetadata {
        generation_id: 1,
        k: 2,
        field: Field::Gf8,
        vector: CodingVector(vec![1, 2]),
    };
    assert_eq!(
        meta.to_tlv().as_ref(),
        CODED_METADATA_GOLDEN,
        "CodedMetadata wire bytes drifted — update the spec vector deliberately"
    );
}

#[test]
fn coded_metadata_decodes_from_spec_bytes() {
    // A different implementation hands us the golden head + a payload; we must
    // decode it per the spec alone.
    let mut wire = CODED_METADATA_GOLDEN.to_vec();
    wire.extend_from_slice(b"ROW"); // coded row bytes follow the metadata
    let (meta, payload) = CodedMetadata::split(&wire).expect("decode from-spec bytes");
    assert_eq!(meta.generation_id, 1);
    assert_eq!(meta.k, 2);
    assert_eq!(meta.field, Field::Gf8);
    assert_eq!(meta.vector.0, vec![1, 2]);
    assert_eq!(payload.as_ref(), b"ROW");
}

/// Name-bearing structures (descriptor, token) carry an NDN Name TLV whose
/// exact bytes belong to `ndn-packet`, so we pin **canonical stability**
/// (decode∘encode is byte-identical, and the outer type is as specified)
/// rather than restate the Name encoding here.
#[test]
fn descriptor_and_token_canonical_roundtrip() {
    let sources: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
    let desc = GenerationDescriptor {
        generation_id: 42,
        k: 2,
        symbol_size: 4,
        field: Field::Gf8,
        content_name: "/alice/clip/v=3".parse().unwrap(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };
    let wire = desc.to_tlv();
    assert_eq!(wire[0], 0xD8, "GEN-DESCRIPTOR outer type (wire spec §6)");
    let decoded = GenerationDescriptor::from_tlv(&wire).unwrap();
    assert_eq!(decoded, desc);
    // Canonical: re-encoding the decoded form yields identical bytes.
    assert_eq!(decoded.to_tlv(), wire);

    let token = RecodeToken {
        generation_id: 7,
        recoder: "/site-a/recoders".parse().unwrap(),
        signature: Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]),
    };
    let twire = token.to_tlv();
    assert_eq!(twire[0], 0xEE, "RECODE-TOKEN outer type (wire spec §6)");
    let dtoken = RecodeToken::from_tlv(&twire).unwrap();
    assert_eq!(dtoken, token);
    assert_eq!(dtoken.to_tlv(), twire);
}
