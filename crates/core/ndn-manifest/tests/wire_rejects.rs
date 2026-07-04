//! Document-level wire rejects — the freeze's own mini red team, replayed
//! (ndf-the-landing Act III: "six attacks, six rejections"). These are the
//! named W-vectors' shapes; the materialized `.ndfv` files under
//! conformance/vectors/wire mirror these bytes.

use ndn_manifest::canon::{decode_document, put_tlv, put_varint, ty, Reject};

/// A minimal, canonical manifest whose single entry carries `value_tlv`.
fn manifest_with_entry(value_tlv: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_tlv(&mut body, ty::V_TERM_REF, &[7u8; 32]); // type term
    let mut d = Vec::new();
    put_tlv(&mut d, ty::V_NAME, b"yard.north/hive-a7/scale");
    put_tlv(&mut body, ty::DESCRIBES, &d);
    let mut e = Vec::new();
    put_tlv(&mut e, ty::V_TERM_REF, &[1u8; 32]); // field term
    e.extend_from_slice(value_tlv);
    put_tlv(&mut body, ty::MANIFEST_ENTRY, &e);
    let mut out = Vec::new();
    put_tlv(&mut out, ty::MANIFEST, &body);
    out
}

fn text_tlv(t: u64, s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_tlv(&mut out, t, s.as_bytes());
    out
}

#[test]
fn w03_non_minimal_length_smuggling_rejects() {
    // R2: a length of 0 encoded in two varint groups (0x80 0x00).
    let bytes = [0x30u8, 0x80, 0x00];
    assert_eq!(decode_document(&bytes), Err(Reject::NonMinimalVarint));
    // …and a non-minimal *type* likewise (0x30 encoded as 0xB0 0x00).
    let bytes = [0xB0u8, 0x00, 0x00];
    assert_eq!(decode_document(&bytes), Err(Reject::NonMinimalVarint));
}

#[test]
fn w22_varint_overflow_rejects() {
    // R3: an 11-byte all-continuation varint overflows u64.
    let mut bytes = vec![0x30u8];
    bytes.extend_from_slice(&[0xFF; 11]);
    assert_eq!(decode_document(&bytes), Err(Reject::VarintOverflow));
}

#[test]
fn w07_duplicate_map_key_rejects_verdict_flipping() {
    // R8: same key twice — the classic verdict-flip vehicle.
    let mut entries = Vec::new();
    for b in [0x01u8, 0x00] {
        entries.extend_from_slice(&text_tlv(ty::V_TEXT, "queen"));
        put_tlv(&mut entries, ty::V_BOOLEAN, &[b]);
    }
    let mut map = Vec::new();
    put_tlv(&mut map, ty::V_MAP, &entries);
    let doc = manifest_with_entry(&map);
    assert_eq!(decode_document(&doc), Err(Reject::DuplicateMapKey));
}

#[test]
fn w07b_unsorted_map_keys_reject() {
    let mut entries = Vec::new();
    for key in ["z", "a"] {
        entries.extend_from_slice(&text_tlv(ty::V_TEXT, key));
        put_tlv(&mut entries, ty::V_BOOLEAN, &[0x01]);
    }
    let mut map = Vec::new();
    put_tlv(&mut map, ty::V_MAP, &entries);
    let doc = manifest_with_entry(&map);
    assert_eq!(decode_document(&doc), Err(Reject::UnsortedMapKeys));
}

#[test]
fn w11_decimal_aliasing_cannot_fork_hashes() {
    // R4: 1 / 1.0 / +1 are one value with ONE encoding — only "1" decodes.
    for alias in ["1.0", "+1", "01", "-0", "0.50"] {
        let doc = manifest_with_entry(&text_tlv(ty::V_DECIMAL, alias));
        assert_eq!(decode_document(&doc), Err(Reject::NonCanonicalDecimal), "alias {alias}");
    }
    let ok = manifest_with_entry(&text_tlv(ty::V_DECIMAL, "1"));
    assert!(decode_document(&ok).is_ok());
}

#[test]
fn w14_nfc_confusables_are_distinct_on_the_wire() {
    // R5: no normalization — NFC "café" and NFD "café" are two byte strings,
    // two documents, two hashes. The wire stays honest; chips are UI duty.
    let nfc = manifest_with_entry(&text_tlv(ty::V_TEXT, "caf\u{e9}"));
    let nfd = manifest_with_entry(&text_tlv(ty::V_TEXT, "cafe\u{301}"));
    let a = decode_document(&nfc).expect("nfc decodes");
    let b = decode_document(&nfd).expect("nfd decodes");
    assert_ne!(nfc, nfd);
    assert_ne!(a, b);
    assert_ne!(
        ndn_manifest::document_hash(&nfc),
        ndn_manifest::document_hash(&nfd)
    );
}

#[test]
fn w19_critical_unknown_tlv_is_unresolved_not_a_crash() {
    // R12: critical bit set (odd extension type) ⇒ matches become Unresolved;
    // clear (even) ⇒ skipped. Neither crashes; both re-emit byte-identically.
    let mut critical = manifest_with_entry(&text_tlv(ty::V_TEXT, "x"));
    put_tlv(&mut critical, 0x81, &[0xde, 0xad, 0xbe, 0xef]);
    let d = decode_document(&critical).expect("decodes, never crashes");
    assert!(d.critical);

    let mut benign = manifest_with_entry(&text_tlv(ty::V_TEXT, "x"));
    put_tlv(&mut benign, 0x80, &[0x01]);
    let d = decode_document(&benign).expect("decodes");
    assert!(!d.critical);
}

#[test]
fn reserved_and_unassigned_types_reject() {
    // R1: 0x00–0x1F reserved; unassigned < 0x80 is spec-owned space.
    let mut bytes = Vec::new();
    put_tlv(&mut bytes, 0x05, &[]);
    assert_eq!(decode_document(&bytes), Err(Reject::NotADocument));
    // Unassigned 0x43 inside a value position.
    let mut inner = Vec::new();
    put_tlv(&mut inner, 0x43, &[0x01]);
    let doc = manifest_with_entry(&inner);
    assert_eq!(decode_document(&doc), Err(Reject::UnknownReservedType));
}

#[test]
fn trailing_non_extension_bytes_reject() {
    let mut bytes = manifest_with_entry(&text_tlv(ty::V_TEXT, "x"));
    put_tlv(&mut bytes, ty::MANIFEST, &[]); // a second document is not an extension
    assert_eq!(decode_document(&bytes), Err(Reject::TrailingBytes));
}

#[test]
fn truncation_rejects() {
    let bytes = manifest_with_entry(&text_tlv(ty::V_TEXT, "x"));
    for cut in 1..bytes.len() {
        // Every strict prefix must reject (typed), never panic.
        assert!(decode_document(&bytes[..cut]).is_err(), "prefix of {cut} bytes decoded");
    }
}

#[test]
fn boolean_bytes_are_00_or_01_only() {
    let mut v = Vec::new();
    put_tlv(&mut v, ty::V_BOOLEAN, &[0x02]);
    let doc = manifest_with_entry(&v);
    assert_eq!(decode_document(&doc), Err(Reject::InvalidBoolean));
}

#[test]
fn hash_bodies_are_exactly_32_bytes() {
    let mut v = Vec::new();
    put_tlv(&mut v, ty::V_HASH, &[0u8; 31]);
    let doc = manifest_with_entry(&v);
    assert_eq!(decode_document(&doc), Err(Reject::InvalidHashLength));
}

#[test]
fn varint_encoder_is_minimal_by_construction() {
    // The encoder half of R2/R3: spot-check boundary values.
    for (v, want) in [
        (0u64, vec![0x00u8]),
        (127, vec![0x7F]),
        (128, vec![0x80, 0x01]),
        (16_383, vec![0xFF, 0x7F]),
        (16_384, vec![0x80, 0x80, 0x01]),
    ] {
        let mut buf = Vec::new();
        put_varint(&mut buf, v);
        assert_eq!(buf, want, "varint({v})");
    }
}
