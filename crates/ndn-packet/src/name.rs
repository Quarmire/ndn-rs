//! NDN Name and NameComponent — re-exported from `ndn-foundation-types` so
//! lightweight consumers can pull in name primitives without `ndn-packet`.

pub use ndn_foundation_types::name::{Name, NameComponent};

/// Construct a [`Name`] from an NDN URI string literal.
///
/// ```
/// # use ndn_packet::name;
/// let prefix = name!("/iperf");
/// assert_eq!(prefix.to_string(), "/iperf");
/// ```
///
/// Panics at runtime if the string is not a valid NDN name.
#[macro_export]
macro_rules! name {
    ($s:expr) => {
        <$crate::Name as ::core::str::FromStr>::from_str($s)
            .expect(concat!("invalid NDN name: ", $s))
    };
}

#[cfg(test)]
pub(crate) fn build_name_value(components: &[&[u8]]) -> bytes::Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for comp in components {
        w.write_tlv(crate::tlv_type::NAME_COMPONENT, comp);
    }
    w.finish()
}

// The tests from the original name.rs — they use Name/NameComponent which are
// now re-exported, so they should compile without modification.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv_type;
    use bytes::Bytes;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(name: &Name) -> u64 {
        let mut h = DefaultHasher::new();
        name.hash(&mut h);
        h.finish()
    }

    fn comp(s: &[u8]) -> NameComponent {
        NameComponent::generic(bytes::Bytes::copy_from_slice(s))
    }

    #[test]
    fn root_is_empty() {
        let n = Name::root();
        assert!(n.is_empty());
        assert_eq!(n.len(), 0);
        assert_eq!(n.components().len(), 0);
    }

    #[test]
    fn from_components_stores_all() {
        let n = Name::from_components([comp(b"edu"), comp(b"ucla"), comp(b"news")]);
        assert_eq!(n.len(), 3);
        assert_eq!(n.components()[0].value.as_ref(), b"edu");
        assert_eq!(n.components()[1].value.as_ref(), b"ucla");
        assert_eq!(n.components()[2].value.as_ref(), b"news");
    }

    #[test]
    fn has_prefix_true() {
        let name = Name::from_components([comp(b"edu"), comp(b"ucla"), comp(b"news")]);
        let prefix = Name::from_components([comp(b"edu"), comp(b"ucla")]);
        assert!(name.has_prefix(&prefix));
    }

    #[test]
    fn has_prefix_equal_names() {
        let name = Name::from_components([comp(b"edu"), comp(b"ucla")]);
        assert!(name.has_prefix(&name.clone()));
    }

    #[test]
    fn has_prefix_root_is_prefix_of_everything() {
        let name = Name::from_components([comp(b"any"), comp(b"name")]);
        assert!(name.has_prefix(&Name::root()));
    }

    #[test]
    fn has_prefix_false_different_component() {
        let name = Name::from_components([comp(b"edu"), comp(b"ucla")]);
        let prefix = Name::from_components([comp(b"edu"), comp(b"mit")]);
        assert!(!name.has_prefix(&prefix));
    }

    #[test]
    fn has_prefix_false_prefix_longer_than_name() {
        let name = Name::from_components([comp(b"edu")]);
        let prefix = Name::from_components([comp(b"edu"), comp(b"ucla")]);
        assert!(!name.has_prefix(&prefix));
    }

    #[test]
    fn decode_empty_name() {
        let name = Name::decode(bytes::Bytes::new()).unwrap();
        assert!(name.is_empty());
    }

    #[test]
    fn decode_one_component() {
        let value = build_name_value(&[b"hello"]);
        let name = Name::decode(value).unwrap();
        assert_eq!(name.len(), 1);
        assert_eq!(name.components()[0].value.as_ref(), b"hello");
        assert_eq!(name.components()[0].typ, tlv_type::NAME_COMPONENT);
    }

    #[test]
    fn decode_multiple_components() {
        let value = build_name_value(&[b"edu", b"ucla", b"data"]);
        let name = Name::decode(value).unwrap();
        assert_eq!(name.len(), 3);
        assert_eq!(name.components()[2].value.as_ref(), b"data");
    }

    #[test]
    fn decode_preserves_component_type() {
        // Component with a non-generic type (e.g. ImplicitSha256 = 0x01).
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_tlv(0x01, &[0xAA; 32]);
        let value = w.finish();
        let name = Name::decode(value).unwrap();
        assert_eq!(name.components()[0].typ, 0x01);
    }

    #[test]
    fn display_root() {
        assert_eq!(Name::root().to_string(), "/");
    }

    #[test]
    fn display_single_component() {
        let n = Name::from_components([comp(b"ndn")]);
        assert_eq!(n.to_string(), "/ndn");
    }

    #[test]
    fn display_multi_component() {
        let n = Name::from_components([comp(b"edu"), comp(b"ucla"), comp(b"data")]);
        assert_eq!(n.to_string(), "/edu/ucla/data");
    }

    #[test]
    fn display_non_ascii_percent_encoded() {
        let n =
            Name::from_components([NameComponent::generic(bytes::Bytes::from(vec![0x00, 0xFF]))]);
        // 0x00 is not ascii_graphic, 0xFF is not ascii_graphic
        assert_eq!(n.to_string(), "/%00%FF");
    }

    #[test]
    fn equal_names_have_equal_hash() {
        let a = Name::from_components([comp(b"foo"), comp(b"bar")]);
        let b = Name::from_components([comp(b"foo"), comp(b"bar")]);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn different_names_are_not_equal() {
        let a = Name::from_components([comp(b"foo")]);
        let b = Name::from_components([comp(b"bar")]);
        assert_ne!(a, b);
    }

    #[test]
    fn component_type_affects_equality() {
        let generic = NameComponent::generic(bytes::Bytes::copy_from_slice(b"abc"));
        let implicit = NameComponent {
            typ: 0x01,
            value: bytes::Bytes::copy_from_slice(b"abc"),
        };
        assert_ne!(generic, implicit);
    }

    #[test]
    fn from_str_simple() {
        let n: Name = "/edu/ucla/data".parse().unwrap();
        assert_eq!(n.len(), 3);
        assert_eq!(n.components()[0].value.as_ref(), b"edu");
        assert_eq!(n.components()[2].value.as_ref(), b"data");
    }

    #[test]
    fn from_str_root() {
        let n: Name = "/".parse().unwrap();
        assert!(n.is_empty());
    }

    #[test]
    fn from_str_empty_string() {
        let n: Name = "".parse().unwrap();
        assert!(n.is_empty());
    }

    #[test]
    fn from_str_trailing_slash() {
        let n: Name = "/test/".parse().unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n.components()[0].value.as_ref(), b"test");
    }

    #[test]
    fn from_str_percent_decode() {
        let n: Name = "/%00%FF".parse().unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n.components()[0].value.as_ref(), &[0x00, 0xFF]);
    }

    #[test]
    fn from_str_lowercase_hex() {
        let n: Name = "/%0a%ff".parse().unwrap();
        assert_eq!(n.components()[0].value.as_ref(), &[0x0A, 0xFF]);
    }

    #[test]
    fn from_str_no_leading_slash_is_err() {
        assert!("edu/ucla".parse::<Name>().is_err());
    }

    #[test]
    fn from_str_bad_percent_is_err() {
        assert!("/%ZZ".parse::<Name>().is_err());
    }

    #[test]
    fn display_from_str_roundtrip() {
        let original = Name::from_components([
            comp(b"edu"),
            comp(b"ucla"),
            NameComponent::generic(bytes::Bytes::from(vec![0x00, 0xFF])),
        ]);
        let s = original.to_string();
        let parsed: Name = s.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn append_builds_name() {
        let n = Name::root().append("edu").append("ucla");
        assert_eq!(n.len(), 2);
        assert_eq!(n.to_string(), "/edu/ucla");
    }

    #[test]
    fn append_segment() {
        let n: Name = "/iperf".parse().unwrap();
        let n = n.append_segment(42);
        assert_eq!(n.len(), 2);
        assert_eq!(n.components()[1].typ, tlv_type::SEGMENT);
    }

    #[test]
    fn append_segment_zero() {
        let n = Name::root().append_segment(0);
        assert_eq!(n.components()[0].value.as_ref(), &[0u8]);
    }

    #[test]
    fn name_macro() {
        let n = name!("/iperf/data");
        assert_eq!(n.len(), 2);
        assert_eq!(n.to_string(), "/iperf/data");
    }

    #[test]
    fn keyword_component_roundtrip() {
        let c = NameComponent::keyword(Bytes::from_static(b"hello"));
        assert_eq!(c.typ, tlv_type::KEYWORD);
        assert_eq!(c.value.as_ref(), b"hello");
    }

    #[test]
    fn byte_offset_roundtrip() {
        let c = NameComponent::byte_offset(1024);
        assert_eq!(c.typ, tlv_type::BYTE_OFFSET);
        assert_eq!(c.as_byte_offset(), Some(1024));
    }

    #[test]
    fn version_roundtrip() {
        let c = NameComponent::version(7);
        assert_eq!(c.typ, tlv_type::VERSION);
        assert_eq!(c.as_version(), Some(7));
    }

    #[test]
    fn timestamp_roundtrip() {
        let c = NameComponent::timestamp(1_700_000_000);
        assert_eq!(c.typ, tlv_type::TIMESTAMP);
        assert_eq!(c.as_timestamp(), Some(1_700_000_000));
    }

    #[test]
    fn sequence_num_roundtrip() {
        let c = NameComponent::sequence_num(42);
        assert_eq!(c.typ, tlv_type::SEQUENCE_NUM);
        assert_eq!(c.as_sequence_num(), Some(42));
    }

    #[test]
    fn zero_value_roundtrip() {
        assert_eq!(NameComponent::version(0).as_version(), Some(0));
        assert_eq!(NameComponent::sequence_num(0).as_sequence_num(), Some(0));
        assert_eq!(NameComponent::byte_offset(0).as_byte_offset(), Some(0));
        assert_eq!(NameComponent::timestamp(0).as_timestamp(), Some(0));
    }

    #[test]
    fn accessor_wrong_type_returns_none() {
        let c = NameComponent::version(5);
        assert_eq!(c.as_segment(), None);
        assert_eq!(c.as_byte_offset(), None);
        assert_eq!(c.as_timestamp(), None);
        assert_eq!(c.as_sequence_num(), None);
    }

    #[test]
    fn as_segment_accessor() {
        let n = Name::root().append_segment(99);
        assert_eq!(n.components()[0].as_segment(), Some(99));
    }

    #[test]
    fn builder_chaining_all_types() {
        let n = Name::root()
            .append("data")
            .append_version(3)
            .append_segment(0);
        assert_eq!(n.len(), 3);
        assert_eq!(n.components()[0].typ, tlv_type::NAME_COMPONENT);
        assert_eq!(n.components()[1].typ, tlv_type::VERSION);
        assert_eq!(n.components()[1].as_version(), Some(3));
        assert_eq!(n.components()[2].typ, tlv_type::SEGMENT);
        assert_eq!(n.components()[2].as_segment(), Some(0));
    }

    #[test]
    fn builder_timestamp_and_sequence() {
        let n = Name::root()
            .append("sensor")
            .append_timestamp(1_700_000)
            .append_sequence_num(5)
            .append_byte_offset(4096);
        assert_eq!(n.len(), 4);
        assert_eq!(n.components()[1].as_timestamp(), Some(1_700_000));
        assert_eq!(n.components()[2].as_sequence_num(), Some(5));
        assert_eq!(n.components()[3].as_byte_offset(), Some(4096));
    }

    #[test]
    fn display_segment() {
        let n = Name::root().append("data").append_segment(42);
        assert_eq!(n.to_string(), "/data/seg=42");
    }

    #[test]
    fn display_version() {
        let n = Name::root().append("data").append_version(3);
        assert_eq!(n.to_string(), "/data/v=3");
    }

    #[test]
    fn display_timestamp() {
        let n = Name::root().append("data").append_timestamp(1000);
        assert_eq!(n.to_string(), "/data/t=1000");
    }

    #[test]
    fn display_sequence_num() {
        let n = Name::root().append("data").append_sequence_num(7);
        assert_eq!(n.to_string(), "/data/seq=7");
    }

    #[test]
    fn display_byte_offset() {
        let n = Name::root().append("data").append_byte_offset(512);
        assert_eq!(n.to_string(), "/data/off=512");
    }

    #[test]
    fn display_keyword() {
        let n = Name::root().append_component(NameComponent::keyword(Bytes::from_static(b"test")));
        assert_eq!(n.to_string(), "/keyword=test");
    }

    #[test]
    fn display_sha256digest() {
        let digest = [0xABu8; 32];
        let n = Name::root().append_component(NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::copy_from_slice(&digest),
        ));
        let expected_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(n.to_string(), format!("/sha256digest={expected_hex}"));
    }

    #[test]
    fn display_params_sha256() {
        let digest = [0xCDu8; 32];
        let n = Name::root().append_component(NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::copy_from_slice(&digest),
        ));
        let expected_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(n.to_string(), format!("/params-sha256={expected_hex}"));
    }

    #[test]
    fn display_mixed_typed_and_generic() {
        let n = Name::root()
            .append("ndn")
            .append("data")
            .append_version(3)
            .append_segment(0);
        assert_eq!(n.to_string(), "/ndn/data/v=3/seg=0");
    }

    /// `Name::from_str` round-trips the URI alternates the Display side emits
    /// (`sha256digest=`, `params-sha256=`, `keyword=`).
    #[test]
    fn a19_uri_roundtrip_sha256digest() {
        let digest = [0xABu8; 32];
        let n = Name::root().append_component(NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::copy_from_slice(&digest),
        ));
        let s = n.to_string();
        let parsed: Name = s.parse().expect("sha256digest URI must parse");
        assert_eq!(parsed.components()[0].typ, tlv_type::IMPLICIT_SHA256);
        assert_eq!(parsed.components()[0].value.as_ref(), &digest);
    }

    #[test]
    fn a19_uri_roundtrip_params_sha256() {
        let digest = [0xCDu8; 32];
        let n = Name::root().append_component(NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::copy_from_slice(&digest),
        ));
        let parsed: Name = n.to_string().parse().expect("params-sha256 URI must parse");
        assert_eq!(parsed.components()[0].typ, tlv_type::PARAMETERS_SHA256);
        assert_eq!(parsed.components()[0].value.as_ref(), &digest);
    }

    #[test]
    fn a19_uri_roundtrip_keyword() {
        let n = Name::root().append_component(NameComponent::keyword(Bytes::from_static(b"hello")));
        let parsed: Name = n.to_string().parse().expect("keyword= URI must parse");
        assert_eq!(parsed.components()[0].typ, tlv_type::KEYWORD);
        assert_eq!(parsed.components()[0].value.as_ref(), b"hello");
    }

    /// Canonical `<type-number>=<value>` form per `name.html`; any spec-defined
    /// typed component round-trips via its decimal TLV-TYPE.
    #[test]
    fn a19_uri_roundtrip_canonical_typed_form() {
        // Type 200 with value "abc" — arbitrary, not a registered type.
        let parsed: Name = "/200=abc".parse().expect("typed-component URI must parse");
        assert_eq!(parsed.components()[0].typ, 200);
        assert_eq!(parsed.components()[0].value.as_ref(), b"abc");
    }

    #[test]
    fn a19_uri_display_preserves_arbitrary_typed_component() {
        let n = Name::root().append_component(NameComponent::new(200, Bytes::from_static(b"abc")));
        assert_eq!(n.to_string(), "/200=abc");
        let parsed: Name = n
            .to_string()
            .parse()
            .expect("typed-component URI must parse");
        assert_eq!(parsed.components()[0].typ, 200);
        assert_eq!(parsed.components()[0].value.as_ref(), b"abc");
    }

    #[test]
    fn a01_type3_component_has_no_blake3_uri_semantics() {
        let n = Name::root().append_component(NameComponent::new(3, Bytes::from_static(b"abc")));
        assert_eq!(n.to_string(), "/3=abc");

        let parsed: Name = "/blake3digest=abc"
            .parse()
            .expect("unrecognized URI prefix falls back to generic component");
        assert_eq!(parsed.components()[0].typ, tlv_type::NAME_COMPONENT);
        assert_eq!(parsed.components()[0].value.as_ref(), b"blake3digest=abc");
    }
}
