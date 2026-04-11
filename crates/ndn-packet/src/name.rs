use core::str::FromStr;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::PacketError;
use crate::tlv_type;
use ndn_tlv::TlvReader;

/// A single NDN name component: a (type, value) pair.
///
/// The value is a zero-copy slice of the original packet buffer.
///
/// Ordering follows the NDN Packet Format v0.3 §2.1 canonical order:
/// TLV-TYPE first, then TLV-LENGTH (shorter is smaller), then TLV-VALUE
/// byte-by-byte. This matches the order used by NFD and ndn-cxx.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NameComponent {
    pub typ: u64,
    pub value: Bytes,
}

impl PartialOrd for NameComponent {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameComponent {
    /// NDN canonical component ordering (NDN Packet Format v0.3 §2.1).
    ///
    /// Order: TLV-TYPE ascending, then TLV-LENGTH ascending (shorter is
    /// smaller), then TLV-VALUE byte-by-byte ascending.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.typ
            .cmp(&other.typ)
            .then_with(|| self.value.len().cmp(&other.value.len()))
            .then_with(|| self.value.as_ref().cmp(other.value.as_ref()))
    }
}

impl NameComponent {
    pub fn new(typ: u64, value: Bytes) -> Self {
        Self { typ, value }
    }

    pub fn generic(value: Bytes) -> Self {
        Self {
            typ: tlv_type::NAME_COMPONENT,
            value,
        }
    }

    /// Create a Keyword component (type 0x20) with opaque bytes.
    pub fn keyword(value: Bytes) -> Self {
        Self::new(tlv_type::KEYWORD, value)
    }

    /// Create a ByteOffset component (type 0x34), big-endian with leading zeros stripped.
    pub fn byte_offset(offset: u64) -> Self {
        Self::new(tlv_type::BYTE_OFFSET, encode_nonnegtive_integer(offset))
    }

    /// Create a Version component (type 0x36), big-endian with leading zeros stripped.
    pub fn version(v: u64) -> Self {
        Self::new(tlv_type::VERSION, encode_nonnegtive_integer(v))
    }

    /// Create a Timestamp component (type 0x38), big-endian with leading zeros stripped.
    pub fn timestamp(ts: u64) -> Self {
        Self::new(tlv_type::TIMESTAMP, encode_nonnegtive_integer(ts))
    }

    /// Create a SequenceNum component (type 0x3A), big-endian with leading zeros stripped.
    pub fn sequence_num(seq: u64) -> Self {
        Self::new(tlv_type::SEQUENCE_NUM, encode_nonnegtive_integer(seq))
    }

    /// Decode a Segment component value as u64. Returns `None` if not type 0x32.
    pub fn as_segment(&self) -> Option<u64> {
        if self.typ == tlv_type::SEGMENT {
            Some(decode_nonnegative_integer(&self.value))
        } else {
            None
        }
    }

    /// Decode a ByteOffset component value as u64. Returns `None` if not type 0x34.
    pub fn as_byte_offset(&self) -> Option<u64> {
        if self.typ == tlv_type::BYTE_OFFSET {
            Some(decode_nonnegative_integer(&self.value))
        } else {
            None
        }
    }

    /// Decode a Version component value as u64. Returns `None` if not type 0x36.
    pub fn as_version(&self) -> Option<u64> {
        if self.typ == tlv_type::VERSION {
            Some(decode_nonnegative_integer(&self.value))
        } else {
            None
        }
    }

    /// Decode a Timestamp component value as u64. Returns `None` if not type 0x38.
    pub fn as_timestamp(&self) -> Option<u64> {
        if self.typ == tlv_type::TIMESTAMP {
            Some(decode_nonnegative_integer(&self.value))
        } else {
            None
        }
    }

    /// Decode a SequenceNum component value as u64. Returns `None` if not type 0x3A.
    pub fn as_sequence_num(&self) -> Option<u64> {
        if self.typ == tlv_type::SEQUENCE_NUM {
            Some(decode_nonnegative_integer(&self.value))
        } else {
            None
        }
    }
}

/// Encode a u64 as big-endian bytes with leading zeros stripped (at least 1 byte).
fn encode_nonnegtive_integer(v: u64) -> Bytes {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    Bytes::copy_from_slice(&bytes[start..])
}

/// Decode big-endian stripped bytes back to u64.
fn decode_nonnegative_integer(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    val
}

/// An NDN name: an ordered sequence of name components.
///
/// Components are stored in a `SmallVec` with inline capacity for 8 elements,
/// covering typical 4–8 component names without heap allocation.
///
/// Ordering follows the NDN Packet Format v0.3 §2.1 canonical order,
/// component by component using [`NameComponent`]'s `Ord` impl.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    components: SmallVec<[NameComponent; 8]>,
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    /// NDN canonical name ordering (NDN Packet Format v0.3 §2.1).
    ///
    /// Names are compared component by component from left to right.
    /// If all shared components are equal, the shorter name is smaller
    /// (prefix ordering).
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.components.iter().cmp(other.components.iter())
    }
}

impl Name {
    /// The root (empty) name `/`.
    pub fn root() -> Self {
        Self {
            components: SmallVec::new(),
        }
    }

    pub fn from_components(components: impl IntoIterator<Item = NameComponent>) -> Self {
        Self {
            components: components.into_iter().collect(),
        }
    }

    pub fn components(&self) -> &[NameComponent] {
        &self.components
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns `true` if `prefix` is a prefix of (or equal to) this name.
    pub fn has_prefix(&self, prefix: &Name) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        self.components
            .iter()
            .zip(prefix.components.iter())
            .all(|(a, b)| a == b)
    }

    /// Decode a `Name` TLV from `reader`. The reader must be positioned at the
    /// start of the Name value (after the outer type+length have been consumed).
    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(value);
        let mut components = SmallVec::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            components.push(NameComponent::new(typ, val));
        }
        Ok(Self { components })
    }

    // ── Builder methods ──────────────────────────────────────────────────────

    /// Append a generic component from raw bytes.
    pub fn append(mut self, value: impl AsRef<[u8]>) -> Self {
        self.components
            .push(NameComponent::generic(Bytes::copy_from_slice(
                value.as_ref(),
            )));
        self
    }

    /// Append an already-constructed component.
    pub fn append_component(mut self, comp: NameComponent) -> Self {
        self.components.push(comp);
        self
    }

    /// Append a segment number component (type `0x32`, big-endian encoding with
    /// leading zeros stripped per NDN naming conventions).
    pub fn append_segment(self, seg: u64) -> Self {
        self.append_component(NameComponent::new(
            tlv_type::SEGMENT,
            encode_nonnegtive_integer(seg),
        ))
    }

    /// Append a Version component (type 0x36).
    pub fn append_version(self, v: u64) -> Self {
        self.append_component(NameComponent::version(v))
    }

    /// Append a Timestamp component (type 0x38).
    pub fn append_timestamp(self, ts: u64) -> Self {
        self.append_component(NameComponent::timestamp(ts))
    }

    /// Append a SequenceNum component (type 0x3A).
    pub fn append_sequence_num(self, seq: u64) -> Self {
        self.append_component(NameComponent::sequence_num(seq))
    }

    /// Append a ByteOffset component (type 0x34).
    pub fn append_byte_offset(self, off: u64) -> Self {
        self.append_component(NameComponent::byte_offset(off))
    }
}

impl FromStr for Name {
    type Err = PacketError;

    /// Parse an NDN URI string into a `Name`.
    ///
    /// Handles percent-decoding to roundtrip with `Display`.
    ///
    /// ```
    /// # use ndn_packet::Name;
    /// let name: Name = "/edu/ucla/data".parse().unwrap();
    /// assert_eq!(name.to_string(), "/edu/ucla/data");
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() || s == "/" {
            return Ok(Self::root());
        }

        // Must start with '/'.
        if !s.starts_with('/') {
            return Err(PacketError::MalformedPacket(
                "name must start with '/'".into(),
            ));
        }

        let mut components = SmallVec::new();
        for part in s[1..].split('/') {
            if part.is_empty() {
                continue; // tolerate trailing slash
            }
            let decoded = percent_decode(part).map_err(|_| {
                PacketError::MalformedPacket("invalid percent-encoding in name".into())
            })?;
            components.push(NameComponent::generic(Bytes::from(decoded)));
        }

        if components.is_empty() {
            Ok(Self::root())
        } else {
            Ok(Self { components })
        }
    }
}

/// Decode percent-encoded bytes in a name component.
fn percent_decode(s: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hi = hex_digit(bytes[i + 1])?;
            let lo = hex_digit(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(()),
    }
}

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

/// Build Name TLV value bytes (the content inside a `0x07` TLV) for testing.
#[cfg(test)]
pub(crate) fn build_name_value(components: &[&[u8]]) -> bytes::Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for comp in components {
        w.write_tlv(tlv_type::NAME_COMPONENT, comp);
    }
    w.finish()
}

/// Percent-encode a byte slice for NDN URI display.
fn percent_encode_component(f: &mut core::fmt::Formatter<'_>, value: &[u8]) -> core::fmt::Result {
    for &b in value {
        if b.is_ascii_graphic() && b != b'/' && b != b'%' {
            write!(f, "{}", b as char)?;
        } else {
            write!(f, "%{b:02X}")?;
        }
    }
    Ok(())
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "/")?;
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            match c.typ {
                tlv_type::IMPLICIT_SHA256 => {
                    write!(f, "sha256digest=")?;
                    for &b in c.value.iter() {
                        write!(f, "{b:02x}")?;
                    }
                }
                tlv_type::PARAMETERS_SHA256 => {
                    write!(f, "params-sha256=")?;
                    for &b in c.value.iter() {
                        write!(f, "{b:02x}")?;
                    }
                }
                tlv_type::KEYWORD => {
                    write!(f, "keyword=")?;
                    percent_encode_component(f, &c.value)?;
                }
                tlv_type::SEGMENT => {
                    write!(f, "seg={}", decode_nonnegative_integer(&c.value))?;
                }
                tlv_type::BYTE_OFFSET => {
                    write!(f, "off={}", decode_nonnegative_integer(&c.value))?;
                }
                tlv_type::VERSION => {
                    write!(f, "v={}", decode_nonnegative_integer(&c.value))?;
                }
                tlv_type::TIMESTAMP => {
                    write!(f, "t={}", decode_nonnegative_integer(&c.value))?;
                }
                tlv_type::SEQUENCE_NUM => {
                    write!(f, "seq={}", decode_nonnegative_integer(&c.value))?;
                }
                _ => {
                    // Generic component or unknown type: percent-encode.
                    percent_encode_component(f, &c.value)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // ── constructors ──────────────────────────────────────────────────────────

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

    // ── has_prefix ────────────────────────────────────────────────────────────

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

    // ── decode ────────────────────────────────────────────────────────────────

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

    // ── Display ───────────────────────────────────────────────────────────────

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

    // ── Hash / Eq ─────────────────────────────────────────────────────────────

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

    // ── FromStr ───────────────────────────────────────────────────────────────

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

    // ── append ────────────────────────────────────────────────────────────────

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

    // ── name! macro ───────────────────────────────────────────────────────────

    #[test]
    fn name_macro() {
        let n = name!("/iperf/data");
        assert_eq!(n.len(), 2);
        assert_eq!(n.to_string(), "/iperf/data");
    }

    // ── Typed component constructors ─────────────────────────────────────────

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

    // ── Builder method chaining ──────────────────────────────────────────────

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

    // ── Display with typed components ────────────────────────────────────────

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
}
