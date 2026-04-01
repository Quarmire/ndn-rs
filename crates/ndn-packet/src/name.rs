use core::str::FromStr;

use bytes::Bytes;
use smallvec::SmallVec;

use crate::PacketError;
use crate::tlv_type;
use ndn_tlv::TlvReader;

/// A single NDN name component: a (type, value) pair.
///
/// The value is a zero-copy slice of the original packet buffer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NameComponent {
    pub typ:   u64,
    pub value: Bytes,
}

impl NameComponent {
    pub fn new(typ: u64, value: Bytes) -> Self {
        Self { typ, value }
    }

    pub fn generic(value: Bytes) -> Self {
        Self { typ: tlv_type::NAME_COMPONENT, value }
    }
}

/// An NDN name: an ordered sequence of name components.
///
/// Components are stored in a `SmallVec` with inline capacity for 8 elements,
/// covering typical 4–8 component names without heap allocation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    components: SmallVec<[NameComponent; 8]>,
}

impl Name {
    /// The root (empty) name `/`.
    pub fn root() -> Self {
        Self { components: SmallVec::new() }
    }

    pub fn from_components(components: impl IntoIterator<Item = NameComponent>) -> Self {
        Self { components: components.into_iter().collect() }
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
        self.components.iter().zip(prefix.components.iter()).all(|(a, b)| a == b)
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
        self.components.push(NameComponent::generic(
            Bytes::copy_from_slice(value.as_ref()),
        ));
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
        let bytes = seg.to_be_bytes();
        // Strip leading zeros but keep at least one byte.
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let value = Bytes::copy_from_slice(&bytes[start..]);
        self.append_component(NameComponent::new(tlv_type::SEGMENT, value))
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
            return Err(PacketError::MalformedPacket("name must start with '/'".into()));
        }

        let mut components = SmallVec::new();
        for part in s[1..].split('/') {
            if part.is_empty() {
                continue; // tolerate trailing slash
            }
            let decoded = percent_decode(part)
                .map_err(|_| PacketError::MalformedPacket("invalid percent-encoding in name".into()))?;
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

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "/")?;
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            // Print printable ASCII; percent-encode everything else.
            for &b in c.value.iter() {
                if b.is_ascii_graphic() && b != b'/' && b != b'%' {
                    write!(f, "{}", b as char)?;
                } else {
                    write!(f, "%{b:02X}")?;
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
        let name   = Name::from_components([comp(b"edu"), comp(b"ucla"), comp(b"news")]);
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
        let name   = Name::from_components([comp(b"edu"), comp(b"ucla")]);
        let prefix = Name::from_components([comp(b"edu"), comp(b"mit")]);
        assert!(!name.has_prefix(&prefix));
    }

    #[test]
    fn has_prefix_false_prefix_longer_than_name() {
        let name   = Name::from_components([comp(b"edu")]);
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
        let n = Name::from_components([NameComponent::generic(
            bytes::Bytes::from(vec![0x00, 0xFF])
        )]);
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
        let generic  = NameComponent::generic(bytes::Bytes::copy_from_slice(b"abc"));
        let implicit = NameComponent { typ: 0x01, value: bytes::Bytes::copy_from_slice(b"abc") };
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
}
