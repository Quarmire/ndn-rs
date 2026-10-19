//! `Name` and `NameComponent` — NDN hierarchical names.

use core::iter;
use core::str::FromStr;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bytes::Bytes;
use smallvec::SmallVec;

use ndn_tlv::{TlvReader, TlvWriter};

use crate::compat::Arc;
use crate::tlv_type;

/// Why a byte string or URI is not a valid [`Name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// The NAME TLV (or a component TLV inside it) is truncated or malformed.
    Tlv,
    /// The outer TLV is not a NAME (TLV-TYPE 7).
    NotNameTlv,
    /// A component's TLV-TYPE is outside the range 1–65535 the NDN packet
    /// format allows for name components.
    ComponentTypeOutOfRange,
    /// A non-empty URI does not start with `/`.
    MissingLeadingSlash,
    /// A `%` escape is not followed by two hex digits.
    InvalidPercentEncoding,
    /// A `sha256digest=` / `params-sha256=` value is not an even-length hex string.
    InvalidDigestHex,
    /// A `<type-number>=` prefix is not a valid component TLV-TYPE.
    InvalidTypeNumber,
    /// A component value of one or two periods (illegal in the NDN URI scheme).
    IllegalPeriods,
}

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            NameError::Tlv => "name error: TLV read error",
            NameError::NotNameTlv => "name error: expected NAME TLV type 7",
            NameError::ComponentTypeOutOfRange => "name error: component TLV-TYPE outside 1-65535",
            NameError::MissingLeadingSlash => "name error: name must start with '/'",
            NameError::InvalidPercentEncoding => "name error: invalid percent-encoding",
            NameError::InvalidDigestHex => "name error: invalid digest hex",
            NameError::InvalidTypeNumber => "name error: invalid typed-component TLV-TYPE",
            NameError::IllegalPeriods => "name error: component of one or two periods is illegal",
        })
    }
}

impl core::error::Error for NameError {}

/// A single NDN name component (type, value).
///
/// Ordering follows NDN Packet Format v0.3 §2.1 canonical order: TLV-TYPE,
/// then TLV-LENGTH (shorter is smaller), then TLV-VALUE byte-by-byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NameComponent {
    /// TLV-TYPE of the component (e.g. `GenericNameComponent`, `SegmentNameComponent`).
    pub typ: u64,
    /// TLV-VALUE bytes of the component.
    pub value: Bytes,
}

impl PartialOrd for NameComponent {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameComponent {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.typ
            .cmp(&other.typ)
            .then_with(|| self.value.len().cmp(&other.value.len()))
            .then_with(|| self.value.as_ref().cmp(other.value.as_ref()))
    }
}

impl NameComponent {
    /// Builds a component from an explicit TLV type and value.
    pub fn new(typ: u64, value: Bytes) -> Self {
        Self { typ, value }
    }

    /// A `GenericNameComponent` holding arbitrary bytes.
    pub fn generic(value: Bytes) -> Self {
        Self {
            typ: tlv_type::GENERIC_NAME_COMPONENT,
            value,
        }
    }

    /// A `KeywordNameComponent`.
    pub fn keyword(value: Bytes) -> Self {
        Self::new(tlv_type::KEYWORD, value)
    }

    /// A `ByteOffsetNameComponent` encoding `offset` as a NonNegativeInteger.
    pub fn byte_offset(offset: u64) -> Self {
        Self::new(tlv_type::BYTE_OFFSET, encode_nonneg_integer(offset))
    }

    /// A `VersionNameComponent` encoding `v` as a NonNegativeInteger.
    pub fn version(v: u64) -> Self {
        Self::new(tlv_type::VERSION, encode_nonneg_integer(v))
    }

    /// A `TimestampNameComponent` encoding `ts` as a NonNegativeInteger.
    pub fn timestamp(ts: u64) -> Self {
        Self::new(tlv_type::TIMESTAMP, encode_nonneg_integer(ts))
    }

    /// A `SequenceNumNameComponent` encoding `seq` as a NonNegativeInteger.
    pub fn sequence_num(seq: u64) -> Self {
        Self::new(tlv_type::SEQUENCE_NUM, encode_nonneg_integer(seq))
    }

    /// The segment number, or `None` if this is not a `SegmentNameComponent`
    /// or its value is not a NonNegativeInteger (1, 2, 4 or 8 octets).
    pub fn as_segment(&self) -> Option<u64> {
        self.nonneg_integer_of(tlv_type::SEGMENT)
    }

    /// The byte offset, or `None` if this is not a `ByteOffsetNameComponent`
    /// or its value is not a NonNegativeInteger.
    pub fn as_byte_offset(&self) -> Option<u64> {
        self.nonneg_integer_of(tlv_type::BYTE_OFFSET)
    }

    /// The version, or `None` if this is not a `VersionNameComponent` or its
    /// value is not a NonNegativeInteger.
    pub fn as_version(&self) -> Option<u64> {
        self.nonneg_integer_of(tlv_type::VERSION)
    }

    /// The timestamp, or `None` if this is not a `TimestampNameComponent` or
    /// its value is not a NonNegativeInteger.
    pub fn as_timestamp(&self) -> Option<u64> {
        self.nonneg_integer_of(tlv_type::TIMESTAMP)
    }

    /// The sequence number, or `None` if this is not a
    /// `SequenceNumNameComponent` or its value is not a NonNegativeInteger.
    pub fn as_sequence_num(&self) -> Option<u64> {
        self.nonneg_integer_of(tlv_type::SEQUENCE_NUM)
    }

    fn nonneg_integer_of(&self, typ: u64) -> Option<u64> {
        if self.typ != typ {
            return None;
        }
        decode_nonnegative_integer(&self.value)
    }
}

fn encode_nonneg_integer(v: u64) -> Bytes {
    let b = v.to_be_bytes();
    Bytes::copy_from_slice(match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x10000..=0xFFFF_FFFF => &b[4..],
        _ => &b,
    })
}

/// Decode an NDN NonNegativeInteger: big-endian in exactly 1, 2, 4 or 8
/// octets (NDN Packet Format v0.3 §1.2). Any other width — empty, 3, 5–7, or
/// more than 8 octets — is `None`, never a truncated or zero value. A
/// non-minimal width (e.g. `00 01`) is accepted, as ndn-cxx does.
fn decode_nonnegative_integer(bytes: &[u8]) -> Option<u64> {
    if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
        return None;
    }
    Some(bytes.iter().fold(0u64, |val, &b| (val << 8) | u64::from(b)))
}

/// Decode a value as a *canonical* NonNegativeInteger: 1/2/4/8 octets in the
/// spec's minimal width. Returns `None` for any other byte string, so callers
/// can preserve malformed values verbatim instead of silently rewriting them.
fn canonical_nonneg_integer(bytes: &[u8]) -> Option<u64> {
    let v = decode_nonnegative_integer(bytes)?;
    (encode_nonneg_integer(v).as_ref() == bytes).then_some(v)
}

/// A hierarchical NDN name: an ordered, possibly empty sequence of
/// [`NameComponent`]s that identifies a piece of Data.
///
/// Names are the primary addressing primitive in NDN — an Interest carries the
/// name (or prefix) it wants, and Data carries the name it answers to.
/// Comparison is component-wise in canonical NDN order (see [`NameComponent`]),
/// so names sort exactly the way a forwarder's longest-prefix match expects;
/// the empty name is the routable root (`/`). The textual form is the familiar
/// `/a/b/c` URI; parsing one is fallible (`str::parse` / [`FromStr`]).
///
/// There is no infallible conversion from text: a malformed URI is an error,
/// never a silently substituted name.
///
/// ```compile_fail
/// let _ = ndn_foundation_types::Name::from("/%ZZ");
/// ```
///
/// ```compile_fail
/// let _: ndn_foundation_types::Name = String::from("/%ZZ").into();
/// ```
///
/// The components live in one shared, immutable `Arc<[NameComponent]>`, so a
/// `Name` is two words: moving or storing one costs 16 bytes and cloning one is
/// a reference-count increment. The `append*` builders produce a new component
/// array (moving the old components when this `Name` is the only owner).
#[derive(Clone, Debug)]
pub struct Name {
    components: Arc<[NameComponent]>,
}

// Eq, Ord and Hash all compare the component slice; the pointer check is
// only a shortcut for clones of one name.
impl core::hash::Hash for Name {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.components[..].hash(state);
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.components, &other.components)
            || self.components[..] == other.components[..]
    }
}

impl Eq for Name {}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if Arc::ptr_eq(&self.components, &other.components) {
            return core::cmp::Ordering::Equal;
        }
        self.components.iter().cmp(other.components.iter())
    }
}

/// Move a component out of a staging slot, leaving an empty placeholder (no
/// refcount traffic: the placeholder's `Bytes::new()` is static).
fn take_component(slot: &mut NameComponent) -> NameComponent {
    core::mem::replace(slot, NameComponent::new(0, Bytes::new()))
}

/// Components are staged on the stack while a name is decoded or parsed, then
/// moved into a single exact-size shared allocation, so a name of up to 16
/// components costs one allocation.
type Staging = SmallVec<[NameComponent; 16]>;

fn seal(mut staged: Staging) -> Arc<[NameComponent]> {
    staged.iter_mut().map(take_component).collect()
}

/// NDN Packet Format v0.3 §2.1: name-component TLV-TYPEs are 1–65535.
const fn valid_component_type(typ: u64) -> bool {
    matches!(typ, 1..=0xFFFF)
}

impl Name {
    /// The empty (root) name, `/`.
    pub fn root() -> Self {
        Self {
            components: Arc::default(),
        }
    }

    /// Builds a name from an iterator of components.
    pub fn from_components(components: impl IntoIterator<Item = NameComponent>) -> Self {
        Self {
            components: components.into_iter().collect(),
        }
    }

    /// The name's components in order.
    pub fn components(&self) -> &[NameComponent] {
        &self.components
    }

    /// The number of components in the name.
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Whether this is the root name (no components).
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Whether `prefix` is a prefix of (or equal to) this name.
    pub fn has_prefix(&self, prefix: &Name) -> bool {
        Arc::ptr_eq(&self.components, &prefix.components)
            || self
                .components
                .get(..prefix.len())
                .is_some_and(|head| head == &prefix.components[..])
    }

    /// Decode the inner bytes of a NAME TLV (components only, no outer T-L).
    ///
    /// Refuses a component whose TLV-TYPE is outside 1–65535.
    pub fn decode(value: Bytes) -> Result<Self, NameError> {
        let mut reader = TlvReader::new(value);
        let mut components = Staging::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv().map_err(|_| NameError::Tlv)?;
            if !valid_component_type(typ) {
                return Err(NameError::ComponentTypeOutOfRange);
            }
            components.push(NameComponent::new(typ, val));
        }
        Ok(Self {
            components: seal(components),
        })
    }

    /// Appends a `GenericNameComponent` holding `value`.
    pub fn append(self, value: impl AsRef<[u8]>) -> Self {
        self.append_component(NameComponent::generic(Bytes::copy_from_slice(
            value.as_ref(),
        )))
    }

    /// Appends an explicit component.
    pub fn append_component(mut self, comp: NameComponent) -> Self {
        self.components = match Arc::get_mut(&mut self.components) {
            // Sole owner: move the existing components into the new array.
            Some(owned) => owned
                .iter_mut()
                .map(take_component)
                .chain(iter::once(comp))
                .collect(),
            None => self
                .components
                .iter()
                .cloned()
                .chain(iter::once(comp))
                .collect(),
        };
        self
    }

    /// Appends a `SegmentNameComponent`.
    pub fn append_segment(self, seg: u64) -> Self {
        self.append_component(NameComponent::new(
            tlv_type::SEGMENT,
            encode_nonneg_integer(seg),
        ))
    }

    /// Appends a `VersionNameComponent`.
    pub fn append_version(self, v: u64) -> Self {
        self.append_component(NameComponent::version(v))
    }

    /// Append an `ImplicitSha256DigestComponent` (TLV-TYPE `0x01`) — the
    /// content hash that names a specific Data object exactly. This is the
    /// supported consumer-API way to address a Block by content hash
    /// (`<auth>/blocks/<hash>`, NDF F14 / D-40 track B) instead of
    /// hand-constructing the typed component. The digest is the SHA-256 of the
    /// Data's wire encoding ([`Data::implicit_digest`](../ndn_packet/struct.Data.html#method.implicit_digest)).
    pub fn append_implicit_digest(self, digest: [u8; 32]) -> Self {
        self.append_component(NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::copy_from_slice(&digest),
        ))
    }

    /// Appends a `TimestampNameComponent`.
    pub fn append_timestamp(self, ts: u64) -> Self {
        self.append_component(NameComponent::timestamp(ts))
    }

    /// Appends a `SequenceNumNameComponent`.
    pub fn append_sequence_num(self, seq: u64) -> Self {
        self.append_component(NameComponent::sequence_num(seq))
    }

    /// Appends a `ByteOffsetNameComponent`.
    pub fn append_byte_offset(self, off: u64) -> Self {
        self.append_component(NameComponent::byte_offset(off))
    }

    /// Encode as a complete NAME TLV record (T=7, L, components...).
    pub fn encode_to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NAME, |inner| {
            for c in self.components.iter() {
                inner.write_tlv(c.typ, &c.value);
            }
        });
        w.finish()
    }

    /// Decode from a complete NAME TLV record (T=7 is consumed).
    pub fn decode_from_tlv(bytes: Bytes) -> Result<Self, NameError> {
        let mut r = TlvReader::new(bytes);
        let (typ, inner) = r.read_tlv().map_err(|_| NameError::Tlv)?;
        if typ != tlv_type::NAME {
            return Err(NameError::NotNameTlv);
        }
        Self::decode(inner)
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn split_typed_prefix(part: &str) -> Option<(&str, &str)> {
    let eq = part.find('=')?;
    let (head, tail) = part.split_at(eq);
    (!head.is_empty() && head.bytes().all(|b| b.is_ascii_digit())).then(|| (head, &tail[1..]))
}

/// `prefix=<u64>` → typed integer component, falling back to a percent-decoded
/// generic component when the tail isn't a valid integer.
fn parse_integer_prefix(part: &str, prefix: &str, typ: u64) -> Option<Result<NameComponent, ()>> {
    let rest = part.strip_prefix(prefix)?;
    Some(if let Ok(n) = rest.parse::<u64>() {
        Ok(NameComponent::new(typ, encode_nonneg_integer(n)))
    } else {
        percent_decode(part).map(|d| NameComponent::generic(Bytes::from(d)))
    })
}

const INTEGER_PREFIXES: &[(&str, u64)] = &[
    ("seg=", tlv_type::SEGMENT),
    ("v=", tlv_type::VERSION),
    ("off=", tlv_type::BYTE_OFFSET),
    ("t=", tlv_type::TIMESTAMP),
    ("seq=", tlv_type::SEQUENCE_NUM),
];

fn parse_component(part: &str) -> Result<NameComponent, NameError> {
    for &(prefix, typ) in INTEGER_PREFIXES {
        if let Some(r) = parse_integer_prefix(part, prefix, typ) {
            return r.map_err(|_| NameError::InvalidPercentEncoding);
        }
    }
    if let Some(hex) = part.strip_prefix("sha256digest=") {
        return Ok(NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::from(parse_hex(hex).ok_or(NameError::InvalidDigestHex)?),
        ));
    }
    if let Some(hex) = part.strip_prefix("params-sha256=") {
        return Ok(NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::from(parse_hex(hex).ok_or(NameError::InvalidDigestHex)?),
        ));
    }
    if let Some(rest) = part.strip_prefix("keyword=") {
        return Ok(NameComponent::new(
            tlv_type::KEYWORD,
            Bytes::from(percent_decode(rest).map_err(|_| NameError::InvalidPercentEncoding)?),
        ));
    }
    // Canonical `<type-number>=<value>` form per NDN name.html: any spec-defined
    // typed component round-trips through the decimal TLV-TYPE prefix.
    if let Some((typ_str, val_str)) = split_typed_prefix(part) {
        let typ: u64 = typ_str
            .parse()
            .ok()
            .filter(|&t| valid_component_type(t))
            .ok_or(NameError::InvalidTypeNumber)?;
        return Ok(NameComponent::new(
            typ,
            Bytes::from(decode_uri_value(val_str)?),
        ));
    }
    Ok(NameComponent::generic(Bytes::from(decode_uri_value(part)?)))
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() || s == "/" {
            return Ok(Self::root());
        }
        if !s.starts_with('/') {
            return Err(NameError::MissingLeadingSlash);
        }

        let mut components = Staging::new();
        for part in s[1..].split('/') {
            if part.is_empty() {
                continue;
            }
            components.push(parse_component(part)?);
        }
        Ok(Self {
            components: seal(components),
        })
    }
}

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

fn percent_encode_component(f: &mut core::fmt::Formatter<'_>, value: &[u8]) -> core::fmt::Result {
    for &b in value {
        // NDN URI scheme (name.html): only the RFC 3986 unreserved set is
        // emitted raw. Everything else — including '=', which would otherwise
        // re-parse as a `<type>=` prefix — is percent-encoded.
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            write!(f, "{}", b as char)?;
        } else {
            write!(f, "%{b:02X}")?;
        }
    }
    Ok(())
}

/// Render a component value with the NDN URI periods rule: a value that is
/// empty or consists solely of periods gets three additional periods (so an
/// empty value is `...`, a single `.` is `....`), disambiguating it from
/// path-like text. Everything else percent-encodes normally.
fn write_uri_value(f: &mut core::fmt::Formatter<'_>, value: &[u8]) -> core::fmt::Result {
    if value.iter().all(|&b| b == b'.') {
        for _ in 0..value.len() + 3 {
            write!(f, ".")?;
        }
        Ok(())
    } else {
        percent_encode_component(f, value)
    }
}

/// Parse a URI component value: percent-decode, then apply the periods rule
/// in reverse (`...` → empty, `....` → `.`; one or two periods are illegal).
fn decode_uri_value(s: &str) -> Result<Vec<u8>, NameError> {
    let decoded = percent_decode(s).map_err(|_| NameError::InvalidPercentEncoding)?;
    if decoded.iter().all(|&b| b == b'.') {
        if decoded.len() < 3 {
            return Err(NameError::IllegalPeriods);
        }
        return Ok(decoded[3..].to_vec());
    }
    Ok(decoded)
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
                // The `seg=`/`off=`/`v=`/`t=`/`seq=` sugar is only correct for
                // canonical NonNegativeInteger values; a malformed width must
                // render as the raw `<type>=<escaped>` form or the bytes are
                // silently rewritten on a render→parse round-trip.
                tlv_type::SEGMENT
                | tlv_type::BYTE_OFFSET
                | tlv_type::VERSION
                | tlv_type::TIMESTAMP
                | tlv_type::SEQUENCE_NUM => match canonical_nonneg_integer(&c.value) {
                    Some(n) => {
                        let prefix = match c.typ {
                            tlv_type::SEGMENT => "seg",
                            tlv_type::BYTE_OFFSET => "off",
                            tlv_type::VERSION => "v",
                            tlv_type::TIMESTAMP => "t",
                            _ => "seq",
                        };
                        write!(f, "{prefix}={n}")?;
                    }
                    None => {
                        write!(f, "{}=", c.typ)?;
                        write_uri_value(f, &c.value)?;
                    }
                },
                tlv_type::GENERIC_NAME_COMPONENT => write_uri_value(f, &c.value)?,
                _ => {
                    write!(f, "{}=", c.typ)?;
                    write_uri_value(f, &c.value)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod implicit_digest_tests {
    use super::*;

    #[test]
    fn append_implicit_digest_round_trips() {
        let digest = [0x9au8; 32];
        let name = Name::root().append("blocks").append_implicit_digest(digest);
        let last = name.components().last().expect("has a last component");
        assert_eq!(last.typ, tlv_type::IMPLICIT_SHA256);
        assert_eq!(last.value.as_ref(), &digest[..]);

        // Survives a wire round-trip and stays a digest component.
        let decoded = Name::decode_from_tlv(name.encode_to_tlv()).expect("decode");
        let dlast = decoded.components().last().unwrap();
        assert_eq!(dlast.typ, tlv_type::IMPLICIT_SHA256);
        assert_eq!(dlast.value.as_ref(), &digest[..]);
    }
}

#[cfg(test)]
mod component_type_range_tests {
    use super::*;

    fn name_tlv_with_component_type(typ: u64) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NAME, |inner| inner.write_tlv(typ, b"x"));
        w.finish()
    }

    #[test]
    fn decode_refuses_component_types_outside_1_to_65535() {
        for typ in [0, 0x1_0000, 0xFFFF_FFFF] {
            let wire = name_tlv_with_component_type(typ);
            assert_eq!(
                Name::decode_from_tlv(wire.clone()),
                Err(NameError::ComponentTypeOutOfRange),
                "type {typ:#x}"
            );
            // `decode` takes the NAME's inner bytes: skip T=7 and its 1-byte L.
            assert_eq!(
                Name::decode(wire.slice(2..)),
                Err(NameError::ComponentTypeOutOfRange),
                "type {typ:#x}"
            );
        }
    }

    #[test]
    fn decode_accepts_the_range_bounds() {
        for typ in [1, 0xFFFF] {
            let name = Name::decode_from_tlv(name_tlv_with_component_type(typ)).expect("in range");
            assert_eq!(name.components()[0].typ, typ);
        }
    }

    #[test]
    fn parse_refuses_typed_components_outside_1_to_65535() {
        for uri in ["/0=x", "/65536=x"] {
            assert_eq!(
                uri.parse::<Name>(),
                Err(NameError::InvalidTypeNumber),
                "{uri}"
            );
        }
        assert_eq!(
            "/65535=x".parse::<Name>().unwrap().components()[0].typ,
            0xFFFF
        );
    }
}

#[cfg(test)]
mod representation_tests {
    extern crate std;

    use super::*;
    use core::hash::{Hash, Hasher};
    use std::hash::DefaultHasher;

    fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
        let mut h = DefaultHasher::new();
        value.hash(&mut h);
        h.finish()
    }

    /// Every PIT/CS/FIB entry and packet struct carries a `Name`: it must stay
    /// a handle, not an inline component array.
    #[test]
    fn a_name_is_at_most_three_words() {
        assert!(core::mem::size_of::<Name>() <= 24);
        assert!(core::mem::size_of::<Option<Name>>() <= 24);
    }

    /// `Name`'s hash is its component slice's hash, as it was with the inline
    /// representation, so hashed names (sharding, persisted keys) are stable.
    #[test]
    fn hash_is_the_component_slice_hash() {
        let name: Name = "/a/b/v=3".parse().unwrap();
        assert_eq!(hash_of(&name), hash_of(name.components()));
        let rebuilt = Name::root().append("a").append("b").append_version(3);
        assert_eq!(hash_of(&name), hash_of(&rebuilt));
    }
}

#[cfg(test)]
mod nonneg_integer_tests {
    use super::*;

    fn version_component(value: &[u8]) -> NameComponent {
        NameComponent::new(tlv_type::VERSION, Bytes::copy_from_slice(value))
    }

    #[test]
    fn only_ndn_widths_decode() {
        assert_eq!(version_component(&[7]).as_version(), Some(7));
        assert_eq!(version_component(&[0, 7]).as_version(), Some(7));
        assert_eq!(version_component(&[0, 0, 1, 0]).as_version(), Some(256));
        assert_eq!(version_component(&[0xFF; 8]).as_version(), Some(u64::MAX));
        for len in [0usize, 3, 5, 6, 7, 9, 16] {
            let c = version_component(&[1u8; 16][..len]);
            assert_eq!(c.as_version(), None, "{len} octets");
            let seg = NameComponent::new(tlv_type::SEGMENT, c.value.clone());
            assert_eq!(seg.as_segment(), None, "{len} octets");
        }
    }

    #[test]
    fn more_than_eight_octets_never_drop_high_octets() {
        // 9 octets whose low 8 read as 1: must not decode as version 1.
        let c = version_component(&[1, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(c.as_version(), None);
    }
}
