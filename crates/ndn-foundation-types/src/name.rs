//! `Name` and `NameComponent` — NDN hierarchical names.

use core::str::FromStr;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bytes::Bytes;
use smallvec::SmallVec;

use ndn_tlv::{TlvReader, TlvWriter};

use crate::tlv_type;

#[derive(Debug, PartialEq, Eq)]
pub struct NameError(pub &'static str);

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "name error: {}", self.0)
    }
}

impl core::error::Error for NameError {}

/// A single NDN name component (type, value).
///
/// Ordering follows NDN Packet Format v0.3 §2.1 canonical order: TLV-TYPE,
/// then TLV-LENGTH (shorter is smaller), then TLV-VALUE byte-by-byte.
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
            typ: tlv_type::GENERIC_NAME_COMPONENT,
            value,
        }
    }

    pub fn keyword(value: Bytes) -> Self {
        Self::new(tlv_type::KEYWORD, value)
    }

    pub fn byte_offset(offset: u64) -> Self {
        Self::new(tlv_type::BYTE_OFFSET, encode_nonneg_integer(offset))
    }

    pub fn version(v: u64) -> Self {
        Self::new(tlv_type::VERSION, encode_nonneg_integer(v))
    }

    pub fn timestamp(ts: u64) -> Self {
        Self::new(tlv_type::TIMESTAMP, encode_nonneg_integer(ts))
    }

    pub fn sequence_num(seq: u64) -> Self {
        Self::new(tlv_type::SEQUENCE_NUM, encode_nonneg_integer(seq))
    }

    pub fn as_segment(&self) -> Option<u64> {
        (self.typ == tlv_type::SEGMENT).then(|| decode_nonnegative_integer(&self.value))
    }

    pub fn as_byte_offset(&self) -> Option<u64> {
        (self.typ == tlv_type::BYTE_OFFSET).then(|| decode_nonnegative_integer(&self.value))
    }

    pub fn as_version(&self) -> Option<u64> {
        (self.typ == tlv_type::VERSION).then(|| decode_nonnegative_integer(&self.value))
    }

    pub fn as_timestamp(&self) -> Option<u64> {
        (self.typ == tlv_type::TIMESTAMP).then(|| decode_nonnegative_integer(&self.value))
    }

    pub fn as_sequence_num(&self) -> Option<u64> {
        (self.typ == tlv_type::SEQUENCE_NUM).then(|| decode_nonnegative_integer(&self.value))
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

fn decode_nonnegative_integer(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    val
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    pub(crate) components: SmallVec<[NameComponent; 8]>,
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.components.iter().cmp(other.components.iter())
    }
}

impl Name {
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

    pub fn has_prefix(&self, prefix: &Name) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        self.components
            .iter()
            .zip(prefix.components.iter())
            .all(|(a, b)| a == b)
    }

    /// Decode the inner bytes of a NAME TLV (components only, no outer T-L).
    pub fn decode(value: Bytes) -> Result<Self, NameError> {
        let mut reader = TlvReader::new(value);
        let mut components = SmallVec::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv().map_err(|_| NameError("TLV read error"))?;
            components.push(NameComponent::new(typ, val));
        }
        Ok(Self { components })
    }

    pub fn append(mut self, value: impl AsRef<[u8]>) -> Self {
        self.components
            .push(NameComponent::generic(Bytes::copy_from_slice(
                value.as_ref(),
            )));
        self
    }

    pub fn append_component(mut self, comp: NameComponent) -> Self {
        self.components.push(comp);
        self
    }

    pub fn append_segment(self, seg: u64) -> Self {
        self.append_component(NameComponent::new(
            tlv_type::SEGMENT,
            encode_nonneg_integer(seg),
        ))
    }

    pub fn append_version(self, v: u64) -> Self {
        self.append_component(NameComponent::version(v))
    }

    pub fn append_timestamp(self, ts: u64) -> Self {
        self.append_component(NameComponent::timestamp(ts))
    }

    pub fn append_sequence_num(self, seq: u64) -> Self {
        self.append_component(NameComponent::sequence_num(seq))
    }

    pub fn append_byte_offset(self, off: u64) -> Self {
        self.append_component(NameComponent::byte_offset(off))
    }

    /// Encode as a complete NAME TLV record (T=7, L, components...).
    pub fn encode_to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NAME, |inner| {
            for c in &self.components {
                inner.write_tlv(c.typ, &c.value);
            }
        });
        w.finish()
    }

    /// Decode from a complete NAME TLV record (T=7 is consumed).
    pub fn decode_from_tlv(bytes: Bytes) -> Result<Self, NameError> {
        let mut r = TlvReader::new(bytes);
        let (typ, inner) = r.read_tlv().map_err(|_| NameError("TLV read error"))?;
        if typ != tlv_type::NAME {
            return Err(NameError("expected NAME TLV type 7"));
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
            return r.map_err(|_| NameError("invalid percent-encoding"));
        }
    }
    if let Some(hex) = part.strip_prefix("sha256digest=") {
        return Ok(NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::from(parse_hex(hex).ok_or(NameError("invalid sha256digest hex"))?),
        ));
    }
    if let Some(hex) = part.strip_prefix("params-sha256=") {
        return Ok(NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::from(parse_hex(hex).ok_or(NameError("invalid params-sha256 hex"))?),
        ));
    }
    if let Some(rest) = part.strip_prefix("keyword=") {
        return Ok(NameComponent::new(
            tlv_type::KEYWORD,
            Bytes::from(percent_decode(rest).map_err(|_| NameError("invalid percent-encoding"))?),
        ));
    }
    // Canonical `<type-number>=<value>` form per NDN name.html: any spec-defined
    // typed component round-trips through the decimal TLV-TYPE prefix.
    if let Some((typ_str, val_str)) = split_typed_prefix(part) {
        let typ: u64 = typ_str
            .parse()
            .map_err(|_| NameError("invalid typed-component TLV-TYPE"))?;
        let decoded = percent_decode(val_str).map_err(|_| NameError("invalid percent-encoding"))?;
        return Ok(NameComponent::new(typ, Bytes::from(decoded)));
    }
    let decoded = percent_decode(part).map_err(|_| NameError("invalid percent-encoding"))?;
    Ok(NameComponent::generic(Bytes::from(decoded)))
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() || s == "/" {
            return Ok(Self::root());
        }
        if !s.starts_with('/') {
            return Err(NameError("name must start with '/'"));
        }

        let mut components = SmallVec::new();
        for part in s[1..].split('/') {
            if part.is_empty() {
                continue;
            }
            components.push(parse_component(part)?);
        }
        if components.is_empty() {
            Ok(Self::root())
        } else {
            Ok(Self { components })
        }
    }
}

impl From<&str> for Name {
    /// Parse an NDN URI; falls back to root on error.
    fn from(s: &str) -> Self {
        s.parse().unwrap_or_else(|_| Name::root())
    }
}

#[cfg(feature = "std")]
impl From<std::string::String> for Name {
    fn from(s: std::string::String) -> Self {
        s.parse().unwrap_or_else(|_| Name::root())
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
                tlv_type::SEGMENT => write!(f, "seg={}", decode_nonnegative_integer(&c.value))?,
                tlv_type::BYTE_OFFSET => write!(f, "off={}", decode_nonnegative_integer(&c.value))?,
                tlv_type::VERSION => write!(f, "v={}", decode_nonnegative_integer(&c.value))?,
                tlv_type::TIMESTAMP => write!(f, "t={}", decode_nonnegative_integer(&c.value))?,
                tlv_type::SEQUENCE_NUM => {
                    write!(f, "seq={}", decode_nonnegative_integer(&c.value))?
                }
                tlv_type::GENERIC_NAME_COMPONENT => percent_encode_component(f, &c.value)?,
                _ => {
                    write!(f, "{}=", c.typ)?;
                    percent_encode_component(f, &c.value)?;
                }
            }
        }
        Ok(())
    }
}
