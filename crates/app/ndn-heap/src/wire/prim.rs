//! The TLV primitives every record of the layer is built from, and the one
//! error a decoder answers with.

use bytes::Bytes;
use ndn_foundation_types::{Name, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use super::names::is_device_name;
use super::tlv;
use super::types::EpochId;

/// Read the TLVs of a record: each arm names a TLV-TYPE and stores what it
/// reads (through `v`, the value), and a type no arm names is [`each`]'s to
/// skip (even) or refuse (odd).
macro_rules! fields {
    ($value:expr, |$v:ident| { $($typ:pat => $arm:expr),+ $(,)? }) => {
        $crate::wire::each($value, |t, $v| {
            match t {
                $($typ => { $arm; })+
                _ => return Ok(false),
            }
            Ok(true)
        })?
    };
}
pub(crate) use fields;

/// Read a record whose every field appears exactly once: builds
/// `Type { field, … }` from what `read` makes of the TLV value `v` of each
/// field's TLV-TYPE, refusing a field twice or absent (the error names `what`
/// the record is and the field).
macro_rules! record {
    ($ty:path, $value:expr, $what:literal, |$v:ident| {
        $($f:ident: $typ:pat => $read:expr),+ $(,)?
    }) => {{
        $(let mut $f = None;)+
        $crate::wire::fields!($value, |$v| {
            $($typ => $crate::wire::once(&mut $f, $read, concat!($what, "'s ", stringify!($f)))?),+
        });
        $ty {
            $($f: $f.ok_or($crate::wire::WireError::Missing(
                concat!($what, "'s ", stringify!($f)),
            ))?),+
        }
    }};
}
pub(crate) use record;

/// Why bytes are not a record of the layer (or a record cannot be written).
/// Every refusal says what is wrong and what to do about it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// An odd (critical) TLV-TYPE this version does not know.
    #[error(
        "TLV-TYPE {0:#x} is critical (odd) and this version of ndn-heap does not know it: the \
         writer is newer than this reader; upgrade ndn-heap before reading this record"
    )]
    UnknownCritical(u64),
    /// A record over the size the layer allows.
    #[error(
        "{what} is {size} octets, over the {max}-octet limit; keep it under the limit (a \
         value too large for an entry travels in pieces)"
    )]
    TooLarge {
        /// What is too large.
        what: &'static str,
        /// Its size in octets.
        size: usize,
        /// The most the layer allows.
        max: usize,
    },
    /// A list over the number of items the layer allows.
    #[error("{what} lists {count} items, over the limit of {max}; split it across several entries")]
    TooMany {
        /// What lists too many.
        what: &'static str,
        /// How many it lists.
        count: usize,
        /// The most the layer allows.
        max: usize,
    },
    /// The octets are not well-formed TLV.
    #[error(
        "the octets are not well-formed TLV ({0}); the packet is truncated or is not a heap \
         record, discard it"
    )]
    Tlv(String),
    /// A `KIND` that this version does not define.
    #[error("entry KIND {0} is not one this version defines (0 Put, 1 Members, 2 Epoch)")]
    UnknownKind(u64),
    /// A `KIND` that disagrees with the body the entry carries.
    #[error(
        "the entry says KIND {kind} but carries {body}; a writer must derive KIND from the \
         body, so discard the entry"
    )]
    KindMismatch {
        /// What `KIND` said.
        kind: u64,
        /// What the body is.
        body: &'static str,
    },
    /// A required field is absent.
    #[error("{0} is missing; the record is incomplete, discard it")]
    Missing(&'static str),
    /// A field that may appear once appears again.
    #[error("{0} appears twice; the record is ambiguous, discard it")]
    Duplicate(&'static str),
    /// A field whose value breaks the format.
    #[error("{0}")]
    Malformed(&'static str),
}

/// A field that may appear once: store it, refuse a second.
pub(crate) fn once<T>(slot: &mut Option<T>, value: T, what: &'static str) -> Result<(), WireError> {
    if slot.replace(value).is_some() {
        return Err(WireError::Duplicate(what));
    }
    Ok(())
}

/// Write a NonNegativeInteger TLV.
pub(crate) fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let b = v.to_be_bytes();
    let s = match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x1_0000..=0xFFFF_FFFF => &b[4..],
        _ => &b[..],
    };
    w.write_tlv(typ, s);
}

/// Read a NonNegativeInteger value.
pub(crate) fn read_nni(v: &[u8]) -> Result<u64, WireError> {
    if !matches!(v.len(), 1 | 2 | 4 | 8) {
        return Err(WireError::Malformed(
            "a NonNegativeInteger is 1, 2, 4 or 8 octets",
        ));
    }
    Ok(v.iter().fold(0, |n, &b| n << 8 | u64::from(b)))
}

/// Write a `Name` TLV.
pub(crate) fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

/// Read the value of a `Name` TLV.
pub(crate) fn read_name(value: Bytes) -> Result<Name, WireError> {
    Name::decode(value)
        .map_err(|_| WireError::Malformed("a name is a run of well-formed components"))
}

/// Read a fixed-size octet string.
pub(crate) fn read_array<const N: usize>(
    v: &[u8],
    what: &'static str,
) -> Result<[u8; N], WireError> {
    <[u8; N]>::try_from(v).map_err(|_| WireError::Malformed(what))
}

/// Read a 32-octet digest.
pub(crate) fn read_digest(v: &[u8]) -> Result<[u8; 32], WireError> {
    read_array(v, "a digest is 32 octets")
}

/// Iterate the TLVs of `value`, handing each to `f`, which returns whether it
/// knew the type. An unknown even type is skipped, an unknown odd (critical)
/// one refuses.
pub(crate) fn each(
    value: Bytes,
    mut f: impl FnMut(u64, Bytes) -> Result<bool, WireError>,
) -> Result<(), WireError> {
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, v) = r.read_tlv().map_err(|e| WireError::Tlv(format!("{e:?}")))?;
        if !f(typ, v)? && typ % 2 == 1 {
            return Err(WireError::UnknownCritical(typ));
        }
    }
    Ok(())
}

/// Read exactly one TLV of type `typ` from `content` and return its value.
pub(crate) fn only(content: Bytes, typ: u64, what: &'static str) -> Result<Bytes, WireError> {
    let mut r = TlvReader::new(content);
    let (t, v) = r.read_tlv().map_err(|e| WireError::Tlv(format!("{e:?}")))?;
    if t != typ {
        return Err(if t % 2 == 1 {
            WireError::UnknownCritical(t)
        } else {
            WireError::Malformed(what)
        });
    }
    if !r.is_empty() {
        return Err(WireError::Malformed(what));
    }
    Ok(v)
}

/// Write an `EPOCH_ID`: `{ Name(creator), SEQ }`.
pub(crate) fn write_epoch_id(w: &mut TlvWriter, e: &EpochId) {
    w.write_nested(tlv::EPOCH_ID, |w| {
        write_name(w, &e.creator);
        write_nni(w, tlv::SEQ, e.seq);
    });
}

/// Read the value of an `EPOCH_ID`.
pub(crate) fn read_epoch_id(value: Bytes) -> Result<EpochId, WireError> {
    let (mut creator, mut seq) = (None, None);
    fields!(value, |v| {
        tlv_type::NAME => once(&mut creator, read_name(v)?, "an epoch id's creator")?,
        tlv::SEQ => once(&mut seq, read_nni(&v)?, "an epoch id's seq")?,
    });
    match (creator, seq) {
        (Some(creator), Some(seq)) if is_device_name(&creator) => Ok(EpochId { creator, seq }),
        _ => Err(WireError::Malformed(
            "an epoch id names a device (no keyword component) and a seq",
        )),
    }
}
