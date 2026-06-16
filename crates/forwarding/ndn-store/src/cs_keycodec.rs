//! Shared key/value codec for the persistent content stores
//! ([`FjallCs`](crate::FjallCs), [`SqliteCs`](crate::SqliteCs)).
//!
//! Keys are the concatenated TLV encoding of name components (Name TLV value
//! bytes, without the outer `0x07` wrapper) so NDN lexicographic ordering is
//! preserved and `CanBePrefix` lookups become range scans.
//!
//! Values: `[stale_at: 8B BE u64][wire-format Data bytes]`.

use bytes::Bytes;
use ndn_packet::Name;

/// Length of the big-endian `stale_at` prefix on every stored value.
/// Only the fjall backend packs `[stale_at][data]`; SQLite uses columns.
#[cfg_attr(not(feature = "fjall"), allow(dead_code))]
pub(crate) const STALE_AT_LEN: usize = 8;

pub(crate) fn name_to_key(name: &Name) -> Vec<u8> {
    let mut key = Vec::new();
    for comp in name.components() {
        write_var(&mut key, comp.typ);
        write_var(&mut key, comp.value.len() as u64);
        key.extend_from_slice(&comp.value);
    }
    key
}

pub(crate) fn key_to_name(key: &[u8]) -> Option<Name> {
    use ndn_packet::NameComponent;
    let mut components = smallvec::SmallVec::<[NameComponent; 8]>::new();
    let mut pos = 0;
    while pos < key.len() {
        let (typ, consumed) = read_var(&key[pos..])?;
        pos += consumed;
        let (len, consumed) = read_var(&key[pos..])?;
        pos += consumed;
        let len = len as usize;
        if pos + len > key.len() {
            return None;
        }
        components.push(NameComponent::new(
            typ,
            Bytes::copy_from_slice(&key[pos..pos + len]),
        ));
        pos += len;
    }
    Some(Name::from_components(components))
}

/// Smallest key that is strictly greater than every key with `prefix` as a
/// prefix — the exclusive upper bound for a prefix range scan. Returns `None`
/// when `prefix` is empty or all-`0xFF` (scan to the end of the keyspace).
// Only the SQLite backend range-scans by this bound; fjall uses its own
// `prefix` iterator.
#[cfg_attr(not(feature = "sqlite-cs"), allow(dead_code))]
pub(crate) fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

#[cfg_attr(not(feature = "fjall"), allow(dead_code))]
pub(crate) fn encode_value(stale_at: u64, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(STALE_AT_LEN + data.len());
    v.extend_from_slice(&stale_at.to_be_bytes());
    v.extend_from_slice(data);
    v
}

#[cfg_attr(not(feature = "fjall"), allow(dead_code))]
pub(crate) fn decode_value(val: &[u8]) -> Option<(u64, Bytes)> {
    if val.len() < STALE_AT_LEN {
        return None;
    }
    let stale_at = u64::from_be_bytes(val[..STALE_AT_LEN].try_into().ok()?);
    let data = Bytes::copy_from_slice(&val[STALE_AT_LEN..]);
    Some((stale_at, data))
}

pub(crate) fn write_var(buf: &mut Vec<u8>, val: u64) {
    if val < 253 {
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(253);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(254);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

pub(crate) fn read_var(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        v @ 0..=252 => Some((v as u64, 1)),
        253 => {
            if buf.len() < 3 {
                return None;
            }
            Some((u16::from_be_bytes([buf[1], buf[2]]) as u64, 3))
        }
        254 => {
            if buf.len() < 5 {
                return None;
            }
            Some((
                u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64,
                5,
            ))
        }
        _ => {
            // 255
            if buf.len() < 9 {
                return None;
            }
            Some((
                u64::from_be_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]),
                9,
            ))
        }
    }
}

pub(crate) fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
