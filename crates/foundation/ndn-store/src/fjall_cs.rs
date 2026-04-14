//! Persistent content store backed by [fjall](https://docs.rs/fjall) LSM-tree.
//!
//! ## Key layout
//!
//! Keys are the concatenated TLV encoding of all name components (the Name TLV
//! *value* bytes, without the outer `0x07` type+length wrapper). This preserves
//! NDN lexicographic ordering so that `CanBePrefix` lookups become range scans:
//! all Data names starting with a given prefix share a common key prefix.
//!
//! ## Value layout
//!
//! ```text
//! [stale_at: 8 bytes big-endian u64] [wire-format Data bytes]
//! ```
//!
//! ## Feature gate
//!
//! Available when the `fjall` feature is enabled on `ndn-store`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;

use ndn_packet::{Interest, Name};

use crate::{ContentStore, CsCapacity, CsEntry, CsMeta, InsertResult};

const STALE_AT_LEN: usize = 8;

/// Persistent content store backed by fjall.
///
/// Data survives process restarts. The on-disk size is bounded by
/// `max_bytes` (measured in logical Data bytes, not on-disk size including
/// LSM overhead).
pub struct FjallCs {
    keyspace: fjall::Keyspace,
    // Kept alive so the underlying fjall::Database is not dropped while the
    // keyspace is in use.
    #[allow(dead_code)]
    db: fjall::Database,
    max_bytes: AtomicUsize,
    current_bytes: AtomicUsize,
    entry_count: AtomicUsize,
}

impl FjallCs {
    /// Open (or create) a persistent CS at the given directory path.
    ///
    /// `max_bytes` limits the total logical Data bytes stored (not on-disk size).
    pub fn open(path: impl AsRef<std::path::Path>, max_bytes: usize) -> fjall::Result<Self> {
        let db = fjall::Database::builder(path).open()?;
        let keyspace = db.keyspace("cs", fjall::KeyspaceCreateOptions::default)?;

        // Recover current_bytes and entry_count by scanning existing entries.
        let (count, bytes) = Self::scan_stats(&keyspace);

        Ok(Self {
            keyspace,
            db,
            max_bytes: AtomicUsize::new(max_bytes),
            current_bytes: AtomicUsize::new(bytes),
            entry_count: AtomicUsize::new(count),
        })
    }

    /// Scan the keyspace to recover entry count and total bytes.
    fn scan_stats(ks: &fjall::Keyspace) -> (usize, usize) {
        let mut count = 0usize;
        let mut bytes = 0usize;
        for guard in ks.iter() {
            if let Ok((_key, val)) = guard.into_inner()
                && val.len() > STALE_AT_LEN
            {
                bytes += val.len() - STALE_AT_LEN;
                count += 1;
            }
        }
        (count, bytes)
    }

    /// Evict the oldest entries (by insertion order / key order) until we are
    /// within capacity. fjall iteration is in key-sorted order.
    fn evict_to_fit(&self, needed: usize) {
        let max = self.max_bytes.load(Ordering::Relaxed);
        let mut current = self.current_bytes.load(Ordering::Relaxed);

        if current + needed <= max {
            return;
        }

        // Collect keys to delete — iterate in key order (oldest prefix first).
        let mut to_delete: Vec<(Vec<u8>, usize)> = Vec::new();
        for guard in self.keyspace.iter() {
            if current + needed <= max {
                break;
            }
            if let Ok((key, val)) = guard.into_inner() {
                let data_len = val.len().saturating_sub(STALE_AT_LEN);
                to_delete.push((key.to_vec(), data_len));
                current = current.saturating_sub(data_len);
            }
        }

        for (key, _) in &to_delete {
            let _ = self.keyspace.remove(key.as_slice());
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }
        self.current_bytes.store(current, Ordering::Relaxed);
    }
}

/// Encode a `Name` into its key bytes: concatenated component TLVs.
fn name_to_key(name: &Name) -> Vec<u8> {
    let mut key = Vec::new();
    for comp in name.components() {
        // Write component TLV: type (var) + length (var) + value
        write_var(&mut key, comp.typ);
        write_var(&mut key, comp.value.len() as u64);
        key.extend_from_slice(&comp.value);
    }
    key
}

/// Decode key bytes back into a `Name`.
fn key_to_name(key: &[u8]) -> Option<Name> {
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

/// Encode value: [stale_at: 8B BE][wire data bytes]
fn encode_value(stale_at: u64, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(STALE_AT_LEN + data.len());
    v.extend_from_slice(&stale_at.to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// Decode value back into (stale_at, data_bytes).
fn decode_value(val: &[u8]) -> Option<(u64, Bytes)> {
    if val.len() < STALE_AT_LEN {
        return None;
    }
    let stale_at = u64::from_be_bytes(val[..STALE_AT_LEN].try_into().ok()?);
    let data = Bytes::copy_from_slice(&val[STALE_AT_LEN..]);
    Some((stale_at, data))
}

/// Write a TLV-style variable-length unsigned integer.
fn write_var(buf: &mut Vec<u8>, val: u64) {
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

/// Read a TLV-style variable-length unsigned integer. Returns (value, bytes_consumed).
fn read_var(buf: &[u8]) -> Option<(u64, usize)> {
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

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl ContentStore for FjallCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        if self.entry_count.load(Ordering::Relaxed) == 0 {
            return None;
        }

        let comps = interest.name.components();
        let has_implicit_digest =
            !comps.is_empty() && comps.last().unwrap().typ == ndn_packet::tlv_type::IMPLICIT_SHA256;

        let entry = if has_implicit_digest {
            // Build Data name (without digest component) and look up.
            let data_name = Name::from_components(comps[..comps.len() - 1].iter().cloned());
            let key = name_to_key(&data_name);
            let slice = self.keyspace.get(&key).ok()??;
            let (stale_at, data) = decode_value(&slice)?;

            // Verify implicit digest.
            let expected_digest = &comps.last().unwrap().value;
            let actual = ring::digest::digest(&ring::digest::SHA256, &data);
            if expected_digest.as_ref() != actual.as_ref() {
                return None;
            }
            CsEntry {
                data,
                stale_at,
                name: Arc::new(data_name),
            }
        } else if interest.selectors().can_be_prefix {
            // Range scan: find first key with the interest name as prefix.
            let prefix_key = name_to_key(&interest.name);
            let mut found = None;
            for guard in self.keyspace.prefix(&prefix_key) {
                if let Ok((key, val)) = guard.into_inner()
                    && let Some((stale_at, data)) = decode_value(&val)
                    && let Some(name) = key_to_name(&key)
                {
                    found = Some(CsEntry {
                        data,
                        stale_at,
                        name: Arc::new(name),
                    });
                    break;
                }
            }
            found?
        } else {
            // Exact match.
            let key = name_to_key(&interest.name);
            let slice = self.keyspace.get(&key).ok()??;
            let (stale_at, data) = decode_value(&slice)?;
            CsEntry {
                data,
                stale_at,
                name: interest.name.clone(),
            }
        };

        if interest.selectors().must_be_fresh && !entry.is_fresh(now_ns()) {
            return None;
        }
        Some(entry)
    }

    async fn insert(&self, data: Bytes, name: Arc<Name>, meta: CsMeta) -> InsertResult {
        let entry_bytes = data.len();
        let key = name_to_key(&name);

        // Check for existing entry.
        let was_present = if let Ok(Some(old_val)) = self.keyspace.get(&key) {
            let old_data_len = old_val.len().saturating_sub(STALE_AT_LEN);
            self.current_bytes
                .fetch_sub(old_data_len, Ordering::Relaxed);
            true
        } else {
            false
        };

        // Evict to make room.
        self.evict_to_fit(entry_bytes);

        let val = encode_value(meta.stale_at, &data);
        if self.keyspace.insert(&key, &val).is_err() {
            return InsertResult::Skipped;
        }

        self.current_bytes.fetch_add(entry_bytes, Ordering::Relaxed);
        if !was_present {
            self.entry_count.fetch_add(1, Ordering::Relaxed);
        }

        if was_present {
            InsertResult::Replaced
        } else {
            InsertResult::Inserted
        }
    }

    async fn evict(&self, name: &Name) -> bool {
        let key = name_to_key(name);
        if let Ok(Some(old_val)) = self.keyspace.get(&key) {
            let old_data_len = old_val.len().saturating_sub(STALE_AT_LEN);
            let _ = self.keyspace.remove(&key);
            self.current_bytes
                .fetch_sub(old_data_len, Ordering::Relaxed);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn capacity(&self) -> CsCapacity {
        CsCapacity::bytes(self.max_bytes.load(Ordering::Relaxed))
    }

    fn len(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    fn current_bytes(&self) -> usize {
        self.current_bytes.load(Ordering::Relaxed)
    }

    fn set_capacity(&self, max_bytes: usize) {
        self.max_bytes.store(max_bytes, Ordering::Relaxed);
        // Evict excess.
        self.evict_to_fit(0);
    }

    fn variant_name(&self) -> &str {
        "fjall"
    }

    async fn evict_prefix(&self, prefix: &Name, limit: Option<usize>) -> usize {
        let prefix_key = name_to_key(prefix);
        let max = limit.unwrap_or(usize::MAX);
        let mut evicted = 0;
        let mut to_delete: Vec<(Vec<u8>, usize)> = Vec::new();

        for guard in self.keyspace.prefix(&prefix_key) {
            if evicted >= max {
                break;
            }
            if let Ok((key, val)) = guard.into_inner() {
                let data_len = val.len().saturating_sub(STALE_AT_LEN);
                to_delete.push((key.to_vec(), data_len));
                evicted += 1;
            }
        }

        for (key, data_len) in &to_delete {
            let _ = self.keyspace.remove(key.as_slice());
            self.current_bytes.fetch_sub(*data_len, Ordering::Relaxed);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{Interest, Name, NameComponent};

    fn arc_name(components: &[&str]) -> Arc<Name> {
        Arc::new(Name::from_components(components.iter().map(|s| {
            NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
        })))
    }

    fn meta_fresh() -> CsMeta {
        CsMeta { stale_at: u64::MAX }
    }

    fn meta_stale() -> CsMeta {
        CsMeta { stale_at: 0 }
    }

    fn interest(components: &[&str]) -> Interest {
        Interest::new((*arc_name(components)).clone())
    }

    fn interest_fresh(components: &[&str]) -> Interest {
        use ndn_packet::tlv_type;
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp.as_bytes());
                }
            });
            w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
        });
        Interest::decode(w.finish()).unwrap()
    }

    fn interest_can_be_prefix(components: &[&str]) -> Interest {
        use ndn_packet::tlv_type;
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp.as_bytes());
                }
            });
            w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        });
        Interest::decode(w.finish()).unwrap()
    }

    fn open_temp_cs(capacity: usize) -> FjallCs {
        let dir = tempfile::tempdir().unwrap();
        FjallCs::open(dir.path(), capacity).unwrap()
    }

    // ── key encoding roundtrip ───────────────────────────────────────────────

    #[test]
    fn name_key_roundtrip() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"edu")),
            NameComponent::generic(Bytes::from_static(b"ucla")),
        ]);
        let key = name_to_key(&name);
        let decoded = key_to_name(&key).unwrap();
        assert_eq!(name, decoded);
    }

    #[test]
    fn prefix_key_is_prefix_of_child_key() {
        let parent = Name::from_components([NameComponent::generic(Bytes::from_static(b"a"))]);
        let child = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"a")),
            NameComponent::generic(Bytes::from_static(b"b")),
        ]);
        let pk = name_to_key(&parent);
        let ck = name_to_key(&child);
        assert!(ck.starts_with(&pk));
    }

    // ── basic insert / get ───────────────────────────────────────────────────

    #[tokio::test]
    async fn get_miss_returns_none() {
        let cs = open_temp_cs(65536);
        assert!(cs.get(&interest(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn insert_then_get_returns_entry() {
        let cs = open_temp_cs(65536);
        let name = arc_name(&["a", "b"]);
        cs.insert(Bytes::from_static(b"data"), name.clone(), meta_fresh())
            .await;
        let entry = cs.get(&interest(&["a", "b"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"data");
    }

    #[tokio::test]
    async fn insert_returns_inserted() {
        let cs = open_temp_cs(65536);
        let r = cs
            .insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert_eq!(r, InsertResult::Inserted);
    }

    #[tokio::test]
    async fn insert_replaces_existing() {
        let cs = open_temp_cs(65536);
        let name = arc_name(&["a"]);
        cs.insert(Bytes::from_static(b"old"), name.clone(), meta_fresh())
            .await;
        let r = cs
            .insert(Bytes::from_static(b"new"), name.clone(), meta_fresh())
            .await;
        assert_eq!(r, InsertResult::Replaced);
        let entry = cs.get(&interest(&["a"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"new");
    }

    // ── must_be_fresh ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn must_be_fresh_rejects_stale_entry() {
        let cs = open_temp_cs(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale())
            .await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn must_be_fresh_accepts_fresh_entry() {
        let cs = open_temp_cs(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_some());
    }

    #[tokio::test]
    async fn no_must_be_fresh_returns_stale_entry() {
        let cs = open_temp_cs(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale())
            .await;
        assert!(cs.get(&interest(&["a"])).await.is_some());
    }

    // ── can_be_prefix ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn can_be_prefix_finds_longer_name() {
        let cs = open_temp_cs(65536);
        cs.insert(
            Bytes::from_static(b"v"),
            arc_name(&["a", "b", "1"]),
            meta_fresh(),
        )
        .await;
        let entry = cs.get(&interest_can_be_prefix(&["a", "b"])).await;
        assert!(entry.is_some());
    }

    #[tokio::test]
    async fn can_be_prefix_miss_for_unrelated_name() {
        let cs = open_temp_cs(65536);
        cs.insert(
            Bytes::from_static(b"v"),
            arc_name(&["x", "y"]),
            meta_fresh(),
        )
        .await;
        assert!(cs.get(&interest_can_be_prefix(&["a", "b"])).await.is_none());
    }

    // ── evict ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn evict_removes_entry() {
        let cs = open_temp_cs(65536);
        let name = arc_name(&["a"]);
        cs.insert(Bytes::from_static(b"x"), name.clone(), meta_fresh())
            .await;
        let removed = cs.evict(&name).await;
        assert!(removed);
        assert!(cs.get(&interest(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn evict_nonexistent_returns_false() {
        let cs = open_temp_cs(65536);
        assert!(!cs.evict(&arc_name(&["z"])).await);
    }

    // ── capacity eviction ────────────────────────────────────────────────────

    #[tokio::test]
    async fn capacity_eviction_keeps_byte_count_bounded() {
        let cs = open_temp_cs(20);
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["a"]), meta_fresh())
            .await;
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["b"]), meta_fresh())
            .await;
        // Third insert evicts earliest key-order entry.
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["c"]), meta_fresh())
            .await;
        assert!(cs.get(&interest(&["a"])).await.is_none());
        assert!(cs.get(&interest(&["c"])).await.is_some());
    }

    // ── implicit SHA-256 digest ──────────────────────────────────────────────

    #[tokio::test]
    async fn implicit_digest_lookup_matches() {
        let cs = open_temp_cs(65536);
        let data_bytes = Bytes::from_static(b"wire-format-data");
        let name = arc_name(&["a", "b"]);
        cs.insert(data_bytes.clone(), name.clone(), meta_fresh())
            .await;

        let digest = ring::digest::digest(&ring::digest::SHA256, &data_bytes);
        let mut comps: Vec<NameComponent> = name.components().to_vec();
        comps.push(NameComponent {
            typ: ndn_packet::tlv_type::IMPLICIT_SHA256,
            value: Bytes::copy_from_slice(digest.as_ref()),
        });
        let i = Interest::new(Name::from_components(comps));
        let entry = cs.get(&i).await.expect("implicit digest hit");
        assert_eq!(entry.data.as_ref(), b"wire-format-data");
    }

    #[tokio::test]
    async fn implicit_digest_wrong_hash_misses() {
        let cs = open_temp_cs(65536);
        cs.insert(Bytes::from_static(b"data"), arc_name(&["a"]), meta_fresh())
            .await;
        let mut comps: Vec<NameComponent> = arc_name(&["a"]).components().to_vec();
        comps.push(NameComponent {
            typ: ndn_packet::tlv_type::IMPLICIT_SHA256,
            value: Bytes::from_static(&[0u8; 32]),
        });
        let i = Interest::new(Name::from_components(comps));
        assert!(cs.get(&i).await.is_none());
    }

    // ── len / current_bytes / set_capacity ───────────────────────────────────

    #[tokio::test]
    async fn len_tracks_entries() {
        let cs = open_temp_cs(65536);
        assert_eq!(cs.len(), 0);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert_eq!(cs.len(), 1);
        cs.insert(Bytes::from_static(b"y"), arc_name(&["b"]), meta_fresh())
            .await;
        assert_eq!(cs.len(), 2);
        cs.evict(&arc_name(&["a"])).await;
        assert_eq!(cs.len(), 1);
    }

    #[tokio::test]
    async fn set_capacity_evicts_excess() {
        let cs = open_temp_cs(100);
        cs.insert(Bytes::from(vec![0u8; 40]), arc_name(&["a"]), meta_fresh())
            .await;
        cs.insert(Bytes::from(vec![0u8; 40]), arc_name(&["b"]), meta_fresh())
            .await;
        assert_eq!(cs.len(), 2);
        cs.set_capacity(50);
        assert_eq!(cs.capacity().max_bytes, 50);
        assert_eq!(cs.len(), 1);
    }

    #[tokio::test]
    async fn variant_name_is_fjall() {
        let cs = open_temp_cs(1024);
        assert_eq!(cs.variant_name(), "fjall");
    }

    // ── evict_prefix ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn evict_prefix_removes_matching_entries() {
        let cs = open_temp_cs(65536);
        cs.insert(
            Bytes::from_static(b"1"),
            arc_name(&["a", "b", "1"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"2"),
            arc_name(&["a", "b", "2"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"3"),
            arc_name(&["x", "y"]),
            meta_fresh(),
        )
        .await;
        let name_ab = Name::from_components(
            ["a", "b"]
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        );
        let evicted = cs.evict_prefix(&name_ab, None).await;
        assert_eq!(evicted, 2);
        assert_eq!(cs.len(), 1);
        assert!(cs.get(&interest(&["x", "y"])).await.is_some());
    }

    #[tokio::test]
    async fn evict_prefix_respects_limit() {
        let cs = open_temp_cs(65536);
        cs.insert(
            Bytes::from_static(b"1"),
            arc_name(&["a", "1"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"2"),
            arc_name(&["a", "2"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"3"),
            arc_name(&["a", "3"]),
            meta_fresh(),
        )
        .await;
        let name_a = Name::from_components(std::iter::once(NameComponent::generic(
            Bytes::copy_from_slice(b"a"),
        )));
        let evicted = cs.evict_prefix(&name_a, Some(1)).await;
        assert_eq!(evicted, 1);
        assert_eq!(cs.len(), 2);
    }

    // ── persistence across reopen ────────────────────────────────────────────

    #[tokio::test]
    async fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let cs = FjallCs::open(dir.path(), 65536).unwrap();
            cs.insert(
                Bytes::from_static(b"persistent"),
                arc_name(&["a"]),
                meta_fresh(),
            )
            .await;
            assert_eq!(cs.len(), 1);
        }
        // Reopen from the same path.
        let cs = FjallCs::open(dir.path(), 65536).unwrap();
        assert_eq!(cs.len(), 1);
        let entry = cs.get(&interest(&["a"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"persistent");
    }
}
