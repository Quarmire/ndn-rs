use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use lru::LruCache;
use sha2::{Digest, Sha256};

use ndn_packet::{Interest, Name};

use crate::{ContentStore, CsCapacity, CsEntry, CsMeta, InsertResult, NameTrie};

/// In-memory LRU content store, bounded by total byte capacity. `get()` skips
/// the Mutex via an atomic empty check so cache-cold paths are lock-free.
pub struct LruCs {
    inner: Mutex<LruInner>,
    capacity_bytes: AtomicUsize,
    entry_count: AtomicUsize,
    /// NFD cs/config Admit/Serve toggles (default on).
    admit: AtomicBool,
    serve: AtomicBool,
}

struct LruInner {
    cache: LruCache<Arc<Name>, CsEntry>,
    prefix_index: NameTrie<Arc<Name>>,
    current_bytes: usize,
}

impl LruCs {
    pub fn new(capacity_bytes: usize) -> Self {
        use std::num::NonZeroUsize;
        // Entry limit set to `capacity_bytes` so the byte-based eviction loop
        // always fires first (every Data packet is at least 1 byte).
        let max_entries = NonZeroUsize::new(capacity_bytes.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruInner {
                cache: LruCache::new(max_entries),
                prefix_index: NameTrie::new(),
                current_bytes: 0,
            }),
            capacity_bytes: AtomicUsize::new(capacity_bytes),
            entry_count: AtomicUsize::new(0),
            admit: AtomicBool::new(true),
            serve: AtomicBool::new(true),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count.load(Ordering::Relaxed) == 0
    }
}

impl ContentStore for LruCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        // NFD cs/config Serve gate (Cs::findImpl): don't satisfy from cache
        // when serving is disabled.
        if !self.serve.load(Ordering::Relaxed) {
            return None;
        }
        if self.entry_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();

        // Trailing digest components: ImplicitSha256DigestComponent verifies
        // against the cached wire bytes; ParametersSha256DigestComponent is
        // stripped (not a multiplexing key) to mirror the PIT side.
        let comps = interest.name.components();
        let last_typ = comps.last().map(|c| c.typ);
        let has_implicit_digest = last_typ == Some(ndn_packet::tlv_type::IMPLICIT_SHA256);
        let has_psdc = last_typ == Some(ndn_packet::tlv_type::PARAMETERS_SHA256);

        let entry = if has_implicit_digest {
            let data_name = Name::from_components(comps[..comps.len() - 1].iter().cloned());
            let candidate = inner.cache.get(&data_name)?.clone();
            let expected_digest = &comps.last().unwrap().value;
            let actual = Sha256::digest(&candidate.data);
            if expected_digest.as_ref() != actual.as_slice() {
                return None;
            }
            candidate
        } else if has_psdc {
            let data_name = Name::from_components(comps[..comps.len() - 1].iter().cloned());
            inner.cache.get(&data_name)?.clone()
        } else if interest.selectors().can_be_prefix {
            let data_name = inner.prefix_index.first_descendant(&interest.name)?;
            inner.cache.get(data_name.as_ref())?.clone()
        } else {
            inner.cache.get(interest.name.as_ref())?.clone()
        };

        if interest.selectors().must_be_fresh && !entry.is_fresh(now_ns()) {
            return None;
        }
        Some(entry)
    }

    async fn insert(&self, data: Bytes, name: Arc<Name>, meta: CsMeta) -> InsertResult {
        // NFD cs/config Admit gate (Cs::insert): admit no new Data when
        // admission is disabled.
        if !self.admit.load(Ordering::Relaxed) {
            return InsertResult::Skipped;
        }
        let entry_bytes = data.len();
        let capacity = self.capacity_bytes.load(Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();

        let was_present = if let Some(old) = inner.cache.peek(name.as_ref()) {
            inner.current_bytes = inner.current_bytes.saturating_sub(old.data.len());
            true
        } else {
            false
        };

        while inner.current_bytes + entry_bytes > capacity {
            if let Some((evicted_name, evicted)) = inner.cache.pop_lru() {
                inner.current_bytes = inner.current_bytes.saturating_sub(evicted.data.len());
                inner.prefix_index.remove(&evicted_name);
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
            } else {
                break;
            }
        }

        let entry = CsEntry {
            data,
            stale_at: meta.stale_at,
            name: name.clone(),
        };
        inner.cache.put(name.clone(), entry);
        inner.current_bytes += entry_bytes;

        if !was_present {
            inner.prefix_index.insert(name.as_ref(), Arc::clone(&name));
        }

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
        let mut inner = self.inner.lock().unwrap();
        if let Some(evicted) = inner.cache.pop(name) {
            inner.current_bytes = inner.current_bytes.saturating_sub(evicted.data.len());
            inner.prefix_index.remove(name);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn capacity(&self) -> CsCapacity {
        CsCapacity::bytes(self.capacity_bytes.load(Ordering::Relaxed))
    }

    fn len(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    fn current_bytes(&self) -> usize {
        self.inner.lock().unwrap().current_bytes
    }

    fn set_capacity(&self, max_bytes: usize) {
        self.capacity_bytes.store(max_bytes, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        while inner.current_bytes > max_bytes {
            if let Some((evicted_name, evicted)) = inner.cache.pop_lru() {
                inner.current_bytes = inner.current_bytes.saturating_sub(evicted.data.len());
                inner.prefix_index.remove(&evicted_name);
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    fn admit_enabled(&self) -> bool {
        self.admit.load(Ordering::Relaxed)
    }
    fn serve_enabled(&self) -> bool {
        self.serve.load(Ordering::Relaxed)
    }
    fn set_admit(&self, enabled: bool) {
        self.admit.store(enabled, Ordering::Relaxed);
    }
    fn set_serve(&self, enabled: bool) {
        self.serve.store(enabled, Ordering::Relaxed);
    }

    fn variant_name(&self) -> &str {
        "lru"
    }

    async fn evict_prefix(&self, prefix: &Name, limit: Option<usize>) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let names: Vec<Arc<Name>> = inner.prefix_index.descendants(prefix);
        let max = limit.unwrap_or(usize::MAX);
        let mut evicted = 0;
        for name in names {
            if evicted >= max {
                break;
            }
            if let Some(entry) = inner.cache.pop(name.as_ref()) {
                inner.current_bytes = inner.current_bytes.saturating_sub(entry.data.len());
                inner.prefix_index.remove(name.as_ref());
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
                evicted += 1;
            }
        }
        evicted
    }
}

fn now_ns() -> u64 {
    use web_time::SystemTime;
    use web_time::UNIX_EPOCH;
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
        let name = (*arc_name(components)).clone();
        let _ = Interest::new(name);
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

    #[tokio::test]
    async fn get_miss_returns_none() {
        let cs = LruCs::new(65536);
        assert!(cs.get(&interest(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn insert_then_get_returns_entry() {
        let cs = LruCs::new(65536);
        let name = arc_name(&["a", "b"]);
        cs.insert(Bytes::from_static(b"data"), name.clone(), meta_fresh())
            .await;
        let entry = cs.get(&interest(&["a", "b"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"data");
    }

    #[tokio::test]
    async fn insert_returns_inserted() {
        let cs = LruCs::new(65536);
        let r = cs
            .insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert_eq!(r, InsertResult::Inserted);
    }

    #[tokio::test]
    async fn insert_replaces_existing() {
        let cs = LruCs::new(65536);
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

    #[tokio::test]
    async fn must_be_fresh_rejects_stale_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale())
            .await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn must_be_fresh_accepts_fresh_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_some());
    }

    #[tokio::test]
    async fn no_must_be_fresh_returns_stale_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale())
            .await;
        // Without MustBeFresh the stale entry is still returned.
        assert!(cs.get(&interest(&["a"])).await.is_some());
    }

    #[tokio::test]
    async fn can_be_prefix_finds_longer_name() {
        let cs = LruCs::new(65536);
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
        let cs = LruCs::new(65536);
        cs.insert(
            Bytes::from_static(b"v"),
            arc_name(&["x", "y"]),
            meta_fresh(),
        )
        .await;
        assert!(cs.get(&interest_can_be_prefix(&["a", "b"])).await.is_none());
    }

    #[tokio::test]
    async fn evict_removes_entry() {
        let cs = LruCs::new(65536);
        let name = arc_name(&["a"]);
        cs.insert(Bytes::from_static(b"x"), name.clone(), meta_fresh())
            .await;
        let removed = cs.evict(&name).await;
        assert!(removed);
        assert!(cs.get(&interest(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn evict_nonexistent_returns_false() {
        let cs = LruCs::new(65536);
        assert!(!cs.evict(&arc_name(&["z"])).await);
    }

    #[tokio::test]
    async fn evict_removes_from_prefix_index() {
        let cs = LruCs::new(65536);
        cs.insert(
            Bytes::from_static(b"x"),
            arc_name(&["a", "b"]),
            meta_fresh(),
        )
        .await;
        cs.evict(&arc_name(&["a", "b"])).await;
        // CanBePrefix should also miss now.
        assert!(cs.get(&interest_can_be_prefix(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn capacity_is_reported() {
        let cs = LruCs::new(1024);
        assert_eq!(cs.capacity().max_bytes, 1024);
    }

    #[tokio::test]
    async fn serve_flag_gates_lookup() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(
            cs.get(&interest(&["a"])).await.is_some(),
            "served by default"
        );

        cs.set_serve(false);
        assert!(
            cs.get(&interest(&["a"])).await.is_none(),
            "serve disabled → cache not consulted"
        );
        cs.set_serve(true);
        assert!(
            cs.get(&interest(&["a"])).await.is_some(),
            "serve re-enabled"
        );
    }

    #[tokio::test]
    async fn admit_flag_gates_insert() {
        let cs = LruCs::new(65536);
        cs.set_admit(false);
        let r = cs
            .insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(
            matches!(r, InsertResult::Skipped),
            "admit off → not inserted"
        );
        assert!(cs.get(&interest(&["a"])).await.is_none(), "nothing cached");

        cs.set_admit(true);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(
            cs.get(&interest(&["a"])).await.is_some(),
            "admit on → cached"
        );
    }

    #[tokio::test]
    async fn lru_eviction_keeps_byte_count_bounded() {
        // Capacity = 20 bytes; each entry is 10 bytes → room for 2.
        let cs = LruCs::new(20);
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["a"]), meta_fresh())
            .await;
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["b"]), meta_fresh())
            .await;
        // Third insert evicts /a (LRU).
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["c"]), meta_fresh())
            .await;
        assert!(cs.get(&interest(&["a"])).await.is_none());
        assert!(cs.get(&interest(&["b"])).await.is_some());
        assert!(cs.get(&interest(&["c"])).await.is_some());
    }

    #[tokio::test]
    async fn implicit_digest_lookup_matches() {
        let cs = LruCs::new(65536);
        let data_bytes = Bytes::from_static(b"wire-format-data");
        let name = arc_name(&["a", "b"]);
        cs.insert(data_bytes.clone(), name.clone(), meta_fresh())
            .await;

        // Build an Interest whose name is /a/b/<implicit-digest>
        let digest = ring::digest::digest(&ring::digest::SHA256, &data_bytes);
        let mut comps: Vec<NameComponent> = name.components().to_vec();
        comps.push(NameComponent {
            typ: ndn_packet::tlv_type::IMPLICIT_SHA256,
            value: Bytes::copy_from_slice(digest.as_ref()),
        });
        let interest_name = Name::from_components(comps);
        let i = Interest::new(interest_name);
        let entry = cs.get(&i).await.expect("implicit digest hit");
        assert_eq!(entry.data.as_ref(), b"wire-format-data");
    }

    #[tokio::test]
    async fn implicit_digest_wrong_hash_misses() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"data"), arc_name(&["a"]), meta_fresh())
            .await;

        // Wrong digest
        let mut comps: Vec<NameComponent> = arc_name(&["a"]).components().to_vec();
        comps.push(NameComponent {
            typ: ndn_packet::tlv_type::IMPLICIT_SHA256,
            value: Bytes::from_static(&[0u8; 32]),
        });
        let i = Interest::new(Name::from_components(comps));
        assert!(cs.get(&i).await.is_none());
    }

    #[tokio::test]
    async fn lru_eviction_removes_from_prefix_index() {
        let cs = LruCs::new(20);
        cs.insert(
            Bytes::from(vec![0u8; 10]),
            arc_name(&["a", "b"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from(vec![0u8; 10]),
            arc_name(&["b", "c"]),
            meta_fresh(),
        )
        .await;
        // Third insert evicts /a/b.
        cs.insert(
            Bytes::from(vec![0u8; 10]),
            arc_name(&["c", "d"]),
            meta_fresh(),
        )
        .await;
        // CanBePrefix for /a should now miss (evicted entry removed from index).
        assert!(cs.get(&interest_can_be_prefix(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn len_tracks_entries() {
        let cs = LruCs::new(65536);
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
        let cs = LruCs::new(100);
        cs.insert(Bytes::from(vec![0u8; 40]), arc_name(&["a"]), meta_fresh())
            .await;
        cs.insert(Bytes::from(vec![0u8; 40]), arc_name(&["b"]), meta_fresh())
            .await;
        assert_eq!(cs.len(), 2);
        // Shrink capacity below current usage — should evict LRU entries.
        cs.set_capacity(50);
        assert_eq!(cs.capacity().max_bytes, 50);
        assert_eq!(cs.len(), 1);
        // The more recently used entry (/b) survives.
        assert!(cs.get(&interest(&["b"])).await.is_some());
    }

    #[tokio::test]
    async fn variant_name_is_lru() {
        let cs = LruCs::new(1024);
        assert_eq!(cs.variant_name(), "lru");
    }

    #[tokio::test]
    async fn evict_prefix_removes_matching_entries() {
        let cs = LruCs::new(65536);
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
        // /x/y should still be there.
        assert!(cs.get(&interest(&["x", "y"])).await.is_some());
    }

    #[tokio::test]
    async fn evict_prefix_respects_limit() {
        let cs = LruCs::new(65536);
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
}
