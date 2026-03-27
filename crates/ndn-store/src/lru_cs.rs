use std::sync::{Arc, Mutex};

use bytes::Bytes;
use lru::LruCache;

use ndn_packet::{Interest, Name};

use crate::{CsCapacity, CsEntry, CsMeta, ContentStore, InsertResult, NameTrie};

/// In-memory LRU content store, bounded by total byte capacity.
///
/// Maintains two indices:
/// - `cache`: `LruCache<Arc<Name>, CsEntry>` — exact-match lookup in O(1).
/// - `prefix_index`: `NameTrie<Arc<Name>>` — maps each cached name to itself,
///   enabling `CanBePrefix` lookups via `first_descendant`.
///
/// All insertions and evictions update both indices atomically under the lock.
pub struct LruCs {
    inner: Mutex<LruInner>,
    capacity_bytes: usize,
}

struct LruInner {
    cache:         LruCache<Arc<Name>, CsEntry>,
    prefix_index:  NameTrie<Arc<Name>>,
    current_bytes: usize,
}

impl LruCs {
    /// Create an LRU CS with the given byte capacity.
    pub fn new(capacity_bytes: usize) -> Self {
        use std::num::NonZeroUsize;
        // Set the LruCache entry limit to capacity_bytes so it never fires before
        // our byte-based eviction loop does. Each Data packet is at least 1 byte,
        // so we can never accumulate more than capacity_bytes entries.
        let max_entries = NonZeroUsize::new(capacity_bytes.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruInner {
                cache:         LruCache::new(max_entries),
                prefix_index:  NameTrie::new(),
                current_bytes: 0,
            }),
            capacity_bytes,
        }
    }
}

impl ContentStore for LruCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        let mut inner = self.inner.lock().unwrap();
        let entry = if interest.selectors().can_be_prefix {
            // Walk the prefix trie to find a cached data whose name starts
            // with the interest name, then look it up in the LRU cache
            // (which promotes it to MRU).
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

    async fn insert(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> InsertResult {
        let entry_bytes = data.len();
        let mut inner = self.inner.lock().unwrap();

        // Track whether we are replacing an existing entry.
        let was_present = if let Some(old) = inner.cache.peek(name.as_ref()) {
            inner.current_bytes = inner.current_bytes.saturating_sub(old.data.len());
            true
        } else {
            false
        };

        // Evict LRU entries until there is room, keeping prefix_index in sync.
        while inner.current_bytes + entry_bytes > self.capacity_bytes {
            if let Some((evicted_name, evicted)) = inner.cache.pop_lru() {
                inner.current_bytes =
                    inner.current_bytes.saturating_sub(evicted.data.len());
                inner.prefix_index.remove(&*evicted_name);
            } else {
                break;
            }
        }

        let entry = CsEntry { data, stale_at: meta.stale_at, name: name.clone() };
        inner.cache.put(name.clone(), entry);
        inner.current_bytes += entry_bytes;

        // Only index new entries; replacements keep the same name in the trie.
        if !was_present {
            inner.prefix_index.insert(name.as_ref(), Arc::clone(&name));
        }

        if was_present { InsertResult::Replaced } else { InsertResult::Inserted }
    }

    async fn evict(&self, name: &Name) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if let Some(evicted) = inner.cache.pop(name) {
            inner.current_bytes =
                inner.current_bytes.saturating_sub(evicted.data.len());
            inner.prefix_index.remove(name);
            return true;
        }
        false
    }

    fn capacity(&self) -> CsCapacity {
        CsCapacity::bytes(self.capacity_bytes)
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
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
        Arc::new(Name::from_components(
            components.iter().map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes())))
        ))
    }

    fn meta_fresh() -> CsMeta {
        CsMeta { stale_at: u64::MAX }
    }

    fn meta_stale() -> CsMeta {
        CsMeta { stale_at: 0 }  // already stale
    }

    fn interest(components: &[&str]) -> Interest {
        Interest::new((*arc_name(components)).clone())
    }

    fn interest_fresh(components: &[&str]) -> Interest {
        let name = (*arc_name(components)).clone();
        let _ = Interest::new(name);
        // Force must_be_fresh by building wire bytes with the flag set.
        // For testing purposes we build via TlvWriter.
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

    // ── basic insert / get ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_miss_returns_none() {
        let cs = LruCs::new(65536);
        assert!(cs.get(&interest(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn insert_then_get_returns_entry() {
        let cs = LruCs::new(65536);
        let name = arc_name(&["a", "b"]);
        cs.insert(Bytes::from_static(b"data"), name.clone(), meta_fresh()).await;
        let entry = cs.get(&interest(&["a", "b"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"data");
    }

    #[tokio::test]
    async fn insert_returns_inserted() {
        let cs = LruCs::new(65536);
        let r = cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh()).await;
        assert_eq!(r, InsertResult::Inserted);
    }

    #[tokio::test]
    async fn insert_replaces_existing() {
        let cs = LruCs::new(65536);
        let name = arc_name(&["a"]);
        cs.insert(Bytes::from_static(b"old"), name.clone(), meta_fresh()).await;
        let r = cs.insert(Bytes::from_static(b"new"), name.clone(), meta_fresh()).await;
        assert_eq!(r, InsertResult::Replaced);
        let entry = cs.get(&interest(&["a"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"new");
    }

    // ── must_be_fresh ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn must_be_fresh_rejects_stale_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale()).await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_none());
    }

    #[tokio::test]
    async fn must_be_fresh_accepts_fresh_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_fresh()).await;
        assert!(cs.get(&interest_fresh(&["a"])).await.is_some());
    }

    #[tokio::test]
    async fn no_must_be_fresh_returns_stale_entry() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a"]), meta_stale()).await;
        // Without MustBeFresh the stale entry is still returned.
        assert!(cs.get(&interest(&["a"])).await.is_some());
    }

    // ── can_be_prefix ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn can_be_prefix_finds_longer_name() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"v"), arc_name(&["a", "b", "1"]), meta_fresh()).await;
        let entry = cs.get(&interest_can_be_prefix(&["a", "b"])).await;
        assert!(entry.is_some());
    }

    #[tokio::test]
    async fn can_be_prefix_miss_for_unrelated_name() {
        let cs = LruCs::new(65536);
        cs.insert(Bytes::from_static(b"v"), arc_name(&["x", "y"]), meta_fresh()).await;
        assert!(cs.get(&interest_can_be_prefix(&["a", "b"])).await.is_none());
    }

    // ── evict ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn evict_removes_entry() {
        let cs = LruCs::new(65536);
        let name = arc_name(&["a"]);
        cs.insert(Bytes::from_static(b"x"), name.clone(), meta_fresh()).await;
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
        cs.insert(Bytes::from_static(b"x"), arc_name(&["a", "b"]), meta_fresh()).await;
        cs.evict(&arc_name(&["a", "b"])).await;
        // CanBePrefix should also miss now.
        assert!(cs.get(&interest_can_be_prefix(&["a"])).await.is_none());
    }

    // ── capacity / LRU eviction ───────────────────────────────────────────────

    #[tokio::test]
    async fn capacity_is_reported() {
        let cs = LruCs::new(1024);
        assert_eq!(cs.capacity().max_bytes, 1024);
    }

    #[tokio::test]
    async fn lru_eviction_keeps_byte_count_bounded() {
        // Capacity = 20 bytes; each entry is 10 bytes → room for 2.
        let cs = LruCs::new(20);
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["a"]), meta_fresh()).await;
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["b"]), meta_fresh()).await;
        // Third insert evicts /a (LRU).
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["c"]), meta_fresh()).await;
        assert!(cs.get(&interest(&["a"])).await.is_none());
        assert!(cs.get(&interest(&["b"])).await.is_some());
        assert!(cs.get(&interest(&["c"])).await.is_some());
    }

    #[tokio::test]
    async fn lru_eviction_removes_from_prefix_index() {
        let cs = LruCs::new(20);
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["a", "b"]), meta_fresh()).await;
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["b", "c"]), meta_fresh()).await;
        // Third insert evicts /a/b.
        cs.insert(Bytes::from(vec![0u8; 10]), arc_name(&["c", "d"]), meta_fresh()).await;
        // CanBePrefix for /a should now miss (evicted entry removed from index).
        assert!(cs.get(&interest_can_be_prefix(&["a"])).await.is_none());
    }
}
