use std::sync::{Arc, Mutex};

use bytes::Bytes;
use lru::LruCache;

use ndn_packet::{Interest, Name};

use crate::{CsCapacity, CsEntry, CsMeta, ContentStore, InsertResult};

/// In-memory LRU content store, bounded by total byte capacity.
pub struct LruCs {
    inner: Mutex<LruInner>,
    capacity_bytes: usize,
}

struct LruInner {
    cache:         LruCache<Arc<Name>, CsEntry>,
    current_bytes: usize,
}

impl LruCs {
    /// Create an LRU CS with the given byte capacity.
    pub fn new(capacity_bytes: usize) -> Self {
        use std::num::NonZeroUsize;
        // The LruCache is bounded by entry count; we manage byte capacity ourselves.
        let max_entries = NonZeroUsize::new(capacity_bytes / 64).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(LruInner {
                cache: LruCache::new(max_entries),
                current_bytes: 0,
            }),
            capacity_bytes,
        }
    }
}

impl ContentStore for LruCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        let mut inner = self.inner.lock().unwrap();
        // Exact-match lookup (CanBePrefix requires trie; handled by ShardedCs wrapper).
        let entry = inner.cache.get(&interest.name)?.clone();
        if interest.selectors().must_be_fresh {
            let now = now_ns();
            if !entry.is_fresh(now) {
                return None;
            }
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

        // Remove the old entry's byte count if replacing.
        let was_present = if let Some(old) = inner.cache.peek(&name) {
            inner.current_bytes = inner.current_bytes.saturating_sub(old.data.len());
            true
        } else {
            false
        };

        // Evict LRU entries until there is room.
        while inner.current_bytes + entry_bytes > self.capacity_bytes {
            if let Some((_, evicted)) = inner.cache.pop_lru() {
                inner.current_bytes = inner.current_bytes.saturating_sub(evicted.data.len());
            } else {
                break;
            }
        }

        let entry = CsEntry { data, stale_at: meta.stale_at, name: name.clone() };
        inner.cache.put(name, entry);
        inner.current_bytes += entry_bytes;

        if was_present { InsertResult::Replaced } else { InsertResult::Inserted }
    }

    async fn evict(&self, name: &Name) -> bool {
        let mut inner = self.inner.lock().unwrap();
        // Build an Arc<Name> key for the lookup — LruCache requires owned key.
        // This is a best-effort linear scan workaround; a real implementation
        // would store names as Arc to avoid this.
        let key = inner.cache.iter()
            .find(|(k, _)| k.as_ref() == name)
            .map(|(k, _)| k.clone());
        if let Some(k) = key {
            if let Some(evicted) = inner.cache.pop(&k) {
                inner.current_bytes = inner.current_bytes.saturating_sub(evicted.data.len());
                return true;
            }
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
