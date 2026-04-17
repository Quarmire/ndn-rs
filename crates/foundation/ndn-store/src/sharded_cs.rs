use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::{Interest, Name};

use crate::{ContentStore, CsCapacity, CsEntry, CsMeta, CsStats, InsertResult};

/// Shards a `ContentStore` across `N` instances to reduce lock contention.
///
/// Shard selection is by **first name component** (not full name hash) so that
/// related content (`/video/seg/1`, `/video/seg/2`) lands in the same shard,
/// preserving LRU locality for sequential access.
///
/// The shard count is the length of the `shards` `Vec` and is fixed at
/// construction time.
pub struct ShardedCs<C: ContentStore> {
    shards: Vec<C>,
    shard_count: usize,
}

impl<C: ContentStore> ShardedCs<C> {
    /// Create a `ShardedCs` from pre-constructed inner stores.
    ///
    /// # Panics
    ///
    /// Panics if `shards` is empty.
    pub fn new(shards: Vec<C>) -> Self {
        let shard_count = shards.len();
        assert!(shard_count > 0, "ShardedCs requires at least one shard");
        Self {
            shards,
            shard_count,
        }
    }

    pub fn shard_count(&self) -> usize {
        self.shard_count
    }

    fn shard_for(&self, name: &Name) -> usize {
        match name.components().first() {
            Some(first) => {
                let mut h = DefaultHasher::new();
                first.hash(&mut h);
                (h.finish() as usize) % self.shard_count
            }
            None => 0,
        }
    }
}

impl<C: ContentStore> ContentStore for ShardedCs<C> {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        let idx = self.shard_for(&interest.name);
        self.shards[idx].get(interest).await
    }

    async fn insert(&self, data: Bytes, name: Arc<Name>, meta: CsMeta) -> InsertResult {
        let idx = self.shard_for(&name);
        self.shards[idx].insert(data, name, meta).await
    }

    async fn evict(&self, name: &Name) -> bool {
        let idx = self.shard_for(name);
        self.shards[idx].evict(name).await
    }

    fn capacity(&self) -> CsCapacity {
        let total: usize = self.shards.iter().map(|s| s.capacity().max_bytes).sum();
        CsCapacity::bytes(total)
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.len()).sum()
    }

    fn current_bytes(&self) -> usize {
        self.shards.iter().map(|s| s.current_bytes()).sum()
    }

    fn set_capacity(&self, max_bytes: usize) {
        let per_shard = max_bytes / self.shard_count;
        for shard in &self.shards {
            shard.set_capacity(per_shard);
        }
    }

    fn variant_name(&self) -> &str {
        "sharded-lru"
    }

    async fn evict_prefix(&self, prefix: &Name, limit: Option<usize>) -> usize {
        let idx = self.shard_for(prefix);
        self.shards[idx].evict_prefix(prefix, limit).await
    }

    fn stats(&self) -> CsStats {
        let mut combined = CsStats::default();
        for shard in &self.shards {
            let s = shard.stats();
            combined.hits += s.hits;
            combined.misses += s.misses;
            combined.inserts += s.inserts;
            combined.evictions += s.evictions;
        }
        combined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LruCs;
    use ndn_packet::NameComponent;

    fn arc_name(components: &[&str]) -> Arc<Name> {
        Arc::new(Name::from_components(components.iter().map(|s| {
            NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
        })))
    }

    fn meta_fresh() -> CsMeta {
        CsMeta { stale_at: u64::MAX }
    }

    fn interest(components: &[&str]) -> Interest {
        Interest::new((*arc_name(components)).clone())
    }

    fn make_sharded(n: usize, shard_bytes: usize) -> ShardedCs<LruCs> {
        ShardedCs::new((0..n).map(|_| LruCs::new(shard_bytes)).collect())
    }

    #[test]
    fn shard_count_reported() {
        let cs = make_sharded(4, 1024);
        assert_eq!(cs.shard_count(), 4);
    }

    #[test]
    fn capacity_is_sum_of_shards() {
        let cs = make_sharded(4, 1024);
        assert_eq!(cs.capacity().max_bytes, 4 * 1024);
    }

    #[test]
    #[should_panic]
    fn empty_shards_panics() {
        let _cs: ShardedCs<LruCs> = ShardedCs::new(vec![]);
    }

    #[tokio::test]
    async fn insert_then_get_roundtrip() {
        let cs = make_sharded(4, 65536);
        let name = arc_name(&["edu", "ucla", "data"]);
        cs.insert(Bytes::from_static(b"payload"), name.clone(), meta_fresh())
            .await;
        let entry = cs.get(&interest(&["edu", "ucla", "data"])).await.unwrap();
        assert_eq!(entry.data.as_ref(), b"payload");
    }

    #[tokio::test]
    async fn miss_returns_none() {
        let cs = make_sharded(2, 65536);
        assert!(cs.get(&interest(&["x"])).await.is_none());
    }

    #[tokio::test]
    async fn names_with_same_first_component_land_in_same_shard() {
        // /a/1 and /a/2 share first component → same shard → both accessible.
        let cs = make_sharded(4, 65536);
        cs.insert(
            Bytes::from_static(b"v1"),
            arc_name(&["a", "1"]),
            meta_fresh(),
        )
        .await;
        cs.insert(
            Bytes::from_static(b"v2"),
            arc_name(&["a", "2"]),
            meta_fresh(),
        )
        .await;
        assert!(cs.get(&interest(&["a", "1"])).await.is_some());
        assert!(cs.get(&interest(&["a", "2"])).await.is_some());
    }

    #[tokio::test]
    async fn evict_removes_entry() {
        let cs = make_sharded(2, 65536);
        let name = arc_name(&["b", "1"]);
        cs.insert(Bytes::from_static(b"v"), name.clone(), meta_fresh())
            .await;
        assert!(cs.evict(&name).await);
        assert!(cs.get(&interest(&["b", "1"])).await.is_none());
    }

    #[tokio::test]
    async fn evict_nonexistent_returns_false() {
        let cs = make_sharded(2, 65536);
        assert!(!cs.evict(&arc_name(&["z"])).await);
    }

    #[tokio::test]
    async fn single_shard_works() {
        let cs = make_sharded(1, 65536);
        cs.insert(Bytes::from_static(b"data"), arc_name(&["a"]), meta_fresh())
            .await;
        assert!(cs.get(&interest(&["a"])).await.is_some());
    }
}
