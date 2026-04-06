//! Observable content store wrapper with event hooks and atomic counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::{Interest, Name};

use crate::{CsCapacity, CsEntry, CsMeta, CsStats, ErasedContentStore, InsertResult};

/// Events emitted by an observable content store.
#[derive(Debug)]
pub enum CsEvent {
    Hit { name: Arc<Name> },
    Miss { name: Arc<Name> },
    Insert { name: Arc<Name>, bytes: usize },
    Evict { name: Arc<Name> },
}

/// Observer that receives CS events.
///
/// Implementations must be non-blocking — the observer is called inline
/// on the hot path. Use a channel or atomic buffer for expensive processing.
pub trait CsObserver: Send + Sync + 'static {
    fn on_event(&self, event: CsEvent);
}

/// Atomic counters for CS hit/miss/insert/eviction tracking.
struct CsStatsCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
}

impl CsStatsCounters {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> CsStats {
        CsStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

/// Wraps any [`ErasedContentStore`] with hit/miss/insert/eviction counters
/// and an optional [`CsObserver`] callback.
///
/// When no observer is registered, the overhead is a single `Option` check
/// plus an atomic increment per operation.
pub struct ObservableCs {
    inner: Arc<dyn ErasedContentStore>,
    observer: Option<Arc<dyn CsObserver>>,
    counters: CsStatsCounters,
}

impl ObservableCs {
    pub fn new(
        inner: Arc<dyn ErasedContentStore>,
        observer: Option<Arc<dyn CsObserver>>,
    ) -> Self {
        Self {
            inner,
            observer,
            counters: CsStatsCounters::new(),
        }
    }

    fn emit(&self, event: CsEvent) {
        if let Some(ref obs) = self.observer {
            obs.on_event(event);
        }
    }
}

impl ErasedContentStore for ObservableCs {
    fn get_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<CsEntry>> + Send + 'a>> {
        Box::pin(async move {
            let result = self.inner.get_erased(interest).await;
            let name = Arc::clone(&interest.name);
            if result.is_some() {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                self.emit(CsEvent::Hit { name });
            } else {
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                self.emit(CsEvent::Miss { name });
            }
            result
        })
    }

    fn insert_erased(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = InsertResult> + Send + '_>> {
        Box::pin(async move {
            let bytes = data.len();
            let result = self.inner.insert_erased(data, name.clone(), meta).await;
            if result != InsertResult::Skipped {
                self.counters.inserts.fetch_add(1, Ordering::Relaxed);
                self.emit(CsEvent::Insert { name, bytes });
            }
            result
        })
    }

    fn evict_erased<'a>(
        &'a self,
        name: &'a Name,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let removed = self.inner.evict_erased(name).await;
            if removed {
                self.counters.evictions.fetch_add(1, Ordering::Relaxed);
                self.emit(CsEvent::Evict {
                    name: Arc::new(name.clone()),
                });
            }
            removed
        })
    }

    fn evict_prefix_erased<'a>(
        &'a self,
        prefix: &'a Name,
        limit: Option<usize>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + 'a>> {
        Box::pin(async move {
            let evicted = self.inner.evict_prefix_erased(prefix, limit).await;
            self.counters
                .evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
            evicted
        })
    }

    fn capacity(&self) -> CsCapacity {
        self.inner.capacity()
    }

    fn set_capacity(&self, max_bytes: usize) {
        self.inner.set_capacity(max_bytes);
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn current_bytes(&self) -> usize {
        self.inner.current_bytes()
    }

    fn variant_name(&self) -> &str {
        self.inner.variant_name()
    }

    fn stats(&self) -> CsStats {
        self.counters.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LruCs;
    use ndn_packet::NameComponent;
    use std::sync::atomic::AtomicUsize;

    fn arc_name(components: &[&str]) -> Arc<Name> {
        Arc::new(Name::from_components(components.iter().map(|s| {
            NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
        })))
    }

    fn interest(components: &[&str]) -> Interest {
        Interest::new((*arc_name(components)).clone())
    }

    struct CountingObserver {
        hits: AtomicUsize,
        misses: AtomicUsize,
        inserts: AtomicUsize,
    }

    impl CountingObserver {
        fn new() -> Self {
            Self {
                hits: AtomicUsize::new(0),
                misses: AtomicUsize::new(0),
                inserts: AtomicUsize::new(0),
            }
        }
    }

    impl CsObserver for CountingObserver {
        fn on_event(&self, event: CsEvent) {
            match event {
                CsEvent::Hit { .. } => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                }
                CsEvent::Miss { .. } => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                }
                CsEvent::Insert { .. } => {
                    self.inserts.fetch_add(1, Ordering::Relaxed);
                }
                CsEvent::Evict { .. } => {}
            }
        }
    }

    #[tokio::test]
    async fn observable_tracks_hits_and_misses() {
        let observer = Arc::new(CountingObserver::new());
        let inner: Arc<dyn ErasedContentStore> = Arc::new(LruCs::new(65536));
        let cs = ObservableCs::new(inner, Some(Arc::clone(&observer) as _));

        // Miss
        cs.get_erased(&interest(&["a"])).await;
        assert_eq!(observer.misses.load(Ordering::Relaxed), 1);

        // Insert + hit
        cs.insert_erased(
            Bytes::from_static(b"data"),
            arc_name(&["a"]),
            CsMeta { stale_at: u64::MAX },
        )
        .await;
        cs.get_erased(&interest(&["a"])).await;
        assert_eq!(observer.hits.load(Ordering::Relaxed), 1);
        assert_eq!(observer.inserts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stats_reflect_operations() {
        let inner: Arc<dyn ErasedContentStore> = Arc::new(LruCs::new(65536));
        let cs = ObservableCs::new(inner, None);
        cs.insert_erased(
            Bytes::from_static(b"x"),
            arc_name(&["a"]),
            CsMeta { stale_at: u64::MAX },
        )
        .await;
        cs.get_erased(&interest(&["a"])).await; // hit
        cs.get_erased(&interest(&["b"])).await; // miss

        let stats = cs.stats();
        assert_eq!(stats.inserts, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }
}
