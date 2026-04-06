use bytes::Bytes;
use criterion::{
    BatchSize, BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main,
};
use ndn_packet::{Name, NameComponent};
use ndn_store::{ContentStore, CsMeta, InsertResult, LruCs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn comp(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

fn data_wire(name: &Name) -> Bytes {
    Bytes::copy_from_slice(name.to_string().as_bytes())
}

fn far_future() -> u64 {
    u64::MAX
}

fn interest_for(name_s: &str) -> ndn_packet::Interest {
    use ndn_packet::encode::InterestBuilder;
    let wire = InterestBuilder::new(name_s).build();
    ndn_packet::Interest::decode(wire).unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

// ── get_miss_empty ────────────────────────────────────────────────────────────
// Fast path: atomic load, no lock.

fn bench_get_miss_empty(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    let interest = interest_for("/ndn/data");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_miss_empty", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&interest));
            debug_assert!(result.is_none());
            result
        });
    });
}

// ── get_miss_populated ────────────────────────────────────────────────────────
// Cache full of unrelated names; exercises lock + LRU traversal miss.

fn bench_get_miss_populated(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    for i in 0..200u64 {
        let name: Arc<Name> = Arc::new(format!("/a/populate/{i}").parse().unwrap());
        let wire = data_wire(&name);
        rt.block_on(cs.insert(
            wire,
            name,
            CsMeta {
                stale_at: far_future(),
            },
        ));
    }
    let interest = interest_for("/ndn/not/cached");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_miss_populated", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&interest));
            debug_assert!(result.is_none());
            result
        });
    });
}

// ── get_hit ───────────────────────────────────────────────────────────────────

fn bench_get_hit(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    let name: Arc<Name> = Arc::new("/ndn/hit".parse().unwrap());
    rt.block_on(cs.insert(
        data_wire(&name),
        Arc::clone(&name),
        CsMeta {
            stale_at: far_future(),
        },
    ));
    let interest = interest_for("/ndn/hit");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_hit", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&interest));
            debug_assert!(result.is_some());
            result
        });
    });
}

// ── get_can_be_prefix ─────────────────────────────────────────────────────────
// NameTrie first_descendant path vs. LruCache exact-match path.

fn bench_get_can_be_prefix(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    let name: Arc<Name> = Arc::new("/ndn/prefix/data".parse().unwrap());
    rt.block_on(cs.insert(
        data_wire(&name),
        Arc::clone(&name),
        CsMeta {
            stale_at: far_future(),
        },
    ));
    use ndn_packet::encode::InterestBuilder;
    let wire = InterestBuilder::new("/ndn/prefix").can_be_prefix().build();
    let interest = ndn_packet::Interest::decode(wire).unwrap();
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_can_be_prefix", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&interest));
            debug_assert!(result.is_some());
            result
        });
    });
}

// ── insert_replace ────────────────────────────────────────────────────────────
// Same name every iteration — steady-state replacement (no NameTrie update).

fn bench_insert_replace(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    let name: Arc<Name> = Arc::new("/ndn/replace".parse().unwrap());
    rt.block_on(cs.insert(
        data_wire(&name),
        Arc::clone(&name),
        CsMeta {
            stale_at: far_future(),
        },
    ));
    g.throughput(Throughput::Elements(1));
    g.bench_function("insert_replace", |b| {
        b.iter(|| {
            let wire = data_wire(&name);
            let result = rt.block_on(cs.insert(
                wire,
                Arc::clone(&name),
                CsMeta {
                    stale_at: far_future(),
                },
            ));
            debug_assert_eq!(result, InsertResult::Replaced);
            result
        });
    });
}

// ── insert_new ────────────────────────────────────────────────────────────────
// Unique name per iteration — fresh insert + NameTrie update + LRU eviction.

fn bench_insert_new(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    g.throughput(Throughput::Elements(1));
    g.bench_function("insert_new", |b| {
        b.iter(|| {
            let i = COUNTER.fetch_add(1, Ordering::Relaxed);
            let name: Arc<Name> = Arc::new(format!("/ndn/new/{i}").parse().unwrap());
            let wire = data_wire(&name);
            let result = rt.block_on(cs.insert(
                wire,
                name,
                CsMeta {
                    stale_at: far_future(),
                },
            ));
            debug_assert_eq!(result, InsertResult::Inserted);
            result
        });
    });
}

// ── evict ─────────────────────────────────────────────────────────────────────

fn bench_evict(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    g.throughput(Throughput::Elements(1));
    g.bench_function("evict", |b| {
        b.iter_batched(
            || {
                let name: Arc<Name> = Arc::new("/ndn/evict".parse().unwrap());
                rt.block_on(cs.insert(
                    data_wire(&name),
                    name,
                    CsMeta {
                        stale_at: far_future(),
                    },
                ));
                let evict_name: Name = "/ndn/evict".parse().unwrap();
                evict_name
            },
            |n| {
                let evicted = rt.block_on(cs.evict(&n));
                debug_assert!(evicted);
                evicted
            },
            BatchSize::SmallInput,
        );
    });
}

// ── evict_prefix ──────────────────────────────────────────────────────────────
// 100 entries under /a/b; measures NameTrie descendants walk.

fn bench_evict_prefix(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    let rt = rt();
    let cs = LruCs::new(1 << 20);
    let prefix: Name = "/a/b".parse().unwrap();
    g.throughput(Throughput::Elements(100));
    g.bench_function("evict_prefix", |b| {
        b.iter_batched(
            || {
                for i in 0..100u64 {
                    let name: Arc<Name> = Arc::new(format!("/a/b/{i}").parse().unwrap());
                    rt.block_on(cs.insert(
                        data_wire(&name),
                        name,
                        CsMeta {
                            stale_at: far_future(),
                        },
                    ));
                }
            },
            |_| rt.block_on(cs.evict_prefix(&prefix, None)),
            BatchSize::SmallInput,
        );
    });
}

// ── top-level group ───────────────────────────────────────────────────────────

fn bench_lru(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru");
    bench_get_miss_empty(&mut group);
    bench_get_miss_populated(&mut group);
    bench_get_hit(&mut group);
    bench_get_can_be_prefix(&mut group);
    bench_insert_replace(&mut group);
    bench_insert_new(&mut group);
    bench_evict(&mut group);
    bench_evict_prefix(&mut group);
    group.finish();
}

criterion_group!(benches, bench_lru);
criterion_main!(benches);
