use bytes::Bytes;
use criterion::{
    BatchSize, BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main,
};
use ndn_packet::Name;
use ndn_store::{ContentStore, CsMeta, InsertResult, LruCs};
use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn data_wire(name: &Name) -> Bytes {
    Bytes::copy_from_slice(name.to_string().as_bytes())
}

/// Lookup time: entries are stamped `far_future()`, so any earlier instant.
const NOW: u64 = 0;

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
            let result = rt.block_on(cs.get(&interest, NOW));
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
            let result = rt.block_on(cs.get(&interest, NOW));
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
            let result = rt.block_on(cs.get(&interest, NOW));
            debug_assert!(result.is_some());
            result
        });
    });
}

// ── get_can_be_prefix ─────────────────────────────────────────────────────────
// FreshIndex freshest-descendant path vs. LruCache exact-match path.

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
            let result = rt.block_on(cs.get(&interest, NOW));
            debug_assert!(result.is_some());
            result
        });
    });
}

// ── get_latest_of_13k_versions ────────────────────────────────────────────────
// CanBePrefix+MustBeFresh against one prefix holding 13 000 versions of which
// only the newest is fresh — the telemetry shape of nfd-divergence-findings
// Round 14. `FreshIndex` answers in one walk down the Interest name, so this
// should cost about what `get_can_be_prefix` does, not a 13 000-entry scan.
// Measured 2026-09-22 (M4 Pro, `--quick`): 151 ns, against 113 ns for
// `get_can_be_prefix` over a single descendant.

fn bench_get_latest_of_many_versions(g: &mut BenchmarkGroup<criterion::measurement::WallTime>) {
    const VERSIONS: u64 = 13_000;
    let rt = rt();
    let cs = LruCs::new(64 << 20);
    for v in 1..=VERSIONS {
        let name: Arc<Name> =
            Arc::new(format!("/muas/telemetry/live/v={v}/seg=0").parse().unwrap());
        // Looked up at VERSIONS - 1 below: only v = VERSIONS is still fresh.
        rt.block_on(cs.insert(data_wire(&name), Arc::clone(&name), CsMeta { stale_at: v }));
    }
    use ndn_packet::encode::InterestBuilder;
    let wire = InterestBuilder::new("/muas/telemetry/live")
        .can_be_prefix()
        .must_be_fresh()
        .build();
    let interest = ndn_packet::Interest::decode(wire).unwrap();
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_latest_of_13k_versions", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&interest, VERSIONS - 1));
            debug_assert!(result.is_some());
            result
        });
    });
}

// ── insert_replace ────────────────────────────────────────────────────────────
// Same name every iteration — steady-state replacement (re-ranks the index
// entry; allocates no new index nodes).

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
    bench_get_latest_of_many_versions(&mut group);
    bench_insert_replace(&mut group);
    bench_insert_new(&mut group);
    bench_evict(&mut group);
    bench_evict_prefix(&mut group);
    group.finish();
}

criterion_group!(benches, bench_lru);
criterion_main!(benches);
