use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::{Interest, Name, NameComponent};
use ndn_store::{ContentStore, CsMeta, InsertResult, LruCs, ShardedCs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn data_wire(name: &Name) -> Bytes {
    // Minimal wire-format Data: just a recognizable opaque byte sequence.
    // Content store only stores and returns the bytes; it doesn't decode them.
    let label = name.to_string();
    Bytes::copy_from_slice(label.as_bytes())
}

fn far_future() -> u64 {
    u64::MAX
}

/// Build an exact-match Interest for `name`.
fn interest_for(name_s: &str) -> Interest {
    use ndn_packet::encode::InterestBuilder;
    let wire = InterestBuilder::new(name_s).build();
    Interest::decode(wire).unwrap()
}

// ── LruCs benchmarks ──────────────────────────────────────────────────────

fn bench_lru(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("lru");

    // ── get_miss_empty ─────────────────────────────────────────────────────
    // Fast path: atomic load only, no lock acquired.
    {
        let cs = LruCs::new(1 << 20);
        let interest = interest_for("/ndn/data");
        group.throughput(Throughput::Elements(1));
        group.bench_function("get_miss_empty", |b| {
            b.iter(|| {
                let result = rt.block_on(cs.get(&interest));
                debug_assert!(result.is_none());
                result
            });
        });
    }

    // ── get_miss_populated ─────────────────────────────────────────────────
    // Cache is full of unrelated names; exercises full lock+LRU traversal miss.
    {
        let cs = LruCs::new(1 << 20);
        for i in 0..200u64 {
            let name: Arc<Name> = Arc::new(format!("/a/populate/{i}").parse().unwrap());
            let wire = data_wire(&name);
            rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }));
        }
        let interest = interest_for("/ndn/not/cached");
        group.throughput(Throughput::Elements(1));
        group.bench_function("get_miss_populated", |b| {
            b.iter(|| {
                let result = rt.block_on(cs.get(&interest));
                debug_assert!(result.is_none());
                result
            });
        });
    }

    // ── get_hit ────────────────────────────────────────────────────────────
    {
        let cs = LruCs::new(1 << 20);
        let name: Arc<Name> = Arc::new("/ndn/hit".parse().unwrap());
        let wire = data_wire(&name);
        rt.block_on(cs.insert(wire, Arc::clone(&name), CsMeta { stale_at: far_future() }));
        let interest = interest_for("/ndn/hit");
        group.throughput(Throughput::Elements(1));
        group.bench_function("get_hit", |b| {
            b.iter(|| {
                let result = rt.block_on(cs.get(&interest));
                debug_assert!(result.is_some());
                result
            });
        });
    }

    // ── get_can_be_prefix ──────────────────────────────────────────────────
    // Exercises the NameTrie first_descendant path (different from exact-match).
    {
        let cs = LruCs::new(1 << 20);
        // Insert a name one component longer than the prefix we'll query with.
        let name: Arc<Name> = Arc::new("/ndn/prefix/data".parse().unwrap());
        let wire = data_wire(&name);
        rt.block_on(cs.insert(wire, Arc::clone(&name), CsMeta { stale_at: far_future() }));
        // CanBePrefix Interest at /ndn/prefix
        use ndn_packet::encode::InterestBuilder;
        let wire = InterestBuilder::new("/ndn/prefix")
            .can_be_prefix()
            .build();
        let interest = Interest::decode(wire).unwrap();
        group.throughput(Throughput::Elements(1));
        group.bench_function("get_can_be_prefix", |b| {
            b.iter(|| {
                let result = rt.block_on(cs.get(&interest));
                debug_assert!(result.is_some());
                result
            });
        });
    }

    // ── insert_replace ─────────────────────────────────────────────────────
    // Same name every iteration — steady-state replacement cost (no trie update).
    {
        let cs = LruCs::new(1 << 20);
        let name: Arc<Name> = Arc::new("/ndn/replace".parse().unwrap());
        // Pre-insert once so every bench iteration is a Replaced call.
        let wire = data_wire(&name);
        rt.block_on(cs.insert(wire, Arc::clone(&name), CsMeta { stale_at: far_future() }));
        group.throughput(Throughput::Elements(1));
        group.bench_function("insert_replace", |b| {
            b.iter(|| {
                let wire = data_wire(&name);
                let result = rt.block_on(cs.insert(
                    wire,
                    Arc::clone(&name),
                    CsMeta { stale_at: far_future() },
                ));
                debug_assert_eq!(result, InsertResult::Replaced);
                result
            });
        });
    }

    // ── insert_new ─────────────────────────────────────────────────────────
    // Unique name per iteration — measures fresh insert + NameTrie update + LRU eviction.
    {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let cs = LruCs::new(1 << 20);
        group.throughput(Throughput::Elements(1));
        group.bench_function("insert_new", |b| {
            b.iter(|| {
                let i = COUNTER.fetch_add(1, Ordering::Relaxed);
                let name: Arc<Name> = Arc::new(format!("/ndn/new/{i}").parse().unwrap());
                let wire = data_wire(&name);
                let result = rt.block_on(cs.insert(
                    wire,
                    name,
                    CsMeta { stale_at: far_future() },
                ));
                debug_assert_eq!(result, InsertResult::Inserted);
                result
            });
        });
    }

    // ── evict ──────────────────────────────────────────────────────────────
    {
        let cs = LruCs::new(1 << 20);
        group.throughput(Throughput::Elements(1));
        group.bench_function("evict", |b| {
            b.iter_batched(
                || {
                    // Setup: insert the entry to be evicted.
                    let name: Arc<Name> = Arc::new("/ndn/evict".parse().unwrap());
                    let wire = data_wire(&name);
                    rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }));
                    let evict_name: Name = "/ndn/evict".parse().unwrap();
                    evict_name
                },
                |n| {
                    let evicted = rt.block_on(cs.evict(&n));
                    debug_assert!(evicted);
                    evicted
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // ── evict_prefix ───────────────────────────────────────────────────────
    // 100 entries under /a/b; evict_prefix walks NameTrie descendants.
    {
        let cs = LruCs::new(1 << 20);
        // Pre-insert 100 entries permanently (setup, not timed).
        for i in 0..100u64 {
            let name: Arc<Name> = Arc::new(format!("/a/b/{i}").parse().unwrap());
            let wire = data_wire(&name);
            rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }));
        }
        let prefix: Name = "/a/b".parse().unwrap();
        group.throughput(Throughput::Elements(100));
        group.bench_function("evict_prefix", |b| {
            b.iter_batched(
                || {
                    // Re-insert before each iteration.
                    for i in 0..100u64 {
                        let name: Arc<Name> = Arc::new(format!("/a/b/{i}").parse().unwrap());
                        let wire = data_wire(&name);
                        rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }));
                    }
                },
                |_| rt.block_on(cs.evict_prefix(&prefix, None)),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ── ShardedCs benchmarks ──────────────────────────────────────────────────

fn bench_sharded(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("sharded");

    for shard_count in [1usize, 4, 8, 16] {
        let shard_bytes = (1 << 20) / shard_count;
        let cs = ShardedCs::new(
            (0..shard_count)
                .map(|_| LruCs::new(shard_bytes))
                .collect(),
        );
        // Pre-insert a known name for get_hit.
        let hit_name: Arc<Name> = Arc::new("/ndn/sharded/hit".parse().unwrap());
        rt.block_on(cs.insert(
            data_wire(&hit_name),
            Arc::clone(&hit_name),
            CsMeta { stale_at: far_future() },
        ));
        let interest = interest_for("/ndn/sharded/hit");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("get_hit", format!("shards={shard_count}")),
            &shard_count,
            |b, _| {
                b.iter(|| {
                    let result = rt.block_on(cs.get(&interest));
                    debug_assert!(result.is_some());
                    result
                });
            },
        );

        static SHARDED_CTR: AtomicU64 = AtomicU64::new(0);
        group.bench_with_input(
            BenchmarkId::new("insert", format!("shards={shard_count}")),
            &shard_count,
            |b, _| {
                b.iter(|| {
                    let i = SHARDED_CTR.fetch_add(1, Ordering::Relaxed);
                    let name: Arc<Name> =
                        Arc::new(format!("/ndn/sharded/new/{i}").parse().unwrap());
                    let wire = data_wire(&name);
                    rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }))
                });
            },
        );
    }

    group.finish();
}

// ── FjallCs benchmarks ────────────────────────────────────────────────────

fn bench_fjall(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let cs = ndn_store::FjallCs::open(dir.path(), 1 << 24).unwrap();

    let mut group = c.benchmark_group("fjall");

    // Pre-insert a hit entry.
    let hit_name: Arc<Name> = Arc::new("/fjall/hit".parse().unwrap());
    rt.block_on(cs.insert(
        data_wire(&hit_name),
        Arc::clone(&hit_name),
        CsMeta { stale_at: far_future() },
    ));
    let hit_interest = interest_for("/fjall/hit");
    let miss_interest = interest_for("/fjall/miss/not/cached");

    group.throughput(Throughput::Elements(1));

    group.bench_function("get_hit", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&hit_interest));
            debug_assert!(result.is_some());
            result
        });
    });

    group.bench_function("get_miss", |b| {
        b.iter(|| {
            let result = rt.block_on(cs.get(&miss_interest));
            debug_assert!(result.is_none());
            result
        });
    });

    static FJALL_CTR: AtomicU64 = AtomicU64::new(0);
    group.bench_function("insert", |b| {
        b.iter(|| {
            let i = FJALL_CTR.fetch_add(1, Ordering::Relaxed);
            let name: Arc<Name> = Arc::new(format!("/fjall/new/{i}").parse().unwrap());
            let wire = data_wire(&name);
            rt.block_on(cs.insert(wire, name, CsMeta { stale_at: far_future() }))
        });
    });

    group.finish();

    // Keep tempdir alive until after group.finish().
    drop(dir);
}

criterion_group!(benches, bench_lru, bench_sharded, bench_fjall);
criterion_main!(benches);
