use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::Name;
use ndn_store::{ContentStore, CsMeta, FjallCs};
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

/// Small byte budget: ~8 KB means ~400-500 entries of ~15 bytes each.
/// Reaching capacity requires only a few hundred inserts, so the warmup
/// phase transitions to steady-state (evict-one-insert-one) very quickly
/// with no significant LSM compaction pressure.
const MAX_BYTES: usize = 8 * 1024;

fn bench_fjall(c: &mut Criterion) {
    let rt = rt();

    // Each bench variant uses its own tempdir so they don't interfere.
    // get_hit / get_miss share one store; insert has its own pre-filled store.

    // ── get_hit / get_miss ────────────────────────────────────────────────────
    let dir_rw = tempfile::tempdir().unwrap();
    let cs_rw = FjallCs::open(dir_rw.path(), MAX_BYTES).unwrap();

    let hit_name: Arc<Name> = Arc::new("/fjall/hit".parse().unwrap());
    rt.block_on(cs_rw.insert(
        data_wire(&hit_name),
        Arc::clone(&hit_name),
        CsMeta {
            stale_at: far_future(),
        },
    ));
    let hit_interest = interest_for("/fjall/hit");
    let miss_interest = interest_for("/fjall/miss/not/cached");

    let mut group = c.benchmark_group("fjall");
    group.throughput(Throughput::Elements(1));

    group.bench_function("get_hit", |b| {
        b.iter(|| {
            let result = rt.block_on(cs_rw.get(&hit_interest, NOW));
            debug_assert!(result.is_some());
            result
        });
    });

    group.bench_function("get_miss", |b| {
        b.iter(|| {
            let result = rt.block_on(cs_rw.get(&miss_interest, NOW));
            debug_assert!(result.is_none());
            result
        });
    });

    // ── get_latest_of_1000_versions ──────────────────────────────────────────
    //
    // CanBePrefix+MustBeFresh over 1000 cached versions of one prefix, only
    // the newest fresh. FjallCs keeps no in-memory index, so each lookup scans
    // every version's `stale_at`: this grows linearly with the version count,
    // unlike LruCs's `get_latest_of_13k_versions`.
    // Measured 2026-09-22 (M4 Pro, `--quick`): 64 µs, ~64 ns per version, so
    // ~0.8 ms per lookup at the ~13k versions of nfd-divergence-findings
    // Round 14 (LruCs: ~150 ns).
    const VERSIONS: u64 = 1_000;
    let dir_versions = tempfile::tempdir().unwrap();
    let cs_versions = FjallCs::open(dir_versions.path(), 1 << 20).unwrap();
    for v in 1..=VERSIONS {
        let name: Arc<Name> = Arc::new(format!("/fjall/live/v={v}/seg=0").parse().unwrap());
        // Looked up at VERSIONS - 1 below: only v = VERSIONS is still fresh.
        rt.block_on(cs_versions.insert(
            data_wire(&name),
            Arc::clone(&name),
            CsMeta { stale_at: v },
        ));
    }
    let latest = {
        use ndn_packet::encode::InterestBuilder;
        let wire = InterestBuilder::new("/fjall/live")
            .can_be_prefix()
            .must_be_fresh()
            .build();
        ndn_packet::Interest::decode(wire).unwrap()
    };
    group.bench_function("get_latest_of_1000_versions", |b| {
        b.iter(|| {
            let result = rt.block_on(cs_versions.get(&latest, VERSIONS - 1));
            debug_assert!(result.is_some());
            result
        });
    });

    // ── insert — pre-filled to capacity ──────────────────────────────────────
    //
    // Pre-filling ensures the store is at capacity before the bench begins,
    // so every warmup and measurement iteration is in the same steady state:
    // evict one old entry, insert one new entry.  No compaction surprises
    // during warmup.
    let dir_ins = tempfile::tempdir().unwrap();
    let cs_ins = FjallCs::open(dir_ins.path(), MAX_BYTES).unwrap();

    // Insert enough entries to fill the store.  Entries are ~15 bytes each
    // so MAX_BYTES / 15 ≈ 546 entries.  Inserting 1 000 ensures the store
    // is saturated regardless of exact entry size.
    for i in 0..1_000u64 {
        let name: Arc<Name> = Arc::new(format!("/fjall/seed/{i}").parse().unwrap());
        let wire = data_wire(&name);
        rt.block_on(cs_ins.insert(
            wire,
            name,
            CsMeta {
                stale_at: far_future(),
            },
        ));
    }

    static CTR: AtomicU64 = AtomicU64::new(0);
    group.bench_function("insert", |b| {
        b.iter(|| {
            let i = CTR.fetch_add(1, Ordering::Relaxed);
            // Names outside the seed range → always new entries, always evict.
            let name: Arc<Name> = Arc::new(format!("/fjall/new/{i}").parse().unwrap());
            let wire = data_wire(&name);
            rt.block_on(cs_ins.insert(
                wire,
                name,
                CsMeta {
                    stale_at: far_future(),
                },
            ))
        });
    });

    group.finish();

    // FjallCs (and its background threads) must be dropped before the
    // TempDir so the database files are closed before the directory is deleted.
    drop(cs_ins);
    drop(cs_rw);
    drop(dir_ins);
    drop(dir_rw);
}

criterion_group!(benches, bench_fjall);
criterion_main!(benches);
