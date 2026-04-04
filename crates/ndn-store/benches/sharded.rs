use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::{Name, NameComponent};
use ndn_store::{ContentStore, CsMeta, LruCs, ShardedCs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Build a ShardedCs<LruCs> with `shard_count` shards, total capacity ~1 MB.
fn make_sharded(shard_count: usize) -> ShardedCs<LruCs> {
    let shard_bytes = (1 << 20) / shard_count;
    ShardedCs::new((0..shard_count).map(|_| LruCs::new(shard_bytes)).collect())
}

fn bench_sharded(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("sharded");

    for shard_count in [1usize, 4, 8, 16] {
        let cs = make_sharded(shard_count);

        // Pre-insert hit entry.
        let hit_name: Arc<Name> = Arc::new("/ndn/sharded/hit".parse().unwrap());
        rt.block_on(cs.insert(
            data_wire(&hit_name),
            Arc::clone(&hit_name),
            CsMeta { stale_at: far_future() },
        ));
        let hit_interest = interest_for("/ndn/sharded/hit");

        group.throughput(Throughput::Elements(1));

        group.bench_with_input(
            BenchmarkId::new("get_hit", shard_count),
            &shard_count,
            |b, _| {
                b.iter(|| {
                    let result = rt.block_on(cs.get(&hit_interest));
                    debug_assert!(result.is_some());
                    result
                });
            },
        );

        static CTR: AtomicU64 = AtomicU64::new(0);
        group.bench_with_input(
            BenchmarkId::new("insert", shard_count),
            &shard_count,
            |b, _| {
                b.iter(|| {
                    let i = CTR.fetch_add(1, Ordering::Relaxed);
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

criterion_group!(benches, bench_sharded);
criterion_main!(benches);
