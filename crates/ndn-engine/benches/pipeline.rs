//! Benchmarks for the NDN forwarding pipeline hot path.
//!
//! Measures individual stage costs and full pipeline latency for Interest and
//! Data packets at realistic name lengths (4 and 8 components).
//!
//! Run:
//! ```text
//! cargo bench -p ndn-engine
//! ```

use std::sync::Arc;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use ndn_packet::{Name, NameComponent};
use ndn_packet::encode::{encode_data_unsigned, encode_interest};
use ndn_pipeline::{Action, DecodedPacket, PacketContext};
use ndn_store::{CsMeta, ContentStore, LruCs, Pit, PitToken};
use ndn_transport::FaceId;

use ndn_engine::Fib;
use ndn_engine::stages::{
    CsInsertStage, CsLookupStage, PitCheckStage, PitMatchStage, TlvDecodeStage,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn name(components: &[&[u8]]) -> Name {
    Name::from_components(
        components
            .iter()
            .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
    )
}

/// Build realistic Interest wire bytes with N name components.
fn interest_wire(n_components: usize) -> Bytes {
    let comps: Vec<Vec<u8>> = (0..n_components)
        .map(|i| format!("comp-{i:04}").into_bytes())
        .collect();
    let comp_refs: Vec<&[u8]> = comps.iter().map(|c| c.as_slice()).collect();
    let n = name(&comp_refs);
    encode_interest(&n, None)
}

/// Build realistic Data wire bytes with N name components and ~100 B content.
fn data_wire(n_components: usize) -> Bytes {
    let comps: Vec<Vec<u8>> = (0..n_components)
        .map(|i| format!("comp-{i:04}").into_bytes())
        .collect();
    let comp_refs: Vec<&[u8]> = comps.iter().map(|c| c.as_slice()).collect();
    let n = name(&comp_refs);
    encode_data_unsigned(&n, &[0xAA; 100])
}

/// Extract decoded name from wire Interest bytes.
fn decoded_name(wire: &Bytes) -> Arc<Name> {
    ndn_packet::Interest::decode(wire.clone()).unwrap().name.clone()
}

fn ctx(raw: Bytes) -> PacketContext {
    PacketContext::new(raw, FaceId(1), 0)
}

fn current_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ─── TLV Decode ──────────────────────────────────────────────────────────────

fn bench_decode_interest(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode/interest");
    for &n in &[4, 8] {
        let wire = interest_wire(n);
        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &wire, |b, wire| {
            let stage = TlvDecodeStage;
            b.iter(|| {
                let action = stage.process(ctx(wire.clone()));
                debug_assert!(matches!(action, Action::Continue(_)));
            });
        });
    }
    group.finish();
}

fn bench_decode_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode/data");
    for &n in &[4, 8] {
        let wire = data_wire(n);
        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &wire, |b, wire| {
            let stage = TlvDecodeStage;
            b.iter(|| {
                let action = stage.process(ctx(wire.clone()));
                debug_assert!(matches!(action, Action::Continue(_)));
            });
        });
    }
    group.finish();
}

// ─── CS Lookup ───────────────────────────────────────────────────────────────

fn bench_cs_lookup(c: &mut Criterion) {
    let rt = current_thread_rt();
    let cs = Arc::new(LruCs::new(64 * 1024 * 1024));
    let wire = data_wire(4);
    let n = decoded_name(&interest_wire(4));

    // Pre-populate for hit benchmark.
    rt.block_on(cs.insert(
        wire.clone(),
        n.clone(),
        CsMeta { stale_at: u64::MAX },
    ));

    let stage = CsLookupStage { cs: Arc::clone(&cs) };

    let mut group = c.benchmark_group("cs");

    // CS hit
    group.bench_function("hit", |b| {
        let interest_bytes = interest_wire(4);
        b.iter(|| {
            rt.block_on(async {
                let mut c = ctx(interest_bytes.clone());
                // Pre-decode so CS lookup works.
                let interest = ndn_packet::Interest::decode(interest_bytes.clone()).unwrap();
                c.name = Some(interest.name.clone());
                c.packet = DecodedPacket::Interest(Box::new(interest));
                let action = stage.process(c).await;
                debug_assert!(matches!(action, Action::Satisfy(_)));
            });
        });
    });

    // CS miss
    group.bench_function("miss", |b| {
        let miss_wire = interest_wire(4);
        let miss_name = name(&[b"no", b"such", b"name", b"here"]);
        b.iter(|| {
            rt.block_on(async {
                let mut c = ctx(miss_wire.clone());
                let interest = ndn_packet::Interest::new(miss_name.clone());
                c.name = Some(Arc::new(miss_name.clone()));
                c.packet = DecodedPacket::Interest(Box::new(interest));
                let action = stage.process(c).await;
                debug_assert!(matches!(action, Action::Continue(_)));
            });
        });
    });

    group.finish();
}

// ─── PIT Check ───────────────────────────────────────────────────────────────

fn bench_pit_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("pit");

    // New entry — fresh PIT each iteration.
    group.bench_function("new_entry", |b| {
        let wire = interest_wire(4);
        b.iter(|| {
            let pit = Arc::new(Pit::new());
            let stage = PitCheckStage { pit };
            let mut c = ctx(wire.clone());
            let interest = ndn_packet::Interest::decode(wire.clone()).unwrap();
            c.name = Some(interest.name.clone());
            c.packet = DecodedPacket::Interest(Box::new(interest));
            let action = stage.process(c);
            debug_assert!(matches!(action, Action::Continue(_)));
        });
    });

    // Aggregation — second Interest with different nonce hits existing entry.
    group.bench_function("aggregate", |b| {
        let pit = Arc::new(Pit::new());
        let stage = PitCheckStage { pit: Arc::clone(&pit) };

        // Seed the PIT with one entry.
        let wire = interest_wire(4);
        {
            let mut c = ctx(wire.clone());
            let interest = ndn_packet::Interest::decode(wire.clone()).unwrap();
            c.name = Some(interest.name.clone());
            c.packet = DecodedPacket::Interest(Box::new(interest));
            stage.process(c);
        }

        // Benchmark aggregation: different nonce, same name.
        b.iter(|| {
            let wire2 = interest_wire(4); // new wire = new nonce
            let mut c = ctx(wire2.clone());
            let interest = ndn_packet::Interest::decode(wire2).unwrap();
            c.name = Some(interest.name.clone());
            c.packet = DecodedPacket::Interest(Box::new(interest));
            let action = stage.process(c);
            debug_assert!(matches!(action, Action::Drop(_)));
        });
    });

    group.finish();
}

// ─── FIB LPM ─────────────────────────────────────────────────────────────────

fn bench_fib_lpm(c: &mut Criterion) {
    let mut group = c.benchmark_group("fib/lpm");

    for &n_routes in &[10, 100, 1000] {
        let fib = Fib::new();

        // Populate with N routes of varying prefix lengths.
        for i in 0..n_routes {
            let prefix = name(&[
                format!("prefix-{}", i / 10).as_bytes(),
                format!("sub-{i}").as_bytes(),
            ]);
            fib.add_nexthop(&prefix, FaceId(((i % 10) + 2) as u32), 10);
        }

        // Lookup name that matches a mid-range route.
        let lookup = name(&[b"prefix-5", b"sub-50", b"extra", b"component"]);

        group.bench_with_input(
            BenchmarkId::from_parameter(n_routes),
            &lookup,
            |b, lookup| {
                b.iter(|| {
                    let _ = fib.lpm(lookup);
                });
            },
        );
    }

    group.finish();
}

// ─── PIT Match (Data path) ───────────────────────────────────────────────────

fn bench_pit_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("pit_match");

    group.bench_function("hit", |b| {
        let interest_bytes = interest_wire(4);
        let data_bytes = data_wire(4);

        b.iter(|| {
            // Fresh PIT each iteration, seed then match.
            let pit = Arc::new(Pit::new());
            let interest = ndn_packet::Interest::decode(interest_bytes.clone()).unwrap();
            let token = PitToken::from_interest_full(
                &interest.name,
                Some(interest.selectors()),
                interest.forwarding_hint(),
            );
            let mut entry = ndn_store::PitEntry::new(
                interest.name.clone(),
                Some(interest.selectors().clone()),
                0,
                4000,
            );
            entry.add_in_record(1, interest.nonce().unwrap_or(0), u64::MAX);
            pit.insert(token, entry);

            let stage = PitMatchStage { pit };
            let mut c = ctx(data_bytes.clone());
            let data = ndn_packet::Data::decode(data_bytes.clone()).unwrap();
            c.name = Some(data.name.clone());
            c.packet = DecodedPacket::Data(Box::new(data));
            let action = stage.process(c);
            debug_assert!(matches!(action, Action::Continue(_)));
        });
    });

    group.bench_function("miss", |b| {
        let data_bytes = data_wire(4);
        let pit = Arc::new(Pit::new());
        let stage = PitMatchStage { pit };

        b.iter(|| {
            let mut c = ctx(data_bytes.clone());
            let data = ndn_packet::Data::decode(data_bytes.clone()).unwrap();
            c.name = Some(data.name.clone());
            c.packet = DecodedPacket::Data(Box::new(data));
            let action = stage.process(c);
            debug_assert!(matches!(action, Action::Drop(_)));
        });
    });

    group.finish();
}

// ─── CS Insert ───────────────────────────────────────────────────────────────

fn bench_cs_insert(c: &mut Criterion) {
    let rt = current_thread_rt();

    let mut group = c.benchmark_group("cs_insert");

    group.bench_function("insert", |b| {
        let cs = Arc::new(LruCs::new(64 * 1024 * 1024));
        let stage = CsInsertStage {
            cs: Arc::clone(&cs),
            admission: Arc::new(ndn_store::AdmitAllPolicy),
        };
        let wire = data_wire(4);

        b.iter(|| {
            rt.block_on(async {
                let mut c = ctx(wire.clone());
                let data = ndn_packet::Data::decode(wire.clone()).unwrap();
                c.name = Some(data.name.clone());
                c.packet = DecodedPacket::Data(Box::new(data));
                stage.process(c).await;
            });
        });
    });

    group.finish();
}

// ─── Full Interest Pipeline (decode → CS miss → PIT new → strategy Nack) ────

fn bench_interest_pipeline(c: &mut Criterion) {
    let rt = current_thread_rt();
    let mut group = c.benchmark_group("interest_pipeline");

    for &n in &[4, 8] {
        let wire = interest_wire(n);
        group.throughput(Throughput::Bytes(wire.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("no_route", n),
            &wire,
            |b, wire| {
                let cs = Arc::new(LruCs::new(64 * 1024 * 1024));
                let pit = Arc::new(Pit::new());

                let decode = TlvDecodeStage;
                let cs_lookup = CsLookupStage { cs: Arc::clone(&cs) };
                let pit_check = PitCheckStage { pit: Arc::clone(&pit) };

                b.iter(|| {
                    rt.block_on(async {
                        // Fresh PIT per iteration to always get new-entry path.
                        pit.clear();

                        let c = ctx(wire.clone());

                        // Decode
                        let c = match decode.process(c) {
                            Action::Continue(c) => c,
                            _ => panic!("decode failed"),
                        };

                        // CS lookup (miss)
                        let c = match cs_lookup.process(c).await {
                            Action::Continue(c) => c,
                            _ => panic!("unexpected CS hit"),
                        };

                        // PIT check (new entry)
                        let _c = match pit_check.process(c) {
                            Action::Continue(c) => c,
                            _ => panic!("unexpected PIT result"),
                        };

                        // Strategy would run here but requires full wiring;
                        // we stop at PIT to isolate pipeline overhead.
                    });
                });
            },
        );
    }

    group.finish();
}

// ─── Full Interest Pipeline with CS Hit ──────────────────────────────────────

fn bench_interest_cs_hit(c: &mut Criterion) {
    let rt = current_thread_rt();
    let cs = Arc::new(LruCs::new(64 * 1024 * 1024));

    // Pre-populate CS with data matching the Interest.
    let data_bytes = data_wire(4);
    let data = ndn_packet::Data::decode(data_bytes.clone()).unwrap();
    rt.block_on(cs.insert(
        data_bytes,
        data.name.clone(),
        CsMeta { stale_at: u64::MAX },
    ));

    let decode = TlvDecodeStage;
    let cs_lookup = CsLookupStage { cs: Arc::clone(&cs) };

    let wire = interest_wire(4);

    c.bench_function("interest_pipeline/cs_hit", |b| {
        b.iter(|| {
            rt.block_on(async {
                let c = ctx(wire.clone());
                let c = match decode.process(c) {
                    Action::Continue(c) => c,
                    _ => panic!("decode failed"),
                };
                let action = cs_lookup.process(c).await;
                debug_assert!(matches!(action, Action::Satisfy(_)));
            });
        });
    });
}

// ─── Full Data Pipeline (decode → PIT match → CS insert) ────────────────────

fn bench_data_pipeline(c: &mut Criterion) {
    let rt = current_thread_rt();
    let mut group = c.benchmark_group("data_pipeline");

    for &n in &[4, 8] {
        let interest_bytes = interest_wire(n);
        let data_bytes = data_wire(n);

        group.throughput(Throughput::Bytes(data_bytes.len() as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &data_bytes,
            |b, data_bytes| {
                let cs = Arc::new(LruCs::new(64 * 1024 * 1024));
                let pit = Arc::new(Pit::new());
                let decode = TlvDecodeStage;
                let pit_match = PitMatchStage { pit: Arc::clone(&pit) };
                let cs_insert = CsInsertStage {
                    cs: Arc::clone(&cs),
                    admission: Arc::new(ndn_store::AdmitAllPolicy),
                };

                b.iter(|| {
                    rt.block_on(async {
                        // Seed PIT with matching Interest.
                        let interest = ndn_packet::Interest::decode(interest_bytes.clone()).unwrap();
                        let token = PitToken::from_interest_full(
                            &interest.name,
                            Some(interest.selectors()),
                            interest.forwarding_hint(),
                        );
                        let mut entry = ndn_store::PitEntry::new(
                            interest.name.clone(),
                            Some(interest.selectors().clone()),
                            0,
                            4000,
                        );
                        entry.add_in_record(1, interest.nonce().unwrap_or(0), u64::MAX);
                        pit.insert(token, entry);

                        // Decode Data
                        let c = ctx(data_bytes.clone());
                        let c = match decode.process(c) {
                            Action::Continue(c) => c,
                            _ => panic!("decode failed"),
                        };

                        // PIT match
                        let c = match pit_match.process(c) {
                            Action::Continue(c) => c,
                            _ => panic!("PIT miss"),
                        };

                        // CS insert
                        cs_insert.process(c).await;
                    });
                });
            },
        );
    }

    group.finish();
}

// ─── Throughput: batch of Interests through decode ───────────────────────────

fn bench_decode_throughput(c: &mut Criterion) {
    const N: u64 = 1000;
    let mut group = c.benchmark_group("decode_throughput");

    for &n_comp in &[4, 8] {
        let wire = interest_wire(n_comp);
        group.throughput(Throughput::Elements(N));

        group.bench_with_input(
            BenchmarkId::from_parameter(n_comp),
            &wire,
            |b, wire| {
                let stage = TlvDecodeStage;
                b.iter(|| {
                    for _ in 0..N {
                        let action = stage.process(ctx(wire.clone()));
                        debug_assert!(matches!(action, Action::Continue(_)));
                    }
                });
            },
        );
    }

    group.finish();
}

// ─── Registration ────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_decode_interest,
    bench_decode_data,
    bench_cs_lookup,
    bench_pit_check,
    bench_fib_lpm,
    bench_pit_match,
    bench_cs_insert,
    bench_interest_pipeline,
    bench_interest_cs_hit,
    bench_data_pipeline,
    bench_decode_throughput,
);
criterion_main!(benches);
