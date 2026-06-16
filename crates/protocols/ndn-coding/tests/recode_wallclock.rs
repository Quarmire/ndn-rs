//! Wall-clock live-stack benchmark.
//!
//! Times recovery of a generation through the **real** `ForwarderEngine`,
//! both ways, over fresh names each iteration (so nothing is served from the
//! Content Store — every generation is processed cold):
//!
//! - **recode**: a `RecoderFace` mints K fresh combinations; the consumer
//!   decodes (GF(2^8) RREF) + verify-on-decode.
//! - **plain**: an `ndn-app` `Producer` serves K plain source segments; the
//!   consumer concatenates (no coding).
//!
//! In-process faces are lossless, so this is **not** a loss-recovery
//! comparison (that is the structural sim in `recode_throughput.rs`); it
//! measures the *processing cost* of coding on a clean live path — which the
//! doctrine predicts is pure overhead. The numbers are printed (run with
//! `--nocapture`); the test only asserts completion + a loose ceiling to catch
//! gross regressions, since wall-clock thresholds are environment-dependent.
//!
//! Gated by `f2-recode-face`.

#![cfg(feature = "f2-recode-face")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_transport::FaceId;

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, naming, row_hash,
};
use ndn_coding::recode_face;

const K: u16 = 16;
const SYMBOL: usize = 256; // 16 * 256 = 4 KiB generation
const ITERS: u64 = 20;

fn make_sources(seed: u64) -> Vec<Vec<u8>> {
    (0..K)
        .map(|s| {
            (0..SYMBOL)
                .map(|j| ((seed as usize * 7 + s as usize * 31 + j) & 0xff) as u8)
                .collect()
        })
        .collect()
}

fn descriptor(object: &Name, g: u64, sources: &[Vec<u8>]) -> GenerationDescriptor {
    GenerationDescriptor {
        generation_id: g,
        k: K,
        symbol_size: SYMBOL as u32,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    }
}

/// Time recovering `ITERS` fresh generations via the recoder through the engine.
async fn time_recode() -> Duration {
    let object: Name = "/bench/recode".parse().unwrap();
    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.unwrap();
    let handle = recode_face::attach(&engine, None);
    let mut consumer = Consumer::from_handle(chandle);

    let mut total = Duration::ZERO;
    for g in 0..ITERS {
        let sources = make_sources(g);
        let desc = descriptor(&object, g, &sources);
        let gen_prefix = naming::generation_name(&object, g);
        engine.fib().add_nexthop(&gen_prefix, handle.face_id, 0);
        handle.state.install_generation(desc.clone()).await;
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id: g,
                k: K,
                field: Field::Gf8,
                vector: CodingVector::unit(K, i as u16),
            };
            handle
                .state
                .feed(&object, g, &meta, Bytes::from(row.clone()))
                .await;
        }

        let start = Instant::now();
        let mut buf = GenerationBuffer::new(desc);
        let mut req = 0u64;
        while !buf.is_decodable() && req < 64 {
            let name = naming::request_name(&object, g, req);
            if let Ok(Ok(data)) =
                tokio::time::timeout(Duration::from_millis(500), consumer.fetch(name)).await
                && let Some(c) = data.content()
                && let Ok((meta, row)) = CodedMetadata::split(c)
            {
                buf.absorb(&meta, row).ok();
            }
            req += 1;
        }
        let payload = buf.decode().expect("recode recover");
        total += start.elapsed();
        assert_eq!(payload.len(), K as usize * SYMBOL);
    }
    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    total
}

/// Time fetching `ITERS` fresh plain-segmented objects (no coding).
async fn time_plain() -> Duration {
    let object: Name = "/bench/plain".parse().unwrap();
    let (cface, chandle) = InProcFace::new(FaceId(1), 256);
    let (pface, phandle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(cface)
        .face(pface)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(&object, FaceId(2), 0);

    // Pre-build every segment the producer will serve: <object>/v=<g>/<i>.
    let mut table: HashMap<Name, Bytes> = HashMap::new();
    for g in 0..ITERS {
        for (i, row) in make_sources(g).into_iter().enumerate() {
            let name = object
                .clone()
                .append(format!("v={g}"))
                .append(i.to_string());
            table.insert(name, Bytes::from(row));
        }
    }
    let table = Arc::new(table);
    let producer = Producer::from_handle(phandle, object.clone());
    let serve_table = Arc::clone(&table);
    let ptask = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let table = Arc::clone(&serve_table);
                async move {
                    let name = (*interest.name).clone();
                    if let Some(content) = table.get(&name) {
                        let wire = DataBuilder::new(name, content).build();
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            })
            .await
    });

    let mut consumer = Consumer::from_handle(chandle);
    let mut total = Duration::ZERO;
    for g in 0..ITERS {
        let start = Instant::now();
        let mut payload = Vec::with_capacity(K as usize * SYMBOL);
        for i in 0..K {
            let name = object
                .clone()
                .append(format!("v={g}"))
                .append(i.to_string());
            let data = tokio::time::timeout(Duration::from_millis(500), consumer.fetch(name))
                .await
                .expect("no timeout")
                .expect("plain fetch");
            payload.extend_from_slice(data.content().unwrap());
        }
        total += start.elapsed();
        assert_eq!(payload.len(), K as usize * SYMBOL);
    }
    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = ptask.await;
    total
}

#[tokio::test]
async fn wallclock_recode_vs_plain() {
    let recode = time_recode().await;
    let plain = time_plain().await;
    let gen_bytes = K as usize * SYMBOL;
    let mbps = |d: Duration| (gen_bytes as f64 * ITERS as f64) / d.as_secs_f64() / 1.0e6;
    let per_gen = |d: Duration| d.as_secs_f64() * 1.0e3 / ITERS as f64;

    eprintln!(
        "\nWall-clock live-stack (K={K}, {}-byte generation, {ITERS} fresh generations):",
        gen_bytes
    );
    eprintln!("  path     ms/gen    MB/s");
    eprintln!("  ------   ------   ------");
    eprintln!(
        "  recode   {:>6.3}   {:>6.1}",
        per_gen(recode),
        mbps(recode)
    );
    eprintln!("  plain    {:>6.3}   {:>6.1}", per_gen(plain), mbps(plain));
    eprintln!(
        "  → coding overhead on a clean path: {:.2}x (expected > 1; the doctrine\n    calls clean-path coding pure overhead — the win is multicast/lossy).",
        recode.as_secs_f64() / plain.as_secs_f64().max(1e-9)
    );

    // Sanity only (wall-clock thresholds are environment-dependent): both
    // complete and a generation recovers in well under the per-fetch timeout.
    assert!(
        per_gen(recode) < 100.0,
        "recode/g {:.3} ms unexpectedly high",
        per_gen(recode)
    );
    assert!(
        per_gen(plain) < 100.0,
        "plain/g {:.3} ms unexpectedly high",
        per_gen(plain)
    );
}
