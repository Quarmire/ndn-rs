//! End-to-end F1 round-trip through an in-process forwarder.
//!
//! Wires `ndn-coding`'s `segment_payload` + `CodedAssembler` to a
//! real `Producer` and `Consumer` against an embedded
//! `ForwarderEngine`. Mirrors the pattern in
//! `crates/ndn-app/tests/embedded.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_transport::FaceId;

use ndn_coding::policy::Field;
use ndn_coding::{
    CodedAssembler, CodedFetcher, CodedProducer, FecPolicy, FetchConfig, segment_payload,
};

/// Parse the last component of `name` as an ASCII-decimal segment
/// index, given that the first `prefix.len()` components match
/// `prefix`. Returns `None` for unexpected names.
fn parse_segment_index(name: &Name, prefix: &Name) -> Option<u16> {
    if name.len() != prefix.len() + 1 {
        return None;
    }
    if !name.has_prefix(prefix) {
        return None;
    }
    let comp = name.components().last()?;
    std::str::from_utf8(&comp.value).ok()?.parse::<u16>().ok()
}

#[tokio::test]
async fn fec_round_trip_no_loss() {
    let payload: Bytes = Bytes::from((0u16..1024).map(|i| (i & 0xff) as u8).collect::<Vec<u8>>());
    let policy = FecPolicy {
        k: 8,
        n: 12,
        field: Field::Gf8,
    };

    let recovered = run_fetch(&payload, &policy, &[]).await;
    assert_eq!(recovered, payload);
}

#[tokio::test]
async fn fec_round_trip_with_source_losses() {
    let payload: Bytes = Bytes::from(
        (0u16..2048)
            .map(|i| ((i * 7) & 0xff) as u8)
            .collect::<Vec<u8>>(),
    );
    let policy = FecPolicy {
        k: 8,
        n: 12,
        field: Field::Gf8,
    };

    // Refuse to serve segments 1, 4, 6 (sources). The consumer must
    // recover via parity instead.
    let recovered = run_fetch(&payload, &policy, &[1, 4, 6]).await;
    assert_eq!(recovered, payload);
}

/// Spin up an embedded engine, serve coded segments for `payload`
/// while refusing to send the segment indices in `withhold`, drive
/// the consumer through the fetch + assemble loop, return the
/// recovered payload.
async fn run_fetch(payload: &Bytes, policy: &FecPolicy, withhold: &[u16]) -> Bytes {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/test/fec".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, prefix.clone());

    let plan = segment_payload(payload, policy, 1).expect("segment_payload");
    let table: Arc<HashMap<u16, Bytes>> =
        Arc::new(plan.into_iter().map(|s| (s.index, s.content)).collect());
    let withheld: Arc<std::collections::HashSet<u16>> =
        Arc::new(withhold.iter().copied().collect());

    let serve_prefix = prefix.clone();
    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let table = Arc::clone(&table);
                let withheld = Arc::clone(&withheld);
                let prefix = serve_prefix.clone();
                async move {
                    let name = (*interest.name).clone();
                    let Some(idx) = parse_segment_index(&name, &prefix) else {
                        return;
                    };
                    if withheld.contains(&idx) {
                        return; // drop on the floor — consumer must time out and try the next
                    }
                    if let Some(content) = table.get(&idx) {
                        let wire = DataBuilder::new(name, content).build();
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            })
            .await
    });

    // Consumer side: iterate segment indices 0..n, fetch each (skip on
    // timeout/error), feed to the assembler, stop when complete.
    let mut asm = CodedAssembler::new();
    let mut recovered: Option<Bytes> = None;
    for i in 0..policy.n {
        let name = prefix.clone().append(i.to_string());
        let fetch =
            tokio::time::timeout(std::time::Duration::from_millis(300), consumer.fetch(name)).await;
        let data = match fetch {
            Ok(Ok(d)) => d,
            _ => continue,
        };
        let Some(content) = data.content() else {
            continue;
        };
        if let Some(r) = asm.absorb_content(content).expect("absorb") {
            recovered = Some(r);
            break;
        }
    }

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;

    recovered.expect("assembler completed")
}

// ---- endpoint API (CodedProducer / CodedFetcher) -----------------------

fn test_fetch_config() -> FetchConfig {
    FetchConfig {
        window: 8,
        segment_timeout: Duration::from_millis(300),
        total_timeout: Duration::from_secs(5),
        lifetime: Duration::from_millis(1000),
    }
}

/// `CodedProducer::serve_object` publishing all N segments; the
/// `CodedFetcher` recovers from the first K with no loss.
#[tokio::test]
async fn endpoint_round_trip_no_loss() {
    let payload: Bytes = Bytes::from((0u16..1500).map(|i| (i & 0xff) as u8).collect::<Vec<u8>>());
    let policy = FecPolicy {
        k: 8,
        n: 12,
        field: Field::Gf8,
    };
    let object: Name = "/test/fec/obj".parse().unwrap();

    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&object, FaceId(2), 0);

    let producer = Producer::from_handle(producer_handle, object.clone());
    let coded = CodedProducer::new(producer, policy.clone());
    let serve_payload = payload.clone();
    let serve_object = object.clone();
    let producer_task =
        tokio::spawn(async move { coded.serve_object(serve_object, serve_payload, 1).await });

    let consumer = Consumer::from_handle(consumer_handle);
    let fetcher = CodedFetcher::with_config(test_fetch_config());
    let recovered = fetcher
        .fetch(&consumer, object, &policy)
        .await
        .expect("coded fetch completes");
    assert_eq!(recovered, payload);

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}

/// The `CodedFetcher` recovers via parity when source segments 1/4/6 are
/// withheld at the producer — exercising its adaptive over-fetch.
#[tokio::test]
async fn endpoint_fetcher_recovers_via_parity() {
    let payload: Bytes = Bytes::from(
        (0u16..3000)
            .map(|i| ((i * 5) & 0xff) as u8)
            .collect::<Vec<u8>>(),
    );
    let policy = FecPolicy {
        k: 8,
        n: 12,
        field: Field::Gf8,
    };
    let object: Name = "/test/fec/obj".parse().unwrap();

    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&object, FaceId(2), 0);

    // Producer serves coded segments but drops sources 1, 4, 6.
    let plan = segment_payload(&payload, &policy, 1).expect("segment_payload");
    let table: Arc<HashMap<u16, Bytes>> =
        Arc::new(plan.into_iter().map(|s| (s.index, s.content)).collect());
    let withheld: Arc<std::collections::HashSet<u16>> =
        Arc::new([1u16, 4, 6].into_iter().collect());
    let producer = Producer::from_handle(producer_handle, object.clone());
    let serve_object = object.clone();
    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let table = Arc::clone(&table);
                let withheld = Arc::clone(&withheld);
                let object = serve_object.clone();
                async move {
                    let name = (*interest.name).clone();
                    if name.len() != object.len() + 1 || !name.has_prefix(&object) {
                        return;
                    }
                    let Some(idx) = name
                        .components()
                        .last()
                        .and_then(|c| std::str::from_utf8(&c.value).ok())
                        .and_then(|s| s.parse::<u16>().ok())
                    else {
                        return;
                    };
                    if withheld.contains(&idx) {
                        return;
                    }
                    if let Some(content) = table.get(&idx) {
                        let wire = DataBuilder::new(name, content).build();
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            })
            .await
    });

    let consumer = Consumer::from_handle(consumer_handle);
    let fetcher = CodedFetcher::with_config(test_fetch_config());
    let recovered = fetcher
        .fetch(&consumer, object, &policy)
        .await
        .expect("coded fetch recovers via parity");
    assert_eq!(recovered, payload);

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}
