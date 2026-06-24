//! G4 — egress scheduling wired through the engine. With `with_priority_egress`, every
//! face drains a `PriorityScheduler` instead of its plain mpsc. This proves the wiring is
//! non-regressive: a normal Interest→Data round-trip still completes when both the
//! forwarded Interest and the returning Data flow through the scheduler, for a classified
//! (non-default) class and the default class alike. (Strict-priority *ordering* is unit-
//! tested in `egress.rs`; here we exercise the engine enqueue→dequeue path end to end.)

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig, PrefixClassifier, TrafficClass};
use ndn_face_local::InProcFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_transport::FaceId;

const A: u64 = 1; // consumer
const B: u64 = 2; // producer

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn priority_egress_forwards_both_classes() {
    let (face_a, handle_a) = InProcFace::new(FaceId(A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(B), 128);

    // Bulk → low priority (class 5); everything else → default (class 0).
    let classifier = Arc::new(PrefixClassifier::new(
        vec![("/bulk".parse().unwrap(), TrafficClass(5))],
        TrafficClass::DEFAULT,
    ));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .with_priority_egress(classifier, 256)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&"/".parse().unwrap(), FaceId(B), 0);

    // Producer side: answer each forwarded Interest with Data for the same name.
    let producer = tokio::spawn(async move {
        for name in ["/bulk/seg=0", "/ctrl/v=1"] {
            let _interest = handle_b.recv().await.expect("forwarded interest");
            let data = DataBuilder::new(name, b"payload").sign_digest_sha256();
            handle_b.send(data).await.expect("send data");
        }
    });

    // A bulk-class fetch (class 5) and a default-class fetch (class 0) both complete —
    // the scheduler-drained egress delivers the forwarded Interest to B and the Data
    // back to A in each case.
    for name in ["/bulk/seg=0", "/ctrl/v=1"] {
        let interest = InterestBuilder::new(name).must_be_fresh().build();
        handle_a.send(interest).await.expect("express interest");
        let got = tokio::time::timeout(Duration::from_secs(2), handle_a.recv())
            .await
            .unwrap_or_else(|_| panic!("Data for {name} timed out via the priority egress"));
        assert!(got.is_some(), "Data for {name} returned through the scheduler");
    }

    producer.await.unwrap();
    shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drr_egress_forwards() {
    // The DRR scheduler path also forwards end to end (starvation-free fairness variant).
    let (face_a, handle_a) = InProcFace::new(FaceId(A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(B), 128);

    let classifier = Arc::new(PrefixClassifier::new(
        vec![("/bulk".parse().unwrap(), TrafficClass(5))],
        TrafficClass::DEFAULT,
    ));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .with_drr_egress(classifier, 1500, 256)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&"/".parse().unwrap(), FaceId(B), 0);

    let producer = tokio::spawn(async move {
        let _i = handle_b.recv().await.expect("forwarded interest");
        let data = DataBuilder::new("/bulk/seg=0", b"payload").sign_digest_sha256();
        handle_b.send(data).await.expect("send data");
    });

    let interest = InterestBuilder::new("/bulk/seg=0").must_be_fresh().build();
    handle_a.send(interest).await.expect("express interest");
    let got = tokio::time::timeout(Duration::from_secs(2), handle_a.recv())
        .await
        .expect("Data timed out via the DRR egress");
    assert!(got.is_some(), "Data returned through the DRR scheduler");

    producer.await.unwrap();
    shutdown.shutdown().await;
}
