//! Two downstreams ask for the same name at the same moment; one upstream
//! answers. Both must get the Data, and neither a Nack.
//!
//! On the parallel pipeline the second Interest can reach the strategy while
//! the first one's pass is still running (the PIT check sends a new
//! downstream's Interest to the strategy while nothing went upstream yet).
//! Whichever pass finds the other's Interest already sent upstream is
//! suppressed, as NFD's retransmission suppression would in its serial order,
//! and waits on the entry for that upstream's Data.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Interest, Name};
use ndn_transport::FaceId;

const FACE_A: u64 = 1;
const FACE_B: u64 = 2;
const UPSTREAM: u64 = 3;

async fn recv_timeout(handle: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), handle.recv())
        .await
        .ok()
        .flatten()
}

/// What a face received, unwrapped from NDNLPv2.
#[derive(Debug)]
enum Packet {
    Interest(Name),
    Data(Name),
    Nack,
}

fn classify(wire: &Bytes) -> Packet {
    let (nack, inner) = match LpPacket::decode(wire.clone()) {
        Ok(lp) => (lp.nack.is_some(), lp.fragment.unwrap_or_default()),
        Err(_) => (false, wire.clone()),
    };
    if nack {
        return Packet::Nack;
    }
    if let Ok(i) = Interest::decode(inner.clone()) {
        return Packet::Interest((*i.name).clone());
    }
    Packet::Data((*Data::decode(inner).expect("Interest, Data or Nack").name).clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_interests_from_two_faces_are_both_satisfied() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (face_u, handle_u) = InProcFace::new(FaceId(UPSTREAM), 128);
    // The daemon's parallel pipeline, where the two strategy passes overlap.
    let (engine, shutdown) = EngineBuilder::new(EngineConfig {
        pipeline_threads: 4,
        ..EngineConfig::default()
    })
    .face(face_a)
    .face(face_b)
    .face(face_u)
    .build()
    .await
    .expect("engine build");
    let prefix: Name = "/simultaneous".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(UPSTREAM), 0);

    // The upstream answers every Interest it receives.
    let upstream_interests = Arc::new(AtomicUsize::new(0));
    let responder = tokio::spawn({
        let count = Arc::clone(&upstream_interests);
        async move {
            while let Some(wire) = handle_u.recv().await {
                let Packet::Interest(name) = classify(&wire) else {
                    panic!("the upstream only receives Interests");
                };
                count.fetch_add(1, Ordering::Relaxed);
                let data = DataBuilder::new(name, b"x").build();
                if handle_u.send(data).await.is_err() {
                    return;
                }
            }
        }
    });

    const ROUNDS: u64 = 300;
    let mut failures = Vec::new();
    for i in 0..ROUNDS {
        let name = prefix.clone().append_segment(i);
        let interest = || {
            InterestBuilder::new(name.clone())
                .lifetime(Duration::from_secs(4))
                .build()
        };
        let (ra, rb) = tokio::join!(handle_a.send(interest()), handle_b.send(interest()));
        ra.expect("inject on A");
        rb.expect("inject on B");
        for (face, handle) in [("A", &handle_a), ("B", &handle_b)] {
            let got = recv_timeout(handle, 1000).await.map(|w| classify(&w));
            if !matches!(&got, Some(Packet::Data(n)) if *n == name) {
                failures.push(format!("round {i}: {face} got {got:?}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {ROUNDS} rounds left a downstream without the Data (upstream received {} \
         Interests): {failures:#?}",
        failures.len(),
        upstream_interests.load(Ordering::Relaxed),
    );

    responder.abort();
    shutdown.shutdown().await;
}
