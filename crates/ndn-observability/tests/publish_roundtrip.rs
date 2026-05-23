//! End-to-end witness for `mount_observability`.
//!
//! Mounts a `SpanPublisher` on a fresh engine, publishes a known
//! span, expresses a Consumer Interest for that span's Data name
//! through an app-side InProcHandle, and asserts the Data content
//! decodes as the expected OTLP `Span` protobuf.
//!
//! Phase-3 §D unit witness for the publisher → Producer → Consumer →
//! OTLP-protobuf round-trip.  Per the prompt's stop conditions this
//! ships even when the engine-pipeline-instruments-spans witness
//! (obs_phase3_ndn_publish.sh) is still failing.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_observability::{Attr, Span, SpanKind, SpanPublisher, SpanRetention, StatusCode};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(10_000);

fn obs_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::from_static(b"observability")),
    ])
}

fn sample_span(trace: u8, sp: u8) -> Span {
    Span {
        trace_id: [trace; 16],
        span_id: [sp; 8],
        parent_span_id: None,
        name: "fwd.pipeline".into(),
        kind: SpanKind::Internal,
        start_unix_nano: 1_700_000_000_000_000_000,
        end_unix_nano: 1_700_000_000_001_000_000,
        attributes: vec![Attr::str("interest.name", "/audit/obs/witness")],
        status_code: StatusCode::Ok,
        status_message: String::new(),
    }
}

#[tokio::test]
async fn publish_then_fetch_via_engine() {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    ndn_observability::mount_observability(&engine, cancel.clone(), Arc::clone(&publisher));

    // Give the producer task time to register its face.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let span = sample_span(0xAA, 0xBB);
    publisher.publish(&span);

    // Build the Consumer Interest for that span.
    let span_name = publisher.span_name(&span.trace_id, &span.span_id);
    let interest_wire = InterestBuilder::new(span_name.clone())
        .must_be_fresh()
        .build();
    app_handle
        .send(interest_wire)
        .await
        .expect("send interest");

    // Wait for the Data response.
    let wire = tokio::time::timeout(Duration::from_millis(500), app_handle.recv())
        .await
        .expect("data within timeout")
        .expect("Data wire");
    let data = Data::decode(wire).expect("Data decode");
    assert_eq!(*data.name, span_name);
    let content = data.content().cloned().expect("Data content");

    // The Content is the OTLP Span protobuf.  Field 1 (trace_id) is
    // length-prefixed bytes — first byte 0x0a, second byte 16, next
    // 16 bytes = the trace_id we published.
    assert_eq!(content[0], 0x0A, "OTLP trace_id field tag");
    assert_eq!(content[1], 16, "OTLP trace_id length");
    assert_eq!(&content[2..18], &span.trace_id[..]);

    cancel.cancel();
}

#[tokio::test]
async fn recent_endpoint_lists_cached_spans() {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    ndn_observability::mount_observability(&engine, cancel.clone(), Arc::clone(&publisher));
    tokio::time::sleep(Duration::from_millis(20)).await;

    publisher.publish(&sample_span(0x01, 0xA1));
    publisher.publish(&sample_span(0x02, 0xA2));

    let recent_name = {
        let mut n = obs_prefix();
        n = n.append_component(NameComponent::generic(Bytes::from_static(b"recent")));
        n
    };
    let interest_wire = InterestBuilder::new(recent_name).must_be_fresh().build();
    app_handle.send(interest_wire).await.expect("send");

    let wire = tokio::time::timeout(Duration::from_millis(500), app_handle.recv())
        .await
        .expect("data within timeout")
        .expect("Data wire");
    let data = Data::decode(wire).expect("Data decode");
    let body = data.content().cloned().expect("Content");
    let text = std::str::from_utf8(&body).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "two spans cached");
    // Newest-first ordering.
    // 16 bytes of 0x02 → 32 hex chars.
    assert!(lines[0].starts_with("02020202020202020202020202020202/"));
    cancel.cancel();
}

#[tokio::test]
async fn miss_drops_silently() {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    ndn_observability::mount_observability(&engine, cancel.clone(), Arc::clone(&publisher));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Express an Interest for a span the publisher never saw.
    let span_name = publisher.span_name(&[0xCC; 16], &[0xDD; 8]);
    let interest_wire = InterestBuilder::new(span_name.clone())
        .must_be_fresh()
        .build();
    app_handle.send(interest_wire).await.expect("send");

    // No Data should arrive within a short budget.
    let recv = tokio::time::timeout(Duration::from_millis(200), app_handle.recv()).await;
    assert!(
        recv.is_err(),
        "publisher must not synthesise content for unknown (trace, span)"
    );

    cancel.cancel();
}
