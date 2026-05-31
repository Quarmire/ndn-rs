//! Witness: the [`NdnObservabilityLayer`] turns `tracing` spans into
//! OTLP `Span` protobufs and lands them in the publisher's ring.
//!
//! Phase-3 §D.6 unit test — the layer side of the publisher binding.

#![cfg(feature = "layer")]

use std::sync::Arc;

use bytes::Bytes;
use ndn_observability::{NdnObservabilityLayer, SpanPublisher, SpanRetention, ratio_sampler};
use ndn_packet::{Data, Name, NameComponent};
use tracing_subscriber::layer::SubscriberExt;

fn obs_prefix() -> Name {
    Name::from_components([NameComponent::generic(Bytes::from_static(b"obs"))])
}

#[test]
fn span_close_publishes_otlp_data() {
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    let layer = NdnObservabilityLayer::new(Arc::clone(&publisher), ratio_sampler(1.0));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    {
        let span = tracing::info_span!(
            "fwd.pipeline",
            interest.name = "/audit/obs/witness",
            face.id = 42_i64,
        );
        let _enter = span.enter();
    }
    // Drop closes the span and triggers on_close → publish.

    assert!(
        !publisher.is_empty(),
        "expected at least one published span"
    );
    let wire = publisher.latest_wire().expect("latest");
    // Decode as Data; Content is the OTLP Span protobuf.
    let data = Data::decode(wire).expect("Data decode");
    let content = data.content().cloned().expect("Content");
    // First byte = OTLP trace_id field tag (field=1 wire=2 = 0x0A).
    assert_eq!(content[0], 0x0A);
    assert_eq!(content[1], 16);
}

#[test]
fn sampler_zero_emits_nothing() {
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    let layer = NdnObservabilityLayer::new(Arc::clone(&publisher), ratio_sampler(0.0));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    for _ in 0..5 {
        let s = tracing::info_span!("fwd.pipeline");
        let _e = s.enter();
    }
    assert_eq!(publisher.len(), 0);
}

#[test]
fn inbound_trace_id_override_appears_in_span_wire() {
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    let layer = NdnObservabilityLayer::new(Arc::clone(&publisher), ratio_sampler(1.0));
    let trace_id = [0x77; 16];
    layer.set_inbound_trace_id(trace_id);
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    {
        let s = tracing::info_span!("fwd.strategy");
        let _e = s.enter();
    }
    let wire = publisher.latest_wire().expect("latest");
    let data = Data::decode(wire).expect("Data decode");
    let content = data.content().cloned().expect("Content");
    assert_eq!(&content[2..18], &trace_id[..]);
}
