//! NDN-native span publisher.
//!
//! [`SpanPublisher`] turns completed `tracing` spans into OTLP `Span`
//! protobufs and serves them as Data under a configurable NDN prefix —
//! the OTLP wire format travels inside Data content, the substrate is
//! the transport. Consumers Interest by trace-id / span-id; PIT
//! aggregation, CS caching, NAC, and signing all apply.
//!
//! The publisher ring is bounded ([`SpanRetention`]); for persistent
//! retention layer a persistent CS over the same prefix. Cross-router
//! stitching lives in `ndn-transport`'s `TraceContextFeature`; this
//! crate provides publish-side bytes only and is wired to it through
//! [`layer::NdnObservabilityLayer::set_inbound_trace_id`].
//!
//! ```no_run
//! use std::sync::Arc;
//! use ndn_observability::{SpanPublisher, SpanRetention, mount_observability};
//! use ndn_packet::{Name, NameComponent};
//! use bytes::Bytes;
//! # let engine: ndn_engine::ForwarderEngine = unimplemented!();
//! # let cancel = tokio_util::sync::CancellationToken::new();
//!
//! let prefix = Name::from_components([
//!     NameComponent::generic(Bytes::from_static(b"localhost")),
//!     NameComponent::generic(Bytes::from_static(b"nfd")),
//!     NameComponent::generic(Bytes::from_static(b"observability")),
//! ]);
//! let publisher = SpanPublisher::new(prefix, SpanRetention::default());
//! mount_observability(&engine, cancel, Arc::clone(&publisher));
//! ```

pub mod otlp;
pub mod publisher;
// Multi-radio testbed instrumentation (folded in from the former ndn-research
// draft crate): per-flow statistics + a pipeline observer stage.
pub mod flow_table;
pub mod observer;
pub use flow_table::FlowTable;
pub use observer::FlowObserverStage;

#[cfg(feature = "layer")]
pub mod layer;

pub use otlp::{Attr, AttrValue, Span, SpanKind, StatusCode};
pub use publisher::{SpanPublisher, SpanRetention};

#[cfg(feature = "layer")]
pub use layer::{NdnObservabilityLayer, SampleDecision, ratio_sampler};

use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use tokio_util::sync::CancellationToken;

/// Allocates an internal in-process face, registers the publisher's
/// prefix in the FIB, and spawns the serve loop.
pub fn mount_observability(
    engine: &ForwarderEngine,
    cancel: CancellationToken,
    publisher: Arc<SpanPublisher>,
) {
    Arc::clone(&publisher).install(engine, cancel);
}
