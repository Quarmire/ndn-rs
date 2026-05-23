//! `tracing::Subscriber` layer that converts completed spans into OTLP
//! `Span` protobufs and hands them to a [`SpanPublisher`].
//!
//! Sampling is decided at span-open time; once a span is sampled the
//! flag flows to all child spans (W3C trace-flags bit 0 = sampled).
//! [`SampleDecision`] is swappable so operators can plug in
//! deterministic / rate-limited / adaptive samplers.
//!
//! Current limitations: span links and span events are not exported;
//! attribute extraction covers `&str` / `i64` / `u64` / `bool` and
//! best-effort debug stringification.

#![cfg(feature = "layer")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tracing::span::{Attributes, Id, Record};
use tracing::{Subscriber, field};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::otlp::{Attr, Span as OtlpSpan, SpanKind, StatusCode};
use crate::publisher::SpanPublisher;

/// Returning `false` skips OTLP export; the span is still observed by
/// other Layers (stderr/file/ring).
pub type SampleDecision = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Head-based ratio sampler. Deterministic per-process via a counter
/// so test runs are reproducible.
pub fn ratio_sampler(p: f64) -> SampleDecision {
    let p = p.clamp(0.0, 1.0);
    if p >= 1.0 {
        return Arc::new(|_| true);
    }
    if p <= 0.0 {
        return Arc::new(|_| false);
    }
    let counter = Arc::new(AtomicU64::new(0));
    let stride = (1.0 / p).round() as u64;
    Arc::new(move |_target| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        n.is_multiple_of(stride)
    })
}

struct OpenSpan {
    name: String,
    target: String,
    start_nanos: u64,
    attrs: Vec<Attr>,
    sampled: bool,
}

struct LayerCore {
    publisher: Arc<SpanPublisher>,
    trace_id: [u8; 16],
    next_span_id: AtomicU64,
    sample: SampleDecision,
    overrides: Mutex<Option<[u8; 16]>>,
}

#[derive(Clone)]
pub struct NdnObservabilityLayer {
    core: Arc<LayerCore>,
}

impl NdnObservabilityLayer {
    /// Spans share a single 128-bit trace-id by default; cross-router
    /// stitching replaces it per inbound LP frame via
    /// [`Self::set_inbound_trace_id`].
    pub fn new(publisher: Arc<SpanPublisher>, sample: SampleDecision) -> Self {
        let trace_id = process_seed_trace_id();
        Self {
            core: Arc::new(LayerCore {
                publisher,
                trace_id,
                next_span_id: AtomicU64::new(1),
                sample,
                overrides: Mutex::new(None),
            }),
        }
    }

    /// Override the trace-id used for subsequent spans. The engine
    /// calls this on Interest entry with the trace-id pulled from the
    /// inbound LP `TraceContext` TLV (or a Nonce-fallback synthesis).
    pub fn set_inbound_trace_id(&self, trace_id: [u8; 16]) {
        *self.core.overrides.lock() = Some(trace_id);
    }

    fn current_trace_id(&self) -> [u8; 16] {
        self.core.overrides.lock().unwrap_or(self.core.trace_id)
    }

    /// Fresh `TraceContext` for splicing into an outbound LP frame:
    /// current trace-id + a freshly-allocated span-id + `SAMPLED`.
    /// Called per outbound frame by `TraceContextFeature` when peer
    /// propagation is enabled.
    pub fn current_outbound_context(&self) -> ndn_packet::lp::TraceContext {
        ndn_packet::lp::TraceContext {
            trace_id: ndn_packet::lp::TraceId(self.current_trace_id()),
            span_id: ndn_packet::lp::SpanId(self.alloc_span_id()),
            flags: ndn_packet::lp::TraceFlags::SAMPLED,
            timestamp_us: unix_now_nanos() / 1000,
        }
    }

    fn alloc_span_id(&self) -> [u8; 8] {
        self.core
            .next_span_id
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes()
    }
}

impl<S> tracing_subscriber::Layer<S> for NdnObservabilityLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let sampled = (self.core.sample)(attrs.metadata().target());
        let mut collected = AttrCollector::default();
        attrs.record(&mut collected);

        let start_nanos = unix_now_nanos();
        let span = ctx.span(id).expect("span open");
        span.extensions_mut().insert(OpenSpan {
            name: attrs.metadata().name().to_string(),
            target: attrs.metadata().target().to_string(),
            start_nanos,
            attrs: collected.into_attrs(),
            sampled,
        });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span exists");
        let mut ext = span.extensions_mut();
        let Some(state) = ext.get_mut::<OpenSpan>() else {
            return;
        };
        let mut collected = AttrCollector::default();
        values.record(&mut collected);
        state.attrs.extend(collected.into_attrs());
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("span exists");
        let state = span
            .extensions_mut()
            .remove::<OpenSpan>();
        let Some(state) = state else { return };
        if !state.sampled {
            return;
        }
        let end_nanos = unix_now_nanos();
        let mut attrs = state.attrs;
        attrs.push(Attr::str("ndn.target", state.target));
        let span_id = self.alloc_span_id();
        let trace_id = self.current_trace_id();
        let otlp_span = OtlpSpan {
            trace_id,
            span_id,
            parent_span_id: None,
            name: state.name,
            kind: SpanKind::Internal,
            start_unix_nano: state.start_nanos,
            end_unix_nano: end_nanos,
            attributes: attrs,
            status_code: StatusCode::Ok,
            status_message: String::new(),
        };
        self.core.publisher.publish(&otlp_span);
    }
}

#[derive(Default)]
struct AttrCollector {
    out: Vec<Attr>,
}

impl AttrCollector {
    fn into_attrs(self) -> Vec<Attr> {
        self.out
    }
}

impl field::Visit for AttrCollector {
    fn record_str(&mut self, field: &field::Field, value: &str) {
        self.out.push(Attr::str(field.name(), value));
    }

    fn record_i64(&mut self, field: &field::Field, value: i64) {
        self.out.push(Attr::int(field.name(), value));
    }

    fn record_u64(&mut self, field: &field::Field, value: u64) {
        self.out
            .push(Attr::int(field.name(), value.min(i64::MAX as u64) as i64));
    }

    fn record_bool(&mut self, field: &field::Field, value: bool) {
        self.out.push(Attr::bool_(field.name(), value));
    }

    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        let mut buf = String::new();
        use std::fmt::Write as _;
        if write!(&mut buf, "{:?}", value).is_ok() {
            self.out.push(Attr::str(field.name(), buf));
        }
    }
}

fn process_seed_trace_id() -> [u8; 16] {
    let nanos = web_time::SystemTime::now()
        .duration_since(web_time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos.to_be_bytes()
}

fn unix_now_nanos() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_sampler_zero_never_samples() {
        let s = ratio_sampler(0.0);
        assert!(!s("any"));
        assert!(!s("any"));
    }

    #[test]
    fn ratio_sampler_one_always_samples() {
        let s = ratio_sampler(1.0);
        assert!(s("any"));
        assert!(s("any"));
    }

    #[test]
    fn ratio_sampler_half_alternates_strict_count() {
        let s = ratio_sampler(0.5);
        let mut samples = 0u32;
        for _ in 0..100 {
            if s("any") {
                samples += 1;
            }
        }
        assert_eq!(samples, 50);
    }
}
