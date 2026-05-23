//! TraceContext feature — in-band LP `TraceContext` TLV (type `0x520`)
//! propagation across routers.
//!
//! `on_egress`: if an egress source is registered and yields a
//! `TraceContext`, splice the TLV into the outbound LP wire.
//! `on_ingress`: extract the TLV from the inbound LP wire and hand it
//! to the registered sink.
//!
//! Span emission is NDN-native and lives in `ndn-observability`; this
//! feature carries no dep on opentelemetry/tonic and only touches the
//! LP TLV.

use core::fmt;
use std::sync::Arc;

use std::sync::{OnceLock, RwLock};

use ndn_packet::lp::{TraceContext, extract_from_lp_wire, splice_into_lp_wire};

use super::super::LinkServiceFeature;

/// Process-global default; consulted when the per-face source is unset.
/// `OnceLock` — first writer wins.
static GLOBAL_EGRESS_SOURCE: OnceLock<OutboundSource> = OnceLock::new();
static GLOBAL_INGRESS_SINK: OnceLock<InboundSink> = OnceLock::new();

pub fn install_global_egress_source(source: OutboundSource) {
    let _ = GLOBAL_EGRESS_SOURCE.set(source);
}

pub fn install_global_ingress_sink(sink: InboundSink) {
    let _ = GLOBAL_INGRESS_SINK.set(sink);
}

/// Produces the `TraceContext` to inject on the next outbound LP frame
/// (or `None` to skip).
pub type OutboundSource = Arc<dyn Fn() -> Option<TraceContext> + Send + Sync>;

/// Invoked on every inbound LP frame carrying a `TraceContext` TLV.
pub type InboundSink = Arc<dyn Fn(TraceContext) + Send + Sync>;

pub struct TraceContextFeature {
    egress: RwLock<Option<OutboundSource>>,
    ingress: RwLock<Option<InboundSink>>,
}

impl fmt::Debug for TraceContextFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceContextFeature")
            .field(
                "egress_set",
                &self
                    .egress
                    .read()
                    .ok()
                    .map(|g| g.is_some())
                    .unwrap_or(false),
            )
            .field(
                "ingress_set",
                &self
                    .ingress
                    .read()
                    .ok()
                    .map(|g| g.is_some())
                    .unwrap_or(false),
            )
            .finish()
    }
}

impl Default for TraceContextFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceContextFeature {
    pub fn new() -> Self {
        Self {
            egress: RwLock::new(None),
            ingress: RwLock::new(None),
        }
    }

    pub fn set_egress_source(&self, source: Option<OutboundSource>) {
        if let Ok(mut g) = self.egress.write() {
            *g = source;
        }
    }

    pub fn set_ingress_sink(&self, sink: Option<InboundSink>) {
        if let Ok(mut g) = self.ingress.write() {
            *g = sink;
        }
    }

    pub fn egress_active(&self) -> bool {
        self.egress
            .read()
            .ok()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }
}

impl LinkServiceFeature for TraceContextFeature {
    fn name(&self) -> &'static str {
        "trace-context"
    }

    fn on_egress(
        &self,
        frame: &mut super::super::OutboundLpFrame,
        _ctx: &super::super::EgressCtx,
    ) {
        // Per-face source has priority; fall back to the process-global.
        let source = match self.egress.read() {
            Ok(g) => g.as_ref().cloned(),
            Err(_) => return,
        };
        let source = source.or_else(|| GLOBAL_EGRESS_SOURCE.get().cloned());
        let Some(source) = source else { return };
        let Some(tc) = source() else { return };
        frame.wire = splice_into_lp_wire(frame.wire.clone(), &tc);
    }

    fn on_ingress(
        &self,
        frame: &super::super::InboundLpFrame,
        _ctx: &super::super::IngressCtx,
    ) {
        let sink = match self.ingress.read() {
            Ok(g) => g.as_ref().cloned(),
            Err(_) => return,
        };
        let sink = sink.or_else(|| GLOBAL_INGRESS_SINK.get().cloned());
        let Some(sink) = sink else { return };
        if let Some(tc) = extract_from_lp_wire(&frame.wire) {
            sink(tc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::face::FaceId;
    use crate::link_service::feature::{
        EgressCtx, IngressCtx, InboundLpFrame, OutboundLpFrame,
    };
    use bytes::Bytes;
    use ndn_packet::lp::{SpanId, TraceFlags, TraceId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn sample_ctx() -> TraceContext {
        TraceContext {
            trace_id: TraceId([0xAB; 16]),
            span_id: SpanId([0xCD; 8]),
            flags: TraceFlags::SAMPLED,
            timestamp_us: 1_234_567,
        }
    }

    fn lp_wire_around(inner: &[u8]) -> Bytes {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::LP_PACKET, |w| {
            w.write_tlv(ndn_packet::tlv_type::LP_FRAGMENT, inner);
        });
        w.finish()
    }

    fn minimal_interest_wire() -> Bytes {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::INTEREST, |w| {
            w.write_nested(ndn_packet::tlv_type::NAME, |w| {
                w.write_tlv(ndn_packet::tlv_type::NAME_COMPONENT, b"t");
            });
            w.write_tlv(ndn_packet::tlv_type::NONCE, &[1, 2, 3, 4]);
        });
        w.finish()
    }

    #[test]
    fn egress_inert_when_source_unset() {
        let feat = TraceContextFeature::new();
        let wire = lp_wire_around(&minimal_interest_wire());
        let original = wire.clone();
        let mut frame = OutboundLpFrame::new(wire, true);
        feat.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
        assert_eq!(frame.wire, original);
    }

    #[test]
    fn egress_splices_when_source_present() {
        let feat = TraceContextFeature::new();
        feat.set_egress_source(Some(Arc::new(|| Some(sample_ctx()))));
        let wire = lp_wire_around(&minimal_interest_wire());
        let mut frame = OutboundLpFrame::new(wire, true);
        feat.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
        let extracted = extract_from_lp_wire(&frame.wire).expect("must extract");
        assert_eq!(extracted, sample_ctx());
    }

    #[test]
    fn egress_source_returning_none_is_no_op() {
        let feat = TraceContextFeature::new();
        feat.set_egress_source(Some(Arc::new(|| None)));
        let wire = lp_wire_around(&minimal_interest_wire());
        let original = wire.clone();
        let mut frame = OutboundLpFrame::new(wire, true);
        feat.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
        assert_eq!(frame.wire, original);
    }

    #[test]
    fn ingress_invokes_sink_when_context_present() {
        let feat = TraceContextFeature::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        feat.set_ingress_sink(Some(Arc::new(move |tc| {
            assert_eq!(tc, sample_ctx());
            c.fetch_add(1, Ordering::Relaxed);
        })));
        let wire = splice_into_lp_wire(lp_wire_around(&minimal_interest_wire()), &sample_ctx());
        let frame = InboundLpFrame::bare(wire);
        feat.on_ingress(&frame, &IngressCtx::new(FaceId(1)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ingress_skips_when_no_context_on_wire() {
        let feat = TraceContextFeature::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        feat.set_ingress_sink(Some(Arc::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        })));
        let wire = lp_wire_around(&minimal_interest_wire());
        let frame = InboundLpFrame::bare(wire);
        feat.on_ingress(&frame, &IngressCtx::new(FaceId(1)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
