//! `LinkServiceFeature` — per-LP-frame extension trait composed into
//! [`super::LpLinkService`].
//!
//! Hook order: on ingress, features run after raw-bytes recv and before
//! engine decode, in registration order. On egress, features run after
//! fragmentation / LP-wrap and before `transport.send_bytes`, also in
//! registration order. The composer is the single writer for the final
//! wire bytes; features observe and stage typed slots.

use bytes::Bytes;
use core::time::Duration;

use crate::face::{FaceAddr, FaceId};

/// Outbound LP frame view. Features observe; the composer is the single
/// writer for the final wire bytes.
#[derive(Clone, Debug)]
pub struct OutboundLpFrame {
    pub wire: Bytes,
    /// `true` if `wire` is already LP-wrapped; `false` for a bare
    /// Interest/Data the composer will wrap.
    pub is_lp_wrapped: bool,
}

impl OutboundLpFrame {
    pub fn new(wire: Bytes, is_lp_wrapped: bool) -> Self {
        Self {
            wire,
            is_lp_wrapped,
        }
    }
}

/// Inbound LP frame view. Populated by the composer's recv path from raw
/// transport bytes; features inspect.
#[derive(Clone, Debug)]
pub struct InboundLpFrame {
    pub wire: Bytes,
    pub addr: Option<FaceAddr>,
    /// In-process originator id (passthrough faces only).
    pub source_face_tag: Option<FaceId>,
    pub congestion_mark: Option<u64>,
    pub prefix_announcement: Option<Bytes>,
}

impl InboundLpFrame {
    pub fn bare(wire: Bytes) -> Self {
        Self {
            wire,
            addr: None,
            source_face_tag: None,
            congestion_mark: None,
            prefix_announcement: None,
        }
    }

    pub fn with_addr(wire: Bytes, addr: Option<FaceAddr>) -> Self {
        Self {
            wire,
            addr,
            source_face_tag: None,
            congestion_mark: None,
            prefix_announcement: None,
        }
    }
}

/// Context for [`LinkServiceFeature::on_egress`]. `face_id` is the local
/// face the packet is leaving on; `source` is the in-process originator
/// (for IncomingFaceId stamping), when known.
#[derive(Clone, Copy, Debug)]
pub struct EgressCtx {
    pub face_id: FaceId,
    pub source: Option<FaceId>,
}

impl EgressCtx {
    pub fn new(face_id: FaceId, source: Option<FaceId>) -> Self {
        Self { face_id, source }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IngressCtx {
    pub face_id: FaceId,
}

impl IngressCtx {
    pub fn new(face_id: FaceId) -> Self {
        Self { face_id }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TickCtx {
    pub face_id: FaceId,
}

impl TickCtx {
    pub fn new(face_id: FaceId) -> Self {
        Self { face_id }
    }
}

/// Per-LP-frame extension trait composed into [`super::LpLinkService`].
/// Object-safe; the composer holds `Vec<Arc<dyn LinkServiceFeature>>`.
pub trait LinkServiceFeature: Send + Sync + 'static {
    /// Kebab-case symbol used in tracing + the `feature_set` FaceStatus TLV.
    fn name(&self) -> &'static str;

    fn on_egress(&self, _frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {}
    fn on_ingress(&self, _frame: &InboundLpFrame, _ctx: &IngressCtx) {}

    /// `Some(d)` to be ticked again after `d`; `None` to opt out.
    fn tick(&self, _ctx: &TickCtx) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct StubFeature;
    impl LinkServiceFeature for StubFeature {
        fn name(&self) -> &'static str {
            "stub"
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let _: Arc<dyn LinkServiceFeature> = Arc::new(StubFeature);
    }

    #[test]
    fn default_hooks_are_no_ops() {
        let f = StubFeature;
        let mut frame = OutboundLpFrame::new(Bytes::from_static(&[0x05, 0x00]), false);
        let ectx = EgressCtx::new(FaceId(0), None);
        f.on_egress(&mut frame, &ectx);

        let inbound = InboundLpFrame::bare(Bytes::from_static(&[0x05, 0x00]));
        let ictx = IngressCtx::new(FaceId(0));
        f.on_ingress(&inbound, &ictx);

        let tctx = TickCtx::new(FaceId(0));
        assert!(f.tick(&tctx).is_none());
    }
}
