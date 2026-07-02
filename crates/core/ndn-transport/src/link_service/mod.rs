//! `LinkService` — the framing/policy half of a face. Owns NDNLPv2 framing,
//! per-face reliability, congestion marks, and IncomingFaceId tagging that
//! NFD's `GenericLinkService` consolidates. The transport ships raw bytes.
//!
//! [`default_link_service_for_kind`] picks [`PassthroughLinkService`] for
//! [`FaceScope::Local`] kinds and [`LpLinkService`] for
//! [`FaceScope::NonLocal`] kinds.
//!
//! ndn-rs adds [`LinkServiceFeature`] as the per-frame extension seam
//! (fragmentation, reliability, congestion-marking, IncomingFaceId,
//! NACK, LocalFields, trace-context); NFD inlines these in
//! `GenericLinkService`.

use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::face::{FaceAddr, FaceError, FaceId, FaceKind};
use crate::face_options::{FaceOption, FaceOptionError, FaceOptions};
use crate::reliability::ReliabilityConfig;
use crate::transport::ErasedTransport;

pub mod feature;
pub mod features;

pub use feature::{
    EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame, TickCtx,
};
pub use features::{
    CongestionMarkingFeature, FragmentationFeature, IncomingFaceIdFeature, LocalFieldsFeature,
    NackFeature, NetworkFeatureSet, ReassemblyFeature, ReliabilityFeature, TraceContextFeature,
};

/// One frame surfaced by a [`LinkService::recv`]: wire payload plus any
/// LP fields the link service extracted.
#[derive(Debug, Clone)]
pub struct LinkServiceFrame {
    pub wire: Bytes,
    /// Link-layer sender, from multicast/broadcast transports.
    pub addr: Option<FaceAddr>,
    /// In-process originator id, populated by [`PassthroughLinkService`].
    pub source_face_tag: Option<FaceId>,
    pub congestion_mark: Option<u64>,
    pub prefix_announcement: Option<Bytes>,
}

impl LinkServiceFrame {
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

/// Object-safe (no generics, no RPIT). The face table holds
/// `Arc<dyn LinkService>` paired with `Arc<dyn ErasedTransport>`.
pub trait LinkService: Send + Sync + 'static {
    /// Send a packet through the underlying transport, applying any LP
    /// framing this service advertises.
    fn send<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
        packet: Bytes,
        source: Option<FaceId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>>;

    /// Send a burst of already-framed wires (the NDNLPv2 fragments of one
    /// packet) sharing one `source`. The default ships them through [`send`]
    /// one at a time; a framing link service may override to apply the egress
    /// feature pipeline per frame and then hand the whole burst to
    /// [`ErasedTransport::send_batch`] for a single batched syscall.
    ///
    /// [`send`]: LinkService::send
    fn send_batch<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
        wires: &'a [Bytes],
        source: Option<FaceId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>> {
        Box::pin(async move {
            for wire in wires {
                self.send(transport, wire.clone(), source).await?;
            }
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
    ) -> Pin<Box<dyn Future<Output = Result<LinkServiceFrame, FaceError>> + Send + 'a>>;

    /// Whether this link service applies NDNLPv2 framing on egress. The
    /// engine consults this to decide whether to attach LP-only fields
    /// (IncomingFaceId, CongestionMark, NextHopFaceId).
    fn lp_encodes(&self) -> bool;

    fn reliability_enabled(&self) -> bool {
        false
    }

    /// Apply a typed [`FaceOption`] at runtime. Default errors with
    /// `NotSupportedByTransport`.
    fn apply(&self, opt: FaceOption) -> Result<(), FaceOptionError> {
        Err(FaceOptionError::NotSupportedByTransport { option: opt.name() })
    }

    /// Typed snapshot for the `faces/list` writer.
    fn snapshot(&self) -> FaceOptions {
        FaceOptions::default()
    }

    /// Kebab-case names of per-frame features active on this link service,
    /// in registration order. Surfaced on `faces/list` via `FeatureSet`.
    fn feature_names(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// `(n_lp_resent_packets, rto_micros)` if a `ReliabilityFeature` is
    /// present and enabled.
    fn reliability_counters(&self) -> Option<(u64, u64)> {
        None
    }

    /// `(n_marks_sent, n_marks_received)` if a `CongestionMarkingFeature`
    /// is present.
    fn congestion_counters(&self) -> Option<(u64, u64)> {
        None
    }

    /// Engine wires a closure returning the current egress queue depth so
    /// the CongestionMarking feature's CoDel can observe it.
    fn wire_queue_depth_fn(&self, _queue_depth_fn: Arc<dyn Fn() -> u64 + Send + Sync>) {}

    /// Handle for the per-face tick task to pump retransmissions.
    fn reliability_feature_handle(&self) -> Option<Arc<features::ReliabilityFeature>> {
        None
    }

    /// Handle for the per-face tick task to emit A-LAL idle beacons (CCLF).
    fn a_lal_feature_handle(&self) -> Option<Arc<features::AlalFeature>> {
        None
    }
}

/// LinkService for local (same-host IPC) faces. Skips LP framing in both
/// directions and forwards `source` provenance via
/// `Transport::send_bytes_with_source` — the in-process counterpart to
/// NDNLPv2 `IncomingFaceId`.
pub struct PassthroughLinkService;

impl LinkService for PassthroughLinkService {
    fn send<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
        packet: Bytes,
        source: Option<FaceId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>> {
        Box::pin(async move {
            match source {
                Some(src) => transport.send_bytes_with_source(packet, src).await,
                None => transport.send_bytes(packet).await,
            }
        })
    }

    fn recv<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
    ) -> Pin<Box<dyn Future<Output = Result<LinkServiceFrame, FaceError>> + Send + 'a>> {
        Box::pin(async move {
            let (wire, addr) = transport.recv_bytes_with_addr().await?;
            Ok(LinkServiceFrame::with_addr(wire, addr))
        })
    }

    fn lp_encodes(&self) -> bool {
        false
    }
}

/// LinkService for non-local (network) faces. Owns NDNLPv2 framing,
/// fragmentation, and the per-frame feature pipeline.
pub struct LpLinkService {
    pub reliability: Option<ReliabilityConfig>,
    // NDNLPv2 LocalFields (IncomingFaceId) live in the engine layer
    // (`FaceState.flags`, read by the dispatcher), not here — there is no
    // link-service-side `local_fields_enabled` flag.
    /// Monotonic fragmentation sequence; each oversized packet claims one
    /// sequence and emits N consecutive LP fragments under it.
    fragment_seq: AtomicU64,
    /// Per-LP-frame feature pipeline. Features run after fragmentation/LP-wrap
    /// on egress and before reassembly on ingress, in registration order.
    features: Vec<Arc<dyn LinkServiceFeature>>,
    /// Typed handle into `features` so `apply()` can flip the switch directly.
    reliability_feature: Arc<ReliabilityFeature>,
    congestion_marking_feature: Arc<CongestionMarkingFeature>,
    a_lal_feature: Arc<features::AlalFeature>,
}

impl LpLinkService {
    pub fn new() -> Self {
        let set = features::default_features_for_network_face();
        Self {
            reliability: None,
            fragment_seq: AtomicU64::new(0),
            features: set.features,
            reliability_feature: set.reliability,
            congestion_marking_feature: set.congestion_marking,
            a_lal_feature: set.a_lal,
        }
    }

    pub fn with_reliability(reliability: ReliabilityConfig) -> Self {
        let set = features::default_features_for_network_face();
        let reliability_feature = Arc::new(ReliabilityFeature::with_config(reliability.clone()));
        reliability_feature.set_enabled(true);
        let mut features = set.features;
        // Point the pipeline at the same pre-armed instance the typed
        // handle holds, so flips through `apply()` and the composer see
        // the same state.
        if let Some(slot) = features.iter_mut().find(|f| f.name() == "reliability") {
            *slot = Arc::clone(&reliability_feature) as Arc<dyn LinkServiceFeature>;
        }
        Self {
            reliability: Some(reliability),
            fragment_seq: AtomicU64::new(0),
            features,
            reliability_feature,
            congestion_marking_feature: set.congestion_marking,
            a_lal_feature: set.a_lal,
        }
    }

    pub fn features(&self) -> &[Arc<dyn LinkServiceFeature>] {
        &self.features
    }

    /// Register a custom per-LP-frame feature on this link service (e.g. the
    /// named-radio control plane). It runs in the egress/ingress pipeline and is
    /// pumped by the engine's per-face tick alongside the built-in features.
    pub fn with_extra_feature(mut self, feature: Arc<dyn LinkServiceFeature>) -> Self {
        self.features.push(feature);
        self
    }

    pub fn reliability_feature(&self) -> &Arc<ReliabilityFeature> {
        &self.reliability_feature
    }

    pub fn congestion_marking_feature(&self) -> &Arc<CongestionMarkingFeature> {
        &self.congestion_marking_feature
    }

    pub fn a_lal_feature(&self) -> &Arc<features::AlalFeature> {
        &self.a_lal_feature
    }
}

impl Default for LpLinkService {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkService for LpLinkService {
    /// Encodes Interest/Data in an `LpPacket`, fragmenting to the
    /// transport's MTU. Already-LP input passes through unchanged unless it is a
    /// *complete* packet that overruns the MTU, in which case its inner network
    /// packet is re-fragmented to fit (dropping link-local headers).
    /// `source` is unused here: the in-proc tag-bag carries it for IPC faces,
    /// and the dispatcher attaches NDNLPv2 `IncomingFaceId` on LP egress when
    /// the face has LocalFields enabled (`FaceState.flags`).
    fn send<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
        packet: Bytes,
        source: Option<FaceId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>> {
        Box::pin(async move {
            let egress_ctx = EgressCtx::new(FaceId(transport.id().0), source);

            // Fragment / LP-wrap, then run the feature pipeline on each
            // frame, then send.
            if ndn_packet::lp::is_lp_packet(&packet) {
                // Re-fragment an already-LP-framed packet that exceeds the MTU.
                // A dispatcher may hand us a *complete* LP packet (the network
                // packet wrapped with link-local fields, e.g. IncomingFaceId);
                // sending that whole past a small-frame radio (Wi-Fi Aware
                // follow-up ~200 B, BLE advert ~245 B) overruns the frame and the
                // radio silently drops it — exactly what stalled the offer-board
                // fetch (a signed segment arrives framed and oversized). Split its
                // inner network packet to the MTU instead. We re-fragment only a
                // complete packet (not one that is already a fragment) and drop the
                // link-local headers — the receiver re-derives them from the actual
                // arrival face.
                if let Some(mtu) = transport.send_mtu()
                    && packet.len() > mtu
                    && mtu > ndn_packet::fragment::FRAG_OVERHEAD
                    && let Ok(lp) = ndn_packet::lp::LpPacket::decode(packet.clone())
                    && lp.frag_count.unwrap_or(1) <= 1
                    && let Some(inner) = lp.fragment.as_ref()
                {
                    let seq = self.fragment_seq.fetch_add(1, Ordering::Relaxed);
                    let fragments = ndn_packet::fragment::fragment_packet(inner, mtu, seq);
                    for frag in fragments {
                        let mut frame = OutboundLpFrame::new(frag, true);
                        for feature in &self.features {
                            feature.on_egress(&mut frame, &egress_ctx);
                        }
                        transport.send_bytes(frame.wire).await?;
                    }
                    return Ok(());
                }
                let mut frame = OutboundLpFrame::new(packet, true);
                for feature in &self.features {
                    feature.on_egress(&mut frame, &egress_ctx);
                }
                return transport.send_bytes(frame.wire).await;
            }
            match transport.send_mtu() {
                Some(mtu) if packet.len() + 4 > mtu => {
                    let seq = self.fragment_seq.fetch_add(1, Ordering::Relaxed);
                    let fragments = ndn_packet::fragment::fragment_packet(&packet, mtu, seq);
                    for frag in fragments {
                        let mut frame = OutboundLpFrame::new(frag, true);
                        for feature in &self.features {
                            feature.on_egress(&mut frame, &egress_ctx);
                        }
                        transport.send_bytes(frame.wire).await?;
                    }
                    Ok(())
                }
                _ => {
                    let wire = ndn_packet::lp::encode_lp_packet(&packet);
                    let mut frame = OutboundLpFrame::new(wire, true);
                    for feature in &self.features {
                        feature.on_egress(&mut frame, &egress_ctx);
                    }
                    transport.send_bytes(frame.wire).await
                }
            }
        })
    }

    /// Batched counterpart to [`send`](LpLinkService::send). The engine hands
    /// us a packet's already-LP-framed fragments; we run the egress feature
    /// pipeline on each (exactly as the `is_lp_packet` branch of `send` does)
    /// and ship the whole burst with one [`ErasedTransport::send_batch`]. Falls
    /// back to the per-wire path if any wire is not already LP-framed.
    fn send_batch<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
        wires: &'a [Bytes],
        source: Option<FaceId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>> {
        Box::pin(async move {
            if wires.is_empty() {
                return Ok(());
            }
            if !wires.iter().all(|w| ndn_packet::lp::is_lp_packet(w)) {
                for wire in wires {
                    self.send(transport, wire.clone(), source).await?;
                }
                return Ok(());
            }
            // If any wire overruns the transport MTU, route the whole burst
            // through the per-wire `send` path, which re-fragments an oversize
            // already-LP packet to fit (the batch fast-path below assumes every
            // wire already fits one frame). Without this, an LP-framed packet
            // larger than a small-frame radio's MTU — e.g. a signed offer-board
            // segment over a Wi-Fi Aware follow-up — is shipped whole and the
            // radio rejects it ("Message length longer than supported"). This is
            // the egress path the engine actually uses (opportunistic batching),
            // so the `send`-only fix did not cover it.
            if let Some(mtu) = transport.send_mtu()
                && wires.iter().any(|w| w.len() > mtu)
            {
                for wire in wires {
                    self.send(transport, wire.clone(), source).await?;
                }
                return Ok(());
            }
            let egress_ctx = EgressCtx::new(FaceId(transport.id().0), source);
            let mut out = Vec::with_capacity(wires.len());
            for wire in wires {
                let mut frame = OutboundLpFrame::new(wire.clone(), true);
                for feature in &self.features {
                    feature.on_egress(&mut frame, &egress_ctx);
                }
                out.push(frame.wire);
            }
            transport.send_batch(&out).await
        })
    }

    fn recv<'a>(
        &'a self,
        transport: &'a dyn ErasedTransport,
    ) -> Pin<Box<dyn Future<Output = Result<LinkServiceFrame, FaceError>> + Send + 'a>> {
        Box::pin(async move {
            let (wire, addr) = transport.recv_bytes_with_addr().await?;
            let ingress_ctx = IngressCtx::new(FaceId(transport.id().0));
            let inbound = InboundLpFrame::with_addr(wire.clone(), addr.clone());
            for feature in &self.features {
                feature.on_ingress(&inbound, &ingress_ctx);
            }
            Ok(LinkServiceFrame::with_addr(wire, addr))
        })
    }

    fn lp_encodes(&self) -> bool {
        true
    }

    fn reliability_enabled(&self) -> bool {
        self.reliability.is_some()
    }

    /// Typed options flip the matching `LinkServiceFeature` at runtime.
    /// MTU and persistency are rejected here — they belong to the
    /// [`crate::transport::Transport`] surface.
    fn apply(&self, opt: FaceOption) -> Result<(), FaceOptionError> {
        match opt {
            FaceOption::LocalFields(_) => Ok(()),
            FaceOption::LpReliability(on) => {
                self.reliability_feature.set_enabled(on);
                Ok(())
            }
            FaceOption::CongestionMarking(on) => {
                self.congestion_marking_feature.set_enabled(on);
                Ok(())
            }
            FaceOption::BaseCongestionMarkingInterval(d) => {
                self.congestion_marking_feature.set_base_cong_interval(d);
                Ok(())
            }
            FaceOption::DefaultCongestionThreshold(t) => {
                self.congestion_marking_feature.set_def_cong_threshold(t);
                Ok(())
            }
            _ => Err(FaceOptionError::NotSupportedByTransport { option: opt.name() }),
        }
    }

    fn snapshot(&self) -> FaceOptions {
        FaceOptions {
            lp_reliability: self.reliability_feature.is_enabled(),
            congestion_marking: self.congestion_marking_feature.is_enabled(),
            // local_fields is engine-layer state (FaceState.flags); the
            // link service does not track it. Left at default (false) here —
            // faces/list reports the truth from the FaceState flags bitmap.
            base_congestion_marking_interval: Some(
                self.congestion_marking_feature.base_cong_interval(),
            ),
            default_congestion_threshold: Some(
                self.congestion_marking_feature.def_cong_threshold(),
            ),
            ..FaceOptions::default()
        }
    }

    fn feature_names(&self) -> Vec<&'static str> {
        self.features.iter().map(|f| f.name()).collect()
    }

    fn reliability_counters(&self) -> Option<(u64, u64)> {
        Some((
            self.reliability_feature.n_lp_resent_packets(),
            self.reliability_feature.rto_micros(),
        ))
    }

    fn congestion_counters(&self) -> Option<(u64, u64)> {
        // Egress count = marks stamped on outbound frames; ingress count
        // requires the tag-bag pass that lands with the queue-depth wiring.
        Some((self.congestion_marking_feature.n_lp_congestion_marked(), 0))
    }

    fn wire_queue_depth_fn(&self, queue_depth_fn: Arc<dyn Fn() -> u64 + Send + Sync>) {
        self.congestion_marking_feature
            .set_queue_depth_fn(queue_depth_fn);
    }

    fn reliability_feature_handle(&self) -> Option<Arc<features::ReliabilityFeature>> {
        Some(Arc::clone(&self.reliability_feature))
    }

    fn a_lal_feature_handle(&self) -> Option<Arc<features::AlalFeature>> {
        Some(Arc::clone(&self.a_lal_feature))
    }
}

/// IPC kinds (bare TLV) get [`PassthroughLinkService`]; wire kinds get
/// [`LpLinkService`] (NDNLPv2 framing) with reliability disabled. Keyed on the
/// *framing* axis ([`FaceKind::uses_lp_framing`]), not [`FaceScope`]: a loopback
/// UDP/WebTransport face is `Local` scope yet still LP-framed.
pub fn default_link_service_for_kind(kind: FaceKind) -> std::sync::Arc<dyn LinkService> {
    if kind.uses_lp_framing() {
        std::sync::Arc::new(LpLinkService::new())
    } else {
        std::sync::Arc::new(PassthroughLinkService)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::face::LinkType;
    use crate::transport::Transport;
    use std::sync::{Arc, Mutex};

    struct CaptureTransport {
        id: FaceId,
        kind: FaceKind,
        mtu: Option<usize>,
        sent: Arc<Mutex<Vec<Bytes>>>,
    }
    impl Transport for CaptureTransport {
        fn id(&self) -> FaceId {
            self.id
        }
        fn kind(&self) -> FaceKind {
            self.kind
        }
        fn link_type(&self) -> LinkType {
            LinkType::PointToPoint
        }
        fn send_mtu(&self) -> Option<usize> {
            self.mtu
        }
        async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
            self.sent.lock().unwrap().push(wire);
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            Err(FaceError::Closed)
        }
    }

    fn test_interest() -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[0xAB]);
        w.finish()
    }

    #[test]
    fn passthrough_does_not_lp_encode() {
        assert!(!PassthroughLinkService.lp_encodes());
    }

    #[test]
    fn lp_link_service_lp_encodes() {
        assert!(LpLinkService::new().lp_encodes());
    }

    #[tokio::test]
    async fn passthrough_writes_raw_lp_writes_wrapped() {
        let pkt = test_interest();
        let raw_capture = Arc::new(Mutex::new(Vec::new()));
        let lp_capture = Arc::new(Mutex::new(Vec::new()));

        let raw_tx = CaptureTransport {
            id: FaceId(1),
            kind: FaceKind::App,
            mtu: None,
            sent: Arc::clone(&raw_capture),
        };
        let lp_tx = CaptureTransport {
            id: FaceId(2),
            kind: FaceKind::Udp,
            mtu: None,
            sent: Arc::clone(&lp_capture),
        };

        PassthroughLinkService
            .send(&raw_tx, pkt.clone(), None)
            .await
            .unwrap();
        LpLinkService::new()
            .send(&lp_tx, pkt.clone(), None)
            .await
            .unwrap();

        let raw_sent = raw_capture.lock().unwrap();
        let lp_sent = lp_capture.lock().unwrap();
        assert_eq!(raw_sent.len(), 1);
        assert_eq!(raw_sent[0], pkt, "Passthrough must write raw bytes");
        assert_eq!(lp_sent.len(), 1);
        assert_eq!(
            lp_sent[0],
            ndn_packet::lp::encode_lp_packet(&pkt),
            "LpLinkService must LP-wrap before write"
        );
        assert!(ndn_packet::lp::is_lp_packet(&lp_sent[0]));
        assert!(!ndn_packet::lp::is_lp_packet(&raw_sent[0]));
    }

    #[tokio::test]
    async fn lp_link_service_fragments_at_mtu() {
        let payload = vec![0u8; 4096];
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_tlv(0x05, &payload);
        let big = w.finish();

        let capture = Arc::new(Mutex::new(Vec::new()));
        let tx = CaptureTransport {
            id: FaceId(3),
            kind: FaceKind::Udp,
            mtu: Some(1400),
            sent: Arc::clone(&capture),
        };
        LpLinkService::new()
            .send(&tx, big.clone(), None)
            .await
            .unwrap();

        let sent = capture.lock().unwrap();
        assert!(
            sent.len() > 1,
            "oversize packet must produce multiple fragments"
        );
        for frag in sent.iter() {
            assert!(frag.len() <= 1400, "fragment exceeds MTU");
            assert!(ndn_packet::lp::is_lp_packet(frag));
        }
    }

    #[tokio::test]
    async fn lp_link_service_passes_through_already_lp() {
        let wrapped = ndn_packet::lp::encode_lp_packet(&test_interest());
        let capture = Arc::new(Mutex::new(Vec::new()));
        let tx = CaptureTransport {
            id: FaceId(4),
            kind: FaceKind::Udp,
            mtu: None,
            sent: Arc::clone(&capture),
        };
        LpLinkService::new()
            .send(&tx, wrapped.clone(), None)
            .await
            .unwrap();
        let sent = capture.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], wrapped);
    }

    #[tokio::test]
    async fn lp_link_service_refragments_oversize_already_lp() {
        // A *complete* LP packet (network packet wrapped with link-local fields)
        // bigger than the MTU must be re-fragmented, not sent whole — otherwise a
        // small-frame radio silently drops the oversize frame.
        let payload = vec![0u8; 4096];
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_tlv(0x05, &payload);
        let big = w.finish();
        let wrapped = ndn_packet::lp::encode_lp_packet(&big);
        assert!(ndn_packet::lp::is_lp_packet(&wrapped));
        assert!(
            wrapped.len() > 1400,
            "wrapped packet should exceed the test MTU"
        );

        let capture = Arc::new(Mutex::new(Vec::new()));
        let tx = CaptureTransport {
            id: FaceId(5),
            kind: FaceKind::Udp,
            mtu: Some(1400),
            sent: Arc::clone(&capture),
        };
        LpLinkService::new()
            .send(&tx, wrapped.clone(), None)
            .await
            .unwrap();

        let sent = capture.lock().unwrap();
        assert!(
            sent.len() > 1,
            "oversize framed packet must re-fragment, not send whole"
        );
        for frag in sent.iter() {
            assert!(frag.len() <= 1400, "re-fragment exceeds MTU");
            assert!(ndn_packet::lp::is_lp_packet(frag));
        }
    }

    #[test]
    fn congestion_params_apply_and_snapshot() {
        // faces/update routes BaseCongestionMarkingInterval / DefaultCongestionThreshold
        // here; the values must take effect and be reported in the snapshot.
        let ls = LpLinkService::new();
        ls.apply(FaceOption::BaseCongestionMarkingInterval(
            std::time::Duration::from_micros(50_000),
        ))
        .unwrap();
        ls.apply(FaceOption::DefaultCongestionThreshold(4321))
            .unwrap();
        let snap = ls.snapshot();
        assert_eq!(
            snap.base_congestion_marking_interval,
            Some(std::time::Duration::from_micros(50_000))
        );
        assert_eq!(snap.default_congestion_threshold, Some(4321));
    }

    #[test]
    fn default_link_service_matches_framing() {
        // Wire kinds (incl. WS/WT/WebRTC) frame with NDNLPv2.
        for kind in [
            FaceKind::Udp,
            FaceKind::Tcp,
            FaceKind::Ethernet,
            FaceKind::EtherMulticast,
            FaceKind::Serial,
            FaceKind::Multicast,
            FaceKind::WebSocket,
            FaceKind::WebTransport,
            FaceKind::WebRtc,
        ] {
            let svc = default_link_service_for_kind(kind);
            assert!(svc.lp_encodes(), "{kind:?} is a wire kind → LpLinkService");
        }

        // IPC kinds carry bare TLV.
        for kind in [
            FaceKind::Unix,
            FaceKind::App,
            FaceKind::Shm,
            FaceKind::Internal,
            FaceKind::Compute,
            FaceKind::Management,
        ] {
            let svc = default_link_service_for_kind(kind);
            assert!(
                !svc.lp_encodes(),
                "{kind:?} is an IPC kind → PassthroughLinkService"
            );
        }
    }
}
