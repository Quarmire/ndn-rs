//! A-LAL (Ad-hoc Link Adaptation Layer) `LinkServiceFeature` — egress presence
//! piggyback + ingress neighbor observation for CCLF.
//!
//! On egress (when a presence source is configured and the frame is LP-wrapped)
//! it splices this node's presence — its encoded `Name` wire — onto the
//! outgoing frame, so any neighbor overhearing forwarded traffic learns this
//! node at the **network layer** for ~free (no dedicated beacon; the
//! airtime-efficient path). On ingress it extracts a peer's presence and hands
//! `(face, name_wire)` to a sink the upper layer wires to the strategy's
//! neighbor observer — after trust-schema validation, which is the app's
//! responsibility. Density is thus a network-layer signal, independent of
//! MAC/host addressing.
//!
//! Like [`super::trace_context`], a source/sink may be set **per face** or
//! installed **process-globally**; the per-face value takes priority. The
//! feature is **inert** (no wire change, no sink call) until something is
//! installed, so a default-composed face does nothing differently. The global
//! seam is how the native engine wires CCLF without threading handles: the
//! `CclfStrategy` installs the global ingress sink (→ its neighbor table) and
//! the app installs the global presence source (the node's Name).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

// `web_time::Instant` is `std::time::Instant` on native and a `performance.now()`
// shim on wasm32 — raw `std::time::Instant::now()` panics in the browser
// ("time not implemented"), which broke wasm face setup (e.g. the dioxus
// onboarding/join path).
use web_time::Instant;

use bytes::Bytes;
use ndn_packet::lp::{TLV_AL_PRESENCE, extract_lp_header, splice_lp_header};

use super::super::{EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame};
use crate::face::FaceId;

/// Egress presence provider: returns this node's encoded `Name` wire to
/// advertise, or `None` to advertise nothing this frame.
pub type PresenceSource = Arc<dyn Fn() -> Option<Bytes> + Send + Sync>;

/// Ingress sink invoked with the egress `face` the frame arrived on and the
/// peer's encoded `Name` wire. The upper layer wires this to the strategy's
/// neighbor observer (after trust-schema validation).
pub type PresenceSink = Arc<dyn Fn(FaceId, Bytes) + Send + Sync>;

static GLOBAL_PRESENCE_SOURCE: OnceLock<PresenceSource> = OnceLock::new();
static GLOBAL_INGRESS_SINK: OnceLock<PresenceSink> = OnceLock::new();

/// Install the process-global egress presence source (the node's `Name`).
/// First writer wins (mirrors [`super::trace_context`]).
pub fn install_global_presence_source(source: PresenceSource) {
    let _ = GLOBAL_PRESENCE_SOURCE.set(source);
}

/// Install the process-global ingress neighbor-observation sink.
pub fn install_global_presence_sink(sink: PresenceSink) {
    let _ = GLOBAL_INGRESS_SINK.set(sink);
}

/// A-LAL feature: presence piggyback (egress) + neighbor observation (ingress)
/// + idle-fallback beacon (per-face engine tick).
pub struct AlalFeature {
    /// Per-face presence override (a fixed Name wire); falls back to the global
    /// source when unset.
    presence: RwLock<Option<Bytes>>,
    /// Per-face ingress sink override; falls back to the global sink.
    sink: RwLock<Option<PresenceSink>>,
    /// Tracks whether this face has ever observed/advertised (diagnostics only).
    active: AtomicBool,
    /// Source of a complete (app-signed) beacon wire for the idle fallback.
    beacon: RwLock<Option<PresenceSource>>,
    /// Beacon interval in ms; `0` disables the idle beacon (the default).
    beacon_interval_ms: AtomicU64,
    /// Per-face monotonic clock origin + last-egress stamp (ms since origin).
    start: Instant,
    last_activity_ms: AtomicU64,
}

impl AlalFeature {
    pub fn new() -> Self {
        Self {
            presence: RwLock::new(None),
            sink: RwLock::new(None),
            active: AtomicBool::new(false),
            beacon: RwLock::new(None),
            beacon_interval_ms: AtomicU64::new(0),
            start: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Install the idle-fallback beacon: `source` yields a complete (app-signed)
    /// beacon wire, emitted on a face that has been silent for `interval_ms`.
    /// `interval_ms = 0` disables it. Piggybacked presence covers active faces;
    /// this only fires when the face is otherwise idle.
    pub fn set_beacon(&self, source: Option<PresenceSource>, interval_ms: u64) {
        if let Ok(mut g) = self.beacon.write() {
            *g = source;
        }
        self.beacon_interval_ms
            .store(interval_ms, Ordering::Relaxed);
    }

    /// Whether the idle beacon is enabled (so the engine tick should run).
    pub fn is_beacon_enabled(&self) -> bool {
        self.beacon_interval_ms.load(Ordering::Relaxed) > 0
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn note_activity(&self) {
        self.last_activity_ms
            .store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// If the idle beacon is due (enabled, a source is set, and the face has
    /// been silent for the interval), return the beacon wire to send and reset
    /// the idle timer. Called by the per-face engine tick.
    pub fn due_beacon(&self) -> Option<Bytes> {
        let interval = self.beacon_interval_ms.load(Ordering::Relaxed);
        if interval == 0 {
            return None;
        }
        let now = self.elapsed_ms();
        if now.saturating_sub(self.last_activity_ms.load(Ordering::Relaxed)) < interval {
            return None;
        }
        let wire = self
            .beacon
            .read()
            .ok()
            .and_then(|g| g.as_ref().and_then(|s| s()));
        if wire.is_some() {
            self.last_activity_ms.store(now, Ordering::Relaxed);
        }
        wire
    }

    /// Set a per-face presence override (its encoded `Name` wire).
    pub fn set_presence(&self, name_wire: Option<Bytes>) {
        if let Ok(mut g) = self.presence.write() {
            *g = name_wire;
        }
    }

    /// Set a per-face ingress sink override.
    pub fn set_sink(&self, sink: Option<PresenceSink>) {
        if let Ok(mut g) = self.sink.write() {
            *g = sink;
        }
    }

    fn presence_wire(&self) -> Option<Bytes> {
        if let Ok(g) = self.presence.read()
            && let Some(p) = g.clone()
        {
            return Some(p);
        }
        GLOBAL_PRESENCE_SOURCE.get().and_then(|s| s())
    }

    fn ingress_sink(&self) -> Option<PresenceSink> {
        if let Ok(g) = self.sink.read()
            && let Some(s) = g.as_ref().cloned()
        {
            return Some(s);
        }
        GLOBAL_INGRESS_SINK.get().cloned()
    }
}

impl Default for AlalFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AlalFeature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AlalFeature")
            .field("active", &self.active.load(Ordering::Relaxed))
            .finish()
    }
}

impl LinkServiceFeature for AlalFeature {
    fn name(&self) -> &'static str {
        "a-lal"
    }

    fn on_egress(&self, frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {
        // Any egress counts as activity, so the idle beacon only fires on a
        // genuinely silent face.
        self.note_activity();
        if !frame.is_lp_wrapped {
            return;
        }
        let Some(name_wire) = self.presence_wire() else {
            return;
        };
        self.active.store(true, Ordering::Relaxed);
        frame.wire = splice_lp_header(frame.wire.clone(), TLV_AL_PRESENCE, &name_wire);
    }

    fn on_ingress(&self, frame: &InboundLpFrame, ctx: &IngressCtx) {
        let Some(sink) = self.ingress_sink() else {
            return;
        };
        if let Some(name_wire) = extract_lp_header(&frame.wire, TLV_AL_PRESENCE) {
            self.active.store(true, Ordering::Relaxed);
            sink(ctx.face_id, name_wire);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;

    fn lp_wire(interest: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::LP_PACKET, |w| {
            w.write_tlv(ndn_packet::tlv_type::LP_FRAGMENT, interest);
        });
        w.finish()
    }

    #[test]
    fn inert_until_presence_set() {
        let f = AlalFeature::new();
        let original = lp_wire(b"\x05\x02\x00\x00");
        let mut frame = OutboundLpFrame::new(original.clone(), true);
        f.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
        assert_eq!(frame.wire, original, "no presence source → wire untouched");
    }

    #[test]
    fn per_face_presence_splices_on_egress() {
        let f = AlalFeature::new();
        f.set_presence(Some(Bytes::from_static(b"node-A")));
        let mut frame = OutboundLpFrame::new(lp_wire(b"\x05\x02\x00\x00"), true);
        f.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
        assert_eq!(
            extract_lp_header(&frame.wire, TLV_AL_PRESENCE).as_deref(),
            Some(&b"node-A"[..]),
        );
    }

    #[test]
    fn per_face_sink_gets_face_and_name_on_ingress() {
        use std::sync::Mutex;
        let f = AlalFeature::new();
        let seen: Arc<Mutex<Vec<(u64, Bytes)>>> = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        f.set_sink(Some(Arc::new(move |face: FaceId, name: Bytes| {
            seen2.lock().unwrap().push((face.0, name));
        })));
        let spliced = splice_lp_header(lp_wire(b"\x05\x02\x00\x00"), TLV_AL_PRESENCE, b"peer-B");
        f.on_ingress(&InboundLpFrame::bare(spliced), &IngressCtx::new(FaceId(9)));
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 9);
        assert_eq!(got[0].1.as_ref(), b"peer-B");
    }

    #[test]
    fn idle_beacon_due_after_interval_not_before() {
        let f = AlalFeature::new();
        assert!(f.due_beacon().is_none(), "no beacon source → never due");
        // Fresh face, long interval → not idle long enough yet.
        f.set_beacon(
            Some(Arc::new(|| Some(Bytes::from_static(b"beacon")))),
            10_000,
        );
        assert!(f.due_beacon().is_none(), "not idle beyond interval");
        // Short interval, wait past it → due once, then resets.
        f.set_beacon(Some(Arc::new(|| Some(Bytes::from_static(b"beacon")))), 2);
        std::thread::sleep(std::time::Duration::from_millis(8));
        assert_eq!(
            f.due_beacon().as_deref(),
            Some(&b"beacon"[..]),
            "idle → beacon due"
        );
    }

    #[test]
    fn egress_activity_resets_idle_beacon() {
        let f = AlalFeature::new();
        f.set_beacon(Some(Arc::new(|| Some(Bytes::from_static(b"b")))), 10_000);
        f.note_activity();
        assert!(f.due_beacon().is_none(), "recent activity → beacon not due");
    }

    #[test]
    fn ingress_without_presence_does_not_invoke_sink() {
        use std::sync::atomic::AtomicU32;
        let f = AlalFeature::new();
        let calls = Arc::new(AtomicU32::new(0));
        let c2 = Arc::clone(&calls);
        f.set_sink(Some(Arc::new(move |_f, _n| {
            c2.fetch_add(1, Ordering::Relaxed);
        })));
        f.on_ingress(
            &InboundLpFrame::bare(lp_wire(b"\x05\x02\x00\x00")),
            &IngressCtx::new(FaceId(9)),
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "no presence → no sink call"
        );
    }
}
