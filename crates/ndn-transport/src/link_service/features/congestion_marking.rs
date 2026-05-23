//! CoDel-style producer-side congestion marking. When egress queue depth
//! stays above `def_cong_threshold` for at least `base_cong_interval`,
//! the feature stamps an LP `CongestionMark` (TLV 0x0340) on the next
//! outbound frame.
//!
//! The engine injects a `queue_depth_fn` closure returning current queue
//! depth in items; this keeps the feature free of an `ndn-engine` dep
//! and wasm-portable.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use web_time::Instant;

use ndn_tlv::{TlvWriter, read_varu64};

use super::super::feature::{
    EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame,
};

/// LP `CongestionMark` TLV-TYPE (NDNLPv2 §3.3).
const LP_CONGESTION_MARK_TLV: u64 = 0x0340;
const LP_PACKET_TLV: u8 = 0x64;

/// NFD-default `BaseCongestionMarkingInterval`.
const DEFAULT_BASE_CONG_INTERVAL: Duration = Duration::from_millis(100);
/// NFD-default `DefaultCongestionThreshold` (64 KiB; re-interpreted as
/// item count when the queue-depth closure returns counts).
const DEFAULT_DEF_CONG_THRESHOLD: u64 = 64 * 1024;
/// `HighCongestion` — any value > 0 signals above-threshold.
const CONGESTION_MARK_VALUE: u64 = 1;

/// Returns current egress queue depth in items.
type QueueDepthFn = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct CongestionMarkingFeature {
    enabled: AtomicBool,
    base_cong_interval: Mutex<Duration>,
    def_cong_threshold: AtomicU64,
    /// Earliest moment the queue was observed at-or-above threshold
    /// without dropping below; `None` means currently below.
    above_threshold_since: Mutex<Option<Instant>>,
    queue_depth_fn: Mutex<QueueDepthFn>,
    n_lp_congestion_marked: AtomicU64,
}

impl CongestionMarkingFeature {
    pub fn new() -> Self {
        let inert: QueueDepthFn = Arc::new(|| 0u64);
        Self {
            enabled: AtomicBool::new(false),
            base_cong_interval: Mutex::new(DEFAULT_BASE_CONG_INTERVAL),
            def_cong_threshold: AtomicU64::new(DEFAULT_DEF_CONG_THRESHOLD),
            above_threshold_since: Mutex::new(None),
            queue_depth_fn: Mutex::new(inert),
            n_lp_congestion_marked: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        if !enabled {
            *self.above_threshold_since.lock().unwrap() = None;
        }
    }

    pub fn set_base_cong_interval(&self, interval: Duration) {
        *self.base_cong_interval.lock().unwrap() = interval;
    }

    pub fn set_def_cong_threshold(&self, threshold: u64) {
        self.def_cong_threshold.store(threshold, Ordering::Release);
    }

    pub fn def_cong_threshold(&self) -> u64 {
        self.def_cong_threshold.load(Ordering::Acquire)
    }

    pub fn base_cong_interval(&self) -> Duration {
        *self.base_cong_interval.lock().unwrap()
    }

    pub fn set_queue_depth_fn(&self, f: QueueDepthFn) {
        *self.queue_depth_fn.lock().unwrap() = f;
    }

    pub fn n_lp_congestion_marked(&self) -> u64 {
        self.n_lp_congestion_marked.load(Ordering::Relaxed)
    }

    /// CoDel core: decides whether to mark this frame given live queue depth.
    fn should_mark_now(&self, depth: u64, now: Instant) -> bool {
        let threshold = self.def_cong_threshold.load(Ordering::Acquire);
        if depth < threshold {
            *self.above_threshold_since.lock().unwrap() = None;
            return false;
        }
        let interval = *self.base_cong_interval.lock().unwrap();
        let mut since = self.above_threshold_since.lock().unwrap();
        match *since {
            None => {
                // NFD CoDel waits one interval before the first mark.
                *since = Some(now);
                false
            }
            Some(t0) => {
                if now.duration_since(t0) >= interval {
                    *since = Some(now);
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl Default for CongestionMarkingFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkServiceFeature for CongestionMarkingFeature {
    fn name(&self) -> &'static str {
        "congestion-marking"
    }

    fn on_egress(&self, frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {
        if !self.is_enabled() {
            return;
        }
        if !frame.is_lp_wrapped {
            return;
        }
        let depth = (self.queue_depth_fn.lock().unwrap())();
        if !self.should_mark_now(depth, Instant::now()) {
            return;
        }
        if let Some(new_wire) = splice_congestion_mark(&frame.wire, CONGESTION_MARK_VALUE) {
            frame.wire = new_wire;
            self.n_lp_congestion_marked.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_ingress(&self, _frame: &InboundLpFrame, _ctx: &IngressCtx) {
        // Ingress marks are surfaced via the inbound `congestion_mark`
        // typed slot for consumer-side controllers; nothing to do here.
    }
}

/// Prepend an LP `CongestionMark` TLV to the payload of an already-LP-wrapped
/// wire (NFD's LP decoder is order-agnostic). Returns `None` on parse error;
/// callers pass through unchanged.
fn splice_congestion_mark(lp_wire: &[u8], mark: u64) -> Option<Bytes> {
    if lp_wire.first() != Some(&LP_PACKET_TLV) {
        return None;
    }
    let (typ, n_t) = read_varu64(lp_wire).ok()?;
    if typ != LP_PACKET_TLV as u64 {
        return None;
    }
    let (len_v, n_l) = read_varu64(&lp_wire[n_t..]).ok()?;
    let payload_start = n_t + n_l;
    let payload_end = payload_start.checked_add(len_v as usize)?;
    if payload_end > lp_wire.len() {
        return None;
    }
    let existing_payload = &lp_wire[payload_start..payload_end];

    // Build the CongestionMark TLV body once.
    let mark_value = encode_non_neg_int(mark);
    let mut cm_tlv = BytesMut::with_capacity(8 + mark_value.len());
    write_varu64(&mut cm_tlv, LP_CONGESTION_MARK_TLV);
    write_varu64(&mut cm_tlv, mark_value.len() as u64);
    cm_tlv.extend_from_slice(&mark_value);

    let new_payload_len = (cm_tlv.len() + existing_payload.len()) as u64;
    let mut out = TlvWriter::new();
    out.write_nested(LP_PACKET_TLV as u64, |w| {
        w.write_raw(&cm_tlv);
        w.write_raw(existing_payload);
    });
    let _ = new_payload_len;
    Some(out.finish())
}

fn encode_non_neg_int(v: u64) -> Vec<u8> {
    if v <= 0xFF {
        vec![v as u8]
    } else if v <= 0xFFFF {
        (v as u16).to_be_bytes().to_vec()
    } else if v <= 0xFFFF_FFFF {
        (v as u32).to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}

fn write_varu64(buf: &mut BytesMut, v: u64) {
    use bytes::BufMut;
    if v <= 252 {
        buf.put_u8(v as u8);
    } else if v <= 0xFFFF {
        buf.put_u8(0xFD);
        buf.put_u16(v as u16);
    } else if v <= 0xFFFF_FFFF {
        buf.put_u8(0xFE);
        buf.put_u32(v as u32);
    } else {
        buf.put_u8(0xFF);
        buf.put_u64(v);
    }
}

pub type SharedCongestionMarkingFeature = Arc<CongestionMarkingFeature>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FaceId;
    use ndn_packet::lp::{LpPacket, encode_lp_packet};
    use std::sync::atomic::AtomicU64;

    fn bare_interest() -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[0xAB]);
        w.finish()
    }

    #[test]
    fn apply_flips_congestion_marking_feature() {
        let f = CongestionMarkingFeature::new();
        assert!(!f.is_enabled());
        f.set_enabled(true);
        assert!(f.is_enabled());
        f.set_enabled(false);
        assert!(!f.is_enabled());
    }

    #[test]
    fn congestion_mark_propagates_on_saturation() {
        let f = CongestionMarkingFeature::new();
        f.set_enabled(true);
        f.set_def_cong_threshold(4);
        f.set_base_cong_interval(Duration::from_millis(0));

        let depth = Arc::new(AtomicU64::new(64));
        let depth_for_closure = Arc::clone(&depth);
        f.set_queue_depth_fn(Arc::new(move || depth_for_closure.load(Ordering::Relaxed)));

        // First call seeds the above-threshold timer; second marks.
        let mut frame1 = OutboundLpFrame::new(encode_lp_packet(&bare_interest()), true);
        f.on_egress(&mut frame1, &EgressCtx::new(FaceId(1), None));
        let mut frame2 = OutboundLpFrame::new(encode_lp_packet(&bare_interest()), true);
        f.on_egress(&mut frame2, &EgressCtx::new(FaceId(1), None));

        assert!(f.n_lp_congestion_marked() >= 1);
        let decoded = LpPacket::decode(frame2.wire.clone()).expect("LP decode");
        assert_eq!(decoded.congestion_mark, Some(CONGESTION_MARK_VALUE));
    }

    #[test]
    fn congestion_mark_silent_when_below_threshold() {
        let f = CongestionMarkingFeature::new();
        f.set_enabled(true);
        f.set_def_cong_threshold(100);
        f.set_queue_depth_fn(Arc::new(|| 1));

        let lp_wire = encode_lp_packet(&bare_interest());
        let mut frame = OutboundLpFrame::new(lp_wire.clone(), true);
        f.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));

        assert_eq!(f.n_lp_congestion_marked(), 0);
        assert_eq!(frame.wire, lp_wire);
    }

    #[test]
    fn congestion_mark_disabled_is_inert() {
        let f = CongestionMarkingFeature::new();
        f.set_def_cong_threshold(4);
        f.set_queue_depth_fn(Arc::new(|| 64));

        let lp_wire = encode_lp_packet(&bare_interest());
        let mut frame = OutboundLpFrame::new(lp_wire.clone(), true);
        f.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));

        assert_eq!(f.n_lp_congestion_marked(), 0);
        assert_eq!(frame.wire, lp_wire);
    }

    #[test]
    fn splice_preserves_existing_payload() {
        let lp_wire = encode_lp_packet(&bare_interest());
        let spliced = splice_congestion_mark(&lp_wire, 1).expect("splice");
        let decoded = LpPacket::decode(spliced).expect("decode");
        assert_eq!(decoded.congestion_mark, Some(1));
        let frag = decoded.fragment.expect("fragment present");
        assert_eq!(frag, bare_interest());
    }
}
