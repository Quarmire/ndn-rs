//! NDNLPv2 per-hop reliability behind the [`LinkServiceFeature`] trait.
//! Wraps [`crate::reliability::LpReliability`].
//!
//! - `on_egress` records already-LP-wrapped wires for retransmission.
//! - `on_ingress` feeds inbound LP bytes so Acks consume tracked entries.
//! - `take_retransmissions` pulls retx wires and bumps `n_lp_resent_packets`.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use super::super::feature::{
    EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame,
};
use crate::reliability::{LpReliability, ReliabilityConfig};

const DEFAULT_RELIABILITY_MTU: usize = 8800;

/// Per-feature reliability state. Constructed disabled; flipping the
/// switch does not lose unacked entries.
pub struct ReliabilityFeature {
    enabled: AtomicBool,
    state: Mutex<LpReliability>,
    /// Total LP frames re-emitted by `take_retransmissions`.
    n_lp_resent_packets: AtomicU64,
}

impl ReliabilityFeature {
    pub fn new() -> Self {
        Self::with_config(ReliabilityConfig::default())
    }

    pub fn with_config(config: ReliabilityConfig) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            state: Mutex::new(LpReliability::from_config(DEFAULT_RELIABILITY_MTU, config)),
            n_lp_resent_packets: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn n_lp_resent_packets(&self) -> u64 {
        self.n_lp_resent_packets.load(Ordering::Relaxed)
    }

    /// Current RTO in microseconds. Surfaced on `faces/list` as `rto_micros`
    /// (TLV 0xE2).
    pub fn rto_micros(&self) -> u64 {
        self.state.lock().unwrap().rto_us()
    }

    /// LP wire bytes due for retransmission. Increments
    /// [`Self::n_lp_resent_packets`]. Empty when disabled.
    pub fn take_retransmissions(&self) -> Vec<Bytes> {
        if !self.is_enabled() {
            return Vec::new();
        }
        let mut s = self.state.lock().unwrap();
        let retx = s.check_retransmit();
        if !retx.is_empty() {
            self.n_lp_resent_packets
                .fetch_add(retx.len() as u64, Ordering::Relaxed);
        }
        retx
    }

    /// Canonically frame a bare network packet for reliable egress: assign a
    /// `TxSequence`, piggyback any pending Acks, and buffer for retransmission
    /// (`LpReliability::on_send`). The single egress framer (the per-face send
    /// loop) calls this — instead of `frame_with_intent` — when reliability is
    /// enabled. Returns the wire frame(s); empty when disabled.
    pub fn frame(&self, payload: &[u8]) -> Vec<Bytes> {
        if !self.is_enabled() {
            return Vec::new();
        }
        self.state.lock().unwrap().on_send(payload)
    }

    /// Standalone Ack frame for received reliable frames not yet piggybacked,
    /// pumped on the retx tick alongside [`Self::take_retransmissions`]. `None`
    /// when disabled or nothing to Ack.
    pub fn take_acks(&self) -> Option<Bytes> {
        if !self.is_enabled() {
            return None;
        }
        self.state.lock().unwrap().flush_acks()
    }

    /// Feed inbound wire bytes so peer Acks clear tracked entries and received
    /// reliable frames queue an Ack. For the discovery `inject_packet` recv
    /// path, which does not run the LinkService feature pipeline; the socket
    /// recv path drives the same state via [`LinkServiceFeature::on_ingress`].
    pub fn note_receive(&self, raw: &[u8]) {
        if !self.is_enabled() {
            return;
        }
        self.state.lock().unwrap().on_receive(raw);
    }
}

impl Default for ReliabilityFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkServiceFeature for ReliabilityFeature {
    fn name(&self) -> &'static str {
        "reliability"
    }

    /// Reliable egress framing happens in the send loop ([`Self::frame`], which
    /// assigns a `TxSequence`), not here — by `on_egress` time the wire is
    /// already framed (or a retransmission). No-op; the feature stays in the
    /// pipeline only for `on_ingress` (Ack consumption on socket faces).
    fn on_egress(&self, _frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {}

    fn on_ingress(&self, frame: &InboundLpFrame, _ctx: &IngressCtx) {
        if !self.is_enabled() {
            return;
        }
        let mut s = self.state.lock().unwrap();
        s.on_receive(&frame.wire);
    }
}

/// Shared handle the engine's tick loop holds.
pub type SharedReliabilityFeature = Arc<ReliabilityFeature>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::{ReliabilityConfig, RtoStrategy};
    use std::thread;
    use std::time::Duration;

    fn bare_interest() -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[0xAB]);
        w.finish()
    }

    #[test]
    fn apply_flips_reliability_feature() {
        let f = ReliabilityFeature::new();
        assert!(!f.is_enabled(), "starts disabled");
        f.set_enabled(true);
        assert!(f.is_enabled(), "set_enabled(true) flips on");
        f.set_enabled(false);
        assert!(!f.is_enabled(), "set_enabled(false) flips off");
    }

    #[test]
    fn reliability_feature_tracks_for_retx() {
        let config = ReliabilityConfig {
            rto_strategy: RtoStrategy::Fixed { rto_us: 5_000 },
            max_retries: 3,
            max_unacked: 256,
            max_retx_per_tick: 8,
        };
        let f = ReliabilityFeature::with_config(config);
        f.set_enabled(true);

        // Canonical egress framing: each `frame` call assigns a TxSequence and
        // buffers the wire for retransmission.
        for _ in 0..3 {
            let frames = f.frame(&bare_interest());
            assert_eq!(frames.len(), 1, "small packet → one reliable frame");
        }

        thread::sleep(Duration::from_millis(20));
        let retx = f.take_retransmissions();
        assert!(!retx.is_empty(), "retransmissions must fire after RTO");
        assert!(
            f.n_lp_resent_packets() >= retx.len() as u64,
            "n_lp_resent_packets must reflect retx count",
        );
    }

    #[test]
    fn reliability_feature_disabled_is_inert() {
        let f = ReliabilityFeature::new();
        // Disabled: `frame` returns nothing and tracks nothing.
        assert!(f.frame(&bare_interest()).is_empty());

        thread::sleep(Duration::from_millis(20));
        let retx = f.take_retransmissions();
        assert!(retx.is_empty(), "disabled feature must not retransmit");
        assert_eq!(f.n_lp_resent_packets(), 0);
    }
}
