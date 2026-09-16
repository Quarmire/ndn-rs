//! NDNLPv2 per-hop reliability behind the [`LinkServiceFeature`] trait.
//! Wraps [`crate::reliability::LpReliability`].
//!
//! - `on_egress` records already-LP-wrapped wires for retransmission.
//! - `on_ingress` feeds inbound LP bytes so Acks consume tracked entries.
//! - `take_retransmissions` pulls retx wires and bumps `n_lp_resent_packets`.

use core::sync::atomic::{AtomicBool, Ordering};
use portable_atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use super::super::feature::{
    EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame,
};
use crate::reliability::{LpReliability, ReliabilityConfig};

/// LP fragmentation threshold.
///
/// 8800 — the max NDN packet size, i.e. effectively "do not fragment here".
///
/// This was briefly lowered to 1452 to stop UDP faces handing oversized
/// datagrams to IP (measured 76% IP-reassembly failure on a Wi-Fi fleet). That
/// was the wrong place to fix it: the threshold is GLOBAL, so it also applied
/// to the local unix app socket, where fragmentation is meaningless (a stream
/// transport the kernel already segments) and actively harmful — the
/// application's reader desynchronised and every agent crash-looped on
/// `Expecting LpPacket element, but TLV has type 140`.
///
/// A datagram-only fragmentation limit has to be attached to the FACE, not to
/// this shared constant. Until that exists, keep the safe default: a stream
/// face is never corrupted, and the two defects that actually broke NDNSF on
/// this fabric were the PSDC decode rejection and config routes missing
/// CHILD_INHERIT, neither of which is about MTU.
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

    /// Fragmentation threshold for this face. See `LpReliability::set_mtu`.
    /// Applied by the engine when a face is wired, from the face's own kind.
    pub fn set_mtu(&self, mtu: usize) {
        self.state.lock().unwrap().set_mtu(mtu);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    /// Frames sent with a `TxSequence` that are not yet Acked (still owed a
    /// retransmission if their RTO expires).
    pub fn unacked_count(&self) -> usize {
        self.state.lock().unwrap().unacked_count()
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
    /// [`Self::n_lp_resent_packets`].
    ///
    /// NOT gated on `is_enabled`: like [`Self::take_acks`], this is a duty owed
    /// for frames we already put on the wire with a `TxSequence`. Fragmented
    /// egress is tracked via [`Self::frame_fragments`] regardless of the
    /// enabled flag (a lost fragment destroys the whole packet and nothing
    /// below us can repair it), so gating here would strand those frames
    /// un-retransmitted. Returns empty when nothing is tracked.
    pub fn take_retransmissions(&self) -> Vec<Bytes> {
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

    /// Fragment `payload` to `mtu` for reliable egress: every fragment gets its
    /// own `TxSequence` and is buffered for retransmission.
    ///
    /// This is the ONLY safe way to put a fragmented packet on a datagram face.
    /// A packet split into N fragments is lost if ANY one of them is lost, and
    /// no layer below can repair it -- so fragmenting without `TxSequence`
    /// turns a p% frame loss into a 1-(1-p)^N packet loss with no recovery
    /// path. Measured on the miniMUAS Wi-Fi fleet: ~5% frame loss became 26%
    /// packet loss across 6-fragment NDNSF mapping blocks, of which 0% were
    /// recoverable because the fragments carried no `TxSequence`.
    ///
    /// NOT gated on `is_enabled` -- see [`Self::take_retransmissions`].
    pub fn frame_fragments(&self, payload: &[u8], mtu: usize) -> Vec<Bytes> {
        let mut s = self.state.lock().unwrap();
        s.set_mtu(mtu);
        s.on_send(payload)
    }

    /// Standalone Ack frame for received reliable frames not yet piggybacked,
    /// pumped on the retx tick alongside [`Self::take_retransmissions`]. `None`
    /// when there is nothing to Ack.
    ///
    /// NOT gated on `is_enabled`: see [`Self::on_ingress`]. Acking is a
    /// receiver-side duty owed to whoever sent us a TxSequence, independent of
    /// whether WE transmit reliably.
    pub fn take_acks(&self) -> Option<Bytes> {
        self.state.lock().unwrap().flush_acks()
    }

    /// Feed inbound wire bytes so peer Acks clear tracked entries and received
    /// reliable frames queue an Ack. For the discovery `inject_packet` recv
    /// path, which does not run the LinkService feature pipeline; the socket
    /// recv path drives the same state via [`LinkServiceFeature::on_ingress`].
    pub fn note_receive(&self, raw: &[u8]) {
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

    /// Consume inbound Acks and queue Acks for inbound reliable frames —
    /// **regardless of `is_enabled`**.
    ///
    /// LpReliability is UNIDIRECTIONAL: the sender opts in by attaching a
    /// TxSequence, and a receiver that implements the feature owes it an Ack.
    /// Gating ingress on our own transmit-side setting made a one-sided
    /// configuration fail catastrophically instead of merely being one-sided:
    /// a face with reliability off silently dropped every peer TxSequence, so
    /// the peer never got an Ack and retransmitted EVERY packet at its RTO,
    /// which never adapted (no Ack, no RTT sample). Measured on a 3-drone
    /// fleet: the GCS's peer face sat at the initial 1 s RTO having resent
    /// 4217 of 4257 Interests (99%), against a drone whose own face had
    /// adapted to 200 ms and resent 2.3%. The link was not lossy; the two ends
    /// simply disagreed about who had the feature on.
    ///
    /// Sending is still opt-in: `frame` and `take_retransmissions` stay gated,
    /// so a disabled face never attaches a TxSequence or retransmits its own
    /// traffic. It only answers.
    fn on_ingress(&self, frame: &InboundLpFrame, _ctx: &IngressCtx) {
        let mut s = self.state.lock().unwrap();
        s.on_receive(&frame.wire);
    }
}

/// Shared handle the engine's tick loop holds.
pub type SharedReliabilityFeature = Arc<ReliabilityFeature>;

#[cfg(test)]
mod tests {

    #[test]
    fn disabled_receiver_still_acks_a_reliable_sender() {
        // LpReliability is unidirectional. A receiver with its own transmit
        // side OFF must still Ack what it is sent, or the sender never gets an
        // Ack, never takes an RTT sample, keeps its initial RTO and
        // retransmits everything forever. Field-measured: 4217/4257 (99%) of
        // Interests resent at a stuck 1 s RTO across a link that was not lossy.
        let sender = ReliabilityFeature::new();
        sender.set_enabled(true);
        let receiver = ReliabilityFeature::new();
        // receiver deliberately left DISABLED

        let wires = sender.frame(b"hello");
        assert!(!wires.is_empty(), "enabled sender frames reliably");

        // receiver must queue an Ack even though it is disabled
        receiver.note_receive(&wires[0]);
        let ack = receiver
            .take_acks()
            .expect("a disabled receiver still owes the sender an Ack");

        // and that Ack must clear the sender's unacked entry, so nothing is
        // due for retransmission
        sender.note_receive(&ack);
        assert!(
            sender.take_retransmissions().is_empty(),
            "Ack from a disabled receiver must clear the sender's backlog"
        );
    }

    #[test]
    fn disabled_face_still_does_not_transmit_reliably() {
        // The other half of the contract: answering is unconditional, but
        // sending reliably stays opt-in.
        let f = ReliabilityFeature::new();
        assert!(f.frame(b"x").is_empty(), "disabled face must not frame reliably");
        assert!(
            f.take_retransmissions().is_empty(),
            "disabled face must not retransmit its own traffic"
        );
    }

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
        // "Inert" now means inert as a SENDER. A disabled face still Acks what
        // it receives (see disabled_receiver_still_acks_a_reliable_sender); it
        // just never frames or retransmits its own traffic.
        let f = ReliabilityFeature::new();
        // Disabled: `frame` returns nothing and tracks nothing.
        assert!(f.frame(&bare_interest()).is_empty());

        thread::sleep(Duration::from_millis(20));
        let retx = f.take_retransmissions();
        assert!(retx.is_empty(), "disabled feature must not retransmit");
        assert_eq!(f.n_lp_resent_packets(), 0);
    }
}
