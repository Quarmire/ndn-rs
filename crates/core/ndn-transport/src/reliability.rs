//! NDNLPv2 per-hop reliability. Synchronous state machine; methods return
//! wire-ready packets and callers handle I/O.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use web_time::Instant;

use ndn_packet::fragment::FRAG_OVERHEAD;
use ndn_packet::lp::{encode_lp_acks, encode_lp_reliable, extract_acks};

const MAX_PIGGYBACKED_ACKS: usize = 16;
const DEFAULT_MAX_RETRIES: u8 = 1;
/// Cap retransmits per tick so retx bursts don't starve new packets.
const MAX_RETX_PER_TICK: usize = 8;
/// Cap unacked map to bound lingering retx after high-throughput flows end.
const MAX_UNACKED: usize = 256;

const RFC6298_INITIAL_RTO_US: u64 = 1_000_000;
const RFC6298_MIN_RTO_US: u64 = 200_000;
const RFC6298_MAX_RTO_US: u64 = 4_000_000;
const RFC6298_GRANULARITY_US: u64 = 100_000;
const RFC6298_ALPHA: f64 = 0.125;
const RFC6298_BETA: f64 = 0.25;

const QUIC_INITIAL_RTO_US: u64 = 333_000;
const QUIC_MIN_RTO_US: u64 = 1_000;
const QUIC_MAX_RTO_US: u64 = 4_000_000;
const QUIC_GRANULARITY_US: u64 = 1_000;

/// RTO computation strategy.
///
/// `Rfc6298`: EWMA + Karn's algorithm, conservative default.
/// `Quic` (RFC 9002): lower initial RTO, tighter granularity.
/// `MinRtt`: minimum observed RTT + margin; aggressive, stable links only.
/// `Fixed`: constant timeout, for known-latency local faces.
#[derive(Debug, Clone, Default)]
pub enum RtoStrategy {
    #[default]
    Rfc6298,
    Quic,
    MinRtt {
        margin_us: u64,
    },
    Fixed {
        rto_us: u64,
    },
}

/// Per-face reliability configuration. Presets: `default()` (RFC 6298),
/// `local()`, `ethernet()`, `wifi()`.
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    pub rto_strategy: RtoStrategy,
    pub max_retries: u8,
    pub max_unacked: usize,
    pub max_retx_per_tick: usize,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            rto_strategy: RtoStrategy::Rfc6298,
            max_retries: DEFAULT_MAX_RETRIES,
            max_unacked: MAX_UNACKED,
            max_retx_per_tick: MAX_RETX_PER_TICK,
        }
    }
}

impl ReliabilityConfig {
    pub fn local() -> Self {
        Self {
            rto_strategy: RtoStrategy::Fixed { rto_us: 1_000 },
            max_retries: 0,
            max_unacked: 64,
            max_retx_per_tick: 4,
        }
    }

    pub fn ethernet() -> Self {
        Self {
            rto_strategy: RtoStrategy::Quic,
            max_retries: 1,
            max_unacked: 256,
            max_retx_per_tick: 8,
        }
    }

    /// Local Wi-Fi mesh: retry hard, and recover FAST.
    ///
    /// `Rfc6298` is wrong for this link. Its 100 ms granularity floor plus a
    /// 200 ms RTO minimum are WAN-TCP numbers; a local mesh runs ~1-2 ms RTT,
    /// so the RTO pins at the 200 ms floor — measured on the fleet as exactly
    /// `rto=200000µs`, i.e. the clamp binding, not an estimate. Because a
    /// predictive stream delivers in cursor order, every recovery
    /// head-of-line-blocks the frames behind it for that full 200 ms, and the
    /// backlog then arrives as a burst which a latest-wins consumer collapses
    /// to a single frame. `Quic` uses a 1 ms granularity and 1 ms floor, so the
    /// same link computes ~5-10 ms from srtt + 4*rttvar — the estimator still
    /// governs, it is simply no longer clamped 100x above the true RTT.
    pub fn wifi() -> Self {
        Self {
            rto_strategy: RtoStrategy::Rfc6298,
            max_retries: 3,
            max_unacked: 512,
            max_retx_per_tick: 16,
        }
    }
}

struct UnackedEntry {
    wire: Bytes,
    first_sent: Instant,
    last_sent: Instant,
    retx_count: u8,
    is_retx: bool,
}

/// Per-face NDNLPv2 reliability state.
pub struct LpReliability {
    /// Network-packet Sequence (LP TLV 0x51); shared across all fragments
    /// of one packet, incremented per network-layer packet.
    next_seq: u64,
    /// Per-LP TxSequence (LP TLV 0x0348); assigned per LP transmission;
    /// receiver Acks reference these.
    next_tx_seq: u64,
    /// Keyed by TxSequence.
    unacked: HashMap<u64, UnackedEntry>,
    pending_acks: VecDeque<u64>,
    srtt_us: f64,
    rttvar_us: f64,
    rto_us: u64,
    min_rtt_us: u64,
    mtu: usize,
    max_retries: u8,
    max_unacked: usize,
    max_retx_per_tick: usize,
    rto_strategy: RtoStrategy,
    /// Frames abandoned after `max_retries` retransmissions without an Ack.
    /// Each one is a packet the peer can never reassemble: if it was a
    /// fragment, its whole group is dead and every sibling already sent is
    /// wasted airtime.
    rto_expirations: u64,
    /// Frames evicted from `unacked` by the `max_unacked` cap before they
    /// were Acked or retried to exhaustion — silent, unrecoverable loss.
    unacked_evictions: u64,
    /// TxSequences seen recently, for duplicate-frame suppression, with the
    /// time each was first seen. Aged out after one RTO — long enough to
    /// cover a retransmission, short enough to stay small.
    recent_recv: HashMap<u64, Instant>,
    /// `recent_recv` keys in arrival order, so ageing is O(expired).
    recent_recv_order: VecDeque<u64>,
    /// Inbound frames dropped as duplicates (a peer retransmission whose
    /// original already arrived).
    duplicate_frames: u64,
}

fn initial_rto_for(strategy: &RtoStrategy) -> u64 {
    match strategy {
        RtoStrategy::Rfc6298 => RFC6298_INITIAL_RTO_US,
        RtoStrategy::Quic => QUIC_INITIAL_RTO_US,
        RtoStrategy::MinRtt { margin_us } => *margin_us,
        RtoStrategy::Fixed { rto_us } => *rto_us,
    }
}

impl LpReliability {
    pub fn new(mtu: usize) -> Self {
        Self::from_config(mtu, ReliabilityConfig::default())
    }

    pub fn from_config(mtu: usize, config: ReliabilityConfig) -> Self {
        let initial_rto = initial_rto_for(&config.rto_strategy);
        Self {
            next_seq: 0,
            next_tx_seq: 0,
            unacked: HashMap::new(),
            pending_acks: VecDeque::new(),
            srtt_us: 0.0,
            rttvar_us: 0.0,
            rto_us: initial_rto,
            min_rtt_us: u64::MAX,
            mtu,
            max_retries: config.max_retries,
            max_unacked: config.max_unacked,
            max_retx_per_tick: config.max_retx_per_tick,
            rto_strategy: config.rto_strategy,
            rto_expirations: 0,
            unacked_evictions: 0,
            recent_recv: HashMap::new(),
            recent_recv_order: VecDeque::new(),
            duplicate_frames: 0,
        }
    }

    pub fn apply_config(&mut self, config: ReliabilityConfig) {
        self.rto_us = initial_rto_for(&config.rto_strategy);
        self.srtt_us = 0.0;
        self.rttvar_us = 0.0;
        self.min_rtt_us = u64::MAX;
        self.max_retries = config.max_retries;
        self.max_unacked = config.max_unacked;
        self.max_retx_per_tick = config.max_retx_per_tick;
        self.rto_strategy = config.rto_strategy;
    }

    pub fn config(&self) -> ReliabilityConfig {
        ReliabilityConfig {
            rto_strategy: self.rto_strategy.clone(),
            max_retries: self.max_retries,
            max_unacked: self.max_unacked,
            max_retx_per_tick: self.max_retx_per_tick,
        }
    }

    /// Fragment if needed, assign TxSequences, piggyback pending Acks,
    /// buffer for retransmit. Returns wire-ready LpPackets.
    pub fn on_send(&mut self, pkt: &[u8]) -> Vec<Bytes> {
        let now = Instant::now();

        let acks: Vec<u64> = self
            .pending_acks
            .drain(..self.pending_acks.len().min(MAX_PIGGYBACKED_ACKS))
            .collect();

        let ack_overhead = acks.len() * 10;
        let payload_cap = self
            .mtu
            .saturating_sub(FRAG_OVERHEAD)
            .saturating_sub(ack_overhead);

        if payload_cap == 0 {
            return vec![];
        }

        let frag_count = pkt.len().div_ceil(payload_cap);
        // Reserve a CONSECUTIVE block: NDNLPv2 Sequence increments per
        // fragment, and the receiver recovers the group key as
        // `Sequence - FragIndex` (see the engine's decode stage, and NFD's
        // LpReassembler). Emitting one Sequence for the whole packet put every
        // fragment in a DIFFERENT reassembly group -- key `net_seq - i` -- so a
        // multi-fragment packet could never complete: each fragment sat alone
        // until the 5 s timeout swept it.
        let net_seq = self.next_seq;
        self.next_seq += frag_count as u64;

        let mut wires = Vec::with_capacity(frag_count);
        for i in 0..frag_count {
            let start = i * payload_cap;
            let end = (start + payload_cap).min(pkt.len());
            let chunk = &pkt[start..end];
            let tx_seq = self.next_tx_seq;
            self.next_tx_seq += 1;

            let frag_info = if frag_count > 1 {
                Some((net_seq + i as u64, i as u64, frag_count as u64))
            } else {
                None
            };

            let frag_acks = if i == 0 { &acks[..] } else { &[] };
            let wire = encode_lp_reliable(chunk, tx_seq, frag_info, frag_acks);

            while self.unacked.len() >= self.max_unacked {
                if let Some(&oldest_seq) = self.unacked.keys().min() {
                    self.unacked.remove(&oldest_seq);
                    self.unacked_evictions += 1;
                } else {
                    break;
                }
            }

            self.unacked.insert(
                tx_seq,
                UnackedEntry {
                    wire: wire.clone(),
                    first_sent: now,
                    last_sent: now,
                    retx_count: 0,
                    is_retx: false,
                },
            );

            wires.push(wire);
        }

        wires
    }

    /// Lower (or raise) the fragmentation threshold for this face.
    ///
    /// Set per-FACE, not globally: a datagram transport must fragment below
    /// the path MTU so the layer under it never does (a lost IP fragment
    /// destroys the whole Data and LpReliability cannot retransmit just the
    /// missing piece), while a stream transport must NOT fragment — the kernel
    /// already segments it, and fragmenting there corrupts application framing.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Consume a peer's Acks and queue an Ack for a received reliable frame.
    ///
    /// Returns `true` when this frame is a DUPLICATE — a peer retransmission
    /// whose original already arrived — and the caller must drop it without
    /// reassembling or forwarding it.
    ///
    /// Mirrors NFD `LpReliability::processIncomingPacket`, which tracks
    /// recently-received frames and returns `!isDuplicate` so
    /// `GenericLinkService::decodeFragment` can return early. Without this the
    /// duplicate travels up the pipeline, where the PIT sees an Interest whose
    /// nonce it has already recorded and misreads a link-layer retransmission
    /// as a FORWARDING LOOP — dropping it and cancelling any pending forward
    /// for that entry.
    ///
    /// Keyed on `TxSequence`, not `Sequence`: `check_retransmit` resends
    /// `entry.wire` byte-for-byte, so the TxSequence is stable across
    /// retransmissions here, and unlike `Sequence` it is present on
    /// single-fragment frames too (`on_send` omits frag fields when
    /// `frag_count == 1`). NFD must key on `Sequence` only because it
    /// re-stamps a fresh TxSequence when it retransmits.
    ///
    /// The Ack is queued BEFORE the duplicate verdict, exactly as NFD does:
    /// the peer retransmitted because it never got our Ack, so staying silent
    /// would make it retransmit again.
    pub fn on_receive(&mut self, raw: &[u8]) -> bool {
        let (tx_seq, acks) = extract_acks(raw);

        let mut is_duplicate = false;
        if let Some(seq) = tx_seq {
            self.pending_acks.push_back(seq);

            let now = Instant::now();
            let rto = std::time::Duration::from_micros(self.rto_us);
            while let Some(&front) = self.recent_recv_order.front() {
                match self.recent_recv.get(&front) {
                    Some(&seen) if now.duration_since(seen) > rto => {
                        self.recent_recv.remove(&front);
                        self.recent_recv_order.pop_front();
                    }
                    _ => break,
                }
            }
            if self.recent_recv.insert(seq, now).is_some() {
                is_duplicate = true;
                self.duplicate_frames += 1;
            } else {
                self.recent_recv_order.push_back(seq);
            }
        }

        let now = Instant::now();
        for ack_seq in acks {
            if let Some(entry) = self.unacked.remove(&ack_seq) {
                // Karn: only measure RTT on non-retransmitted packets.
                if !entry.is_retx {
                    let rtt_us = now.duration_since(entry.first_sent).as_micros() as f64;
                    self.update_rto(rtt_us);
                }
            }
        }
        is_duplicate
    }

    /// Inbound frames dropped as peer retransmissions of an already-received
    /// frame.
    pub fn duplicate_frames(&self) -> u64 {
        self.duplicate_frames
    }

    /// Returns wire packets due for retransmission.
    pub fn check_retransmit(&mut self) -> Vec<Bytes> {
        let now = Instant::now();
        let rto = std::time::Duration::from_micros(self.rto_us);
        let mut retx = Vec::new();
        let mut expired = Vec::new();

        for (&seq, entry) in &self.unacked {
            if now.duration_since(entry.last_sent) >= rto {
                if entry.retx_count >= self.max_retries {
                    expired.push(seq);
                } else {
                    retx.push(seq);
                }
            }
        }

        for seq in expired {
            self.unacked.remove(&seq);
            self.rto_expirations += 1;
        }

        let mut wires = Vec::with_capacity(retx.len().min(self.max_retx_per_tick));
        for seq in retx.into_iter().take(self.max_retx_per_tick) {
            if let Some(entry) = self.unacked.get_mut(&seq) {
                entry.last_sent = now;
                entry.retx_count += 1;
                entry.is_retx = true;
                wires.push(entry.wire.clone());
            }
        }

        wires
    }

    pub fn flush_acks(&mut self) -> Option<Bytes> {
        if self.pending_acks.is_empty() {
            return None;
        }
        let acks: Vec<u64> = self.pending_acks.drain(..).collect();
        Some(encode_lp_acks(&acks))
    }

    pub fn unacked_count(&self) -> usize {
        self.unacked.len()
    }

    /// Frames given up on after `max_retries` (see `rto_expirations`).
    pub fn rto_expirations(&self) -> u64 {
        self.rto_expirations
    }

    /// Frames dropped from the retransmit buffer by the `max_unacked` cap.
    pub fn unacked_evictions(&self) -> u64 {
        self.unacked_evictions
    }


    pub fn rto_us(&self) -> u64 {
        self.rto_us
    }

    fn update_rto(&mut self, rtt_us: f64) {
        let rtt_int = rtt_us as u64;
        if rtt_int < self.min_rtt_us {
            self.min_rtt_us = rtt_int;
        }

        match &self.rto_strategy {
            RtoStrategy::Fixed { .. } => {}
            RtoStrategy::MinRtt { margin_us } => {
                self.rto_us = self.min_rtt_us.saturating_add(*margin_us);
            }
            RtoStrategy::Rfc6298 => {
                self.update_ewma(rtt_us, RFC6298_ALPHA, RFC6298_BETA);
                let rto = self.srtt_us + (4.0 * self.rttvar_us).max(RFC6298_GRANULARITY_US as f64);
                self.rto_us = (rto as u64).clamp(RFC6298_MIN_RTO_US, RFC6298_MAX_RTO_US);
            }
            RtoStrategy::Quic => {
                self.update_ewma(rtt_us, RFC6298_ALPHA, RFC6298_BETA);
                let rto = self.srtt_us + (4.0 * self.rttvar_us).max(QUIC_GRANULARITY_US as f64);
                self.rto_us = (rto as u64).clamp(QUIC_MIN_RTO_US, QUIC_MAX_RTO_US);
            }
        }
    }

    fn update_ewma(&mut self, rtt_us: f64, alpha: f64, beta: f64) {
        if self.srtt_us == 0.0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2.0;
        } else {
            self.rttvar_us = (1.0 - beta) * self.rttvar_us + beta * (self.srtt_us - rtt_us).abs();
            self.srtt_us = (1.0 - alpha) * self.srtt_us + alpha * rtt_us;
        }
    }
}

#[cfg(test)]
mod tests {

    /// A fragmented packet emitted by `on_send` must REASSEMBLE at the
    /// receiver, using the receiver's real key derivation.
    ///
    /// The engine's decode stage recovers the group as `Sequence - FragIndex`
    /// (NDNLPv2: Sequence increments per fragment). Emitting a single Sequence
    /// for the whole packet keyed every fragment differently, so multi-fragment
    /// packets never completed — each fragment sat alone until the 5 s timeout.
    /// Single-fragment traffic took the fast path and was unaffected, which is
    /// why this presented as "video dies, telemetry is fine" on a lossy link
    /// and was invisible on a lossless one.
    #[test]
    fn fragmented_send_reassembles_at_the_receiver() {
        use ndn_packet::fragment::ReassemblyBuffer;
        use ndn_packet::lp::extract_fragment;

        let mut r = LpReliability::new(300); // small MTU -> several fragments
        let payload: Vec<u8> = (0..2000u32).map(|x| (x % 251) as u8).collect();
        let wires = r.on_send(&payload);
        assert!(wires.len() > 1, "payload must actually fragment");

        let mut rb = ReassemblyBuffer::default();
        let mut done = None;
        for w in &wires {
            let h = extract_fragment(w).expect("fragment header present");
            // exactly how the engine's decode stage keys the group
            let base = h
                .sequence
                .checked_sub(h.frag_index)
                .expect("Sequence must be >= FragIndex");
            if let Some(pkt) = rb.process(
                0,
                base,
                h.frag_index,
                h.frag_count,
                Bytes::copy_from_slice(&w[h.frag_start..h.frag_end]),
            ) {
                done = Some(pkt);
            }
        }
        let got = done.expect("fragments must reassemble into one packet");
        assert_eq!(&got[..], &payload[..], "reassembled payload must match");
    }

    use super::*;

    fn small_packet() -> Vec<u8> {
        vec![0x05, 0x03, 0xAA, 0xBB, 0xCC]
    }

    #[test]
    fn on_send_returns_one_fragment_for_small_packet() {
        let mut rel = LpReliability::new(1400);
        let wires = rel.on_send(&small_packet());
        assert_eq!(wires.len(), 1);
        assert_eq!(rel.unacked_count(), 1);
    }

    #[test]
    fn on_send_fragments_large_packet() {
        let mut rel = LpReliability::new(200);
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let wires = rel.on_send(&data);
        assert!(wires.len() > 1);
        assert_eq!(rel.unacked_count(), wires.len());
    }

    #[test]
    fn on_send_assigns_consecutive_sequences() {
        let mut rel = LpReliability::new(1400);
        let w1 = rel.on_send(&small_packet());
        let w2 = rel.on_send(&small_packet());
        let (seq1, _) = extract_acks(&w1[0]);
        let (seq2, _) = extract_acks(&w2[0]);
        assert_eq!(seq1, Some(0));
        assert_eq!(seq2, Some(1));
    }

    #[test]
    fn on_receive_queues_ack() {
        let mut sender = LpReliability::new(1400);
        let mut receiver = LpReliability::new(1400);

        let wires = sender.on_send(&small_packet());
        receiver.on_receive(&wires[0]);

        let ack_pkt = receiver.flush_acks();
        assert!(ack_pkt.is_some());
    }

    #[test]
    fn ack_clears_unacked() {
        let mut sender = LpReliability::new(1400);
        let mut receiver = LpReliability::new(1400);

        let wires = sender.on_send(&small_packet());
        assert_eq!(sender.unacked_count(), 1);

        receiver.on_receive(&wires[0]);
        let reply = receiver.on_send(&small_packet());

        sender.on_receive(&reply[0]);
        assert_eq!(sender.unacked_count(), 0);
    }

    fn fast_rto_config() -> ReliabilityConfig {
        ReliabilityConfig {
            rto_strategy: RtoStrategy::Fixed { rto_us: 1_000 },
            ..Default::default()
        }
    }

    #[test]
    fn retransmit_after_rto() {
        let mut rel = LpReliability::from_config(1400, fast_rto_config());

        let _wires = rel.on_send(&small_packet());
        assert_eq!(rel.unacked_count(), 1);

        std::thread::sleep(std::time::Duration::from_millis(5));

        let retx = rel.check_retransmit();
        assert_eq!(retx.len(), 1);
        assert_eq!(rel.unacked_count(), 1);
    }

    #[test]
    fn max_retries_drops_entry() {
        let mut rel = LpReliability::from_config(
            1400,
            ReliabilityConfig {
                max_retries: 1,
                ..fast_rto_config()
            },
        );

        let _wires = rel.on_send(&small_packet());
        std::thread::sleep(std::time::Duration::from_millis(5));

        let retx = rel.check_retransmit();
        assert_eq!(retx.len(), 1);

        std::thread::sleep(std::time::Duration::from_millis(5));

        let retx = rel.check_retransmit();
        assert!(retx.is_empty());
        assert_eq!(rel.unacked_count(), 0);
    }

    #[test]
    fn rto_converges_with_measurements() {
        let mut rel = LpReliability::new(1400);
        assert_eq!(rel.rto_us, RFC6298_INITIAL_RTO_US);

        for _ in 0..10 {
            rel.update_rto(500.0);
        }
        assert!(rel.rto_us <= RFC6298_MIN_RTO_US + RFC6298_GRANULARITY_US);
    }

    #[test]
    fn flush_acks_returns_none_when_empty() {
        let mut rel = LpReliability::new(1400);
        assert!(rel.flush_acks().is_none());
    }

    #[test]
    fn piggybacked_acks_in_outgoing_packet() {
        let mut sender = LpReliability::new(1400);
        let mut receiver = LpReliability::new(1400);

        let wires = sender.on_send(&small_packet());

        receiver.on_receive(&wires[0]);
        let reply = receiver.on_send(&small_packet());

        let (_, acks) = extract_acks(&reply[0]);
        assert!(!acks.is_empty());
        assert_eq!(acks[0], 0);
    }

    #[test]
    fn quic_strategy_lower_initial_rto() {
        let cfg = ReliabilityConfig {
            rto_strategy: RtoStrategy::Quic,
            ..Default::default()
        };
        let rel = LpReliability::from_config(1400, cfg);
        assert_eq!(rel.rto_us, QUIC_INITIAL_RTO_US);
        assert!(rel.rto_us < RFC6298_INITIAL_RTO_US);
    }

    #[test]
    fn quic_strategy_converges_tighter() {
        let cfg = ReliabilityConfig {
            rto_strategy: RtoStrategy::Quic,
            ..Default::default()
        };
        let mut rel = LpReliability::from_config(1400, cfg);
        for _ in 0..10 {
            rel.update_rto(500.0);
        }
        assert!(rel.rto_us < RFC6298_MIN_RTO_US);
    }

    #[test]
    fn fixed_strategy_never_changes() {
        let cfg = ReliabilityConfig {
            rto_strategy: RtoStrategy::Fixed { rto_us: 50_000 },
            ..Default::default()
        };
        let mut rel = LpReliability::from_config(1400, cfg);
        assert_eq!(rel.rto_us, 50_000);
        for _ in 0..20 {
            rel.update_rto(1_000.0);
        }
        assert_eq!(rel.rto_us, 50_000);
    }

    #[test]
    fn min_rtt_strategy_tracks_minimum() {
        let cfg = ReliabilityConfig {
            rto_strategy: RtoStrategy::MinRtt { margin_us: 5_000 },
            ..Default::default()
        };
        let mut rel = LpReliability::from_config(1400, cfg);
        rel.update_rto(10_000.0);
        rel.update_rto(8_000.0);
        rel.update_rto(15_000.0);
        assert_eq!(rel.rto_us, 8_000 + 5_000);
    }

    #[test]
    fn apply_config_resets_state() {
        let mut rel = LpReliability::new(1400);
        for _ in 0..10 {
            rel.update_rto(500.0);
        }
        assert_ne!(rel.srtt_us, 0.0);

        rel.apply_config(ReliabilityConfig {
            rto_strategy: RtoStrategy::Fixed { rto_us: 100_000 },
            ..Default::default()
        });
        assert_eq!(rel.rto_us, 100_000);
        assert_eq!(rel.srtt_us, 0.0);
        assert_eq!(rel.min_rtt_us, u64::MAX);
    }

    #[test]
    fn presets_are_consistent() {
        let local = LpReliability::from_config(1400, ReliabilityConfig::local());
        let eth = LpReliability::from_config(1400, ReliabilityConfig::ethernet());
        let wifi = LpReliability::from_config(1400, ReliabilityConfig::wifi());

        assert!(local.rto_us < eth.rto_us);
        assert!(wifi.config().max_retries > eth.config().max_retries);
    }

    /// On a local-mesh RTT, RFC6298 pins at its floor while Quic tracks the
    /// link — a ~40x difference in how fast a loss can be recovered.
    ///
    /// RFC6298's 100 ms granularity and 200 ms floor are WAN-TCP numbers; this
    /// fleet's mesh runs ~1-2 ms RTT, and `rto=200000µs` was read straight off
    /// a live face — the clamp binding, not an estimate. Because a predictive
    /// stream delivers in cursor order, each recovery head-of-line-blocks the
    /// frames behind it for that whole window.
    ///
    /// `wifi()` deliberately still selects RFC6298. Quic was tried on the
    /// fleet (3ae75e41) and had to be reverted: its ~4.5 ms RTO undercut the
    /// Ack delay of the day, so the sender retransmitted before an Ack was
    /// physically possible. Acking on receipt removes that floor, but the
    /// estimator must be shown to actually converge on hardware before the
    /// profile switches. This test pins the MEASURED difference so the
    /// motivation survives the deferral.
    #[test]
    fn rfc6298_pins_at_its_floor_on_a_mesh_rtt_where_quic_tracks_the_link() {
        const MESH_RTT_US: f64 = 1_500.0; // ~1.5 ms, measured on the fleet

        let base = ReliabilityConfig::wifi();
        let mut rfc = LpReliability::from_config(
            1400,
            ReliabilityConfig {
                rto_strategy: RtoStrategy::Rfc6298,
                ..base.clone()
            },
        );
        let mut quic = LpReliability::from_config(
            1400,
            ReliabilityConfig {
                rto_strategy: RtoStrategy::Quic,
                ..base
            },
        );
        for _ in 0..20 {
            rfc.update_rto(MESH_RTT_US);
            quic.update_rto(MESH_RTT_US);
        }

        assert_eq!(
            rfc.rto_us(),
            RFC6298_MIN_RTO_US,
            "RFC6298 pins at its 200 ms floor on a 1.5 ms link"
        );
        assert!(
            quic.rto_us() < 50_000,
            "Quic must track the link, not a WAN floor (got {} µs)",
            quic.rto_us()
        );
        assert!(
            quic.rto_us() >= MESH_RTT_US as u64,
            "but must still cover the RTT (got {} µs)",
            quic.rto_us()
        );
    }

    #[test]
    fn unacked_map_capped_at_max() {
        let mut rel = LpReliability::new(1400);
        for _ in 0..(MAX_UNACKED + 100) {
            rel.on_send(&small_packet());
        }
        assert!(rel.unacked_count() <= MAX_UNACKED);
    }
}

#[cfg(test)]
mod duplicate_suppression_tests {
    use super::*;

    fn reliable_frame(tx_seq: u64) -> Bytes {
        encode_lp_reliable(&[0x05, 0x03, 0x07, 0x01, 0xAA], tx_seq, None, &[])
    }

    /// A peer retransmission must be reported as a DUPLICATE so the caller
    /// drops it before reassembly/forwarding — but must still be Acked.
    ///
    /// Without the drop, the duplicate reaches the PIT, which sees an Interest
    /// whose nonce it already holds and misreads a link-layer retransmission as
    /// a forwarding loop (NFD suppresses it in
    /// `LpReliability::processIncomingPacket`). Without the Ack, the peer never
    /// learns we have it and retransmits again.
    #[test]
    fn a_retransmitted_frame_is_reported_duplicate_but_still_acked() {
        let mut rel = LpReliability::new(1400);
        const TX: u64 = 77;

        assert!(!rel.on_receive(&reliable_frame(TX)), "first arrival is not a duplicate");
        assert!(rel.on_receive(&reliable_frame(TX)), "retransmission must be flagged duplicate");
        assert!(rel.on_receive(&reliable_frame(TX)), "and stay flagged while in the window");
        assert_eq!(rel.duplicate_frames(), 2);

        // Every arrival queued an Ack, duplicates included.
        let acks = rel.flush_acks().expect("Acks queued");
        let (_tx, list) = extract_acks(&acks);
        assert_eq!(
            list.iter().filter(|&&a| a == TX).count(),
            3,
            "each arrival, duplicate or not, owes the peer an Ack"
        );
    }

    /// Distinct frames must not be mistaken for each other.
    #[test]
    fn distinct_txsequences_are_not_duplicates() {
        let mut rel = LpReliability::new(1400);
        for tx in 0..50u64 {
            assert!(!rel.on_receive(&reliable_frame(tx)), "tx={tx} is first-seen");
        }
        assert_eq!(rel.duplicate_frames(), 0);
    }

    /// The dedup window is bounded: entries age out after one RTO, so a long
    /// flow cannot grow it without limit.
    #[test]
    fn dedup_window_ages_out_and_stays_bounded() {
        let mut rel = LpReliability::from_config(
            1400,
            ReliabilityConfig {
                rto_strategy: RtoStrategy::Fixed { rto_us: 1 },
                ..Default::default()
            },
        );
        for tx in 0..200u64 {
            rel.on_receive(&reliable_frame(tx));
            std::thread::sleep(std::time::Duration::from_micros(2));
        }
        assert!(
            rel.recent_recv.len() < 200,
            "window must age out (holding {})",
            rel.recent_recv.len()
        );
    }
}
