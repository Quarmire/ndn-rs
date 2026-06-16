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
        let net_seq = self.next_seq;
        self.next_seq += 1;

        let mut wires = Vec::with_capacity(frag_count);
        for i in 0..frag_count {
            let start = i * payload_cap;
            let end = (start + payload_cap).min(pkt.len());
            let chunk = &pkt[start..end];
            let tx_seq = self.next_tx_seq;
            self.next_tx_seq += 1;

            let frag_info = if frag_count > 1 {
                Some((net_seq, i as u64, frag_count as u64))
            } else {
                None
            };

            let frag_acks = if i == 0 { &acks[..] } else { &[] };
            let wire = encode_lp_reliable(chunk, tx_seq, frag_info, frag_acks);

            while self.unacked.len() >= self.max_unacked {
                if let Some(&oldest_seq) = self.unacked.keys().min() {
                    self.unacked.remove(&oldest_seq);
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

    pub fn on_receive(&mut self, raw: &[u8]) {
        let (tx_seq, acks) = extract_acks(raw);

        if let Some(seq) = tx_seq {
            self.pending_acks.push_back(seq);
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

    #[test]
    fn unacked_map_capped_at_max() {
        let mut rel = LpReliability::new(1400);
        for _ in 0..(MAX_UNACKED + 100) {
            rel.on_send(&small_packet());
        }
        assert!(rel.unacked_count() <= MAX_UNACKED);
    }
}
