//! NDNLPv2 per-hop reliability.
//!
//! Pure synchronous state machine — no async, no tokio dependency.
//! Methods return wire-ready packets; callers handle I/O.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use bytes::Bytes;

use ndn_packet::fragment::FRAG_OVERHEAD;
use ndn_packet::lp::{encode_lp_acks, encode_lp_reliable, extract_acks};

/// Maximum number of Ack TLVs to piggyback per outgoing packet.
const MAX_PIGGYBACKED_ACKS: usize = 16;

/// Maximum retransmission attempts before giving up on a packet.
/// Keep low — NDN already has end-to-end recovery via Interest re-expression;
/// per-hop reliability is just best-effort loss recovery.
const DEFAULT_MAX_RETRIES: u8 = 1;

/// Maximum retransmit packets per `check_retransmit()` call.
/// Prevents burst retransmissions from blocking the face_sender, which would
/// starve delivery of new packets and cause a throughput collapse.
const MAX_RETX_PER_TICK: usize = 8;

/// Maximum entries in the unacked map.
/// Caps how long post-flow retransmit drain can last:
/// MAX_UNACKED / (MAX_RETX_PER_TICK × ticks/sec) ≈ 256 / 160 ≈ 1.6s.
const MAX_UNACKED: usize = 256;

// ─── RTO defaults ────────────────────────────────────────────────────────────

/// RFC 6298 defaults.
const RFC6298_INITIAL_RTO_US: u64 = 1_000_000; // 1 second
const RFC6298_MIN_RTO_US: u64 = 200_000; // 200 ms
const RFC6298_MAX_RTO_US: u64 = 4_000_000; // 4 seconds
const RFC6298_GRANULARITY_US: u64 = 100_000; // 100 ms
const RFC6298_ALPHA: f64 = 0.125; // 1/8
const RFC6298_BETA: f64 = 0.25; // 1/4

/// QUIC (RFC 9002) defaults.
const QUIC_INITIAL_RTO_US: u64 = 333_000; // 333 ms
const QUIC_MIN_RTO_US: u64 = 1_000; // 1 µs (QUIC has no minimum)
const QUIC_MAX_RTO_US: u64 = 4_000_000; // 4 seconds
const QUIC_GRANULARITY_US: u64 = 1_000; // 1 ms (kGranularity)

/// RTO computation strategy.
///
/// Different algorithms suit different link types:
/// - `Rfc6298`: Conservative, jitter-tolerant — good default for unknown links.
/// - `Quic`: Lower initial RTO (333ms vs 1s), tighter granularity — better for
///   short flows and first-contact latency.
/// - `MinRtt`: Uses minimum observed RTT + margin — aggressive, best for stable
///   low-jitter links (dedicated point-to-point Ethernet).
/// - `Fixed`: Constant timeout, no adaptation — ideal for local faces (Unix, SHM)
///   where RTT is known and stable.
#[derive(Debug, Clone, Default)]
pub enum RtoStrategy {
    /// RFC 6298 EWMA with Karn's algorithm. Default.
    #[default]
    Rfc6298,
    /// QUIC (RFC 9002): lower initial RTO, tighter granularity.
    Quic,
    /// Minimum observed RTT + configurable margin. Aggressive.
    MinRtt {
        /// Added to min RTT to compute RTO (default: 5ms).
        margin_us: u64,
    },
    /// Fixed RTO, no adaptation. For known-latency links.
    Fixed {
        /// Constant RTO value in microseconds.
        rto_us: u64,
    },
}

/// Per-face reliability configuration.
///
/// Bundles all tunable knobs into a single struct that can be stored in
/// config files, passed when creating faces, or selected via presets.
///
/// # Presets
///
/// ```rust
/// use ndn_face_net::ReliabilityConfig;
///
/// let _ = ReliabilityConfig::default();      // conservative (RFC 6298)
/// let _ = ReliabilityConfig::local();        // local Unix/SHM faces
/// let _ = ReliabilityConfig::wifi();         // lossy wireless
/// let _ = ReliabilityConfig::ethernet();     // stable wired links
/// ```
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    /// RTO computation algorithm.
    pub rto_strategy: RtoStrategy,
    /// Maximum retransmission attempts before giving up (default: 1).
    pub max_retries: u8,
    /// Maximum unacked entries before oldest are evicted (default: 256).
    pub max_unacked: usize,
    /// Maximum retransmit packets per timer tick (default: 8).
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
    /// Local faces (Unix socket, SHM). Fixed 1ms RTO, minimal retries.
    pub fn local() -> Self {
        Self {
            rto_strategy: RtoStrategy::Fixed { rto_us: 1_000 },
            max_retries: 0,
            max_unacked: 64,
            max_retx_per_tick: 4,
        }
    }

    /// Stable wired Ethernet. QUIC-style adaptive with tight bounds.
    pub fn ethernet() -> Self {
        Self {
            rto_strategy: RtoStrategy::Quic,
            max_retries: 1,
            max_unacked: 256,
            max_retx_per_tick: 8,
        }
    }

    /// Lossy wireless (WiFi, Bluetooth). More retries, jitter-tolerant RTO.
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
///
/// Tracks outbound TxSequences, piggybacked Acks, and adaptive RTO.
/// All methods are synchronous and return wire-ready packets.
pub struct LpReliability {
    next_seq: u64,
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
    /// Create with default configuration (RFC 6298, conservative).
    pub fn new(mtu: usize) -> Self {
        Self::from_config(mtu, ReliabilityConfig::default())
    }

    /// Create from a full configuration.
    pub fn from_config(mtu: usize, config: ReliabilityConfig) -> Self {
        let initial_rto = initial_rto_for(&config.rto_strategy);
        Self {
            next_seq: 0,
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

    /// Apply a new configuration. Resets RTO adaptation state.
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

    /// Current configuration (snapshot).
    pub fn config(&self) -> ReliabilityConfig {
        ReliabilityConfig {
            rto_strategy: self.rto_strategy.clone(),
            max_retries: self.max_retries,
            max_unacked: self.max_unacked,
            max_retx_per_tick: self.max_retx_per_tick,
        }
    }

    /// Process an outbound packet: fragment if needed, assign TxSequences,
    /// piggyback pending Acks, buffer for retransmit.
    ///
    /// Returns wire-ready LpPackets.
    pub fn on_send(&mut self, pkt: &[u8]) -> Vec<Bytes> {
        let now = Instant::now();

        // Drain pending acks to piggyback.
        let acks: Vec<u64> = self
            .pending_acks
            .drain(..self.pending_acks.len().min(MAX_PIGGYBACKED_ACKS))
            .collect();

        // Compute per-fragment payload capacity.
        // Ack overhead: each Ack TLV is ~1-2 (type) + 1 (length) + 1-8 (value) bytes.
        // Conservative: 10 bytes per ack.
        let ack_overhead = acks.len() * 10;
        let payload_cap = self
            .mtu
            .saturating_sub(FRAG_OVERHEAD)
            .saturating_sub(ack_overhead);

        if payload_cap == 0 {
            return vec![];
        }

        let frag_count = pkt.len().div_ceil(payload_cap);
        let base_seq = self.next_seq;
        self.next_seq += frag_count as u64;

        let mut wires = Vec::with_capacity(frag_count);
        for i in 0..frag_count {
            let start = i * payload_cap;
            let end = (start + payload_cap).min(pkt.len());
            let chunk = &pkt[start..end];
            let seq = base_seq + i as u64;

            let frag_info = if frag_count > 1 {
                Some((i as u64, frag_count as u64))
            } else {
                None
            };

            // Only piggyback acks on the first fragment.
            let frag_acks = if i == 0 { &acks[..] } else { &[] };
            let wire = encode_lp_reliable(chunk, seq, frag_info, frag_acks);

            // Evict oldest entries if at capacity to prevent unbounded growth.
            // Without this cap, high-throughput flows accumulate thousands of
            // entries that drain at ~160/sec after the flow ends, causing
            // minutes of lingering retransmit traffic.
            while self.unacked.len() >= self.max_unacked {
                if let Some(&oldest_seq) = self.unacked.keys().min() {
                    self.unacked.remove(&oldest_seq);
                } else {
                    break;
                }
            }

            self.unacked.insert(
                seq,
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

    /// Process an inbound raw LpPacket: extract TxSequence (queue for Ack)
    /// and process any piggybacked Acks (clear unacked, measure RTT).
    pub fn on_receive(&mut self, raw: &[u8]) {
        let (tx_seq, acks) = extract_acks(raw);

        // Queue ack for the sender's TxSequence.
        if let Some(seq) = tx_seq {
            self.pending_acks.push_back(seq);
        }

        // Process Acks from the remote.
        let now = Instant::now();
        for ack_seq in acks {
            if let Some(entry) = self.unacked.remove(&ack_seq) {
                // Karn's algorithm: only measure RTT on non-retransmitted packets.
                if !entry.is_retx {
                    let rtt_us = now.duration_since(entry.first_sent).as_micros() as f64;
                    self.update_rto(rtt_us);
                }
            }
        }
    }

    /// Check for retransmit-eligible entries. Returns wire packets to resend.
    ///
    /// Rate-limited to `MAX_RETX_PER_TICK` to prevent burst retransmissions
    /// from blocking the face_sender (which would starve new packet delivery
    /// and cause throughput collapse).
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

        // Remove entries that exceeded max retries.
        for seq in expired {
            self.unacked.remove(&seq);
        }

        // Rate-limit retransmissions to avoid blocking the face_sender.
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

    /// Flush pending Acks as a bare Ack-only LpPacket.
    /// Call when the retransmit timer fires and there's been no recent outgoing traffic.
    pub fn flush_acks(&mut self) -> Option<Bytes> {
        if self.pending_acks.is_empty() {
            return None;
        }
        let acks: Vec<u64> = self.pending_acks.drain(..).collect();
        Some(encode_lp_acks(&acks))
    }

    /// Number of unacknowledged packets in flight.
    pub fn unacked_count(&self) -> usize {
        self.unacked.len()
    }

    /// Current RTO in microseconds.
    pub fn rto_us(&self) -> u64 {
        self.rto_us
    }

    /// Update SRTT, RTTVAR, and RTO based on the active strategy.
    fn update_rto(&mut self, rtt_us: f64) {
        // Track min RTT for MinRtt strategy.
        let rtt_int = rtt_us as u64;
        if rtt_int < self.min_rtt_us {
            self.min_rtt_us = rtt_int;
        }

        match &self.rto_strategy {
            RtoStrategy::Fixed { .. } => {
                // No adaptation — RTO stays constant.
            }
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

    /// EWMA update shared by RFC 6298 and QUIC strategies.
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

        // Receiver should have a pending ack.
        let ack_pkt = receiver.flush_acks();
        assert!(ack_pkt.is_some());
    }

    #[test]
    fn ack_clears_unacked() {
        let mut sender = LpReliability::new(1400);
        let mut receiver = LpReliability::new(1400);

        let wires = sender.on_send(&small_packet());
        assert_eq!(sender.unacked_count(), 1);

        // Receiver gets packet, then sends something back with piggybacked ack.
        receiver.on_receive(&wires[0]);
        let reply = receiver.on_send(&small_packet());

        // Sender processes reply (which piggybacks the ack).
        sender.on_receive(&reply[0]);
        assert_eq!(sender.unacked_count(), 0);
    }

    fn fast_rto_config() -> ReliabilityConfig {
        ReliabilityConfig {
            rto_strategy: RtoStrategy::Fixed { rto_us: 1_000 }, // 1ms
            ..Default::default()
        }
    }

    #[test]
    fn retransmit_after_rto() {
        let mut rel = LpReliability::from_config(1400, fast_rto_config());

        let _wires = rel.on_send(&small_packet());
        assert_eq!(rel.unacked_count(), 1);

        // Wait for RTO.
        std::thread::sleep(std::time::Duration::from_millis(5));

        let retx = rel.check_retransmit();
        assert_eq!(retx.len(), 1);
        assert_eq!(rel.unacked_count(), 1); // still tracked
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

        // First retransmit.
        let retx = rel.check_retransmit();
        assert_eq!(retx.len(), 1);

        std::thread::sleep(std::time::Duration::from_millis(5));

        // Second attempt exceeds max_retries=1, entry is dropped.
        let retx = rel.check_retransmit();
        assert!(retx.is_empty());
        assert_eq!(rel.unacked_count(), 0);
    }

    #[test]
    fn rto_converges_with_measurements() {
        let mut rel = LpReliability::new(1400);
        assert_eq!(rel.rto_us, RFC6298_INITIAL_RTO_US);

        // Simulate low-RTT measurements.
        for _ in 0..10 {
            rel.update_rto(500.0); // 500 µs
        }
        // RTO should have converged to near the minimum.
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

        // Sender sends a packet.
        let wires = sender.on_send(&small_packet());

        // Receiver processes it (queues ack), then sends own packet.
        receiver.on_receive(&wires[0]);
        let reply = receiver.on_send(&small_packet());

        // The reply should contain piggybacked ack.
        let (_, acks) = extract_acks(&reply[0]);
        assert!(!acks.is_empty());
        assert_eq!(acks[0], 0); // ack for sender's seq=0
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
        // QUIC has no 200ms floor, so RTO can go much lower than RFC 6298.
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
        rel.update_rto(10_000.0); // 10ms
        rel.update_rto(8_000.0); // 8ms
        rel.update_rto(15_000.0); // 15ms — should not raise RTO
        // RTO = min(10k, 8k, 15k) + 5k = 13k
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
        // Smoke test that presets produce valid configs.
        let local = LpReliability::from_config(1400, ReliabilityConfig::local());
        let eth = LpReliability::from_config(1400, ReliabilityConfig::ethernet());
        let wifi = LpReliability::from_config(1400, ReliabilityConfig::wifi());

        // Local should have lowest RTO, wifi the most retries.
        assert!(local.rto_us < eth.rto_us);
        assert!(wifi.config().max_retries > eth.config().max_retries);
    }

    #[test]
    fn unacked_map_capped_at_max() {
        let mut rel = LpReliability::new(1400);
        // Send more packets than MAX_UNACKED.
        for _ in 0..(MAX_UNACKED + 100) {
            rel.on_send(&small_packet());
        }
        assert!(rel.unacked_count() <= MAX_UNACKED);
    }
}
