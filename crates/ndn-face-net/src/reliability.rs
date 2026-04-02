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
const DEFAULT_MAX_RETRIES: u8 = 3;

/// RTO parameters (RFC 6298).
const INITIAL_RTO_US: u64 = 1_000_000;   // 1 second
const MIN_RTO_US: u64     =   200_000;   // 200 ms
const MAX_RTO_US: u64     = 4_000_000;   // 4 seconds
const GRANULARITY_US: u64 =   100_000;   // 100 ms
const ALPHA: f64 = 0.125; // 1/8
const BETA:  f64 = 0.25;  // 1/4

struct UnackedEntry {
    wire:       Bytes,
    first_sent: Instant,
    last_sent:  Instant,
    retx_count: u8,
    is_retx:    bool,
}

/// Per-face NDNLPv2 reliability state.
///
/// Tracks outbound TxSequences, piggybacked Acks, and adaptive RTO.
/// All methods are synchronous and return wire-ready packets.
pub struct LpReliability {
    next_seq:     u64,
    unacked:      HashMap<u64, UnackedEntry>,
    pending_acks: VecDeque<u64>,
    srtt_us:      f64,
    rttvar_us:    f64,
    rto_us:       u64,
    mtu:          usize,
    max_retries:  u8,
}

impl LpReliability {
    pub fn new(mtu: usize) -> Self {
        Self {
            next_seq:     0,
            unacked:      HashMap::new(),
            pending_acks: VecDeque::new(),
            srtt_us:      0.0,
            rttvar_us:    0.0,
            rto_us:       INITIAL_RTO_US,
            mtu,
            max_retries:  DEFAULT_MAX_RETRIES,
        }
    }

    /// Process an outbound packet: fragment if needed, assign TxSequences,
    /// piggyback pending Acks, buffer for retransmit.
    ///
    /// Returns wire-ready LpPackets.
    pub fn on_send(&mut self, pkt: &[u8]) -> Vec<Bytes> {
        let now = Instant::now();

        // Drain pending acks to piggyback.
        let acks: Vec<u64> = self.pending_acks
            .drain(..self.pending_acks.len().min(MAX_PIGGYBACKED_ACKS))
            .collect();

        // Compute per-fragment payload capacity.
        // Ack overhead: each Ack TLV is ~1-2 (type) + 1 (length) + 1-8 (value) bytes.
        // Conservative: 10 bytes per ack.
        let ack_overhead = acks.len() * 10;
        let payload_cap = self.mtu
            .saturating_sub(FRAG_OVERHEAD)
            .saturating_sub(ack_overhead);

        if payload_cap == 0 {
            return vec![];
        }

        let frag_count = (pkt.len() + payload_cap - 1) / payload_cap;
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

            self.unacked.insert(seq, UnackedEntry {
                wire:       wire.clone(),
                first_sent: now,
                last_sent:  now,
                retx_count: 0,
                is_retx:    false,
            });

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

        // Retransmit and apply exponential backoff.
        let mut wires = Vec::with_capacity(retx.len());
        for seq in retx {
            if let Some(entry) = self.unacked.get_mut(&seq) {
                entry.last_sent = now;
                entry.retx_count += 1;
                entry.is_retx = true;
                wires.push(entry.wire.clone());
            }
        }

        // Exponential backoff: double RTO on any retransmit.
        if !wires.is_empty() {
            self.rto_us = (self.rto_us * 2).min(MAX_RTO_US);
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

    /// Update SRTT, RTTVAR, and RTO per RFC 6298.
    fn update_rto(&mut self, rtt_us: f64) {
        if self.srtt_us == 0.0 {
            // First measurement.
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2.0;
        } else {
            self.rttvar_us = (1.0 - BETA) * self.rttvar_us + BETA * (self.srtt_us - rtt_us).abs();
            self.srtt_us = (1.0 - ALPHA) * self.srtt_us + ALPHA * rtt_us;
        }
        let rto = self.srtt_us + (4.0 * self.rttvar_us).max(GRANULARITY_US as f64);
        self.rto_us = (rto as u64).clamp(MIN_RTO_US, MAX_RTO_US);
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

    #[test]
    fn retransmit_after_rto() {
        let mut rel = LpReliability::new(1400);
        rel.rto_us = 1000; // 1ms for testing

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
        let mut rel = LpReliability::new(1400);
        rel.rto_us = 1000; // 1ms for testing
        rel.max_retries = 1;

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
        assert_eq!(rel.rto_us, INITIAL_RTO_US);

        // Simulate low-RTT measurements.
        for _ in 0..10 {
            rel.update_rto(500.0); // 500 µs
        }
        // RTO should have converged to near the minimum.
        assert!(rel.rto_us <= MIN_RTO_US + GRANULARITY_US);
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
}
