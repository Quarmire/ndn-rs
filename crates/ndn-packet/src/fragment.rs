//! NDNLPv2 fragmentation and reassembly.
//!
//! NDN Data packets can be up to ~8800 bytes, but a UDP datagram over Ethernet
//! should stay within the path MTU (typically ~1400 bytes).  NDNLPv2 handles
//! this by splitting a packet into multiple LpPacket fragments, each carrying
//! `Sequence`, `FragIndex`, and `FragCount` fields.
//!
//! This module provides:
//! - [`fragment_packet`]: split a packet into MTU-sized LpPacket fragments
//! - [`ReassemblyBuffer`]: per-peer stateful reassembly of incoming fragments

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_tlv::TlvWriter;

use crate::tlv_type;
use crate::encode::nni;

/// Default MTU for UDP faces (conservative for Ethernet + IP + UDP headers).
pub const DEFAULT_UDP_MTU: usize = 1400;

/// Default timeout for incomplete reassemblies.
const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Overhead per fragment: LpPacket TLV envelope + Sequence(8) + FragIndex(max 4)
/// + FragCount(max 4) + Fragment TLV header.  Conservative estimate.
pub const FRAG_OVERHEAD: usize = 50;

/// Fragment a network-layer packet into NDNLPv2 LpPacket fragments.
///
/// Each fragment is an independently-decodable LpPacket containing:
/// - `Sequence` = `base_seq` (same for all fragments of one packet)
/// - `FragIndex` = 0-based index
/// - `FragCount` = total number of fragments
/// - `Fragment` = the chunk of the original packet
///
/// If the packet fits in a single fragment, a single LpPacket is returned
/// (still carrying the fragmentation fields, as required by NDNLPv2 when
/// the sender uses fragmentation).
///
/// # Panics
///
/// Panics if `mtu` is too small to fit even the fragmentation overhead.
pub fn fragment_packet(packet: &[u8], mtu: usize, base_seq: u64) -> Vec<Bytes> {
    let payload_cap = mtu.checked_sub(FRAG_OVERHEAD)
        .expect("MTU too small for fragmentation overhead");
    assert!(payload_cap > 0, "MTU too small");

    let frag_count = (packet.len() + payload_cap - 1) / payload_cap;

    let mut fragments = Vec::with_capacity(frag_count);
    for i in 0..frag_count {
        let start = i * payload_cap;
        let end = (start + payload_cap).min(packet.len());
        let chunk = &packet[start..end];

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            let (buf, len) = nni(base_seq + i as u64);
            w.write_tlv(tlv_type::LP_SEQUENCE, &buf[..len]);
            let (buf, len) = nni(i as u64);
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &buf[..len]);
            let (buf, len) = nni(frag_count as u64);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &buf[..len]);
            w.write_tlv(tlv_type::LP_FRAGMENT, chunk);
        });
        fragments.push(w.finish());
    }

    fragments
}

/// State for one in-progress reassembly.
struct Pending {
    fragments:  Vec<Option<Bytes>>,
    frag_count: usize,
    received:   usize,
    created:    Instant,
}

/// Per-peer reassembly buffer for NDNLPv2 fragments.
///
/// Tracks incomplete reassemblies keyed by sequence number.  When all fragments
/// of a packet arrive, `process()` returns the reassembled packet.
pub struct ReassemblyBuffer {
    pending: HashMap<u64, Pending>,
    timeout: Duration,
}

impl ReassemblyBuffer {
    pub fn new(timeout: Duration) -> Self {
        Self { pending: HashMap::new(), timeout }
    }

    /// Feed a decoded LpPacket fragment.
    ///
    /// Returns `Some(complete_packet)` when all fragments of the original
    /// packet have been received.  Returns `None` if fragments are still
    /// missing or if the packet has no fragmentation fields.
    pub fn process(&mut self, seq: u64, frag_index: u64, frag_count: u64, fragment: Bytes) -> Option<Bytes> {
        let count = frag_count as usize;
        let idx = frag_index as usize;

        if count == 0 || idx >= count {
            return None;
        }

        let entry = self.pending.entry(seq).or_insert_with(|| Pending {
            fragments: vec![None; count],
            frag_count: count,
            received: 0,
            created: Instant::now(),
        });

        // Validate consistency.
        if entry.frag_count != count || idx >= entry.frag_count {
            return None;
        }

        // Don't double-count duplicates.
        if entry.fragments[idx].is_none() {
            entry.received += 1;
        }
        entry.fragments[idx] = Some(fragment);

        if entry.received == entry.frag_count {
            let entry = self.pending.remove(&seq).unwrap();
            let total_len: usize = entry.fragments.iter()
                .map(|f| f.as_ref().unwrap().len())
                .sum();
            let mut buf = Vec::with_capacity(total_len);
            for frag in &entry.fragments {
                buf.extend_from_slice(frag.as_ref().unwrap());
            }
            Some(Bytes::from(buf))
        } else {
            None
        }
    }

    /// Drop incomplete reassemblies older than the configured timeout.
    pub fn purge_expired(&mut self) {
        let timeout = self.timeout;
        self.pending.retain(|_, v| v.created.elapsed() < timeout);
    }

    /// Number of in-progress reassemblies.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_REASSEMBLY_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_roundtrip() {
        let data = vec![0x06, 0x03, 0xAA, 0xBB, 0xCC]; // small "Data"
        let frags = fragment_packet(&data, DEFAULT_UDP_MTU, 100);
        assert_eq!(frags.len(), 1);

        // Decode the LpPacket and check fields.
        let lp = crate::lp::LpPacket::decode(frags[0].clone()).unwrap();
        assert_eq!(lp.sequence, Some(100));
        assert_eq!(lp.frag_index, Some(0));
        assert_eq!(lp.frag_count, Some(1));
        assert_eq!(lp.fragment.as_deref().unwrap(), &data[..]);
    }

    #[test]
    fn multi_fragment_roundtrip() {
        // Create a packet larger than the MTU.
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 42);
        assert!(frags.len() > 1, "expected multiple fragments, got {}", frags.len());

        // Reassemble using base_seq = sequence - frag_index.
        let mut buf = ReassemblyBuffer::default();
        let mut result = None;
        for (i, frag_bytes) in frags.iter().enumerate() {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            // Per-fragment unique sequence: base_seq + i.
            assert_eq!(lp.sequence, Some(42 + i as u64));
            assert!(lp.is_fragmented());

            let base_seq = lp.sequence.unwrap() - lp.frag_index.unwrap();
            result = buf.process(
                base_seq,
                lp.frag_index.unwrap(),
                lp.frag_count.unwrap(),
                lp.fragment.unwrap(),
            );
        }

        let reassembled = result.expect("reassembly should complete");
        assert_eq!(reassembled.as_ref(), &data[..]);
        assert_eq!(buf.pending_count(), 0);
    }

    /// Helper: compute base_seq from per-fragment unique sequence.
    fn base_seq(lp: &crate::lp::LpPacket) -> u64 {
        lp.sequence.unwrap() - lp.frag_index.unwrap()
    }

    #[test]
    fn out_of_order_reassembly() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 7);
        assert!(frags.len() > 2);

        // Feed in reverse order.
        let mut buf = ReassemblyBuffer::default();
        let mut result = None;
        for frag_bytes in frags.iter().rev() {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            result = buf.process(
                base_seq(&lp),
                lp.frag_index.unwrap(),
                lp.frag_count.unwrap(),
                lp.fragment.unwrap(),
            );
        }

        let reassembled = result.expect("out-of-order reassembly should complete");
        assert_eq!(reassembled.as_ref(), &data[..]);
    }

    #[test]
    fn duplicate_fragment_handled() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 1);

        let mut buf = ReassemblyBuffer::default();
        // Feed all fragments, then re-feed the first one.
        for frag_bytes in &frags[..frags.len() - 1] {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            let r = buf.process(base_seq(&lp), lp.frag_index.unwrap(), lp.frag_count.unwrap(), lp.fragment.unwrap());
            assert!(r.is_none());
        }
        // Duplicate of first fragment.
        let lp0 = crate::lp::LpPacket::decode(frags[0].clone()).unwrap();
        let r = buf.process(base_seq(&lp0), lp0.frag_index.unwrap(), lp0.frag_count.unwrap(), lp0.fragment.unwrap());
        assert!(r.is_none());

        // Now feed the last fragment to complete.
        let lp_last = crate::lp::LpPacket::decode(frags.last().unwrap().clone()).unwrap();
        let r = buf.process(base_seq(&lp_last), lp_last.frag_index.unwrap(), lp_last.frag_count.unwrap(), lp_last.fragment.unwrap());
        assert!(r.is_some());
    }

    #[test]
    fn purge_expired() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 1);

        let mut buf = ReassemblyBuffer::new(Duration::from_millis(0));
        // Feed only the first fragment.
        let lp = crate::lp::LpPacket::decode(frags[0].clone()).unwrap();
        buf.process(base_seq(&lp), lp.frag_index.unwrap(), lp.frag_count.unwrap(), lp.fragment.unwrap());
        assert_eq!(buf.pending_count(), 1);

        // Purge — timeout is 0ms so everything is expired.
        buf.purge_expired();
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn each_fragment_within_mtu() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let mtu = 500;
        let frags = fragment_packet(&data, mtu, 0);
        for (i, frag) in frags.iter().enumerate() {
            assert!(frag.len() <= mtu, "fragment {i} is {} bytes, exceeds MTU {mtu}", frag.len());
        }
    }
}
