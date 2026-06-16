//! NDNLPv2 fragmentation and reassembly. Splits network-layer packets into
//! MTU-sized LpPacket fragments carrying `Sequence` / `FragIndex` /
//! `FragCount`, and reassembles them on the receive side.

use std::collections::HashMap;
use std::time::Duration;
use web_time::Instant;

use bytes::Bytes;
use ndn_tlv::TlvWriter;

use crate::tlv_type;

pub const DEFAULT_UDP_MTU: usize = 1400;
const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

/// LpPacket TLV envelope + Sequence(8) + FragIndex(max 4) + FragCount(max 4)
/// + Fragment TLV header. Conservative estimate.
pub const FRAG_OVERHEAD: usize = 50;

/// Fragment a network-layer packet into NDNLPv2 LpPacket fragments.
///
/// # Panics
///
/// Panics if `mtu` is too small to fit even the fragmentation overhead.
pub fn fragment_packet(packet: &[u8], mtu: usize, base_seq: u64) -> Vec<Bytes> {
    let payload_cap = mtu
        .checked_sub(FRAG_OVERHEAD)
        .expect("MTU too small for fragmentation overhead");
    assert!(payload_cap > 0, "MTU too small");

    let frag_count = packet.len().div_ceil(payload_cap);

    let mut fragments = Vec::with_capacity(frag_count);
    for i in 0..frag_count {
        let start = i * payload_cap;
        let end = (start + payload_cap).min(packet.len());
        let chunk = &packet[start..end];

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            // NDNLPv2 §6.3: Sequence, FragIndex, FragCount MUST be exactly
            // 8-byte NonNegativeInteger. NFD rejects shorter encodings with
            // "must contain a 64-bit integer" parse error.
            w.write_tlv(tlv_type::LP_SEQUENCE, &(base_seq + i as u64).to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &(i as u64).to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &(frag_count as u64).to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAGMENT, chunk);
        });
        fragments.push(w.finish());
    }

    fragments
}

struct Pending {
    fragments: Vec<Option<Bytes>>,
    frag_count: usize,
    received: usize,
    created: Instant,
}

/// Maximum fragments per network-layer packet, matching NFD's
/// `nMaxFragments = 400`. `FragCount` values above this are rejected before
/// any allocation.
pub const MAX_FRAGMENTS: u64 = 400;

/// Cap on concurrent partial-reassembly groups. Without it, a peer sending
/// first-fragments of never-completed groups could grow memory between
/// `purge_expired` ticks.
pub const MAX_PENDING_PACKETS: usize = 1024;

pub struct ReassemblyBuffer {
    /// Keyed by `(endpoint_id, seq)`. Multi-access faces (UDP multicast,
    /// Ethernet, BLE multicast) must pass distinct endpoint identifiers per
    /// remote source so peers sharing a Sequence value do not collide.
    /// Unicast faces pass `0`. Mirrors NFD's `(EndpointId, Sequence)` key.
    pending: HashMap<(u64, u64), Pending>,
    timeout: Duration,
}

impl ReassemblyBuffer {
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            timeout,
        }
    }

    /// Returns `Some(complete_packet)` when all fragments have arrived.
    /// `endpoint_id` distinguishes remote senders on a multi-access face;
    /// unicast faces pass `0`.
    pub fn process(
        &mut self,
        endpoint_id: u64,
        seq: u64,
        frag_index: u64,
        frag_count: u64,
        fragment: Bytes,
    ) -> Option<Bytes> {
        // Bound `frag_count` before any allocation: an attacker-supplied
        // `FragCount = u32::MAX` would otherwise trigger a `usize::MAX`-sized
        // `vec![None; count]` below.
        if frag_count == 0 || frag_count > MAX_FRAGMENTS {
            return None;
        }
        let count = frag_count as usize;
        let idx = frag_index as usize;

        if idx >= count {
            return None;
        }

        let key = (endpoint_id, seq);
        // New keys honor the cap: purge expired entries, then evict the
        // oldest if still over. Continuing fragment groups bypass the check.
        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_PACKETS {
            self.purge_expired();
            if self.pending.len() >= MAX_PENDING_PACKETS
                && let Some(oldest_key) = self
                    .pending
                    .iter()
                    .min_by_key(|(_, v)| v.created)
                    .map(|(k, _)| *k)
            {
                self.pending.remove(&oldest_key);
            }
        }
        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            fragments: vec![None; count],
            frag_count: count,
            received: 0,
            created: Instant::now(),
        });

        if entry.frag_count != count || idx >= entry.frag_count {
            return None;
        }

        if entry.fragments[idx].is_none() {
            entry.received += 1;
        }
        entry.fragments[idx] = Some(fragment);

        if entry.received == entry.frag_count {
            let entry = self.pending.remove(&key).unwrap();
            let total_len: usize = entry
                .fragments
                .iter()
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

    pub fn purge_expired(&mut self) {
        let timeout = self.timeout;
        self.pending.retain(|_, v| v.created.elapsed() < timeout);
    }

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

    /// `(endpoint_id, seq)` keying isolates concurrent fragmenting peers on
    /// a multi-access face: two peers using the same `seq=42` must not
    /// overwrite each other's first fragment.
    #[test]
    fn n02_per_endpoint_keying_isolates_overlapping_sequences() {
        let mut buf = ReassemblyBuffer::default();

        let _ = buf.process(1, 42, 0, 2, Bytes::from_static(&[0xAA]));
        let _ = buf.process(2, 42, 0, 2, Bytes::from_static(&[0xBB]));

        assert_eq!(
            buf.pending.len(),
            2,
            "two endpoints with overlapping seq must produce two pending entries"
        );

        let a = buf
            .process(1, 42, 1, 2, Bytes::from_static(&[0xAA, 0xAA]))
            .expect("peer A reassembly should complete");
        assert_eq!(a.as_ref(), &[0xAA, 0xAA, 0xAA][..]);

        assert_eq!(buf.pending.len(), 1, "peer A's entry consumed");

        let b = buf
            .process(2, 42, 1, 2, Bytes::from_static(&[0xBB, 0xBB]))
            .expect("peer B reassembly should complete");
        assert_eq!(
            b.as_ref(),
            &[0xBB, 0xBB, 0xBB][..],
            "peer B's payload must NOT have been clobbered by peer A's same-seq write"
        );
        assert_eq!(buf.pending.len(), 0);
    }

    #[test]
    fn n01_oversized_frag_count_does_not_allocate() {
        let mut buf = ReassemblyBuffer::default();
        let result = buf.process(
            /* endpoint_id */ 0,
            /* seq */ 1,
            /* frag_index */ 0,
            /* frag_count */ u32::MAX as u64,
            Bytes::from_static(&[0xAA]),
        );
        assert!(
            result.is_none(),
            "process must return None for FragCount > MAX_FRAGMENTS"
        );
        // No Pending entry implies no allocation in the `vec![None; count]` path.
        assert!(buf.pending.is_empty(), "no Pending entry should be created");
    }

    #[test]
    fn n01_frag_count_at_limit_is_accepted() {
        let mut buf = ReassemblyBuffer::default();
        let result = buf.process(0, 2, 0, MAX_FRAGMENTS, Bytes::from_static(&[0xBB]));
        assert!(
            result.is_none(),
            "single fragment of multi-frag set is incomplete"
        );
        assert_eq!(
            buf.pending.len(),
            1,
            "Pending entry created for in-range FragCount"
        );
    }

    #[test]
    fn single_fragment_roundtrip() {
        let data = vec![0x06, 0x03, 0xAA, 0xBB, 0xCC]; // small "Data"
        let frags = fragment_packet(&data, DEFAULT_UDP_MTU, 100);
        assert_eq!(frags.len(), 1);

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
        assert!(
            frags.len() > 1,
            "expected multiple fragments, got {}",
            frags.len()
        );

        let mut buf = ReassemblyBuffer::default();
        let mut result = None;
        for (i, frag_bytes) in frags.iter().enumerate() {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            assert_eq!(lp.sequence, Some(42 + i as u64));
            assert!(lp.is_fragmented());

            let base_seq = lp.sequence.unwrap() - lp.frag_index.unwrap();
            result = buf.process(
                /* endpoint_id */ 0,
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

    fn base_seq(lp: &crate::lp::LpPacket) -> u64 {
        lp.sequence.unwrap() - lp.frag_index.unwrap()
    }

    #[test]
    fn out_of_order_reassembly() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 7);
        assert!(frags.len() > 2);

        let mut buf = ReassemblyBuffer::default();
        let mut result = None;
        for frag_bytes in frags.iter().rev() {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            result = buf.process(
                0,
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
        for frag_bytes in &frags[..frags.len() - 1] {
            let lp = crate::lp::LpPacket::decode(frag_bytes.clone()).unwrap();
            let r = buf.process(
                0,
                base_seq(&lp),
                lp.frag_index.unwrap(),
                lp.frag_count.unwrap(),
                lp.fragment.unwrap(),
            );
            assert!(r.is_none());
        }
        let lp0 = crate::lp::LpPacket::decode(frags[0].clone()).unwrap();
        let r = buf.process(
            0,
            base_seq(&lp0),
            lp0.frag_index.unwrap(),
            lp0.frag_count.unwrap(),
            lp0.fragment.unwrap(),
        );
        assert!(r.is_none());

        let lp_last = crate::lp::LpPacket::decode(frags.last().unwrap().clone()).unwrap();
        let r = buf.process(
            0,
            base_seq(&lp_last),
            lp_last.frag_index.unwrap(),
            lp_last.frag_count.unwrap(),
            lp_last.fragment.unwrap(),
        );
        assert!(r.is_some());
    }

    #[test]
    fn purge_expired() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 200, 1);

        let mut buf = ReassemblyBuffer::new(Duration::from_millis(0));
        let lp = crate::lp::LpPacket::decode(frags[0].clone()).unwrap();
        buf.process(
            0,
            base_seq(&lp),
            lp.frag_index.unwrap(),
            lp.frag_count.unwrap(),
            lp.fragment.unwrap(),
        );
        assert_eq!(buf.pending_count(), 1);

        buf.purge_expired();
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn each_fragment_within_mtu() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let mtu = 500;
        let frags = fragment_packet(&data, mtu, 0);
        for (i, frag) in frags.iter().enumerate() {
            assert!(
                frag.len() <= mtu,
                "fragment {i} is {} bytes, exceeds MTU {mtu}",
                frag.len()
            );
        }
    }

    /// `ReassemblyBuffer` caps the number of concurrent partial-reassembly
    /// groups so a peer feeding never-completing first-fragments cannot
    /// inflate memory between `purge_expired` ticks.
    #[test]
    fn b10_reassembly_buffer_caps_pending_groups() {
        let mut buf = ReassemblyBuffer::default();

        let overflow = (MAX_PENDING_PACKETS as u64) + 64;
        for seq in 0..overflow {
            let _ = buf.process(1, seq, 0, 2, Bytes::from_static(&[0xAB]));
        }

        assert!(
            buf.pending_count() <= MAX_PENDING_PACKETS,
            "pending buffer must not exceed cap (got {}, cap {})",
            buf.pending_count(),
            MAX_PENDING_PACKETS,
        );
    }
}
