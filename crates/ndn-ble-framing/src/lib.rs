//! Shared BLE wire-framing codec for ndn-rs faces.
//!
//! Two framings share the NDN-BLE GATT profile and the BLE advertising bearer:
//!
//! - **NDNLPv2** — ndn-rs native: one `LpPacket` (TLV `0x64`) per write/advert;
//!   reassembly is the engine pipeline's job, so the face passes frames through
//!   raw. Per-fragment overhead ≈ `ndn_packet::fragment::FRAG_OVERHEAD` (~50 B),
//!   which is *larger than a legacy BLE advertisement* — so NDNLPv2 needs
//!   extended advertising (or a GATT MTU) to fragment at all.
//! - **NDNts 1-byte header** — stock NDNts / `esp8266ndn`: first fragment
//!   `0x80 | seq`, continuations `seq & 0x7F`, unfragmented packets carry no
//!   header. ~1 byte of overhead, so it fits a legacy 31-byte advertisement.
//!   The engine pipeline can't reassemble this; the face does it with
//!   [`NdntsReassembler`] (point-to-point) or [`PerSenderReassembler`]
//!   (broadcast — keyed by L2 sender, since the 1-byte header carries no
//!   sender id).
//!
//! This crate is intentionally `tokio`-free and wasm-buildable so the browser
//! Web Bluetooth central, the native GATT faces, and the BLE advertising face
//! all share one copy.

use std::collections::HashMap;
use std::hash::Hash;

use bytes::Bytes;

use ndn_packet::fragment::fragment_packet;
use ndn_packet::lp::{encode_lp_packet, is_lp_packet};

/// Wire framing carried over the shared GATT characteristics / advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BleFraming {
    /// ndn-rs native NDNLPv2 (one `LpPacket` per write/advert).
    #[default]
    Ndnlpv2,
    /// NDNts/esp8266ndn 1-byte fragmentation header.
    Ndnts,
}

impl BleFraming {
    /// Detect the framing of an inbound frame from its first byte: `0x64` is
    /// the `LpPacket` TLV (NDNLPv2); anything else is NDNts — either a
    /// `0x80|seq` fragment header or a bare Interest/Data (`0x05`/`0x06`).
    pub fn detect(first_write: &[u8]) -> Self {
        match first_write.first() {
            Some(&0x64) => Self::Ndnlpv2,
            _ => Self::Ndnts,
        }
    }

    /// Value advertised by the capability characteristic.
    pub fn capability_byte(self) -> u8 {
        match self {
            Self::Ndnlpv2 => 1,
            Self::Ndnts => 2,
        }
    }

    /// Interpret a capability-characteristic value; unknown values default to
    /// NDNLPv2 (the characteristic only exists on ndn-rs peers).
    pub fn from_capability_byte(b: u8) -> Self {
        match b {
            2 => Self::Ndnts,
            _ => Self::Ndnlpv2,
        }
    }

    /// Frame `pkt` into fragments no larger than `ble_mtu` usable payload
    /// bytes. `seq` is bumped per fragmented NDNLPv2 packet (NDNts carries its
    /// own per-fragment seq and ignores it).
    pub fn frame(self, pkt: &Bytes, ble_mtu: usize, seq: &mut u64) -> Vec<Bytes> {
        match self {
            Self::Ndnlpv2 => {
                if is_lp_packet(pkt) {
                    vec![pkt.clone()]
                } else if pkt.len() + 4 <= ble_mtu {
                    vec![encode_lp_packet(pkt)]
                } else {
                    let s = *seq;
                    *seq = seq.wrapping_add(1);
                    fragment_packet(pkt, ble_mtu, s)
                }
            }
            Self::Ndnts => ndnts_frame(pkt, ble_mtu),
        }
    }
}

/// NDNts 1-byte-header fragmentation.
fn ndnts_frame(pkt: &[u8], max_payload: usize) -> Vec<Bytes> {
    if pkt.len() <= max_payload {
        return vec![Bytes::copy_from_slice(pkt)];
    }
    let frag_payload = max_payload.saturating_sub(1).max(1);
    let mut out = Vec::new();
    let mut offset = 0;
    let mut seq: u8 = 0;
    let mut first = true;
    while offset < pkt.len() {
        let end = (offset + frag_payload).min(pkt.len());
        let header = if first {
            first = false;
            0x80 | (seq & 0x7F)
        } else {
            seq & 0x7F
        };
        seq = (seq + 1) & 0x7F;
        let mut frag = Vec::with_capacity(1 + (end - offset));
        frag.push(header);
        frag.extend_from_slice(&pkt[offset..end]);
        out.push(Bytes::from(frag));
        offset = end;
    }
    out
}

/// Reassembles NDNts 1-byte-header fragments into complete TLV packets. One per
/// peer, fed in arrival order. NDNLPv2 needs no equivalent — the engine
/// pipeline's reassembly handles it.
#[derive(Default)]
pub struct NdntsReassembler {
    buffer: Vec<u8>,
    active: bool,
}

impl NdntsReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one frame; returns a complete packet when one is ready.
    pub fn feed(&mut self, fragment: &[u8]) -> Option<Bytes> {
        let first = *fragment.first()?;
        if first & 0x80 != 0 {
            self.buffer = fragment[1..].to_vec();
            self.active = true;
        } else if self.active {
            self.buffer.extend_from_slice(&fragment[1..]);
        } else {
            // Unfragmented packet (no header byte).
            return Some(Bytes::copy_from_slice(fragment));
        }
        let end = tlv_packet_end(&self.buffer)?;
        let pkt = Bytes::copy_from_slice(&self.buffer[..end]);
        self.buffer.drain(..end);
        if self.buffer.is_empty() {
            self.active = false;
        }
        Some(pkt)
    }
}

/// Per-sender NDNts reassembly for a **shared/broadcast** medium (BLE
/// advertising, multi-access) where fragments from multiple senders interleave.
/// The 1-byte header carries no sender id, so the demux key `K` (e.g. a BD_ADDR
/// `[u8; 6]`) must come from the link layer. A single [`NdntsReassembler`]
/// would splice fragments from different senders into garbage; this keeps one
/// buffer per sender.
pub struct PerSenderReassembler<K> {
    streams: HashMap<K, NdntsReassembler>,
}

impl<K: Eq + Hash> Default for PerSenderReassembler<K> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash> PerSenderReassembler<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one frame heard from `sender`; returns a complete packet when one
    /// is ready for that sender.
    pub fn feed(&mut self, sender: K, fragment: &[u8]) -> Option<Bytes> {
        self.streams.entry(sender).or_default().feed(fragment)
    }

    /// Forget a sender's partial buffer (peer gone, or GC of stale streams).
    pub fn forget(&mut self, sender: &K) {
        self.streams.remove(sender);
    }
}

fn parse_varnumber(buf: &[u8]) -> Option<(u64, usize)> {
    match buf.first().copied()? {
        b if b <= 252 => Some((b as u64, 1)),
        253 if buf.len() >= 3 => Some((u16::from_be_bytes([buf[1], buf[2]]) as u64, 3)),
        254 if buf.len() >= 5 => Some((
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64,
            5,
        )),
        255 if buf.len() >= 9 => Some((
            u64::from_be_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            9,
        )),
        _ => None,
    }
}

fn tlv_packet_end(buf: &[u8]) -> Option<usize> {
    let (_, type_len) = parse_varnumber(buf)?;
    let (length, length_len) = parse_varnumber(buf.get(type_len..)?)?;
    let total = type_len + length_len + length as usize;
    (buf.len() >= total).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_distinguishes_framings() {
        assert_eq!(BleFraming::detect(&[0x64, 0x05]), BleFraming::Ndnlpv2);
        assert_eq!(BleFraming::detect(&[0x80, 0xAA]), BleFraming::Ndnts); // first frag
        assert_eq!(BleFraming::detect(&[0x05, 0x03]), BleFraming::Ndnts); // bare Interest
        assert_eq!(BleFraming::detect(&[]), BleFraming::Ndnts);
    }

    #[test]
    fn capability_byte_roundtrip() {
        for f in [BleFraming::Ndnlpv2, BleFraming::Ndnts] {
            assert_eq!(BleFraming::from_capability_byte(f.capability_byte()), f);
        }
        assert_eq!(BleFraming::from_capability_byte(99), BleFraming::Ndnlpv2);
    }

    fn big_tlv(payload_len: usize) -> Bytes {
        // 0x06 (Data), 3-byte length form, then payload.
        let mut pkt = vec![0x06, 253, (payload_len >> 8) as u8, (payload_len & 0xff) as u8];
        pkt.extend((0..payload_len).map(|i| (i % 251) as u8));
        Bytes::from(pkt)
    }

    #[test]
    fn ndnts_frame_reassemble_roundtrip() {
        let bytes = big_tlv(200);
        let frags = BleFraming::Ndnts.frame(&bytes, 64, &mut 0);
        assert!(frags.len() > 1, "must fragment");
        assert!(frags.iter().all(|f| f.len() <= 64));

        let mut asm = NdntsReassembler::new();
        let mut got = None;
        for f in &frags {
            if let Some(p) = asm.feed(f) {
                got = Some(p);
            }
        }
        assert_eq!(got.expect("reassembled"), bytes);
    }

    #[test]
    fn ndnts_fits_legacy_advertisement_mtu() {
        // The whole point: NDNts framing fits a 26-byte legacy advert payload,
        // where NDNLPv2 (≈50 B overhead) cannot fragment at all.
        let bytes = big_tlv(120);
        let frags = BleFraming::Ndnts.frame(&bytes, 26, &mut 0);
        assert!(frags.len() > 1);
        assert!(
            frags.iter().all(|f| f.len() <= 26),
            "every fragment must fit one legacy advertisement"
        );
        let mut asm = NdntsReassembler::new();
        let mut got = None;
        for f in &frags {
            got = asm.feed(f).or(got);
        }
        assert_eq!(got.expect("reassembled"), bytes);
    }

    #[test]
    fn ndnts_unfragmented_passthrough() {
        let small = Bytes::from_static(&[0x05, 0x03, 1, 2, 3]);
        let frags = BleFraming::Ndnts.frame(&small, 64, &mut 0);
        assert_eq!(frags, vec![small.clone()]);
        assert_eq!(NdntsReassembler::new().feed(&small), Some(small));
    }

    #[test]
    fn ndnlpv2_wraps_bare_packet() {
        let payload = Bytes::from_static(&[0x05, 0x02, 1, 2]);
        let frags = BleFraming::Ndnlpv2.frame(&payload, 244, &mut 0);
        assert_eq!(frags.len(), 1);
        assert!(is_lp_packet(&frags[0]));
    }

    /// Interleaved fragments from two senders must NOT corrupt each other —
    /// the per-sender reassembler keeps a buffer per key.
    #[test]
    fn per_sender_reassembly_isolates_interleaved_streams() {
        let a = big_tlv(100);
        let b = big_tlv(150);
        let fa = BleFraming::Ndnts.frame(&a, 26, &mut 0);
        let fb = BleFraming::Ndnts.frame(&b, 26, &mut 0);

        let mut r = PerSenderReassembler::<u8>::new();
        let mut got_a = None;
        let mut got_b = None;
        // Interleave A and B fragments arbitrarily.
        let mut ia = fa.iter();
        let mut ib = fb.iter();
        loop {
            let mut progressed = false;
            if let Some(f) = ia.next() {
                got_a = r.feed(0xAA, f).or(got_a);
                progressed = true;
            }
            if let Some(f) = ib.next() {
                got_b = r.feed(0xBB, f).or(got_b);
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        assert_eq!(got_a.expect("A reassembled"), a);
        assert_eq!(got_b.expect("B reassembled"), b);
    }
}
