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

/// Maximum bytes a single NDNts reassembly will buffer (audit BLE-1). A peer
/// could otherwise declare a huge TLV length in its first fragment and stream
/// continuation fragments to grow the buffer without bound. Well above any
/// BLE-delivered NDN packet (≤ ~8800), low enough to bound memory.
const MAX_REASSEMBLY_SIZE: usize = 16 * 1024;

/// Maximum concurrent per-sender reassembly streams on a broadcast medium
/// (audit BLE-3). Bounds a spoofed-BD_ADDR flood; far above any realistic count
/// of simultaneously-fragmenting BLE peers.
const MAX_SENDERS: usize = 256;

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
        // BLE-1: abandon a partial that grows past — or already declares more
        // than — MAX_REASSEMBLY_SIZE, so a peer can't exhaust memory by streaming
        // toward a huge declared TLV length.
        if self.buffer.len() > MAX_REASSEMBLY_SIZE
            || declared_exceeds(&self.buffer, MAX_REASSEMBLY_SIZE)
        {
            self.buffer.clear();
            self.active = false;
            return None;
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

impl<K: Eq + Hash + Clone> PerSenderReassembler<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one frame heard from `sender`; returns a complete packet when one
    /// is ready for that sender.
    pub fn feed(&mut self, sender: K, fragment: &[u8]) -> Option<Bytes> {
        // BLE-3: bound concurrent sender streams. A spoofed-BD_ADDR flood would
        // otherwise grow the map without limit; drop one stream to make room.
        if !self.streams.contains_key(&sender)
            && self.streams.len() >= MAX_SENDERS
            && let Some(victim) = self.streams.keys().next().cloned()
        {
            self.streams.remove(&victim);
        }
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

/// Declared total size of the TLV at the front of `buf`, if its type+length
/// header is fully present. `None` while the header is still incomplete.
fn tlv_declared_total(buf: &[u8]) -> Option<usize> {
    let (_, type_len) = parse_varnumber(buf)?;
    let (length, length_len) = parse_varnumber(buf.get(type_len..)?)?;
    // BLE-2: checked arithmetic so a near-u64::MAX declared length can't wrap.
    type_len
        .checked_add(length_len)?
        .checked_add(usize::try_from(length).ok()?)
}

/// `true` if the front TLV declares a total larger than `max` (or overflows).
fn declared_exceeds(buf: &[u8], max: usize) -> bool {
    match tlv_declared_total(buf) {
        Some(total) => total > max,
        // Header parsed but the size arithmetic overflowed → definitely too big.
        // Header not yet complete → not (yet) known to exceed; the buffer-length
        // cap still applies.
        None => {
            // Distinguish "overflow" from "incomplete header": only the former
            // means too-large. parse succeeded but checked_add returned None.
            parse_varnumber(buf)
                .and_then(|(_, t)| buf.get(t..).and_then(parse_varnumber).map(|_| true))
                .unwrap_or(false)
        }
    }
}

fn tlv_packet_end(buf: &[u8]) -> Option<usize> {
    let total = tlv_declared_total(buf)?;
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
        let mut pkt = vec![
            0x06,
            253,
            (payload_len >> 8) as u8,
            (payload_len & 0xff) as u8,
        ];
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
    fn ble1_oversize_declared_length_is_abandoned() {
        // First fragment declares a ~1 GiB TLV via the 4-byte length form. The
        // reassembler must abandon it immediately (return None, drop the
        // partial) rather than waiting to buffer ~1 GiB of continuations.
        let mut asm = NdntsReassembler::new();
        // 0x80 = first-frag header byte; then 0x06 (Data), 254 (4-byte len), 1 GiB.
        let first = [0x80, 0x06, 254, 0x40, 0x00, 0x00, 0x00];
        assert!(asm.feed(&first).is_none());
        assert!(asm.buffer.is_empty(), "oversize partial must be dropped");
        // A subsequent legitimate fragmented packet still reassembles fine.
        let bytes = big_tlv(200);
        let frags = BleFraming::Ndnts.frame(&bytes, 64, &mut 0);
        let mut got = None;
        for f in &frags {
            if let Some(p) = asm.feed(f) {
                got = Some(p);
            }
        }
        assert_eq!(got.expect("reassembled after abandon"), bytes);
    }

    #[test]
    fn ble3_sender_map_is_capped() {
        let mut asm: PerSenderReassembler<[u8; 6]> = PerSenderReassembler::new();
        // A spoofed-BD_ADDR flood: each "sender" opens a partial stream.
        for i in 0..(MAX_SENDERS + 500) as u32 {
            let mut addr = [0u8; 6];
            addr[..4].copy_from_slice(&i.to_be_bytes());
            // First-frag header so a partial buffer is retained for this sender.
            let _ = asm.feed(addr, &[0x80, 0x06, 253, 0x10, 0x00]);
        }
        assert!(asm.streams.len() <= MAX_SENDERS);
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
