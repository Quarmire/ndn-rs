//! Platform-neutral NDNts BLE fragmentation and reassembly.
//!
//! # Wire format
//!
//! - **Unfragmented** (packet ≤ `max_payload` bytes): sent as raw NDN TLV,
//!   no header byte.
//! - **Fragmented** (packet > `max_payload` bytes): each BLE write/notify
//!   carries one fragment prefixed by a 1-byte header:
//!
//! ```text
//! ┌─────────────────────┬──────────────────────────┐
//! │  Header (1 byte)    │  Fragment payload         │
//! │  0x80|seq  (first)  │  ≤ max_payload − 1 bytes  │
//! │  seq       (cont.)  │                            │
//! └─────────────────────┴──────────────────────────┘
//! ```
//!
//! `seq` is a monotonically incrementing 7-bit counter (wraps at 0x7F).
//! The high bit distinguishes first fragments from continuations.
//!
//! Reassembly is self-delimiting: after accumulating fragment data the
//! receiver parses the top-level NDN TLV length to determine when the
//! packet is complete (no fragment-count field needed).

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// ATT protocol overhead per write/notify (1-byte opcode + 2-byte handle).
pub const ATT_OVERHEAD: usize = 3;

/// Size of the NDNts BLE fragment header.
const FRAG_HDR: usize = 1;

// ── Fragmentation (TX) ────────────────────────────────────────────────────────

/// Send one NDN packet over BLE, fragmenting if it exceeds `max_payload`.
///
/// `writer` must be the `AsyncWrite` handle for a single BLE notify/write
/// characteristic.  Each `write_all` call maps to exactly one ATT operation.
pub async fn send_pkt(
    writer: &mut (impl AsyncWrite + Unpin),
    pkt: &Bytes,
    max_payload: usize,
) -> std::io::Result<()> {
    if pkt.len() <= max_payload {
        // Fits in one BLE payload — no fragment header.
        writer.write_all(pkt).await
    } else {
        // Fragment: each chunk prefixed with a 1-byte header.
        let frag_payload = max_payload.saturating_sub(FRAG_HDR);
        let mut seq: u8 = 0;
        let mut is_first = true;
        let mut offset = 0;
        while offset < pkt.len() {
            let end = (offset + frag_payload).min(pkt.len());
            let chunk = &pkt[offset..end];
            let header = if is_first {
                is_first = false;
                0x80 | (seq & 0x7F)
            } else {
                seq & 0x7F
            };
            seq = seq.wrapping_add(1);
            let mut frag = BytesMut::with_capacity(FRAG_HDR + chunk.len());
            frag.extend_from_slice(&[header]);
            frag.extend_from_slice(chunk);
            writer.write_all(&frag).await?;
            offset = end;
        }
        Ok(())
    }
}

/// Like [`send_pkt`] but writes fragments to a `Vec<u8>` accumulator instead
/// of an async writer.  Used by the macOS and embedded platforms where
/// fragmentation must be done synchronously before handing bytes to the OS.
pub fn fragment_to_vec(pkt: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
    if pkt.len() <= max_payload {
        return vec![pkt.to_vec()];
    }
    let frag_payload = max_payload.saturating_sub(FRAG_HDR);
    let mut frags = Vec::new();
    let mut seq: u8 = 0;
    let mut is_first = true;
    let mut offset = 0;
    while offset < pkt.len() {
        let end = (offset + frag_payload).min(pkt.len());
        let chunk = &pkt[offset..end];
        let header = if is_first {
            is_first = false;
            0x80 | (seq & 0x7F)
        } else {
            seq & 0x7F
        };
        seq = seq.wrapping_add(1);
        let mut frag = Vec::with_capacity(FRAG_HDR + chunk.len());
        frag.push(header);
        frag.extend_from_slice(chunk);
        frags.push(frag);
        offset = end;
    }
    frags
}

// ── Reassembly (RX) ───────────────────────────────────────────────────────────

/// Reassembles fragmented NDN packets received from BLE writes.
///
/// Call [`push`] once per BLE write payload (one ATT operation = one call).
/// Returns `Some(packet)` when the accumulated bytes form a complete NDN TLV
/// packet; returns `None` while still waiting for more fragments.
///
/// [`push`]: Assembler::push
#[derive(Default)]
pub struct Assembler {
    buf: BytesMut,
    active: bool,
}

impl Assembler {
    /// Process one BLE write payload.
    pub fn push(&mut self, chunk: Bytes) -> Option<Bytes> {
        if chunk.is_empty() {
            return None;
        }
        let first_byte = chunk[0];
        if first_byte & 0x80 != 0 {
            // First fragment — discard any partial previous packet and start fresh.
            self.buf.clear();
            self.buf.extend_from_slice(&chunk[1..]);
            self.active = true;
        } else if self.active {
            // Continuation fragment.
            self.buf.extend_from_slice(&chunk[1..]);
        } else {
            // No header byte → complete unfragmented packet.
            return Some(chunk);
        }
        // After each fragment, check TLV completeness.
        if let Some(len) = tlv_packet_end(&self.buf) {
            let pkt = self.buf.split_to(len).freeze();
            self.active = false;
            return Some(pkt);
        }
        None
    }
}

// ── TLV completeness check ────────────────────────────────────────────────────

/// Parse an NDN TLV varint (type or length field) from the start of `buf`.
/// Returns `(value, bytes_consumed)` or `None` if `buf` is too short.
fn parse_varlength(buf: &[u8]) -> Option<(u64, usize)> {
    match buf.first().copied()? {
        b if b <= 252 => Some((b as u64, 1)),
        253 if buf.len() >= 3 => {
            Some((u16::from_be_bytes(buf[1..3].try_into().unwrap()) as u64, 3))
        }
        254 if buf.len() >= 5 => {
            Some((u32::from_be_bytes(buf[1..5].try_into().unwrap()) as u64, 5))
        }
        255 if buf.len() >= 9 => {
            Some((u64::from_be_bytes(buf[1..9].try_into().unwrap()), 9))
        }
        _ => None,
    }
}

/// Return the total byte length of the first complete NDN TLV packet in `buf`,
/// or `None` if the buffer does not yet contain a complete packet.
pub fn tlv_packet_end(buf: &[u8]) -> Option<usize> {
    let (_, type_len) = parse_varlength(buf)?;
    let (length, length_len) = parse_varlength(&buf[type_len..])?;
    let total = type_len + length_len + length as usize;
    if buf.len() >= total { Some(total) } else { None }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkt(type_byte: u8, payload: &[u8]) -> Bytes {
        let mut b = BytesMut::new();
        b.extend_from_slice(&[type_byte, payload.len() as u8]);
        b.extend_from_slice(payload);
        b.freeze()
    }

    // ── tlv_packet_end ──────────────────────────────────────────────────────

    #[test]
    fn tlv_end_complete() {
        let pkt = [0x05u8, 0x03, 0x00, 0x01, 0x02];
        assert_eq!(tlv_packet_end(&pkt), Some(5));
    }

    #[test]
    fn tlv_end_incomplete() {
        let pkt = [0x05u8, 0x04, 0x00, 0x01];
        assert_eq!(tlv_packet_end(&pkt), None);
    }

    #[test]
    fn tlv_end_exact() {
        let pkt = [0x06u8, 0x02, 0xAA, 0xBB];
        assert_eq!(tlv_packet_end(&pkt), Some(4));
    }

    // ── Assembler ────────────────────────────────────────────────────────────

    #[test]
    fn assembler_unfragmented() {
        let mut asm = Assembler::default();
        let pkt = make_pkt(0x05, b"hello");
        assert_eq!(asm.push(pkt.clone()), Some(pkt));
    }

    #[test]
    fn assembler_two_fragments() {
        let mut asm = Assembler::default();
        // Full packet: type=6, length=4, value=[1,2,3,4]  (6 bytes)
        // Fragment 1 (first): 0x80, then [0x06,0x04,0x01,0x02]
        // Fragment 2 (cont):  0x01, then [0x03,0x04]
        let f1 = Bytes::from_static(&[0x80, 0x06, 0x04, 0x01, 0x02]);
        let f2 = Bytes::from_static(&[0x01, 0x03, 0x04]);
        assert_eq!(asm.push(f1), None);
        assert_eq!(
            asm.push(f2),
            Some(Bytes::from_static(&[0x06, 0x04, 0x01, 0x02, 0x03, 0x04]))
        );
    }

    #[test]
    fn assembler_resets_on_new_first_frag() {
        let mut asm = Assembler::default();
        // Partial junk, then a new first-fragment that forms a complete packet.
        assert_eq!(asm.push(Bytes::from_static(&[0x80, 0xFF])), None);
        let complete = Bytes::from_static(&[0x80, 0x05, 0x01, 0x42]);
        assert_eq!(asm.push(complete), Some(Bytes::from_static(&[0x05, 0x01, 0x42])));
    }

    // ── fragment_to_vec ──────────────────────────────────────────────────────

    #[test]
    fn no_fragmentation_needed() {
        let pkt = make_pkt(0x05, &[1, 2, 3]);
        let frags = fragment_to_vec(&pkt, 64);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], &pkt[..]);
    }

    #[tokio::test]
    async fn send_pkt_no_frag() {
        let pkt = make_pkt(0x05, &[1, 2, 3]);
        let mut buf = Vec::new();
        send_pkt(&mut buf, &pkt, 64).await.unwrap();
        assert_eq!(&buf[..], &pkt[..]);
    }

    #[tokio::test]
    async fn frag_roundtrip() {
        // 10-byte payload, max_payload=4 → frag_payload=3 → ceil(10/3)=4 fragments.
        let payload = [0xAAu8; 10];
        let pkt = make_pkt(0x06, &payload);
        let mut wire = Vec::new();
        send_pkt(&mut wire, &pkt, 4).await.unwrap();

        let mut asm = Assembler::default();
        let mut result = None;
        let mut cursor = &wire[..];
        while !cursor.is_empty() {
            let n = 4.min(cursor.len());
            let chunk = Bytes::copy_from_slice(&cursor[..n]);
            cursor = &cursor[n..];
            if let Some(p) = asm.push(chunk) {
                result = Some(p);
            }
        }
        assert_eq!(result.as_deref(), Some(&pkt[..]));
    }
}
