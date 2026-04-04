//! Minimal slice-based NDN packet encoder.
//!
//! Unlike `ndn-packet`'s `encode` module (which uses `BytesMut`), these
//! functions write directly into caller-supplied `&mut [u8]` buffers.
//! No heap allocation is required.
//!
//! The nonce is caller-supplied. Use an MCU hardware RNG, a counter backed
//! by a `static AtomicU32`, or any other source of per-packet randomness.

// ── NDN TLV type codes ────────────────────────────────────────────────────────

const TYPE_INTEREST: u64 = 0x05;
const TYPE_DATA: u64 = 0x06;
const TYPE_NAME: u64 = 0x07;
const TYPE_NAME_COMPONENT: u64 = 0x08;
const TYPE_CAN_BE_PREFIX: u64 = 0x21;
const TYPE_MUST_BE_FRESH: u64 = 0x12;
const TYPE_NONCE: u64 = 0x0a;
const TYPE_INTEREST_LIFETIME: u64 = 0x0c;
const TYPE_CONTENT: u64 = 0x15;
const TYPE_SIGNATURE_INFO: u64 = 0x16;
const TYPE_SIGNATURE_VALUE: u64 = 0x17;
const TYPE_SIGNATURE_TYPE: u64 = 0x1b;

/// Encode an Interest packet into `buf`.
///
/// # Parameters
///
/// - `buf`: output buffer (must be large enough; ~64 + name size bytes is typical).
/// - `name_components`: name components as raw byte slices (GenericNameComponent values).
/// - `nonce`: 32-bit nonce (must be unique per Interest for loop detection).
/// - `lifetime_ms`: Interest lifetime in milliseconds (0 = omit, forwarder uses default).
/// - `can_be_prefix`: set the CanBePrefix selector.
/// - `must_be_fresh`: set the MustBeFresh selector.
///
/// # Returns
///
/// Number of bytes written, or `None` if `buf` is too small.
pub fn encode_interest(
    buf: &mut [u8],
    name_components: &[&[u8]],
    nonce: u32,
    lifetime_ms: u32,
    can_be_prefix: bool,
    must_be_fresh: bool,
) -> Option<usize> {
    // Build the Name TLV value into a stack buffer.
    let mut name_val = [0u8; 128];
    let mut w = Cursor::new(&mut name_val);
    for comp in name_components {
        w.write_tlv(TYPE_NAME_COMPONENT, comp)?;
    }
    let name_val_len = w.pos;

    // Build the Interest inner content.
    let mut inner = [0u8; 224];
    let mut w = Cursor::new(&mut inner);
    w.write_tlv_with_value(TYPE_NAME, &name_val[..name_val_len])?;
    if can_be_prefix {
        w.write_tlv(TYPE_CAN_BE_PREFIX, &[])?;
    }
    if must_be_fresh {
        w.write_tlv(TYPE_MUST_BE_FRESH, &[])?;
    }
    w.write_tlv(TYPE_NONCE, &nonce.to_be_bytes())?;
    if lifetime_ms > 0 {
        let nni = encode_nni(lifetime_ms as u64);
        w.write_tlv(TYPE_INTEREST_LIFETIME, nni.as_slice())?;
    }
    let inner_len = w.pos;

    // Write the outer Interest TLV.
    let mut out = Cursor::new(buf);
    out.write_tlv_with_value(TYPE_INTEREST, &inner[..inner_len])?;
    Some(out.pos)
}

/// Encode an unsigned Data packet into `buf`.
///
/// Writes a DigestSha256 signature (type 0) with a 32-byte zero placeholder.
/// For embedded nodes that produce sensor readings, this produces a
/// well-formed packet that NDN forwarders accept and cache.
///
/// # Returns
///
/// Number of bytes written, or `None` if `buf` is too small.
pub fn encode_data(buf: &mut [u8], name_components: &[&[u8]], content: &[u8]) -> Option<usize> {
    // Name value.
    let mut name_val = [0u8; 128];
    let mut w = Cursor::new(&mut name_val);
    for comp in name_components {
        w.write_tlv(TYPE_NAME_COMPONENT, comp)?;
    }
    let name_val_len = w.pos;

    // SignatureInfo value: SignatureType = DigestSha256 (0).
    let mut sig_info_val = [0u8; 8];
    let mut w = Cursor::new(&mut sig_info_val);
    w.write_tlv(TYPE_SIGNATURE_TYPE, &[0u8])?;
    let sig_info_len = w.pos;

    // Data inner content.
    let mut inner = [0u8; 512];
    let mut w = Cursor::new(&mut inner);
    w.write_tlv_with_value(TYPE_NAME, &name_val[..name_val_len])?;
    w.write_tlv(TYPE_CONTENT, content)?;
    w.write_tlv_with_value(TYPE_SIGNATURE_INFO, &sig_info_val[..sig_info_len])?;
    w.write_tlv(TYPE_SIGNATURE_VALUE, &[0u8; 32])?;
    let inner_len = w.pos;

    // Outer Data TLV.
    let mut out = Cursor::new(buf);
    out.write_tlv_with_value(TYPE_DATA, &inner[..inner_len])?;
    Some(out.pos)
}

// ── NonNegativeInteger encoding ───────────────────────────────────────────────

struct NniBytes {
    data: [u8; 8],
    len: usize,
}

impl NniBytes {
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

fn encode_nni(val: u64) -> NniBytes {
    let be = val.to_be_bytes();
    if val <= 0xFF {
        NniBytes { data: [be[7], 0, 0, 0, 0, 0, 0, 0], len: 1 }
    } else if val <= 0xFFFF {
        NniBytes { data: [be[6], be[7], 0, 0, 0, 0, 0, 0], len: 2 }
    } else if val <= 0xFFFF_FFFF {
        NniBytes { data: [be[4], be[5], be[6], be[7], 0, 0, 0, 0], len: 4 }
    } else {
        NniBytes { data: be, len: 8 }
    }
}

// ── Cursor-based buffer writer ────────────────────────────────────────────────

struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn write_bytes(&mut self, data: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(data.len())?;
        if end > self.buf.len() {
            return None;
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Some(())
    }

    fn write_varu64(&mut self, val: u64) -> Option<()> {
        // NDN varint: 1 byte for 0x00..0xFC, 3 bytes (0xFD prefix) for 0xFD..0xFFFF,
        // 5 bytes (0xFE prefix) for 0x10000..0xFFFFFFFF, 9 bytes (0xFF prefix) otherwise.
        if val < 0xFD {
            self.write_bytes(&[val as u8])
        } else if val <= 0xFFFF {
            let be = (val as u16).to_be_bytes();
            self.write_bytes(&[0xFD, be[0], be[1]])
        } else if val <= 0xFFFF_FFFF {
            let be = (val as u32).to_be_bytes();
            self.write_bytes(&[0xFE, be[0], be[1], be[2], be[3]])
        } else {
            let be = val.to_be_bytes();
            self.write_bytes(&[0xFF, be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7]])
        }
    }

    /// Write a TLV with a pre-computed value slice (type + length + value).
    fn write_tlv_with_value(&mut self, typ: u64, value: &[u8]) -> Option<()> {
        self.write_varu64(typ)?;
        self.write_varu64(value.len() as u64)?;
        self.write_bytes(value)
    }

    /// Alias for `write_tlv_with_value` (matches usage pattern in callers).
    fn write_tlv(&mut self, typ: u64, value: &[u8]) -> Option<()> {
        self.write_tlv_with_value(typ, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{Data, Interest};
    use bytes::Bytes;

    #[test]
    fn encode_decode_interest_roundtrip() {
        let mut buf = [0u8; 256];
        let n = encode_interest(&mut buf, &[b"ndn", b"test"], 0xDEAD_BEEF, 4000, false, false)
            .expect("encode succeeded");
        let raw = Bytes::copy_from_slice(&buf[..n]);
        let interest = Interest::decode(raw).expect("decode succeeded");
        assert_eq!(interest.name.len(), 2);
        assert_eq!(interest.name.components()[0].value.as_ref(), b"ndn");
        assert_eq!(interest.name.components()[1].value.as_ref(), b"test");
        assert_eq!(interest.nonce(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn encode_decode_data_roundtrip() {
        let mut buf = [0u8; 256];
        let n = encode_data(&mut buf, &[b"ndn", b"sensor"], b"temperature=23")
            .expect("encode succeeded");
        let raw = Bytes::copy_from_slice(&buf[..n]);
        let data = Data::decode(raw).expect("decode succeeded");
        assert_eq!(data.name.len(), 2);
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"temperature=23" as &[u8]));
    }

    #[test]
    fn buffer_too_small_returns_none() {
        let mut buf = [0u8; 4]; // way too small
        let result = encode_interest(&mut buf, &[b"ndn", b"test"], 1, 0, false, false);
        assert!(result.is_none());
    }

    #[test]
    fn encode_interest_with_selectors() {
        let mut buf = [0u8; 256];
        let n = encode_interest(&mut buf, &[b"test"], 99, 0, true, true).unwrap();
        let raw = Bytes::copy_from_slice(&buf[..n]);
        let interest = Interest::decode(raw).unwrap();
        assert!(interest.selectors().can_be_prefix);
        assert!(interest.selectors().must_be_fresh);
    }

    #[test]
    fn minimal_length_encoding() {
        // Verify that the encoder produces minimal (non-3-byte-padded) TLV lengths.
        let mut buf = [0u8; 64];
        let _n = encode_interest(&mut buf, &[b"x"], 1, 0, false, false).unwrap();
        // The outer Interest TLV length (byte index 1) should be < 0xFD for a short name.
        assert!(buf[1] < 0xFD, "expected minimal 1-byte length, got 0x{:02X}", buf[1]);
    }
}
