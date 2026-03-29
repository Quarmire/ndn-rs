use bytes::{BufMut, BytesMut};

use crate::varu64_size;

/// TLV encoder backed by a growable `BytesMut` buffer.
pub struct TlvWriter {
    buf: BytesMut,
}

impl TlvWriter {
    pub fn new() -> Self {
        Self { buf: BytesMut::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: BytesMut::with_capacity(cap) }
    }

    fn write_varu64_inner(&mut self, value: u64) {
        let mut tmp = [0u8; 9];
        let n = crate::write_varu64(&mut tmp, value);
        self.buf.put_slice(&tmp[..n]);
    }

    /// Write a flat TLV element (type + length + value bytes).
    pub fn write_tlv(&mut self, typ: u64, value: &[u8]) {
        self.write_varu64_inner(typ);
        self.write_varu64_inner(value.len() as u64);
        self.buf.put_slice(value);
    }

    /// Write a nested TLV element. The closure encodes the inner content;
    /// this method wraps it with the correct outer type and length.
    ///
    /// Inner content is written to a temporary writer, then the type, minimal
    /// length, and content are appended to the main buffer.
    pub fn write_nested<F>(&mut self, typ: u64, f: F)
    where
        F: FnOnce(&mut TlvWriter),
    {
        let mut inner = TlvWriter::new();
        f(&mut inner);
        let inner_bytes = inner.buf;

        self.write_varu64_inner(typ);
        self.write_varu64_inner(inner_bytes.len() as u64);
        self.buf.put_slice(&inner_bytes);
    }

    /// Write raw bytes directly into the buffer (no TLV framing).
    ///
    /// Used when embedding a pre-encoded signed region into an outer TLV.
    pub fn write_raw(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    /// Freeze and return the encoded bytes.
    pub fn finish(self) -> bytes::Bytes {
        self.buf.freeze()
    }

    /// Current encoded length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for TlvWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the total encoded size of a TLV element without allocating.
pub fn tlv_size(typ: u64, value_len: usize) -> usize {
    varu64_size(typ) + varu64_size(value_len as u64) + value_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TlvReader;

    // ── write_tlv ─────────────────────────────────────────────────────────────

    #[test]
    fn write_tlv_empty_value() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x21, &[]);
        let bytes = w.finish();
        assert_eq!(bytes.as_ref(), &[0x21, 0x00]);
    }

    #[test]
    fn write_tlv_with_value() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x08, b"ndn");
        let bytes = w.finish();
        assert_eq!(bytes.as_ref(), &[0x08, 0x03, b'n', b'd', b'n']);
    }

    #[test]
    fn write_tlv_3byte_type() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x0320, &[0xAB]);
        let bytes = w.finish();
        // Type 0x0320 = 800 → [0xFD, 0x03, 0x20]; length 1 → [0x01]; value [0xAB]
        assert_eq!(bytes.as_ref(), &[0xFD, 0x03, 0x20, 0x01, 0xAB]);
    }

    #[test]
    fn write_tlv_roundtrip() {
        let payload = b"hello world";
        let mut w = TlvWriter::new();
        w.write_tlv(0x15, payload);
        let bytes = w.finish();

        let mut r = TlvReader::new(bytes);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x15);
        assert_eq!(val.as_ref(), payload);
        assert!(r.is_empty());
    }

    #[test]
    fn write_multiple_tlvs() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x07, b"name");
        w.write_tlv(0x15, b"content");
        let bytes = w.finish();

        let mut r = TlvReader::new(bytes);
        let (t1, v1) = r.read_tlv().unwrap();
        let (t2, v2) = r.read_tlv().unwrap();
        assert_eq!(t1, 0x07); assert_eq!(v1.as_ref(), b"name");
        assert_eq!(t2, 0x15); assert_eq!(v2.as_ref(), b"content");
        assert!(r.is_empty());
    }

    // ── write_nested ──────────────────────────────────────────────────────────

    #[test]
    fn write_nested_empty_inner() {
        let mut w = TlvWriter::new();
        w.write_nested(0x07, |_| {});
        let bytes = w.finish();

        // type(1) + length-placeholder(5 bytes: 0xFE + u32) + no content
        let mut r = TlvReader::new(bytes);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x07);
        assert_eq!(val.len(), 0);
    }

    #[test]
    fn write_nested_with_inner_tlvs() {
        let mut w = TlvWriter::new();
        w.write_nested(0x07, |inner| {
            inner.write_tlv(0x08, b"foo");
            inner.write_tlv(0x08, b"bar");
        });
        let bytes = w.finish();

        let mut r = TlvReader::new(bytes);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x07);

        let mut inner = TlvReader::new(val);
        let (t1, v1) = inner.read_tlv().unwrap();
        let (t2, v2) = inner.read_tlv().unwrap();
        assert_eq!(t1, 0x08); assert_eq!(v1.as_ref(), b"foo");
        assert_eq!(t2, 0x08); assert_eq!(v2.as_ref(), b"bar");
        assert!(inner.is_empty());
    }

    #[test]
    fn write_nested_three_levels() {
        let mut w = TlvWriter::new();
        w.write_nested(0x05, |outer| {
            outer.write_nested(0x07, |name| {
                name.write_tlv(0x08, b"test");
            });
        });
        let bytes = w.finish();

        let mut r = TlvReader::new(bytes);
        let (t0, v0) = r.read_tlv().unwrap(); assert_eq!(t0, 0x05);
        let mut r1 = TlvReader::new(v0);
        let (t1, v1) = r1.read_tlv().unwrap(); assert_eq!(t1, 0x07);
        let mut r2 = TlvReader::new(v1);
        let (t2, v2) = r2.read_tlv().unwrap(); assert_eq!(t2, 0x08);
        assert_eq!(v2.as_ref(), b"test");
    }

    // ── tlv_size ──────────────────────────────────────────────────────────────

    #[test]
    fn tlv_size_matches_write_tlv_output() {
        let cases: &[(u64, &[u8])] = &[
            (0x08, b"hello"),
            (0x0320, &[0xAB, 0xCD]),
            (0x21, &[]),
        ];
        for &(typ, value) in cases {
            let mut w = TlvWriter::new();
            w.write_tlv(typ, value);
            let expected_size = tlv_size(typ, value.len());
            assert_eq!(w.len(), expected_size, "typ={typ:#x} value_len={}", value.len());
        }
    }

    // ── len / is_empty / with_capacity ────────────────────────────────────────

    #[test]
    fn writer_starts_empty() {
        let w = TlvWriter::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn with_capacity_works_same_as_new() {
        let mut w = TlvWriter::with_capacity(64);
        w.write_tlv(0x08, b"hi");
        assert_eq!(w.len(), 4);
    }
}
