//! Buffer-backed encoder that emits TLV elements in minimal wire form.

use bytes::{BufMut, BytesMut};

use crate::varu64_size;

/// Append-only encoder that builds a TLV byte stream in a growable buffer.
///
/// Every type and length is written in minimal VAR-NUMBER form, so output is
/// canonical and round-trips through [`TlvReader`](crate::TlvReader). Call
/// [`finish`](Self::finish) to freeze the buffer into a shareable
/// [`bytes::Bytes`].
pub struct TlvWriter {
    buf: BytesMut,
}

impl TlvWriter {
    /// Create an empty writer with no pre-allocated capacity.
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    /// Create an empty writer that has reserved room for `cap` bytes, avoiding
    /// reallocations when the encoded size is known ahead of time.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(cap),
        }
    }

    fn write_varu64_inner(&mut self, value: u64) {
        let mut tmp = [0u8; 9];
        let n = crate::write_varu64(&mut tmp, value);
        self.buf.put_slice(&tmp[..n]);
    }

    /// Append a complete TLV element: `typ`, the length of `value`, then
    /// `value`. Use this for leaf elements whose bytes are already in hand.
    pub fn write_tlv(&mut self, typ: u64, value: &[u8]) {
        self.write_varu64_inner(typ);
        self.write_varu64_inner(value.len() as u64);
        self.buf.put_slice(value);
    }

    /// Encode a TLV of type `typ` whose value is produced by `f` against a
    /// temporary inner writer.
    ///
    /// The value is built first, so its TLV-LENGTH is measured and prefixed
    /// automatically — the caller never has to know the nested size in advance.
    /// This is the building block for encoding container elements such as Name
    /// or the Interest/Data body.
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

    /// Append a bare VAR-NUMBER (no type or length prefix), for a naked integer
    /// field such as a nested TLV-TYPE or a numeric component value.
    pub fn write_varu64(&mut self, value: u64) {
        self.write_varu64_inner(value);
    }

    /// Append `data` verbatim, bypassing any framing. Use for splicing in
    /// bytes that are already encoded, e.g. a pre-signed sub-element.
    pub fn write_raw(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    /// Borrow the encoded bytes from offset `start` to the current end.
    ///
    /// Pair with [`len`](Self::len) captured before writing a sub-element to
    /// recover the exact bytes just emitted — e.g. to hash a
    /// SignedInfo region without re-encoding it.
    pub fn slice_from(&self, start: usize) -> &[u8] {
        &self.buf[start..]
    }

    /// Consume the writer and freeze its buffer into a cheaply cloneable
    /// [`bytes::Bytes`] holding the complete encoding.
    pub fn finish(self) -> bytes::Bytes {
        self.buf.freeze()
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for TlvWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Encoded size in bytes of a TLV element with the given type and value length,
/// without encoding it.
///
/// Equals `varu64_size(typ) + varu64_size(value_len) + value_len`; use it to
/// pre-size a [`TlvWriter`] or compute a parent's TLV-LENGTH.
pub fn tlv_size(typ: u64, value_len: usize) -> usize {
    varu64_size(typ) + varu64_size(value_len as u64) + value_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TlvReader;

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
        assert_eq!(t1, 0x07);
        assert_eq!(v1.as_ref(), b"name");
        assert_eq!(t2, 0x15);
        assert_eq!(v2.as_ref(), b"content");
        assert!(r.is_empty());
    }

    #[test]
    fn write_nested_empty_inner() {
        let mut w = TlvWriter::new();
        w.write_nested(0x07, |_| {});
        let bytes = w.finish();

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
        assert_eq!(t1, 0x08);
        assert_eq!(v1.as_ref(), b"foo");
        assert_eq!(t2, 0x08);
        assert_eq!(v2.as_ref(), b"bar");
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
        let (t0, v0) = r.read_tlv().unwrap();
        assert_eq!(t0, 0x05);
        let mut r1 = TlvReader::new(v0);
        let (t1, v1) = r1.read_tlv().unwrap();
        assert_eq!(t1, 0x07);
        let mut r2 = TlvReader::new(v1);
        let (t2, v2) = r2.read_tlv().unwrap();
        assert_eq!(t2, 0x08);
        assert_eq!(v2.as_ref(), b"test");
    }

    #[test]
    fn tlv_size_matches_write_tlv_output() {
        let cases: &[(u64, &[u8])] = &[(0x08, b"hello"), (0x0320, &[0xAB, 0xCD]), (0x21, &[])];
        for &(typ, value) in cases {
            let mut w = TlvWriter::new();
            w.write_tlv(typ, value);
            let expected_size = tlv_size(typ, value.len());
            assert_eq!(
                w.len(),
                expected_size,
                "typ={typ:#x} value_len={}",
                value.len()
            );
        }
    }

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
