use bytes::Bytes;

use crate::{TlvError, read_varu64};

/// Zero-copy TLV reader over a `Bytes` buffer.
///
/// Every slice returned by this reader is a sub-slice of the original `Bytes`,
/// sharing the same reference-counted allocation — no copies.
pub struct TlvReader {
    buf: Bytes,
    pos: usize,
}

impl TlvReader {
    pub fn new(buf: Bytes) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Current byte position within the original buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read the next TLV type code.
    pub fn read_type(&mut self) -> Result<u64, TlvError> {
        let (v, n) = read_varu64(&self.buf[self.pos..])?;
        self.pos += n;
        Ok(v)
    }

    /// Read the next TLV length field.
    pub fn read_length(&mut self) -> Result<usize, TlvError> {
        let (v, n) = read_varu64(&self.buf[self.pos..])?;
        self.pos += n;
        Ok(v as usize)
    }

    /// Read exactly `len` bytes as a zero-copy `Bytes` slice.
    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes, TlvError> {
        if self.pos + len > self.buf.len() {
            return Err(TlvError::UnexpectedEof);
        }
        let slice = self.buf.slice(self.pos..self.pos + len);
        self.pos += len;
        Ok(slice)
    }

    /// Read a complete TLV element: returns `(type, value_bytes)`.
    pub fn read_tlv(&mut self) -> Result<(u64, Bytes), TlvError> {
        let typ = self.read_type()?;
        let len = self.read_length()?;
        let val = self.read_bytes(len)?;
        Ok((typ, val))
    }

    /// Peek at the next TLV type without advancing the position.
    pub fn peek_type(&self) -> Result<u64, TlvError> {
        let (v, _) = read_varu64(&self.buf[self.pos..])?;
        Ok(v)
    }

    /// Skip an unknown TLV element, respecting the critical-bit rule.
    ///
    /// Types 0–31 are always critical (grandfathered, NDN Packet Format v0.3
    /// §1.3). For types >= 32, odd numbers are critical and even are
    /// non-critical.
    pub fn skip_unknown(&mut self, typ: u64) -> Result<(), TlvError> {
        if typ <= 31 || typ & 1 == 1 {
            return Err(TlvError::UnknownCriticalType(typ));
        }
        let len = self.read_length()?;
        if self.pos + len > self.buf.len() {
            return Err(TlvError::UnexpectedEof);
        }
        self.pos += len;
        Ok(())
    }

    /// Return a sub-reader scoped to `len` bytes from the current position.
    pub fn scoped(&mut self, len: usize) -> Result<TlvReader, TlvError> {
        let slice = self.read_bytes(len)?;
        Ok(TlvReader::new(slice))
    }

    /// Return the full remaining buffer as a `Bytes` slice without advancing.
    pub fn as_bytes(&self) -> Bytes {
        self.buf.slice(self.pos..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tlv(typ: u8, value: &[u8]) -> Bytes {
        let mut v = vec![typ, value.len() as u8];
        v.extend_from_slice(value);
        Bytes::from(v)
    }

    // ── basic read_tlv ─────────────────────────────────────────────────────────

    #[test]
    fn read_tlv_basic() {
        let raw = make_tlv(0x08, b"hello");
        let mut r = TlvReader::new(raw);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x08);
        assert_eq!(val.as_ref(), b"hello");
        assert!(r.is_empty());
    }

    #[test]
    fn read_tlv_zero_length_value() {
        let raw = Bytes::from(vec![0x21, 0x00]); // CAN_BE_PREFIX with empty value
        let mut r = TlvReader::new(raw);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x21);
        assert_eq!(val.len(), 0);
    }

    #[test]
    fn read_tlv_zero_copy_same_allocation() {
        let raw = Bytes::from(vec![0x15, 0x03, 0xAA, 0xBB, 0xCC]);
        let ptr = raw.as_ptr();
        let mut r = TlvReader::new(raw);
        let (_, val) = r.read_tlv().unwrap();
        // The value slice should point into the same allocation.
        assert_eq!(val.as_ptr(), unsafe { ptr.add(2) });
    }

    #[test]
    fn read_tlv_three_byte_type() {
        // Type 0x0320 (800) — 3-byte varu64 encoding: [0xFD, 0x03, 0x20]
        let raw = vec![0xFD, 0x03, 0x20, 0x02, 0xAA, 0xBB];
        let bytes = Bytes::from(raw);
        let mut r = TlvReader::new(bytes);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x0320);
        assert_eq!(val.as_ref(), &[0xAA, 0xBB]);
    }

    #[test]
    fn read_tlv_multiple_sequential() {
        let mut raw = vec![];
        raw.extend_from_slice(&[0x07, 0x03, b'f', b'o', b'o']);
        raw.extend_from_slice(&[0x08, 0x03, b'b', b'a', b'r']);
        let mut r = TlvReader::new(Bytes::from(raw));
        let (t1, v1) = r.read_tlv().unwrap();
        let (t2, v2) = r.read_tlv().unwrap();
        assert_eq!(t1, 0x07); assert_eq!(v1.as_ref(), b"foo");
        assert_eq!(t2, 0x08); assert_eq!(v2.as_ref(), b"bar");
        assert!(r.is_empty());
    }

    // ── peek_type ─────────────────────────────────────────────────────────────

    #[test]
    fn peek_type_does_not_advance() {
        let raw = make_tlv(0x05, b"data");
        let r = TlvReader::new(raw);
        let t1 = r.peek_type().unwrap();
        let t2 = r.peek_type().unwrap();
        assert_eq!(t1, 0x05);
        assert_eq!(t2, 0x05);
        assert_eq!(r.remaining(), 6); // type(1) + len(1) + value(4)
    }

    // ── remaining / is_empty / position ───────────────────────────────────────

    #[test]
    fn remaining_and_is_empty() {
        let raw = Bytes::from(vec![0x08, 0x01, 0x42]);
        let mut r = TlvReader::new(raw);
        assert!(!r.is_empty());
        assert_eq!(r.remaining(), 3);
        r.read_tlv().unwrap();
        assert!(r.is_empty());
        assert_eq!(r.remaining(), 0);
    }

    // ── skip_unknown (critical-bit rule) ──────────────────────────────────────

    #[test]
    fn skip_unknown_even_type_above_31_succeeds() {
        // Type 0x22 (34) is even and >= 32 → non-critical, must skip silently.
        let raw = Bytes::from(vec![0x22, 0x02, 0xAA, 0xBB, 0x08, 0x01, 0x42]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        assert_eq!(typ, 0x22);
        r.skip_unknown(typ).unwrap();
        // Should now be positioned at the 0x08 TLV.
        let (t, v) = r.read_tlv().unwrap();
        assert_eq!(t, 0x08);
        assert_eq!(v.as_ref(), &[0x42]);
    }

    #[test]
    fn skip_unknown_even_type_0_to_31_is_critical() {
        // Type 0x12 (18) is even but <= 31 → grandfathered as critical.
        let raw = Bytes::from(vec![0x12, 0x02, 0xAA, 0xBB]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        assert_eq!(typ, 0x12);
        let err = r.skip_unknown(typ).unwrap_err();
        assert_eq!(err, TlvError::UnknownCriticalType(0x12));
    }

    #[test]
    fn skip_unknown_odd_type_errors() {
        // Type 0x21 (33) is odd → critical, must return error.
        let raw = Bytes::from(vec![0x21, 0x00]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        let err = r.skip_unknown(typ).unwrap_err();
        assert_eq!(err, TlvError::UnknownCriticalType(0x21));
    }

    // ── scoped sub-reader ─────────────────────────────────────────────────────

    #[test]
    fn scoped_reader_contains_only_inner_bytes() {
        // Build: outer TLV containing two inner TLVs.
        let inner: Vec<u8> = vec![0x08, 0x01, b'A', 0x08, 0x01, b'B'];
        let mut raw = vec![0x07, inner.len() as u8];
        raw.extend_from_slice(&inner);
        raw.extend_from_slice(&[0x15, 0x01, 0x99]); // extra TLV after
        let mut r = TlvReader::new(Bytes::from(raw));

        let (typ, _) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x07);

        // Rebuild to test scoped: re-read from scratch.
        let inner2: Vec<u8> = vec![0x08, 0x01, b'A', 0x08, 0x01, b'B'];
        let mut raw2 = vec![0x07, inner2.len() as u8];
        raw2.extend_from_slice(&inner2);
        raw2.push(0x15); raw2.push(0x01); raw2.push(0x99);
        let mut r2 = TlvReader::new(Bytes::from(raw2));
        let _outer_type = r2.read_type().unwrap();
        let outer_len = r2.read_length().unwrap();
        let mut inner_r = r2.scoped(outer_len).unwrap();

        let (t1, v1) = inner_r.read_tlv().unwrap();
        let (t2, v2) = inner_r.read_tlv().unwrap();
        assert_eq!(t1, 0x08); assert_eq!(v1.as_ref(), b"A");
        assert_eq!(t2, 0x08); assert_eq!(v2.as_ref(), b"B");
        assert!(inner_r.is_empty());

        // The outer reader should now be at the 0x15 TLV.
        let (t3, _) = r2.read_tlv().unwrap();
        assert_eq!(t3, 0x15);
    }

    // ── error cases ───────────────────────────────────────────────────────────

    #[test]
    fn read_tlv_truncated_value_errors() {
        // Length says 5 bytes but only 2 are present.
        let raw = Bytes::from(vec![0x08, 0x05, 0xAA, 0xBB]);
        let mut r = TlvReader::new(raw);
        assert_eq!(r.read_tlv().unwrap_err(), TlvError::UnexpectedEof);
    }

    #[test]
    fn read_bytes_truncated_errors() {
        let raw = Bytes::from(vec![0x01, 0x02]);
        let mut r = TlvReader::new(raw);
        assert_eq!(r.read_bytes(10).unwrap_err(), TlvError::UnexpectedEof);
    }
}
