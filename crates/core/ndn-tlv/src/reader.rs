use bytes::Bytes;

use crate::{TlvError, read_varu64};

/// Zero-copy TLV reader. All returned slices share the input's allocation.
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

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn read_type(&mut self) -> Result<u64, TlvError> {
        let (v, n) = read_varu64(&self.buf[self.pos..])?;
        // TLV-TYPE is restricted to VAR-NUMBER-1/3/5 and the u32 range
        // (NDN Packet Format v0.3 §2.0); the 9-byte form is LENGTH-only.
        if n == 9 || v > u64::from(u32::MAX) {
            return Err(TlvError::TypeOutOfRange);
        }
        self.pos += n;
        Ok(v)
    }

    pub fn read_length(&mut self) -> Result<usize, TlvError> {
        let (v, n) = read_varu64(&self.buf[self.pos..])?;
        self.pos += n;
        // A TLV-LENGTH can never exceed the bytes remaining for its value. This
        // rejects an attacker-supplied huge length up front (W-1) and also makes
        // the `v as usize` narrowing safe on 32-bit/wasm targets, since `v` is
        // now bounded by `remaining()` which always fits a `usize`.
        if v > self.remaining() as u64 {
            return Err(TlvError::UnexpectedEof);
        }
        Ok(v as usize)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes, TlvError> {
        // `checked_add` guards against `self.pos + len` overflowing (W-1): a
        // wrapped sum could otherwise pass the bound check and then panic inside
        // `Bytes::slice` on `begin > end`.
        let end = self.pos.checked_add(len).ok_or(TlvError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(TlvError::UnexpectedEof);
        }
        let slice = self.buf.slice(self.pos..end);
        self.pos = end;
        Ok(slice)
    }

    pub fn read_tlv(&mut self) -> Result<(u64, Bytes), TlvError> {
        let typ = self.read_type()?;
        let len = self.read_length()?;
        let val = self.read_bytes(len)?;
        Ok((typ, val))
    }

    pub fn peek_type(&self) -> Result<u64, TlvError> {
        let (v, _) = read_varu64(&self.buf[self.pos..])?;
        Ok(v)
    }

    /// Skip an unknown TLV per the critical-bit rule (NDN Packet Format v0.3
    /// §2.2): types 0-31 and odd types >= 32 are critical and error; even
    /// types >= 32 are non-critical and are skipped.
    pub fn skip_unknown(&mut self, typ: u64) -> Result<(), TlvError> {
        if typ <= 31 || typ & 1 == 1 {
            return Err(TlvError::UnknownCriticalType(typ));
        }
        let len = self.read_length()?;
        let end = self.pos.checked_add(len).ok_or(TlvError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(TlvError::UnexpectedEof);
        }
        self.pos = end;
        Ok(())
    }

    pub fn scoped(&mut self, len: usize) -> Result<TlvReader, TlvError> {
        let slice = self.read_bytes(len)?;
        Ok(TlvReader::new(slice))
    }

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

    #[test]
    fn read_type_rejects_9byte_form() {
        let raw = Bytes::from(vec![0xFF, 0, 0, 0, 1, 0, 0, 0, 0]);
        let mut r = TlvReader::new(raw);
        assert!(matches!(r.read_type(), Err(TlvError::TypeOutOfRange)));
    }

    #[test]
    fn read_type_accepts_5byte_form_within_u32() {
        let raw = Bytes::from(vec![0xFE, 0x12, 0x34, 0x56, 0x78]);
        let mut r = TlvReader::new(raw);
        assert_eq!(r.read_type().unwrap(), 0x1234_5678);
    }

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
        let raw = Bytes::from(vec![0x21, 0x00]);
        let mut r = TlvReader::new(raw);
        let (typ, val) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x21);
        assert_eq!(val.len(), 0);
    }

    #[test]
    // Pointer identity check needs raw pointer arithmetic; sole unsafe in this
    // crate, test-only.
    #[allow(unsafe_code)]
    fn read_tlv_zero_copy_same_allocation() {
        let raw = Bytes::from(vec![0x15, 0x03, 0xAA, 0xBB, 0xCC]);
        let ptr = raw.as_ptr();
        let mut r = TlvReader::new(raw);
        let (_, val) = r.read_tlv().unwrap();
        assert_eq!(val.as_ptr(), unsafe { ptr.add(2) });
    }

    #[test]
    fn read_tlv_three_byte_type() {
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
        assert_eq!(t1, 0x07);
        assert_eq!(v1.as_ref(), b"foo");
        assert_eq!(t2, 0x08);
        assert_eq!(v2.as_ref(), b"bar");
        assert!(r.is_empty());
    }

    #[test]
    fn peek_type_does_not_advance() {
        let raw = make_tlv(0x05, b"data");
        let r = TlvReader::new(raw);
        let t1 = r.peek_type().unwrap();
        let t2 = r.peek_type().unwrap();
        assert_eq!(t1, 0x05);
        assert_eq!(t2, 0x05);
        assert_eq!(r.remaining(), 6);
    }

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

    #[test]
    fn skip_unknown_even_type_above_31_succeeds() {
        let raw = Bytes::from(vec![0x22, 0x02, 0xAA, 0xBB, 0x08, 0x01, 0x42]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        assert_eq!(typ, 0x22);
        r.skip_unknown(typ).unwrap();
        let (t, v) = r.read_tlv().unwrap();
        assert_eq!(t, 0x08);
        assert_eq!(v.as_ref(), &[0x42]);
    }

    #[test]
    fn skip_unknown_even_type_0_to_31_is_critical() {
        let raw = Bytes::from(vec![0x12, 0x02, 0xAA, 0xBB]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        assert_eq!(typ, 0x12);
        let err = r.skip_unknown(typ).unwrap_err();
        assert_eq!(err, TlvError::UnknownCriticalType(0x12));
    }

    #[test]
    fn skip_unknown_odd_type_errors() {
        let raw = Bytes::from(vec![0x21, 0x00]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        let err = r.skip_unknown(typ).unwrap_err();
        assert_eq!(err, TlvError::UnknownCriticalType(0x21));
    }

    #[test]
    fn scoped_reader_contains_only_inner_bytes() {
        let inner: Vec<u8> = vec![0x08, 0x01, b'A', 0x08, 0x01, b'B'];
        let mut raw = vec![0x07, inner.len() as u8];
        raw.extend_from_slice(&inner);
        raw.extend_from_slice(&[0x15, 0x01, 0x99]);
        let mut r = TlvReader::new(Bytes::from(raw));

        let (typ, _) = r.read_tlv().unwrap();
        assert_eq!(typ, 0x07);

        let inner2: Vec<u8> = vec![0x08, 0x01, b'A', 0x08, 0x01, b'B'];
        let mut raw2 = vec![0x07, inner2.len() as u8];
        raw2.extend_from_slice(&inner2);
        raw2.push(0x15);
        raw2.push(0x01);
        raw2.push(0x99);
        let mut r2 = TlvReader::new(Bytes::from(raw2));
        let _outer_type = r2.read_type().unwrap();
        let outer_len = r2.read_length().unwrap();
        let mut inner_r = r2.scoped(outer_len).unwrap();

        let (t1, v1) = inner_r.read_tlv().unwrap();
        let (t2, v2) = inner_r.read_tlv().unwrap();
        assert_eq!(t1, 0x08);
        assert_eq!(v1.as_ref(), b"A");
        assert_eq!(t2, 0x08);
        assert_eq!(v2.as_ref(), b"B");
        assert!(inner_r.is_empty());

        let (t3, _) = r2.read_tlv().unwrap();
        assert_eq!(t3, 0x15);
    }

    #[test]
    fn read_tlv_truncated_value_errors() {
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

    // --- W-1 regression: a near-u64::MAX length must error, never panic ------

    #[test]
    fn w1_huge_length_errors_not_panics() {
        // TLV-TYPE=0x05, TLV-LENGTH = 9-byte form 0xFF + 8×0xFF = u64::MAX.
        let raw = Bytes::from(vec![
            0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        let mut r = TlvReader::new(raw);
        let _ = r.read_type().unwrap();
        assert_eq!(r.read_length().unwrap_err(), TlvError::UnexpectedEof);
    }

    #[test]
    fn w1_read_tlv_huge_length_errors() {
        let raw = Bytes::from(vec![
            0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        let mut r = TlvReader::new(raw);
        assert_eq!(r.read_tlv().unwrap_err(), TlvError::UnexpectedEof);
    }

    #[test]
    fn w1_read_bytes_overflow_len_errors() {
        // len near usize::MAX would overflow self.pos + len; must error.
        let raw = Bytes::from(vec![0x08, 0x01, 0x42]);
        let mut r = TlvReader::new(raw);
        let _ = r.read_type().unwrap();
        assert_eq!(
            r.read_bytes(usize::MAX).unwrap_err(),
            TlvError::UnexpectedEof
        );
    }

    #[test]
    fn w1_skip_unknown_huge_length_errors() {
        // Non-critical type (0x22) with a 9-byte u64::MAX length must error.
        let raw = Bytes::from(vec![
            0x22, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        let mut r = TlvReader::new(raw);
        let typ = r.read_type().unwrap();
        assert_eq!(r.skip_unknown(typ).unwrap_err(), TlvError::UnexpectedEof);
    }
}
