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
    /// Uses a 4-byte length placeholder then patches it after the inner content
    /// is written. The length field is always encoded as 5 bytes (0xFE prefix)
    /// to avoid having to shift the buffer.
    pub fn write_nested<F>(&mut self, typ: u64, f: F)
    where
        F: FnOnce(&mut TlvWriter),
    {
        self.write_varu64_inner(typ);

        // Reserve 5-byte length placeholder (0xFE + 4 bytes).
        let len_pos = self.buf.len();
        self.buf.put_bytes(0, 5);

        let content_start = self.buf.len();
        f(self);
        let content_len = self.buf.len() - content_start;

        // Patch the length in place.
        let len_bytes = &mut self.buf[len_pos..len_pos + 5];
        len_bytes[0] = 0xFE;
        len_bytes[1..5].copy_from_slice(&(content_len as u32).to_be_bytes());
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
