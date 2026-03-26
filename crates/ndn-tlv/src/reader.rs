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
    /// Odd type numbers are critical — encountering one is an error.
    /// Even type numbers are non-critical — skip silently.
    pub fn skip_unknown(&mut self, typ: u64) -> Result<(), TlvError> {
        if typ & 1 == 1 {
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
