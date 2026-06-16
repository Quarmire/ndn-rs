//! `SignatureValue` (TLV 0x17) — raw signature bytes; length is algorithm-dependent.

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::codec::{TlvCodecError, TlvDecode, TlvEncode};
use crate::tlv_type;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureValue(pub Bytes);

impl SignatureValue {
    /// Empty value — used while computing `signing_bytes` (field 0x17 is excluded).
    pub fn empty() -> Self {
        Self(Bytes::new())
    }

    /// 64 zero bytes — test/stub.
    pub fn placeholder() -> Self {
        Self(Bytes::copy_from_slice(&[0u8; 64]))
    }
}

impl TlvEncode for SignatureValue {
    const TYPE: u64 = tlv_type::SIGNATURE_VALUE;
    fn write_value(&self, w: &mut TlvWriter) {
        w.write_raw(&self.0);
    }
}

impl TlvDecode for SignatureValue {
    const TYPE: u64 = tlv_type::SIGNATURE_VALUE;
    fn decode_value(r: &mut TlvReader) -> Result<Self, TlvCodecError> {
        let len = r.remaining();
        let bytes = r.read_bytes(len)?;
        Ok(SignatureValue(bytes))
    }
}
