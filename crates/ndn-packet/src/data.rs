use std::sync::Arc;
use std::sync::OnceLock;

use bytes::Bytes;

use crate::{MetaInfo, Name, PacketError, SignatureInfo};
use crate::tlv_type;
use ndn_tlv::TlvReader;

/// An NDN Data packet.
///
/// Stores wire-format bytes for zero-copy CS storage and signature verification.
/// The signed region is contiguous in the wire encoding — it is sliced directly
/// from `raw` without copying.
pub struct Data {
    /// Wire-format bytes of the full Data TLV.
    pub(crate) raw: Bytes,

    /// Byte range of the signed region within `raw`.
    signed_start: usize,
    signed_end:   usize,

    /// Byte range of the SignatureValue within `raw`.
    sig_value_start: usize,
    sig_value_end:   usize,

    /// Name — always decoded eagerly.
    pub name: Arc<Name>,

    /// MetaInfo — decoded on first access.
    meta_info: OnceLock<Option<MetaInfo>>,

    /// Content payload — decoded on first access.
    content: OnceLock<Option<Bytes>>,

    /// Signature info — decoded on first access.
    sig_info: OnceLock<Option<SignatureInfo>>,
}

impl Data {
    /// Decode a Data packet from raw wire bytes.
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::DATA {
            return Err(PacketError::UnknownPacketType(typ));
        }

        // Signed region starts at byte 2 (after outer TLV header) and ends
        // just before the SignatureValue TLV. We track byte offsets here;
        // a full implementation would scan for the SignatureValue boundary.
        let outer_header_len = raw.len() - value.len();
        let signed_start = outer_header_len;

        let mut inner = TlvReader::new(value.clone());
        let (name_typ, name_val) = inner.read_tlv()?;
        if name_typ != tlv_type::NAME {
            return Err(PacketError::UnknownPacketType(name_typ));
        }
        let name = Name::decode(name_val)?;

        // Scan for SignatureValue to determine the signed region end.
        let mut sig_value_start = 0;
        let mut sig_value_end   = 0;
        let scan = TlvReader::new(value.clone());
        let _ = scan_for_sig_value(&raw, outer_header_len, &mut sig_value_start, &mut sig_value_end);
        let signed_end = if sig_value_start > 0 { sig_value_start } else { raw.len() };

        Ok(Self {
            raw,
            signed_start,
            signed_end,
            sig_value_start,
            sig_value_end,
            name: Arc::new(name),
            meta_info: OnceLock::new(),
            content:   OnceLock::new(),
            sig_info:  OnceLock::new(),
        })
    }

    /// The signed region — a zero-copy slice suitable for signature verification.
    pub fn signed_region(&self) -> &[u8] {
        &self.raw[self.signed_start..self.signed_end]
    }

    /// The signature value bytes — a zero-copy slice.
    pub fn sig_value(&self) -> &[u8] {
        if self.sig_value_start == 0 {
            return &[];
        }
        &self.raw[self.sig_value_start..self.sig_value_end]
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    pub fn content(&self) -> Option<&Bytes> {
        self.content.get_or_init(|| decode_content(&self.raw).ok().flatten()).as_ref()
    }

    pub fn meta_info(&self) -> Option<&MetaInfo> {
        self.meta_info.get_or_init(|| decode_meta_info(&self.raw).ok().flatten()).as_ref()
    }

    pub fn sig_info(&self) -> Option<&SignatureInfo> {
        self.sig_info.get_or_init(|| decode_sig_info(&self.raw).ok().flatten()).as_ref()
    }
}

fn scan_for_sig_value(
    raw: &Bytes,
    start: usize,
    sig_start: &mut usize,
    sig_end: &mut usize,
) -> Result<(), PacketError> {
    let mut reader = TlvReader::new(raw.slice(start..));
    while !reader.is_empty() {
        let pos = start + reader.position();
        let (typ, val) = reader.read_tlv()?;
        if typ == tlv_type::SIGNATURE_VALUE {
            *sig_start = pos;
            *sig_end   = start + reader.position();
            return Ok(());
        }
        let _ = val;
    }
    Ok(())
}

fn decode_content(raw: &Bytes) -> Result<Option<Bytes>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::CONTENT {
            return Ok(Some(val));
        }
    }
    Ok(None)
}

fn decode_meta_info(raw: &Bytes) -> Result<Option<MetaInfo>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::META_INFO {
            return Ok(Some(MetaInfo::decode(val)?));
        }
    }
    Ok(None)
}

fn decode_sig_info(raw: &Bytes) -> Result<Option<SignatureInfo>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::SIGNATURE_INFO {
            return Ok(Some(SignatureInfo::decode(val)?));
        }
    }
    Ok(None)
}
