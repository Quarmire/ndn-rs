#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(not(feature = "std"))]
use core::cell::OnceCell as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

use bytes::Bytes;

use crate::tlv_type;
use crate::{MetaInfo, Name, PacketError, SignatureInfo};
use ndn_tlv::TlvReader;

/// An NDN Data packet.
///
/// The signed region is contiguous in the wire encoding and sliced directly
/// from `raw` without copying, enabling zero-copy CS storage and verification.
#[derive(Debug)]
pub struct Data {
    pub(crate) raw: Bytes,
    signed_start: usize,
    signed_end: usize,
    sig_value_start: usize,
    sig_value_end: usize,
    pub name: Arc<Name>,
    meta_info: OnceLock<Option<MetaInfo>>,
    content: OnceLock<Option<Bytes>>,
    sig_info: OnceLock<Option<SignatureInfo>>,
}

impl Data {
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::DATA {
            return Err(PacketError::UnknownPacketType(typ));
        }

        let outer_header_len = raw.len() - value.len();
        let signed_start = outer_header_len;

        let mut inner = TlvReader::new(value.clone());
        let (name_typ, name_val) = inner.read_tlv()?;
        if name_typ != tlv_type::NAME {
            return Err(PacketError::UnknownPacketType(name_typ));
        }
        let name = Name::decode(name_val)?;

        if name.is_empty() {
            return Err(PacketError::MalformedPacket(
                "Data Name must have at least one component".into(),
            ));
        }

        let mut sig_value_start = 0;
        let mut sig_value_end = 0;
        let _ = scan_for_sig_value(
            &raw,
            outer_header_len,
            &mut sig_value_start,
            &mut sig_value_end,
        );
        let signed_end = if sig_value_start > 0 {
            sig_value_start
        } else {
            raw.len()
        };

        Ok(Self {
            raw,
            signed_start,
            signed_end,
            sig_value_start,
            sig_value_end,
            name: Arc::new(name),
            meta_info: OnceLock::new(),
            content: OnceLock::new(),
            sig_info: OnceLock::new(),
        })
    }

    pub fn signed_region(&self) -> &[u8] {
        &self.raw[self.signed_start..self.signed_end]
    }

    pub fn sig_value(&self) -> &[u8] {
        if self.sig_value_start == 0 || self.sig_value_end == 0 {
            return &[];
        }
        // Parse the SignatureValue TLV header to find where the value bytes begin.
        let sig_tlv = self.raw.slice(self.sig_value_start..self.sig_value_end);
        let mut r = TlvReader::new(sig_tlv);
        match r.read_tlv() {
            Ok((_, val)) => {
                let val_start = self.sig_value_end - val.len();
                &self.raw[val_start..self.sig_value_end]
            }
            Err(_) => &[],
        }
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    /// SHA-256 of the full wire encoding, used for exact Data retrieval via
    /// ImplicitSha256DigestComponent (type 0x01) in Interest names.
    #[cfg(feature = "std")]
    pub fn implicit_digest(&self) -> ring::digest::Digest {
        ring::digest::digest(&ring::digest::SHA256, &self.raw)
    }

    pub fn content(&self) -> Option<&Bytes> {
        self.content
            .get_or_init(|| decode_content(&self.raw).ok().flatten())
            .as_ref()
    }

    pub fn meta_info(&self) -> Option<&MetaInfo> {
        self.meta_info
            .get_or_init(|| decode_meta_info(&self.raw).ok().flatten())
            .as_ref()
    }

    pub fn sig_info(&self) -> Option<&SignatureInfo> {
        self.sig_info
            .get_or_init(|| decode_sig_info(&self.raw).ok().flatten())
            .as_ref()
    }

    /// Per NDN Packet Format v0.3 §6.3.1, when ContentType is LINK the Content
    /// field contains one or more delegation Name TLVs.
    #[cfg(feature = "std")]
    pub fn link_delegations(&self) -> Option<Vec<Arc<Name>>> {
        let mi = self.meta_info()?;
        if mi.content_type != crate::meta_info::ContentType::Link {
            return None;
        }
        let content = self.content()?;
        let mut reader = TlvReader::new(content.clone());
        let mut names = Vec::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv().ok()?;
            if typ == tlv_type::NAME {
                names.push(Arc::new(Name::decode(val).ok()?));
            }
        }
        if names.is_empty() { None } else { Some(names) }
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
            *sig_end = start + reader.position();
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

#[cfg(test)]
pub(crate) fn build_data_packet(
    components: &[&[u8]],
    content: &[u8],
    freshness_ms: Option<u64>,
    sig_type_code: u8,
    sig_value: &[u8],
) -> Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_nested(tlv_type::NAME, |w| {
            for comp in components {
                w.write_tlv(tlv_type::NAME_COMPONENT, comp);
            }
        });
        if let Some(ms) = freshness_ms {
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::FRESHNESS_PERIOD, &ms.to_be_bytes());
            });
        }
        w.write_tlv(tlv_type::CONTENT, content);
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[sig_type_code]);
        });
        w.write_tlv(tlv_type::SIGNATURE_VALUE, sig_value);
    });
    w.finish()
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

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn decode_name() {
        let raw = build_data_packet(&[b"edu", b"ucla"], b"hello", None, 5, &[0xAB]);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.name.len(), 2);
        assert_eq!(d.name.components()[0].value.as_ref(), b"edu");
        assert_eq!(d.name.components()[1].value.as_ref(), b"ucla");
    }


    #[test]
    fn decode_content() {
        let raw = build_data_packet(&[b"test"], b"payload", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let content = d.content().expect("content present");
        assert_eq!(content.as_ref(), b"payload");
    }

    #[test]
    fn decode_empty_content() {
        let raw = build_data_packet(&[b"test"], b"", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let content = d.content().expect("content present");
        assert_eq!(content.len(), 0);
    }


    #[test]
    fn decode_meta_info_freshness() {
        let raw = build_data_packet(&[b"test"], b"", Some(5000), 5, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let mi = d.meta_info().expect("meta_info present");
        assert_eq!(
            mi.freshness_period,
            Some(std::time::Duration::from_millis(5000))
        );
    }

    #[test]
    fn decode_no_meta_info() {
        let raw = build_data_packet(&[b"test"], b"data", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        assert!(d.meta_info().is_none());
    }


    #[test]
    fn decode_sig_info_type() {
        let raw = build_data_packet(&[b"test"], b"", None, 5, &[0xAB]);
        let d = Data::decode(raw).unwrap();
        let si = d.sig_info().expect("sig_info present");
        assert_eq!(si.sig_type, crate::SignatureType::SignatureEd25519);
    }


    #[test]
    fn signed_region_excludes_sig_value() {
        let sig_bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let raw = build_data_packet(&[b"test"], b"content", None, 5, sig_bytes);
        let d = Data::decode(raw.clone()).unwrap();

        let region = d.signed_region();
        assert!(!region.is_empty());
        assert!(!region.ends_with(sig_bytes));
    }

    #[test]
    fn sig_value_correct_bytes() {
        let sig_bytes: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        let raw = build_data_packet(&[b"test"], b"content", None, 5, sig_bytes);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.sig_value(), sig_bytes);
    }

    #[test]
    fn signed_end_equals_sig_value_start() {
        let raw = build_data_packet(&[b"n"], b"x", None, 0, &[0xAB, 0xCD]);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.signed_end, d.sig_value_start);
    }


    #[test]
    fn raw_field_is_full_wire_bytes() {
        let raw = build_data_packet(&[b"test"], b"hi", None, 0, &[0x00]);
        let d = Data::decode(raw.clone()).unwrap();
        assert_eq!(d.raw(), &raw);
    }


    fn build_link_data(name_comps: &[&[u8]], delegations: &[&[&[u8]]]) -> Bytes {
        let mut content_w = ndn_tlv::TlvWriter::new();
        for del in delegations {
            content_w.write_nested(tlv_type::NAME, |w| {
                for comp in *del {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
        }
        let content_bytes = content_w.finish();

        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in name_comps {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::CONTENT_TYPE, &[1]); // LINK = 1
            });
            w.write_tlv(tlv_type::CONTENT, &content_bytes);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0x00]);
        });
        w.finish()
    }

    #[test]
    fn link_delegations_parsed() {
        let raw = build_link_data(
            &[b"link"],
            &[&[b"ndn", b"gateway1"], &[b"ndn", b"gateway2"]],
        );
        let d = Data::decode(raw).unwrap();
        let dels = d.link_delegations().expect("delegations present");
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0].components()[1].value.as_ref(), b"gateway1");
        assert_eq!(dels[1].components()[1].value.as_ref(), b"gateway2");
    }

    #[test]
    fn non_link_data_has_no_delegations() {
        let raw = build_data_packet(&[b"test"], b"payload", None, 5, &[0x00]);
        let d = Data::decode(raw).unwrap();
        assert!(d.link_delegations().is_none());
    }


    #[test]
    fn implicit_digest_is_sha256_of_raw() {
        let raw = build_data_packet(&[b"test"], b"content", None, 5, &[0xAB]);
        let d = Data::decode(raw.clone()).unwrap();
        let expected = ring::digest::digest(&ring::digest::SHA256, &raw);
        assert_eq!(d.implicit_digest().as_ref(), expected.as_ref());
    }


    #[test]
    fn decode_wrong_type_errors() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(0x05, |w| {
            w.write_nested(crate::tlv_type::NAME, |w| {
                w.write_tlv(crate::tlv_type::NAME_COMPONENT, b"test");
            });
        });
        assert!(matches!(
            Data::decode(w.finish()).unwrap_err(),
            crate::PacketError::UnknownPacketType(0x05)
        ));
    }
}
