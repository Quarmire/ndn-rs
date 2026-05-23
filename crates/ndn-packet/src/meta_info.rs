use core::time::Duration;

use bytes::Bytes;

use crate::{PacketError, tlv_type};
use ndn_tlv::TlvReader;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ContentType {
    #[default]
    Blob,
    Link,
    Key,
    Nack,
    /// Code 4 per NDN Packet Format v0.3 §3.3.1; FileShare/RDR-style manifest Data.
    Manifest,
    /// Code 5 per NDN Packet Format v0.3 §3.3.1; NFD prefix-announcement protocol.
    PrefixAnn,
    Other(u64),
}

impl ContentType {
    pub fn code(&self) -> u64 {
        match self {
            ContentType::Blob => 0,
            ContentType::Link => 1,
            ContentType::Key => 2,
            ContentType::Nack => 3,
            ContentType::Manifest => 4,
            ContentType::PrefixAnn => 5,
            ContentType::Other(c) => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            0 => ContentType::Blob,
            1 => ContentType::Link,
            2 => ContentType::Key,
            3 => ContentType::Nack,
            4 => ContentType::Manifest,
            5 => ContentType::PrefixAnn,
            c => ContentType::Other(c),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MetaInfo {
    pub content_type: ContentType,
    pub freshness_period: Option<Duration>,
    pub final_block_id: Option<Bytes>,
}

impl MetaInfo {
    /// Parse `final_block_id` (which wraps a NameComponent TLV per
    /// `data.html`) into a typed [`crate::NameComponent`]. Returns `None`
    /// when absent, `Err` when the wrapped bytes are malformed.
    pub fn final_block_component(&self) -> Option<Result<crate::NameComponent, PacketError>> {
        let raw = self.final_block_id.as_ref()?;
        let mut r = TlvReader::new(raw.clone());
        let parsed = r
            .read_tlv()
            .map_err(PacketError::from)
            .map(|(typ, value)| crate::NameComponent { typ, value });
        Some(parsed)
    }

    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut info = MetaInfo::default();
        let mut reader = TlvReader::new(value);
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            match typ {
                t if t == tlv_type::CONTENT_TYPE => {
                    let code = crate::decode_nni(&val)?;
                    info.content_type = ContentType::from_code(code);
                }
                t if t == tlv_type::FRESHNESS_PERIOD => {
                    let ms = crate::decode_nni(&val)?;
                    info.freshness_period = Some(Duration::from_millis(ms));
                }
                t if t == tlv_type::FINAL_BLOCK_ID => {
                    info.final_block_id = Some(val);
                }
                _ => {
                    // Unknown criticals abort; unknown non-criticals are skipped
                    // for forward-compat (NDN Packet Format v0.3 `tlv.html`).
                    if crate::is_critical_tlv_type(typ) {
                        return Err(PacketError::MalformedPacket(
                            "unknown critical TLV-TYPE in MetaInfo body".into(),
                        ));
                    }
                }
            }
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;

    #[test]
    fn a20_final_block_component_decodes_typed_segment() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SEGMENT, &[0x05]);
        let wrapped: Bytes = w.finish();

        let mi = MetaInfo {
            content_type: ContentType::Blob,
            freshness_period: None,
            final_block_id: Some(wrapped),
        };
        let comp = mi
            .final_block_component()
            .expect("FinalBlockId present")
            .expect("wrapped NameComponent decodes");
        assert_eq!(comp.typ, crate::tlv_type::SEGMENT);
        assert_eq!(comp.value.as_ref(), &[0x05]);
    }

    #[test]
    fn a20_final_block_component_none_when_absent() {
        let mi = MetaInfo::default();
        assert!(mi.final_block_component().is_none());
    }

    fn build_meta_info(
        content_type: Option<u64>,
        freshness_ms: Option<u64>,
        final_block: Option<&[u8]>,
    ) -> bytes::Bytes {
        let mut w = TlvWriter::new();
        if let Some(ct) = content_type {
            w.write_tlv(crate::tlv_type::CONTENT_TYPE, &ct.to_be_bytes());
        }
        if let Some(ms) = freshness_ms {
            w.write_tlv(crate::tlv_type::FRESHNESS_PERIOD, &ms.to_be_bytes());
        }
        if let Some(fb) = final_block {
            w.write_tlv(crate::tlv_type::FINAL_BLOCK_ID, fb);
        }
        w.finish()
    }

    #[test]
    fn a14_content_type_typed_manifest_and_prefix_ann() {
        let raw_manifest = build_meta_info(Some(4), None, None);
        let mi = MetaInfo::decode(raw_manifest).expect("decode manifest");
        assert_eq!(mi.content_type, ContentType::Manifest);
        assert_eq!(mi.content_type.code(), 4);

        let raw_prefix_ann = build_meta_info(Some(5), None, None);
        let mi = MetaInfo::decode(raw_prefix_ann).expect("decode prefix-ann");
        assert_eq!(mi.content_type, ContentType::PrefixAnn);
        assert_eq!(mi.content_type.code(), 5);

        // Codes 0..=3 stay typed; codes ≥ 6 still fall to Other.
        assert_eq!(ContentType::from_code(0), ContentType::Blob);
        assert_eq!(ContentType::from_code(6), ContentType::Other(6));
    }

    #[test]
    fn n04_meta_info_decode_rejects_unknown_critical_tlv() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::FRESHNESS_PERIOD, &500u64.to_be_bytes());
        w.write_tlv(0x99, b"x");
        let err = MetaInfo::decode(w.finish())
            .expect_err("unknown critical TLV inside MetaInfo must be rejected");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    #[test]
    fn n04_meta_info_decode_accepts_unknown_non_critical_tlv() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::FRESHNESS_PERIOD, &500u64.to_be_bytes());
        w.write_tlv(0x70, b"opaque");
        MetaInfo::decode(w.finish())
            .expect("unknown non-critical TLV inside MetaInfo must still decode");
    }

    #[test]
    fn decode_empty_meta_info() {
        let mi = MetaInfo::decode(bytes::Bytes::new()).unwrap();
        assert_eq!(mi.content_type, ContentType::Blob);
        assert_eq!(mi.freshness_period, None);
        assert_eq!(mi.final_block_id, None);
    }

    #[test]
    fn decode_freshness_period() {
        let raw = build_meta_info(None, Some(5000), None);
        let mi = MetaInfo::decode(raw).unwrap();
        assert_eq!(
            mi.freshness_period,
            Some(std::time::Duration::from_millis(5000))
        );
    }

    #[test]
    fn decode_content_type_blob() {
        let raw = build_meta_info(Some(0), None, None);
        let mi = MetaInfo::decode(raw).unwrap();
        assert_eq!(mi.content_type, ContentType::Blob);
    }

    #[test]
    fn decode_content_type_key() {
        let raw = build_meta_info(Some(2), None, None);
        let mi = MetaInfo::decode(raw).unwrap();
        assert_eq!(mi.content_type, ContentType::Key);
    }

    #[test]
    fn decode_content_type_other() {
        let raw = build_meta_info(Some(99), None, None);
        let mi = MetaInfo::decode(raw).unwrap();
        assert_eq!(mi.content_type, ContentType::Other(99));
    }

    #[test]
    fn decode_final_block_id() {
        let raw = build_meta_info(None, None, Some(&[0x08, 0x01, b'5']));
        let mi = MetaInfo::decode(raw).unwrap();
        assert!(mi.final_block_id.is_some());
        assert_eq!(mi.final_block_id.unwrap().as_ref(), &[0x08, 0x01, b'5']);
    }

    #[test]
    fn content_type_code_roundtrip() {
        let types = [
            (ContentType::Blob, 0),
            (ContentType::Link, 1),
            (ContentType::Key, 2),
            (ContentType::Nack, 3),
            (ContentType::Other(42), 42),
        ];
        for (ct, code) in types {
            assert_eq!(ct.code(), code);
        }
    }
}
