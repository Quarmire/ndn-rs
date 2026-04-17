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
    Other(u64),
}

impl ContentType {
    pub fn code(&self) -> u64 {
        match self {
            ContentType::Blob => 0,
            ContentType::Link => 1,
            ContentType::Key => 2,
            ContentType::Nack => 3,
            ContentType::Other(c) => *c,
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
    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut info = MetaInfo::default();
        let mut reader = TlvReader::new(value);
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            match typ {
                t if t == tlv_type::CONTENT_TYPE => {
                    let mut code = 0u64;
                    for &b in val.iter() {
                        code = (code << 8) | b as u64;
                    }
                    info.content_type = match code {
                        0 => ContentType::Blob,
                        1 => ContentType::Link,
                        2 => ContentType::Key,
                        3 => ContentType::Nack,
                        c => ContentType::Other(c),
                    };
                }
                t if t == tlv_type::FRESHNESS_PERIOD => {
                    let mut ms = 0u64;
                    for &b in val.iter() {
                        ms = (ms << 8) | b as u64;
                    }
                    info.freshness_period = Some(Duration::from_millis(ms));
                }
                t if t == tlv_type::FINAL_BLOCK_ID => {
                    info.final_block_id = Some(val);
                }
                _ => {}
            }
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;

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
