use std::time::Duration;

use bytes::Bytes;

use crate::{PacketError, tlv_type};
use ndn_tlv::TlvReader;

/// NDN content types.
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
            ContentType::Blob  => 0,
            ContentType::Link  => 1,
            ContentType::Key   => 2,
            ContentType::Nack  => 3,
            ContentType::Other(c) => *c,
        }
    }
}

/// Metadata carried in a Data packet's MetaInfo TLV.
#[derive(Clone, Debug, Default)]
pub struct MetaInfo {
    pub content_type:     ContentType,
    pub freshness_period: Option<Duration>,
    pub final_block_id:   Option<Bytes>,
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
                    for &b in val.iter() { code = (code << 8) | b as u64; }
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
                    for &b in val.iter() { ms = (ms << 8) | b as u64; }
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
