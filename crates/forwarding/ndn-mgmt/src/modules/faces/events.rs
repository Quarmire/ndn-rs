//! `FaceEvent` wire model — the NFD-canonical `FaceEventNotification`
//! TLV plus ndn-rs semantic-event extensions, and their encode/decode.

use bytes::Bytes;

use ndn_transport::FaceId;

use crate::notification::NotificationEvent;

/// Face lifecycle and semantic-event notifications.
///
/// Wire shape: NFD-canonical `FaceEventNotification` TLV (type `0xC0`,
/// see ndn-cxx `mgmt/nfd/face-event-notification.hpp`) carrying
/// `FaceEventKind` (`0xC1`, NNI) and `FaceId` (`0x69`). NFD reserves
/// kinds 1..=4 for lifecycle (Created / Destroyed / Up / Down); ndn-rs
/// adds kinds 5..=9 (MtuChanged, PersistencyChanged,
/// ReliabilityBackoff, CongestionMark, OptionRefused) — NFD clients
/// ignore kinds > 4.
#[derive(Debug, Clone)]
pub enum FaceEvent {
    Created {
        face_id: FaceId,
    },
    Destroyed {
        face_id: FaceId,
    },
    Up {
        face_id: FaceId,
    },
    Down {
        face_id: FaceId,
    },
    MtuChanged {
        face_id: FaceId,
        old: u64,
        new: u64,
    },
    PersistencyChanged {
        face_id: FaceId,
        old: u64,
        new: u64,
    },
    ReliabilityBackoff {
        face_id: FaceId,
        attempt: u32,
        rto_us: u64,
    },
    CongestionMark {
        face_id: FaceId,
        direction: MarkDirection,
        mark: u64,
    },
    OptionRefused {
        face_id: FaceId,
        option: String,
        reason: String,
    },
}

impl FaceEvent {
    pub fn face_id(&self) -> FaceId {
        match self {
            FaceEvent::Created { face_id }
            | FaceEvent::Destroyed { face_id }
            | FaceEvent::Up { face_id }
            | FaceEvent::Down { face_id }
            | FaceEvent::MtuChanged { face_id, .. }
            | FaceEvent::PersistencyChanged { face_id, .. }
            | FaceEvent::ReliabilityBackoff { face_id, .. }
            | FaceEvent::CongestionMark { face_id, .. }
            | FaceEvent::OptionRefused { face_id, .. } => *face_id,
        }
    }

    pub fn kind(&self) -> FaceEventKind {
        match self {
            FaceEvent::Created { .. } => FaceEventKind::Created,
            FaceEvent::Destroyed { .. } => FaceEventKind::Destroyed,
            FaceEvent::Up { .. } => FaceEventKind::Up,
            FaceEvent::Down { .. } => FaceEventKind::Down,
            FaceEvent::MtuChanged { .. } => FaceEventKind::MtuChanged,
            FaceEvent::PersistencyChanged { .. } => FaceEventKind::PersistencyChanged,
            FaceEvent::ReliabilityBackoff { .. } => FaceEventKind::ReliabilityBackoff,
            FaceEvent::CongestionMark { .. } => FaceEventKind::CongestionMark,
            FaceEvent::OptionRefused { .. } => FaceEventKind::OptionRefused,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaceEventKind {
    Created = 1,
    Destroyed = 2,
    Up = 3,
    Down = 4,
    // ndn-rs semantic-event extensions.
    MtuChanged = 5,
    PersistencyChanged = 6,
    ReliabilityBackoff = 7,
    CongestionMark = 8,
    OptionRefused = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MarkDirection {
    Egress = 0,
    Ingress = 1,
}

/// ndn-cxx `mgmt/nfd/face-event-notification.hpp:62`.
const TLV_FACE_EVENT_NOTIFICATION: u8 = 0xC0;
const TLV_FACE_EVENT_KIND: u8 = 0xC1;
/// Shared with management `FaceStatus`.
const TLV_FACE_ID: u8 = 0x69;

// Extended-event payload TLVs, project-private range 0xD0..=0xD9.
const TLV_OLD_MTU: u8 = 0xD0;
const TLV_NEW_MTU: u8 = 0xD1;
const TLV_OLD_PERSISTENCY: u8 = 0xD2;
const TLV_NEW_PERSISTENCY: u8 = 0xD3;
const TLV_RELIABILITY_ATTEMPT: u8 = 0xD4;
const TLV_RTO: u8 = 0xD5;
const TLV_MARK_DIRECTION: u8 = 0xD6;
const TLV_MARK: u8 = 0xD7;
const TLV_OPTION_NAME: u8 = 0xD8;
const TLV_REFUSAL_REASON: u8 = 0xD9;

impl NotificationEvent for FaceEvent {
    fn encode(&self) -> Bytes {
        let face_id = self.face_id();
        let kind = self.kind();

        let kind_v = encode_non_neg_int(kind as u64);
        let face_id_v = encode_non_neg_int(face_id.0);

        // Inner length must be known before the outer length-prefix.
        let mut payload = Vec::new();
        match self {
            FaceEvent::MtuChanged { old, new, .. } => {
                write_one_byte_tlv_nni(&mut payload, TLV_OLD_MTU, *old);
                write_one_byte_tlv_nni(&mut payload, TLV_NEW_MTU, *new);
            }
            FaceEvent::PersistencyChanged { old, new, .. } => {
                write_one_byte_tlv_nni(&mut payload, TLV_OLD_PERSISTENCY, *old);
                write_one_byte_tlv_nni(&mut payload, TLV_NEW_PERSISTENCY, *new);
            }
            FaceEvent::ReliabilityBackoff {
                attempt, rto_us, ..
            } => {
                write_one_byte_tlv_nni(&mut payload, TLV_RELIABILITY_ATTEMPT, *attempt as u64);
                write_one_byte_tlv_nni(&mut payload, TLV_RTO, *rto_us);
            }
            FaceEvent::CongestionMark {
                direction, mark, ..
            } => {
                payload.push(TLV_MARK_DIRECTION);
                payload.push(1);
                payload.push(*direction as u8);
                write_one_byte_tlv_nni(&mut payload, TLV_MARK, *mark);
            }
            FaceEvent::OptionRefused { option, reason, .. } => {
                write_one_byte_tlv_str(&mut payload, TLV_OPTION_NAME, option);
                write_one_byte_tlv_str(&mut payload, TLV_REFUSAL_REASON, reason);
            }
            _ => {}
        }

        let inner_len = 2 + kind_v.len() + 2 + face_id_v.len() + payload.len();
        // One-byte varu64 budget — promote to multi-byte if payloads grow.
        debug_assert!(
            inner_len <= 252,
            "FaceEvent inner length {inner_len} exceeds one-byte varu64 budget",
        );
        let mut buf = Vec::with_capacity(2 + inner_len);
        buf.push(TLV_FACE_EVENT_NOTIFICATION);
        buf.push(inner_len as u8);
        buf.push(TLV_FACE_EVENT_KIND);
        buf.push(kind_v.len() as u8);
        buf.extend_from_slice(&kind_v);
        buf.push(TLV_FACE_ID);
        buf.push(face_id_v.len() as u8);
        buf.extend_from_slice(&face_id_v);
        buf.extend_from_slice(&payload);
        Bytes::from(buf)
    }
}

fn write_one_byte_tlv_nni(buf: &mut Vec<u8>, typ: u8, v: u64) {
    let bytes = encode_non_neg_int(v);
    buf.push(typ);
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(&bytes);
}

fn write_one_byte_tlv_str(buf: &mut Vec<u8>, typ: u8, s: &str) {
    debug_assert!(
        s.len() <= 252,
        "FaceEvent string field {typ:#x} length {} exceeds one-byte varu64 budget",
        s.len(),
    );
    buf.push(typ);
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

impl FaceEvent {
    /// Decode a wire-format [`FaceEvent`]. Mirrors the encoder's
    /// one-byte-length assumption; events with inner length > 252 are
    /// rejected as malformed.
    pub fn decode(wire: &[u8]) -> Option<Self> {
        if wire.len() < 4 || wire[0] != TLV_FACE_EVENT_NOTIFICATION {
            return None;
        }
        let inner_len = wire[1] as usize;
        let inner = wire.get(2..2 + inner_len)?;

        let mut pos = 0;
        let mut kind: Option<FaceEventKind> = None;
        let mut face_id: Option<FaceId> = None;
        let mut old_mtu: Option<u64> = None;
        let mut new_mtu: Option<u64> = None;
        let mut old_persistency: Option<u64> = None;
        let mut new_persistency: Option<u64> = None;
        let mut attempt: Option<u32> = None;
        let mut rto_us: Option<u64> = None;
        let mut mark_direction: Option<MarkDirection> = None;
        let mut mark: Option<u64> = None;
        let mut option_name: Option<String> = None;
        let mut refusal_reason: Option<String> = None;

        while pos < inner.len() {
            let typ = *inner.get(pos)?;
            let len = *inner.get(pos + 1)? as usize;
            let val = inner.get(pos + 2..pos + 2 + len)?;
            pos += 2 + len;
            match typ {
                TLV_FACE_EVENT_KIND => {
                    kind = Some(match decode_nni(val)? {
                        1 => FaceEventKind::Created,
                        2 => FaceEventKind::Destroyed,
                        3 => FaceEventKind::Up,
                        4 => FaceEventKind::Down,
                        5 => FaceEventKind::MtuChanged,
                        6 => FaceEventKind::PersistencyChanged,
                        7 => FaceEventKind::ReliabilityBackoff,
                        8 => FaceEventKind::CongestionMark,
                        9 => FaceEventKind::OptionRefused,
                        _ => return None,
                    });
                }
                TLV_FACE_ID => face_id = Some(FaceId(decode_nni(val)?)),
                TLV_OLD_MTU => old_mtu = Some(decode_nni(val)?),
                TLV_NEW_MTU => new_mtu = Some(decode_nni(val)?),
                TLV_OLD_PERSISTENCY => old_persistency = Some(decode_nni(val)?),
                TLV_NEW_PERSISTENCY => new_persistency = Some(decode_nni(val)?),
                TLV_RELIABILITY_ATTEMPT => attempt = Some(decode_nni(val)? as u32),
                TLV_RTO => rto_us = Some(decode_nni(val)?),
                TLV_MARK_DIRECTION => {
                    mark_direction = match val.first()? {
                        0 => Some(MarkDirection::Egress),
                        1 => Some(MarkDirection::Ingress),
                        _ => return None,
                    };
                }
                TLV_MARK => mark = Some(decode_nni(val)?),
                TLV_OPTION_NAME => {
                    option_name = Some(std::str::from_utf8(val).ok()?.to_owned());
                }
                TLV_REFUSAL_REASON => {
                    refusal_reason = Some(std::str::from_utf8(val).ok()?.to_owned());
                }
                _ => {}
            }
        }

        let face_id = face_id?;
        Some(match kind? {
            FaceEventKind::Created => FaceEvent::Created { face_id },
            FaceEventKind::Destroyed => FaceEvent::Destroyed { face_id },
            FaceEventKind::Up => FaceEvent::Up { face_id },
            FaceEventKind::Down => FaceEvent::Down { face_id },
            FaceEventKind::MtuChanged => FaceEvent::MtuChanged {
                face_id,
                old: old_mtu?,
                new: new_mtu?,
            },
            FaceEventKind::PersistencyChanged => FaceEvent::PersistencyChanged {
                face_id,
                old: old_persistency?,
                new: new_persistency?,
            },
            FaceEventKind::ReliabilityBackoff => FaceEvent::ReliabilityBackoff {
                face_id,
                attempt: attempt?,
                rto_us: rto_us?,
            },
            FaceEventKind::CongestionMark => FaceEvent::CongestionMark {
                face_id,
                direction: mark_direction?,
                mark: mark?,
            },
            FaceEventKind::OptionRefused => FaceEvent::OptionRefused {
                face_id,
                option: option_name?,
                reason: refusal_reason?,
            },
        })
    }
}

fn decode_nni(buf: &[u8]) -> Option<u64> {
    match buf.len() {
        1 => Some(buf[0] as u64),
        2 => Some(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Some(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])),
        _ => None,
    }
}

/// NDN NonNegativeInteger: 1, 2, 4, or 8 bytes BE, shortest form.
fn encode_non_neg_int(v: u64) -> Vec<u8> {
    if v <= 0xFF {
        vec![v as u8]
    } else if v <= 0xFFFF {
        (v as u16).to_be_bytes().to_vec()
    } else if v <= 0xFFFF_FFFF {
        (v as u32).to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}
