//! NFD status-dataset TLVs returned by `*/list` queries — concatenated
//! 0x80-typed blocks inside a Data content field. Wire format:
//! <https://redmine.named-data.net/projects/nfd/wiki/FaceMgmt>,
//! <https://redmine.named-data.net/projects/nfd/wiki/FibMgmt>,
//! <https://redmine.named-data.net/projects/nfd/wiki/RibMgmt>,
//! <https://redmine.named-data.net/projects/nfd/wiki/StrategyChoice>.
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bytes::{Bytes, BytesMut};
use ndn_foundation_types::{Name, NameComponent};
use ndn_tlv::{TlvReader, TlvWriter};

mod tlv {
    pub const FACE_ID: u64 = 0x69;
    pub const COST: u64 = 0x6a;
    pub const STRATEGY_WRAPPER: u64 = 0x6b;
    pub const FLAGS: u64 = 0x6c;
    pub const EXPIRATION_PERIOD: u64 = 0x6d;
    pub const ORIGIN: u64 = 0x6f;
    pub const URI: u64 = 0x72;

    pub const FACE_STATUS: u64 = 0x80;
    pub const LOCAL_URI: u64 = 0x81;
    pub const FACE_SCOPE: u64 = 0x84;
    pub const FACE_PERSISTENCY: u64 = 0x85;
    pub const LINK_TYPE: u64 = 0x86;
    pub const BASE_CONGESTION_MARKING_INTERVAL: u64 = 0x87;
    pub const DEFAULT_CONGESTION_THRESHOLD: u64 = 0x88;
    pub const MTU: u64 = 0x89;
    pub const N_IN_INTERESTS: u64 = 0x90;
    pub const N_IN_DATA: u64 = 0x91;
    pub const N_OUT_INTERESTS: u64 = 0x92;
    pub const N_OUT_DATA: u64 = 0x93;
    pub const N_IN_BYTES: u64 = 0x94;
    pub const N_OUT_BYTES: u64 = 0x95;
    pub const N_IN_NACKS: u64 = 0x97;
    pub const N_OUT_NACKS: u64 = 0x98;
    pub const N_SATISFIED_INTERESTS: u64 = 0x99;
    pub const N_UNSATISFIED_INTERESTS: u64 = 0x9a;

    // ndn-rs-specific FaceStatus extensions in project-private
    // 0xDA..=0xE2. NFD clients ignore unknown non-critical codes, so
    // these are additive on the wire.
    pub const N_LP_ACKS_RECEIVED: u64 = 0xda;
    pub const N_LP_RESENT_PACKETS: u64 = 0xdb;
    pub const N_LP_RTO_EXPIRATIONS: u64 = 0xdc;
    pub const N_CONGESTION_MARKS_SENT: u64 = 0xdd;
    pub const N_CONGESTION_MARKS_RECEIVED: u64 = 0xde;
    pub const EFFECTIVE_MTU: u64 = 0xdf;
    pub const FEATURE_SET: u64 = 0xe0;
    pub const FEATURE_NAME: u64 = 0xe1;
    pub const RTO_MICROS: u64 = 0xe2;

    pub const ENTRY: u64 = 0x80;
    pub const NEXT_HOP_RECORD: u64 = 0x81;
    pub const ROUTE: u64 = 0x81;
    pub const NAME: u64 = 0x07;
}

fn encode_non_neg_int(value: u64) -> Vec<u8> {
    if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFF_FFFF {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn write_non_neg_int(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_non_neg_int(value));
}

fn read_non_neg_int(buf: &[u8]) -> Option<u64> {
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

fn encode_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

fn decode_name(value: Bytes) -> Option<Name> {
    let mut r = TlvReader::new(value);
    let mut components = Vec::new();
    while !r.is_empty() {
        let (typ, val) = r.read_tlv().ok()?;
        components.push(NameComponent { typ, value: val });
    }
    if components.is_empty() {
        Some(Name::root())
    } else {
        Some(Name::from_components(components))
    }
}

/// One entry from `faces/list` (TLV 0x80).
#[derive(Debug, Clone, Default)]
pub struct FaceStatus {
    pub face_id: u64,
    pub uri: String,
    pub local_uri: String,
    pub face_scope: u64,
    pub face_persistency: u64,
    pub link_type: u64,
    pub mtu: Option<u64>,
    pub base_congestion_marking_interval: Option<u64>,
    pub default_congestion_threshold: Option<u64>,
    pub n_in_interests: u64,
    pub n_in_data: u64,
    pub n_in_nacks: u64,
    pub n_out_interests: u64,
    pub n_out_data: u64,
    pub n_out_nacks: u64,
    pub n_in_bytes: u64,
    pub n_out_bytes: u64,
    pub n_satisfied_interests: u64,
    pub n_unsatisfied_interests: u64,
    /// FaceFlags bitmap (NFD tlv-nfd.hpp `Flags`=0x6c). Bit 0 =
    /// LocalFieldsEnabled, 1 = LpReliabilityEnabled, 2 =
    /// CongestionMarkingEnabled. Mutable via `faces/update` `Flags`
    /// + `Mask`.
    pub flags: u64,

    // `None` here means "not populated / not applicable", distinct
    // from `Some(0)` ("feature on, counter at zero").
    pub n_lp_acks_received: Option<u64>,
    pub n_lp_resent_packets: Option<u64>,
    /// LP packets dropped after `max_retries`.
    pub n_lp_rto_expirations: Option<u64>,
    pub n_congestion_marks_sent: Option<u64>,
    /// Ingress observations of LP `CongestionMark` (0x340).
    pub n_congestion_marks_received: Option<u64>,
    /// MTU after LinkService-layer override; `mtu` is the raw transport
    /// frame budget.
    pub effective_mtu: Option<u64>,
    /// Registered LinkService feature names (kebab-case); empty for
    /// PassthroughLinkService faces.
    pub feature_set: Vec<String>,
    /// Reliability RTO in microseconds; `None` when the face has no
    /// reliability feature.
    pub rto_micros: Option<u64>,
}

impl FaceStatus {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::FACE_STATUS, |w| {
            write_non_neg_int(w, tlv::FACE_ID, self.face_id);
            w.write_tlv(tlv::URI, self.uri.as_bytes());
            w.write_tlv(tlv::LOCAL_URI, self.local_uri.as_bytes());
            write_non_neg_int(w, tlv::FACE_SCOPE, self.face_scope);
            write_non_neg_int(w, tlv::FACE_PERSISTENCY, self.face_persistency);
            write_non_neg_int(w, tlv::LINK_TYPE, self.link_type);
            if let Some(v) = self.base_congestion_marking_interval {
                write_non_neg_int(w, tlv::BASE_CONGESTION_MARKING_INTERVAL, v);
            }
            if let Some(v) = self.default_congestion_threshold {
                write_non_neg_int(w, tlv::DEFAULT_CONGESTION_THRESHOLD, v);
            }
            if let Some(v) = self.mtu {
                write_non_neg_int(w, tlv::MTU, v);
            }
            write_non_neg_int(w, tlv::N_IN_INTERESTS, self.n_in_interests);
            write_non_neg_int(w, tlv::N_IN_DATA, self.n_in_data);
            write_non_neg_int(w, tlv::N_IN_NACKS, self.n_in_nacks);
            write_non_neg_int(w, tlv::N_OUT_INTERESTS, self.n_out_interests);
            write_non_neg_int(w, tlv::N_OUT_DATA, self.n_out_data);
            write_non_neg_int(w, tlv::N_OUT_NACKS, self.n_out_nacks);
            write_non_neg_int(w, tlv::N_IN_BYTES, self.n_in_bytes);
            write_non_neg_int(w, tlv::N_OUT_BYTES, self.n_out_bytes);
            write_non_neg_int(w, tlv::FLAGS, self.flags);

            // Tier 4 §4.3 — ndn-rs extension fields, append at the
            // end so NFD clients reading top-down hit them after
            // every NFD-canonical field.
            if let Some(v) = self.n_lp_acks_received {
                write_non_neg_int(w, tlv::N_LP_ACKS_RECEIVED, v);
            }
            if let Some(v) = self.n_lp_resent_packets {
                write_non_neg_int(w, tlv::N_LP_RESENT_PACKETS, v);
            }
            if let Some(v) = self.n_lp_rto_expirations {
                write_non_neg_int(w, tlv::N_LP_RTO_EXPIRATIONS, v);
            }
            if let Some(v) = self.n_congestion_marks_sent {
                write_non_neg_int(w, tlv::N_CONGESTION_MARKS_SENT, v);
            }
            if let Some(v) = self.n_congestion_marks_received {
                write_non_neg_int(w, tlv::N_CONGESTION_MARKS_RECEIVED, v);
            }
            if let Some(v) = self.effective_mtu {
                write_non_neg_int(w, tlv::EFFECTIVE_MTU, v);
            }
            if !self.feature_set.is_empty() {
                w.write_nested(tlv::FEATURE_SET, |w| {
                    for name in &self.feature_set {
                        w.write_tlv(tlv::FEATURE_NAME, name.as_bytes());
                    }
                });
            }
            if let Some(v) = self.rto_micros {
                write_non_neg_int(w, tlv::RTO_MICROS, v);
            }
        });
        w.finish()
    }

    pub fn decode(buf: &mut &[u8]) -> Option<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(buf));
        let (typ, value) = r.read_tlv().ok()?;
        if typ != tlv::FACE_STATUS {
            return None;
        }
        let consumed = buf.len() - r.remaining();
        *buf = &buf[consumed..];

        let mut inner = TlvReader::new(value);
        let mut face_id = 0u64;
        let mut uri = String::new();
        let mut local_uri = String::new();
        let mut face_scope = 0u64;
        let mut face_persistency = 0u64;
        let mut link_type = 0u64;
        let mut mtu = None;
        let mut base_congestion = None;
        let mut def_congestion = None;
        let mut n_in_interests = 0u64;
        let mut n_in_data = 0u64;
        let mut n_in_nacks = 0u64;
        let mut n_out_interests = 0u64;
        let mut n_out_data = 0u64;
        let mut n_out_nacks = 0u64;
        let mut n_in_bytes = 0u64;
        let mut n_out_bytes = 0u64;
        let mut n_satisfied_interests = 0u64;
        let mut n_unsatisfied_interests = 0u64;
        let mut flags = 0u64;
        let mut n_lp_acks_received = None;
        let mut n_lp_resent_packets = None;
        let mut n_lp_rto_expirations = None;
        let mut n_congestion_marks_sent = None;
        let mut n_congestion_marks_received = None;
        let mut effective_mtu = None;
        let mut feature_set: Vec<String> = Vec::new();
        let mut rto_micros = None;

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                tlv::FACE_ID => face_id = read_non_neg_int(&v)?,
                tlv::URI => uri = core::str::from_utf8(&v).ok()?.to_owned(),
                tlv::LOCAL_URI => local_uri = core::str::from_utf8(&v).ok()?.to_owned(),
                tlv::FACE_SCOPE => face_scope = read_non_neg_int(&v)?,
                tlv::FACE_PERSISTENCY => face_persistency = read_non_neg_int(&v)?,
                tlv::LINK_TYPE => link_type = read_non_neg_int(&v)?,
                tlv::MTU => mtu = read_non_neg_int(&v),
                tlv::BASE_CONGESTION_MARKING_INTERVAL => {
                    base_congestion = read_non_neg_int(&v);
                }
                tlv::DEFAULT_CONGESTION_THRESHOLD => {
                    def_congestion = read_non_neg_int(&v);
                }
                tlv::N_IN_INTERESTS => n_in_interests = read_non_neg_int(&v)?,
                tlv::N_IN_DATA => n_in_data = read_non_neg_int(&v)?,
                tlv::N_IN_NACKS => n_in_nacks = read_non_neg_int(&v)?,
                tlv::N_OUT_INTERESTS => n_out_interests = read_non_neg_int(&v)?,
                tlv::N_OUT_DATA => n_out_data = read_non_neg_int(&v)?,
                tlv::N_OUT_NACKS => n_out_nacks = read_non_neg_int(&v)?,
                tlv::N_IN_BYTES => n_in_bytes = read_non_neg_int(&v)?,
                tlv::N_OUT_BYTES => n_out_bytes = read_non_neg_int(&v)?,
                tlv::N_SATISFIED_INTERESTS => n_satisfied_interests = read_non_neg_int(&v)?,
                tlv::N_UNSATISFIED_INTERESTS => n_unsatisfied_interests = read_non_neg_int(&v)?,
                tlv::FLAGS => flags = read_non_neg_int(&v)?,
                tlv::N_LP_ACKS_RECEIVED => n_lp_acks_received = read_non_neg_int(&v),
                tlv::N_LP_RESENT_PACKETS => n_lp_resent_packets = read_non_neg_int(&v),
                tlv::N_LP_RTO_EXPIRATIONS => n_lp_rto_expirations = read_non_neg_int(&v),
                tlv::N_CONGESTION_MARKS_SENT => n_congestion_marks_sent = read_non_neg_int(&v),
                tlv::N_CONGESTION_MARKS_RECEIVED => {
                    n_congestion_marks_received = read_non_neg_int(&v);
                }
                tlv::EFFECTIVE_MTU => effective_mtu = read_non_neg_int(&v),
                tlv::FEATURE_SET => {
                    let mut feat_r = TlvReader::new(v);
                    while !feat_r.is_empty() {
                        let (ft, fv) = feat_r.read_tlv().ok()?;
                        if ft == tlv::FEATURE_NAME
                            && let Ok(s) = core::str::from_utf8(&fv)
                        {
                            feature_set.push(s.to_owned());
                        }
                    }
                }
                tlv::RTO_MICROS => rto_micros = read_non_neg_int(&v),
                _ => {}
            }
        }

        Some(FaceStatus {
            face_id,
            uri,
            local_uri,
            face_scope,
            face_persistency,
            link_type,
            mtu,
            base_congestion_marking_interval: base_congestion,
            default_congestion_threshold: def_congestion,
            n_in_interests,
            n_in_data,
            n_in_nacks,
            n_out_interests,
            n_out_data,
            n_out_nacks,
            n_in_bytes,
            n_out_bytes,
            n_satisfied_interests,
            n_unsatisfied_interests,
            flags,
            n_lp_acks_received,
            n_lp_resent_packets,
            n_lp_rto_expirations,
            n_congestion_marks_sent,
            n_congestion_marks_received,
            effective_mtu,
            feature_set,
            rto_micros,
        })
    }

    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        let mut buf = bytes;
        let mut out = Vec::new();
        while !buf.is_empty() {
            match Self::decode(&mut buf) {
                Some(entry) => out.push(entry),
                None => break,
            }
        }
        out
    }

    pub fn persistency_str(&self) -> &'static str {
        match self.face_persistency {
            0 => "persistent",
            1 => "on-demand",
            2 => "permanent",
            _ => "unknown",
        }
    }

    pub fn scope_str(&self) -> &'static str {
        match self.face_scope {
            1 => "local",
            _ => "non-local",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NextHopRecord {
    pub face_id: u64,
    pub cost: u64,
}

/// One entry from `fib/list` (TLV 0x80).
#[derive(Debug, Clone)]
pub struct FibEntry {
    pub name: Name,
    pub nexthops: Vec<NextHopRecord>,
}

impl FibEntry {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ENTRY, |w| {
            encode_name(w, &self.name);
            for nh in &self.nexthops {
                w.write_nested(tlv::NEXT_HOP_RECORD, |w| {
                    write_non_neg_int(w, tlv::FACE_ID, nh.face_id);
                    write_non_neg_int(w, tlv::COST, nh.cost);
                });
            }
        });
        w.finish()
    }

    pub fn decode(buf: &mut &[u8]) -> Option<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(buf));
        let (typ, value) = r.read_tlv().ok()?;
        if typ != tlv::ENTRY {
            return None;
        }
        let consumed = buf.len() - r.remaining();
        *buf = &buf[consumed..];

        let mut inner = TlvReader::new(value);
        let mut name = None;
        let mut nexthops = Vec::new();

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                tlv::NAME => name = decode_name(v),
                tlv::NEXT_HOP_RECORD => {
                    let mut nr = TlvReader::new(v);
                    let mut face_id = 0u64;
                    let mut cost = 0u64;
                    while !nr.is_empty() {
                        if let Ok((nt, nv)) = nr.read_tlv() {
                            match nt {
                                tlv::FACE_ID => face_id = read_non_neg_int(&nv).unwrap_or(0),
                                tlv::COST => cost = read_non_neg_int(&nv).unwrap_or(0),
                                _ => {}
                            }
                        }
                    }
                    nexthops.push(NextHopRecord { face_id, cost });
                }
                _ => {}
            }
        }

        Some(FibEntry {
            name: name.unwrap_or_else(Name::root),
            nexthops,
        })
    }

    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        let mut buf = bytes;
        let mut out = Vec::new();
        while !buf.is_empty() {
            match Self::decode(&mut buf) {
                Some(entry) => out.push(entry),
                None => break,
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub face_id: u64,
    pub origin: u64,
    pub cost: u64,
    pub flags: u64,
    pub expiration_period: Option<u64>,
}

/// One entry from `rib/list` (TLV 0x80).
#[derive(Debug, Clone)]
pub struct RibEntry {
    pub name: Name,
    pub routes: Vec<Route>,
}

impl RibEntry {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ENTRY, |w| {
            encode_name(w, &self.name);
            for route in &self.routes {
                w.write_nested(tlv::ROUTE, |w| {
                    write_non_neg_int(w, tlv::FACE_ID, route.face_id);
                    write_non_neg_int(w, tlv::ORIGIN, route.origin);
                    write_non_neg_int(w, tlv::COST, route.cost);
                    write_non_neg_int(w, tlv::FLAGS, route.flags);
                    if let Some(ep) = route.expiration_period {
                        write_non_neg_int(w, tlv::EXPIRATION_PERIOD, ep);
                    }
                });
            }
        });
        w.finish()
    }

    pub fn decode(buf: &mut &[u8]) -> Option<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(buf));
        let (typ, value) = r.read_tlv().ok()?;
        if typ != tlv::ENTRY {
            return None;
        }
        let consumed = buf.len() - r.remaining();
        *buf = &buf[consumed..];

        let mut inner = TlvReader::new(value);
        let mut name = None;
        let mut routes = Vec::new();

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                tlv::NAME => name = decode_name(v),
                tlv::ROUTE => {
                    let mut rr = TlvReader::new(v);
                    let mut face_id = 0u64;
                    let mut origin = 0u64;
                    let mut cost = 0u64;
                    let mut flags = 0u64;
                    let mut expiration_period = None;
                    while !rr.is_empty() {
                        if let Ok((rt, rv)) = rr.read_tlv() {
                            match rt {
                                tlv::FACE_ID => {
                                    face_id = read_non_neg_int(&rv).unwrap_or(0);
                                }
                                tlv::ORIGIN => {
                                    origin = read_non_neg_int(&rv).unwrap_or(0);
                                }
                                tlv::COST => {
                                    cost = read_non_neg_int(&rv).unwrap_or(0);
                                }
                                tlv::FLAGS => {
                                    flags = read_non_neg_int(&rv).unwrap_or(0);
                                }
                                tlv::EXPIRATION_PERIOD => {
                                    expiration_period = read_non_neg_int(&rv);
                                }
                                _ => {}
                            }
                        }
                    }
                    routes.push(Route {
                        face_id,
                        origin,
                        cost,
                        flags,
                        expiration_period,
                    });
                }
                _ => {}
            }
        }

        Some(RibEntry {
            name: name.unwrap_or_else(Name::root),
            routes,
        })
    }

    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        let mut buf = bytes;
        let mut out = Vec::new();
        while !buf.is_empty() {
            match Self::decode(&mut buf) {
                Some(entry) => out.push(entry),
                None => break,
            }
        }
        out
    }
}

/// One entry from `strategy-choice/list` (TLV 0x80).
#[derive(Debug, Clone)]
pub struct StrategyChoice {
    pub name: Name,
    pub strategy: Name,
}

impl StrategyChoice {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ENTRY, |w| {
            encode_name(w, &self.name);
            w.write_nested(tlv::STRATEGY_WRAPPER, |w| {
                encode_name(w, &self.strategy);
            });
        });
        w.finish()
    }

    pub fn decode(buf: &mut &[u8]) -> Option<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(buf));
        let (typ, value) = r.read_tlv().ok()?;
        if typ != tlv::ENTRY {
            return None;
        }
        let consumed = buf.len() - r.remaining();
        *buf = &buf[consumed..];

        let mut inner = TlvReader::new(value);
        let mut name = None;
        let mut strategy = None;

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                tlv::NAME => name = decode_name(v),
                tlv::STRATEGY_WRAPPER => {
                    let mut sr = TlvReader::new(v);
                    if let Ok((st, sv)) = sr.read_tlv()
                        && st == tlv::NAME
                    {
                        strategy = decode_name(sv);
                    }
                }
                _ => {}
            }
        }

        Some(StrategyChoice {
            name: name.unwrap_or_else(Name::root),
            strategy: strategy.unwrap_or_else(Name::root),
        })
    }

    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        let mut buf = bytes;
        let mut out = Vec::new();
        while !buf.is_empty() {
            match Self::decode(&mut buf) {
                Some(entry) => out.push(entry),
                None => break,
            }
        }
        out
    }
}

pub fn encode_dataset<T, F>(items: &[T], encode_fn: F) -> Bytes
where
    F: Fn(&T) -> Bytes,
{
    let mut buf = BytesMut::new();
    for item in items {
        buf.extend_from_slice(&encode_fn(item));
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_foundation_types::NameComponent;

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    #[test]
    fn face_status_roundtrip() {
        let fs = FaceStatus {
            face_id: 1,
            uri: "udp4://192.168.1.1:6363".to_owned(),
            local_uri: "udp4://0.0.0.0:6363".to_owned(),
            face_scope: 0,
            face_persistency: 0,
            link_type: 0,
            mtu: Some(8800),
            base_congestion_marking_interval: None,
            default_congestion_threshold: None,
            n_in_interests: 100,
            n_in_data: 50,
            n_in_nacks: 2,
            n_out_interests: 80,
            n_out_data: 30,
            n_out_nacks: 1,
            n_in_bytes: 10000,
            n_out_bytes: 5000,
            n_satisfied_interests: 42,
            n_unsatisfied_interests: 3,
            flags: 0b101,
            ..Default::default()
        };
        let encoded = fs.encode();
        let mut buf = encoded.as_ref();
        let decoded = FaceStatus::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(decoded.face_id, 1);
        assert_eq!(decoded.uri, "udp4://192.168.1.1:6363");
        assert_eq!(decoded.local_uri, "udp4://0.0.0.0:6363");
        assert_eq!(decoded.mtu, Some(8800));
        assert_eq!(decoded.n_in_interests, 100);
        assert_eq!(decoded.flags, 0b101);
    }

    #[test]
    fn face_status_emits_flags() {
        let fs = FaceStatus {
            face_id: 7,
            uri: "udp4://10.0.0.1:6363".to_owned(),
            local_uri: "udp4://0.0.0.0:6363".to_owned(),
            face_scope: 0,
            face_persistency: 0,
            link_type: 0,
            mtu: None,
            base_congestion_marking_interval: None,
            default_congestion_threshold: None,
            n_in_interests: 0,
            n_in_data: 0,
            n_in_nacks: 0,
            n_out_interests: 0,
            n_out_data: 0,
            n_out_nacks: 0,
            n_in_bytes: 0,
            n_out_bytes: 0,
            n_satisfied_interests: 0,
            n_unsatisfied_interests: 0,
            flags: 0,
            ..Default::default()
        };
        let encoded = fs.encode();
        assert!(
            encoded.windows(1).any(|b| b[0] == tlv::FLAGS as u8),
            "Flags TLV (0x6c) absent"
        );
    }

    #[test]
    fn face_status_wire_order_keeps_nfd_required_flags_before_extensions() {
        let fs = FaceStatus {
            face_id: 7,
            uri: "udp4://10.0.0.1:6363".to_owned(),
            local_uri: "udp4://0.0.0.0:6363".to_owned(),
            face_scope: 0,
            face_persistency: 0,
            link_type: 0,
            flags: 0,
            n_lp_resent_packets: Some(3),
            ..Default::default()
        };
        let encoded = fs.encode();
        let mut outer = TlvReader::new(encoded);
        let (typ, value) = outer.read_tlv().unwrap();
        assert_eq!(typ, tlv::FACE_STATUS);

        let mut inner = TlvReader::new(value);
        let mut seen_flags = false;
        while !inner.is_empty() {
            let (typ, _) = inner.read_tlv().unwrap();
            assert_ne!(
                typ,
                tlv::N_SATISFIED_INTERESTS,
                "FaceStatus must not emit GeneralStatus NSatisfiedInterests"
            );
            assert_ne!(
                typ,
                tlv::N_UNSATISFIED_INTERESTS,
                "FaceStatus must not emit GeneralStatus NUnsatisfiedInterests"
            );
            if typ == tlv::N_LP_RESENT_PACKETS {
                assert!(seen_flags, "NFD-required Flags must precede extensions");
            }
            seen_flags |= typ == tlv::FLAGS;
        }
        assert!(seen_flags, "Flags TLV (0x6c) absent");
    }

    #[test]
    fn face_status_decode_all() {
        let faces = vec![
            FaceStatus {
                face_id: 1,
                uri: "udp4://1.2.3.4:6363".to_owned(),
                local_uri: "udp4://0.0.0.0:0".to_owned(),
                face_scope: 0,
                face_persistency: 0,
                link_type: 0,
                mtu: None,
                base_congestion_marking_interval: None,
                default_congestion_threshold: None,
                n_in_interests: 0,
                n_in_data: 0,
                n_in_nacks: 0,
                n_out_interests: 0,
                n_out_data: 0,
                n_out_nacks: 0,
                n_in_bytes: 0,
                n_out_bytes: 0,
                n_satisfied_interests: 0,
                n_unsatisfied_interests: 0,
                flags: 0,
                ..Default::default()
            },
            FaceStatus {
                face_id: 2,
                uri: "tcp4://5.6.7.8:6363".to_owned(),
                local_uri: "tcp4://0.0.0.0:0".to_owned(),
                face_scope: 1,
                face_persistency: 2,
                link_type: 0,
                mtu: None,
                base_congestion_marking_interval: None,
                default_congestion_threshold: None,
                n_in_interests: 0,
                n_in_data: 0,
                n_in_nacks: 0,
                n_out_interests: 0,
                n_out_data: 0,
                n_out_nacks: 0,
                n_in_bytes: 0,
                n_out_bytes: 0,
                n_satisfied_interests: 0,
                n_unsatisfied_interests: 0,
                flags: 0,
                ..Default::default()
            },
        ];
        let mut buf = BytesMut::new();
        for f in &faces {
            buf.extend_from_slice(&f.encode());
        }
        let decoded = FaceStatus::decode_all(&buf);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].face_id, 1);
        assert_eq!(decoded[1].face_id, 2);
        assert_eq!(decoded[1].face_persistency, 2);
    }

    #[test]
    fn face_status_extended_round_trips() {
        let fs = FaceStatus {
            face_id: 42,
            uri: "udp4://10.0.0.1:6363".to_owned(),
            local_uri: "udp4://0.0.0.0:6363".to_owned(),
            face_scope: 0,
            face_persistency: 0,
            link_type: 0,
            mtu: Some(8800),
            base_congestion_marking_interval: Some(100_000),
            default_congestion_threshold: Some(65_536),
            n_in_interests: 1,
            n_in_data: 2,
            n_in_nacks: 3,
            n_out_interests: 4,
            n_out_data: 5,
            n_out_nacks: 6,
            n_in_bytes: 7,
            n_out_bytes: 8,
            n_satisfied_interests: 9,
            n_unsatisfied_interests: 10,
            flags: 0b110,
            n_lp_acks_received: Some(11),
            n_lp_resent_packets: Some(12),
            n_lp_rto_expirations: Some(13),
            n_congestion_marks_sent: Some(14),
            n_congestion_marks_received: Some(15),
            effective_mtu: Some(8500),
            feature_set: vec![
                "fragmentation".to_owned(),
                "reliability".to_owned(),
                "congestion-marking".to_owned(),
            ],
            rto_micros: Some(420),
        };
        let encoded = fs.encode();
        let mut buf = encoded.as_ref();
        let decoded = FaceStatus::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(decoded.n_lp_acks_received, Some(11));
        assert_eq!(decoded.n_lp_resent_packets, Some(12));
        assert_eq!(decoded.n_lp_rto_expirations, Some(13));
        assert_eq!(decoded.n_congestion_marks_sent, Some(14));
        assert_eq!(decoded.n_congestion_marks_received, Some(15));
        assert_eq!(decoded.effective_mtu, Some(8500));
        assert_eq!(decoded.feature_set, fs.feature_set);
        assert_eq!(decoded.rto_micros, Some(420));
        assert_eq!(decoded.face_id, 42);
        assert_eq!(decoded.flags, 0b110);
    }

    #[test]
    fn face_status_extended_absent_decodes_as_none() {
        let fs = FaceStatus {
            face_id: 1,
            uri: "udp4://127.0.0.1:6363".to_owned(),
            local_uri: "udp4://0.0.0.0:6363".to_owned(),
            ..Default::default()
        };
        let encoded = fs.encode();
        let mut buf = encoded.as_ref();
        let decoded = FaceStatus::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(decoded.n_lp_resent_packets, None);
        assert_eq!(decoded.effective_mtu, None);
        assert!(decoded.feature_set.is_empty());
        assert_eq!(decoded.rto_micros, None);
    }

    #[test]
    fn fib_entry_roundtrip() {
        let entry = FibEntry {
            name: name(&[b"ndn", b"test"]),
            nexthops: vec![
                NextHopRecord {
                    face_id: 1,
                    cost: 10,
                },
                NextHopRecord {
                    face_id: 2,
                    cost: 5,
                },
            ],
        };
        let encoded = entry.encode();
        let mut buf = encoded.as_ref();
        let decoded = FibEntry::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(decoded.nexthops.len(), 2);
        assert_eq!(decoded.nexthops[0].face_id, 1);
        assert_eq!(decoded.nexthops[0].cost, 10);
        assert_eq!(decoded.nexthops[1].face_id, 2);
        assert_eq!(decoded.nexthops[1].cost, 5);
    }

    #[test]
    fn rib_entry_roundtrip() {
        let entry = RibEntry {
            name: name(&[b"ndn"]),
            routes: vec![Route {
                face_id: 3,
                origin: 0,
                cost: 10,
                flags: 1,
                expiration_period: Some(30_000),
            }],
        };
        let encoded = entry.encode();
        let mut buf = encoded.as_ref();
        let decoded = RibEntry::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(decoded.routes.len(), 1);
        assert_eq!(decoded.routes[0].face_id, 3);
        assert_eq!(decoded.routes[0].expiration_period, Some(30_000));
    }

    #[test]
    fn strategy_choice_roundtrip() {
        let entry = StrategyChoice {
            name: name(&[b"ndn"]),
            strategy: name(&[b"localhost", b"nfd", b"strategy", b"best-route"]),
        };
        let encoded = entry.encode();
        let mut buf = encoded.as_ref();
        let decoded = StrategyChoice::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(
            decoded.strategy.to_string(),
            "/localhost/nfd/strategy/best-route"
        );
    }
}
