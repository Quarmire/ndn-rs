/// NFD Management Protocol — Status Dataset TLV encoding and decoding.
///
/// Status datasets are returned for list queries (`faces/list`, `fib/list`,
/// `rib/list`, `strategy-choice/list`).  Each dataset is a concatenation of
/// repeated TLV blocks (type 0x80) inside a Data content field.
///
/// Wire format follows the NFD Management Protocol specification:
/// <https://redmine.named-data.net/projects/nfd/wiki/FaceMgmt>
/// <https://redmine.named-data.net/projects/nfd/wiki/FibMgmt>
/// <https://redmine.named-data.net/projects/nfd/wiki/RibMgmt>
/// <https://redmine.named-data.net/projects/nfd/wiki/StrategyChoice>
use bytes::{Bytes, BytesMut};
use ndn_packet::{Name, NameComponent};
use ndn_tlv::{TlvReader, TlvWriter};

// ─── TLV type constants ──────────────────────────────────────────────────────

mod tlv {
    // Shared across dataset types (also overlap with ControlParameters fields).
    pub const FACE_ID: u64 = 0x69;
    pub const COST: u64 = 0x6a;
    pub const STRATEGY_WRAPPER: u64 = 0x6b;
    pub const FLAGS: u64 = 0x6c;
    pub const EXPIRATION_PERIOD: u64 = 0x6d;
    pub const ORIGIN: u64 = 0x6f;
    pub const URI: u64 = 0x72;

    // FaceStatus
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

    // FibEntry / RibEntry outer container
    pub const ENTRY: u64 = 0x80;
    // FibEntry NextHopRecord
    pub const NEXT_HOP_RECORD: u64 = 0x81;
    // RibEntry Route
    pub const ROUTE: u64 = 0x81;

    // Standard NDN Name type.
    pub const NAME: u64 = 0x07;
    #[allow(dead_code)]
    pub const NAME_COMPONENT: u64 = 0x08;
}

// ─── NonNegativeInteger helpers ──────────────────────────────────────────────

/// Encode a NonNegativeInteger: the shortest big-endian representation.
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

/// Write a TLV element with a NonNegativeInteger value.
fn write_non_neg_int(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_non_neg_int(value));
}

/// Read a NonNegativeInteger from a value slice (1, 2, 4, or 8 bytes).
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

// ─── Name helpers ─────────────────────────────────────────────────────────────

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

// ─── FaceStatus ───────────────────────────────────────────────────────────────

/// NFD FaceStatus dataset entry (TLV type 0x80).
///
/// Returned by `faces/list`.
#[derive(Debug, Clone)]
pub struct FaceStatus {
    pub face_id: u64,
    /// Remote URI (e.g. `udp4://192.168.1.1:6363`)
    pub uri: String,
    /// Local URI (e.g. `udp4://0.0.0.0:6363`)
    pub local_uri: String,
    /// 0 = non-local, 1 = local
    pub face_scope: u64,
    /// 0 = persistent, 1 = on-demand, 2 = permanent
    pub face_persistency: u64,
    /// 0 = point-to-point, 1 = multi-access
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
}

impl FaceStatus {
    /// Encode to a complete FaceStatus TLV block (type 0x80).
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
        });
        w.finish()
    }

    /// Decode one FaceStatus entry from the front of `buf`, advancing the cursor.
    pub fn decode(buf: &mut &[u8]) -> Option<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(buf));
        let (typ, value) = r.read_tlv().ok()?;
        if typ != tlv::FACE_STATUS {
            return None;
        }
        // Advance the caller's cursor past this entry.
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

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                tlv::FACE_ID => face_id = read_non_neg_int(&v)?,
                tlv::URI => uri = std::str::from_utf8(&v).ok()?.to_owned(),
                tlv::LOCAL_URI => local_uri = std::str::from_utf8(&v).ok()?.to_owned(),
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
                _ => {} // skip unknown fields
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
        })
    }

    /// Decode a concatenated series of FaceStatus entries (full dataset content).
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

    /// Persistency label for display.
    pub fn persistency_str(&self) -> &'static str {
        match self.face_persistency {
            0 => "persistent",
            1 => "on-demand",
            2 => "permanent",
            _ => "unknown",
        }
    }

    /// Scope label for display.
    pub fn scope_str(&self) -> &'static str {
        match self.face_scope {
            1 => "local",
            _ => "non-local",
        }
    }
}

// ─── NextHopRecord / FibEntry ─────────────────────────────────────────────────

/// A single nexthop in a FIB entry.
#[derive(Debug, Clone)]
pub struct NextHopRecord {
    pub face_id: u64,
    pub cost: u64,
}

/// NFD FibEntry dataset entry (TLV type 0x80).
///
/// Returned by `fib/list`.
#[derive(Debug, Clone)]
pub struct FibEntry {
    pub name: Name,
    pub nexthops: Vec<NextHopRecord>,
}

impl FibEntry {
    /// Encode to a complete FibEntry TLV block (type 0x80).
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

    /// Decode one FibEntry from the front of `buf`, advancing the cursor.
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

    /// Decode a concatenated series of FibEntry entries (full dataset content).
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

// ─── Route / RibEntry ─────────────────────────────────────────────────────────

/// A single route in a RIB entry.
#[derive(Debug, Clone)]
pub struct Route {
    pub face_id: u64,
    pub origin: u64,
    pub cost: u64,
    pub flags: u64,
    pub expiration_period: Option<u64>,
}

/// NFD RibEntry dataset entry (TLV type 0x80).
///
/// Returned by `rib/list`.
#[derive(Debug, Clone)]
pub struct RibEntry {
    pub name: Name,
    pub routes: Vec<Route>,
}

impl RibEntry {
    /// Encode to a complete RibEntry TLV block (type 0x80).
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

    /// Decode one RibEntry from the front of `buf`, advancing the cursor.
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

    /// Decode a concatenated series of RibEntry entries (full dataset content).
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

// ─── StrategyChoice ───────────────────────────────────────────────────────────

/// NFD StrategyChoice dataset entry (TLV type 0x80).
///
/// Returned by `strategy-choice/list`.
#[derive(Debug, Clone)]
pub struct StrategyChoice {
    pub name: Name,
    pub strategy: Name,
}

impl StrategyChoice {
    /// Encode to a complete StrategyChoice TLV block (type 0x80).
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

    /// Decode one StrategyChoice from the front of `buf`, advancing the cursor.
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
                    // strategy wrapper contains a Name
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

    /// Decode a concatenated series of StrategyChoice entries (full dataset content).
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

// ─── Encode helpers ───────────────────────────────────────────────────────────

/// Concatenate multiple encoded dataset entries into a single `Bytes` buffer.
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
    use ndn_packet::NameComponent;

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
