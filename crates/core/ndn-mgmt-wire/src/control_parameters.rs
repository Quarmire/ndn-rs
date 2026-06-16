//! ControlParameters (TLV 0x68) — argument block for NFD management
//! commands. Wire format:
//! <https://redmine.named-data.net/projects/nfd/wiki/ControlCommand>.
//! All fields are optional; the command determines which are required.
//! Integers use NDN NonNegativeInteger (1/2/4/8-byte big-endian).
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_tlv::{TlvReader, TlvWriter};

pub mod tlv {
    pub const CONTROL_PARAMETERS: u64 = 0x68;
    pub const FACE_ID: u64 = 0x69;
    pub const COST: u64 = 0x6A;
    pub const STRATEGY: u64 = 0x6B;
    pub const FLAGS: u64 = 0x6C;
    pub const EXPIRATION_PERIOD: u64 = 0x6D;
    pub const ORIGIN: u64 = 0x6F;
    pub const MASK: u64 = 0x70;
    pub const URI: u64 = 0x72;
    pub const LOCAL_URI: u64 = 0x81;
    pub const CAPACITY: u64 = 0x83;
    pub const COUNT: u64 = 0x84;
    pub const FACE_PERSISTENCY: u64 = 0x85;
    pub const BASE_CONG_INTERVAL: u64 = 0x87;
    pub const DEF_CONG_THRESHOLD: u64 = 0x88;
    pub const MTU: u64 = 0x89;

    // Coding management — see `crates/draft/ndn-coding`.
    pub const FEC_K: u64 = 0x90;
    pub const FEC_N: u64 = 0x92;
    pub const FEC_FIELD: u64 = 0x94;
    pub const FEC_ROLE: u64 = 0x96;

    // Idempotent faces/create partial-failure body. Provisional codes
    // in project-private 0xE4..=0xE5 / 0xD8..=0xD9; see TLV allocations.
    pub const PARTIAL_FAILURES: u64 = 0xE4;
    pub const PARTIAL_FAILURE: u64 = 0xE5;
    pub const OPTION_NAME: u64 = 0xD8;
    pub const REFUSAL_REASON: u64 = 0xD9;

    // Rate-limit management — see `crates/ndn-ratelimit`.
    pub const RL_DIRECTION: u64 = 0xA0;
    pub const RL_INTEREST_PPS: u64 = 0xA2;
    pub const RL_INTEREST_BURST: u64 = 0xA4;
    pub const RL_DATA_BPS: u64 = 0xA6;
    pub const RL_DATA_BURST_BYTES: u64 = 0xA8;
    pub const RL_OVERFLOW: u64 = 0xAA;
    pub const RL_QUEUE_MAX: u64 = 0xAC;

    pub const NAME: u64 = 0x07;
    pub const NAME_COMPONENT: u64 = 0x08;
}

pub mod rl_direction {
    pub const INBOUND: u8 = 0;
    pub const OUTBOUND: u8 = 1;
}

pub mod rl_overflow {
    pub const NACK: u8 = 0;
    pub const DROP: u8 = 1;
    pub const QUEUE: u8 = 2;
}

pub mod fec_field {
    pub const GF8: u8 = 0;
}

pub mod fec_role {
    pub const PRODUCED: u8 = 0;
    pub const CONSUMED: u8 = 1;
}

/// NFD RIB route origin codes.
pub mod origin {
    pub const APP: u64 = 0;
    pub const AUTOREG: u64 = 64;
    pub const CLIENT: u64 = 65;
    pub const AUTOCONF: u64 = 66;
    pub const DVR: u64 = 127;
    pub const NLSR: u64 = 128;
    pub const PREFIX_ANN: u64 = 129;
    pub const STATIC: u64 = 255;
}

pub mod route_flags {
    pub const CHILD_INHERIT: u64 = 1;
    pub const CAPTURE: u64 = 2;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlParameters {
    pub name: Option<Name>,
    pub face_id: Option<u64>,
    pub uri: Option<String>,
    pub local_uri: Option<String>,
    pub origin: Option<u64>,
    pub cost: Option<u64>,
    pub flags: Option<u64>,
    pub mask: Option<u64>,
    pub expiration_period: Option<u64>,
    pub face_persistency: Option<u64>,
    pub strategy: Option<Name>,
    pub mtu: Option<u64>,
    /// NFD `BaseCongestionMarkingInterval`, microseconds.
    pub base_cong_interval: Option<u64>,
    /// NFD `DefaultCongestionThreshold`, bytes.
    pub def_cong_threshold: Option<u64>,
    pub capacity: Option<u64>,
    pub count: Option<u64>,
    /// Source segments per generation.
    pub fec_k: Option<u16>,
    /// Total segments per generation.
    pub fec_n: Option<u16>,
    /// See `tlv::fec_field`.
    pub fec_field: Option<u8>,
    /// See `tlv::fec_role`.
    pub fec_role: Option<u8>,
    /// See `tlv::rl_direction`.
    pub rl_direction: Option<u8>,
    pub rl_interest_pps: Option<u32>,
    pub rl_interest_burst: Option<u32>,
    pub rl_data_bps: Option<u64>,
    pub rl_data_burst_bytes: Option<u64>,
    /// See `tlv::rl_overflow`.
    pub rl_overflow: Option<u8>,
    /// Used only when `rl_overflow == queue`.
    pub rl_queue_max: Option<u32>,
    /// `(option_name, reason)` reported by idempotent faces/create on
    /// partial apply; empty in every other response body.
    pub partial_failures: Vec<(String, String)>,
}

impl ControlParameters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_PARAMETERS, |w| {
            self.encode_inner(w);
        });
        w.finish()
    }

    /// No outer 0x68 wrapper; for embedding in a name component.
    pub fn encode_value(&self) -> Bytes {
        let mut w = TlvWriter::new();
        self.encode_inner(&mut w);
        w.finish()
    }

    fn encode_inner(&self, w: &mut TlvWriter) {
        if let Some(ref name) = self.name {
            encode_name(w, name);
        }
        if let Some(id) = self.face_id {
            write_non_neg_int(w, tlv::FACE_ID, id);
        }
        if let Some(ref uri) = self.uri {
            w.write_tlv(tlv::URI, uri.as_bytes());
        }
        if let Some(ref local_uri) = self.local_uri {
            w.write_tlv(tlv::LOCAL_URI, local_uri.as_bytes());
        }
        if let Some(origin) = self.origin {
            write_non_neg_int(w, tlv::ORIGIN, origin);
        }
        if let Some(cost) = self.cost {
            write_non_neg_int(w, tlv::COST, cost);
        }
        if let Some(flags) = self.flags {
            write_non_neg_int(w, tlv::FLAGS, flags);
        }
        if let Some(mask) = self.mask {
            write_non_neg_int(w, tlv::MASK, mask);
        }
        if let Some(strategy) = self.strategy.as_ref() {
            w.write_nested(tlv::STRATEGY, |w| {
                encode_name(w, strategy);
            });
        }
        if let Some(ep) = self.expiration_period {
            write_non_neg_int(w, tlv::EXPIRATION_PERIOD, ep);
        }
        if let Some(fp) = self.face_persistency {
            write_non_neg_int(w, tlv::FACE_PERSISTENCY, fp);
        }
        if let Some(mtu) = self.mtu {
            write_non_neg_int(w, tlv::MTU, mtu);
        }
        if let Some(v) = self.base_cong_interval {
            write_non_neg_int(w, tlv::BASE_CONG_INTERVAL, v);
        }
        if let Some(v) = self.def_cong_threshold {
            write_non_neg_int(w, tlv::DEF_CONG_THRESHOLD, v);
        }
        if let Some(capacity) = self.capacity {
            write_non_neg_int(w, tlv::CAPACITY, capacity);
        }
        if let Some(count) = self.count {
            write_non_neg_int(w, tlv::COUNT, count);
        }
        if let Some(k) = self.fec_k {
            write_non_neg_int(w, tlv::FEC_K, k as u64);
        }
        if let Some(n) = self.fec_n {
            write_non_neg_int(w, tlv::FEC_N, n as u64);
        }
        if let Some(f) = self.fec_field {
            w.write_tlv(tlv::FEC_FIELD, &[f]);
        }
        if let Some(r) = self.fec_role {
            w.write_tlv(tlv::FEC_ROLE, &[r]);
        }
        if let Some(d) = self.rl_direction {
            w.write_tlv(tlv::RL_DIRECTION, &[d]);
        }
        if let Some(r) = self.rl_interest_pps {
            write_non_neg_int(w, tlv::RL_INTEREST_PPS, r as u64);
        }
        if let Some(r) = self.rl_interest_burst {
            write_non_neg_int(w, tlv::RL_INTEREST_BURST, r as u64);
        }
        if let Some(r) = self.rl_data_bps {
            write_non_neg_int(w, tlv::RL_DATA_BPS, r);
        }
        if let Some(r) = self.rl_data_burst_bytes {
            write_non_neg_int(w, tlv::RL_DATA_BURST_BYTES, r);
        }
        if let Some(o) = self.rl_overflow {
            w.write_tlv(tlv::RL_OVERFLOW, &[o]);
        }
        if let Some(q) = self.rl_queue_max {
            write_non_neg_int(w, tlv::RL_QUEUE_MAX, q as u64);
        }
        if !self.partial_failures.is_empty() {
            w.write_nested(tlv::PARTIAL_FAILURES, |w| {
                for (option, reason) in &self.partial_failures {
                    w.write_nested(tlv::PARTIAL_FAILURE, |w| {
                        w.write_tlv(tlv::OPTION_NAME, option.as_bytes());
                        w.write_tlv(tlv::REFUSAL_REASON, reason.as_bytes());
                    });
                }
            });
        }
    }

    pub fn decode(wire: Bytes) -> Result<Self, ControlParametersError> {
        let mut r = TlvReader::new(wire);
        let (typ, value) = r
            .read_tlv()
            .map_err(|_| ControlParametersError::MalformedTlv)?;
        if typ != tlv::CONTROL_PARAMETERS {
            return Err(ControlParametersError::WrongType(typ));
        }
        Self::decode_value(value)
    }

    /// Permissive decode of a concatenated stream of ControlParameters
    /// TLVs (the wire shape of `coding/list` and `rate-limit/list`).
    /// Malformed suffix bytes terminate parsing without erroring.
    pub fn decode_all(bytes: &[u8]) -> Vec<Self> {
        let mut reader = TlvReader::new(Bytes::copy_from_slice(bytes));
        let mut out = Vec::new();
        while !reader.is_empty() {
            let Ok((typ, value)) = reader.read_tlv() else {
                break;
            };
            if typ != tlv::CONTROL_PARAMETERS {
                continue;
            }
            if let Ok(cp) = Self::decode_value(value) {
                out.push(cp);
            }
        }
        out
    }

    pub fn decode_value(value: Bytes) -> Result<Self, ControlParametersError> {
        let mut r = TlvReader::new(value);
        let mut params = ControlParameters::default();

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|_| ControlParametersError::MalformedTlv)?;
            match typ {
                tlv::NAME => {
                    params.name = Some(decode_name(val)?);
                }
                tlv::FACE_ID => {
                    params.face_id = Some(read_non_neg_int(&val)?);
                }
                tlv::URI => {
                    params.uri = Some(
                        core::str::from_utf8(&val)
                            .map_err(|_| ControlParametersError::InvalidUtf8)?
                            .to_owned(),
                    );
                }
                tlv::LOCAL_URI => {
                    params.local_uri = Some(
                        core::str::from_utf8(&val)
                            .map_err(|_| ControlParametersError::InvalidUtf8)?
                            .to_owned(),
                    );
                }
                tlv::ORIGIN => {
                    params.origin = Some(read_non_neg_int(&val)?);
                }
                tlv::COST => {
                    params.cost = Some(read_non_neg_int(&val)?);
                }
                tlv::FLAGS => {
                    params.flags = Some(read_non_neg_int(&val)?);
                }
                tlv::MASK => {
                    params.mask = Some(read_non_neg_int(&val)?);
                }
                tlv::STRATEGY => {
                    let mut inner = TlvReader::new(val);
                    let (t, v) = inner
                        .read_tlv()
                        .map_err(|_| ControlParametersError::MalformedTlv)?;
                    if t != tlv::NAME {
                        return Err(ControlParametersError::WrongType(t));
                    }
                    params.strategy = Some(decode_name(v)?);
                }
                tlv::EXPIRATION_PERIOD => {
                    params.expiration_period = Some(read_non_neg_int(&val)?);
                }
                tlv::FACE_PERSISTENCY => {
                    params.face_persistency = Some(read_non_neg_int(&val)?);
                }
                tlv::MTU => {
                    params.mtu = Some(read_non_neg_int(&val)?);
                }
                tlv::BASE_CONG_INTERVAL => {
                    params.base_cong_interval = Some(read_non_neg_int(&val)?);
                }
                tlv::DEF_CONG_THRESHOLD => {
                    params.def_cong_threshold = Some(read_non_neg_int(&val)?);
                }
                tlv::CAPACITY => {
                    params.capacity = Some(read_non_neg_int(&val)?);
                }
                tlv::COUNT => {
                    params.count = Some(read_non_neg_int(&val)?);
                }
                tlv::FEC_K => {
                    let v = read_non_neg_int(&val)?;
                    params.fec_k =
                        Some(u16::try_from(v).map_err(|_| ControlParametersError::MalformedTlv)?);
                }
                tlv::FEC_N => {
                    let v = read_non_neg_int(&val)?;
                    params.fec_n =
                        Some(u16::try_from(v).map_err(|_| ControlParametersError::MalformedTlv)?);
                }
                tlv::FEC_FIELD => {
                    if val.len() != 1 {
                        return Err(ControlParametersError::MalformedTlv);
                    }
                    params.fec_field = Some(val[0]);
                }
                tlv::FEC_ROLE => {
                    if val.len() != 1 {
                        return Err(ControlParametersError::MalformedTlv);
                    }
                    params.fec_role = Some(val[0]);
                }
                tlv::RL_DIRECTION => {
                    if val.len() != 1 {
                        return Err(ControlParametersError::MalformedTlv);
                    }
                    params.rl_direction = Some(val[0]);
                }
                tlv::RL_INTEREST_PPS => {
                    let v = read_non_neg_int(&val)?;
                    params.rl_interest_pps =
                        Some(u32::try_from(v).map_err(|_| ControlParametersError::MalformedTlv)?);
                }
                tlv::RL_INTEREST_BURST => {
                    let v = read_non_neg_int(&val)?;
                    params.rl_interest_burst =
                        Some(u32::try_from(v).map_err(|_| ControlParametersError::MalformedTlv)?);
                }
                tlv::RL_DATA_BPS => {
                    params.rl_data_bps = Some(read_non_neg_int(&val)?);
                }
                tlv::RL_DATA_BURST_BYTES => {
                    params.rl_data_burst_bytes = Some(read_non_neg_int(&val)?);
                }
                tlv::RL_OVERFLOW => {
                    if val.len() != 1 {
                        return Err(ControlParametersError::MalformedTlv);
                    }
                    params.rl_overflow = Some(val[0]);
                }
                tlv::RL_QUEUE_MAX => {
                    let v = read_non_neg_int(&val)?;
                    params.rl_queue_max =
                        Some(u32::try_from(v).map_err(|_| ControlParametersError::MalformedTlv)?);
                }
                tlv::PARTIAL_FAILURES => {
                    let mut outer = TlvReader::new(val);
                    while !outer.is_empty() {
                        let (t, v) = outer
                            .read_tlv()
                            .map_err(|_| ControlParametersError::MalformedTlv)?;
                        if t != tlv::PARTIAL_FAILURE {
                            continue;
                        }
                        let mut inner = TlvReader::new(v);
                        let mut option = String::new();
                        let mut reason = String::new();
                        while !inner.is_empty() {
                            let (t, v) = inner
                                .read_tlv()
                                .map_err(|_| ControlParametersError::MalformedTlv)?;
                            match t {
                                tlv::OPTION_NAME => {
                                    option = core::str::from_utf8(&v)
                                        .map_err(|_| ControlParametersError::InvalidUtf8)?
                                        .to_owned();
                                }
                                tlv::REFUSAL_REASON => {
                                    reason = core::str::from_utf8(&v)
                                        .map_err(|_| ControlParametersError::InvalidUtf8)?
                                        .to_owned();
                                }
                                _ => {}
                            }
                        }
                        params.partial_failures.push((option, reason));
                    }
                }
                _ => {}
            }
        }

        Ok(params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlParametersError {
    #[error("malformed TLV")]
    MalformedTlv,
    #[error("unexpected TLV type {0:#x}")]
    WrongType(u64),
    #[error("invalid NonNegativeInteger length")]
    InvalidNonNegInt,
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,
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

fn read_non_neg_int(buf: &[u8]) -> Result<u64, ControlParametersError> {
    match buf.len() {
        1 => Ok(buf[0] as u64),
        2 => Ok(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Ok(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])),
        _ => Err(ControlParametersError::InvalidNonNegInt),
    }
}

fn encode_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

fn decode_name(value: Bytes) -> Result<Name, ControlParametersError> {
    let mut r = TlvReader::new(value);
    let mut components = Vec::new();
    while !r.is_empty() {
        let (typ, val) = r
            .read_tlv()
            .map_err(|_| ControlParametersError::MalformedTlv)?;
        components.push(NameComponent { typ, value: val });
    }
    if components.is_empty() {
        Ok(Name::root())
    } else {
        Ok(Name::from_components(components))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    #[test]
    fn non_neg_int_encoding() {
        assert_eq!(encode_non_neg_int(0), vec![0]);
        assert_eq!(encode_non_neg_int(255), vec![255]);
        assert_eq!(encode_non_neg_int(256), vec![1, 0]);
        assert_eq!(encode_non_neg_int(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_non_neg_int(0x10000), vec![0, 1, 0, 0]);
        assert_eq!(
            encode_non_neg_int(0x1_0000_0000),
            vec![0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn non_neg_int_roundtrip() {
        for v in [
            0u64,
            1,
            255,
            256,
            0xFFFF,
            0x10000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let encoded = encode_non_neg_int(v);
            let decoded = read_non_neg_int(&encoded).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn encode_decode_empty() {
        let params = ControlParameters::new();
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn encode_decode_rib_register() {
        let params = ControlParameters {
            name: Some(name(&[b"ndn", b"test"])),
            face_id: Some(5),
            origin: Some(origin::APP),
            cost: Some(10),
            flags: Some(route_flags::CHILD_INHERIT),
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn encode_decode_faces_create() {
        let params = ControlParameters {
            uri: Some("shm://myapp".to_owned()),
            face_persistency: Some(0),
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn encode_decode_with_strategy() {
        let params = ControlParameters {
            name: Some(name(&[b"test"])),
            strategy: Some(name(&[b"ndn", b"strategy", b"best-route"])),
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn encode_decode_all_fields() {
        let params = ControlParameters {
            name: Some(name(&[b"hello"])),
            face_id: Some(42),
            uri: Some("udp4://192.168.1.1:6363".to_owned()),
            local_uri: Some("udp4://0.0.0.0:6363".to_owned()),
            origin: Some(origin::STATIC),
            cost: Some(100),
            flags: Some(route_flags::CHILD_INHERIT | route_flags::CAPTURE),
            mask: Some(3),
            expiration_period: Some(30_000),
            face_persistency: Some(1),
            strategy: Some(name(&[b"ndn", b"strategy", b"multicast"])),
            mtu: Some(8800),
            base_cong_interval: Some(100_000),
            def_cong_threshold: Some(64 * 1024),
            capacity: Some(1024 * 1024),
            count: Some(42),
            fec_k: Some(16),
            fec_n: Some(20),
            fec_field: Some(fec_field::GF8),
            fec_role: Some(fec_role::PRODUCED),
            rl_direction: Some(rl_direction::INBOUND),
            rl_interest_pps: Some(100),
            rl_interest_burst: Some(200),
            rl_data_bps: Some(1_000_000),
            rl_data_burst_bytes: Some(100_000),
            rl_overflow: Some(rl_overflow::NACK),
            rl_queue_max: None,
            partial_failures: vec![
                ("mtu".to_owned(), "immutable-on-shm".to_owned()),
                (
                    "flags:lp-reliability".to_owned(),
                    "transport-not-eligible".to_owned(),
                ),
            ],
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn encode_decode_partial_failures() {
        let params = ControlParameters {
            face_id: Some(42),
            partial_failures: vec![
                ("mtu".to_owned(), "udp-max-65507".to_owned()),
                ("persistency".to_owned(), "immutable-on-shm".to_owned()),
            ],
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded.face_id, Some(42));
        assert_eq!(decoded.partial_failures.len(), 2);
        assert_eq!(decoded.partial_failures[0].0, "mtu");
        assert_eq!(decoded.partial_failures[0].1, "udp-max-65507");
        assert_eq!(decoded.partial_failures[1].0, "persistency");
        assert_eq!(decoded.partial_failures[1].1, "immutable-on-shm");
    }

    #[test]
    fn encode_decode_rl_fields_round_trip() {
        let params = ControlParameters {
            name: Some(name(&[b"udp4", b"0.0.0.0:6363"])),
            face_id: Some(7),
            rl_direction: Some(rl_direction::INBOUND),
            rl_interest_pps: Some(100),
            rl_interest_burst: Some(200),
            rl_overflow: Some(rl_overflow::NACK),
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded.rl_direction, Some(rl_direction::INBOUND));
        assert_eq!(decoded.rl_interest_pps, Some(100));
        assert_eq!(decoded.rl_overflow, Some(rl_overflow::NACK));
    }

    #[test]
    fn encode_decode_fec_fields_round_trip() {
        let params = ControlParameters {
            name: Some(name(&[b"alice", b"video"])),
            fec_k: Some(16),
            fec_n: Some(20),
            fec_field: Some(fec_field::GF8),
            fec_role: Some(fec_role::PRODUCED),
            ..Default::default()
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded.fec_k, Some(16));
        assert_eq!(decoded.fec_n, Some(20));
        assert_eq!(decoded.fec_field, Some(fec_field::GF8));
        assert_eq!(decoded.fec_role, Some(fec_role::PRODUCED));
    }

    #[test]
    fn decode_value_works() {
        let params = ControlParameters {
            name: Some(name(&[b"test"])),
            cost: Some(5),
            ..Default::default()
        };
        let value = params.encode_value();
        let decoded = ControlParameters::decode_value(value).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn decode_wrong_type_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(0x05, |_| {});
        let result = ControlParameters::decode(w.finish());
        assert!(matches!(
            result,
            Err(ControlParametersError::WrongType(0x05))
        ));
    }

    #[test]
    fn decode_ignores_unknown_types() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_PARAMETERS, |w| {
            write_non_neg_int(w, tlv::COST, 10);
            w.write_tlv(0xFE, b"unknown");
            write_non_neg_int(w, tlv::FACE_ID, 3);
        });
        let decoded = ControlParameters::decode(w.finish()).unwrap();
        assert_eq!(decoded.cost, Some(10));
        assert_eq!(decoded.face_id, Some(3));
    }
}
