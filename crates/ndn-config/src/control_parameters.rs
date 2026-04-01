/// NFD Management ControlParameters TLV encoding and decoding.
///
/// ControlParameters (TLV type 0x68) carries the arguments for NFD management
/// commands. All fields are optional; which fields are required depends on the
/// specific command (e.g. `rib/register` requires Name).
///
/// Wire format follows the NFD Management Protocol specification:
/// <https://redmine.named-data.net/projects/nfd/wiki/ControlCommand>
///
/// # NonNegativeInteger encoding
///
/// Integer-valued fields use the NDN NonNegativeInteger encoding: the shortest
/// big-endian representation that fits the value (1, 2, 4, or 8 bytes).
use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_tlv::{TlvReader, TlvWriter};

// ─── TLV type constants ──────────────────────────────────────────────────────

pub mod tlv {
    pub const CONTROL_PARAMETERS: u64 = 0x68;
    pub const FACE_ID:            u64 = 0x69;
    pub const COST:               u64 = 0x6A;
    pub const STRATEGY:           u64 = 0x6B;
    pub const FLAGS:              u64 = 0x6C;
    pub const EXPIRATION_PERIOD:  u64 = 0x6D;
    pub const ORIGIN:             u64 = 0x6F;
    pub const MASK:               u64 = 0x70;
    pub const URI:                u64 = 0x72;
    pub const LOCAL_URI:          u64 = 0x81;
    pub const CAPACITY:           u64 = 0x83;
    pub const FACE_PERSISTENCY:   u64 = 0x85;
    pub const BASE_CONG_INTERVAL: u64 = 0x87;
    pub const DEF_CONG_THRESHOLD: u64 = 0x88;
    pub const MTU:                u64 = 0x89;

    // Standard NDN Name type.
    pub const NAME:               u64 = 0x07;
    pub const NAME_COMPONENT:     u64 = 0x08;
}

/// Route origin values (NFD RIB management).
pub mod origin {
    pub const APP:        u64 = 0;
    pub const AUTOREG:    u64 = 64;
    pub const CLIENT:     u64 = 65;
    pub const AUTOCONF:   u64 = 66;
    pub const NLSR:       u64 = 128;
    pub const PREFIX_ANN: u64 = 129;
    pub const STATIC:     u64 = 255;
}

/// Route flags (NFD RIB management).
pub mod route_flags {
    pub const CHILD_INHERIT: u64 = 1;
    pub const CAPTURE:       u64 = 2;
}

// ─── ControlParameters ───────────────────────────────────────────────────────

/// NFD ControlParameters — all fields optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlParameters {
    pub name:               Option<Name>,
    pub face_id:            Option<u64>,
    pub uri:                Option<String>,
    pub local_uri:          Option<String>,
    pub origin:             Option<u64>,
    pub cost:               Option<u64>,
    pub flags:              Option<u64>,
    pub mask:               Option<u64>,
    pub expiration_period:  Option<u64>,
    pub face_persistency:   Option<u64>,
    pub strategy:           Option<Name>,
    pub mtu:                Option<u64>,
}

impl ControlParameters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode to wire format as a complete ControlParameters TLV (type 0x68).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_PARAMETERS, |w| {
            self.encode_inner(w);
        });
        w.finish()
    }

    /// Encode the inner fields (without the outer 0x68 wrapper).
    /// Useful for embedding in a name component.
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
    }

    /// Decode from a complete ControlParameters TLV (type 0x68).
    pub fn decode(wire: Bytes) -> Result<Self, ControlParametersError> {
        let mut r = TlvReader::new(wire);
        let (typ, value) = r.read_tlv()
            .map_err(|_| ControlParametersError::MalformedTlv)?;
        if typ != tlv::CONTROL_PARAMETERS {
            return Err(ControlParametersError::WrongType(typ));
        }
        Self::decode_value(value)
    }

    /// Decode from the inner value bytes (without the outer 0x68 wrapper).
    pub fn decode_value(value: Bytes) -> Result<Self, ControlParametersError> {
        let mut r = TlvReader::new(value);
        let mut params = ControlParameters::default();

        while !r.is_empty() {
            let (typ, val) = r.read_tlv()
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
                        std::str::from_utf8(&val)
                            .map_err(|_| ControlParametersError::InvalidUtf8)?
                            .to_owned(),
                    );
                }
                tlv::LOCAL_URI => {
                    params.local_uri = Some(
                        std::str::from_utf8(&val)
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
                    let (t, v) = inner.read_tlv()
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
                // Unknown non-critical types are silently skipped.
                _ => {}
            }
        }

        Ok(params)
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

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
fn read_non_neg_int(buf: &[u8]) -> Result<u64, ControlParametersError> {
    match buf.len() {
        1 => Ok(buf[0] as u64),
        2 => Ok(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Ok(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ])),
        _ => Err(ControlParametersError::InvalidNonNegInt),
    }
}

// ─── Name helpers ────────────────────────────────────────────────────────────

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
        let (typ, val) = r.read_tlv()
            .map_err(|_| ControlParametersError::MalformedTlv)?;
        components.push(NameComponent { typ, value: val });
    }
    if components.is_empty() {
        Ok(Name::root())
    } else {
        Ok(Name::from_components(components))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components.iter().map(|c| NameComponent::generic(Bytes::copy_from_slice(c)))
        )
    }

    #[test]
    fn non_neg_int_encoding() {
        assert_eq!(encode_non_neg_int(0), vec![0]);
        assert_eq!(encode_non_neg_int(255), vec![255]);
        assert_eq!(encode_non_neg_int(256), vec![1, 0]);
        assert_eq!(encode_non_neg_int(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_non_neg_int(0x10000), vec![0, 1, 0, 0]);
        assert_eq!(encode_non_neg_int(0x1_0000_0000), vec![0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn non_neg_int_roundtrip() {
        for v in [0u64, 1, 255, 256, 0xFFFF, 0x10000, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX] {
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
            face_persistency: Some(0), // persistent
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
        };
        let wire = params.encode();
        let decoded = ControlParameters::decode(wire).unwrap();
        assert_eq!(decoded, params);
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
        // Build a TLV with type 0x05 (Interest) instead of 0x68
        let mut w = TlvWriter::new();
        w.write_nested(0x05, |_| {});
        let result = ControlParameters::decode(w.finish());
        assert!(matches!(result, Err(ControlParametersError::WrongType(0x05))));
    }

    #[test]
    fn decode_ignores_unknown_types() {
        // Build ControlParameters with an unknown even-typed field
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_PARAMETERS, |w| {
            write_non_neg_int(w, tlv::COST, 10);
            w.write_tlv(0xFE, b"unknown"); // unknown non-critical
            write_non_neg_int(w, tlv::FACE_ID, 3);
        });
        let decoded = ControlParameters::decode(w.finish()).unwrap();
        assert_eq!(decoded.cost, Some(10));
        assert_eq!(decoded.face_id, Some(3));
    }
}
