//! `AbeCiphertext` — versioned NDN-TLV wire-format container for ABE ciphertext.
//!
//! The container carries the scheme-produced ciphertext blob together with the
//! policy string and the KGC reference(s) a consumer needs to locate its
//! attribute keys. It can be placed in the Content of a signable Data packet.
//!
//! Wire layout (ascending type numbers, all even = non-critical extensions):
//!   ABE_CIPHERTEXT_TYPE(260) {
//!     schema_version: u16 big-endian (2 raw bytes, no inner T-L wrapper)
//!     ABE_SCHEME_ID_TYPE(262)    { u8 disc }
//!     ABE_POLICY_SOURCE_TYPE(264){ utf-8 bytes }
//!     ABE_KGC_REFS_TYPE(266) {
//!       ABE_KGC_REF_TYPE(268)* {
//!         [Name TLV (type 7) — kgc_did, written raw]
//!         ABE_MASTER_PARAMS_HASH_TYPE(272){ 32 bytes }
//!       }
//!     }
//!     ABE_CIPHERTEXT_BLOB_TYPE(274) { rabe ciphertext bytes }
//!   }

use bytes::Bytes;
use ndn_foundation_types::{Hash, Name, TlvCodecError, TlvDecode, TlvEncode, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::AbeSchemeId;
use crate::types::*;

/// Current schema version for `AbeCiphertext` encoding.
pub const CIPHERTEXT_SCHEMA_VERSION: u16 = 1;

/// Versioned TLV container for an ABE ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbeCiphertext {
    /// Schema version. Must equal [`CIPHERTEXT_SCHEMA_VERSION`] to decode.
    pub schema_version: u16,
    /// The ABE scheme that produced this ciphertext.
    pub scheme: AbeSchemeId,
    /// The policy expression string (canonical form).
    pub policy_source: String,
    /// KGC references. Empty for inline single-authority tests.
    pub kgc_refs: Vec<KgcRef>,
    /// bincode-serialized rabe ciphertext (`CpAbeCiphertext` or `Aw11Ciphertext`).
    pub rabe_ciphertext_bytes: Bytes,
}

/// Reference to a KGC and its master parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KgcRef {
    /// KGC identity (an NDN Name).
    pub kgc_did: Name,
    /// SHA-256 hash of the KGC's published master-params payload.
    pub master_params_hash: Hash,
}

/// Read a complete NAME TLV (type 7) from `r`, leaving the reader positioned
/// after it. The Name is written raw (its own T-L-V) inside a KgcRef envelope.
pub(crate) fn read_name(r: &mut TlvReader) -> Result<Name, TlvCodecError> {
    let typ = r.read_type()?;
    if typ != tlv_type::NAME {
        return Err(TlvCodecError::UnexpectedType {
            expected: tlv_type::NAME,
            found: typ,
        });
    }
    let len = r.read_length()?;
    let inner = r.read_bytes(len)?;
    Name::decode(inner).map_err(|_| TlvCodecError::MalformedField(tlv_type::NAME))
}

impl AbeSchemeId {
    pub(crate) const fn wire_disc(self) -> u8 {
        match self {
            AbeSchemeId::BSW => 1,
            AbeSchemeId::LewkoWaters => 2,
        }
    }
    pub(crate) const fn from_wire_disc(b: u8) -> Option<Self> {
        match b {
            1 => Some(AbeSchemeId::BSW),
            2 => Some(AbeSchemeId::LewkoWaters),
            _ => None,
        }
    }
}

impl TlvEncode for AbeCiphertext {
    const TYPE: u64 = ABE_CIPHERTEXT_TYPE;

    fn write_value(&self, w: &mut TlvWriter) {
        // schema_version: raw 2 bytes, no inner TLV wrapper
        w.write_raw(&self.schema_version.to_be_bytes());

        // scheme_id
        w.write_nested(ABE_SCHEME_ID_TYPE, |inner: &mut TlvWriter| {
            inner.write_raw(&[self.scheme.wire_disc()]);
        });

        // policy_source
        w.write_nested(ABE_POLICY_SOURCE_TYPE, |inner: &mut TlvWriter| {
            inner.write_raw(self.policy_source.as_bytes());
        });

        // kgc_refs
        w.write_nested(ABE_KGC_REFS_TYPE, |refs_w: &mut TlvWriter| {
            for kgc_ref in &self.kgc_refs {
                refs_w.write_nested(ABE_KGC_REF_TYPE, |ref_w: &mut TlvWriter| {
                    // kgc_did: raw Name TLV bytes (type 7), no extra wrapper
                    let name_bytes = kgc_ref.kgc_did.encode_to_tlv();
                    ref_w.write_raw(&name_bytes);
                    // master_params_hash
                    ref_w.write_nested(ABE_MASTER_PARAMS_HASH_TYPE, |hw: &mut TlvWriter| {
                        hw.write_raw(&kgc_ref.master_params_hash.0);
                    });
                });
            }
        });

        // rabe ciphertext blob
        w.write_nested(ABE_CIPHERTEXT_BLOB_TYPE, |bw: &mut TlvWriter| {
            bw.write_raw(&self.rabe_ciphertext_bytes);
        });
    }
}

impl TlvDecode for AbeCiphertext {
    const TYPE: u64 = ABE_CIPHERTEXT_TYPE;

    fn decode_value(r: &mut TlvReader) -> Result<Self, TlvCodecError> {
        // schema_version: raw 2 bytes (no inner T-L)
        let sv = r.read_bytes(2)?;
        let schema_version = u16::from_be_bytes([sv[0], sv[1]]);
        if schema_version != CIPHERTEXT_SCHEMA_VERSION {
            return Err(TlvCodecError::UnrecognizedVariant(schema_version as u8));
        }

        // scheme_id
        let typ = r.read_type()?;
        if typ != ABE_SCHEME_ID_TYPE {
            return Err(TlvCodecError::UnexpectedType {
                expected: ABE_SCHEME_ID_TYPE,
                found: typ,
            });
        }
        let len = r.read_length()?;
        let disc_bytes = r.read_bytes(len)?;
        let scheme = AbeSchemeId::from_wire_disc(disc_bytes[0])
            .ok_or(TlvCodecError::UnrecognizedVariant(disc_bytes[0]))?;

        // policy_source
        let typ = r.read_type()?;
        if typ != ABE_POLICY_SOURCE_TYPE {
            return Err(TlvCodecError::UnexpectedType {
                expected: ABE_POLICY_SOURCE_TYPE,
                found: typ,
            });
        }
        let len = r.read_length()?;
        let policy_bytes = r.read_bytes(len)?;
        let policy_source = String::from_utf8(policy_bytes.to_vec())
            .map_err(|_| TlvCodecError::MalformedField(ABE_POLICY_SOURCE_TYPE))?;

        // kgc_refs
        let typ = r.read_type()?;
        if typ != ABE_KGC_REFS_TYPE {
            return Err(TlvCodecError::UnexpectedType {
                expected: ABE_KGC_REFS_TYPE,
                found: typ,
            });
        }
        let refs_len = r.read_length()?;
        let mut refs_r = r.scoped(refs_len)?;
        let mut kgc_refs = Vec::new();
        while !refs_r.is_empty() {
            let typ = refs_r.read_type()?;
            if typ != ABE_KGC_REF_TYPE {
                return Err(TlvCodecError::UnexpectedType {
                    expected: ABE_KGC_REF_TYPE,
                    found: typ,
                });
            }
            let ref_len = refs_r.read_length()?;
            let mut ref_r = refs_r.scoped(ref_len)?;

            // kgc_did: raw Name TLV (type 7 is next)
            let kgc_did = read_name(&mut ref_r)?;

            // master_params_hash
            let typ = ref_r.read_type()?;
            if typ != ABE_MASTER_PARAMS_HASH_TYPE {
                return Err(TlvCodecError::UnexpectedType {
                    expected: ABE_MASTER_PARAMS_HASH_TYPE,
                    found: typ,
                });
            }
            let hlen = ref_r.read_length()?;
            let hbytes = ref_r.read_bytes(hlen)?;
            if hbytes.len() != 32 {
                return Err(TlvCodecError::MalformedField(ABE_MASTER_PARAMS_HASH_TYPE));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hbytes);
            kgc_refs.push(KgcRef {
                kgc_did,
                master_params_hash: Hash::from_bytes(arr),
            });
        }

        // rabe ciphertext blob
        let typ = r.read_type()?;
        if typ != ABE_CIPHERTEXT_BLOB_TYPE {
            return Err(TlvCodecError::UnexpectedType {
                expected: ABE_CIPHERTEXT_BLOB_TYPE,
                found: typ,
            });
        }
        let blob_len = r.read_length()?;
        let rabe_ciphertext_bytes = r.read_bytes(blob_len)?;

        Ok(AbeCiphertext {
            schema_version,
            scheme,
            policy_source,
            kgc_refs,
            rabe_ciphertext_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ct(scheme: AbeSchemeId) -> AbeCiphertext {
        AbeCiphertext {
            schema_version: CIPHERTEXT_SCHEMA_VERSION,
            scheme,
            policy_source: "role:doctor AND dept:cardiology".into(),
            kgc_refs: vec![KgcRef {
                kgc_did: "/hospital/kgc".parse().unwrap(),
                master_params_hash: Hash::of(b"params"),
            }],
            rabe_ciphertext_bytes: Bytes::from_static(b"fake_rabe_bytes"),
        }
    }

    fn round_trip(ct: AbeCiphertext) -> AbeCiphertext {
        let encoded = ct.encode_to_bytes();
        AbeCiphertext::decode_from_bytes(encoded).unwrap()
    }

    #[test]
    fn ciphertext_tlv_round_trip_bsw() {
        let ct = sample_ct(AbeSchemeId::BSW);
        assert_eq!(ct, round_trip(ct.clone()));
    }

    #[test]
    fn ciphertext_tlv_round_trip_lewko_waters() {
        let ct = sample_ct(AbeSchemeId::LewkoWaters);
        assert_eq!(ct, round_trip(ct.clone()));
    }

    #[test]
    fn ciphertext_tlv_round_trip_no_kgc_refs() {
        let ct = AbeCiphertext {
            schema_version: CIPHERTEXT_SCHEMA_VERSION,
            scheme: AbeSchemeId::BSW,
            policy_source: "x:y".into(),
            kgc_refs: vec![],
            rabe_ciphertext_bytes: Bytes::from_static(b"blob"),
        };
        assert_eq!(ct, round_trip(ct.clone()));
    }

    #[test]
    fn ciphertext_unknown_schema_version_returns_error() {
        let mut ct = sample_ct(AbeSchemeId::BSW);
        ct.schema_version = 999;
        let encoded = ct.encode_to_bytes();
        assert!(AbeCiphertext::decode_from_bytes(encoded).is_err());
    }
}
