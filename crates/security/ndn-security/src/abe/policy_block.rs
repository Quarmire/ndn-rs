//! `PolicyBlockPayload` — a published descriptor that names the policy and the
//! KGC(s) required to encrypt under it.
//!
//! A producer creates one `PolicyBlockPayload`, encodes it, and publishes it as
//! named Data; protected content then references that payload's name + hash so
//! a consumer can discover which policy and KGC(s) govern access.
//!
//! Wire layout (ABE_POLICY_BLOCK_TYPE = 276):
//!   ABE_POLICY_BLOCK_TYPE(276) {
//!     schema_version: u16 big-endian (2 raw bytes)
//!     ABE_SCHEME_ID_TYPE(262)    { u8 disc }
//!     ABE_POLICY_SOURCE_TYPE(264){ utf-8 bytes }
//!     ABE_KGC_REFS_TYPE(266) {
//!       ABE_KGC_REF_TYPE(268)* {
//!         [Name TLV (type 7) raw]
//!         ABE_MASTER_PARAMS_HASH_TYPE(272){ 32 bytes }
//!       }
//!     }
//!   }

use bytes::Bytes;
use ndn_foundation_types::{Hash, TlvCodecError, TlvDecode, TlvEncode};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::abe::AbeSchemeId;
use crate::abe::ciphertext::{KgcRef, read_name};
use crate::abe::types::*;

/// Current schema version for `PolicyBlockPayload` encoding.
pub const POLICY_BLOCK_SCHEMA_VERSION: u16 = 1;

/// Published descriptor naming the policy and the KGC(s) required to encrypt
/// under it. Protected content references this by name + content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBlockPayload {
    /// Schema version; must equal [`POLICY_BLOCK_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// ABE scheme that must be used for encryption under this policy.
    pub scheme: AbeSchemeId,
    /// Canonical policy expression string (e.g. `"role:doctor AND dept:cardiology"`).
    pub policy_source: String,
    /// KGC(s) whose master params are required to encrypt under this policy.
    pub kgc_refs: Vec<KgcRef>,
}

impl PolicyBlockPayload {
    /// Encode to bytes for storage as a Data payload.
    pub fn encode(&self) -> Bytes {
        self.encode_to_bytes()
    }

    /// Decode from Data payload bytes.
    pub fn decode(bytes: Bytes) -> Result<Self, TlvCodecError> {
        Self::decode_from_bytes(bytes)
    }
}

impl TlvEncode for PolicyBlockPayload {
    const TYPE: u64 = ABE_POLICY_BLOCK_TYPE;

    fn write_value(&self, w: &mut TlvWriter) {
        w.write_raw(&self.schema_version.to_be_bytes());

        w.write_nested(ABE_SCHEME_ID_TYPE, |inner: &mut TlvWriter| {
            inner.write_raw(&[self.scheme.wire_disc()]);
        });

        w.write_nested(ABE_POLICY_SOURCE_TYPE, |inner: &mut TlvWriter| {
            inner.write_raw(self.policy_source.as_bytes());
        });

        w.write_nested(ABE_KGC_REFS_TYPE, |inner: &mut TlvWriter| {
            for kref in &self.kgc_refs {
                inner.write_nested(ABE_KGC_REF_TYPE, |kw: &mut TlvWriter| {
                    kw.write_raw(&kref.kgc_did.encode_to_tlv());
                    kw.write_nested(ABE_MASTER_PARAMS_HASH_TYPE, |hw: &mut TlvWriter| {
                        hw.write_raw(&kref.master_params_hash.0);
                    });
                });
            }
        });
    }
}

impl TlvDecode for PolicyBlockPayload {
    const TYPE: u64 = ABE_POLICY_BLOCK_TYPE;

    fn decode_value(r: &mut TlvReader) -> Result<Self, TlvCodecError> {
        // schema_version: raw 2 bytes
        let sv = r.read_bytes(2)?;
        let schema_version = u16::from_be_bytes([sv[0], sv[1]]);

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

            let kgc_did = read_name(&mut ref_r)?;

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

        Ok(PolicyBlockPayload {
            schema_version,
            scheme,
            policy_source,
            kgc_refs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(p: PolicyBlockPayload) -> PolicyBlockPayload {
        let bytes = p.encode_to_bytes();
        PolicyBlockPayload::decode_from_bytes(bytes).unwrap()
    }

    #[test]
    fn policy_block_payload_round_trips_bsw() {
        let payload = PolicyBlockPayload {
            schema_version: POLICY_BLOCK_SCHEMA_VERSION,
            scheme: AbeSchemeId::BSW,
            policy_source: "role:doctor".to_string(),
            kgc_refs: vec![KgcRef {
                kgc_did: "/hospital/kgc".parse().unwrap(),
                master_params_hash: Hash::of(b"params-hash"),
            }],
        };
        assert_eq!(payload, round_trip(payload.clone()));
    }

    #[test]
    fn policy_block_payload_round_trips_aw11_no_refs() {
        let payload = PolicyBlockPayload {
            schema_version: POLICY_BLOCK_SCHEMA_VERSION,
            scheme: AbeSchemeId::LewkoWaters,
            policy_source: "role:doctor AND dept:cardiology".to_string(),
            kgc_refs: vec![],
        };
        assert_eq!(payload, round_trip(payload.clone()));
    }

    #[test]
    fn policy_block_payload_round_trips_multi_kgc_refs() {
        let payload = PolicyBlockPayload {
            schema_version: POLICY_BLOCK_SCHEMA_VERSION,
            scheme: AbeSchemeId::LewkoWaters,
            policy_source: "ROLE:DOCTOR and DEPT:CARDIOLOGY".to_string(),
            kgc_refs: vec![
                KgcRef {
                    kgc_did: "/hospital/kgc-1".parse().unwrap(),
                    master_params_hash: Hash::of(b"kgc1"),
                },
                KgcRef {
                    kgc_did: "/licensing/kgc-2".parse().unwrap(),
                    master_params_hash: Hash::of(b"kgc2"),
                },
            ],
        };
        assert_eq!(payload, round_trip(payload.clone()));
    }
}
