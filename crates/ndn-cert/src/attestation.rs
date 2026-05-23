//! Challenge attestations — structured evidence of *how* an NDNCERT
//! challenge was satisfied, embedded in the issued certificate.
//!
//! ## Wire placement
//!
//! Attestations ride in the cert's `SignatureInfo` →
//! `AdditionalDescription` (TLV `0x0102`), the same non-critical extension
//! point ndn-cxx uses for cert metadata. A single `DescriptionEntry`
//! (`0x0200`) carries the set:
//!
//! ```text
//! AdditionalDescription 0x0102
//!   DescriptionEntry 0x0200
//!     DescriptionKey   0x0201  "ndn.challenge-attestations"
//!     DescriptionValue 0x0202  <canonical JSON of AttestationSet>
//! ```
//!
//! Because the element is non-critical and even-typed, NDN verifiers that
//! don't recognise it skip it cleanly; `ndnsec cert-dump` renders the entry
//! as readable text. The bytes fall inside the cert's signed region, so the
//! CA's signature covers them — there is no separate per-attestation
//! signature in this version (see [`ChallengeAttestation::signature`]).
//!
//! ## Why JSON in the value
//!
//! `DescriptionValue` is a text element. The attestation shape carries a
//! nested per-kind `evidence` map that flat key/value entries can't
//! represent, so the value is a canonical JSON document. Multi-challenge
//! compositions encode as an ordered `leaves` array with a `combinator`
//! tag, so the satisfied-leaf order and the AND/OR shape both survive.

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_packet::tlv_type;
use ndn_security::Certificate;
use ndn_tlv::{TlvReader, TlvWriter};
use serde::{Deserialize, Serialize};

/// `DescriptionKey` under which the [`AttestationSet`] JSON is stored.
pub const ATTESTATION_DESCRIPTION_KEY: &str = "ndn.challenge-attestations";

/// How the leaves of an [`AttestationSet`] combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Combinator {
    /// One challenge satisfied the request (the common case).
    Single,
    /// Every leaf was satisfied (an `all-of` composition).
    AllOf,
    /// One leaf of several satisfied the request (an `any-of` composition).
    AnyOf,
    /// `required` of `total` leaves satisfied the request (a `nofm`
    /// composition). The `leaves` carry the `required` that were satisfied.
    NofM { required: usize, total: usize },
}

/// Evidence about a single satisfied challenge leaf.
///
/// `kind` is the challenge type (`"token"`, `"device-approval"`, …);
/// `evidence` is kind-specific (e.g. the device-approval request id). The
/// `performed_at` timestamp is stamped by the CA at issuance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChallengeAttestation {
    pub kind: String,
    /// Unix seconds when the CA recorded the attestation. `0` until the
    /// CA stamps it via [`AttestationSet::stamp`].
    #[serde(default)]
    pub performed_at: u64,
    /// The CA component (e.g. challenge handler) that ran this leaf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_version: Option<String>,
    /// Kind-specific evidence (e.g. `{"request_id": "req-3"}`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: BTreeMap<String, serde_json::Value>,
    /// Reserved for cross-process attestations signed independently by the
    /// handler (e.g. an approving device's key). Unset for CA-covered
    /// attestations, which rely on the CA's signature over the whole cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ChallengeAttestation {
    /// A bare leaf naming the challenge `kind`, with no evidence.
    pub fn of_kind(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            performed_at: 0,
            handler_name: None,
            handler_version: None,
            evidence: BTreeMap::new(),
            signature: None,
        }
    }

    /// Attach one kind-specific evidence field (builder style).
    pub fn with_evidence(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.evidence.insert(key.into(), value);
        self
    }
}

/// An ordered set of challenge attestations plus the combinator that ties
/// them together. This is the unit embedded in an issued cert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationSet {
    pub combinator: Combinator,
    pub leaves: Vec<ChallengeAttestation>,
}

impl AttestationSet {
    /// A single-challenge set ([`Combinator::Single`]).
    pub fn single(leaf: ChallengeAttestation) -> Self {
        Self {
            combinator: Combinator::Single,
            leaves: vec![leaf],
        }
    }

    pub fn new(combinator: Combinator, leaves: Vec<ChallengeAttestation>) -> Self {
        Self { combinator, leaves }
    }

    /// Stamp `performed_at = ts` on every leaf that hasn't been stamped yet.
    pub fn stamp(&mut self, ts: u64) {
        for leaf in &mut self.leaves {
            if leaf.performed_at == 0 {
                leaf.performed_at = ts;
            }
        }
    }

    /// Encode the **value** of the `AdditionalDescription` (0x0102) TLV —
    /// the concatenated `DescriptionEntry` elements — ready to hand to
    /// [`ndn_security::SecurityManager::certify_with_additional_description`].
    /// Returns `None` only if the set serialises to invalid JSON, which
    /// cannot happen for the owned types here.
    pub fn encode_additional_description(&self) -> Option<Vec<u8>> {
        let json = serde_json::to_vec(self).ok()?;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DESCRIPTION_ENTRY, |w| {
            w.write_tlv(
                tlv_type::DESCRIPTION_KEY,
                ATTESTATION_DESCRIPTION_KEY.as_bytes(),
            );
            w.write_tlv(tlv_type::DESCRIPTION_VALUE, &json);
        });
        Some(w.finish().to_vec())
    }

    /// Parse the attestation set out of a decoded certificate, if present.
    /// Returns `None` for certs without attestations (the common case) and
    /// for any malformed/foreign `AdditionalDescription`.
    pub fn from_cert(cert: &Certificate) -> Option<AttestationSet> {
        let signed_region = cert.signed_region.as_ref()?;
        Self::from_signed_region(signed_region)
    }

    /// As [`from_cert`](Self::from_cert), but over the raw signed-region
    /// bytes (the inner TLVs of the cert's `Data`: Name, MetaInfo, Content,
    /// SignatureInfo).
    pub fn from_signed_region(signed_region: &[u8]) -> Option<AttestationSet> {
        let value = find_description_value(signed_region, ATTESTATION_DESCRIPTION_KEY)?;
        serde_json::from_slice(&value).ok()
    }
}

/// Walk `signed_region` → `SignatureInfo` → `AdditionalDescription` and
/// return the `DescriptionValue` of the entry whose `DescriptionKey` matches
/// `key`.
fn find_description_value(signed_region: &[u8], key: &str) -> Option<Bytes> {
    let mut reader = TlvReader::new(Bytes::copy_from_slice(signed_region));
    while !reader.is_empty() {
        let (typ, val) = reader.read_tlv().ok()?;
        if typ != tlv_type::SIGNATURE_INFO {
            continue;
        }
        let mut si = TlvReader::new(val);
        while !si.is_empty() {
            let (stype, sval) = si.read_tlv().ok()?;
            if stype != tlv_type::ADDITIONAL_DESCRIPTION {
                continue;
            }
            let mut ad = TlvReader::new(sval);
            while !ad.is_empty() {
                let (etype, eval) = ad.read_tlv().ok()?;
                if etype != tlv_type::DESCRIPTION_ENTRY {
                    continue;
                }
                if let Some(v) = entry_value_if_key(eval, key) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Given the value of one `DescriptionEntry`, return its `DescriptionValue`
/// iff its `DescriptionKey` equals `key`.
fn entry_value_if_key(entry: Bytes, key: &str) -> Option<Bytes> {
    let mut e = TlvReader::new(entry);
    let mut found_key = false;
    let mut value: Option<Bytes> = None;
    while !e.is_empty() {
        let (t, v) = e.read_tlv().ok()?;
        match t {
            t if t == tlv_type::DESCRIPTION_KEY => found_key = v.as_ref() == key.as_bytes(),
            t if t == tlv_type::DESCRIPTION_VALUE => value = Some(v),
            _ => {}
        }
    }
    if found_key { value } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_set() -> AttestationSet {
        let mut set = AttestationSet::single(
            ChallengeAttestation::of_kind("device-approval")
                .with_evidence("request_id", serde_json::json!("req-3")),
        );
        set.stamp(1_700_000_000);
        set
    }

    #[test]
    fn json_round_trips() {
        let set = sample_set();
        let json = serde_json::to_string(&set).unwrap();
        let back: AttestationSet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn stamp_only_fills_unset_leaves() {
        let mut set = AttestationSet::new(
            Combinator::AllOf,
            vec![
                ChallengeAttestation {
                    performed_at: 42,
                    ..ChallengeAttestation::of_kind("token")
                },
                ChallengeAttestation::of_kind("email"),
            ],
        );
        set.stamp(999);
        assert_eq!(set.leaves[0].performed_at, 42, "pre-stamped leaf untouched");
        assert_eq!(set.leaves[1].performed_at, 999);
    }

    /// Encode an attestation set into an AdditionalDescription, wrap it in a
    /// minimal SignatureInfo-bearing signed region, and parse it back.
    #[test]
    fn additional_description_round_trips_through_signed_region() {
        let set = sample_set();
        let ad = set.encode_additional_description().unwrap();

        // Minimal signed region: just a SignatureInfo carrying the AD.
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5u8]);
            w.write_tlv(tlv_type::ADDITIONAL_DESCRIPTION, &ad);
        });
        let signed_region = w.finish();

        let parsed = AttestationSet::from_signed_region(&signed_region)
            .expect("attestation set should parse out of the signed region");
        assert_eq!(parsed, set);
    }

    #[test]
    fn absent_attestation_parses_as_none() {
        // SignatureInfo with no AdditionalDescription.
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5u8]);
        });
        let signed_region = w.finish();
        assert!(AttestationSet::from_signed_region(&signed_region).is_none());
    }

    #[test]
    fn foreign_description_key_is_ignored() {
        // An AdditionalDescription whose only entry uses a different key.
        let mut entries = TlvWriter::new();
        entries.write_nested(tlv_type::DESCRIPTION_ENTRY, |w| {
            w.write_tlv(tlv_type::DESCRIPTION_KEY, b"some.other.key");
            w.write_tlv(tlv_type::DESCRIPTION_VALUE, b"hello");
        });
        let ad = entries.finish();

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::ADDITIONAL_DESCRIPTION, &ad);
        });
        let signed_region = w.finish();
        assert!(AttestationSet::from_signed_region(&signed_region).is_none());
    }
}
