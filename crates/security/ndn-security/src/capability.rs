//! Capability — a simple, key-bound, time-bounded authorization grant.
//!
//! A capability authorizes a **named key** to perform a **named operation**,
//! bounded in time. It is the cheap authorization path for Tier-0 service calls
//! (see `docs/specs/service-layer.md` §5.3/§6.3): one signature to verify,
//! offline, least-privilege — reserving ABE for *confidentiality*, not access.
//!
//! # Representation
//!
//! A capability *is a signed Data*: the issuer (a `PolicyAuthority`) signs a Data
//! whose Content is the TLV payload defined here. That makes it content-addressed,
//! cacheable, and offline-verifiable — an authority's grant does not require the
//! authority to be online, only that the signed object is valid and fresh.
//!
//! # Verification is composition, not new crypto
//!
//! This module is deliberately pure: it defines the payload, its TLV codec, and
//! the [`Capability::authorizes`] predicate. Signature verification is the job of
//! the existing [`crate::validator::Validator`] (which dispatches on the NDN
//! `SignatureType`, so Ed25519 / ECDSA-P256 / RSA all work without any code here).
//! A provider authorizes a call by:
//!
//! 1. validating the capability Data's signature against a trusted issuer anchor
//!    (`Validator::validate`), then [`Capability::decode`]-ing its Content;
//! 2. validating the request Interest's signature (`Validator::validate_interest`)
//!    to obtain the **verified signer key name** — this is the proof-of-possession:
//!    the caller must hold the private key the capability names;
//! 3. calling [`Capability::authorizes`] with that signer name, the invoked
//!    service name, and the current time.
//!
//! Replay of the signed request Interest is rejected separately by the engine's
//! `ReplayGuard`. **A capability is never a bearer token:** possessing the object
//! is insufficient — step 2 requires the grantee's signing key.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

// Provisional TLV type numbers for the capability payload. Even ⇒ non-critical.
// Allocated in the 0x240 block (the SubscriptionRequest extension uses 0x230).
const TLV_CAPABILITY: u64 = 0x240;
const TLV_CAP_GRANTEE: u64 = 0x242;
const TLV_CAP_OPERATION: u64 = 0x244;
const TLV_CAP_NOT_BEFORE: u64 = 0x246;
const TLV_CAP_NOT_AFTER: u64 = 0x248;
/// NDN Name TLV type.
const TLV_NAME: u64 = 0x07;

/// Errors from the capability layer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// The encoded capability was truncated or had an unexpected structure.
    #[error("capability malformed: {0}")]
    Malformed(&'static str),
    /// The request's verified signer is not under the capability's grantee — the
    /// caller does not hold the key the capability authorizes.
    #[error("request signer is not the capability grantee")]
    NotGrantee,
    /// The invoked operation lies outside the capability's authorized prefix.
    #[error("operation is outside the capability's authorized scope")]
    OutOfScope,
    /// The capability's validity window has not started yet.
    #[error("capability is not yet valid")]
    NotYetValid,
    /// The capability's validity window has passed.
    #[error("capability has expired")]
    Expired,
}

/// A key-bound, time-bounded authorization grant. Carried as the Content of an
/// issuer-signed Data; see the module docs for the issue/verify flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// The identity (or key) name authorized to invoke. The request Interest's
    /// verified signer key name must be *under* this name (an identity may sign
    /// with any of its keys), so a key name matches exactly and an identity name
    /// matches any of its keys.
    pub grantee: Name,
    /// The service-name prefix this capability authorizes (plain prefix scope).
    pub operation: Name,
    /// Start of the validity window, in seconds (inclusive).
    pub not_before: u64,
    /// End of the validity window, in seconds (exclusive).
    pub not_after: u64,
}

impl Capability {
    /// Construct a capability grant.
    pub fn new(grantee: Name, operation: Name, not_before: u64, not_after: u64) -> Self {
        Self {
            grantee,
            operation,
            not_before,
            not_after,
        }
    }

    /// Encode the capability payload (the Content of an issuer-signed Data).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_CAPABILITY, |w| {
            // Names are written as their complete NAME TLV (type 7) inside a
            // typed envelope, mirroring the `abe` container's KgcRef pattern.
            w.write_nested(TLV_CAP_GRANTEE, |w| w.write_raw(&self.grantee.encode_to_tlv()));
            w.write_nested(TLV_CAP_OPERATION, |w| {
                w.write_raw(&self.operation.encode_to_tlv())
            });
            w.write_nested(TLV_CAP_NOT_BEFORE, |w| {
                w.write_raw(&self.not_before.to_be_bytes())
            });
            w.write_nested(TLV_CAP_NOT_AFTER, |w| w.write_raw(&self.not_after.to_be_bytes()));
        });
        w.finish()
    }

    /// Decode a capability payload (e.g. a verified Data's Content).
    pub fn decode(bytes: Bytes) -> Result<Self, CapabilityError> {
        let mut outer = TlvReader::new(bytes);
        let (typ, body) = outer
            .read_tlv()
            .map_err(|_| CapabilityError::Malformed("top-level TLV"))?;
        if typ != TLV_CAPABILITY {
            return Err(CapabilityError::Malformed("not a capability"));
        }
        let mut r = TlvReader::new(body);
        let grantee = read_name_field(&mut r, TLV_CAP_GRANTEE)?;
        let operation = read_name_field(&mut r, TLV_CAP_OPERATION)?;
        let not_before = read_u64_field(&mut r, TLV_CAP_NOT_BEFORE)?;
        let not_after = read_u64_field(&mut r, TLV_CAP_NOT_AFTER)?;
        Ok(Self {
            grantee,
            operation,
            not_before,
            not_after,
        })
    }

    /// The authorization predicate. Call **after** verifying the capability's and
    /// the request's signatures via [`crate::validator::Validator`] (this checks
    /// authorization, not signatures). `request_signer` is the request Interest's
    /// verified signer key name (the proof-of-possession); `requested_op` is the
    /// invoked service name; `now_secs` is the current time.
    pub fn authorizes(
        &self,
        request_signer: &Name,
        requested_op: &Name,
        now_secs: u64,
    ) -> Result<(), CapabilityError> {
        // The signer key must be under the grantee (identity owns its keys).
        if !request_signer.has_prefix(&self.grantee) {
            return Err(CapabilityError::NotGrantee);
        }
        // The invoked operation must fall under the authorized prefix.
        if !requested_op.has_prefix(&self.operation) {
            return Err(CapabilityError::OutOfScope);
        }
        if now_secs < self.not_before {
            return Err(CapabilityError::NotYetValid);
        }
        if now_secs >= self.not_after {
            return Err(CapabilityError::Expired);
        }
        Ok(())
    }
}

/// Read a `field`-typed envelope whose value is a complete NAME TLV.
fn read_name_field(r: &mut TlvReader, field: u64) -> Result<Name, CapabilityError> {
    let (typ, body) = r
        .read_tlv()
        .map_err(|_| CapabilityError::Malformed("name field"))?;
    if typ != field {
        return Err(CapabilityError::Malformed("unexpected field order"));
    }
    let mut nr = TlvReader::new(body);
    let (ntyp, nval) = nr
        .read_tlv()
        .map_err(|_| CapabilityError::Malformed("name TLV"))?;
    if ntyp != TLV_NAME {
        return Err(CapabilityError::Malformed("expected NAME TLV"));
    }
    Name::decode(nval).map_err(|_| CapabilityError::Malformed("name decode"))
}

/// Read a `field`-typed envelope whose value is a big-endian `u64`.
fn read_u64_field(r: &mut TlvReader, field: u64) -> Result<u64, CapabilityError> {
    let (typ, body) = r
        .read_tlv()
        .map_err(|_| CapabilityError::Malformed("u64 field"))?;
    if typ != field {
        return Err(CapabilityError::Malformed("unexpected field order"));
    }
    let arr: [u8; 8] = body
        .as_ref()
        .try_into()
        .map_err(|_| CapabilityError::Malformed("u64 length"))?;
    Ok(u64::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().expect("name")
    }

    fn sample() -> Capability {
        Capability::new(name("/muas/alice"), name("/svc/mavlink"), 100, 200)
    }

    #[test]
    fn encode_decode_round_trips() {
        let cap = sample();
        let decoded = Capability::decode(cap.encode()).expect("decode");
        assert_eq!(decoded, cap);
    }

    #[test]
    fn authorizes_matching_request() {
        let cap = sample();
        // Signer key under the grantee identity, op under the authorized prefix,
        // time inside the window.
        assert_eq!(
            cap.authorizes(&name("/muas/alice/KEY/k1"), &name("/svc/mavlink/execute"), 150),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_grantee() {
        let cap = sample();
        assert_eq!(
            cap.authorizes(&name("/muas/bob/KEY/k1"), &name("/svc/mavlink/execute"), 150),
            Err(CapabilityError::NotGrantee)
        );
    }

    #[test]
    fn rejects_out_of_scope_operation() {
        let cap = sample();
        assert_eq!(
            cap.authorizes(&name("/muas/alice/KEY/k1"), &name("/svc/camera/capture"), 150),
            Err(CapabilityError::OutOfScope)
        );
    }

    #[test]
    fn rejects_before_and_after_window() {
        let cap = sample();
        let signer = name("/muas/alice/KEY/k1");
        let op = name("/svc/mavlink/execute");
        assert_eq!(cap.authorizes(&signer, &op, 99), Err(CapabilityError::NotYetValid));
        // not_after is exclusive: exactly at not_after is expired.
        assert_eq!(cap.authorizes(&signer, &op, 200), Err(CapabilityError::Expired));
        assert_eq!(cap.authorizes(&signer, &op, 199), Ok(()));
    }

    #[test]
    fn grantee_may_be_an_exact_key_name() {
        // When grantee is a full key name, only that exact key matches.
        let cap = Capability::new(name("/muas/alice/KEY/k1"), name("/svc"), 0, 10);
        assert_eq!(cap.authorizes(&name("/muas/alice/KEY/k1"), &name("/svc/x"), 5), Ok(()));
        assert_eq!(
            cap.authorizes(&name("/muas/alice/KEY/k2"), &name("/svc/x"), 5),
            Err(CapabilityError::NotGrantee)
        );
    }

    #[test]
    fn decode_rejects_wrong_top_type() {
        // A NAME TLV is not a capability payload.
        let bogus = name("/not/a/capability").encode_to_tlv();
        assert_eq!(
            Capability::decode(bogus),
            Err(CapabilityError::Malformed("not a capability"))
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut bytes = sample().encode().to_vec();
        bytes.truncate(bytes.len() - 4);
        assert!(Capability::decode(Bytes::from(bytes)).is_err());
    }
}
