//! NDN Certificate Format v2 naming
//! (<https://docs.named-data.net/NDN-packet-spec/current/certificate.html>).
//!
//! A key is named `/<identity>/KEY/<key-id>`; each certificate of that key is
//! `/<identity>/KEY/<key-id>/<issuer-id>/<version>`. A key can hold several
//! certificates at once (a renewal issues a new one under a new name while the
//! old stays valid), so a signer's KeyLocator names the *key* and a verifier
//! resolves it to the newest currently valid certificate under that prefix.
//! A KeyLocator may also name one certificate exactly (other stacks do).
//!
//! Issuer ids follow ndn-cxx: `self` for self-signed certificates, `NDNCERT`
//! for certificates an NDNCERT CA issues, `NA` when no issuer id is given.
//! The version is a version component holding the issuance time in
//! milliseconds since the Unix epoch, kept strictly increasing within a
//! process so two certificates of one key never share a name.
//!
//! Earlier ndn-rs releases named some certificates after their key (no issuer
//! or version). Such *legacy key-named* certificates are still read and
//! validated: a certificate name without the four-component tail is its own
//! key name ([`key_name_of`]), so prefix lookups by key name find both forms.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};

/// The `KEY` component separating an identity from its key id.
pub const KEY_COMPONENT: &str = "KEY";
/// Issuer id of a self-signed certificate.
pub const SELF_ISSUER: &str = "self";
/// Issuer id of a certificate issued by an NDNCERT CA (ndn-cxx `ndncert`).
pub const NDNCERT_ISSUER: &str = "NDNCERT";
/// Issuer id when none is chosen (ndn-cxx `MakeCertificateOptions` default).
pub const DEFAULT_ISSUER: &str = "NA";

/// Whether `c` is the GenericNameComponent `KEY` (TLV-TYPE 8, value `KEY`),
/// as ndn-cxx compares it: a typed component that happens to hold the bytes
/// `KEY` (e.g. `32=KEY`) is not.
pub(crate) fn is_key_component(c: &NameComponent) -> bool {
    c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == KEY_COMPONENT.as_bytes()
}

/// Whether `name` has the certificate shape `…/KEY/<key-id>/<issuer-id>/<version>`
/// (ndn-cxx `Certificate::isValidName`: at least four components, `KEY`
/// fourth from last).
pub fn is_cert_name(name: &Name) -> bool {
    let comps = name.components();
    comps.len() >= 4 && is_key_component(&comps[comps.len() - 4])
}

/// The key a key or certificate name belongs to: a certificate name
/// ([`is_cert_name`]) without its issuer id and version; any other name
/// (a key name, or a legacy key-named certificate) unchanged.
pub fn key_name_of(name: &Name) -> Name {
    if is_cert_name(name) {
        Name::from_components(name.components()[..name.len() - 2].iter().cloned())
    } else {
        name.clone()
    }
}

/// A fresh key name for `identity`: `<identity>/KEY/<16 hex digits>`, the
/// key id 8 random bytes (ndn-cxx's default `KeyIdType::RANDOM`), so a new
/// key never collides with an earlier one. A failing system RNG is an
/// error, never a zero key id that the next failure would repeat.
pub fn new_key_name(identity: &Name) -> Result<Name, crate::TrustError> {
    let mut id = [0u8; 8];
    getrandom::getrandom(&mut id)
        .map_err(|e| crate::TrustError::KeyStore(format!("rng failure: {e}")))?;
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(identity.clone().append(KEY_COMPONENT).append(hex.as_str()))
}

/// The name of a certificate of `key_name` issued by `issuer_id` at
/// `version`: `<key_name>/<issuer_id>/v=<version>`. A certificate-shaped
/// `key_name` is first reduced to its key ([`key_name_of`]).
pub fn cert_name(key_name: &Name, issuer_id: &str, version: u64) -> Name {
    key_name_of(key_name)
        .append_component(NameComponent::generic(Bytes::copy_from_slice(
            issuer_id.as_bytes(),
        )))
        .append_version(version)
}

/// [`cert_name`] with a fresh version ([`next_version`]).
pub fn new_cert_name(key_name: &Name, issuer_id: &str) -> Name {
    cert_name(key_name, issuer_id, next_version())
}

/// A certificate version for "now": the current Unix time in milliseconds,
/// strictly greater than any version this process handed out before.
pub fn next_version() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut prev = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev + 1);
        match LAST.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(p) => prev = p,
        }
    }
}

/// Whether `cert` names a certificate of key `key_name`: `cert` is the key
/// itself (a legacy key-named certificate) or a certificate name under it.
pub fn is_cert_of(cert: &Name, key_name: &Name) -> bool {
    key_name_of(cert) == *key_name
}

/// Components ndn-rs places at the issuer-id position of Data that is *not*
/// a certificate: an admin's NDNCERT decision on an enrollment request is
/// named `<requested key>/ndncert-approve/<request id>` or
/// `<requested key>/ndncert-deny/<request id>`, which has the certificate
/// shape. A chain walk never takes such Data for a certificate of the key,
/// so a schema rule admitting decisions cannot admit a certificate.
pub const RESERVED_NON_CERT_ISSUERS: &[&str] = &["ndncert-approve", "ndncert-deny"];

/// Whether `name` has the certificate shape but an issuer id from
/// [`RESERVED_NON_CERT_ISSUERS`].
pub fn is_reserved_non_cert(name: &Name) -> bool {
    is_cert_name(name)
        && RESERVED_NON_CERT_ISSUERS
            .iter()
            .any(|r| name.components()[name.len() - 2].value.as_ref() == r.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn key_and_certificate_names() {
        let key = n("/home/bob/member/phone/KEY/k1");
        let cert = cert_name(&key, NDNCERT_ISSUER, 7);
        assert_eq!(cert, n("/home/bob/member/phone/KEY/k1/NDNCERT/v=7"));
        assert!(is_cert_name(&cert));
        assert!(!is_cert_name(&key));
        assert_eq!(key_name_of(&cert), key);
        assert_eq!(key_name_of(&key), key);
        assert!(is_cert_of(&cert, &key));
        assert!(is_cert_of(&key, &key));
        assert!(!is_cert_of(
            &n("/home/bob/member/phone/KEY/k2/NDNCERT/v=7"),
            &key
        ));
        // A certificate-shaped key name is reduced to its key first.
        assert_eq!(
            cert_name(&cert, SELF_ISSUER, 9),
            n("/home/bob/member/phone/KEY/k1/self/v=9")
        );
    }

    #[test]
    fn versions_strictly_increase() {
        let a = next_version();
        let b = next_version();
        assert!(b > a);
    }

    /// Only the GenericNameComponent `KEY` marks a key or certificate name.
    #[test]
    fn only_a_generic_key_component_counts() {
        let keyword_key =
            n("/home/bob/x").append_component(NameComponent::keyword(Bytes::from_static(b"KEY")));
        let cert = keyword_key
            .clone()
            .append("k1")
            .append("self")
            .append_version(1);
        assert!(!is_cert_name(&cert));
        assert_eq!(key_name_of(&cert), cert);
        assert!(is_cert_name(&n("/home/bob/x/KEY/k1/self/v=1")));
    }
}
