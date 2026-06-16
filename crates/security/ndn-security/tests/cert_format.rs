//! C.07 + C.08 + C.18 + N.13 — cert wire-format regression tests.
//!
//! Each test asserts a single, binary, NDN-spec-compliant invariant of
//! the certificate wire form per ndn-cxx `security/certificate.{hpp,cpp}`
//! and `security/validity-period.cpp` and the NDNCERT 0.3 protocol.

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent, tlv_type};
use ndn_security::{
    Ed25519Signer, KeyChain, Signer, encode_cert_data, iso8601,
    spki::{self, ED25519_KEY_LEN},
};
use ndn_tlv::TlvReader;

fn name_str(s: &str) -> Name {
    s.parse().expect("test name must parse")
}

/// Issue a self-signed cert via the manager-level encoder, returning the
/// wire bytes plus the structures needed by individual assertions.
async fn issue_cert_data(
    subject_id: &str,
    keyid: &str,
    issuer: &str,
    version: u64,
) -> (Bytes, Name) {
    let identity = name_str(subject_id);
    let key_name = identity
        .clone()
        .append("KEY")
        .append_component(NameComponent::generic(Bytes::copy_from_slice(
            keyid.as_bytes(),
        )));

    // Cert name = key_name + issuer + version.
    let cert_name = key_name
        .clone()
        .append_component(NameComponent::generic(Bytes::copy_from_slice(
            issuer.as_bytes(),
        )))
        .append_version(version);

    let seed = [0u8; 32];
    let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
    let pubkey = signer.public_key().expect("ed25519 must produce pubkey");

    // Use NOW for validity start, +1 year for end.
    let now_ns: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let one_year_ns = 365u64 * 24 * 3600 * 1_000_000_000;

    let wire = encode_cert_data(
        &cert_name,
        &pubkey,
        &signer as &dyn Signer,
        now_ns,
        now_ns.saturating_add(one_year_ns),
    )
    .await
    .expect("cert encode must succeed");

    (wire, cert_name)
}

/// C.07 — cert NAME must end with `/KEY/<keyid>/<issuer>/<version>`
/// (≥ 4 trailing components) per ndn-cxx
/// `Certificate::isValidName` (`security/certificate.cpp:112-116`).
#[test]
fn c07_keychain_ephemeral_cert_name_has_four_trailing_components() {
    let kc = KeyChain::ephemeral("/test/alice").expect("ephemeral must succeed");
    let key_name = kc.key_name();
    let comps = key_name.components();
    let n = comps.len();

    // ndn-cxx MIN_CERT_NAME_LENGTH = 4; the last four components must be
    // KEY / <keyid> / <issuer> / <version>.
    assert!(
        n >= 4,
        "cert/key name must have at least 4 components per ndn-cxx \
         Certificate::isValidName; got {n}: {key_name}"
    );
    assert_eq!(
        comps[n - 4].value.as_ref(),
        b"KEY",
        "fourth-from-last component must be literal `KEY`; got {:?} in {key_name}",
        comps[n - 4].value
    );
}

/// C.08 — cert Content body must be a DER SubjectPublicKeyInfo for
/// Ed25519 per ndn-cxx `security/transform/public-key.cpp:101`
/// (`loadPkcs8`). The Content's value bytes are the raw SPKI envelope —
/// no inner TLV wrap.
#[tokio::test]
async fn c08_cert_content_body_is_der_spki() {
    let (wire, _name) = issue_cert_data("/test/alice", "k1", "self", 1).await;
    let data = Data::decode(wire).expect("cert must parse as Data TLV");
    let content = data.content().expect("cert must carry Content");

    assert!(
        spki::is_ed25519_spki(content),
        "cert Content body must be a DER SPKI envelope (44 bytes starting \
         with the Ed25519 prefix); got {} bytes: {:02x?}",
        content.len(),
        &content[..content.len().min(16)]
    );

    let raw = spki::unwrap_ed25519(content).expect("SPKI must contain a 32-byte key");
    assert_eq!(raw.len(), ED25519_KEY_LEN);
}

/// C.18 — cert ValidityPeriod NotBefore / NotAfter must be 15-byte
/// ASCII `YYYYMMDDTHHMMSS` strings per ndn-cxx
/// `security/validity-period.cpp:29` (`ISO_DATETIME_SIZE = 15`).
/// ValidityPeriod lives inside SignatureInfo, not Content.
#[tokio::test]
async fn c18_cert_validity_period_is_iso8601_inside_signature_info() {
    let (wire, _name) = issue_cert_data("/test/alice", "k1", "self", 1).await;
    let data = Data::decode(wire).expect("cert must parse as Data TLV");

    // SignatureInfo lives in the signed region. Extract ValidityPeriod
    // by walking the SignatureInfo TLV body manually — the public
    // SignatureInfo decoder may not surface this field yet.
    let signed = data.signed_region();
    let mut reader = TlvReader::new(Bytes::copy_from_slice(signed));
    let mut sig_info_value: Option<Bytes> = None;
    while !reader.is_empty() {
        let (typ, val) = reader.read_tlv().expect("signed region must parse");
        if typ == tlv_type::SIGNATURE_INFO {
            sig_info_value = Some(val);
            break;
        }
    }
    let sig_info_value =
        sig_info_value.expect("cert signed region must contain a SignatureInfo TLV");

    let mut si_reader = TlvReader::new(sig_info_value);
    let mut not_before: Option<Bytes> = None;
    let mut not_after: Option<Bytes> = None;
    while !si_reader.is_empty() {
        let (typ, val) = si_reader.read_tlv().expect("SignatureInfo must parse");
        if typ == tlv_type::VALIDITY_PERIOD {
            let mut vp = TlvReader::new(val);
            while !vp.is_empty() {
                let (vt, vv) = vp.read_tlv().expect("ValidityPeriod must parse");
                match vt {
                    t if t == tlv_type::NOT_BEFORE => not_before = Some(vv),
                    t if t == tlv_type::NOT_AFTER => not_after = Some(vv),
                    _ => {}
                }
            }
        }
    }

    let nb = not_before.expect("cert SignatureInfo must contain ValidityPeriod / NotBefore");
    let na = not_after.expect("cert SignatureInfo must contain ValidityPeriod / NotAfter");

    assert_eq!(
        nb.len(),
        iso8601::ISO_DATETIME_LEN,
        "NotBefore must be 15 bytes (ISO-8601 YYYYMMDDTHHMMSS); got {} bytes: {:02x?}",
        nb.len(),
        nb.as_ref()
    );
    assert_eq!(
        na.len(),
        iso8601::ISO_DATETIME_LEN,
        "NotAfter must be 15 bytes; got {} bytes: {:02x?}",
        na.len(),
        na.as_ref()
    );
    assert!(
        iso8601::parse_iso_basic(&nb).is_some(),
        "NotBefore must be a parseable ISO-8601 basic string; got {:?}",
        std::str::from_utf8(&nb).unwrap_or("<non-utf8>")
    );
    assert!(
        iso8601::parse_iso_basic(&na).is_some(),
        "NotAfter must be a parseable ISO-8601 basic string; got {:?}",
        std::str::from_utf8(&na).unwrap_or("<non-utf8>")
    );
}

// N.13 (`serialize_cert` must produce a parseable Data TLV) lives in
// `crates/ndn-cert/tests/n13_serialize_data.rs` to avoid a
// dependency cycle here (ndn-cert depends on ndn-security).
