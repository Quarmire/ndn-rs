//! NDNSF security-invariant witnesses — the subset that maps to shipped ndn-rs
//! primitives (content-key + capability). See
//! `docs/specs/ndnsf-invariants.md` for the full catalogue and the gate: the
//! `ndn-nacabe`/`ndn-ndnsf` layers MUST NOT land until the invariants mapped to
//! them (marked ⛔ in the catalogue) also have passing witnesses.
//!
//! Each test is named for the invariant ID it proves and references the NDNSF
//! source invariant it preserves.

use ndn_packet::Name;
use ndn_security::confidentiality::ConfidentialityError;
use ndn_security::{Capability, CapabilityError, ContentKey, Sealed};

fn n(s: &str) -> Name {
    s.parse().expect("name")
}

/// NSF-T2 — "`ProviderToken` expires after the pending-state TTL." A capability
/// is honoured strictly inside `[not_before, not_after)`; once `now` reaches
/// `not_after` it stops authorizing.
#[test]
fn nsf_t2_capability_expires_after_window() {
    let cap = Capability::new(n("/muas/alice"), n("/svc/mavlink"), 100, 200);
    let signer = n("/muas/alice/KEY/k1");
    let op = n("/svc/mavlink/execute");
    assert_eq!(cap.authorizes(&signer, &op, 199), Ok(()));
    assert_eq!(
        cap.authorizes(&signer, &op, 200),
        Err(CapabilityError::Expired)
    );
}

/// NSF-T4 — "Using an expired token must fail." A capability whose window has
/// fully passed never authorizes.
#[test]
fn nsf_t4_expired_capability_rejected() {
    let cap = Capability::new(n("/muas/alice"), n("/svc"), 0, 10);
    assert_eq!(
        cap.authorizes(&n("/muas/alice/KEY/k1"), &n("/svc/x"), 11),
        Err(CapabilityError::Expired)
    );
}

/// NSF-T5 — "Injecting an unknown or random token must fail." A request whose
/// verified signer is not under the capability's grantee is rejected (the
/// binding half; the signature half is the `Validator`'s job, and gates
/// `ndn-ndnsf`).
#[test]
fn nsf_t5_unknown_grantee_rejected() {
    let cap = Capability::new(n("/muas/alice"), n("/svc"), 0, 100);
    assert_eq!(
        cap.authorizes(&n("/muas/mallory/KEY/k1"), &n("/svc/x"), 50),
        Err(CapabilityError::NotGrantee)
    );
}

/// NSF-F3 — "Decryption failures must not mutate state" / reveal plaintext. A
/// content-key `open` under the wrong key, wrong AAD, or a tampered ciphertext
/// returns `Err` and yields nothing.
#[test]
fn nsf_f3_decryption_failure_yields_no_plaintext() {
    let ck = ContentKey::generate();
    let sealed = ck.seal(b"secret telemetry", b"/muas/drone-A/v1");

    // wrong key
    let other = ContentKey::generate();
    assert_eq!(
        other.open(&sealed, b"/muas/drone-A/v1"),
        Err(ConfidentialityError::OpenFailed)
    );
    // wrong AAD (e.g. a swapped name)
    assert_eq!(
        ck.open(&sealed, b"/muas/drone-A/v2"),
        Err(ConfidentialityError::OpenFailed)
    );
    // tampered ciphertext
    let mut t = sealed.clone();
    let mut bad = t.ciphertext.to_vec();
    bad[0] ^= 0xff;
    t.ciphertext = bytes::Bytes::from(bad);
    assert_eq!(
        ck.open(&t, b"/muas/drone-A/v1"),
        Err(ConfidentialityError::OpenFailed)
    );
}

/// NSF-F4 — "Malformed payloads must not mutate state." Primitives reject at
/// decode, returning `Err` with no partially-applied state.
#[test]
fn nsf_f4_malformed_payload_rejected_at_decode() {
    // A NAME TLV is not a capability payload.
    assert!(Capability::decode(n("/not/a/capability").encode_to_tlv()).is_err());
    // Truncated sealed bytes (shorter than nonce+tag).
    assert!(matches!(
        Sealed::from_bytes(&[0u8; 8]),
        Err(ConfidentialityError::Malformed)
    ));
}

/// NSF-F5 — "Negative paths must fail closed." At the primitive level there is
/// no path to an authorized capability or recovered plaintext when any check
/// fails: a wrong-grantee + out-of-scope + expired request is refused, and a
/// tampered ciphertext never decrypts.
#[test]
fn nsf_f5_primitives_fail_closed() {
    let cap = Capability::new(n("/muas/alice"), n("/svc/mavlink"), 100, 200);
    // Every dimension wrong: wrong principal, out-of-scope op, outside window.
    assert!(
        cap.authorizes(&n("/muas/mallory/KEY/k1"), &n("/svc/camera/capture"), 999)
            .is_err()
    );

    // No "accidental allow": a valid capability still refuses an out-of-scope op.
    assert_eq!(
        cap.authorizes(&n("/muas/alice/KEY/k1"), &n("/other/service"), 150),
        Err(CapabilityError::OutOfScope)
    );

    // Confidentiality fails closed under tamper.
    let ck = ContentKey::generate();
    let sealed = ck.seal(b"x", b"aad");
    let mut t = sealed.clone();
    let mut bad = t.ciphertext.to_vec();
    if let Some(b0) = bad.first_mut() {
        *b0 ^= 0xff;
    }
    t.ciphertext = bytes::Bytes::from(bad);
    assert!(ck.open(&t, b"aad").is_err());
}
