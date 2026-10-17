//! Enrolling with an `ndn-trust://invite` link (`ndn_cert::enroll_with_invite`)
//! against a namespace CA wired in process: a token certifies only its role, the
//! device's private key never crosses the wire, an issued certificate chains
//! to the root the invite names, and a context signed by another root is
//! refused before anything is sent.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::{
    CaExchange, CertError, HierarchicalPolicy, InviteEnrollError, InviteLink, TokenChallenge,
    TokenStore, adopt_with_tofu, anchor_fingerprint, ca_key_name, enroll_with_invite, init_namespace,
    new_device_key_name,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Certificate, Ed25519Signer, Keyring, SecurityManager, Signer};
use ndn_trust_envelope::TrustEnvelope;

const DEVICE_SEED: [u8; 32] = [0x5a; 32];

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

/// Routes Interests straight into a `CaState` and records every Interest
/// wire it was handed.
struct CaWire {
    ca: Arc<CaState>,
    sent: Arc<Mutex<Vec<Bytes>>>,
}

impl CaExchange for CaWire {
    async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
        self.sent.lock().unwrap().push(interest_wire.clone());
        let proto = CertError::Transport;
        let interest =
            Interest::decode(interest_wire).map_err(|e| proto(format!("decode: {e:?}")))?;
        let comps = interest.name.components();
        let verb = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);
        let params = || interest.app_parameters().cloned().unwrap_or_default();
        let body = if verb(b"NEW").is_some() {
            self.ca.handle_new(&params()).await?
        } else if let Some(i) = verb(b"CHALLENGE") {
            let rid: String = comps[i + 1].value.iter().map(|b| format!("{b:02x}")).collect();
            self.ca.handle_challenge(&rid, &params()).await?
        } else {
            let wire = self
                .ca
                .cert_for_interest(&interest.name, interest.selectors().can_be_prefix)
                .ok_or_else(|| proto(format!("no served cert {}", interest.name)))?;
            return Data::decode(Bytes::from(wire)).map_err(|e| proto(format!("{e:?}")));
        };
        let reply = DataBuilder::new(interest.name.as_ref().clone(), &body).sign_digest_sha256();
        Data::decode(reply).map_err(|e| proto(format!("{e:?}")))
    }
}

struct RootDevice {
    ca: Arc<CaState>,
    /// The signed trust context and the root anchor's fingerprint.
    context: Data,
    fingerprint: [u8; 32],
}

/// A namespace rooted at `/home/bob` whose CA (`/home/bob/CA`, certified by the
/// root) redeems the given `(token, scope role)` pairs.
async fn root_dev(tokens: &[(&str, &str)]) -> RootDevice {
    let mgr = SecurityManager::new();
    let root_dev = init_namespace(&mgr, &ns()).unwrap();
    let ca_key = ca_key_name(&ns());
    mgr.generate_ed25519(ca_key.clone()).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
    mgr.certify(&ca_key, ca_pub, &root_dev.anchor_key, 3_650 * 86_400 * 1_000)
        .await
        .unwrap();
    let store = TokenStore::new();
    for (token, role) in tokens {
        store.add_scoped(*token, None, Some(ns().append(*role)));
    }
    let challenges: Vec<Box<dyn ChallengeHandler>> =
        vec![Box::new(TokenChallenge::new(store))];
    let config = CaConfig::new(
        ns(),
        "namespace CA".to_string(),
        Duration::from_secs(86_400),
        Duration::from_secs(365 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .with_signing_key(ca_key);
    RootDevice {
        ca: Arc::new(CaState::new(config, Arc::new(mgr))),
        context: Data::decode(root_dev.context_data.raw().clone()).unwrap(),
        fingerprint: anchor_fingerprint(&root_dev.anchor),
    }
}

fn invite(identity_namespace: &str, token: &str, fingerprint: [u8; 32]) -> String {
    TrustEnvelope::Invite {
        ca_prefix: "/home/bob".into(),
        identity_namespace: identity_namespace.into(),
        token: token.into(),
        ttl_secs: None,
        anchor_fingerprint: Some(fingerprint),
    }
    .to_uri()
}

/// A device keyring that already holds the root device's context (adoption by name
/// is covered by the onboarding tests).
fn device_keyring(root_dev: &RootDevice) -> Arc<Keyring> {
    let keyring = Arc::new(Keyring::new());
    adopt_with_tofu(&keyring, &root_dev.context, &ns(), &root_dev.fingerprint).unwrap();
    keyring
}

fn device_key(invite: &InviteLink, device: &str) -> Arc<dyn Signer> {
    let key = new_device_key_name(&invite.device_identity(device).unwrap());
    Arc::new(Ed25519Signer::from_seed(&DEVICE_SEED, key))
}

async fn run(
    root_dev: &RootDevice,
    keyring: &Arc<Keyring>,
    uri: &str,
    device: &str,
) -> (Result<Certificate, InviteEnrollError>, Vec<Bytes>) {
    let invite = InviteLink::from_uri(uri).expect("well-formed invite");
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut wire = CaWire {
        ca: Arc::clone(&root_dev.ca),
        sent: Arc::clone(&sent),
    };
    let result = enroll_with_invite(
        keyring,
        None,
        &mut wire,
        &invite,
        device_key(&invite, device),
    )
    .await
    .map(|e| e.issued.cert)
    .map_err(|f| f.error);
    let sent = sent.lock().unwrap().clone();
    (result, sent)
}

/// A member token certifies a member key whose certificate chains to the
/// root; the private key never appears in anything sent to the CA.
#[tokio::test]
async fn member_invite_certifies_the_device_key_and_keeps_it_private() {
    let root_dev = root_dev(&[("member-aa", "member")]).await;
    let keyring = device_keyring(&root_dev);
    let uri = invite("/home/bob/member", "member-aa", root_dev.fingerprint);
    let (result, sent) = run(&root_dev, &keyring, &uri, "phone").await;
    let cert = result.expect("member token enrolls a member key");
    assert!(cert.name.has_prefix(&"/home/bob/member/phone/KEY".parse().unwrap()));
    assert_eq!(cert.issuer.as_deref(), Some(&ca_key_name(&ns())));

    let pkcs8 = ndn_security::safebag::ed25519_seed_to_pkcs8(&DEVICE_SEED).unwrap();
    assert!(!sent.is_empty());
    for wire in &sent {
        for secret in [&DEVICE_SEED[..], &pkcs8[..]] {
            assert!(
                !wire.windows(secret.len()).any(|w| w == secret),
                "private key material crossed the wire"
            );
        }
    }
}

/// A token certifies only the role it is scoped to: a guest token rewritten
/// into a member invite is refused before anything is sent, and the CA
/// itself refuses a token scoped to another role than the requested name.
#[tokio::test]
async fn a_token_certifies_only_its_role() {
    let root_dev = root_dev(&[("guest-gg", "guest"), ("plain", "guest")]).await;
    let keyring = device_keyring(&root_dev);

    let forged = invite("/home/bob/member", "guest-gg", root_dev.fingerprint);
    assert!(matches!(
        InviteLink::from_uri(&forged),
        Err(InviteEnrollError::TokenRole { .. })
    ));

    // `plain` carries no role, so the device reads it as a member token;
    // the CA scoped it to guests and refuses the member name.
    let uri = invite("/home/bob/member", "plain", root_dev.fingerprint);
    let (result, _) = run(&root_dev, &keyring, &uri, "phone").await;
    assert!(
        matches!(result, Err(InviteEnrollError::TokenRefused(_))),
        "{result:?}"
    );

    // The guest token still certifies a guest, and only once.
    let uri = invite("/home/bob/guest", "guest-gg", root_dev.fingerprint);
    let (result, _) = run(&root_dev, &keyring, &uri, "friend").await;
    let cert = result.expect("guest token enrolls a guest key");
    assert!(cert.name.has_prefix(&"/home/bob/guest/friend".parse().unwrap()));
    let (again, _) = run(&root_dev, &keyring, &uri, "friend2").await;
    assert!(matches!(again, Err(InviteEnrollError::TokenRefused(_))), "{again:?}");
}

/// A held context signed by another root than the invite expects is refused
/// before anything is sent to the CA; a key outside the invite is refused
/// the same way.
#[tokio::test]
async fn other_root_or_foreign_key_is_refused_before_contacting_the_ca() {
    let root_dev = root_dev(&[("member-aa", "member")]).await;
    let keyring = device_keyring(&root_dev);
    let uri = invite("/home/bob/member", "member-aa", [7; 32]);
    let (result, sent) = run(&root_dev, &keyring, &uri, "phone").await;
    assert!(matches!(result, Err(InviteEnrollError::DifferentRoot { .. })), "{result:?}");
    assert!(sent.is_empty());

    let uri = invite("/home/bob/member", "member-aa", root_dev.fingerprint);
    let invite = InviteLink::from_uri(&uri).unwrap();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut wire = CaWire {
        ca: Arc::clone(&root_dev.ca),
        sent: Arc::clone(&sent),
    };
    let foreign: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
        &DEVICE_SEED,
        "/home/bob/admin/phone/KEY/k".parse().unwrap(),
    ));
    let result = enroll_with_invite(&keyring, None, &mut wire, &invite, foreign).await;
    assert!(matches!(
        result.map_err(|f| f.error),
        Err(InviteEnrollError::KeyOutsideInvite { .. })
    ));
    assert!(sent.lock().unwrap().is_empty());
}

/// The invite names no lifetime: the certificate lasts what the CA's policy
/// issues (this CA: one day by default, a year at most).
#[tokio::test]
async fn the_ca_policy_decides_the_certificate_lifetime() {
    let root_dev = root_dev(&[("member-aa", "member")]).await;
    let keyring = device_keyring(&root_dev);
    let uri = invite("/home/bob/member", "member-aa", root_dev.fingerprint);
    let (result, _) = run(&root_dev, &keyring, &uri, "phone").await;
    let cert = result.expect("enrolls");
    let secs = (cert.valid_until - cert.valid_from) / 1_000_000_000;
    assert!((86_400 - 60..=86_400 + 60).contains(&secs), "lifetime {secs}s");
}

/// A token carrying an expiry is refused once it has passed, before
/// anything is sent; before it, the invite reads normally.
#[test]
fn an_expired_invite_is_refused() {
    use ndn_cert::roles::token_with_expiry;
    let expired = invite("/home/bob/member", &token_with_expiry("member-aa", 1), [1; 32]);
    assert!(matches!(
        InviteLink::from_uri(&expired),
        Err(InviteEnrollError::TokenExpired { .. })
    ));
    let later = token_with_expiry("member-aa", u64::from(u32::MAX));
    let link = InviteLink::from_uri(&invite("/home/bob/member", &later, [1; 32])).unwrap();
    assert_eq!(link.expires_at_secs, Some(u64::from(u32::MAX)));
    assert_eq!(link.role, ndn_cert::roles::Role::Member);
}

/// Malformed or misdirected invites are refused with a reason, never a
/// panic.
#[test]
fn malformed_invites_are_refused_without_panicking() {
    let fp = Some([1u8; 32]);
    let env = |ca: &str, idns: &str, token: &str| {
        TrustEnvelope::Invite {
            ca_prefix: ca.into(),
            identity_namespace: idns.into(),
            token: token.into(),
            ttl_secs: None,
            anchor_fingerprint: fp,
        }
        .to_uri()
    };
    let anchor = TrustEnvelope::Anchor {
        namespace: Some("/home/bob".into()),
        fingerprint: fp,
        version: Some(1),
        context_data: None,
        context_content: None,
    }
    .to_uri();
    let cases = [
        String::new(),
        "garbage".into(),
        "ndn-trust://invite/".into(),
        "ndn-trust://invite/!!!notbase64".into(),
        anchor,
        env("", "/home/bob/member", "member-aa"),
        env("/home/bob", "/home/bob", "member-aa"),
        env("/home/bob", "/member", "member-aa"),
        env("/home/bob", "/home/bob/admin", "admin-aa"),
        env("/home/bob", "/home/bob/node", "node-aa"),
        env("/home/bob", "/home/bob/member", ""),
        env("/home/bob", "/home/bob/member", "guest-aa"),
        env("/home/bob", "/home/bob/guest", "member-aa"),
        env("/home/bob", "/home/bob/guest", "plain"),
        env("/home/bob", "/home/KEY/member", "member-aa"),
    ];
    for uri in cases {
        let refused = InviteLink::from_uri(&uri);
        assert!(refused.is_err(), "accepted {uri:?}");
        assert!(!refused.unwrap_err().to_string().is_empty());
    }

    let ok = InviteLink::from_uri(&env("/home/bob", "/home/bob/member", "member-aa")).unwrap();
    assert_eq!(ok.namespace, ns());
    for device in ["", "KEY", "member", "a/b", "-x", &"x".repeat(64)] {
        assert!(ok.device_identity(device).is_err(), "accepted device {device:?}");
    }
}
