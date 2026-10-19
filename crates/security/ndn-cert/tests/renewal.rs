//! Certificate renewal (`ndn_cert::renew_certificate`, the CA's built-in
//! `renewal` challenge) against a namespace CA wired in process: a device
//! holding a current certificate renews without a token and keeps its key; a
//! revoked key, an expired certificate, a non-renewable role (guest, by
//! default) and a proof by another key are refused; each role's certificates
//! last what the policy sets for that role.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::roles::Role;
use ndn_cert::{
    CaExchange, CertError, HierarchicalPolicy, InviteLink, RENEWAL_CHALLENGE, RenewalError,
    RolePolicy, TokenChallenge, TokenStore, adopt_with_tofu, anchor_fingerprint, ca_key_name,
    enroll_with_invite, init_namespace, new_device_key_name, renew_certificate,
    renewal_proof_message,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Ed25519Signer, Keyring, SecurityManager, Signer};
use ndn_trust_envelope::TrustEnvelope;

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

/// Routes Interests straight into a `CaState`.
struct CaWire(Arc<CaState>);

impl CaExchange for CaWire {
    async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
        let proto = CertError::Transport;
        let interest =
            Interest::decode(interest_wire).map_err(|e| proto(format!("decode: {e:?}")))?;
        let comps = interest.name.components();
        let verb = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);
        let params = || interest.app_parameters().cloned().unwrap_or_default();
        let body = if verb(b"NEW").is_some() {
            self.0.handle_new(&params()).await?
        } else if let Some(i) = verb(b"CHALLENGE") {
            let rid: String = comps[i + 1]
                .value
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            self.0.handle_challenge(&rid, &params()).await?
        } else {
            let wire = self
                .0
                .cert_for_interest(&interest.name, interest.selectors().can_be_prefix)
                .ok_or_else(|| proto(format!("no served cert {}", interest.name)))?;
            return Data::decode(Bytes::from(wire)).map_err(|e| proto(format!("{e:?}")));
        };
        let reply = DataBuilder::new(interest.name.as_ref().clone(), &body).sign_digest_sha256();
        Data::decode(reply).map_err(|e| proto(format!("{e:?}")))
    }
}

struct Namespace {
    ca: Arc<CaState>,
    context: Data,
    fingerprint: [u8; 32],
}

/// A namespace `/home/bob` whose CA redeems a member and a guest token and
/// issues under `policy` (a `RolePolicy` unless the test says otherwise).
async fn namespace(policy: impl FnOnce(Name) -> Box<dyn ndn_cert::IssuancePolicy>) -> Namespace {
    let mgr = SecurityManager::new();
    let root = init_namespace(&mgr, &ns()).unwrap();
    let ca_key = ca_key_name(&ns());
    mgr.generate_ed25519(ca_key.clone()).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
    mgr.certify(&ca_key, ca_pub, &root.anchor_key, 3_650 * 86_400 * 1_000)
        .await
        .unwrap();
    let store = TokenStore::new();
    for (token, role) in [
        ("member-aa", "member"),
        ("member-bb", "member"),
        ("guest-gg", "guest"),
    ] {
        store
            .add_scoped(token, None, Some(ns().append(role)))
            .unwrap();
    }
    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(TokenChallenge::new(store))];
    let mut config = CaConfig::new(
        ns(),
        "namespace CA".to_string(),
        Duration::from_secs(90 * 86_400),
        Duration::from_secs(90 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .with_signing_key(ca_key);
    config.issuance = policy(ns());
    Namespace {
        ca: Arc::new(CaState::new(config, Arc::new(mgr))),
        context: Data::decode(root.context_data.raw().clone()).unwrap(),
        fingerprint: anchor_fingerprint(&root.anchor),
    }
}

fn role_policy(ns: Name) -> Box<dyn ndn_cert::IssuancePolicy> {
    Box::new(
        RolePolicy::new(ns)
            .with_validity(Role::Member, Duration::from_secs(30 * 86_400))
            .with_validity(Role::Guest, Duration::from_secs(7 * 86_400)),
    )
}

/// A device of the namespace: its keyring holds the context.
struct Device {
    keyring: Arc<Keyring>,
    key: Arc<dyn Signer>,
    cert: Data,
}

async fn enroll(ns: &Namespace, role: &str, token: &str, device: &str, seed: u8) -> Device {
    let keyring = Arc::new(Keyring::new());
    adopt_with_tofu(&keyring, &ns.context, &self::ns(), &ns.fingerprint).unwrap();
    let uri = TrustEnvelope::Invite {
        ca_prefix: "/home/bob".into(),
        identity_namespace: format!("/home/bob/{role}"),
        token: token.into(),
        ttl_secs: None,
        anchor_fingerprint: Some(ns.fingerprint),
        device: None,
    }
    .to_uri();
    let invite = InviteLink::from_uri(&uri).unwrap();
    let key_name = new_device_key_name(&invite.device_identity(device).unwrap()).unwrap();
    let key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name));
    let enrolled = enroll_with_invite(
        &keyring,
        None,
        &mut CaWire(Arc::clone(&ns.ca)),
        &invite,
        Arc::clone(&key),
    )
    .await
    .map_err(|f| f.error)
    .expect("the token enrolls the device");
    Device {
        keyring,
        key,
        cert: enrolled.issued.data,
    }
}

async fn renew(
    ns: &Namespace,
    device: &Device,
) -> Result<ndn_cert::IssuedCertificate, RenewalError> {
    renew_certificate(
        &device.keyring,
        &mut CaWire(Arc::clone(&ns.ca)),
        &device.cert,
        &[],
        Arc::clone(&device.key),
    )
    .await
}

fn lifetime_secs(cert: &ndn_security::Certificate) -> u64 {
    (cert.valid_until - cert.valid_from) / 1_000_000_000
}

fn cert_of(data: &Data) -> ndn_security::Certificate {
    ndn_security::Certificate::decode(data).unwrap()
}

/// The CA's verdict on a renewal request sent as-is (no client-side
/// checks): `signer` signs the request and the proof for `cert_name`.
async fn raw_renewal(
    ns: &Namespace,
    signer: Arc<dyn Signer>,
    cert_name: &Name,
) -> Result<Name, CertError> {
    let proof_key = Arc::clone(&signer);
    let cert_name = cert_name.clone();
    ndn_cert::client::enroll(
        &mut CaWire(Arc::clone(&ns.ca)),
        &self::ns(),
        signer,
        0,
        RENEWAL_CHALLENGE,
        move |round| {
            let proof_key = Arc::clone(&proof_key);
            let cert_name = cert_name.clone();
            async move {
                if round.round > 0 {
                    return Ok(None);
                }
                let proof = proof_key
                    .sign(&renewal_proof_message(&round.request_id, &cert_name))
                    .await?;
                let mut params = serde_json::Map::new();
                params.insert("cert_name".into(), cert_name.to_string().into());
                params.insert(
                    "signature".into(),
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&proof)
                        .into(),
                );
                Ok(Some(params))
            }
        },
    )
    .await
}

/// A device holding a current member certificate renews it without any
/// token: same identity, same key, a new certificate (valid for longer)
/// with the member lifetime, chained to the root.
#[tokio::test]
async fn a_valid_device_renews_without_a_token_and_keeps_its_key() {
    let ns = namespace(role_policy).await;
    let device = enroll(&ns, "member", "member-aa", "phone", 1).await;
    let old = cert_of(&device.cert);
    // Validity periods are stored to the second.
    std::thread::sleep(Duration::from_millis(1_100));

    let renewed = renew(&ns, &device)
        .await
        .expect("a current member certificate renews");
    assert!(
        renewed.cert.name.has_prefix(device.key.key_name()),
        "for the same key name"
    );
    assert_eq!(renewed.cert.public_key, old.public_key, "for the same key");
    assert!(
        renewed.cert.valid_until > old.valid_until,
        "a new certificate, valid for longer"
    );
    assert_eq!(renewed.issuer.as_ref(), Some(&ca_key_name(&self::ns())));
    assert!((30 * 86_400 - 60..=30 * 86_400 + 60).contains(&lifetime_secs(&renewed.cert)));

    // The renewed certificate renews in turn.
    let again = Device {
        cert: renewed.data,
        ..device
    };
    renew(&ns, &again)
        .await
        .expect("a renewed certificate renews again");
}

/// Each role's certificates last what the policy sets for that role.
#[tokio::test]
async fn per_role_lifetimes_are_honoured() {
    let ns = namespace(role_policy).await;
    let member = enroll(&ns, "member", "member-aa", "phone", 1).await;
    let guest = enroll(&ns, "guest", "guest-gg", "friend", 2).await;
    let member_secs = lifetime_secs(&cert_of(&member.cert));
    let guest_secs = lifetime_secs(&cert_of(&guest.cert));
    assert!(
        (30 * 86_400 - 60..=30 * 86_400 + 60).contains(&member_secs),
        "{member_secs}"
    );
    assert!(
        (7 * 86_400 - 60..=7 * 86_400 + 60).contains(&guest_secs),
        "{guest_secs}"
    );
}

/// A guest is not renewable by default, so guest access ends at expiry; a
/// policy may make it renewable.
#[tokio::test]
async fn a_guest_cannot_renew_by_default() {
    let ns = namespace(role_policy).await;
    let guest = enroll(&ns, "guest", "guest-gg", "friend", 2).await;
    let refused = renew(&ns, &guest).await;
    assert!(
        matches!(refused, Err(RenewalError::Refused { .. })),
        "{refused:?}"
    );

    let ns = namespace(|ns| Box::new(RolePolicy::new(ns).with_renewable(Role::Guest, true))).await;
    let guest = enroll(&ns, "guest", "guest-gg", "friend", 2).await;
    renew(&ns, &guest)
        .await
        .expect("a policy may make guests renewable");
}

/// A key the CA revoked is never renewed, whichever certificate of it the
/// device presents.
#[tokio::test]
async fn a_revoked_key_cannot_renew() {
    let ns = namespace(role_policy).await;
    let device = enroll(&ns, "member", "member-aa", "phone", 1).await;
    let renewed = renew(&ns, &device)
        .await
        .expect("renews before the revocation");
    let revoked = ns.ca.revoke_issued_under(device.key.key_name());
    assert!(!revoked.revoked.is_empty());

    for cert in [
        Data::decode(device.cert.raw().clone()).unwrap(),
        renewed.data,
    ] {
        let presenting = Device {
            keyring: Arc::clone(&device.keyring),
            key: Arc::clone(&device.key),
            cert,
        };
        let refused = renew(&ns, &presenting).await;
        assert!(
            matches!(refused, Err(RenewalError::Refused { .. })),
            "{refused:?}"
        );
    }
}

/// An expired certificate cannot renew: the device refuses before sending
/// anything, and the CA refuses a request that is sent anyway.
#[tokio::test]
async fn an_expired_certificate_cannot_renew() {
    let ns = namespace(|ns| {
        Box::new(RolePolicy::new(ns).with_validity(Role::Member, Duration::from_secs(2)))
    })
    .await;
    let device = enroll(&ns, "member", "member-aa", "phone", 1).await;
    std::thread::sleep(Duration::from_millis(3_100));

    let refused = renew(&ns, &device).await;
    assert!(
        matches!(refused, Err(RenewalError::Expired { .. })),
        "{refused:?}"
    );

    let cert_name = (*cert_of(&device.cert).name).clone();
    let at_ca = raw_renewal(&ns, Arc::clone(&device.key), &cert_name).await;
    assert!(
        matches!(at_ca, Err(CertError::ChallengeFailed(_))),
        "{at_ca:?}"
    );
}

/// Renewal proves possession of the certified key: another key cannot renew
/// someone's certificate, for itself or by naming it.
#[tokio::test]
async fn another_key_cannot_renew_a_certificate() {
    let ns = namespace(role_policy).await;
    let phone = enroll(&ns, "member", "member-aa", "phone", 1).await;
    let cert_name = (*cert_of(&phone.cert).name).clone();

    // Another key, under the phone's name: not the certified public key.
    let mallory: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
        &[9; 32],
        phone.key.key_name().clone(),
    ));
    let refused = raw_renewal(&ns, mallory, &cert_name).await;
    assert!(refused.is_err(), "{refused:?}");

    // Another enrolled device's key naming the phone's certificate.
    let laptop = enroll(&ns, "member", "member-bb", "laptop", 3).await;
    let refused = raw_renewal(&ns, Arc::clone(&laptop.key), &cert_name).await;
    assert!(refused.is_err(), "{refused:?}");
}

/// A CA whose issuance policy does not renew does not offer renewal.
#[tokio::test]
async fn a_ca_that_does_not_renew_refuses() {
    let renewing = namespace(role_policy).await;
    let device = enroll(&renewing, "member", "member-aa", "phone", 1).await;
    let plain = namespace(|_| Box::new(ndn_cert::AcceptAllIssuance)).await;
    let refused = renew(&plain, &device).await;
    assert!(
        matches!(refused, Err(RenewalError::Refused { .. })),
        "{refused:?}"
    );
}
