//! Renewal at a later CA of the same namespace. The root device of
//! `/home/bob` was replaced: a second root R2 and a new CA key under the same
//! CA identity `/home/bob/CA`, certified by R2, with the old root R1 still an
//! anchor of the trust context. A device holding a certificate from the
//! earlier CA (`/home/bob/CA/KEY/ca`, which nobody serves any more) renews at
//! the new CA by passing the issuer chain it kept to `renew_certificate`,
//! which sends it with the certificate; without it the new CA refuses. The
//! new CA verifies the chain under the trust context it holds and serves the
//! earlier CA's certificate from then on. A context revoking the earlier
//! CA's key, an issuer that is no key of `/home/bob/CA` and a chain to no
//! anchor are refused, and nothing is issued.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::renewal::{CERT_NAME_PARAM, CERTIFICATE_PARAM, ISSUERS_PARAM, PROOF_PARAM};
use ndn_cert::roles::Role;
use ndn_cert::{
    CaExchange, CertError, HierarchicalPolicy, InviteLink, RENEWAL_CHALLENGE, RenewalError,
    RolePolicy, TokenChallenge, TokenStore, adopt_with_tofu, anchor_fingerprint, ca_key_name,
    enroll_with_invite, init_namespace, new_device_key_name, renew_certificate,
    renewal_proof_message,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Ed25519Signer, Keyring, SecurityManager, SignedTrustContext, Signer};
use ndn_trust_envelope::TrustEnvelope;

const DAY_MS: u64 = 86_400 * 1_000;

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

/// What a device's forwarder does with its Interests: everything goes to the
/// CA at `/home/bob`. Nothing else serves certificates, so the issuer
/// certificates a device kept reach a renewal only through
/// `renew_certificate`'s `issuers`.
struct Net {
    ca: Arc<CaState>,
}

impl Net {
    fn to(ca: &Arc<CaState>) -> Self {
        Self { ca: Arc::clone(ca) }
    }
}

impl CaExchange for Net {
    async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
        let proto = CertError::Transport;
        let interest =
            Interest::decode(interest_wire).map_err(|e| proto(format!("decode: {e:?}")))?;
        let comps = interest.name.components();
        let verb = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);
        let params = || interest.app_parameters().cloned().unwrap_or_default();
        let body = if verb(b"NEW").is_some() {
            self.ca.handle_new(&params()).await?
        } else if let Some(i) = verb(b"CHALLENGE") {
            let rid: String = comps[i + 1]
                .value
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            self.ca.handle_challenge(&rid, &params()).await?
        } else {
            let can_be_prefix = interest.selectors().can_be_prefix;
            let wire = self
                .ca
                .cert_for_interest(&interest.name, can_be_prefix)
                .ok_or_else(|| proto(format!("no served cert {}", interest.name)))?;
            return Data::decode(Bytes::from(wire)).map_err(|e| proto(format!("{e:?}")));
        };
        let reply = DataBuilder::new(interest.name.as_ref().clone(), &body).sign_digest_sha256();
        Data::decode(reply).map_err(|e| proto(format!("{e:?}")))
    }
}

/// A namespace CA at `/home/bob` signing with `ca_key` (held by `mgr`, with
/// its certificate), renewing members.
fn ca(mgr: Arc<SecurityManager>, ca_key: Name, tokens: TokenStore) -> Arc<CaState> {
    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(TokenChallenge::new(tokens))];
    let mut config = CaConfig::new(
        ns(),
        "namespace CA".to_string(),
        Duration::from_secs(90 * 86_400),
        Duration::from_secs(90 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .with_signing_key(ca_key);
    config.issuance = Box::new(
        RolePolicy::new(ns()).with_validity(Role::Member, Duration::from_secs(30 * 86_400)),
    );
    Arc::new(CaState::new(config, mgr))
}

/// The namespace before its root device was lost: root R1 (its key held by
/// `mgr`), the context v1, and the earlier CA `/home/bob/CA/KEY/ca`,
/// certified by R1.
struct Earlier {
    mgr: Arc<SecurityManager>,
    root_key: Name,
    ca: Arc<CaState>,
    context: Data,
    content: Bytes,
    fingerprint: [u8; 32],
}

async fn earlier() -> Earlier {
    let mgr = Arc::new(SecurityManager::new());
    let root = init_namespace(&mgr, &ns()).unwrap();
    let ca_key = ca_key_name(&ns());
    mgr.generate_ed25519(ca_key.clone()).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
    mgr.certify(&ca_key, ca_pub, &root.anchor_key, 3_650 * DAY_MS)
        .await
        .unwrap();
    let tokens = TokenStore::new();
    tokens
        .add_scoped("member-aa", None, Some(ns().append("member")))
        .unwrap();
    Earlier {
        ca: ca(Arc::clone(&mgr), ca_key, tokens),
        mgr,
        root_key: root.anchor_key.clone(),
        context: Data::decode(root.context_data.raw().clone()).unwrap(),
        content: root.context.encode_content(),
        fingerprint: anchor_fingerprint(&root.anchor),
    }
}

/// The namespace after its root device was replaced: a second root R2, a
/// new CA key under `/home/bob/CA` certified by R2, and the context v2
/// listing R1 and R2 as anchors (and revoking `revoke`). The later CA takes
/// earlier CAs' certificates under a keyring holding that context.
struct Later {
    ca: Arc<CaState>,
    ca_key: Name,
    context: Arc<SignedTrustContext>,
}

async fn later(earlier: &Earlier, revoke: &[Name]) -> Later {
    let mgr = Arc::new(SecurityManager::new());
    let root_key = ns().append("KEY").append("root2");
    mgr.generate_ed25519(root_key.clone()).unwrap();
    let root_pub = mgr
        .get_signer_sync(&root_key)
        .unwrap()
        .public_key()
        .unwrap();
    let anchor = mgr
        .issue_self_signed_async(&root_key, root_pub, u64::MAX)
        .await
        .unwrap();
    let ca_key = ndn_security::cert_name::new_key_name(&ns().append("CA")).unwrap();
    mgr.generate_ed25519(ca_key.clone()).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
    mgr.certify(&ca_key, ca_pub, &root_key, 3_650 * DAY_MS)
        .await
        .unwrap();

    let mut context = SignedTrustContext::decode_content(&earlier.content, 2).unwrap();
    for key in revoke {
        context = context.with_revocation(key.clone());
    }
    assert!(context.add_anchor(anchor));
    let context = Arc::new(context);
    let keyring = Arc::new(Keyring::new());
    assert!(keyring.adopt(Arc::clone(&context)));

    let ca = ca(mgr, ca_key.clone(), TokenStore::new());
    ca.accept_earlier_ca_certificates(keyring);
    Later {
        ca,
        ca_key,
        context,
    }
}

/// A member device enrolled at the earlier CA: its keyring holds the
/// context v1; it kept the issuer certificates of its enrollment.
struct Device {
    keyring: Arc<Keyring>,
    key: Arc<dyn Signer>,
    cert: Data,
    issuers: Vec<Bytes>,
}

async fn enroll(earlier: &Earlier) -> Device {
    let keyring = Arc::new(Keyring::new());
    adopt_with_tofu(&keyring, &earlier.context, &ns(), &earlier.fingerprint).unwrap();
    let uri = TrustEnvelope::Invite {
        ca_prefix: "/home/bob".into(),
        identity_namespace: "/home/bob/member".into(),
        token: "member-aa".into(),
        ttl_secs: None,
        anchor_fingerprint: Some(earlier.fingerprint),
        device: None,
    }
    .to_uri();
    let invite = InviteLink::from_uri(&uri).unwrap();
    let key_name = new_device_key_name(&invite.device_identity("phone").unwrap()).unwrap();
    let key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[1; 32], key_name));
    let enrolled = enroll_with_invite(
        &keyring,
        None,
        &mut Net::to(&earlier.ca),
        &invite,
        Arc::clone(&key),
    )
    .await
    .map_err(|f| f.error)
    .expect("the token enrolls the device");
    let issuers = enrolled
        .issued
        .issuers
        .iter()
        .map(|d| d.raw().clone())
        .collect();
    Device {
        keyring,
        key,
        cert: enrolled.issued.data,
        issuers,
    }
}

/// `device` renews at the later CA, passing `kept` as the issuer
/// certificates it kept.
async fn renew_keeping(
    later: &Later,
    device: &Device,
    kept: &[Bytes],
) -> Result<ndn_cert::IssuedCertificate, RenewalError> {
    let kept: Vec<Data> = kept
        .iter()
        .map(|w| Data::decode(w.clone()).unwrap())
        .collect();
    renew_certificate(
        &device.keyring,
        &mut Net::to(&later.ca),
        &device.cert,
        &kept,
        Arc::clone(&device.key),
    )
    .await
}

async fn renew(
    later: &Later,
    device: &Device,
) -> Result<ndn_cert::IssuedCertificate, RenewalError> {
    renew_keeping(later, device, &device.issuers).await
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The later CA's verdict on a renewal of `cert` by `signer`, carrying
/// `issuers` as its chain, sent as-is (no device-side checks).
async fn raw_renewal(
    later: &Later,
    signer: Arc<dyn Signer>,
    cert: &Data,
    issuers: &[&Data],
) -> Result<Name, CertError> {
    let cert_name = (*cert.name).clone();
    let certificate = b64(cert.raw());
    let issuers: Vec<serde_json::Value> = issuers.iter().map(|d| b64(d.raw()).into()).collect();
    let proof_key = Arc::clone(&signer);
    ndn_cert::client::enroll(
        &mut Net::to(&later.ca),
        &ns(),
        signer,
        0,
        RENEWAL_CHALLENGE,
        move |round| {
            let proof_key = Arc::clone(&proof_key);
            let cert_name = cert_name.clone();
            let certificate = certificate.clone();
            let issuers = issuers.clone();
            async move {
                if round.round > 0 {
                    return Ok(None);
                }
                let proof = proof_key
                    .sign(&renewal_proof_message(&round.request_id, &cert_name))
                    .await?;
                let mut params = serde_json::Map::new();
                params.insert(CERT_NAME_PARAM.into(), cert_name.to_string().into());
                params.insert(PROOF_PARAM.into(), b64(&proof).into());
                params.insert(CERTIFICATE_PARAM.into(), certificate.into());
                params.insert(ISSUERS_PARAM.into(), serde_json::Value::Array(issuers));
                Ok(Some(params))
            }
        },
    )
    .await
}

/// A device key `/home/bob/member/<device>/KEY/…` and a certificate for it
/// signed by `issuer_key`, held by `mgr`.
async fn certified_device(
    mgr: &SecurityManager,
    issuer_key: &Name,
    device: &str,
    seed: u8,
) -> (Arc<dyn Signer>, Data) {
    let key_name = new_device_key_name(&ns().append("member").append(device)).unwrap();
    let key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
    let cert = mgr
        .certify(
            &key_name,
            key.public_key().unwrap(),
            issuer_key,
            30 * DAY_MS,
        )
        .await
        .unwrap();
    (key, Data::decode(cert.data_wire().unwrap()).unwrap())
}

/// The device renews its earlier CA's certificate at the later CA: the
/// same key, now certified by the later CA's key. The later CA then serves
/// the earlier CA's certificate by its key name, without listing it among
/// the certificates it issued.
#[tokio::test]
async fn a_device_renews_an_earlier_ca_certificate_at_the_later_ca() {
    let earlier = earlier().await;
    let device = enroll(&earlier).await;
    let earlier_ca_key = ca_key_name(&ns());
    let kept: Vec<Name> = device
        .issuers
        .iter()
        .map(|w| (*Data::decode(w.clone()).unwrap().name).clone())
        .collect();
    assert_eq!(
        kept.len(),
        1,
        "the issuer chain short of the anchor: {kept:?}"
    );
    assert!(ndn_security::cert_name::is_cert_of(
        &kept[0],
        &earlier_ca_key
    ));

    let later = later(&earlier, &[]).await;
    assert!(later.ca.cert_for_interest(&earlier_ca_key, true).is_none());
    // The device follows the context naming the new root, as it would.
    assert!(device.keyring.adopt(Arc::clone(&later.context)));

    let renewed = renew(&later, &device)
        .await
        .expect("a current certificate of the earlier CA renews at the later CA");
    let old = ndn_security::Certificate::decode(&device.cert).unwrap();
    assert!(
        renewed.cert.name.has_prefix(device.key.key_name()),
        "for the same key name"
    );
    assert_eq!(renewed.cert.public_key, old.public_key, "for the same key");
    assert_eq!(
        renewed.issuer.as_ref(),
        Some(&later.ca_key),
        "by the later CA"
    );

    let served = later
        .ca
        .cert_for_interest(&earlier_ca_key, true)
        .expect("the later CA serves the earlier CA's certificate");
    assert_eq!(Bytes::from(served), device.issuers[0]);
    assert_eq!(
        later.ca.issued_under(&ns()),
        vec![((*renewed.cert.name).clone(), false)],
        "the earlier CA's certificate is not one the later CA issued"
    );
}

/// With the earlier CA's certificate served by nobody, the device's kept
/// issuer chain is the only way to it: passing none, the later CA refuses
/// (nothing issued, the earlier CA's certificate not served); passing the
/// kept chain, the same device renews. Mobile hosts rely on this: they
/// persist the chain and hand it back to `renew_certificate`.
#[tokio::test]
async fn only_the_kept_issuer_chain_renews_once_nobody_serves_the_earlier_ca() {
    let earlier = earlier().await;
    let device = enroll(&earlier).await;
    let earlier_ca_key = ca_key_name(&ns());
    let later = later(&earlier, &[]).await;
    assert!(device.keyring.adopt(Arc::clone(&later.context)));
    assert!(later.ca.cert_for_interest(&earlier_ca_key, true).is_none());

    let refused = renew_keeping(&later, &device, &[]).await;
    assert!(
        matches!(refused, Err(RenewalError::Refused { .. })),
        "{refused:?}"
    );
    assert!(later.ca.issued_under(&ns()).is_empty(), "nothing issued");
    assert!(later.ca.cert_for_interest(&earlier_ca_key, true).is_none());

    let renewed = renew(&later, &device)
        .await
        .expect("the kept issuer chain renews the earlier CA's certificate");
    assert_eq!(
        renewed.issuer.as_ref(),
        Some(&later.ca_key),
        "by the later CA"
    );
    assert!(later.ca.cert_for_interest(&earlier_ca_key, true).is_some());
}

/// A context that revokes the earlier CA's key: the later CA refuses to
/// renew the certificates it issued, issues nothing and does not serve it.
#[tokio::test]
async fn a_revoked_earlier_ca_is_refused() {
    let earlier = earlier().await;
    let device = enroll(&earlier).await;
    let earlier_ca_key = ca_key_name(&ns());
    let later = later(&earlier, std::slice::from_ref(&earlier_ca_key)).await;

    // The device still holds v1: it sends its chain as before.
    let refused = renew(&later, &device).await;
    assert!(
        matches!(refused, Err(RenewalError::Refused { .. })),
        "{refused:?}"
    );
    assert!(later.ca.issued_under(&ns()).is_empty(), "nothing issued");
    assert!(later.ca.cert_for_interest(&earlier_ca_key, true).is_none());
}

/// A certificate whose issuer is no key of `/home/bob/CA`, or whose chain
/// reaches no anchor of the context, is refused, and nothing is issued or
/// served.
#[tokio::test]
async fn an_issuer_outside_the_ca_or_off_the_chain_is_refused() {
    let earlier = earlier().await;
    let later = later(&earlier, &[]).await;

    // Certified by the root R1 directly: no CA issued it.
    let (key, cert) = certified_device(&earlier.mgr, &earlier.root_key, "laptop", 2).await;
    let refused = raw_renewal(&later, key, &cert, &[]).await;
    assert!(refused.is_err(), "{refused:?}");

    // Certified by a key of `/home/bob/CA` that a root outside the context
    // certified, with that chain carried.
    let mgr = SecurityManager::new();
    let fake_root = ns().append("KEY").append("fake");
    mgr.generate_ed25519(fake_root.clone()).unwrap();
    let fake_pub = mgr
        .get_signer_sync(&fake_root)
        .unwrap()
        .public_key()
        .unwrap();
    let fake_anchor = mgr
        .issue_self_signed_async(&fake_root, fake_pub, u64::MAX)
        .await
        .unwrap();
    let rogue_ca = ns().append("CA").append("KEY").append("rogue");
    mgr.generate_ed25519(rogue_ca.clone()).unwrap();
    let rogue_pub = mgr
        .get_signer_sync(&rogue_ca)
        .unwrap()
        .public_key()
        .unwrap();
    let rogue_cert = mgr
        .certify(&rogue_ca, rogue_pub, &fake_root, 3_650 * DAY_MS)
        .await
        .unwrap();
    let (key, cert) = certified_device(&mgr, &rogue_ca, "tablet", 3).await;
    let chain = [
        Data::decode(rogue_cert.data_wire().unwrap()).unwrap(),
        Data::decode(fake_anchor.data_wire().unwrap()).unwrap(),
    ];
    let refused = raw_renewal(&later, key, &cert, &[&chain[0], &chain[1]]).await;
    assert!(refused.is_err(), "{refused:?}");

    assert!(later.ca.issued_under(&ns()).is_empty(), "nothing issued");
    assert!(later.ca.cert_for_interest(&rogue_ca, true).is_none());
}
