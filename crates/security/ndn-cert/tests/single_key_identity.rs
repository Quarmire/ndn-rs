//! A device identity `/<ns>/<role>/<device>` holds one certified key at a
//! time on a namespace CA (`RolePolicy`): an invite token never certifies a key
//! under a name the CA already certified to another key, so a token cannot
//! take over an enrolled device's name. Only revoking the old certificate or
//! an admin's device approval lets a new key have the name.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::challenge::device_approval::{DeviceApprovalChallenge, PendingApprovalStore};
use ndn_cert::{
    CaExchange, CertError, HierarchicalPolicy, InviteEnrollError, InviteLink, RevokeStatus,
    RolePolicy, TokenChallenge, TokenStore, adopt_with_tofu, anchor_fingerprint, ca_key_name,
    enroll_with_invite, init_namespace, new_device_key_name,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Certificate, Ed25519Signer, Keyring, SecurityManager, Signer};
use ndn_trust_envelope::TrustEnvelope;

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

/// Routes Interests straight into a `CaState`.
#[derive(Clone)]
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
        } else if verb(b"REVOKE").is_some() {
            self.0.handle_revoke(&params()).await
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

struct RootDevice {
    wire: CaWire,
    keyring: Arc<Keyring>,
    fingerprint: [u8; 32],
    approvals: PendingApprovalStore,
}

/// A namespace CA for `/home/bob` issuing by role, offering a `token` challenge
/// (the given member tokens) and a `device-approval` challenge; plus a
/// device keyring that holds the root device's trust context.
async fn root_dev(tokens: &[&str]) -> RootDevice {
    let mgr = SecurityManager::new();
    let root_dev = init_namespace(&mgr, &ns()).unwrap();
    let ca_key = ca_key_name(&ns());
    mgr.generate_ed25519(ca_key.clone()).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
    mgr.certify(&ca_key, ca_pub, &root_dev.anchor_key, 3_650 * 86_400 * 1_000)
        .await
        .unwrap();
    let store = TokenStore::new();
    for token in tokens {
        store.add_scoped(*token, None, Some(ns().append("member")));
    }
    let approvals = PendingApprovalStore::new();
    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![
        Box::new(TokenChallenge::new(store)),
        Box::new(DeviceApprovalChallenge::new(approvals.clone())),
    ];
    let mut config = CaConfig::new(
        ns(),
        "namespace CA".to_string(),
        Duration::from_secs(90 * 86_400),
        Duration::from_secs(90 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .with_signing_key(ca_key);
    config.issuance = Box::new(RolePolicy::new(ns()));

    let context = Data::decode(root_dev.context_data.raw().clone()).unwrap();
    let fingerprint = anchor_fingerprint(&root_dev.anchor);
    let keyring = Arc::new(Keyring::new());
    adopt_with_tofu(&keyring, &context, &ns(), &fingerprint).unwrap();
    RootDevice {
        wire: CaWire(Arc::new(CaState::new(config, Arc::new(mgr)))),
        keyring,
        fingerprint,
        approvals,
    }
}

/// A fresh key (`seed`) for `/home/bob/member/<device>`.
fn key(device: &str, seed: u8) -> Arc<dyn Signer> {
    let identity = ns().append("member").append(device);
    Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        new_device_key_name(&identity),
    ))
}

/// Enroll `key` with a member invite carrying `token`.
async fn enroll(
    root_dev: &RootDevice,
    token: &str,
    key: Arc<dyn Signer>,
) -> Result<Certificate, InviteEnrollError> {
    let uri = TrustEnvelope::Invite {
        ca_prefix: "/home/bob".into(),
        identity_namespace: "/home/bob/member".into(),
        token: token.into(),
        ttl_secs: None,
        anchor_fingerprint: Some(root_dev.fingerprint),
    }
    .to_uri();
    let invite = InviteLink::from_uri(&uri).unwrap();
    enroll_with_invite(
        &root_dev.keyring,
        None,
        &mut root_dev.wire.clone(),
        &invite,
        key,
    )
    .await
    .map(|e| e.issued.cert)
    .map_err(|f| f.error)
}

/// No token certifies a second key for a device name: not sequentially, and
/// not when two keys race for one free name (exactly one wins). A refused
/// request spends nothing: its token still enrolls under another name.
#[tokio::test]
async fn a_token_never_certifies_a_second_key_for_a_device_name() {
    let root_dev = root_dev(&["member-1", "member-2", "member-3", "member-4", "member-5"]).await;
    enroll(&root_dev, "member-1", key("phone", 1))
        .await
        .expect("first key for phone");

    let taken = enroll(&root_dev, "member-2", key("phone", 2)).await;
    assert!(
        matches!(taken, Err(InviteEnrollError::NameRefused(_))),
        "{taken:?}"
    );
    enroll(&root_dev, "member-2", key("tablet", 2))
        .await
        .expect("the refused request did not spend its token");

    let (a, b) = tokio::join!(
        enroll(&root_dev, "member-3", key("laptop", 3)),
        enroll(&root_dev, "member-4", key("laptop", 4)),
    );
    assert_eq!(
        [&a, &b].iter().filter(|r| r.is_ok()).count(),
        1,
        "racing keys for one name: {a:?} / {b:?}"
    );
    let (loser, loser_token) = if a.is_ok() {
        (key("laptop", 4), "member-4")
    } else {
        (key("laptop", 3), "member-3")
    };
    assert!(
        matches!(if a.is_ok() { &b } else { &a }, Err(InviteEnrollError::NameRefused(_))),
        "the race loser is refused by name: {a:?} / {b:?}"
    );
    enroll(&root_dev, loser_token, key("desk", 6))
        .await
        .expect("the race loser did not spend its token");
    let again = enroll(&root_dev, "member-5", loser).await;
    assert!(
        matches!(again, Err(InviteEnrollError::NameRefused(_))),
        "{again:?}"
    );
}

/// Once the certificate holding a name is revoked, a token certifies a new
/// key for it; while it is valid, only an admin's device approval does.
#[tokio::test]
async fn revocation_or_admin_approval_lets_a_new_key_have_the_name() {
    let root_dev = root_dev(&["member-1", "member-2", "member-3"]).await;
    let old = key("phone", 1);
    let cert = enroll(&root_dev, "member-1", Arc::clone(&old)).await.unwrap();

    // An admin approves a new key for the held name.
    let approved = key("phone", 2);
    let approvals = root_dev.approvals.clone();
    let approved_cert = ndn_cert::client::enroll(
        &mut root_dev.wire.clone(),
        &ns(),
        Arc::clone(&approved),
        86_400,
        "device-approval",
        move |round| {
            if round.round > 0 {
                for request in approvals.pending() {
                    approvals.approve(&request.id);
                }
            }
            std::future::ready(Ok(Some(serde_json::Map::new())))
        },
    )
    .await
    .expect("an admin's approval certifies a new key for a held name");

    // A token does not, until every valid certificate for it is revoked.
    let taken = enroll(&root_dev, "member-2", key("phone", 3)).await;
    assert!(
        matches!(taken, Err(InviteEnrollError::NameRefused(_))),
        "{taken:?}"
    );
    for (cert_name, holder) in [(cert.name.as_ref().clone(), old), (approved_cert, approved)] {
        let revoked = ndn_cert::client::revoke(&mut root_dev.wire.clone(), &ns(), &cert_name, holder)
            .await
            .unwrap();
        assert_eq!(revoked, RevokeStatus::Revoked);
    }
    enroll(&root_dev, "member-3", key("phone", 3))
        .await
        .expect("a token certifies a new key once the name's certificates are revoked");
}
