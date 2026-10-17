//! CA signer + durable state: a CA whose key is certified by an offline root
//! signs with that configured key (not the manager's "first trust anchor"),
//! and a CA backed by a `FileCaStore` keeps serving the certs it issued — and
//! refusing the ones it revoked — after a restart with the same keys.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::{CaExchange, CaStore, CertError, FileCaStore, HierarchicalPolicy, NopChallenge};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Certificate, Ed25519Signer, SecurityManager, Signer, VerifyOutcome};

const ROOT_SEED: [u8; 32] = [0x11; 32];
const CA_SEED: [u8; 32] = [0x22; 32];

fn root_key() -> Name {
    "/home/bob/KEY/root".parse().unwrap()
}

fn ca_key() -> Name {
    "/home/bob/CA/KEY/ca".parse().unwrap()
}

/// What a root device's PIB holds, rebuilt from fixed seeds so two calls model one
/// node across a restart: the root as the only trust anchor and the CA key
/// with a certificate issued by the root.
async fn root_manager() -> (Arc<SecurityManager>, Certificate) {
    let mgr = SecurityManager::new();
    mgr.generate_ed25519_from_seed(root_key(), &ROOT_SEED).unwrap();
    let root_pub = mgr.get_signer_sync(&root_key()).unwrap().public_key().unwrap();
    mgr.issue_self_signed(&root_key(), root_pub, u64::MAX).unwrap();

    mgr.generate_ed25519_from_seed(ca_key(), &CA_SEED).unwrap();
    let ca_pub = mgr.get_signer_sync(&ca_key()).unwrap().public_key().unwrap();
    let ca_cert = mgr
        .certify(&ca_key(), ca_pub, &root_key(), 3_650 * 86_400 * 1_000)
        .await
        .unwrap();
    (Arc::new(mgr), ca_cert)
}

fn config() -> CaConfig {
    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(NopChallenge::new())];
    CaConfig::new(
        "/home/bob".parse().unwrap(),
        "namespace CA".to_string(),
        Duration::from_secs(86_400),
        Duration::from_secs(7 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .with_signing_key(ca_key())
}

/// Routes the driver's Interests straight into a `CaState`.
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
            let rid: String = comps[i + 1].value.iter().map(|b| format!("{b:02x}")).collect();
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

async fn enroll(ca: &Arc<CaState>, who: &str, seed: u8) -> Data {
    let key: Name = format!("/home/bob/{who}/KEY/k1").parse().unwrap();
    let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key));
    let mut wire = CaWire(Arc::clone(ca));
    let mut params = Some(serde_json::Map::new());
    let cert_name = ndn_cert::client::enroll(
        &mut wire,
        &"/home/bob".parse().unwrap(),
        signer,
        86_400,
        "nop",
        |_| std::future::ready(Ok(params.take())),
    )
    .await
    .expect("enrollment succeeds");
    ndn_cert::client::fetch_issued_cert(&mut wire, &cert_name)
        .await
        .expect("issued cert is served")
}

async fn signed_by(data: &Data, signer_cert: &Certificate) -> bool {
    let cert = Certificate::decode(data).unwrap();
    matches!(
        ndn_security::verifier::verify_by_sig_type(
            cert.sig_type,
            data.signed_region(),
            data.sig_value(),
            &signer_cert.public_key,
        )
        .await,
        Ok(VerifyOutcome::Valid)
    )
}

/// The manager's only trust anchor is the root; the CA must still sign with
/// its configured, root-certified key and advertise that cert in INFO.
#[tokio::test]
async fn configured_signing_key_signs_issued_certs_not_first_anchor() {
    let (mgr, ca_cert) = root_manager().await;
    let ca = Arc::new(CaState::new(config(), mgr));

    let issued = enroll(&ca, "phone", 0x33).await;
    let issuer = Certificate::decode(&issued).unwrap().issuer.unwrap();
    assert_eq!(*issuer, ca_key(), "issued cert's KeyLocator is the CA key");
    assert!(signed_by(&issued, &ca_cert).await, "signed by the CA key");

    let (_, locator) = ca.response_signer().expect("CA has a response signer");
    // Responses name the CA certificate `<ca key>/<issuer>/<version>`.
    assert_eq!(ndn_security::cert_name::key_name_of(&locator), ca_key());
    assert_eq!(ca.ca_certificate().unwrap().key_name(), ca_key());
    // The CA cert itself is fetchable (by its key name, CanBePrefix) so
    // requesters can walk the chain.
    assert!(ca.cert_for_interest(&ca_key(), true).is_some());
    assert!(ca.get_served_cert(&locator.to_string()).is_some());
}

#[tokio::test]
async fn restarted_ca_serves_old_certs_and_chains_to_same_root() {
    let dir = tempfile::tempdir().unwrap();

    let (mgr, ca_cert_1) = root_manager().await;
    let store: Arc<dyn CaStore> = Arc::new(FileCaStore::open(dir.path()).unwrap());
    let ca = Arc::new(CaState::with_store(config(), mgr, store).unwrap());
    let first = enroll(&ca, "laptop", 0x44).await;
    let first_name = first.name.to_string();
    drop(ca);

    // Restart: same keys (same PIB), fresh process state, same store dir.
    let (mgr, ca_cert_2) = root_manager().await;
    let root = mgr.trust_anchor(&root_key()).unwrap();
    let store: Arc<dyn CaStore> = Arc::new(FileCaStore::open(dir.path()).unwrap());
    let ca = Arc::new(CaState::with_store(config(), mgr, store).unwrap());

    let served = ca
        .get_served_cert(&first_name)
        .expect("previously issued cert is still served after restart");
    assert_eq!(Bytes::from(served), first.raw().clone());

    let second = enroll(&ca, "phone", 0x55).await;
    for (issued, ca_cert) in [(&first, &ca_cert_1), (&second, &ca_cert_2)] {
        assert!(signed_by(issued, ca_cert).await, "issued cert signed by the CA key");
    }
    // Both CA certs are the same key certified by the same root.
    assert_eq!(ca_cert_1.public_key, ca_cert_2.public_key);
    for ca_cert in [&ca_cert_1, &ca_cert_2] {
        let wire = ndn_cert::ca::serialize_cert(ca_cert);
        let data = Data::decode(Bytes::from(wire)).unwrap();
        assert!(signed_by(&data, &root).await, "CA cert chains to the root");
    }
}

#[tokio::test]
async fn revocations_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let revoked = "/home/bob/stolen/KEY/k1";
    FileCaStore::open(dir.path())
        .unwrap()
        .record_revoked(revoked)
        .unwrap();

    let (mgr, _) = root_manager().await;
    let store: Arc<dyn CaStore> = Arc::new(FileCaStore::open(dir.path()).unwrap());
    let ca = CaState::with_store(config(), mgr, store).unwrap();
    assert!(ca.is_revoked(revoked));
    assert!(!ca.is_revoked("/home/bob/phone/KEY/k1"));
}
