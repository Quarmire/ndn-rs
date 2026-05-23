//! Challenge attestations, end-to-end.
//!
//! Drives a full client↔CA enrollment (NEW → CHALLENGE) and asserts:
//!
//! - With `emit_attestations = false` (the default), the issued cert
//!   carries **no** `AdditionalDescription` — byte-identical to the
//!   pre-attestation behaviour.
//! - With `emit_attestations = true`, the issued cert carries a parseable
//!   [`AttestationSet`] recording the challenge that was satisfied, and the
//!   bytes round-trip through `serialize_cert`/`deserialize_cert` (i.e. they
//!   live inside the CA-signed region).

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::ca::{CaConfig, CaState, deserialize_cert};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::client::EnrollmentSession;
use ndn_cert::{AttestationSet, Combinator, HierarchicalPolicy, NopChallenge};
use ndn_packet::Name;
use ndn_security::{Ed25519Signer, SecurityManager};

fn make_ca(emit_attestations: bool) -> Arc<CaState> {
    let mgr = Arc::new(SecurityManager::new());
    let ca_key_name: Name = "/registry/CA/KEY/k1/self/v=1".parse().unwrap();
    mgr.generate_ed25519(ca_key_name.clone()).unwrap();
    let ca_pubkey = mgr
        .get_signer_sync(&ca_key_name)
        .unwrap()
        .public_key()
        .unwrap();
    let ca_cert = mgr
        .issue_self_signed(&ca_key_name, ca_pubkey, 365 * 24 * 3600 * 1_000)
        .unwrap();
    mgr.add_trust_anchor(ca_cert);

    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(NopChallenge)];
    let config = CaConfig::new(
        "/registry/CA".parse().unwrap(),
        "attestation test CA".into(),
        Duration::from_secs(86_400),
        Duration::from_secs(7 * 86_400),
        challenges,
        Box::new(HierarchicalPolicy),
    )
    .emit_attestations(emit_attestations);
    Arc::new(CaState::new(config, mgr))
}

/// Run NEW → CHALLENGE with NopChallenge; return the served cert's wire bytes.
async fn enroll_and_fetch_cert(state: Arc<CaState>, requested_name: &str) -> Vec<u8> {
    let key_name: Name = format!("{requested_name}/KEY/k1").parse().unwrap();
    let seed = [0xCDu8; 32];
    let signer = Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));
    let mut session = EnrollmentSession::new(key_name, signer, 86_400);

    let new_body = session.new_request_body().await.unwrap();
    let new_resp = state.handle_new(&new_body).await.unwrap();
    session.handle_new_response(&new_resp).unwrap();

    let chal_body = session
        .challenge_request_body("nop", serde_json::Map::new())
        .unwrap();
    let request_id = session.request_id().unwrap().to_string();
    let chal_resp = state
        .handle_challenge(&request_id, &chal_body)
        .await
        .unwrap();
    session.handle_challenge_response(&chal_resp).unwrap();

    let issued = session
        .issued_cert_name()
        .expect("cert should have been issued")
        .to_string();
    state
        .get_served_cert(&issued)
        .expect("served cert bytes should be present")
}

#[tokio::test]
async fn default_ca_issues_cert_without_attestation() {
    let state = make_ca(false);
    let wire = enroll_and_fetch_cert(state, "/registry/zone-a/device/x").await;
    let cert = deserialize_cert(&wire).expect("issued cert should decode");
    assert!(
        AttestationSet::from_cert(&cert).is_none(),
        "default CA must not embed attestations"
    );
}

#[tokio::test]
async fn emitting_ca_embeds_parseable_attestation() {
    let state = make_ca(true);
    let wire = enroll_and_fetch_cert(state, "/registry/zone-a/device/y").await;
    let cert = deserialize_cert(&wire).expect("issued cert should decode");

    let set = AttestationSet::from_cert(&cert)
        .expect("emitting CA must embed a parseable attestation set");
    assert_eq!(set.combinator, Combinator::Single);
    assert_eq!(set.leaves.len(), 1);
    assert_eq!(set.leaves[0].kind, "nop");
    assert!(
        set.leaves[0].performed_at > 0,
        "CA must stamp performed_at on emitted leaves"
    );

    // The attestation lives inside the signed region, so it survives the
    // serialize → deserialize round-trip the cert-fetch path uses.
    let reserialized = ndn_cert::ca::serialize_cert(&cert);
    let cert2 = deserialize_cert(&reserialized).expect("re-decode");
    assert_eq!(AttestationSet::from_cert(&cert2), Some(set));
}
