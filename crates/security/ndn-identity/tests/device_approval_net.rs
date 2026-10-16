//! Cross-process NDNCERT device-approval over reflexive forwarding, end-to-end.
//!
//! An approver device (no inbound route) offers approval by advertising to the
//! CA's APPROVE-FEED with a reflexive name; the CA pulls the signed approval
//! Data back along the reverse path, validates it through its trust schema, and
//! records it in the shared PendingApprovalStore that its
//! DeviceApprovalChallenge reads.

use std::sync::Arc;
use std::time::Duration;

use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_cert::challenge::device_approval::{ApprovalState, PendingApprovalStore};
use ndn_engine::EngineConfig;
use ndn_identity::run_approver;
use ndn_security::{Ed25519Signer, Signer};

/// The canonical feed wired into NdncertCa: `serve_with_feed` runs the `/CA/*`
/// service and the validator-checked APPROVE-FEED together; a `run_approver`
/// device flips a pending request through it with a schema-authorized signed
/// approval.
#[tokio::test]
async fn ndncert_ca_serve_with_feed_approves() {
    use ndn_cert::challenge::device_approval::DeviceApprovalChallenge;
    use ndn_identity::{ApprovalFeed, Identity, NdncertCa};
    use ndn_security::{Certificate, SchemaRule, TrustSchema, Validator};

    // Approver key + a self-signed cert named by the key (the validator anchor),
    // authorized by the schema to approve the laptop's enrollment.
    let approver_name = "/lab/alice/devices/phone";
    let approver_key: Name = format!("{approver_name}/KEY/k1").parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[7u8; 32], approver_key.clone());
    let approver_cert = Certificate {
        name: Arc::new(approver_key.clone()),
        public_key: signer.public_key().unwrap(),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    };
    let mut schema = TrustSchema::new();
    schema.add_rule(
        SchemaRule::parse(
            "/lab/alice/devices/laptop/ndncert-approve/<rid> \
             => /lab/alice/devices/phone/KEY/<kid>",
        )
        .expect("rule parses"),
    );
    let validator = Arc::new(Validator::new(schema));
    validator.add_trust_anchor(approver_cert);

    let (ca_face, ca_handle) = InProcFace::new(FaceId(1), 64);
    let (feed_face, feed_handle) = InProcFace::new(FaceId(2), 64);
    let (side_face, side_handle) = InProcFace::new(FaceId(3), 64);
    let (adv_face, adv_handle) = InProcFace::new(FaceId(4), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(ca_face)
        .face(feed_face)
        .face(side_face)
        .face(adv_face)
        .build()
        .await
        .expect("engine build");

    let ca_prefix: Name = "/lab/ca/CA".parse().unwrap();
    let feed_prefix: Name = "/lab/ca/CA/APPROVE-FEED".parse().unwrap();
    engine.fib().add_nexthop(&ca_prefix, FaceId(1), 0);
    engine.fib().add_nexthop(&feed_prefix, FaceId(2), 0); // longer prefix wins

    // The CA's DeviceApprovalChallenge and the feed share one store.
    let store = PendingApprovalStore::new();
    let request_id = store.submit("/lab/alice/devices/laptop", "");

    let identity = Identity::ephemeral("/lab/ca").unwrap();
    let ca = NdncertCa::builder()
        .name("/lab/ca")
        .unwrap()
        .signing_identity(&identity)
        .challenge_box(Box::new(DeviceApprovalChallenge::new(store.clone())))
        .build()
        .unwrap();

    let feed = ApprovalFeed::validated(store.clone(), validator).timeout(Duration::from_secs(2));
    let ca_task = tokio::spawn(ca.serve_with_feed(
        Producer::from_handle(ca_handle, ca_prefix.clone()),
        feed,
        Producer::from_handle(feed_handle, feed_prefix.clone()),
        Consumer::from_handle(side_handle),
    ));

    let feed_for_approver = feed_prefix.clone();
    let approver = tokio::spawn(async move {
        let mut consumer = Consumer::from_handle(adv_handle);
        run_approver(
            &mut consumer,
            feed_for_approver,
            approver_name,
            &signer,
            |_c, _i| async { true },
            Duration::from_millis(800),
        )
        .await
    });

    let mut approved = false;
    for _ in 0..60 {
        if store
            .get(&request_id)
            .map(|e| e.state == ApprovalState::Approved)
            .unwrap_or(false)
        {
            approved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        approved,
        "serve_with_feed must run the APPROVE-FEED and record the validated approval"
    );
    assert_eq!(
        store.get(&request_id).unwrap().approver.as_deref(),
        Some("/lab/alice/devices/phone/KEY/k1"),
        "recorded via the validator-checked path"
    );

    drop(engine);
    shutdown.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), approver).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), ca_task).await;
}

/// Canonical path: the approver sends a real *signed approval Data* named
/// `<subject>/ndncert-approve/<req>`; the CA validates it through a `Validator`
/// whose trust schema authorizes the approver — evaluated over the real
/// `(data_name, signer-cert-name)`, exactly like NDN signature validation. No
/// synthetic names, no bare identities.
#[tokio::test]
async fn canonical_signed_approval_validated_via_schema() {
    use ndn_identity::offer_signed_approval;
    use ndn_security::{Certificate, Ed25519Signer, SchemaRule, Signer, TrustSchema, Validator};

    let (adv_face, adv_handle) = InProcFace::new(FaceId(1), 64);
    let (serve_face, serve_handle) = InProcFace::new(FaceId(2), 64);
    let (pull_face, pull_handle) = InProcFace::new(FaceId(3), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(adv_face)
        .face(serve_face)
        .face(pull_face)
        .build()
        .await
        .expect("engine build");
    let feed: Name = "/lab/ca/CA/APPROVE-FEED".parse().unwrap();
    engine.fib().add_nexthop(&feed, FaceId(2), 0);

    let store = PendingApprovalStore::new();
    let request_id = store.submit("/lab/alice/devices/laptop", "");

    // Approver key + a self-signed cert named by the key (the validator anchor).
    let approver_key: Name = "/lab/alice/devices/phone/KEY/k1".parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[7u8; 32], approver_key.clone());
    let pubkey = signer.public_key().unwrap();
    let approver_cert = Certificate {
        name: std::sync::Arc::new(approver_key.clone()),
        public_key: pubkey,
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    };

    // Canonical schema rule over the REAL (approval data name, signer key name).
    let mut schema = TrustSchema::new();
    schema.add_rule(
        SchemaRule::parse(
            "/lab/alice/devices/laptop/ndncert-approve/<rid> \
             => /lab/alice/devices/phone/KEY/<kid>",
        )
        .expect("rule parses"),
    );
    let validator = Arc::new(Validator::new(schema));
    validator.add_trust_anchor(approver_cert);

    // Exercise the ergonomic builder (wraps serve_approve_feed_validated).
    let ca_feed = ndn_identity::ApprovalFeed::validated(store.clone(), Arc::clone(&validator))
        .timeout(Duration::from_secs(2));
    let ca = tokio::spawn(ca_feed.serve(
        Producer::from_handle(serve_handle, feed.clone()),
        Consumer::from_handle(pull_handle),
    ));

    let mut approver = Consumer::from_handle(adv_handle);
    let approved = offer_signed_approval(
        &mut approver,
        feed.clone(),
        "/lab/alice/devices/phone",
        &signer,
        |_c, _i| async { true },
        Duration::from_secs(3),
    )
    .await
    .expect("offer_signed_approval");
    assert!(approved, "approver signed an approval this cycle");

    let entry = store.get(&request_id).expect("request present");
    assert_eq!(entry.state, ApprovalState::Approved);
    assert!(
        !entry.signed_approval.is_empty(),
        "the approval Data's signature value is recorded as evidence"
    );
    assert_eq!(
        entry.approver.as_deref(),
        Some("/lab/alice/devices/phone/KEY/k1"),
        "approver is the validated signer cert/key name (canonical), not a bare identity",
    );

    drop(approver);
    drop(engine);
    shutdown.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), ca).await;
}

/// Same canonical path, but the schema authorizes a *different* device — the
/// validator rejects the approval, so the request stays pending.
#[tokio::test]
async fn canonical_approval_denied_by_schema() {
    use ndn_identity::{offer_signed_approval, serve_approve_feed_validated};
    use ndn_security::{Certificate, Ed25519Signer, SchemaRule, Signer, TrustSchema, Validator};

    let (adv_face, adv_handle) = InProcFace::new(FaceId(1), 64);
    let (serve_face, serve_handle) = InProcFace::new(FaceId(2), 64);
    let (pull_face, pull_handle) = InProcFace::new(FaceId(3), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(adv_face)
        .face(serve_face)
        .face(pull_face)
        .build()
        .await
        .expect("engine build");
    let feed: Name = "/lab/ca/CA/APPROVE-FEED".parse().unwrap();
    engine.fib().add_nexthop(&feed, FaceId(2), 0);

    let store = PendingApprovalStore::new();
    let request_id = store.submit("/lab/alice/devices/laptop", "");

    let approver_key: Name = "/lab/alice/devices/phone/KEY/k1".parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[7u8; 32], approver_key.clone());
    let approver_cert = Certificate {
        name: std::sync::Arc::new(approver_key.clone()),
        public_key: signer.public_key().unwrap(),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    };

    // Schema authorizes only /lab/bob/... — not the phone.
    let mut schema = TrustSchema::new();
    schema.add_rule(
        SchemaRule::parse(
            "/lab/alice/devices/laptop/ndncert-approve/<rid> => /lab/bob/devices/x/KEY/<kid>",
        )
        .unwrap(),
    );
    let validator = Arc::new(Validator::new(schema));
    validator.add_trust_anchor(approver_cert);

    let ca = tokio::spawn(serve_approve_feed_validated(
        Producer::from_handle(serve_handle, feed.clone()),
        Consumer::from_handle(pull_handle),
        store.clone(),
        Arc::clone(&validator),
        Duration::from_secs(2),
    ));

    let mut approver = Consumer::from_handle(adv_handle);
    let _ = offer_signed_approval(
        &mut approver,
        feed.clone(),
        "/lab/alice/devices/phone",
        &signer,
        |_c, _i| async { true },
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(
        store.get(&request_id).unwrap().state,
        ApprovalState::Pending,
        "schema does not authorize the phone; the validator rejects the approval",
    );

    drop(approver);
    drop(engine);
    shutdown.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), ca).await;
}
