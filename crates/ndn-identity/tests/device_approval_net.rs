//! Cross-process NDNCERT device-approval over reflexive forwarding, end-to-end.
//!
//! An approver device (no inbound route) offers approval by advertising to the
//! CA's APPROVE-FEED with a reflexive name; the CA pulls the signed approval
//! back along the reverse path, verifies it, and records it in the shared
//! PendingApprovalStore that its DeviceApprovalChallenge reads.

use std::sync::Arc;
use std::time::Duration;

use ndn_face_native::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_cert::challenge::device_approval::{ApprovalState, PendingApprovalStore};
use ndn_engine::EngineConfig;
use ndn_identity::{
    StaticTrustedApprovers, offer_approval, pull_and_record_approval, run_approver,
    serve_approve_feed,
};
use ndn_security::{Ed25519Signer, Signer};

#[tokio::test]
async fn cross_process_device_approval_over_reflexive() {
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

    // Shared store with one pending device-approval request (as the CA's
    // DeviceApprovalChallenge would create on a CHALLENGE round).
    let store = PendingApprovalStore::new();
    let cert_name = "/lab/alice/devices/laptop";
    let request_id = store.submit(cert_name, "laptop enrollment");

    // Approver identity + signing key.
    let approver_name = "/lab/alice/devices/phone";
    let approver_key: Name = format!("{approver_name}/KEY/k1").parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[9u8; 32], approver_key);
    let approver_pubkey = signer.public_key().unwrap().to_vec();

    // CA APPROVE-FEED producer: on the approver's forward Interest, pull and
    // record the signed approval for the pending request, then release.
    let producer = Producer::from_handle(serve_handle, feed.clone());
    let side = Arc::new(tokio::sync::Mutex::new(Consumer::from_handle(pull_handle)));
    let ca_store = store.clone();
    let ca_pubkey = approver_pubkey.clone();
    let ca_approver = approver_name.to_string();
    let ca = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let side = Arc::clone(&side);
                let store = ca_store.clone();
                let pubkey = ca_pubkey.clone();
                let approver = ca_approver.clone();
                async move {
                    if let Some(req) = store.pending().into_iter().next() {
                        let resolve =
                            |name: &str| (name == approver.as_str()).then(|| pubkey.clone());
                        let mut sc = side.lock().await;
                        let _ = pull_and_record_approval(
                            &mut sc,
                            &store,
                            &interest,
                            &req.cert_name,
                            &req.id,
                            resolve,
                            Duration::from_secs(2),
                        )
                        .await;
                    }
                    responder
                        .respond((*interest.name).clone(), b"ok".to_vec())
                        .await
                        .ok();
                }
            })
            .await
    });

    // Approver offers approval (auto-approves this enrollment).
    let mut approver = Consumer::from_handle(adv_handle);
    let approved = offer_approval(
        &mut approver,
        feed.clone(),
        approver_name,
        &signer,
        |_cert, _id| async { true },
        Duration::from_secs(3),
    )
    .await
    .expect("offer_approval cycle");
    assert!(approved, "approver should report it approved this cycle");

    // The store now carries a verified, signed cross-process approval.
    let entry = store.get(&request_id).expect("request present");
    assert_eq!(entry.state, ApprovalState::Approved);
    assert_eq!(entry.approver.as_deref(), Some(approver_name));
    assert!(
        !entry.signed_approval.is_empty(),
        "approver's signature over the approval statement was recorded"
    );

    drop(approver);
    drop(engine);
    shutdown.shutdown().await;
    let _ = ca.await;
}

#[tokio::test]
async fn untrusted_approver_is_not_recorded() {
    // Same flow, but the CA resolves no key for the approver → no approval
    // recorded even though the approver answers.
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

    let signer = Ed25519Signer::from_seed(&[9u8; 32], "/lab/eve/KEY/k1".parse().unwrap());

    let producer = Producer::from_handle(serve_handle, feed.clone());
    let side = Arc::new(tokio::sync::Mutex::new(Consumer::from_handle(pull_handle)));
    let ca_store = store.clone();
    let ca = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let side = Arc::clone(&side);
                let store = ca_store.clone();
                async move {
                    if let Some(req) = store.pending().into_iter().next() {
                        let mut sc = side.lock().await;
                        // No approver is trusted: resolve always returns None.
                        let _ = pull_and_record_approval(
                            &mut sc,
                            &store,
                            &interest,
                            &req.cert_name,
                            &req.id,
                            |_name| None,
                            Duration::from_secs(2),
                        )
                        .await;
                    }
                    responder
                        .respond((*interest.name).clone(), b"ok".to_vec())
                        .await
                        .ok();
                }
            })
            .await
    });

    let mut approver = Consumer::from_handle(adv_handle);
    let _ = offer_approval(
        &mut approver,
        feed.clone(),
        "/lab/eve",
        &signer,
        |_c, _i| async { true },
        Duration::from_secs(3),
    )
    .await;

    let entry = store.get(&request_id).expect("request present");
    assert_eq!(
        entry.state,
        ApprovalState::Pending,
        "an untrusted approver must not flip the request"
    );

    drop(approver);
    drop(engine);
    shutdown.shutdown().await;
    let _ = ca.await;
}

/// The long-running loops with real `did:ndn` resolution: a `serve_approve_feed`
/// CA and a `run_approver` device, with the CA resolving the approver's key from
/// a DID resolver wired to a fixture cert fetcher.
#[tokio::test]
async fn approve_feed_loop_with_did_resolution() {
    use std::future::Future;
    use std::pin::Pin;

    use bytes::Bytes;
    use ndn_packet::Data;
    use ndn_security::did::UniversalResolver;
    use ndn_security::{CertCache, CertFetcher, FetchFn, SecurityManager};

    // Approver identity with a self-signed cert resolvable via did:ndn.
    let mgr = SecurityManager::new();
    let approver_name = "/lab/alice/devices/phone";
    let key_name: Name = format!("{approver_name}/KEY/k1").parse().unwrap();
    mgr.generate_ed25519(key_name.clone()).unwrap();
    let signer = mgr.get_signer_sync(&key_name).unwrap();
    let pubkey = signer.public_key().unwrap();
    let cert = mgr
        .issue_self_signed(&key_name, pubkey, 365 * 24 * 3600 * 1000)
        .unwrap();
    let cert_wire = ndn_cert::ca::serialize_cert(&cert);

    let fetch_fn: FetchFn = Arc::new(move |_name: Name| {
        let cw = cert_wire.clone();
        Box::pin(async move { Data::decode(Bytes::from(cw)).ok() })
            as Pin<Box<dyn Future<Output = Option<Data>> + Send>>
    });
    let fetcher = Arc::new(CertFetcher::new(
        Arc::new(CertCache::new()),
        fetch_fn,
        Duration::from_secs(1),
    ));
    let resolver = Arc::new(UniversalResolver::with_cert_fetcher(fetcher));

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

    let authorizer = Arc::new(
        StaticTrustedApprovers::new()
            .allow("/lab/alice".parse().unwrap(), "/lab/alice/devices/phone"),
    );
    let ca = tokio::spawn(serve_approve_feed(
        Producer::from_handle(serve_handle, feed.clone()),
        Consumer::from_handle(pull_handle),
        store.clone(),
        Arc::clone(&resolver),
        authorizer,
        Duration::from_secs(2),
    ));

    let feed_for_approver = feed.clone();
    let approver_owned = approver_name.to_string();
    let approver = tokio::spawn(async move {
        let mut consumer = Consumer::from_handle(adv_handle);
        run_approver(
            &mut consumer,
            feed_for_approver,
            &approver_owned,
            signer.as_ref(),
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
    assert!(approved, "feed loop must approve the pending request via DID resolution");
    let entry = store.get(&request_id).unwrap();
    assert_eq!(entry.approver.as_deref(), Some(approver_name));
    assert!(!entry.signed_approval.is_empty());

    drop(engine);
    shutdown.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), approver).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), ca).await;
}

/// The trustedApprovers gate denies an approver not listed for the subject's
/// principal — short-circuiting before any reverse pull, so the request stays
/// pending. (No engine traffic: the gate returns before touching the wire.)
#[tokio::test]
async fn unauthorized_approver_is_gated_before_pull() {
    use ndn_app::random_reflexive_name;
    use ndn_packet::Interest;
    use ndn_packet::encode::InterestBuilder;
    use ndn_security::did::UniversalResolver;
    use ndn_identity::{StaticTrustedApprovers, pull_and_record_approval_with_resolver};

    let (_face, handle) = InProcFace::new(FaceId(1), 64);
    let mut side = Consumer::from_handle(handle);

    let store = PendingApprovalStore::new();
    let cert_name = "/lab/alice/devices/laptop";
    let request_id = store.submit(cert_name, "");

    // Approver "/lab/eve" advertises, but is not a trusted approver for /lab/alice.
    let hello = serde_json::json!({ "approver": "/lab/eve" }).to_string();
    let forward = Interest::decode(
        InterestBuilder::new("/lab/ca/CA/APPROVE-FEED")
            .app_parameters(hello.into_bytes())
            .reflexive_name(random_reflexive_name())
            .build(),
    )
    .unwrap();

    let resolver = Arc::new(UniversalResolver::new());
    let authorizer = StaticTrustedApprovers::new()
        .allow("/lab/alice".parse().unwrap(), "/lab/alice/devices/phone");

    let recorded = pull_and_record_approval_with_resolver(
        &mut side,
        &store,
        &forward,
        cert_name,
        &request_id,
        &resolver,
        &authorizer,
        Duration::from_millis(200),
    )
    .await
    .expect("gate returns cleanly");

    assert!(!recorded, "unauthorized approver must not be recorded");
    assert_eq!(store.get(&request_id).unwrap().state, ApprovalState::Pending);
}

/// Build an approver identity with a self-signed cert and a DID resolver that
/// resolves it (fixture cert fetcher). Returns (signer, resolver).
fn approver_did_setup(
    approver_name: &str,
) -> (
    Arc<dyn Signer>,
    Arc<ndn_security::did::UniversalResolver>,
) {
    use std::future::Future;
    use std::pin::Pin;

    use bytes::Bytes;
    use ndn_packet::Data;
    use ndn_security::did::UniversalResolver;
    use ndn_security::{CertCache, CertFetcher, FetchFn, SecurityManager};

    let mgr = SecurityManager::new();
    let key_name: Name = format!("{approver_name}/KEY/k1").parse().unwrap();
    mgr.generate_ed25519(key_name.clone()).unwrap();
    let signer = mgr.get_signer_sync(&key_name).unwrap();
    let pubkey = signer.public_key().unwrap();
    let cert = mgr
        .issue_self_signed(&key_name, pubkey, 365 * 24 * 3600 * 1000)
        .unwrap();
    let cert_wire = ndn_cert::ca::serialize_cert(&cert);
    let fetch_fn: FetchFn = Arc::new(move |_n: Name| {
        let cw = cert_wire.clone();
        Box::pin(async move { Data::decode(Bytes::from(cw)).ok() })
            as Pin<Box<dyn Future<Output = Option<Data>> + Send>>
    });
    let fetcher = Arc::new(CertFetcher::new(
        Arc::new(CertCache::new()),
        fetch_fn,
        Duration::from_secs(1),
    ));
    (signer, Arc::new(UniversalResolver::with_cert_fetcher(fetcher)))
}

/// The feed wired into NdncertCa: `serve_with_feed` runs the `/CA/*` service and
/// the APPROVE-FEED together; an approver flips a pending request through it.
#[tokio::test]
async fn ndncert_ca_serve_with_feed_approves() {
    use ndn_cert::challenge::device_approval::DeviceApprovalChallenge;
    use ndn_identity::{ApproveFeed, NdnIdentity, NdncertCa, StaticTrustedApprovers};

    let approver_name = "/lab/alice/devices/phone";
    let (signer, resolver) = approver_did_setup(approver_name);

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

    let identity = NdnIdentity::ephemeral("/lab/ca").unwrap();
    let ca = NdncertCa::builder()
        .name("/lab/ca")
        .unwrap()
        .signing_identity(&identity)
        .challenge_box(Box::new(DeviceApprovalChallenge::new(store.clone())))
        .build()
        .unwrap();

    let authorizer = Arc::new(
        StaticTrustedApprovers::new().allow("/lab/alice".parse().unwrap(), approver_name),
    );
    let feed = ApproveFeed {
        producer: Producer::from_handle(feed_handle, feed_prefix.clone()),
        side: Consumer::from_handle(side_handle),
        store: store.clone(),
        resolver,
        authorizer,
        timeout: Duration::from_secs(2),
    };
    let ca_task = tokio::spawn(
        ca.serve_with_feed(Producer::from_handle(ca_handle, ca_prefix.clone()), feed),
    );

    let feed_for_approver = feed_prefix.clone();
    let approver_owned = approver_name.to_string();
    let approver = tokio::spawn(async move {
        let mut consumer = Consumer::from_handle(adv_handle);
        run_approver(
            &mut consumer,
            feed_for_approver,
            &approver_owned,
            signer.as_ref(),
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
    assert!(approved, "serve_with_feed must run the APPROVE-FEED and approve via DID resolution");

    drop(engine);
    shutdown.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), approver).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), ca_task).await;
}

/// DidApproverAuthorizer reads the principal's *published* trustedApprovers:
/// the list rides in the principal cert's signed AdditionalDescription and is
/// surfaced as DID-Document services on resolution.
#[tokio::test]
async fn did_authorizer_reads_published_trusted_approvers() {
    use std::future::Future;
    use std::pin::Pin;

    use bytes::Bytes;
    use ndn_packet::Data;
    use ndn_security::did::{UniversalResolver, encode_trusted_approvers_description};
    use ndn_security::{CertCache, CertFetcher, FetchFn, SecurityManager};
    use ndn_identity::{ApproverAuthorizer, DidApproverAuthorizer};

    // Alice's cert publishes /lab/alice/devices/phone as a trusted approver.
    let mgr = SecurityManager::new();
    let alice_key: Name = "/lab/alice/KEY/k1".parse().unwrap();
    mgr.generate_ed25519(alice_key.clone()).unwrap();
    let alice_pub = mgr.get_signer_sync(&alice_key).unwrap().public_key().unwrap();
    let ad = encode_trusted_approvers_description(&["/lab/alice/devices/phone".to_string()]);
    let alice_cert = mgr
        .certify_with_additional_description(
            &alice_key,
            alice_pub,
            &alice_key,
            365 * 24 * 3600 * 1000,
            Some(&ad),
        )
        .await
        .unwrap();
    let cert_wire = ndn_cert::ca::serialize_cert(&alice_cert);

    let fetch_fn: FetchFn = Arc::new(move |_n: Name| {
        let cw = cert_wire.clone();
        Box::pin(async move { Data::decode(Bytes::from(cw)).ok() })
            as Pin<Box<dyn Future<Output = Option<Data>> + Send>>
    });
    let fetcher = Arc::new(CertFetcher::new(
        Arc::new(CertCache::new()),
        fetch_fn,
        Duration::from_secs(1),
    ));
    let resolver = Arc::new(UniversalResolver::with_cert_fetcher(fetcher));

    // Principal = strip the trailing `/devices/<x>` from the subject name.
    let authz = DidApproverAuthorizer::new(resolver, |n: &Name| {
        let c = n.components();
        (c.len() >= 2).then(|| Name::from_components(c[..c.len() - 2].iter().cloned()))
    });

    let laptop: Name = "/lab/alice/devices/laptop".parse().unwrap();
    assert!(
        authz
            .is_authorized("/lab/alice/devices/phone", &laptop)
            .await,
        "the published trusted approver is authorized"
    );
    assert!(
        !authz.is_authorized("/lab/eve", &laptop).await,
        "an identity not in the published list is denied"
    );
}

/// Canonical path: the approver sends a real *signed approval Data* named
/// `<subject>/ndncert-approve/<req>`; the CA validates it through a `Validator`
/// whose trust schema authorizes the approver — evaluated over the real
/// `(data_name, signer-cert-name)`, exactly like NDN signature validation. No
/// synthetic names, no bare identities.
#[tokio::test]
async fn canonical_signed_approval_validated_via_schema() {
    use ndn_security::{Certificate, Ed25519Signer, SchemaRule, Signer, TrustSchema, Validator};
    use ndn_identity::{offer_signed_approval, serve_approve_feed_validated};

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

    let ca = tokio::spawn(serve_approve_feed_validated(
        Producer::from_handle(serve_handle, feed.clone()),
        Consumer::from_handle(pull_handle),
        store.clone(),
        Arc::clone(&validator),
        Duration::from_secs(2),
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
    assert!(entry.validated, "recorded via the validator-checked path");
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
    use ndn_security::{Certificate, Ed25519Signer, SchemaRule, Signer, TrustSchema, Validator};
    use ndn_identity::{offer_signed_approval, serve_approve_feed_validated};

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
