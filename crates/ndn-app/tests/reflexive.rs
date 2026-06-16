//! Reflexive-forwarding endpoint helpers, end-to-end over an embedded engine.
//!
//! Topology (three in-process faces, reflexive forwarding on by default):
//!
//! ```text
//!   advertiser (Face 1) --I1 /svc/req1 (+R)--> [engine] --FIB /svc--> puller serve (Face 2)
//!   puller side    (Face 3) --I2 R/params--> [engine] --reflexive R--> advertiser (Face 1)
//!   advertiser     (Face 1) --D2 R/params "approved"--> [engine] --PIT--> puller side (Face 3)
//!   puller serve   (Face 2) --D1 /svc/req1 "approved"--> [engine] --PIT--> advertiser (Face 1)
//! ```
//!
//! The puller never had a route to the advertiser; it reached it purely along
//! the reverse path the advertiser's reflexive name established.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face::local::InProcFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name, SignatureType};
use ndn_transport::FaceId;

use ndn_app::{Consumer, EngineBuilder, Producer, random_reflexive_name};
use ndn_engine::EngineConfig;

#[tokio::test]
async fn reflexive_reverse_pull_round_trip() {
    let (advertiser_face, advertiser_handle) = InProcFace::new(FaceId(1), 64);
    let (serve_face, serve_handle) = InProcFace::new(FaceId(2), 64);
    let (pull_face, pull_handle) = InProcFace::new(FaceId(3), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(advertiser_face)
        .face(serve_face)
        .face(pull_face)
        .build()
        .await
        .expect("engine build");
    assert!(
        engine.reflexive().is_enabled(),
        "reflexive forwarding must be on by default for this test"
    );

    let svc: Name = "/svc".parse().unwrap();
    engine.fib().add_nexthop(&svc, FaceId(2), 0);

    // Puller: serves /svc; on each forward Interest it pulls `R/params` back
    // from the advertiser via its side consumer (Face 3), then answers the
    // forward Interest with whatever it pulled.
    let producer = Producer::from_handle(serve_handle, svc.clone());
    let side = Arc::new(tokio::sync::Mutex::new(Consumer::from_handle(pull_handle)));
    let puller = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let side = Arc::clone(&side);
                async move {
                    let mut sc = side.lock().await;
                    match sc
                        .pull_reflexive(&interest, "params", Duration::from_secs(2))
                        .await
                    {
                        Ok(pulled) => {
                            let content = pulled.content().map(|c| c.to_vec()).unwrap_or_default();
                            let d1 = DataBuilder::new((*interest.name).clone(), &content).build();
                            responder.respond_bytes(d1).await.ok();
                        }
                        Err(_) => {
                            responder.nack(ndn_packet::NackReason::NoRoute).await.ok();
                        }
                    }
                }
            })
            .await
    });

    // Advertiser: sends the forward Interest with a reflexive name and answers
    // the puller's reverse pull with "approved".
    let mut advertiser = Consumer::from_handle(advertiser_handle);
    let r = random_reflexive_name();
    let forward = InterestBuilder::new("/svc/req1").lifetime(Duration::from_secs(4));
    let d1 = advertiser
        .fetch_reflexive(
            forward,
            r,
            Duration::from_secs(4),
            |reverse: Interest| async move {
                // Answer the reverse Interest, named after it, with the approval.
                Ok(DataBuilder::new((*reverse.name).clone(), b"approved").build())
            },
        )
        .await
        .expect("forward Data should arrive after the reverse pull");

    assert_eq!(
        d1.content().map(|c| c.to_vec()),
        Some(b"approved".to_vec()),
        "the puller relayed exactly what it pulled from the advertiser over the reverse path"
    );

    drop(advertiser);
    drop(engine);
    shutdown.shutdown().await;
    let _ = puller.await;
}

/// The `/localhop` cert-distribution shape: the advertiser sends a **signed**
/// forward command carrying `R` (via [`Consumer::fetch_reflexive_wire`], so the
/// caller controls signing) and serves its certificate — a `Data` — as the
/// *content* of reverse pulls under `R`. The puller pulls `"cert"`, decodes the
/// content back into a `Data`, and relays the cert's name as proof. This is
/// exactly what the gateway does to pre-cache a registrant's cert before
/// validating the register command (`reflexive_prefetch_localhop_cert`).
#[tokio::test]
async fn reflexive_cert_distribution_via_signed_wire() {
    let (advertiser_face, advertiser_handle) = InProcFace::new(FaceId(1), 64);
    let (serve_face, serve_handle) = InProcFace::new(FaceId(2), 64);
    let (pull_face, pull_handle) = InProcFace::new(FaceId(3), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(advertiser_face)
        .face(serve_face)
        .face(pull_face)
        .build()
        .await
        .expect("engine build");

    // The gateway's mgmt face is reached via FIB; the requester is reachable
    // only along the reflexive reverse path it establishes.
    let localhop: Name = "/localhop".parse().unwrap();
    engine.fib().add_nexthop(&localhop, FaceId(2), 0);

    // The certificate the requester will serve (a Data named like a cert).
    let cert_wire: Bytes = DataBuilder::new("/op/alice/KEY/k1", b"PUBKEY").build();

    let producer = Producer::from_handle(serve_handle, localhop.clone());
    let side = Arc::new(tokio::sync::Mutex::new(Consumer::from_handle(pull_handle)));
    let puller = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let side = Arc::clone(&side);
                async move {
                    let mut sc = side.lock().await;
                    // Pull the requester's cert back along the reverse path, decode
                    // its content into a Data (the cert), and answer with the cert
                    // name as evidence the round trip + decode worked.
                    let name = match sc
                        .pull_reflexive(&interest, "cert", Duration::from_secs(2))
                        .await
                    {
                        Ok(wrapper) => wrapper
                            .content()
                            .and_then(|c| Data::decode(c.clone()).ok())
                            .map(|cert| cert.name.to_string())
                            .unwrap_or_default(),
                        Err(_) => String::new(),
                    };
                    let d1 = DataBuilder::new((*interest.name).clone(), name.as_bytes()).build();
                    responder.respond_bytes(d1).await.ok();
                }
            })
            .await
    });

    let mut advertiser = Consumer::from_handle(advertiser_handle);
    let r = random_reflexive_name();
    let kl: Name = "/op/alice/KEY/k1".parse().unwrap();
    // A SIGNED forward command that still carries R (the real announce is signed).
    let wire = InterestBuilder::new("/localhop/nfd/rib/register")
        .must_be_fresh()
        .lifetime(Duration::from_secs(4))
        .reflexive_name(r.clone())
        .app_parameters(b"params")
        .sign_sync(SignatureType::SignatureEd25519, Some(&kl), |_| {
            Bytes::from_static(&[9u8; 64])
        });
    let cert_for_serve = cert_wire.clone();
    let d1 = advertiser
        .fetch_reflexive_wire(
            wire,
            r,
            Duration::from_secs(4),
            move |reverse: Interest| {
                let cert = cert_for_serve.clone();
                async move { Ok(DataBuilder::new((*reverse.name).clone(), &cert).build()) }
            },
        )
        .await
        .expect("forward Data should arrive after the reverse cert pull");

    assert_eq!(
        d1.content().map(|c| String::from_utf8_lossy(c).to_string()),
        Some("/op/alice/KEY/k1".to_string()),
        "gateway pulled and decoded the requester's cert over the reverse path",
    );

    drop(advertiser);
    drop(engine);
    shutdown.shutdown().await;
    let _ = puller.await;
}

#[tokio::test]
async fn pull_reflexive_errors_without_reflexive_name() {
    // A plain forward Interest carries no reflexive name; the puller helper
    // must refuse before touching the wire.
    let (_face, handle) = InProcFace::new(FaceId(1), 64);
    let mut consumer = Consumer::from_handle(handle);
    let plain = Interest::decode(InterestBuilder::new("/svc/x").build()).unwrap();
    let err = consumer
        .pull_reflexive(&plain, "params", Duration::from_millis(200))
        .await
        .expect_err("must error without a reflexive name");
    assert!(format!("{err}").contains("reflexive name"));
}
