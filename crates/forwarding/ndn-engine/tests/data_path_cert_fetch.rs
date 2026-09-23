//! The engine fetches the certificate its own Data path needs.
//!
//! Face B stands in for a remote peer (its Data is validated, as Data from a
//! network face is). It answers the consumer's Interest with Data signed by a
//! key whose certificate the engine has not cached, and serves that certificate
//! under the KeyLocator name. The engine must express the certificate Interest
//! itself -- through its FIB, out face B -- and forward the Data once the
//! certificate verifies it. Before, `default` wired a no-op fetcher and
//! `accept-signed` none: no certificate Interest ever left the engine and the
//! Data was dropped when the pending-validation timeout expired.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Ed25519Signer, SecurityProfile, SignWith, Signer, encode_cert_data};
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // consumer
const FACE_B: u64 = 2; // remote producer
const KEY: &str = "/p/KEY/k1";

/// Serve face B: the signed Data for any other Interest, the certificate for
/// `KEY` (counted).
fn serve_producer(b: InProcHandle, data: Bytes, cert: Bytes, cert_interests: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        while let Some(wire) = b.recv().await {
            let Ok(interest) = Interest::decode(wire) else {
                continue;
            };
            let reply = if interest.name.to_string() == KEY {
                cert_interests.fetch_add(1, Ordering::Relaxed);
                cert.clone()
            } else {
                data.clone()
            };
            let _ = b.send(reply).await;
        }
    });
}

/// Consumer A asks for `/p/data` through an engine running `profile`; B
/// answers it with Data signed by `KEY`, whose self-signed certificate it also
/// serves. Returns what A received within `wait` and how many certificate
/// Interests reached B.
async fn fetch_through(profile: SecurityProfile, wait: Duration) -> (Option<Bytes>, usize) {
    let key = Ed25519Signer::from_seed(&[7; 32], KEY.parse().unwrap());
    let cert = encode_cert_data(
        key.key_name(),
        &key.public_key().unwrap(),
        &key,
        0,
        u64::MAX,
    )
    .await
    .unwrap();
    let data = DataBuilder::new("/p/data".parse::<Name>().unwrap(), b"payload")
        .sign_with_sync(&key)
        .unwrap();

    let (face_a, a) = InProcFace::new(FaceId(FACE_A), 64);
    let (face_b, b) = InProcFace::new(FaceId(FACE_B), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(profile)
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .unwrap();
    engine.set_require_data_validation(FaceId(FACE_B), true);
    engine
        .fib()
        .add_nexthop(&"/p".parse::<Name>().unwrap(), FaceId(FACE_B), 0);
    let cert_interests = Arc::new(AtomicUsize::new(0));
    serve_producer(b, data, cert, Arc::clone(&cert_interests));

    a.send(
        InterestBuilder::new("/p/data")
            .lifetime(Duration::from_secs(4))
            .build(),
    )
    .await
    .unwrap();
    let got = tokio::time::timeout(wait, a.recv())
        .await
        .ok()
        .flatten()
        .and_then(|w| Data::decode(w).ok())
        .and_then(|d| d.content().cloned());
    let requests = cert_interests.load(Ordering::Relaxed);
    shutdown.shutdown().await;
    (got, requests)
}

#[tokio::test]
async fn accept_signed_fetches_the_uncached_signer_cert_through_the_engine() {
    let (got, cert_interests) =
        fetch_through(SecurityProfile::AcceptSigned, Duration::from_secs(2)).await;
    assert_eq!(
        cert_interests, 1,
        "the engine must express one Interest for the signer's certificate"
    );
    assert_eq!(
        got.as_deref(),
        Some(&b"payload"[..]),
        "the Data must be forwarded once the fetched certificate verifies it"
    );
}

/// `default` with no SecurityManager has no trust anchors. It still walks the
/// chain -- fetching the cert -- and drops key-signed Data rather than falling
/// back to checking the signature alone.
#[tokio::test]
async fn default_without_anchors_fails_closed() {
    let (got, cert_interests) =
        fetch_through(SecurityProfile::Default, Duration::from_secs(1)).await;
    assert_eq!(
        cert_interests, 1,
        "the chain walk must fetch the signer's cert"
    );
    assert_eq!(
        got, None,
        "no anchor vouches for the signer: the Data must be dropped"
    );
}
