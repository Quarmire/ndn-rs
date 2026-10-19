//! A namespace's trust context held at a relay, end to end over three
//! engines — the root device (serves the CA's and the devices' certificates,
//! as the namespace CA does), a relay that holds only the context, and a
//! device producing signed Data — linked by non-local faces. Each test guards
//! one invariant:
//!
//! - Data from an enrolled device validates at a relay that has none of its
//!   chain cached, whether the relay's routes take the certificate fetch to
//!   the CA or to the device;
//! - once the relay adopts a context version revoking the device's key, its
//!   Content Store never serves Data that key signed (nor the key's
//!   certificate).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, EngineBuilder, ForwarderEngine, Producer, ShutdownHandle};
use ndn_engine::EngineConfig;
use ndn_face::local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, NackReason, Name};
use ndn_security::{CertCache, FilePib, Keyring, SecurityProfile, Validator};
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Add a non-local face to each engine and pump packets between them.
fn link(a: &ForwarderEngine, b: &ForwarderEngine, cancel: &CancellationToken) -> (FaceId, FaceId) {
    let face = |e: &ForwarderEngine| {
        let id = e.faces().alloc_id();
        let (face, handle) = InProcFace::new_kind(id, 256, FaceKind::Udp);
        e.add_face(face, cancel.child_token());
        (id, Arc::new(handle))
    };
    let ((a_id, a), (b_id, b)) = (face(a), face(b));
    let pump = |from: Arc<InProcHandle>, to: Arc<InProcHandle>| {
        tokio::spawn(async move {
            while let Some(pkt) = from.recv().await {
                if to.send(pkt).await.is_err() {
                    break;
                }
            }
        })
    };
    pump(Arc::clone(&a), Arc::clone(&b));
    pump(b, a);
    (a_id, b_id)
}

/// Answer the Interests `producer` receives from `served`: by exact name,
/// or with CanBePrefix the first Data under the Interest's name (a
/// certificate fetched by its key name); else Nack them.
fn serve(producer: Producer, served: Vec<(Name, Bytes)>) {
    let served = Arc::new(served);
    tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let served = Arc::clone(&served);
                async move {
                    let prefix = interest.selectors().can_be_prefix;
                    match served.iter().find(|(name, _)| {
                        *name == *interest.name || (prefix && name.has_prefix(&interest.name))
                    }) {
                        Some((_, wire)) => responder.respond_bytes(wire.clone()).await.ok(),
                        None => responder.nack(NackReason::NoRoute).await.ok(),
                    };
                }
            })
            .await
            .ok();
    });
}

struct Namespace {
    _dir: tempfile::TempDir,
    pib: FilePib,
    ns: ndn_cert::PersistedNamespace,
}

impl Namespace {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = futures::executor::block_on(ndn_cert::init_namespace_in_pib(
            &pib,
            &n("/home/bob"),
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
        ))
        .unwrap();
        Self { _dir: dir, pib, ns }
    }

    fn ca_cert(&self) -> (Name, Bytes) {
        let name = (*self.ns.ca_cert.name).clone();
        (name, std::fs::read(&self.ns.ca_cert_path).unwrap().into())
    }

    fn device_cert(&self) -> (Name, Bytes) {
        let name = (*self.ns.device_cert.name).clone();
        (name, std::fs::read(&self.ns.device_cert_path).unwrap().into())
    }

    /// `/home/bob/admin/desk/data/<suffix>`, signed by the device's key.
    fn device_data(&self, suffix: &str) -> (Name, Bytes) {
        let name = self.ns.device_identity.clone().append("data").append(suffix);
        let signer = self.pib.get_signer(&self.ns.device_key).unwrap();
        let wire = DataBuilder::new(name.clone(), b"photo")
            .freshness(Duration::from_secs(600))
            .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
                signer.sign_sync(region).unwrap()
            });
        (name, wire)
    }
}

struct Relay {
    engine: ForwarderEngine,
    keyring: Arc<Keyring>,
    consumer: Consumer,
    cancel: CancellationToken,
    shutdowns: Vec<ShutdownHandle>,
}

/// The three engines. The relay routes `/home/bob` to the root device and
/// `device_route` to the device; it holds the namespace's context (only the
/// root's anchor) and caches nothing else.
async fn relay(ns: &Namespace, device_route: Name, photos: &[&str]) -> Relay {
    let cancel = CancellationToken::new();
    let build = |profile| async move {
        EngineBuilder::new(EngineConfig::default())
            .security_profile(profile)
            .build()
            .await
            .unwrap()
    };
    let keyring = Arc::new(Keyring::new());
    ndn_cert::adopt_with_tofu(
        &keyring,
        &ns.ns.init.context_data,
        &n("/home/bob"),
        &ndn_cert::anchor_fingerprint(&ns.ns.init.anchor),
    )
    .unwrap();
    let validator = Arc::new(Validator::with_keyring(
        Arc::clone(&keyring),
        Arc::new(CertCache::new()),
        None,
        5,
    ));
    let (relay, relay_sd) = build(SecurityProfile::Custom(validator)).await;
    assert!(ndn_app::install_engine_cert_fetcher(&relay, cancel.child_token()));
    let (root, root_sd) = build(SecurityProfile::Disabled).await;
    let (device, device_sd) = build(SecurityProfile::Disabled).await;

    let (to_root, _) = link(&relay, &root, &cancel);
    let (to_device, _) = link(&relay, &device, &cancel);
    relay.fib().add_nexthop(&n("/home/bob"), to_root, 0);
    relay.fib().add_nexthop(&device_route, to_device, 0);

    // The root device answers cert-fetch for the CA's and the device's
    // certificates, as the namespace CA does.
    serve(
        root.register_producer(n("/home/bob"), cancel.child_token()),
        vec![ns.ca_cert(), ns.device_cert()],
    );
    // The device serves its Data and, by convention, its own certificate.
    let mut served: Vec<_> = photos.iter().map(|p| ns.device_data(p)).collect();
    served.push(ns.device_cert());
    serve(
        device.register_producer(ns.ns.device_identity.clone(), cancel.child_token()),
        served,
    );

    Relay {
        consumer: relay.app_consumer(cancel.child_token()),
        engine: relay,
        keyring,
        cancel,
        shutdowns: vec![relay_sd, root_sd, device_sd],
    }
}

impl Relay {
    async fn fetch(&mut self, name: &Name) -> Option<Bytes> {
        self.consumer
            .fetch_with(InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(3)))
            .await
            .ok()
            .and_then(|d| d.content().cloned())
    }

    async fn cached(&self, name: &Name) -> bool {
        let interest = Interest::decode(InterestBuilder::new(name.clone()).build()).unwrap();
        self.engine.cs().get_erased(&interest, 0).await.is_some()
    }

    fn cs_hits(&self) -> u64 {
        self.engine.cs().stats().hits
    }

    async fn stop(self) {
        self.cancel.cancel();
        for sd in self.shutdowns {
            sd.shutdown().await;
        }
    }
}

/// The device's certificate and the CA's are both fetched (the first is
/// parked until the second arrives), whichever node the routes reach.
#[tokio::test]
async fn device_data_validates_at_a_relay_holding_only_the_context() {
    let ns = Namespace::new();
    let identity = ns.ns.device_identity.clone();
    for (route, certs_from) in [
        (identity.clone().append("data"), "the root device (the CA)"),
        (identity.clone(), "the device itself"),
    ] {
        let mut relay = relay(&ns, route, &["1"]).await;
        let (photo, _) = ns.device_data("1");
        assert_eq!(
            relay.fetch(&photo).await.as_deref(),
            Some(&b"photo"[..]),
            "Data must validate at the relay with its chain fetched from {certs_from}"
        );
        relay.stop().await;
    }
}

/// After the relay adopts the version revoking the device's key, the Data
/// that key signed — validated and cached before — is gone from its Content
/// Store: an Interest for it is not answered from there, and what the
/// device sends back is refused.
#[tokio::test]
async fn a_relay_never_serves_cached_data_of_a_key_revoked_by_an_update() {
    let ns = Namespace::new();
    let mut relay = relay(&ns, ns.ns.device_identity.clone(), &["1", "2"]).await;
    let (photo1, _) = ns.device_data("1");
    let (photo2, _) = ns.device_data("2");
    for photo in [&photo1, &photo2] {
        assert!(relay.fetch(photo).await.is_some(), "valid before revocation");
        assert!(relay.cached(photo).await);
    }
    let (cert_name, _) = ns.device_cert();
    assert!(relay.cached(&cert_name).await);
    let hits = relay.cs_hits();
    assert_eq!(relay.fetch(&photo1).await.as_deref(), Some(&b"photo"[..]));
    assert_eq!(relay.cs_hits(), hits + 1, "the repeat is answered from the CS");

    let root = ndn_cert::RootStore::open(&ns.pib).unwrap().unwrap();
    let root = root.signer(None).await.unwrap();
    let bump = ndn_cert::bump_context_revoking(
        root.as_ref(),
        &ns.ns.init.context_data,
        std::slice::from_ref(&ns.ns.device_key),
    )
    .await
    .unwrap()
    .expect("a new version");
    relay.keyring.adopt_update(Arc::new(bump.context)).unwrap();

    for photo in [&photo1, &photo2] {
        assert!(!relay.cached(photo).await, "evicted when the update was adopted");
    }
    assert!(!relay.cached(&cert_name).await, "the revoked key's certificate too");
    let hits = relay.cs_hits();
    assert_eq!(relay.fetch(&photo1).await, None, "refused when fetched again");
    assert_eq!(relay.cs_hits(), hits, "not answered from the CS");
    relay.stop().await;
}
