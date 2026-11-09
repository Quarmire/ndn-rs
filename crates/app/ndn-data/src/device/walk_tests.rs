//! A walk not taken in full stays owed (spec §17.1): every version a
//! verified summary lists that the device follows and does not hold is asked
//! for again after the pause, whatever ended the walk — a first look's wait
//! running out, a fetch that missed — with no new notice from its writer.

use std::sync::atomic::AtomicBool;

use super::*;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

/// A forwarder that delivers nothing.
struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        std::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// A reader's link to one writer device: an Interest under the writer's
/// name is answered with what the writer serves, except one for `lost`
/// while `losing` holds (it, or its answer, is lost); nothing else is
/// answered.
struct Link {
    writer: Arc<Inner>,
    lost: Name,
    losing: AtomicBool,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

impl Link {
    fn new(writer: &Device, lost: &Name) -> Arc<Self> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Arc::new(Link {
            writer: Arc::clone(&writer.inner),
            lost: lost.clone(),
            losing: AtomicBool::new(true),
            tx,
            rx: futures::lock::Mutex::new(rx),
        })
    }
}

#[async_trait::async_trait]
impl Connection for Link {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire) else {
            return Ok(());
        };
        if !interest.name.has_prefix(&self.writer.device)
            || (self.losing.load(Ordering::Relaxed) && interest.name.has_prefix(&self.lost))
        {
            return Ok(());
        }
        if let Some(reply) = self
            .writer
            .packet_for(&interest.name, interest.selectors().can_be_prefix)
        {
            let _ = self.tx.unbounded_send(reply);
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.next().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// A device key of `device` certified by `issuer` of `authority`: its key
/// store (holding the certificate) and the certificate.
async fn device_key(
    authority: &SecurityManager,
    issuer: &Name,
    device: &Name,
) -> (Arc<SecurityManager>, ndn_security::Certificate) {
    let keys = Arc::new(SecurityManager::new());
    let key = keys
        .generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
    let cert = authority
        .certify(&key, public, issuer, VALIDITY_MS)
        .await
        .unwrap();
    keys.cert_cache().insert(cert.clone());
    (keys, cert)
}

async fn start_on(
    device: &Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    conn: Arc<dyn Connection>,
) -> Device {
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device.clone(),
        keys,
        validator,
        Arc::new(MemoryStore::new()),
        Config::new(),
    )
    .await
    .unwrap()
}

/// Whether `dev` holds `version` verified and opened.
fn holds(dev: &Device, version: &Name) -> bool {
    matches!(
        dev.inner.st.lock().held.get(version),
        Some(Held::Version(_))
    )
}

/// The laptop writes a version into a collection the phone then reads. The
/// phone's first look walks the laptop's summary — root verified, the
/// version listed — but every ask of the version is lost, so the walk is
/// not taken in full. The laptop announces nothing more. Once the version
/// is to be had again, the phone fetches it: the walk was owed by the root
/// it verified, not by a notice.
#[tokio::test(start_paused = true)]
async fn a_walk_that_missed_a_listed_version_fetches_it_later_without_a_new_notice() {
    let ns = n("/wendy");
    let authority = SecurityManager::new();
    let issuer = authority
        .generate_ed25519(ns.clone().append("KEY").append("ns"))
        .unwrap();
    let public = authority
        .get_signer_sync(&issuer)
        .unwrap()
        .public_key()
        .unwrap();
    let anchor = authority
        .issue_self_signed_async(&issuer, public, VALIDITY_MS)
        .await
        .unwrap();
    let (laptop, phone) = (n("/wendy/laptop"), n("/wendy/phone"));
    let (laptop_keys, laptop_cert) = device_key(&authority, &issuer, &laptop).await;
    let (phone_keys, phone_cert) = device_key(&authority, &issuer, &phone).await;
    let validator = || {
        let v = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let ctx = SignedTrustContext::hierarchical(ns.clone());
        assert!(ctx.add_anchor(anchor.clone()));
        v.adopt_context(Arc::new(ctx)).unwrap();
        v.cert_cache().insert(laptop_cert.clone());
        v.cert_cache().insert(phone_cert.clone());
        v
    };

    let writer = start_on(&laptop, laptop_keys, validator(), Arc::new(Unconnected)).await;
    let c = n("/wendy/32=data/notes");
    writer
        .share(
            &c,
            crate::layer::Share {
                rule: Rule::Log,
                writers: vec![ns.clone()],
                readers: Vec::new(),
            },
        )
        .await
        .unwrap();
    let options = PutOptions {
        type_id: crate::TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    };
    let id = writer
        .put(&c, Content::new().with("t", Bytes::from("1")), options)
        .await
        .unwrap();
    let version = log_name(&laptop, Some(&c), id.seq.0);
    for _ in 0..100 {
        if writer.inner.packet_for(&version, false).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        writer.inner.packet_for(&version, false).is_some(),
        "the laptop serves its version once durable"
    );

    let link = Link::new(&writer, &version);
    let reader = start_on(&phone, phone_keys, validator(), link.clone()).await;
    // The phone hears of the laptop before it follows anything of `ns`.
    reader.inner.on_update(
        &ns,
        SyncUpdate {
            publisher: laptop.to_string(),
            name: laptop.clone(),
            low_seq: 1,
            high_seq: 1,
            mapping: None,
            serving_party: None,
        },
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = reader.get(&c).await;
    assert!(
        reader.inner.st.lock().peers[&(laptop.clone(), ns.clone())].head >= id.seq.0,
        "the phone verified the laptop's root listing the version"
    );
    assert!(
        !holds(&reader, &version),
        "every ask of the version was lost"
    );

    link.losing.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(
        holds(&reader, &version),
        "a version a verified root lists is owed until held, asked again without a new notice"
    );
    reader.shutdown();
    writer.shutdown();
}
