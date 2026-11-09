//! A walk not taken in full stays owed (spec §17.1): every version a
//! verified summary lists that the device follows and does not hold is asked
//! for again after the pause, whatever ended the walk — a first look's wait
//! running out, a fetch that missed — with no new notice from its writer;
//! and a root no trust context held here judges yet is owed from the
//! adoption that makes it judgeable; and a sync notice is answered only by a
//! root its writer gave, newer than every root verified before it unless
//! every round of the root brought nothing newer.

use std::sync::atomic::AtomicBool;

use super::*;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_security::self_certifying::{Genesis, self_certifying_name};
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
    start_with(device, keys, validator, conn, Config::new()).await
}

async fn start_with(
    device: &Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    conn: Arc<dyn Connection>,
    config: Config,
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
        config,
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

/// A reader's link to one writer device over a slow path: every Interest
/// under the writer's name is answered with what the writer serves after
/// `delay`, except the first `lose` Interests for `lost`, which are lost.
struct SlowLink {
    writer: Arc<Inner>,
    delay: Duration,
    lost: Name,
    lose: std::sync::atomic::AtomicUsize,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait::async_trait]
impl Connection for SlowLink {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire) else {
            return Ok(());
        };
        if !interest.name.has_prefix(&self.writer.device) {
            return Ok(());
        }
        if interest.name.has_prefix(&self.lost)
            && self
                .lose
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
        {
            return Ok(());
        }
        if let Some(reply) = self
            .writer
            .packet_for(&interest.name, interest.selectors().can_be_prefix)
        {
            let (tx, delay) = (self.tx.clone(), self.delay);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = tx.unbounded_send(reply);
            });
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

/// The laptop's collection lists many versions, which the phone's walk
/// takes a few at a time over a slow path; every ask of the first one in
/// its first round of asks is lost. That version is asked again in place
/// (spec §17.1, inside a walk): held a round of asks later, not only once
/// every other version of the walk came and a new walk began from the root.
#[tokio::test(start_paused = true)]
async fn a_version_missed_inside_a_walk_is_asked_again_in_place_not_after_the_walk() {
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
    let options = || PutOptions {
        type_id: crate::TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    };
    // Versions enough that the walk takes them for far longer than a round
    // of asks of one: two at a time, a second each.
    const VERSIONS: usize = 80;
    let mut ids = Vec::new();
    for i in 0..VERSIONS {
        let content = Content::new().with("t", Bytes::from(i.to_string()));
        ids.push(writer.put(&c, content, options()).await.unwrap());
    }
    let first = log_name(&laptop, Some(&c), ids[0].seq.0);
    let last = log_name(&laptop, Some(&c), ids[VERSIONS - 1].seq.0);
    for _ in 0..100 {
        if writer.inner.packet_for(&last, false).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        writer.inner.packet_for(&last, false).is_some(),
        "the laptop serves its versions once durable"
    );

    // Each reply comes so near the end of its Interest's lifetime that no
    // Interest is expressed again (spec §17.1): an ask is one Interest.
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let link = Arc::new(SlowLink {
        writer: Arc::clone(&writer.inner),
        delay: Config::new().lifetime - RTO_MIN / 2,
        lost: first.clone(),
        // Every ask of one round.
        lose: std::sync::atomic::AtomicUsize::new(FETCH_TRIES as usize),
        tx,
        rx: futures::lock::Mutex::new(rx),
    });
    let mut config = Config::new();
    config.window = 2;
    let reader = start_with(&phone, phone_keys, validator(), link.clone(), config).await;
    reader.inner.on_update(
        &ns,
        SyncUpdate {
            publisher: laptop.to_string(),
            name: laptop.clone(),
            low_seq: 1,
            high_seq: ids[VERSIONS - 1].seq.0,
            mapping: None,
            serving_party: None,
        },
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let started = tokio::time::Instant::now();
    let _ = reader.get(&c).await;
    // A round of asks lost, the pause, and one more ask: well within the
    // time the walk takes the other versions (two a lifetime).
    let within = Duration::from_secs(25);
    tokio::time::sleep(within.saturating_sub(started.elapsed())).await;
    assert!(
        !holds(&reader, &last),
        "the walk is still taking the other versions"
    );
    assert!(
        holds(&reader, &first),
        "a version that missed inside a walk is asked again in place, not after the walk"
    );
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(holds(&reader, &last), "the walk takes every version");
    reader.shutdown();
    writer.shutdown();
}

/// The laptop's notes folder holds a long collection `a`, which the
/// phone's refresh loop walks a few versions at a time over a slow path,
/// and a short one `b`. Once that walk took its first version, the laptop
/// writes into `b` and is heard of again. The pass of the loop begins a
/// walk of the newer root beside the long one (spec §17.1, walks of newer
/// roots): the new version is held a few exchanges later, while the long
/// walk is still taking `a`, not only once it ended.
#[tokio::test(start_paused = true)]
async fn a_version_written_during_a_long_walk_is_taken_by_a_walk_beside_it() {
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
    let (a, b) = (n("/wendy/32=data/notes/a"), n("/wendy/32=data/notes/b"));
    for c in [&a, &b] {
        writer
            .share(
                c,
                crate::layer::Share {
                    rule: Rule::Log,
                    writers: vec![ns.clone()],
                    readers: Vec::new(),
                },
            )
            .await
            .unwrap();
    }
    let options = || PutOptions {
        type_id: crate::TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    };
    let put = |c: Name, i: usize| {
        let (writer, laptop, options) = (&writer, &laptop, &options);
        async move {
            let content = Content::new().with("t", Bytes::from(i.to_string()));
            let id = writer.put(&c, content, options()).await.unwrap();
            let name = log_name(laptop, Some(&c), id.seq.0);
            for _ in 0..100 {
                if writer.inner.packet_for(&name, false).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                writer.inner.packet_for(&name, false).is_some(),
                "the laptop serves its version once durable"
            );
            (name, id.seq.0)
        }
    };
    // Versions enough that a walk takes them for far longer than a few
    // exchanges: two at a time, one exchange each.
    const VERSIONS: usize = 80;
    let mut long = Vec::new();
    for i in 0..VERSIONS {
        long.push(put(a.clone(), i).await.0);
    }
    let (_, mut head) = put(b.clone(), 0).await;
    let heard = |head: u64| SyncUpdate {
        publisher: laptop.to_string(),
        name: laptop.clone(),
        low_seq: 1,
        high_seq: head,
        mapping: None,
        serving_party: None,
    };

    // Each reply comes so near the end of its Interest's lifetime that no
    // Interest is expressed again (spec §17.1): an exchange is one Interest.
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let link = Arc::new(SlowLink {
        writer: Arc::clone(&writer.inner),
        delay: Config::new().lifetime - RTO_MIN / 2,
        lost: n("/nothing/lost"),
        lose: std::sync::atomic::AtomicUsize::new(0),
        tx,
        rx: futures::lock::Mutex::new(rx),
    });
    let mut config = Config::new();
    config.window = 2;
    let reader = start_with(&phone, phone_keys, validator(), link.clone(), config).await;
    // Followed without a first look: the refresh loop walks, on a notice.
    for c in [&a, &b] {
        reader.inner.follow(c).await.unwrap();
    }
    reader.inner.on_update(&ns, heard(head));
    let mut waited = 0;
    while !long.iter().any(|v| holds(&reader, v)) && waited < 60 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        waited += 1;
    }
    assert!(
        long.iter().any(|v| holds(&reader, v)),
        "precondition: the loop's walk takes the long collection's versions"
    );

    let (newer, seq) = put(b.clone(), 1).await;
    head = head.max(seq);
    reader.inner.on_update(&ns, heard(head));
    let started = tokio::time::Instant::now();
    // The newer root, and the nodes on the way to `b` and its version, one
    // exchange each: well within the time the long walk takes `a`.
    let within = Duration::from_secs(25);
    while !holds(&reader, &newer) && started.elapsed() < within {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        !holds(&reader, &long[VERSIONS - 1]),
        "precondition: the long walk is still taking the long collection"
    );
    assert!(
        holds(&reader, &newer),
        "a version written during a long walk is taken by a walk of the newer root beside it, \
         not only after the long walk"
    );
    tokio::time::sleep(Duration::from_secs(180)).await;
    assert!(
        long.iter().all(|v| holds(&reader, v)),
        "the long walk takes every version"
    );
    reader.shutdown();
    writer.shutdown();
}

/// A person's root key (from `seed`) in `mgr`: the namespace it names
/// (`/user/<0xA1: …>`), the key's name and its self-signed anchor.
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, ndn_security::Certificate) {
    let seed = [seed; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let key = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(key.clone(), &seed).unwrap();
    let anchor = mgr
        .issue_self_signed(&key, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    (ns, key, anchor)
}

/// Version 1 of `ns`'s trust context, anchored at `anchor` and signed by
/// its key in `mgr`, checked as the namespace's genesis.
async fn genesis(
    mgr: &SecurityManager,
    ns: &Name,
    key: &Name,
    anchor: &ndn_security::Certificate,
) -> Genesis {
    let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
    assert!(ctx.add_anchor(anchor.clone()));
    let signer = mgr.get_signer_sync(key).unwrap();
    let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
    Genesis::open_received(&data).await.unwrap()
}

/// Alice and Bob are named by their keys. Bob's phone follows Alice's notes
/// and hears her laptop before it holds her namespace: every root of the
/// laptop is refused then — no context held here judges it — whatever is
/// asked, so nothing is learned by asking and no try of the walk is spent
/// on it. Long after a notice's tries would have run out, Bob's phone
/// adopts Alice's namespace; the laptop announces nothing more. The
/// adoption makes the walk owed: the phone comes to hold the laptop's
/// version (spec §17.1).
#[tokio::test(start_paused = true)]
async fn a_root_refused_before_its_namespace_is_held_is_walked_once_the_namespace_is_adopted() {
    let alice_mgr = SecurityManager::new();
    let (alice, alice_key, alice_anchor) = person(&alice_mgr, 0xa1);
    let bob_mgr = SecurityManager::new();
    let (bob, bob_key, bob_anchor) = person(&bob_mgr, 0xb0);
    let alice_genesis = genesis(&alice_mgr, &alice, &alice_key, &alice_anchor).await;
    let bob_genesis = genesis(&bob_mgr, &bob, &bob_key, &bob_anchor).await;
    let laptop = alice.clone().append("laptop");
    let phone = bob.clone().append("phone");
    let (laptop_keys, laptop_cert) = device_key(&alice_mgr, &alice_key, &laptop).await;
    let (phone_keys, phone_cert) = device_key(&bob_mgr, &bob_key, &phone).await;
    let holding = |held: &[&Genesis]| {
        let v = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for g in held {
            v.keyring()
                .adopt_genesis(g, Arc::clone(g.context()))
                .unwrap();
        }
        v.cert_cache().insert(laptop_cert.clone());
        v.cert_cache().insert(phone_cert.clone());
        v
    };

    let writer = start_on(
        &laptop,
        laptop_keys,
        holding(&[&alice_genesis]),
        Arc::new(Unconnected),
    )
    .await;
    let c = wire::data_folder(&alice).append("notes");
    writer
        .share(
            &c,
            crate::layer::Share {
                rule: Rule::Log,
                writers: vec![alice.clone()],
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

    let link = Link::new(&writer, &n("/nothing/lost"));
    link.losing.store(false, Ordering::Relaxed);
    let validator = holding(&[&bob_genesis]);
    let reader = start_on(&phone, phone_keys, Arc::clone(&validator), link.clone()).await;
    let _ = reader.get(&c).await;
    // The phone hears the laptop in Alice's group, which it joined to follow
    // the notes.
    reader.inner.on_update(
        &alice,
        SyncUpdate {
            publisher: laptop.to_string(),
            name: laptop.clone(),
            low_seq: 1,
            high_seq: 1,
            mapping: None,
            serving_party: None,
        },
    );
    // Far longer than a notice's REFRESH_TRIES asks take.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(
        !holds(&reader, &version),
        "precondition: no root of a namespace not held is taken"
    );

    validator
        .keyring()
        .adopt_genesis(&alice_genesis, Arc::clone(alice_genesis.context()))
        .unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(
        holds(&reader, &version),
        "a root refused only because its namespace was not held is owed once the namespace is \
         adopted, walked without a new notice"
    );
    reader.shutdown();
    writer.shutdown();
}

/// A reader's link to some devices, the writer first: an Interest under a
/// device's name is answered with what that device serves — under its
/// `32=held`, what it holds for others (spec §13.5). One for `root`, the
/// writer's root prefix, is lost while `losing` holds, or answered once with
/// `stale`, an old copy of the root the network delayed. `losing` ends once a
/// device answered for the writer's root and the reader then asks the writer
/// for something else: it walks the root that device gave.
struct Net {
    devices: Vec<Arc<Inner>>,
    root: Name,
    losing: AtomicBool,
    relayed: AtomicBool,
    stale: std::sync::Mutex<Option<Bytes>>,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

impl Net {
    fn new(devices: &[&Device], root: Name) -> Arc<Self> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Arc::new(Net {
            devices: devices.iter().map(|d| Arc::clone(&d.inner)).collect(),
            root,
            losing: AtomicBool::new(false),
            relayed: AtomicBool::new(false),
            stale: std::sync::Mutex::new(None),
            tx,
            rx: futures::lock::Mutex::new(rx),
        })
    }
}

#[async_trait::async_trait]
impl Connection for Net {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire) else {
            return Ok(());
        };
        let name: &Name = &interest.name;
        if name.has_prefix(&self.root) {
            if self.losing.load(Ordering::Relaxed) {
                return Ok(());
            }
            if let Some(old) = self.stale.lock().unwrap().take() {
                let _ = self.tx.unbounded_send(old);
                return Ok(());
            }
        }
        let Some(device) = self.devices.iter().find(|d| name.has_prefix(&d.device)) else {
            return Ok(());
        };
        let reply = match parse_held_name(name) {
            Some((holder, piece)) if holder == device.device => {
                let reply = device
                    .held_packet(&piece)
                    .map(|w| DataBuilder::new(name.clone(), &w).sign_digest_sha256());
                if reply.is_some() && piece.has_prefix(&self.root) {
                    self.relayed.store(true, Ordering::Relaxed);
                }
                reply
            }
            _ => {
                if self.relayed.load(Ordering::Relaxed) && device.device == self.devices[0].device {
                    self.losing.store(false, Ordering::Relaxed);
                }
                device.packet_for(name, interest.selectors().can_be_prefix)
            }
        };
        if let Some(reply) = reply {
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

/// Wendy's namespace, with `devices` certified in it: each one's key store,
/// and a maker of validators trusting them all.
async fn wendy(
    devices: &[&Name],
) -> (
    Name,
    Vec<Arc<SecurityManager>>,
    impl Fn() -> Arc<Validator> + use<>,
) {
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
    let (mut keys, mut certs) = (Vec::new(), Vec::new());
    for d in devices {
        let (k, cert) = device_key(&authority, &issuer, d).await;
        keys.push(k);
        certs.push(cert);
    }
    let context = ns.clone();
    let validator = move || {
        let v = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let ctx = SignedTrustContext::hierarchical(context.clone());
        assert!(ctx.add_anchor(anchor.clone()));
        v.adopt_context(Arc::new(ctx)).unwrap();
        for cert in &certs {
            v.cert_cache().insert(cert.clone());
        }
        v
    };
    (ns, keys, validator)
}

/// Share `c` as a log collection Wendy's namespace writes, from `writer`.
async fn share_log(writer: &Device, c: &Name, ns: &Name) {
    writer
        .share(
            c,
            crate::layer::Share {
                rule: Rule::Log,
                writers: vec![ns.clone()],
                readers: Vec::new(),
            },
        )
        .await
        .unwrap();
}

/// Put version `i` into `c` from `writer` (device `device`) and wait until it
/// is served (durable): its log entry name.
async fn put_served(writer: &Device, device: &Name, c: &Name, i: usize) -> Name {
    let options = PutOptions {
        type_id: crate::TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    };
    let content = Content::new().with("t", Bytes::from(i.to_string()));
    let id = writer.put(c, content, options).await.unwrap();
    let name = log_name(device, Some(c), id.seq.0);
    for _ in 0..100 {
        if writer.inner.packet_for(&name, false).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        writer.inner.packet_for(&name, false).is_some(),
        "the writer serves its version once durable"
    );
    name
}

/// A sync notice that `device` moved.
fn notice(device: &Name) -> SyncUpdate {
    SyncUpdate {
        publisher: device.to_string(),
        name: device.clone(),
        low_seq: 1,
        high_seq: 1,
        mapping: None,
        serving_party: None,
    }
}

/// Whether `dev` holds `version` within `secs` seconds.
async fn held_within(dev: &Device, version: &Name, secs: u64) -> bool {
    for _ in 0..secs {
        if holds(dev, version) {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    holds(dev, version)
}

/// The laptop writes a second version and announces it; the root that
/// answers the phone's walk of that notice is an old copy of the laptop's
/// root — a duplicate the network delayed — which the phone walked in full
/// already. The laptop announces nothing more. The phone asks the laptop
/// again in the root's next round and takes the second version: a notice is
/// answered by a root newer than every root verified before it, or by the
/// writer's own root once every round brought nothing newer (spec §17.1).
#[tokio::test(start_paused = true)]
async fn a_notice_answered_by_an_old_copy_of_the_writers_root_asks_the_writer_again() {
    let (laptop, phone) = (n("/wendy/laptop"), n("/wendy/phone"));
    let (ns, keys, validator) = wendy(&[&laptop, &phone]).await;
    let writer = start_on(
        &laptop,
        Arc::clone(&keys[0]),
        validator(),
        Arc::new(Unconnected),
    )
    .await;
    let c = n("/wendy/32=data/notes");
    share_log(&writer, &c, &ns).await;
    let first = put_served(&writer, &laptop, &c, 0).await;
    let root = root_prefix(&laptop, &ns);
    let net = Net::new(&[&writer], root.clone());
    let reader = start_on(&phone, Arc::clone(&keys[1]), validator(), net.clone()).await;
    reader.inner.follow(&c).await.unwrap();
    reader.inner.on_update(&ns, notice(&laptop));
    assert!(
        held_within(&reader, &first, 60).await,
        "precondition: the phone takes the first version"
    );

    let old = writer.inner.packet_for(&root, true).unwrap();
    let second = put_served(&writer, &laptop, &c, 1).await;
    *net.stale.lock().unwrap() = Some(old);
    reader.inner.on_update(&ns, notice(&laptop));
    assert!(
        held_within(&reader, &second, 30).await,
        "an old copy of the writer's root answering a notice does not end it: the writer is \
         asked again"
    );
    reader.shutdown();
    writer.shutdown();
}

/// The tablet holds the laptop's root of its second version; the phone
/// walked the first. The laptop writes a third and announces it, but its
/// root does not reach the phone in the walk's first two rounds, so the walk
/// takes the tablet's root: newer than the one walked, yet behind what the
/// laptop announced. The laptop announces nothing more. The phone's loop asks
/// the laptop again and takes the third version: a root only a device
/// answering for the writer gave does not answer the writer's notice (spec
/// §17.1).
#[tokio::test(start_paused = true)]
async fn a_notice_answered_by_a_relays_root_behind_the_writer_asks_the_writer_again() {
    let (laptop, tablet, phone) = (n("/wendy/laptop"), n("/wendy/tablet"), n("/wendy/phone"));
    let (ns, keys, validator) = wendy(&[&laptop, &tablet, &phone]).await;
    let writer = start_on(
        &laptop,
        Arc::clone(&keys[0]),
        validator(),
        Arc::new(Unconnected),
    )
    .await;
    let c = n("/wendy/32=data/notes");
    share_log(&writer, &c, &ns).await;
    let first = put_served(&writer, &laptop, &c, 0).await;
    let root = root_prefix(&laptop, &ns);
    let to_writer = Net::new(&[&writer], n("/nothing"));
    let relay = start_on(&tablet, Arc::clone(&keys[1]), validator(), to_writer).await;
    let net = Net::new(&[&writer, &relay], root.clone());
    let reader = start_on(&phone, Arc::clone(&keys[2]), validator(), net.clone()).await;
    reader.inner.follow(&c).await.unwrap();
    // The phone has heard the tablet in the group: it may answer for the
    // laptop.
    reader.inner.on_update(&ns, notice(&tablet));
    reader.inner.on_update(&ns, notice(&laptop));
    assert!(
        held_within(&reader, &first, 60).await,
        "precondition: the phone takes the first version"
    );

    let second = put_served(&writer, &laptop, &c, 1).await;
    relay.inner.follow(&c).await.unwrap();
    relay.inner.on_update(&ns, notice(&laptop));
    assert!(
        held_within(&relay, &second, 60).await,
        "precondition: the tablet takes the second version"
    );
    let third = put_served(&writer, &laptop, &c, 2).await;
    net.losing.store(true, Ordering::Relaxed);
    reader.inner.on_update(&ns, notice(&laptop));
    assert!(
        held_within(&reader, &second, 30).await,
        "precondition: the phone walks the tablet's root"
    );
    assert!(
        held_within(&reader, &third, 30).await,
        "a root only a device answering for the writer gave does not answer the writer's \
         notice: the writer is asked again"
    );
    reader.shutdown();
    relay.shutdown();
    writer.shutdown();
}
