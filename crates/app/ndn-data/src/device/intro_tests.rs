//! Introductions (spec §19), the offering device's side judged in process:
//! devices of strangers' namespaces on a forwarder that delivers nothing, an
//! ask built as [`Device::join`] builds it and handed to the offering
//! device's [`Inner::answer_intro`]. What the network cases (conformance
//! `i1`…) cannot see: what goes into the validator's cache, a joiner whose
//! key is its own anchor, a host that does not adopt, and a crowd of asks.

use super::*;
use crate::intro::{
    AnswerBody, AskBody, Grant, IntroAsk, IntroPolicy, IntroRefusal, Introducer, Offer, Outcome,
    Role, ask_proof, intro_name, intro_prefix, proof_key,
};
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::{Certificate, SignedTrustContext, TrustSchema, encode_cert_data};
use ndn_sync::MemoryStore;
use ndn_trust_envelope::TrustEnvelope;
use tokio::sync::Notify;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

/// A forwarder that never delivers anything.
struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

fn now_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// A person: a namespace whose root key signs its trust context (version
/// 1, hierarchical) and certifies its devices.
struct Person {
    root: Arc<dyn Signer>,
    ctx: Arc<SignedTrustContext>,
    signed: Bytes,
}

impl Person {
    /// `ns` rooted in a key of its own, `<ns>/KEY/ns`.
    fn new(ns: &str) -> Person {
        let mgr = SecurityManager::new();
        let root = mgr
            .generate_ed25519(n(ns).append("KEY").append("ns"))
            .unwrap();
        Person::rooted(ns, &mgr, &root)
    }

    /// `ns` rooted in the key `root` held by `mgr`.
    fn rooted(ns: &str, mgr: &SecurityManager, root: &Name) -> Person {
        Person::rooted_with(ns, mgr, root, Vec::new())
    }

    /// `ns` rooted in a key of its own, its trust context advertising the
    /// relay device `relay` (an endpoint to dial it at is part of the entry).
    fn relayed(ns: &str, relay: &str) -> Person {
        let mgr = SecurityManager::new();
        let root = mgr
            .generate_ed25519(n(ns).append("KEY").append("ns"))
            .unwrap();
        let relay = ndn_security::AdvertisedRelay {
            device: n(relay),
            key: None,
            endpoints: vec!["relay.example.net:6363".to_string()],
            preference: 0,
        };
        Person::rooted_with(ns, &mgr, &root, vec![relay])
    }

    /// [`rooted`](Self::rooted), the trust context advertising `relays`.
    fn rooted_with(
        ns: &str,
        mgr: &SecurityManager,
        root: &Name,
        relays: Vec<ndn_security::AdvertisedRelay>,
    ) -> Person {
        let signer = mgr.get_signer_sync(root).unwrap();
        let anchor = mgr
            .issue_self_signed(root, signer.public_key().unwrap(), VALIDITY_MS)
            .unwrap();
        let ctx = SignedTrustContext::hierarchical(n(ns))
            .with_version(1)
            .with_relays(relays);
        assert!(ctx.add_anchor(anchor));
        let signed = ctx.sign_into_data(signer.as_ref()).unwrap().raw().clone();
        Person {
            root: signer,
            ctx: Arc::new(ctx),
            signed,
        }
    }

    /// A certificate named under `key` of `public`, signed by the root.
    async fn certify(&self, key: &Name, public: &[u8]) -> Certificate {
        let wire = encode_cert_data(
            &new_cert_name(key, DEFAULT_ISSUER),
            public,
            self.root.as_ref(),
            now_ns() - 1_000_000_000,
            now_ns() + VALIDITY_MS * 1_000_000,
        )
        .await
        .unwrap();
        Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
    }
}

/// What a host was asked to dial and to take down, and whether its dial
/// succeeds.
#[derive(Default)]
struct Calls {
    dialled: std::sync::Mutex<Vec<Name>>,
    undialled: std::sync::Mutex<Vec<Name>>,
    /// The key of every link hint `undial` was given.
    undialled_keys: std::sync::Mutex<Vec<[u8; 32]>>,
    dial_succeeds: std::sync::atomic::AtomicBool,
    /// Every `dial_first`: the inviter and the address.
    first_dialled: std::sync::Mutex<Vec<(Name, std::net::SocketAddr)>>,
    /// What `dial_first` answers: the key the link proved, or why not;
    /// `None`: a host with no link layer.
    first_dial: std::sync::Mutex<Option<Result<[u8; 32], String>>>,
    /// What `link_hint` gives: this host's key and its addresses.
    hint: std::sync::Mutex<Option<crate::intro::LinkHint>>,
    /// Whether a dial of this host's succeeded and was not taken down since:
    /// a link a test's network carries introduction names over.
    linked: std::sync::atomic::AtomicBool,
    /// Whether this host adopted a namespace: its links carry every name of
    /// it from then on.
    adopted: std::sync::atomic::AtomicBool,
    granted: std::sync::Mutex<Vec<Grant>>,
    revoked: std::sync::Mutex<Vec<([u8; 32], Name)>>,
    departed: std::sync::Mutex<Vec<crate::intro::Departure>>,
    /// Every `departure` and `revoke_grant` call, in the order made.
    order: std::sync::Mutex<Vec<&'static str>>,
}

impl Calls {
    fn dialled(&self) -> Vec<Name> {
        self.dialled.lock().unwrap().clone()
    }

    fn undialled(&self) -> Vec<Name> {
        self.undialled.lock().unwrap().clone()
    }

    fn undialled_keys(&self) -> Vec<[u8; 32]> {
        self.undialled_keys.lock().unwrap().clone()
    }

    fn first_dialled(&self) -> Vec<(Name, std::net::SocketAddr)> {
        self.first_dialled.lock().unwrap().clone()
    }

    fn linked(&self) -> bool {
        self.linked.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn adopted(&self) -> bool {
        self.adopted.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn granted(&self) -> Vec<Grant> {
        self.granted.lock().unwrap().clone()
    }

    fn revoked(&self) -> Vec<[u8; 32]> {
        self.revoked.lock().unwrap().iter().map(|r| r.0).collect()
    }

    /// What `revoke_grant` was told: the key and the folder, in order.
    fn revoked_in(&self) -> Vec<([u8; 32], Name)> {
        self.revoked.lock().unwrap().clone()
    }

    fn departed(&self) -> Vec<crate::intro::Departure> {
        self.departed.lock().unwrap().clone()
    }

    fn order(&self) -> Vec<&'static str> {
        self.order.lock().unwrap().clone()
    }
}

/// A host's introducer: gives its person's signed context; adopts a link
/// into its validator — unless it refuses the namespace, or holds every
/// adoption until let go; records what it is asked to dial.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    /// Namespaces it does not adopt.
    refuses: Vec<Name>,
    /// Hold adoptions: told as one starts, let go one per permit.
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    calls: Arc<Calls>,
}

impl Introducer for Host {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    fn grant(&self, grant: &Grant) {
        self.calls.granted.lock().unwrap().push(grant.clone());
    }

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        self.calls.order.lock().unwrap().push("revoke_grant");
        self.calls
            .revoked
            .lock()
            .unwrap()
            .push((*key, folder.clone()));
    }

    fn departure(&self, departure: &crate::intro::Departure) {
        self.calls.order.lock().unwrap().push("departure");
        self.calls.departed.lock().unwrap().push(departure.clone());
    }

    fn link_hint(&self) -> Option<crate::intro::LinkHint> {
        self.calls.hint.lock().unwrap().clone()
    }

    fn dial<'a>(
        &'a self,
        _hint: &'a crate::intro::LinkHint,
        inviter: &'a Name,
        _within: Duration,
    ) -> crate::intro::Dialing<'a> {
        self.calls.dialled.lock().unwrap().push(inviter.clone());
        let ok = self
            .calls
            .dial_succeeds
            .load(std::sync::atomic::Ordering::SeqCst);
        if ok {
            self.calls
                .linked
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err("this test host links nothing".to_string())
            }
        })
    }

    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: std::net::SocketAddr,
        _within: Duration,
    ) -> crate::intro::FirstDialing<'a> {
        self.calls
            .first_dialled
            .lock()
            .unwrap()
            .push((inviter.clone(), addr));
        let got = self
            .calls
            .first_dial
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err("this test host links nothing".to_string()));
        if got.is_ok() {
            self.calls
                .linked
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Box::pin(async move { got })
    }

    fn undial(&self, hint: &crate::intro::LinkHint, inviter: &Name) {
        self.calls.undialled.lock().unwrap().push(inviter.clone());
        self.calls.undialled_keys.lock().unwrap().push(hint.key);
        self.calls
            .linked
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> crate::intro::Adopting<'a> {
        Box::pin(async move {
            if let Some((started, gate)) = &self.hold {
                started.notify_one();
                gate.acquire().await.map_err(|e| e.to_string())?.forget();
            }
            let TrustEnvelope::Anchor {
                namespace: Some(ns),
                fingerprint,
                context_data: Some(data),
                ..
            } = link
            else {
                return Err("not an inline anchor link".into());
            };
            let ns: Name = ns.parse().map_err(|_| "no name".to_string())?;
            if self.refuses.contains(&ns) {
                return Err(format!("this host does not adopt {ns}"));
            }
            let data = Data::decode(data.clone()).map_err(|e| format!("{e:?}"))?;
            let (ctx, _) = SignedTrustContext::open_received(&data)
                .await
                .map_err(|e| e.to_string())?;
            // Held at this version or a newer one, rooted in the link's
            // anchor: nothing to adopt (as the daemon's host answers).
            let held = self.validator.keyring().held(&ns).is_some_and(|held| {
                held.version() >= ctx.version()
                    && held
                        .anchors()
                        .iter()
                        .any(|a| Some(ndn_security::anchor_fingerprint(a.value())) == *fingerprint)
            });
            if held {
                self.calls
                    .adopted
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(());
            }
            self.validator
                .adopt_context(Arc::new(ctx))
                .map_err(|refused| refused.to_string())?;
            self.calls
                .adopted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

/// Start `device` of `person`, its key certified by the person's root (or,
/// with `keys`, the key store already holding its key), its host refusing
/// `refuses` and holding adoptions when `hold` is given.
async fn start(
    person: &Person,
    device: &str,
    keys: Option<Arc<SecurityManager>>,
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
) -> Device {
    start_clocked(person, device, keys, refuses, hold, None).await
}

/// [`start`] with the device's clock `clock`, when given.
async fn start_clocked(
    person: &Person,
    device: &str,
    keys: Option<Arc<SecurityManager>>,
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
) -> Device {
    start_recording(
        person,
        device,
        keys,
        refuses,
        hold,
        clock,
        Arc::new(Calls::default()),
    )
    .await
}

/// [`start_clocked`] with a host that records what it is asked to dial and
/// take down in `calls`.
async fn start_recording(
    person: &Person,
    device: &str,
    keys: Option<Arc<SecurityManager>>,
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
    calls: Arc<Calls>,
) -> Device {
    start_policy(
        person,
        device,
        keys,
        refuses,
        hold,
        clock,
        calls,
        IntroPolicy::new(),
        Arc::new(MemoryStore::new()),
    )
    .await
}

/// [`start_recording`] with the device's introduction policy `intro` and its
/// durable store `store`: a device started again over the same store and keys
/// is a restart.
#[allow(clippy::too_many_arguments)]
async fn start_policy(
    person: &Person,
    device: &str,
    keys: Option<Arc<SecurityManager>>,
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
    calls: Arc<Calls>,
    intro: IntroPolicy,
    store: Arc<dyn DataStore>,
) -> Device {
    start_wired(
        person,
        device,
        keys,
        refuses,
        hold,
        clock,
        calls,
        intro,
        store,
        Arc::new(Unconnected),
    )
    .await
}

/// [`start_policy`] on the connection `conn` (the node's; the sync groups'
/// is one that delivers nothing): a device other devices' Interests reach.
#[allow(clippy::too_many_arguments)]
async fn start_wired(
    person: &Person,
    device: &str,
    keys: Option<Arc<SecurityManager>>,
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
    calls: Arc<Calls>,
    intro: IntroPolicy,
    store: Arc<dyn DataStore>,
    conn: Arc<dyn Connection>,
) -> Device {
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    if matches!(
        ndn_security::self_certifying::self_certifying_digest(person.ctx.namespace()),
        Ok(Some(_))
    ) {
        // A self-certifying namespace is held only from its genesis.
        let genesis = ndn_security::self_certifying::Genesis::open_received(
            &Data::decode(person.signed.clone()).unwrap(),
        )
        .await
        .unwrap();
        validator
            .keyring()
            .adopt_genesis(&genesis, Arc::clone(genesis.context()))
            .unwrap();
    } else {
        validator.adopt_context(Arc::clone(&person.ctx)).unwrap();
    }
    let keys = match keys {
        Some(k) => k,
        None => {
            let keys = Arc::new(SecurityManager::new());
            let k = keys.generate_ed25519(key(&device)).unwrap();
            let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
            let cert = person.certify(&k, &public).await;
            keys.cert_cache().insert(cert.clone());
            validator.cert_cache().insert(cert);
            keys
        }
    };
    let host = Host {
        anchor: person.signed.clone(),
        validator: Arc::clone(&validator),
        refuses: refuses.iter().map(|s| n(s)).collect(),
        hold,
        calls,
    };
    Device::start(
        Transport {
            node: Node::from_connection(conn),
            sync: Arc::new(Unconnected),
        },
        device,
        keys,
        validator,
        store,
        Config {
            first_look: Duration::from_millis(50),
            introducer: Some(Arc::new(host)),
            intro,
            ..clock.map_or_else(Config::new, |clock| Config {
                clock,
                ..Config::new()
            })
        },
    )
    .await
    .unwrap()
}

/// Alice's laptop, her notebook shared with herself alone, and an offer of
/// it as a writer: the device, the offer's name and its secret.
async fn alice(
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
) -> (Device, Name, [u8; crate::intro::SECRET_LEN]) {
    alice_at(refuses, hold, None).await
}

/// [`alice`] with her laptop's clock `clock`, when given.
async fn alice_at(
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
) -> (Device, Name, [u8; crate::intro::SECRET_LEN]) {
    let (laptop, code, secret, _) = alice_person(refuses, hold, clock).await;
    (laptop, code.offer, secret)
}

/// [`alice_at`], with the person and the whole code.
async fn alice_person(
    refuses: &[&str],
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
    clock: Option<Clock>,
) -> (
    Device,
    crate::intro::Code,
    [u8; crate::intro::SECRET_LEN],
    Person,
) {
    let alice = Person::new("/alice");
    let laptop = start_clocked(&alice, "/alice/laptop", None, refuses, hold, clock).await;
    alice_offers(laptop, alice, Role::Writer).await
}

/// Alice's `laptop`, her notebook shared with herself alone, and an offer of
/// it as `role`.
async fn alice_offers(
    laptop: Device,
    alice: Person,
    role: Role,
) -> (
    Device,
    crate::intro::Code,
    [u8; crate::intro::SECRET_LEN],
    Person,
) {
    let folder = n("/alice/32=data/notebook");
    laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }
            .into(),
        )
        .await
        .unwrap();
    let code = laptop
        .offer(
            &folder,
            Offer {
                role,
                until: Timestamp((laptop.inner.config.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    let secret = intro.secret;
    (laptop, code, secret, alice)
}

/// The ask `joiner` sends `inviter` for `offer`, as [`Device::join`] builds
/// it, its credentials followed by `extra` certificates: its name and its
/// parameters.
fn ask(
    joiner: &Device,
    inviter: &Device,
    offer: &Name,
    secret: &[u8; crate::intro::SECRET_LEN],
    extra: &[Certificate],
) -> (Name, Bytes) {
    let j = &joiner.inner;
    let me = j.writer.key().clone();
    let digest = j.own_key.unwrap();
    let pk = proof_key(secret, offer);
    let nonce = j.nonce();
    let mut credentials = j.credentials().unwrap();
    credentials.extend(extra.iter().map(|c| c.data_wire().unwrap()));
    let mut body = AskBody {
        offer: offer.clone(),
        nonce,
        proof: ask_proof(&pk, offer, &me, &digest, &nonce),
        credentials,
        asker: Bytes::new(),
    };
    body.asker = j.ask_proof(&body.binding(inviter.name())).unwrap();
    let seal_key = inviter.inner.st.lock().intro.offers[offer].seal_key;
    let aad = intro_prefix(inviter.name()).encode_to_tlv();
    let ck = ContentKey::generate();
    let (ephemeral, key) = wrap_ck_to(&seal_key, &ck, &aad).unwrap();
    let params = IntroAsk {
        ephemeral,
        key: key.to_bytes(),
        sealed: ck.seal(&body.encode(), &aad).to_bytes(),
    }
    .encode();
    (intro_name(inviter.name(), &params), params)
}

/// What `inviter` answers the ask: `None` for no answer.
async fn answer(inviter: &Device, (name, params): (Name, Bytes)) -> Option<Outcome> {
    let reply = inviter.inner.answer_intro(&name, Some(params)).await?;
    let data = Data::decode(reply).unwrap();
    Some(
        AnswerBody::decode(data.content().unwrap().clone())
            .unwrap()
            .outcome,
    )
}

fn accepted(o: &Option<Outcome>) -> bool {
    matches!(o, Some(Outcome::Accepted { .. }))
}

#[tokio::test]
async fn a_joiner_whose_key_is_its_own_anchor_is_answered() {
    let (laptop, offer, secret) = alice(&[], None).await;
    // Carol's phone key is her namespace's anchor: no certificate to show.
    let phone = n("/carol/phone");
    let keys = Arc::new(SecurityManager::new());
    let k = keys.generate_ed25519(key(&phone)).unwrap();
    let carol = Person::rooted("/carol", &keys, &k);
    let carol_phone = start(&carol, "/carol/phone", Some(keys), &[], None).await;
    let got = answer(&laptop, ask(&carol_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        accepted(&got),
        "a joiner whose key is its anchor was answered {got:?}"
    );
}

#[tokio::test]
async fn only_the_certificates_of_the_verified_chain_go_into_the_validator() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    // Bob also presents a certificate of a key under Alice's name, signed
    // by his own root: on no chain of his, it must not be cached.
    let planted_key = n("/alice/laptop/KEY/9");
    let planted = bob.certify(&planted_key, &[7u8; 32]).await;
    let got = answer(
        &laptop,
        ask(&bob_phone, &laptop, &offer, &secret, &[planted]),
    )
    .await;
    assert!(accepted(&got), "bob was answered {got:?}");
    let cache = laptop.inner.validator.cert_cache();
    assert!(
        cache.all(&planted_key).is_empty(),
        "a certificate on no verified chain was cached"
    );
    assert!(
        cache.get_valid(&key(&n("/bob/phone"))).is_some(),
        "the asker's own certificate was not cached"
    );
}

/// Bob's phone asks with credentials carrying his namespace's version 1,
/// whose key his version 2 — the one Alice's laptop holds — revokes. Its
/// proof verifies under the context the credentials carry, but the device
/// judges it by what it holds after its host's adoption: refused.
#[tokio::test]
async fn an_ask_by_a_key_the_held_version_revokes_is_refused() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    let v2 = SignedTrustContext::hierarchical(n("/bob"))
        .with_version(2)
        .with_revocation(key(&n("/bob/phone")));
    let anchor = bob.ctx.anchors().iter().next().unwrap().value().clone();
    assert!(v2.add_anchor(anchor));
    laptop.inner.validator.adopt_context(Arc::new(v2)).unwrap();
    let got = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a key the held version revokes was answered {got:?}"
    );
}

#[tokio::test]
async fn an_offer_is_not_spent_when_the_host_does_not_adopt_the_asker() {
    let (laptop, offer, secret) = alice(&["/bob"], None).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    let got = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        got.is_none(),
        "bob, whose anchor the host refuses, was answered {got:?}"
    );
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone", None, &[], None).await;
    let got = answer(&laptop, ask(&carol_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        accepted(&got),
        "the offer was spent by an adoption that failed: carol was answered {got:?}"
    );
}

/// A device clock the test can move forward: the system's, plus a skew in
/// milliseconds.
fn skewed() -> (Clock, Arc<std::sync::atomic::AtomicU64>) {
    let skew = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let by = Arc::clone(&skew);
    let clock: Clock = Arc::new(move || {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Timestamp(now + by.load(std::sync::atomic::Ordering::SeqCst))
    });
    (clock, skew)
}

/// Spec §19.2: a closed offer admits no one new, and still answers a
/// retry of the writer it admitted — its answer lost — until it expires.
/// Another key is `Closed`; once the offer expired its user is `Expired`.
#[tokio::test]
async fn a_closed_offer_admits_no_one_new_yet_answers_the_one_it_admitted_until_it_expires() {
    let (clock, skew) = skewed();
    let (laptop, offer, secret) = alice_at(&[], None, Some(clock)).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone", None, &[], None).await;
    // Bob's answer is lost: the host closes the offer as soon as it sees
    // the new member, and Bob asks again.
    let first = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(accepted(&first), "bob was answered {first:?}");
    laptop.close_offer(&offer).await.unwrap();
    let again = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert_eq!(
        again, first,
        "the user of a closed offer asking again was not answered the acceptance it was given"
    );
    // Another key is refused as closed, even with the right secret.
    let other = answer(&laptop, ask(&carol_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(other, Some(Outcome::Refused(IntroRefusal::Closed))),
        "another key asking a closed offer was answered {other:?}"
    );
    // Past its expiry the offer answers nobody, its user included.
    skew.store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let late = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(late, Some(Outcome::Refused(IntroRefusal::Expired))),
        "the user of a closed offer asking after its expiry was answered {late:?}"
    );
}

/// An offer closed before anyone used it admits no one, whatever the key
/// and the secret.
#[tokio::test]
async fn an_offer_closed_unused_refuses_every_ask() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    laptop.close_offer(&offer).await.unwrap();
    let got = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an unused closed offer was answered {got:?}"
    );
}

/// Spec §19.2, §19.7: the automatic close of a record that drops the
/// member answers its user as `close_offer` does — what it was given, kept
/// — and admits it nowhere: no members record is signed again.
#[tokio::test]
async fn the_close_of_a_record_that_drops_the_member_still_answers_it_and_never_readmits_it() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let folder = n("/alice/32=data/notebook");
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    let first = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(accepted(&first), "bob was answered {first:?}");
    laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }
            .into(),
        )
        .await
        .unwrap();
    assert!(
        laptop.inner.st.lock().intro.closed.contains(&offer),
        "a record dropping the member did not close the offer it used"
    );
    let signed = laptop.inner.st.lock().head;
    let again = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert_eq!(
        again, first,
        "the removed member's retry was not answered as kept"
    );
    assert_eq!(
        laptop.inner.st.lock().head,
        signed,
        "answering the removed member's retry signed something: it was admitted again"
    );
}

/// Only the device that made an offer closes it.
#[tokio::test]
async fn only_the_device_that_made_an_offer_closes_it() {
    let (laptop, _, _) = alice(&[], None).await;
    let elsewhere = log_name(&n("/alice/phone"), Some(&n("/alice/32=data/notebook")), 1);
    assert!(matches!(
        laptop.close_offer(&elsewhere).await,
        Err(DataError::BadRequest { .. })
    ));
}

#[tokio::test]
async fn asks_beyond_the_queue_get_no_answer_at_once() {
    let started = Arc::new(Notify::new());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (laptop, offer, secret) = alice(&[], Some((Arc::clone(&started), Arc::clone(&gate)))).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    // Bob's ask is judged, and held at the host's adoption.
    let first = ask(&bob_phone, &laptop, &offer, &secret, &[]);
    let held = {
        let laptop = laptop.clone();
        tokio::spawn(async move { answer(&laptop, first).await })
    };
    started.notified().await;
    // As many more ask meanwhile as the device holds at once: past what it
    // holds, an ask is not kept waiting.
    let crowd = laptop.inner.config.intro.asks_queued;
    let mut asks = tokio::task::JoinSet::new();
    for _ in 0..crowd {
        let a = ask(&bob_phone, &laptop, &offer, &secret, &[]);
        let laptop = laptop.clone();
        asks.spawn(async move { answer(&laptop, a).await });
    }
    match tokio::time::timeout(Duration::from_secs(5), asks.join_next()).await {
        Ok(Some(got)) => assert!(got.unwrap().is_none(), "an ask past the queue was answered"),
        _ => panic!("every one of {crowd} asks waited behind an ask held in judgement"),
    }
    gate.add_permits(1);
    assert!(accepted(&held.await.unwrap()));
}

// ---- M2: a code is judged before anything is dialled -------------------------------------------

/// `code`'s link with the namespace it names replaced by `namespace`, and a
/// link hint to an address beyond this machine added: what a join would dial.
fn altered(code: &crate::intro::Code, namespace: Option<&str>) -> String {
    use crate::intro::{HintCandidate, HintKind, LinkHint};
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an introduction link");
    };
    intro.namespace = namespace.map(str::to_string);
    intro.link_hint = Some(
        LinkHint {
            key: [0x42; 32],
            candidates: vec![HintCandidate {
                kind: HintKind::Host,
                addr: "192.0.2.7:6363".parse().unwrap(),
            }],
        }
        .encode(),
    );
    TrustEnvelope::Intro(intro).to_uri()
}

/// Bob's phone, its host recording what it is asked to dial.
async fn bobs_phone(calls: &Arc<Calls>) -> Device {
    let bob = Person::new("/bob");
    start_recording(&bob, "/bob/phone", None, &[], None, None, Arc::clone(calls)).await
}

/// A code that names a namespace its device is not under is altered: the
/// join refuses it before it dials, since the dial gives whoever holds the
/// key a link.
#[tokio::test]
async fn a_code_whose_device_is_outside_the_namespace_it_names_dials_nothing() {
    let (_laptop, code, _secret, _alice) = alice_person(&[], None, None).await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    let got = phone.join(&altered(&code, Some("/evil"))).await;
    assert!(
        calls.dialled().is_empty(),
        "the join dialled {:?} for a code naming a namespace its device is not under (got {got:?})",
        calls.dialled()
    );
    assert!(
        matches!(
            got,
            Err(DataError::Introduction {
                why: IntroRefusal::Forged,
                ..
            })
        ),
        "{got:?}"
    );
}

/// A code whose device is under a namespace this device trusts, naming none
/// or another anchor of it, dials nothing: whoever holds its key would get
/// that namespace's Interests over the link.
#[tokio::test]
async fn a_code_whose_device_is_under_a_held_namespace_of_another_anchor_dials_nothing() {
    let (_laptop, code, _secret, _alice) = alice_person(&[], None, None).await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    // This device holds the real /alice, rooted in another key.
    let real = Person::new("/alice");
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&real.ctx))
        .unwrap();
    for named in [None, Some("/alice")] {
        let got = phone.join(&altered(&code, named)).await;
        assert!(
            calls.dialled().is_empty(),
            "the join dialled {:?} for a device under a held namespace the code does not \
             anchor (code names {named:?}; got {got:?})",
            calls.dialled()
        );
        assert!(
            matches!(
                got,
                Err(DataError::Introduction {
                    why: IntroRefusal::InviterConflict { .. },
                    ..
                })
            ),
            "{got:?}"
        );
    }
}

/// A second invitation from a namespace this device already holds, by the
/// anchor it holds, is still joined: the same anchor is a party known
/// already.
#[tokio::test]
async fn a_code_from_a_held_namespace_by_its_own_anchor_is_still_dialled() {
    let (laptop, code, _secret, alice) = alice_person(&[], None, None).await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    for named in [None, Some("/alice")] {
        let got = phone.join(&altered(&code, named)).await;
        assert_eq!(
            calls.dialled().last(),
            Some(laptop.name()),
            "the code names {named:?}; the join answered {got:?}"
        );
        // Past the dial it goes on to ask: nobody answers here, which is
        // `NotReady`, not a refusal of the code.
        assert!(matches!(got, Err(DataError::NotReady { .. })), "{got:?}");
    }
    assert!(
        calls.undialled().is_empty(),
        "a dial that failed made nothing to take down: {:?}",
        calls.undialled()
    );
}

/// A join that fails after its dial succeeded takes the dial's link down.
#[tokio::test]
async fn a_join_that_fails_after_its_dial_takes_the_link_down() {
    let (laptop, code, _secret, _alice) = alice_person(&[], None, None).await;
    let calls = Arc::new(Calls::default());
    calls
        .dial_succeeds
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let phone = bobs_phone(&calls).await;
    let got = phone.join(&altered(&code, Some("/alice"))).await;
    assert!(matches!(got, Err(DataError::NotReady { .. })), "{got:?}");
    assert_eq!(
        calls.undialled(),
        vec![laptop.name().clone()],
        "the failed join left its dial's link up"
    );
}

// ---- L2: the joined note ------------------------------------------------------------------------

/// Alice's namespace heard in its sync group, her laptop's summary walked
/// in full once `dev` follows `c`: a first put follows it, and a walk that
/// came before would not count for it.
async fn walked_alice(dev: &Device, laptop: &Name, c: &Name) {
    let _ = dev.put(c, Content::new(), options()).await;
    let _ = dev.inner.join(&n("/alice")).await;
    let mut st = dev.inner.st.lock();
    st.groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(laptop.clone());
    st.peers
        .entry((laptop.clone(), n("/alice")))
        .or_default()
        .root = Some([1; 32]);
}

fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// Hand `to` every log entry of `from` about `c` (its members records and
/// its offers' marks), as `from` signed them.
fn relay(from: &Device, to: &Device, c: &Name) {
    let head = from.inner.st.lock().head;
    for seq in 1..=head {
        let name = log_name(from.name(), Some(c), seq);
        let Some(wire) = from.inner.store.get(&name) else {
            continue;
        };
        let content = Data::decode(wire).unwrap().content().unwrap().clone();
        let record = wire::decode_record(content).unwrap();
        let k = key(from.name());
        let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&k),
            |_| Bytes::from_static(&[0; 64]),
        );
        let mut st = to.inner.st.lock();
        to.inner
            .take(&mut st, name.clone(), packet, Writer::new(k), record, false);
        assert_eq!(st.refused.get(&name), None, "the record was refused");
    }
}

/// Spec §19.2, §19.3: an offer's answer admitted this device, and its record
/// is on its way — a put is `NotReady`. An inviter that never sends it
/// cannot keep the device waiting for good: once the offer has expired the
/// device is told it is no member, and to ask the owner.
#[tokio::test]
async fn a_joiner_whose_inviter_never_sends_the_record_is_told_it_is_no_member_once_the_offer_expired()
 {
    let (clock, skew) = skewed();
    let (laptop, offer, _secret, alice) = {
        let (laptop, code, secret, alice) = alice_person(&[], None, None).await;
        (laptop, code.offer, secret, alice)
    };
    let bob = Person::new("/bob");
    let phone = start_clocked(&bob, "/bob/phone", None, &[], None, Some(clock)).await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    let folder = n("/alice/32=data/notebook");
    let note = folder.clone().append("note");
    walked_alice(&phone, laptop.name(), &note).await;
    let until = laptop.inner.st.lock().intro.offers[&offer].until;
    assert!(
        phone
            .inner
            .note_joined(&folder, until, Some(2), Role::Writer)
            .await
    );

    let waiting = phone.put(&note, Content::new(), options()).await;
    assert!(
        matches!(waiting, Err(DataError::NotReady { .. })),
        "while the offer stands the record is on its way: {waiting:?}"
    );
    skew.store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let past = phone.put(&note, Content::new(), options()).await;
    assert!(
        matches!(past, Err(DataError::NotAllowed { .. })),
        "past the offer's expiry a device no record admits is no member: {past:?}"
    );
    assert_eq!(
        past.unwrap_err().next(),
        crate::error::NextStep::AskOwner,
        "and it is told to ask the owner"
    );
}

/// A joiner the folder's members record removed, joining again with its
/// code (the offer answers it as it was, the revision it was admitted at
/// with it), is no member once it holds the record that removed it — not
/// `NotReady` for good.
#[tokio::test]
async fn a_removed_joiner_who_joins_again_is_told_it_is_no_member_not_to_wait() {
    let (laptop, code, secret, alice) = alice_person(&[], None, None).await;
    let offer = code.offer.clone();
    let folder = n("/alice/32=data/notebook");
    let note = folder.clone().append("note");
    let bob = Person::new("/bob");
    let phone = start(&bob, "/bob/phone", None, &[], None).await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    walked_alice(&phone, laptop.name(), &note).await;
    let until = laptop.inner.st.lock().intro.offers[&offer].until;

    let first = answer(&laptop, ask(&phone, &laptop, &offer, &secret, &[])).await;
    let Some(Outcome::Accepted { revision, .. }) = first.clone() else {
        panic!("bob was answered {first:?}");
    };
    let admitted = revision.expect("the answer carries the revision that admits the joiner");
    assert_eq!(
        admitted,
        laptop.inner.st.lock().folders[&folder]
            .members
            .as_ref()
            .unwrap()
            .revision
            .0
    );
    // Alice removes Bob: the next record leaves him out.
    laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }
            .into(),
        )
        .await
        .unwrap();
    // He joins again with the same code: answered as he was, admitted at the
    // revision before the removal.
    let again = answer(&laptop, ask(&phone, &laptop, &offer, &secret, &[])).await;
    assert_eq!(again, first, "the removed joiner was not answered as kept");
    assert!(
        phone
            .inner
            .note_joined(&folder, until, revision, Role::Writer)
            .await
    );
    relay(&laptop, &phone, &folder);

    let put = phone.put(&note, Content::new(), options()).await;
    assert!(
        matches!(
            put,
            Err(DataError::NotAllowed { .. } | DataError::Sealed { .. })
        ),
        "a joiner the record in hand removes is refused as any non-member, and does not wait: \
         {put:?}"
    );
}

/// Spec §15, §19.3: `join` returns once the joiner may write, and a put into
/// a new collection under the folder is `NotReady` while a device of the
/// namespace was not walked toward the folder (it may hold a record of the
/// collection that narrows the folder's). A join whose record came by the
/// offer's answer, with the inviter's summary not walked yet, therefore does
/// not return `Ok` and leave the first put `NotReady`: it waits for the walk
/// within its bound, and says what it waits for when the bound passes.
#[tokio::test(start_paused = true)]
async fn a_join_returns_only_once_the_inviters_summary_was_walked_toward_the_folder() {
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop", None, &[], None).await;
    let folder = n("/alice/32=data/notebook");
    let note = folder.clone().append("page-bob");
    laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: Vec::new(),
            }
            .into(),
        )
        .await
        .unwrap();
    let code = laptop
        .offer(
            &folder,
            Offer {
                role: Role::Writer,
                until: Timestamp((laptop.inner.config.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    let bob = Person::new("/bob");
    let phone = start(&bob, "/bob/phone", None, &[], None).await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    let answered = answer(
        &laptop,
        ask(&phone, &laptop, &code.offer, &intro.secret, &[]),
    )
    .await;
    let Some(Outcome::Accepted { revision, .. }) = answered else {
        panic!("bob was answered {answered:?}");
    };
    let until = laptop.inner.st.lock().intro.offers[&code.offer].until;
    assert!(
        phone
            .inner
            .note_joined(&folder, until, revision, Role::Writer)
            .await
    );
    // The record that admits Bob arrived; the inviter's summary was heard in
    // the group and not walked.
    relay(&laptop, &phone, &folder);
    phone.inner.follow(&folder).await.unwrap();
    let _ = phone.inner.join(&n("/alice")).await;
    phone
        .inner
        .st
        .lock()
        .groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(laptop.name().clone());

    let joined = phone
        .inner
        .await_admission(&folder, Role::Writer, laptop.name())
        .await;
    match &joined {
        Ok(()) => {
            let put = phone.put(&note, Content::new(), options()).await;
            assert!(
                put.is_ok(),
                "join returned Ok, yet the first put right after it is {put:?}"
            );
        }
        Err(DataError::NotReady { why, .. }) => assert!(
            why.contains("/alice/laptop") && why.contains("join again"),
            "a join that waits for the walk names the device and what to do: {why}"
        ),
        other => panic!("the join answered {other:?}"),
    }
    assert!(
        joined.is_err(),
        "the join returned Ok while the inviter's summary was not walked"
    );

    // Walked toward the folder: the join returns, and the first put goes
    // through.
    {
        let mut st = phone.inner.st.lock();
        let peer = st
            .peers
            .entry((laptop.name().clone(), n("/alice")))
            .or_default();
        peer.head = 1;
        peer.walked = 1;
        peer.toward = std::iter::once(folder.clone()).collect();
    }
    phone
        .inner
        .await_admission(&folder, Role::Writer, laptop.name())
        .await
        .unwrap();
    let put = phone.put(&note, Content::new(), options()).await;
    assert!(put.is_ok(), "the first put after the join: {put:?}");
}

// ---- L4: what the introduction link carries -----------------------------------------------------

/// The surface a host gives its link layer is open while an offer has not
/// expired — a closed one included, as it still answers the writer it
/// admitted — and carries the ask and the offer's own record, no other
/// piece the device holds by name.
#[tokio::test]
async fn the_introduction_surface_is_open_while_an_offer_stands_and_carries_only_it() {
    let (clock, skew) = skewed();
    let (laptop, offer, _secret) = alice_at(&[], None, Some(clock)).await;
    let surface = laptop.introductions();
    let device = laptop.name().clone();
    let folder = n("/alice/32=data/notebook");
    let ask = intro_prefix(&device).append("digest");
    let held_offer = wire::held_name(&device, &offer);
    let other = log_name(&device, Some(&folder), 1);
    assert_ne!(other, offer, "the folder's own record is another entry");

    assert!(surface.open(), "an unexpired offer is open");
    assert!(surface.carries(&held_offer), "the offer's record");
    assert!(surface.carries(&ask), "an ask");
    assert!(
        !surface.carries(&wire::held_name(&device, &other)),
        "a held piece that is no offer is carried"
    );
    assert!(
        !surface.carries(&wire::held_prefix(&device).append("anything")),
        "a name under the held prefix that names no offer is carried"
    );
    assert!(
        !surface.carries(&wire::held_name(&n("/alice/phone"), &offer)),
        "another device's held piece is carried"
    );

    laptop.close_offer(&offer).await.unwrap();
    assert!(
        surface.open(),
        "a closed offer still answers the writer it admitted until it expires"
    );
    skew.store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    assert!(!surface.open(), "an expired offer is not open");
    assert!(!surface.carries(&held_offer), "an expired offer's record");
    assert!(!surface.carries(&ask), "an ask, with no offer open");
}

/// A device that has made no offer takes no stranger's introduction link.
#[tokio::test]
async fn a_device_with_no_offer_has_no_open_surface() {
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop", None, &[], None).await;
    let surface = laptop.introductions();
    assert!(!surface.open());
    assert!(!surface.carries(&intro_prefix(laptop.name()).append("digest")));
}

// ---- the grant (spec §19.8) --------------------------------------------------------------------

const NINETY_DAYS_MS: u64 = 90 * 24 * 3600 * 1000;

/// The secret of a code.
fn secret_of(code: &crate::intro::Code) -> [u8; crate::intro::SECRET_LEN] {
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    intro.secret
}

/// `device`'s keys, its key certified by `person`'s root.
async fn keyed(person: &Person, device: &str) -> Arc<SecurityManager> {
    let device = n(device);
    let keys = Arc::new(SecurityManager::new());
    let k = keys.generate_ed25519(key(&device)).unwrap();
    let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
    keys.cert_cache().insert(person.certify(&k, &public).await);
    keys
}

/// Alice's laptop on a store and keys that outlive it, its host recording in
/// `calls`, and its notebook offered as `role`.
struct Inviter {
    laptop: Device,
    alice: Person,
    keys: Arc<SecurityManager>,
    store: Arc<dyn DataStore>,
    calls: Arc<Calls>,
    clock: Clock,
    skew: Arc<std::sync::atomic::AtomicU64>,
    offer: Name,
    secret: [u8; crate::intro::SECRET_LEN],
}

impl Inviter {
    async fn new(role: Role, grant_for: Option<Duration>, refuses: &[&str]) -> Inviter {
        Self::over(role, grant_for, refuses, Arc::new(MemoryStore::new())).await
    }

    /// [`Inviter::new`] over `store`.
    async fn over(
        role: Role,
        grant_for: Option<Duration>,
        refuses: &[&str],
        store: Arc<dyn DataStore>,
    ) -> Inviter {
        let policy = IntroPolicy {
            grant_for,
            ..IntroPolicy::new()
        };
        Self::over_policy(role, policy, refuses, store).await
    }

    /// [`Inviter::new`] with the introduction policy `policy`.
    async fn over_policy(
        role: Role,
        policy: IntroPolicy,
        refuses: &[&str],
        store: Arc<dyn DataStore>,
    ) -> Inviter {
        let (clock, skew) = skewed();
        let alice = Person::new("/alice");
        let keys = keyed(&alice, "/alice/laptop").await;
        let calls = Arc::new(Calls::default());
        let laptop = start_policy(
            &alice,
            "/alice/laptop",
            Some(Arc::clone(&keys)),
            refuses,
            None,
            Some(Arc::clone(&clock)),
            Arc::clone(&calls),
            policy,
            Arc::clone(&store),
        )
        .await;
        let (laptop, code, secret, alice) = alice_offers(laptop, alice, role).await;
        Inviter {
            laptop,
            alice,
            keys,
            store,
            calls,
            clock,
            skew,
            offer: code.offer,
            secret,
        }
    }

    /// Alice's laptop stopped and started again over its store and keys: a
    /// restart, its host a new one recording in `calls`.
    async fn restart(&mut self) -> Arc<Calls> {
        self.laptop.shutdown();
        let calls = Arc::new(Calls::default());
        self.laptop = start_policy(
            &self.alice,
            "/alice/laptop",
            Some(Arc::clone(&self.keys)),
            &[],
            None,
            Some(Arc::clone(&self.clock)),
            Arc::clone(&calls),
            IntroPolicy::new(),
            Arc::clone(&self.store),
        )
        .await;
        calls
    }

    /// What the laptop answers `joiner`'s ask for the first offer.
    async fn answers(&self, joiner: &Device) -> Option<Outcome> {
        answer(
            &self.laptop,
            ask(joiner, &self.laptop, &self.offer, &self.secret, &[]),
        )
        .await
    }

    /// Another offer of the notebook, as a writer: its name and secret.
    async fn another_offer(&self) -> (Name, [u8; crate::intro::SECRET_LEN]) {
        let code = self
            .laptop
            .offer(
                &n("/alice/32=data/notebook"),
                Offer {
                    role: Role::Writer,
                    until: Timestamp((self.clock)().0 + 3_600_000),
                    tries: 3,
                },
            )
            .await
            .unwrap();
        let secret = secret_of(&code);
        (code.offer, secret)
    }
}

/// A person's phone, its host recording nothing of interest.
async fn phone_of(ns: &str) -> Device {
    let person = Person::new(ns);
    start(&person, &format!("{ns}/phone"), None, &[], None).await
}

async fn a_grant_is_made_once_for_the_admitted_key(role: Role, grant_for: Option<Duration>) {
    let alice = Inviter::new(role, grant_for, &[]).await;
    let bob_phone = phone_of("/bob").await;
    let before = (alice.clock)().0;
    let first = alice.answers(&bob_phone).await;
    let after = (alice.clock)().0;
    assert!(accepted(&first), "bob was answered {first:?}");
    let granted = alice.calls.granted();
    assert_eq!(
        granted.len(),
        1,
        "an admitted asker was granted {} times, not once",
        granted.len()
    );
    let g = &granted[0];
    assert_eq!(
        g.key,
        bob_phone.inner.own_key.unwrap(),
        "the grant names another key than the asker's"
    );
    assert_eq!(
        g.namespaces,
        vec![n("/bob")],
        "the grant names other namespaces than the asker's"
    );
    assert_eq!(g.folder, n("/alice/32=data/notebook"));
    assert_eq!(g.role, role, "the grant does not carry the offer's role");
    match grant_for {
        Some(d) => {
            let ms = d.as_millis() as u64;
            assert!(
                g.until
                    .is_some_and(|t| (before + ms..=after + ms).contains(&t.0)),
                "the grant ends at {:?}, not grant_for after the admission",
                g.until
            );
        }
        None => assert_eq!(
            g.until, None,
            "a grant with no grant_for bound carries a date: it follows the members record"
        ),
    }
    assert_eq!(
        alice.laptop.grants(),
        granted,
        "Device::grants is not what the host was told"
    );

    // The same key asking again is answered as before: no second grant, and
    // the end is not moved.
    alice.skew.store(5_000, std::sync::atomic::Ordering::SeqCst);
    let again = alice.answers(&bob_phone).await;
    assert_eq!(again, first, "the retry was not answered as kept");
    assert_eq!(
        alice.calls.granted(),
        granted,
        "a retry of the admitted key was granted again"
    );
    assert_eq!(
        alice.laptop.grants(),
        granted,
        "a retry moved the end of the grant"
    );

    // Another key finds the offer used: refused, and granted nothing.
    let carol_phone = phone_of("/carol").await;
    let other = alice.answers(&carol_phone).await;
    assert!(
        matches!(other, Some(Outcome::Refused(IntroRefusal::Used))),
        "another key asking a used offer was answered {other:?}"
    );
    assert_eq!(
        alice.calls.granted(),
        granted,
        "a refused ask was granted a link"
    );
    assert_eq!(alice.laptop.grants(), granted);
}

/// Spec §19.8: an offer's admission makes one grant, for the admitted key and
/// the asker's namespace, with the offer's role; a retry and a refused ask
/// make none.
#[tokio::test]
async fn a_writers_admission_is_granted_once_and_only_to_its_key() {
    a_grant_is_made_once_for_the_admitted_key(
        Role::Writer,
        Some(Duration::from_millis(NINETY_DAYS_MS)),
    )
    .await;
}

#[tokio::test]
async fn a_readers_admission_is_granted_once_with_the_readers_role() {
    a_grant_is_made_once_for_the_admitted_key(Role::Reader, None).await;
}

/// Spec §19.8: no ask that is refused or not completed grants anything.
#[tokio::test]
async fn a_refused_or_unfinished_ask_grants_nothing() {
    let alice = Inviter::new(
        Role::Writer,
        Some(Duration::from_millis(NINETY_DAYS_MS)),
        &["/dave"],
    )
    .await;
    let bob_phone = phone_of("/bob").await;
    // A wrong secret.
    let wrong = ask(
        &bob_phone,
        &alice.laptop,
        &alice.offer,
        &[9; crate::intro::SECRET_LEN],
        &[],
    );
    let got = answer(&alice.laptop, wrong).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::WrongProof { .. }))),
        "a wrong secret was answered {got:?}"
    );
    // A namespace that overlaps the inviter's own.
    let mallory = Person::new("/alice");
    let mallory_phone = start(&mallory, "/alice/mallory", None, &[], None).await;
    let got = alice.answers(&mallory_phone).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a namespace over the inviter's own was answered {got:?}"
    );
    // A host that does not adopt the asker: the offer is not spent.
    let dave = Person::new("/dave");
    let dave_phone = start(&dave, "/dave/phone", None, &[], None).await;
    let got = alice.answers(&dave_phone).await;
    assert_eq!(got, None, "an asker the host does not adopt was answered");
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "an ask that was refused or not completed was granted a link"
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
    // Once closed, a new key is refused, and granted nothing either.
    alice.laptop.close_offer(&alice.offer).await.unwrap();
    let got = alice.answers(&bob_phone).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an asker of a closed offer was answered {got:?}"
    );
    // Past its expiry, too.
    alice
        .skew
        .store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let got = alice.answers(&bob_phone).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(
                IntroRefusal::Closed | IntroRefusal::Expired
            ))
        ),
        "an asker of an expired offer was answered {got:?}"
    );
    assert_eq!(alice.calls.granted(), Vec::new());
    assert_eq!(alice.laptop.grants(), Vec::new());
}

/// Broad names are reserved for introductions by the default policy: a
/// stranger cannot bring `/com`, yet `/com/acme` is a person's like any other.
#[test]
fn the_default_policy_refuses_broad_names_and_welcomes_names_under_them() {
    let policy = IntroPolicy::new();
    let why = policy
        .refuses(&n("/com"))
        .expect("the default policy refuses /com");
    assert!(
        why.contains("/com") && why.contains("IntroPolicy::shared"),
        "the refusal of /com does not name the name and the field to change: {why}"
    );
    for broad in [
        "/user", "/com", "/org", "/net", "/edu", "/gov", "/mil", "/int", "/info", "/biz", "/arpa",
        "/ndn", "/example", "/test", "/local", "/invalid",
    ] {
        assert!(
            policy.refuses(&n(broad)).is_some(),
            "the default policy brings {broad}"
        );
    }
    assert_eq!(
        policy.refuses(&n("/com/acme")),
        None,
        "a name under a broad one is a person's like any other"
    );
    assert!(
        policy.refuses(&n("/localhost/x")).is_some(),
        "a name under a reserved scope is brought"
    );
    // A deployment frees a broad name by removing it from `shared`.
    let mut freed = IntroPolicy::new();
    freed.shared.retain(|s| s != &n("/com"));
    assert_eq!(freed.refuses(&n("/com")), None);
}

/// A joiner whose namespace is a broad name is refused as a conflict, in the
/// round trip, not only by the policy's own check.
#[tokio::test]
async fn a_joiner_claiming_a_broad_name_is_answered_conflict() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let org = Person::new("/org");
    let org_phone = start(&org, "/org/phone", None, &[], None).await;
    let got = answer(&laptop, ask(&org_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a joiner claiming /org was answered {got:?}"
    );
}

/// Spec §19.8: `grant_for` `Some(ZERO)`: the asker is admitted, nothing is kept, and
/// the host is told nothing.
#[tokio::test]
async fn a_zero_grant_for_makes_no_grant_and_keeps_no_note() {
    let alice = Inviter::new(Role::Writer, Some(Duration::ZERO), &[]).await;
    let bob_phone = phone_of("/bob").await;
    let got = alice.answers(&bob_phone).await;
    assert!(accepted(&got), "bob was answered {got:?}");
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "grant_for = Some(ZERO) granted a link"
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
    let kept = alice
        .store
        .scan_under(&super::intro::local_name_base("grant"), 0);
    assert!(
        kept.is_empty(),
        "grant_for = Some(ZERO) kept {} grant notes",
        kept.len()
    );
}

/// Spec §19.8: a grant is lapsed when its time passes by the device's clock: not
/// in force, and not announced as revoked (the link layer judges expiry itself).
#[tokio::test]
async fn a_grant_lapses_with_its_time_and_is_not_announced_as_revoked() {
    let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600)), &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop.grants().len(), 1);
    alice
        .skew
        .store(3 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "a grant past its time is still in force"
    );
    alice.laptop.inner.settle().await;
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
}

/// The folder's members record that leaves `drop` out, signed by Alice's phone
/// at the revision above the laptop's record in force, as that device's view of
/// the line: the person's writer entry cut, its reader entry gone.
fn phone_leaves_out(laptop: &Device, folder: &Name, drop: &Name) -> MembersBody {
    let m = laptop.inner.st.lock().folders[folder]
        .members
        .clone()
        .expect("a record is held");
    let epoch = Epoch {
        creator: n("/alice/phone"),
        seq: Seq(1),
    };
    MembersBody {
        collection: folder.clone(),
        folder: true,
        revision: m.revision.0 + 1,
        rule: m.rule.clone(),
        writers: m.writers.iter().filter(|w| *w != drop).cloned().collect(),
        readers: m
            .readers
            .iter()
            .filter(|r| !matches!(r, Audience::Person(p) if p == drop))
            .cloned()
            .collect(),
        cuts: vec![CutBody {
            of: drop.clone(),
            accept: Accepted::new(),
        }],
        epoch: Some(epoch.clone()),
        key_check: Some(seal::key_check(&ContentKey::generate(), folder, &epoch)),
        since: None,
        parent: Some(m.as_parent()),
    }
}

/// `body`, as Alice's phone signed it at seq 1 of its log, handed to `to`:
/// the record's name.
fn from_the_phone(to: &Device, body: MembersBody) -> Name {
    from_device(to, "/alice/phone", body)
}

/// `body`, as `device` (a device of Alice's) signed it at seq 1 of its log
/// (about the collection it names), handed to `to`: the record's name.
fn from_device(to: &Device, device: &str, body: MembersBody) -> Name {
    let device = n(device);
    let name = log_name(&device, Some(&body.collection), 1);
    let record = Record::Members(body);
    let k = key(&device);
    let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&k),
        |_| Bytes::from_static(&[0; 64]),
    );
    let mut st = to.inner.st.lock();
    to.inner
        .take(&mut st, name.clone(), packet, Writer::new(k), record, false);
    assert_eq!(
        st.refused.get(&name),
        None,
        "the record of {device} was refused"
    );
    name
}

/// Spec §19.8: a members record held that leaves the person out ends the
/// grant — signed by another device of the inviter's person too — once and
/// durably; the others' grants stand, and after a restart `Device::grants` is
/// the same less the ended.
#[tokio::test]
async fn a_record_of_another_device_that_leaves_the_person_out_revokes_the_grant() {
    let mut alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    let carol_phone = phone_of("/carol").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let (offer2, secret2) = alice.another_offer().await;
    let got = answer(
        &alice.laptop,
        ask(&carol_phone, &alice.laptop, &offer2, &secret2, &[]),
    )
    .await;
    assert!(accepted(&got), "carol was answered {got:?}");
    let both = alice.laptop.grants();
    assert_eq!(both.len(), 2, "two admissions, {} grants", both.len());
    let carols = both
        .iter()
        .find(|g| g.namespaces == [n("/carol")])
        .cloned()
        .expect("carol is granted");

    // The phone's record drops Bob. No record of this device is signed for it.
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.calls.revoked(),
        vec![bob_phone.inner.own_key.unwrap()],
        "a held record signed by another device that leaves bob out did not revoke exactly bob's grant"
    );
    assert_eq!(
        alice.laptop.grants(),
        vec![carols.clone()],
        "Device::grants after a record that leaves bob out is not carol's grant alone"
    );
    // Not again: the end is noted, however often records are settled.
    alice.laptop.inner.settle().await;
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.calls.revoked().len(),
        1,
        "the end of a grant was announced more than once"
    );

    // After a restart the grants are the same, less the ended; the host is not
    // told to revoke what is not granted, nor to grant what the device installs.
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop.grants(),
        vec![carols],
        "Device::grants after a restart is not what it was"
    );
    assert_eq!(
        again.granted(),
        Vec::new(),
        "a restart granted again by itself"
    );
    assert_eq!(
        again.revoked(),
        Vec::<[u8; 32]>::new(),
        "a restart revoked again"
    );

    // Bob, readmitted by a later record, is not granted again by that.
    alice
        .laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice"), n("/bob")],
                readers: vec![
                    Audience::Person(n("/alice")),
                    Audience::Person(n("/bob")),
                    Audience::Person(n("/carol")),
                ],
            }
            .into(),
        )
        .await
        .unwrap();
    assert!(
        alice
            .laptop
            .grants()
            .iter()
            .all(|g| g.key != bob_phone.inner.own_key.unwrap()),
        "a person a record readmitted was granted again by it"
    );
}

/// Spec §19.8: the record this device signs itself, leaving the person out,
/// ends the grant as well.
#[tokio::test]
async fn a_record_this_device_signs_that_leaves_the_person_out_revokes_the_grant() {
    let alice = Inviter::new(Role::Reader, None, &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop.grants().len(), 1);
    alice
        .laptop
        .share_folder(
            &n("/alice/32=data/notebook"),
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }
            .into(),
        )
        .await
        .unwrap();
    assert_eq!(
        alice.calls.revoked(),
        vec![bob_phone.inner.own_key.unwrap()],
        "a record this device signed that leaves bob out did not revoke his grant"
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
}

/// The only grant note an inviter's store keeps, changed in place by `edit`
/// as a party that can write the store would.
fn tamper(store: &dyn DataStore, edit: impl FnOnce(&mut Vec<u8>)) {
    let base = super::intro::local_name_base("grant");
    let mut notes = store.scan_under(&base, 0);
    assert_eq!(notes.len(), 1, "one admission, one grant note");
    let (name, value) = notes.pop().unwrap();
    let mut bytes = value.to_vec();
    edit(&mut bytes);
    store.insert(name, Bytes::from(bytes));
}

/// The octet of a grant note that holds its flags (version, flags, role, ...),
/// and the octets of its date.
const NOTE_FLAGS: usize = 1;
const NOTE_UNTIL: std::ops::Range<usize> = 3..11;

/// A store whose flush does not finish while it is frozen: a disk that has
/// stopped answering.
struct Frozen {
    inner: MemoryStore,
    frozen: std::sync::atomic::AtomicBool,
}

impl Frozen {
    fn new() -> Arc<Frozen> {
        Arc::new(Frozen {
            inner: MemoryStore::new(),
            frozen: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn freeze(&self, on: bool) {
        self.frozen.store(on, std::sync::atomic::Ordering::SeqCst);
    }
}

impl DataStore for Frozen {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.inner.remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        while self.frozen.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}

const TEN_YEARS_MS: u64 = 10 * 365 * 24 * 3600 * 1000;

/// Spec §19.8 (no cliff): a grant with no date lasts as long as the members record
/// admits the person, however far the clock goes; a held record that leaves the
/// person out ends it.
#[tokio::test]
async fn a_grant_with_no_date_follows_the_members_record_not_the_clock() {
    let mut alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let told = alice.calls.granted();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].until, None, "the default grant carries a date");
    alice
        .skew
        .store(TEN_YEARS_MS, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        alice.laptop.grants(),
        told,
        "a grant with no date ended with the clock"
    );
    alice.restart().await;
    assert_eq!(
        alice.laptop.grants(),
        told,
        "a grant with no date ended with the clock across a restart"
    );
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "a record that leaves the person out did not end a grant with no date"
    );
}

/// Spec §19.8 (host control): the host's end of a grant is durable — a restart
/// does not bring it back — and its renewal sets a date durably, for a grant
/// the record still admits, past its old date or not; the Device tells the host
/// nothing itself.
#[tokio::test]
async fn the_host_ends_and_renews_a_grant_durably() {
    let mut alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600)), &[]).await;
    let bob_phone = phone_of("/bob").await;
    let bob = bob_phone.inner.own_key.unwrap();
    assert!(accepted(&alice.answers(&bob_phone).await));
    let first = alice.laptop.grants();
    assert_eq!(first.len(), 1);

    // Past its date the grant is over; the host renews it: it is back, and
    // stays back across a restart.
    alice
        .skew
        .store(3 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(alice.laptop.grants(), Vec::new());
    let now = (alice.clock)().0;
    let later = Timestamp(now + 3_600_000);
    let renewed = alice
        .laptop
        .renew_grant(&bob, Some(later))
        .await
        .expect("a renewal of a grant a held record admits")
        .expect("a grant past its date is renewable");
    assert_eq!(renewed.until, Some(later));
    assert_eq!(renewed.key, bob);
    assert_eq!(alice.laptop.grants(), vec![renewed.clone()]);
    alice.restart().await;
    assert_eq!(
        alice.laptop.grants(),
        vec![renewed.clone()],
        "a renewal did not survive a restart"
    );

    // A date not after the clock is refused, saying what to do; nothing moves.
    let e = alice
        .laptop
        .renew_grant(&bob, Some(Timestamp(now - 1)))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, DataError::BadRequest { why, .. } if why.contains("give a later date")),
        "a renewal to a past date was answered {e:?}"
    );
    assert_eq!(alice.laptop.grants(), vec![renewed]);

    // No date: the grant follows the record from now on.
    let undated = alice.laptop.renew_grant(&bob, None).await.unwrap().unwrap();
    assert_eq!(undated.until, None);
    alice
        .skew
        .store(TEN_YEARS_MS, std::sync::atomic::Ordering::SeqCst);
    alice.restart().await;
    assert_eq!(alice.laptop.grants(), vec![undated]);

    // The host ends it: durably, once; a key nobody granted is none.
    assert!(alice.laptop.end_grant(&bob).await.unwrap());
    assert_eq!(alice.laptop.grants(), Vec::new());
    assert!(
        !alice.laptop.end_grant(&bob).await.unwrap(),
        "an ended grant was ended again"
    );
    assert_eq!(alice.laptop.renew_grant(&bob, None).await.unwrap(), None);
    assert!(!alice.laptop.end_grant(&[7; 32]).await.unwrap());
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "the host's end of a grant did not survive a restart"
    );
    assert_eq!(again.granted(), Vec::new());
    // The Device itself told the host nothing of all of it.
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
    assert_eq!(alice.calls.granted().len(), 1);
}

/// Spec §19.8: a grant a held record ended is not renewed — the person is out;
/// offer the folder again.
#[tokio::test]
async fn a_grant_a_record_ended_is_not_renewed() {
    let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600)), &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    let bob = bob_phone.inner.own_key.unwrap();
    assert!(accepted(&alice.answers(&bob_phone).await));
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    assert_eq!(
        alice
            .laptop
            .renew_grant(&bob, Some(Timestamp((alice.clock)().0 + 1_000_000)))
            .await
            .unwrap(),
        None,
        "a person a held record leaves out was renewed a grant"
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
}

/// Spec §19.8 (notes are checked): a party that can write the data store, but
/// not the key store, cannot bring an ended grant back or lengthen a lapsed
/// one: a note that was changed fails its MAC and is ignored.
#[tokio::test]
async fn a_tampered_grant_note_is_ignored_not_resurrected() {
    // The ended flag cleared on a grant the host ended.
    let mut alice = Inviter::new(Role::Writer, None, &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert!(
        alice
            .laptop
            .end_grant(&bob_phone.inner.own_key.unwrap())
            .await
            .unwrap()
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
    tamper(&*alice.store, |b| b[NOTE_FLAGS] &= !1);
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "a note with its ended flag cleared in the store brought the grant back"
    );
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "a note with its ended flag cleared in the store brought the grant back at a restart"
    );
    assert_eq!(again.granted(), Vec::new());

    // The date pushed out, or taken off, on a grant that lapsed.
    for how in ["extended", "removed"] {
        let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600)), &[]).await;
        let bob_phone = phone_of("/bob").await;
        assert!(accepted(&alice.answers(&bob_phone).await));
        alice
            .skew
            .store(3 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(alice.laptop.grants(), Vec::new());
        tamper(&*alice.store, |b| {
            if how == "extended" {
                b[NOTE_UNTIL].copy_from_slice(&u64::MAX.to_be_bytes());
            } else {
                b[NOTE_FLAGS] &= !2;
            }
        });
        assert_eq!(
            alice.laptop.grants(),
            Vec::new(),
            "a note whose date was {how} in the store brought a lapsed grant back"
        );
    }

    // An unchanged note is read: the check is not a refusal of everything.
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop.grants().len(), 1);
}

/// Spec §19.8 (role re-derived): the grant's role is the one the members record
/// in force gives the person, at every judgement — a writer demoted to a
/// reader is listed as a reader at once, and the host is told again, once; the
/// note then bears it across a restart.
#[tokio::test]
async fn a_writer_demoted_to_a_reader_is_granted_as_a_reader() {
    let mut alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    let bob = bob_phone.inner.own_key.unwrap();
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop.grants()[0].role, Role::Writer);

    let mut demoted = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    demoted.readers.push(Audience::Person(n("/bob")));
    from_the_phone(&alice.laptop, demoted);
    let now = alice.laptop.grants();
    assert_eq!(now.len(), 1, "a demoted person lost the grant: {now:?}");
    assert_eq!(
        now[0].role,
        Role::Reader,
        "a writer a held record demoted to a reader is still granted as a writer"
    );
    alice.laptop.inner.settle().await;
    let told = alice.calls.granted();
    assert_eq!(
        told.len(),
        2,
        "the host was told {told:?}: the admission and, once, the new role"
    );
    assert_eq!(told[1].role, Role::Reader);
    assert_eq!(told[1].key, bob);
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.calls.granted().len(),
        2,
        "the new role was told twice"
    );

    // Durable: after a restart the grant is a reader's and nothing is told again.
    let again = alice.restart().await;
    assert_eq!(alice.laptop.grants(), now);
    assert_eq!(
        again.granted(),
        Vec::new(),
        "the demotion was not in the note: a restart told the host again"
    );
}

/// Spec §19.8 (host first): a record that leaves the person out tells the host
/// before the end is made durable — a disk that has stopped answering does not
/// delay the link layer's end.
#[tokio::test]
async fn the_host_is_told_of_an_end_before_it_is_durable() {
    let store = Frozen::new();
    let alice = Inviter::over(Role::Writer, None, &[], store.clone()).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    // A failing assertion must not leave the disk frozen: the runtime would wait for it.
    struct Thaw(Arc<Frozen>);
    impl Drop for Thaw {
        fn drop(&mut self) {
            self.0.freeze(false);
        }
    }
    store.freeze(true);
    let _thaw = Thaw(store.clone());
    let stuck = tokio::time::timeout(
        Duration::from_millis(300),
        alice.laptop.inner.judge_grants(),
    )
    .await;
    assert!(stuck.is_err(), "the durable end finished on a frozen disk");
    assert_eq!(
        alice.calls.revoked(),
        vec![bob_phone.inner.own_key.unwrap()],
        "the host was not told of the end while the disk was stopped"
    );
}

// ---- round 7: a grant for each folder, and the departure of a person let go (spec §19.8) -------

/// Alice's laptop shares `folder` with herself when it holds no record of it,
/// offers it as `role`, and `who` is admitted by that offer: its name.
async fn invite_to(alice: &Inviter, folder: &Name, role: Role, who: &Device) -> Name {
    let held = alice
        .laptop
        .inner
        .st
        .lock()
        .folders
        .get(folder)
        .is_some_and(|f| f.line.own.is_some());
    if !held {
        alice
            .laptop
            .share_folder(
                folder,
                Share {
                    rule: Rule::Log,
                    writers: vec![n("/alice")],
                    readers: vec![Audience::Person(n("/alice"))],
                }
                .into(),
            )
            .await
            .unwrap();
    }
    let code = alice
        .laptop
        .offer(
            folder,
            Offer {
                role,
                until: Timestamp((alice.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let got = answer(
        &alice.laptop,
        ask(who, &alice.laptop, &code.offer, &secret_of(&code), &[]),
    )
    .await;
    assert!(accepted(&got), "{} was answered {got:?}", who.name());
    code.offer
}

/// Alice's notebook and diary, Bob (one phone, one key) let into both as a
/// writer by two offers: the inviter, Bob's phone, his key.
async fn bob_in_two_folders() -> (Inviter, Device, [u8; 32], Name, Name) {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let diary = n("/alice/32=data/diary");
    invite_to(&alice, &diary, Role::Writer, &bob_phone).await;
    let bob = bob_phone.inner.own_key.unwrap();
    (alice, bob_phone, bob, n("/alice/32=data/notebook"), diary)
}

const SEVEN_DAYS_MS: u64 = 7 * 24 * 3600 * 1000;

/// Spec §19.8 (a second folder): two offers to one person are two grants of
/// one key; a record that lets the person go of one folder ends that
/// folder's grant alone and tells the host which.
#[tokio::test]
async fn two_offers_to_one_person_are_two_grants_and_a_record_ends_one_folders_alone() {
    let (alice, _bob_phone, bob, notebook, diary) = bob_in_two_folders().await;
    let grants = alice.laptop.grants();
    assert_eq!(grants.len(), 2, "two offers, {grants:?}");
    assert!(grants.iter().all(|g| g.key == bob));
    let folders: std::collections::BTreeSet<Name> =
        grants.iter().map(|g| g.folder.clone()).collect();
    assert_eq!(
        folders,
        std::collections::BTreeSet::from([notebook.clone(), diary.clone()]),
        "the two grants of one key are not one for each folder"
    );
    assert_eq!(alice.calls.granted().len(), 2);

    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &notebook, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.calls.revoked_in(),
        vec![(bob, notebook.clone())],
        "a record that lets Bob go of the notebook did not revoke exactly (his key, the notebook)"
    );
    let left = alice.laptop.grants();
    assert_eq!(
        left.iter().map(|g| g.folder.clone()).collect::<Vec<_>>(),
        vec![diary.clone()],
        "letting Bob go of the notebook ended his grant of the diary"
    );
    // Once, however often records are settled.
    alice.laptop.inner.settle().await;
    assert_eq!(alice.calls.revoked_in().len(), 1);

    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &diary, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(
        alice.calls.revoked_in(),
        vec![(bob, notebook), (bob, diary)],
        "the second folder's end was not told by itself, naming it"
    );
    assert_eq!(alice.laptop.grants(), Vec::new());
}

/// Spec §19.8 (the departure): a held record that lets the person go leaves a
/// mark in the grant's note — the record's name and a date — that the host is
/// told of before the end, that `Device::departures` lists, that a restart
/// keeps, and that the clock ends.
#[tokio::test]
async fn a_record_that_lets_the_person_go_leaves_a_departure_mark() {
    let mut alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    let bob = bob_phone.inner.own_key.unwrap();
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(
        alice.laptop.departures(),
        Vec::new(),
        "a mark before a record"
    );

    let before = (alice.clock)().0;
    let record = from_device(
        &alice.laptop,
        "/alice/phone",
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    let after = (alice.clock)().0;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    let mark = &marks[0];
    assert_eq!(mark.key, bob);
    assert_eq!(mark.namespaces, vec![n("/bob")]);
    assert_eq!(mark.folder, folder);
    assert_eq!(mark.record, record, "the mark names another record");
    assert!(
        (before + SEVEN_DAYS_MS..=after + SEVEN_DAYS_MS).contains(&mark.until.0),
        "the mark ends at {:?}, not seven days after the end of the grant",
        mark.until
    );
    assert_eq!(
        alice.calls.departed(),
        marks,
        "the host was told another mark"
    );
    assert_eq!(
        alice.calls.order(),
        vec!["departure", "revoke_grant"],
        "the host is told of the departure just before the end of the grant"
    );

    // Durable: the same marks after a restart; the device tells the host
    // nothing by itself (whoever installs `departures` does).
    let again = alice.restart().await;
    assert_eq!(alice.laptop.departures(), marks, "a restart lost the mark");
    assert_eq!(again.departed(), Vec::new());
    assert_eq!(again.revoked_in(), Vec::new());

    // The clock ends it: not listed after its date.
    alice
        .skew
        .store(SEVEN_DAYS_MS + 5_000, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        alice.laptop.departures(),
        Vec::new(),
        "a mark past its date is still listed"
    );
}

/// Spec §19.8 (`departure_for`): zero makes no mark and the host is told of
/// the end alone.
#[tokio::test]
async fn a_zero_departure_for_makes_no_mark() {
    let policy = IntroPolicy {
        departure_for: Duration::ZERO,
        ..IntroPolicy::new()
    };
    let alice = Inviter::over_policy(Role::Writer, policy, &[], Arc::new(MemoryStore::new())).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(alice.laptop.grants(), Vec::new());
    assert_eq!(alice.laptop.departures(), Vec::new());
    assert_eq!(alice.calls.departed(), Vec::new());
    assert_eq!(alice.calls.order(), vec!["revoke_grant"]);
}

/// Spec §19.8: the host's own end makes no mark (the person was not let go by
/// a record), and `end_grant_in` ends one folder's grants alone.
#[tokio::test]
async fn the_hosts_own_end_makes_no_mark_and_end_grant_in_ends_one_folder() {
    let (mut alice, _bob_phone, bob, notebook, diary) = bob_in_two_folders().await;
    assert!(alice.laptop.end_grant_in(&bob, &notebook).await.unwrap());
    assert!(
        !alice.laptop.end_grant_in(&bob, &notebook).await.unwrap(),
        "an ended grant was ended again"
    );
    assert!(
        !alice
            .laptop
            .end_grant_in(&bob, &n("/alice/32=data/other"))
            .await
            .unwrap(),
        "a folder nobody granted was ended"
    );
    assert_eq!(
        alice
            .laptop
            .grants()
            .iter()
            .map(|g| g.folder.clone())
            .collect::<Vec<_>>(),
        vec![diary.clone()],
        "ending one folder's grant did not leave the other's"
    );
    assert_eq!(
        alice.laptop.departures(),
        Vec::new(),
        "the host's end left a mark"
    );
    assert!(alice.laptop.end_grant(&bob).await.unwrap());
    assert_eq!(alice.laptop.grants(), Vec::new());
    assert_eq!(alice.laptop.departures(), Vec::new());
    alice.restart().await;
    assert_eq!(alice.laptop.grants(), Vec::new());
    assert_eq!(alice.laptop.departures(), Vec::new());
    assert_eq!(alice.calls.departed(), Vec::new());
    assert_eq!(
        alice.calls.revoked_in(),
        Vec::new(),
        "the device told the host of the host's own end"
    );
}

/// Spec §19.8 (two notes of one key): the marks of two notes are two marks,
/// each of its folder's record, listed by folder; the grant that stands is not
/// affected; a person invited again to the folder they were let go of has no
/// mark of it.
#[tokio::test]
async fn two_notes_of_one_key_keep_a_mark_each_and_an_invitation_again_supersedes_one() {
    let (alice, bob_phone, bob, notebook, diary) = bob_in_two_folders().await;
    let r1 = from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &notebook, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1);
    assert_eq!((&marks[0].folder, &marks[0].record), (&notebook, &r1));
    assert_eq!(alice.laptop.grants().len(), 1, "the diary's grant stands");

    let r2 = from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &diary, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 2, "{marks:?}");
    for (folder, record) in [(&notebook, &r1), (&diary, &r2)] {
        assert!(
            marks
                .iter()
                .any(|m| m.key == bob && &m.folder == folder && &m.record == record),
            "no mark of {folder} by {record}: {marks:?}"
        );
    }

    // Invited into the notebook again: the old mark of the notebook is no
    // longer shown (the person holds a grant of it); the diary's stands.
    alice
        .laptop
        .share_folder(
            &notebook,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice"), n("/bob")],
                readers: vec![Audience::Person(n("/alice")), Audience::Person(n("/bob"))],
            }
            .into(),
        )
        .await
        .unwrap();
    let (offer, secret) = alice.another_offer().await;
    let got = answer(
        &alice.laptop,
        ask(&bob_phone, &alice.laptop, &offer, &secret, &[]),
    )
    .await;
    assert!(accepted(&got), "bob was invited again and answered {got:?}");
    let marks = alice.laptop.departures();
    assert_eq!(
        marks.iter().map(|m| m.folder.clone()).collect::<Vec<_>>(),
        vec![diary],
        "a person invited again still has the mark of the folder"
    );
    assert_eq!(
        alice
            .laptop
            .grants()
            .iter()
            .filter(|g| g.folder == notebook)
            .count(),
        1
    );
}

/// Spec §19.8 (which record): among the records of the highest revision held,
/// the one whose own writers and readers leave the person out — lowest signer
/// first.
#[tokio::test]
async fn the_mark_names_the_lowest_signers_record_that_leaves_the_person_out() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let body = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    let high = from_device(&alice.laptop, "/alice/phone", body.clone());
    let low = from_device(&alice.laptop, "/alice/aaa", body);
    assert!(low < high, "the test names the lower signer first");
    // Judged as the records stand: the laptop's own resolving record, which a
    // settle signs, would be the highest revision (and leave Bob out too).
    alice.laptop.inner.judge_grants().await;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        marks[0].record, low,
        "the mark names {} and not the lowest signer's record {low}",
        marks[0].record
    );
}

/// Spec §19.8 (which record, by a cut): when no record of the revision leaves
/// the person out by its own lists — one removed the writer and another the
/// reader, and only the merge leaves them out — the mark names the record with
/// a cut of their prefix.
#[tokio::test]
async fn the_mark_names_the_record_with_the_cut_when_only_the_merge_leaves_the_person_out() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let out = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    // The phone cuts the writer but keeps the reader; the other device drops the
    // reader but keeps the writer and cuts nothing.
    let m = alice.laptop.inner.st.lock().folders[&folder]
        .members
        .clone()
        .unwrap();
    let mut cut_only = out.clone();
    cut_only.readers = m.readers.clone();
    let mut reader_only = out;
    reader_only.writers = m.writers.clone();
    reader_only.cuts = Vec::new();
    let with_cut = from_device(&alice.laptop, "/alice/phone", cut_only);
    from_device(&alice.laptop, "/alice/aaa", reader_only);
    alice.laptop.inner.judge_grants().await;
    assert_eq!(
        alice.laptop.grants(),
        Vec::new(),
        "the merge of the two records did not leave Bob out: the case does not hold"
    );
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        marks[0].record, with_cut,
        "the mark names {} and not the record with the cut, {with_cut}",
        marks[0].record
    );
}

/// Spec §19.8 (which record, the first of the run): when later records arrive
/// with the one that let the person go — each leaving them out too, and listing
/// a person admitted since — the mark names the first of them: the record that
/// actually left Bob out, not a later one that hands him the later membership.
#[tokio::test]
async fn the_mark_names_the_record_that_first_left_the_person_out_not_a_later_one() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let first = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    let mut later = first.clone();
    later.revision += 1;
    later.writers.push(n("/carol"));
    later.readers.push(Audience::Person(n("/carol")));
    let left = from_device(&alice.laptop, "/alice/phone", first);
    from_device(&alice.laptop, "/alice/zzz", later);
    alice.laptop.inner.judge_grants().await;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        marks[0].record, left,
        "the mark names {} and not the record that first left Bob out, {left}",
        marks[0].record
    );
}

/// Spec §19.8 (which record, the run ends at a readmission): a record that
/// readmits the person ends the run, and is never named; let go again by a later
/// record, the person is let go by that one, not the first removal.
#[tokio::test]
async fn the_mark_never_names_a_record_before_a_readmission() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let admitted = alice.laptop.inner.st.lock().folders[&folder]
        .members
        .clone()
        .unwrap();
    let out = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    let mut again = out.clone();
    again.revision += 1;
    again.writers = admitted.writers.clone();
    again.readers = admitted.readers.clone();
    again.cuts = Vec::new();
    let mut out_again = out.clone();
    out_again.revision += 2;
    from_device(&alice.laptop, "/alice/phone", out);
    from_device(&alice.laptop, "/alice/aaa", again);
    let last = from_device(&alice.laptop, "/alice/bbb", out_again);
    alice.laptop.inner.judge_grants().await;
    let marks = alice.laptop.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        marks[0].record, last,
        "the mark names {} and not the record that let Bob go again, {last}",
        marks[0].record
    );
}

/// Spec §19.8 (notes are MAC'd, the mark with them): a mark added to a note
/// the host ended, cleared from one a record ended, or moved (its date pushed
/// out) fails the note's check; nothing is listed from it.
#[tokio::test]
async fn a_mark_added_cleared_or_moved_in_the_store_is_ignored() {
    for how in ["added", "cleared", "moved"] {
        let alice = Inviter::new(Role::Writer, None, &[]).await;
        let folder = n("/alice/32=data/notebook");
        let bob_phone = phone_of("/bob").await;
        let bob = bob_phone.inner.own_key.unwrap();
        assert!(accepted(&alice.answers(&bob_phone).await));
        if how == "added" {
            assert!(alice.laptop.end_grant(&bob).await.unwrap());
        } else {
            from_the_phone(
                &alice.laptop,
                phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
            );
            alice.laptop.inner.settle().await;
            assert_eq!(
                alice.laptop.departures().len(),
                1,
                "{how}: the control has a mark"
            );
        }
        let until = alice.laptop.departures().first().map(|m| m.until);
        tamper(&*alice.store, |b| match how {
            // The flag, and a date and a name where the mark would be.
            "added" => {
                b[NOTE_FLAGS] |= 4;
                let at = b.len() - 32;
                let mut mark = u64::MAX.to_be_bytes().to_vec();
                let name = n("/alice/phone/32=log/alice/32=data/notebook").encode_to_tlv();
                mark.extend_from_slice(&(name.len() as u16).to_be_bytes());
                mark.extend_from_slice(&name);
                b.splice(at..at, mark);
            }
            "cleared" => b[NOTE_FLAGS] &= !4,
            _ => {
                let old = until.unwrap().0.to_be_bytes();
                let at = b
                    .windows(8)
                    .position(|w| w == old)
                    .expect("the mark's date is in the note");
                b[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            }
        });
        assert_eq!(
            alice.laptop.departures(),
            Vec::new(),
            "{how}: a note whose mark was changed in the store still lists a mark"
        );
        assert_eq!(alice.laptop.grants(), Vec::new(), "{how}");
    }

    // The note unchanged: its mark is listed (the check is not a refusal of all).
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    from_the_phone(
        &alice.laptop,
        phone_leaves_out(&alice.laptop, &folder, &n("/bob")),
    );
    alice.laptop.inner.settle().await;
    assert_eq!(alice.laptop.departures().len(), 1);
}

/// Bob's phone, a member of Alice's notebook by one admission: it holds Alice's
/// namespace and every record of the folder her laptop signed. The inviter, the
/// phone, the folder.
async fn bob_holding_the_folder() -> (Inviter, Device, Name) {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let phone = phone_of("/bob").await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.alice.ctx))
        .unwrap();
    assert!(accepted(&alice.answers(&phone).await));
    relay(&alice.laptop, &phone, &folder);
    (alice, phone, folder)
}

/// Spec §19.8 (`take_departure`, what it refuses): a hint that is no folder, no
/// record of the folder, for a folder this device holds no record of, or signed
/// under a namespace this device holds no context of, is refused with why and
/// what to do; a record already held is Ok at once.
#[tokio::test(start_paused = true)]
async fn take_departure_takes_only_a_members_record_of_a_folder_it_is_a_member_of() {
    let (alice, phone, folder) = bob_holding_the_folder().await;
    let laptop = alice.laptop.name().clone();
    let refused = |e: DataError, says: &str| {
        assert!(
            matches!(&e, DataError::BadRequest { why, .. } if why.contains(says) && why.contains(':')),
            "expected a refusal saying {says:?}, got {e:?}"
        );
    };
    // Not a folder name.
    let e = phone
        .take_departure(
            &laptop,
            &n("/alice/notebook"),
            &log_name(&laptop, Some(&n("/alice/notebook")), 1),
        )
        .await
        .unwrap_err();
    refused(e, "no folder name");
    // A record of another folder, a snapshot, a name that is no entry.
    let other = n("/alice/32=data/diary");
    let e = phone
        .take_departure(&laptop, &folder, &log_name(&laptop, Some(&other), 1))
        .await
        .unwrap_err();
    refused(e, "no log entry of");
    let e = phone
        .take_departure(&laptop, &folder, &log_name(&laptop, None, 1))
        .await
        .unwrap_err();
    refused(e, "no log entry of");
    let e = phone
        .take_departure(&laptop, &folder, &folder.clone().append("x"))
        .await
        .unwrap_err();
    refused(e, "no log entry of");
    // A device that holds no record of the folder is no member of it.
    let carol = phone_of("/carol").await;
    let e = carol
        .take_departure(&laptop, &folder, &log_name(&laptop, Some(&folder), 1))
        .await
        .unwrap_err();
    refused(e, "no members record");
    // Signed under a namespace no context of which is held.
    let e = phone
        .take_departure(
            &laptop,
            &folder,
            &log_name(&n("/mallory/phone"), Some(&folder), 1),
        )
        .await
        .unwrap_err();
    refused(e, "no namespace this device holds");
    // A record already held: nothing to do.
    let held: Vec<(u64, Name)> = {
        let st = phone.inner.st.lock();
        st.folders[&folder]
            .line
            .records
            .values()
            .flat_map(|s| s.iter())
            .map(|(w, h)| (h.seq, device_of(w.key()).unwrap()))
            .collect()
    };
    let (seq, device) = held
        .first()
        .cloned()
        .expect("a record of the folder is held");
    phone
        .take_departure(&laptop, &folder, &log_name(&device, Some(&folder), seq))
        .await
        .expect("a record held is taken");
    // Told by a device outside the folder's namespace: refused before anything
    // is looked at, even for a record held (what the link layer passes is the
    // peer's authenticated device, and only the folder's namespace lets a
    // member go of it).
    let stranger = n("/carol/member/phone");
    let e = phone
        .take_departure(&stranger, &folder, &log_name(&device, Some(&folder), seq))
        .await
        .unwrap_err();
    refused(e, "lies under no namespace of");
}

/// Spec §19.8: once a held record leaves this device out of a folder, a walk of
/// the inviter's summary does not descend into that folder's node (it waits for
/// nothing there, so the namespace's other folders are not held back); a member
/// still listed, and the owner's own devices, are never left out.
#[tokio::test]
async fn a_device_a_held_record_leaves_out_does_not_walk_into_the_folder() {
    let (alice, phone, folder) = bob_holding_the_folder().await;
    let node = |d: &Device| {
        let st = d.inner.st.lock();
        d.inner.left_out(&st, &folder)
    };
    assert!(!node(&phone), "a member is left out of its folder");
    assert!(
        !alice
            .laptop
            .inner
            .left_out(&alice.laptop.inner.st.lock(), &folder),
        "the owner's own device is left out of its folder"
    );
    from_the_phone(&phone, phone_leaves_out(&alice.laptop, &folder, &n("/bob")));
    assert!(
        node(&phone),
        "a held record leaves bob out, and his walk still descends"
    );
    // A collection under the folder, and a folder this device holds no record of.
    {
        let st = phone.inner.st.lock();
        assert!(phone.inner.left_out(&st, &folder.clone().append("page")));
        assert!(!phone.inner.left_out(&st, &n("/alice/32=data/diary")));
    }
}

/// Spec §19.8: a joiner is not "let go". It holds the folder's sealed record from
/// before the offer admitted it — which lists it neither as a writer nor a reader —
/// and the revision that admits it is still to be fetched from the very node a walk
/// would skip, so the walk MUST descend (the join waits for it); it is let go only
/// once a held record of the line has admitted it and a later one leaves it out.
#[tokio::test]
async fn a_joiner_holding_the_pre_admission_record_is_not_left_out_until_let_go() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let phone = phone_of("/bob").await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.alice.ctx))
        .unwrap();
    // Before the admission: Alice's sealed record, which does not list Bob.
    relay(&alice.laptop, &phone, &folder);
    let sealed = phone.inner.st.lock().folders[&folder]
        .members
        .clone()
        .expect("the pre-admission record is held");
    assert!(
        sealed.epoch.is_some(),
        "the case needs a sealed pre-admission record"
    );
    let node = |d: &Device| {
        let st = d.inner.st.lock();
        d.inner.left_out(&st, &folder)
    };
    assert!(
        !node(&phone),
        "a joiner holding the record from before its admission is left out: its walk would never fetch the revision that admits it"
    );
    // Admitted, and the record that admits it held: still a member.
    assert!(accepted(&alice.answers(&phone).await));
    relay(&alice.laptop, &phone, &folder);
    assert!(!node(&phone), "an admitted member is left out");
    // Let go: a held record admitted it, and the one in force no longer does.
    from_the_phone(&phone, phone_leaves_out(&alice.laptop, &folder, &n("/bob")));
    assert!(node(&phone), "a person let go still walks into the folder");
}

/// Spec §19.8 (re-invited): a member let go holds the record that admitted it
/// (r1) and the one that left it out (r2, in force). Invited again, the offer's
/// answer names the revision that admits it (r3) and the join notes it: until a
/// record held admits it the admission is pending, and a walk of the inviter's
/// summary MUST descend into the folder's node — the only place r3 is listed —
/// not skip it as it does for a person let go. Once r3 is held it is a member.
async fn let_go_and_invited_again(role: Role) {
    let alice = Inviter::new(role, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let phone = phone_of("/bob").await;
    phone
        .inner
        .validator
        .adopt_context(Arc::clone(&alice.alice.ctx))
        .unwrap();
    assert!(accepted(&alice.answers(&phone).await));
    relay(&alice.laptop, &phone, &folder);
    let node = |d: &Device| {
        let st = d.inner.st.lock();
        d.inner.left_out(&st, &folder)
    };
    // Let go (r2): Bob's phone and Alice's laptop both hold the record.
    let out = phone_leaves_out(&alice.laptop, &folder, &n("/bob"));
    from_the_phone(&phone, out.clone());
    from_the_phone(&alice.laptop, out);
    assert!(node(&phone), "a person let go still walks into the folder");
    // Invited again (r3): the answer carries the revision above r2.
    let (offer, secret) = alice.another_offer().await;
    let got = answer(
        &alice.laptop,
        ask(&phone, &alice.laptop, &offer, &secret, &[]),
    )
    .await;
    let Some(Outcome::Accepted { revision, .. }) = got else {
        panic!("bob was invited again and answered {got:?}");
    };
    let in_force = phone.inner.st.lock().folders[&folder]
        .members
        .as_ref()
        .unwrap()
        .revision
        .0;
    assert!(
        revision.is_some_and(|r| r > in_force),
        "the new admission {revision:?} is not above the record in force ({in_force})"
    );
    let until = alice.laptop.inner.st.lock().intro.offers[&offer].until;
    assert!(
        phone
            .inner
            .note_joined(&folder, until, revision, role)
            .await
    );
    assert!(
        !node(&phone),
        "a member invited again, whose new admission is not held yet, is left out: its walk \
         would skip the node that lists the record and the join would never complete"
    );
    // r3 held: a member.
    relay(&alice.laptop, &phone, &folder);
    assert!(!node(&phone), "a member admitted again is left out");
}

#[tokio::test]
async fn a_let_go_member_invited_again_is_not_left_out_while_the_new_admission_is_pending() {
    let_go_and_invited_again(Role::Writer).await;
}

/// The same for a reader: the audience, not the writers, is what the records
/// admit and leave out, and the join of a reader is noted too.
#[tokio::test]
async fn a_let_go_reader_invited_again_is_not_left_out_while_the_new_admission_is_pending() {
    let_go_and_invited_again(Role::Reader).await;
}

/// Spec §19.8 (re-invited, the walk): a walk of the inviter's summary that ended
/// while the device was let go skipped the folder's node and recorded its root as
/// taken in full; the same root again would be answered with nothing walked, and
/// the record that admits the device — in that very node — never fetched. A join
/// waiting for its record while the admission is pending makes the walks of the
/// folder's namespace go down again: the root is forgotten, and a walk under way
/// since before records none. Not when no admission is pending (the record that
/// admits the device, or the one that undid it, is held).
#[tokio::test]
async fn a_join_waiting_for_its_record_makes_the_walks_of_its_namespace_descend_again() {
    let (alice, phone, folder) = bob_holding_the_folder().await;
    let key = (alice.laptop.name().clone(), n("/alice"));
    let walked = |d: &Device| {
        let mut st = d.inner.st.lock();
        let peer = st.peers.entry(key.clone()).or_default();
        peer.root = Some([7; 32]);
        peer.resets
    };
    let until = Timestamp((alice.clock)().0 + 3_600_000);
    // The admission named a revision the folder's record in force is below.
    let resets = walked(&phone);
    assert!(
        phone
            .inner
            .note_joined(&folder, until, Some(u64::MAX), Role::Writer)
            .await
    );
    phone.inner.descend_again_toward(&folder);
    {
        let st = phone.inner.st.lock();
        let peer = &st.peers[&key];
        assert_eq!(
            peer.root, None,
            "a root walked while the device was let go is still taken for walked in full"
        );
        assert!(
            peer.resets > resets,
            "a walk under way since before the admission would still record its root"
        );
    }
    // The record in force is at the revision the answer named: nothing is pending.
    let resets = walked(&phone);
    assert!(
        phone
            .inner
            .note_joined(&folder, until, Some(1), Role::Writer)
            .await
    );
    phone.inner.descend_again_toward(&folder);
    let st = phone.inner.st.lock();
    assert_eq!(
        st.peers[&key].root,
        Some([7; 32]),
        "walked again with nothing pending"
    );
    assert_eq!(st.peers[&key].resets, resets);
}

/// Spec §19.8 (`take_departure`, bounds): a record that cannot be fetched is
/// `NotReady`, saying what to do; one take of a folder at a time; a bounded
/// number begin a minute.
#[tokio::test(start_paused = true)]
async fn take_departure_is_one_at_a_time_for_a_folder_and_bounded_a_minute() {
    let (alice, phone, folder) = bob_holding_the_folder().await;
    let laptop = alice.laptop.name().clone();
    let missing = |seq: u64| log_name(&laptop, Some(&folder), 900 + seq);
    let e = phone
        .take_departure(&laptop, &folder, &missing(0))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, DataError::NotReady { why, .. } if why.contains("could not be fetched") && why.contains("ask again")),
        "a record nobody serves was answered {e:?}"
    );

    // Two at once for one folder: the second is told one is under way.
    let (one, two) = (missing(1), missing(2));
    let (first, second) = tokio::join!(
        phone.take_departure(&laptop, &folder, &one),
        phone.take_departure(&laptop, &folder, &two),
    );
    assert!(
        matches!(&first, Err(DataError::NotReady { why, .. }) if why.contains("could not be fetched")),
        "{first:?}"
    );
    assert!(
        matches!(&second, Err(DataError::NotReady { why, .. }) if why.contains("being fetched already")),
        "a second take of one folder was answered {second:?}"
    );

    // Two begun so far; the bound is six a minute, whatever the names.
    for seq in 3..7 {
        let e = phone
            .take_departure(&laptop, &folder, &missing(seq))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, DataError::NotReady { why, .. } if why.contains("could not be fetched")),
            "{e:?}"
        );
    }
    let e = phone
        .take_departure(&laptop, &folder, &missing(8))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, DataError::NotReady { why, .. } if why.contains("departure fetches in the last minute")),
        "past the minute's bound a take was answered {e:?}"
    );
}

/// Spec §19.8 (co-writers): `IntroductionSurface::grant_carries` reads the
/// members record in force on every call: the root of a listed writer's
/// namespace is carried while the record lists them and not at the next call
/// after a record without them; the folder's names and a name of a listed
/// writer outside the folder follow `folder_carries` throughout.
#[tokio::test]
async fn grant_carries_follows_the_writers_the_record_in_force_lists() {
    use crate::wire::{root_name, root_prefix};
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let surface = alice.laptop.introductions();
    let device = n("/alice/laptop");
    let carol_root = root_name(&device, &n("/carol"), 4);
    let carol_prefix = root_prefix(&device, &n("/carol"));
    let carol_sync = n("/carol/32=sync/vector");
    let dave_sync = n("/dave/32=sync/vector");
    let dave_root = root_name(&device, &n("/dave"), 4);
    // A name of Carol's outside the folder: an entry of her other collection.
    let carol_other = log_name(
        &n("/carol/member/laptop"),
        Some(&n("/carol/32=data/diary")),
        3,
    );
    // An entry of the folder by her device, which the collection carries.
    let carol_entry = log_name(
        &n("/carol/member/laptop"),
        Some(&folder.clone().append("page")),
        3,
    );

    assert!(
        !surface.grant_carries(&folder, &carol_root),
        "a stranger's root crossed"
    );
    assert!(surface.grant_carries(&folder, &carol_entry));

    // A record that lists Carol as a writer.
    alice
        .laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice"), n("/bob"), n("/carol")],
                readers: vec![
                    Audience::Person(n("/alice")),
                    Audience::Person(n("/bob")),
                    Audience::Person(n("/carol")),
                ],
            }
            .into(),
        )
        .await
        .unwrap();
    assert!(
        surface.grant_carries(&folder, &carol_root),
        "a listed writer's root was not carried"
    );
    assert!(surface.grant_carries(&folder, &carol_prefix));
    assert!(
        surface.grant_carries(&folder, &carol_sync),
        "a listed writer's sync group was not carried"
    );
    assert_eq!(
        surface.writer_namespaces(&folder),
        vec![n("/bob"), n("/carol")],
        "the writers' namespaces are not the listed writers', less the folder's own"
    );
    assert!(!surface.grant_carries(&folder, &dave_sync));
    assert!(
        !surface.grant_carries(&folder, &dave_root),
        "an unlisted namespace's root crossed"
    );
    assert!(
        !surface.grant_carries(&folder, &carol_other),
        "a writer's name outside the folder crossed"
    );
    assert!(surface.grant_carries(&folder, &carol_entry));

    // A record without Carol: her root is out at the next call, her entry of
    // the folder (a name of the collection) is still carried.
    alice
        .laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice"), n("/bob")],
                readers: vec![Audience::Person(n("/alice")), Audience::Person(n("/bob"))],
            }
            .into(),
        )
        .await
        .unwrap();
    assert!(
        !surface.grant_carries(&folder, &carol_root),
        "a removed writer's root is still carried"
    );
    assert!(!surface.grant_carries(&folder, &carol_prefix));
    assert!(
        !surface.grant_carries(&folder, &carol_sync),
        "a removed writer's sync group is still carried"
    );
    assert_eq!(surface.writer_namespaces(&folder), vec![n("/bob")]);
    assert_eq!(
        surface.writer_namespaces(&n("/alice/32=data/diary")),
        Vec::new()
    );
    assert!(surface.grant_carries(&folder, &carol_entry));

    // A folder this device holds no record of lists no writer.
    assert!(!surface.grant_carries(&n("/alice/32=data/diary"), &carol_root));
}

/// Spec §19.8 (co-writers, which namespace): the namespace a listed writer
/// unlocks is the one `writer_namespaces` derives (the trust context's, or the
/// writer's own prefix when none is held), never any name the writer's name
/// merely starts with: a writer `/home/carol/member/x` does not unlock the
/// summary root or the sync group of the broader `/home`.
#[tokio::test]
async fn a_writer_below_a_namespace_unlocks_only_its_own_namespace_not_the_broader_one() {
    use crate::wire::root_name;
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let folder = n("/alice/32=data/notebook");
    let surface = alice.laptop.introductions();
    let device = n("/alice/laptop");
    let writer = n("/home/carol/member/x");
    alice
        .laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice"), writer.clone()],
                readers: vec![Audience::Person(n("/alice"))],
            }
            .into(),
        )
        .await
        .unwrap();
    let namespaces = surface.writer_namespaces(&folder);
    assert_eq!(
        namespaces,
        vec![writer.clone()],
        "the case needs the writer's own prefix as its namespace"
    );
    for ns in &namespaces {
        assert!(
            surface.grant_carries(&folder, &root_name(&device, ns, 4)),
            "the root of {ns}, a namespace of a listed writer, was not carried"
        );
        assert!(
            surface.grant_carries(&folder, &n(&format!("{ns}/32=sync/vector"))),
            "the sync group of {ns}, a namespace of a listed writer, was not carried"
        );
    }
    for above in [n("/home"), n("/home/carol"), n("/home/carol/member")] {
        assert!(
            !surface.grant_carries(&folder, &root_name(&device, &above, 4)),
            "the root of {above}, above the writer's namespace, crossed"
        );
        assert!(
            !surface.grant_carries(&folder, &n(&format!("{above}/32=sync/vector"))),
            "the sync group of {above}, above the writer's namespace, crossed"
        );
    }
}

// ---- round 9: the mirror grant, the joiner's end of a grant (spec §19.8) -----------------------

mod mirror_tests;

// ---- round 10: the short code and its hint record (SHAPES-R10) ----------------------------------

mod hint_tests;
