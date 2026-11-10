//! Introductions (spec §19), the offering device's side judged in process:
//! devices of strangers' namespaces on a forwarder that delivers nothing, an
//! ask built as [`Device::join`] builds it and handed to the offering
//! device's [`Inner::answer_intro`]. What the network cases (conformance
//! `i1`…) cannot see: what goes into the validator's cache, a joiner whose
//! key is its own anchor, a host that does not adopt, and a crowd of asks.

use super::*;
use crate::intro::{
    AnswerBody, AskBody, IntroAsk, IntroRefusal, Introducer, Offer, Outcome, Role, ask_proof,
    intro_name, intro_prefix, proof_key,
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
        let signer = mgr.get_signer_sync(root).unwrap();
        let anchor = mgr
            .issue_self_signed(root, signer.public_key().unwrap(), VALIDITY_MS)
            .unwrap();
        let ctx = SignedTrustContext::hierarchical(n(ns)).with_version(1);
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
    dial_succeeds: std::sync::atomic::AtomicBool,
}

impl Calls {
    fn dialled(&self) -> Vec<Name> {
        self.dialled.lock().unwrap().clone()
    }

    fn undialled(&self) -> Vec<Name> {
        self.undialled.lock().unwrap().clone()
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
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err("this test host links nothing".to_string())
            }
        })
    }

    fn undial(&self, _hint: &crate::intro::LinkHint, inviter: &Name) {
        self.calls.undialled.lock().unwrap().push(inviter.clone());
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
                return Ok(());
            }
            self.validator
                .adopt_context(Arc::new(ctx))
                .map_err(|refused| refused.to_string())
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
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator.adopt_context(Arc::clone(&person.ctx)).unwrap();
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
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        Arc::new(MemoryStore::new()),
        Config {
            first_look: Duration::from_millis(50),
            introducer: Some(Arc::new(host)),
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
    assert!(phone.inner.note_joined(&folder, until, Some(2)).await);

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
    assert!(phone.inner.note_joined(&folder, until, revision).await);
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
    assert!(phone.inner.note_joined(&folder, until, revision).await);
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
