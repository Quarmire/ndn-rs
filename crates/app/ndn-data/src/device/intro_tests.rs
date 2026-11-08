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

/// A host's introducer: gives its person's signed context; adopts a link
/// into its validator — unless it refuses the namespace, or holds every
/// adoption until let go.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    /// Namespaces it does not adopt.
    refuses: Vec<Name>,
    /// Hold adoptions: told as one starts, let go one per permit.
    hold: Option<(Arc<Notify>, Arc<tokio::sync::Semaphore>)>,
}

impl Introducer for Host {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
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
            ..Config::new()
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
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop", None, refuses, hold).await;
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
    (laptop, code.offer, intro.secret)
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

#[tokio::test]
async fn a_closed_offer_refuses_every_ask_its_users_too() {
    let (laptop, offer, secret) = alice(&[], None).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone", None, &[], None).await;
    let got = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(accepted(&got), "bob was answered {got:?}");
    laptop.close_offer(&offer).await.unwrap();
    let got = answer(&laptop, ask(&bob_phone, &laptop, &offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "the user of a closed offer asking again was answered {got:?}"
    );
    // Only the device that made an offer closes it.
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
