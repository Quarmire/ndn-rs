//! The kit the introductions' tests run on (`cfg(test)`): persons with trust contexts,
//! a host that records what it is asked, devices (an `ndn_heap::Node` with its
//! [`Invites`]) either alone on a forwarder that delivers nothing or on one
//! `ndn_engine` forwarder where they reach each other, and the ask a joiner would send,
//! built by hand so that the offering side is judged in process.
//!
//! Owner: InviteOffer. Tests of the other areas use it as it is and add what only they
//! need in their own test files.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt};
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_foundation_types::Name;
use ndn_heap::{Clock, Config, Heap, Node, Readers, Share, Timestamp, Transport};
use ndn_packet::Data;
use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::{
    Certificate, SecurityManager, SignedTrustContext, Signer, TrustSchema, Validator,
    encode_cert_data,
};
use ndn_sync::{DataStore, MemoryStore};
use ndn_trust_envelope::TrustEnvelope;
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::credentials;
use crate::host::{
    Adopting, Code, Departure, Dialing, FirstDialing, Grant, Host, LinkHint, Offer, Role,
};
use crate::invites::{InviteConfig, Invites};
use crate::policy::IntroPolicy;
use crate::proofs::{SECRET_LEN, ask_proof, proof_key};
use crate::sealed::AskKey;
use crate::wire::{
    AnswerBody, AskBody, IntroAsk, Outcome, intro_name, intro_prefix, parse_offer_name,
};

/// A validity that outlasts any test.
const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

/// A name from its URI. Panics on a malformed one: a test's typo.
pub(crate) fn n(s: &str) -> Name {
    s.parse().expect("a valid name")
}

/// `<device>/KEY/1`: the key a test device signs with.
pub(crate) fn key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

fn now_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// A face that never delivers anything.
pub(crate) struct Unconnected;

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

/// A memory store that models a disk with a write cache: reads and writes go to the live
/// state, and what a power cut leaves is [`DiskStore::crash`], the image at the last
/// `sync` that returned. A note is durable exactly when a `sync` began after it.
#[derive(Default)]
pub(crate) struct DiskStore {
    live: MemoryStore,
    image: std::sync::Mutex<Vec<(Name, Bytes)>>,
}

impl DiskStore {
    /// An empty store.
    pub(crate) fn new() -> Arc<DiskStore> {
        Arc::new(DiskStore::default())
    }

    /// The store a restart finds after a power cut that kept what the last returned
    /// `sync` covered and nothing after it.
    pub(crate) fn crash(&self) -> Arc<dyn DataStore> {
        let after = MemoryStore::new();
        for (name, wire) in self.image.lock().unwrap().iter() {
            after.insert(name.clone(), wire.clone());
        }
        Arc::new(after)
    }
}

impl DataStore for DiskStore {
    fn insert(&self, name: Name, wire: Bytes) {
        self.live.insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.live.get(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.live.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.live.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        self.live.remove(name);
    }

    fn apply(&self, ops: Vec<ndn_sync::StoreOp>) {
        self.live.apply(ops);
    }

    fn sync(&self) -> std::io::Result<()> {
        *self.image.lock().unwrap() = self.live.scan_under(&Name::root(), 0);
        Ok(())
    }
}

/// A person: a namespace whose root key signs its trust context (version 1,
/// hierarchical) and certifies its devices.
pub(crate) struct Person {
    pub(crate) root: Arc<dyn Signer>,
    pub(crate) ctx: Arc<SignedTrustContext>,
    pub(crate) signed: Bytes,
}

impl Person {
    /// `ns` rooted in a key of its own, `<ns>/KEY/ns`.
    pub(crate) fn new(ns: &str) -> Person {
        let mgr = SecurityManager::new();
        let root = mgr
            .generate_ed25519(n(ns).append("KEY").append("ns"))
            .unwrap();
        Person::rooted(ns, &mgr, &root)
    }

    /// `ns` rooted in the key `root` held by `mgr`.
    pub(crate) fn rooted(ns: &str, mgr: &SecurityManager, root: &Name) -> Person {
        Person::rooted_with(ns, mgr, root, Vec::new())
    }

    /// `ns` rooted in a key of its own, its trust context advertising the relay
    /// device `relay` (an endpoint to dial it at is part of the entry).
    pub(crate) fn relayed(ns: &str, relay: &str) -> Person {
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
    pub(crate) fn rooted_with(
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
    pub(crate) async fn certify(&self, key: &Name, public: &[u8]) -> Certificate {
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

/// What a host was asked to dial and to take down, and whether its dial succeeds.
#[derive(Default)]
pub(crate) struct Calls {
    dialled: std::sync::Mutex<Vec<Name>>,
    undialled: std::sync::Mutex<Vec<Name>>,
    /// The key of every link hint `undial` was given.
    undialled_keys: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Whether `dial` succeeds.
    pub(crate) dial_succeeds: AtomicBool,
    /// Every `dial_first`: the inviter and the address.
    first_dialled: std::sync::Mutex<Vec<(Name, SocketAddr)>>,
    /// What `dial_first` answers: the key the link proved, or why not; `None`: a host
    /// with no link layer.
    pub(crate) first_dial: std::sync::Mutex<Option<Result<[u8; 32], String>>>,
    /// What `link_hint` gives: this host's key and its addresses.
    pub(crate) hint: std::sync::Mutex<Option<LinkHint>>,
    /// Whether a dial of this host's succeeded and was not taken down since: a link a
    /// test's network carries introduction names over.
    linked: AtomicBool,
    /// Whether this host adopted a namespace.
    adopted: AtomicBool,
    granted: std::sync::Mutex<Vec<Grant>>,
    revoked: std::sync::Mutex<Vec<([u8; 32], Name)>>,
    departed: std::sync::Mutex<Vec<Departure>>,
    /// Every `departure` and `revoke_grant` call, in the order made.
    order: std::sync::Mutex<Vec<&'static str>>,
}

impl Calls {
    pub(crate) fn dialled(&self) -> Vec<Name> {
        self.dialled.lock().unwrap().clone()
    }

    pub(crate) fn undialled(&self) -> Vec<Name> {
        self.undialled.lock().unwrap().clone()
    }

    pub(crate) fn undialled_keys(&self) -> Vec<[u8; 32]> {
        self.undialled_keys.lock().unwrap().clone()
    }

    pub(crate) fn first_dialled(&self) -> Vec<(Name, SocketAddr)> {
        self.first_dialled.lock().unwrap().clone()
    }

    pub(crate) fn linked(&self) -> bool {
        self.linked.load(Ordering::SeqCst)
    }

    pub(crate) fn adopted(&self) -> bool {
        self.adopted.load(Ordering::SeqCst)
    }

    pub(crate) fn granted(&self) -> Vec<Grant> {
        self.granted.lock().unwrap().clone()
    }

    pub(crate) fn revoked(&self) -> Vec<[u8; 32]> {
        self.revoked.lock().unwrap().iter().map(|r| r.0).collect()
    }

    /// What `revoke_grant` was told: the key and the space, in order.
    pub(crate) fn revoked_in(&self) -> Vec<([u8; 32], Name)> {
        self.revoked.lock().unwrap().clone()
    }

    pub(crate) fn departed(&self) -> Vec<Departure> {
        self.departed.lock().unwrap().clone()
    }

    pub(crate) fn order(&self) -> Vec<&'static str> {
        self.order.lock().unwrap().clone()
    }
}

/// A host: gives its person's signed context; adopts a link into its validator — unless
/// it refuses the namespace, or holds every adoption until let go; records what it is
/// asked to dial.
pub(crate) struct TestHost {
    anchor: Bytes,
    validator: Arc<Validator>,
    /// Namespaces it does not adopt.
    refuses: Vec<Name>,
    /// Hold adoptions: told as one starts, let go one per permit.
    hold: Option<(Arc<Notify>, Arc<Semaphore>)>,
    calls: Arc<Calls>,
}

impl Host for TestHost {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    fn grant(&self, grant: &Grant) {
        self.calls.granted.lock().unwrap().push(grant.clone());
    }

    fn revoke_grant(&self, key: &[u8; 32], space: &Name) {
        self.calls.order.lock().unwrap().push("revoke_grant");
        self.calls
            .revoked
            .lock()
            .unwrap()
            .push((*key, space.clone()));
    }

    fn departure(&self, departure: &Departure) {
        self.calls.order.lock().unwrap().push("departure");
        self.calls.departed.lock().unwrap().push(departure.clone());
    }

    fn link_hint(&self) -> Option<LinkHint> {
        self.calls.hint.lock().unwrap().clone()
    }

    fn dial<'a>(
        &'a self,
        _hint: &'a LinkHint,
        inviter: &'a Name,
        _within: Duration,
    ) -> Dialing<'a> {
        self.calls.dialled.lock().unwrap().push(inviter.clone());
        let ok = self.calls.dial_succeeds.load(Ordering::SeqCst);
        if ok {
            self.calls.linked.store(true, Ordering::SeqCst);
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
        addr: SocketAddr,
        _within: Duration,
    ) -> FirstDialing<'a> {
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
            self.calls.linked.store(true, Ordering::SeqCst);
        }
        Box::pin(async move { got })
    }

    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        self.calls.undialled.lock().unwrap().push(inviter.clone());
        self.calls.undialled_keys.lock().unwrap().push(hint.key);
        self.calls.linked.store(false, Ordering::SeqCst);
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
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
            // Held at this version or a newer one, rooted in the link's anchor: nothing
            // to adopt (as the daemon's host answers).
            let held = self.validator.keyring().held(&ns).is_some_and(|held| {
                held.version() >= ctx.version()
                    && held
                        .anchors()
                        .iter()
                        .any(|a| Some(ndn_security::anchor_fingerprint(a.value())) == *fingerprint)
            });
            if !held {
                self.validator
                    .adopt_context(Arc::new(ctx))
                    .map_err(|refused| refused.to_string())?;
            }
            self.calls.adopted.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}

/// The forwarder the devices of one case share, when they must reach each other: every
/// namespace's sync group is carried on it.
pub(crate) struct Net {
    pub(crate) engine: ForwarderEngine,
}

impl Net {
    /// A forwarder that runs as long as the case's runtime does.
    pub(crate) async fn new() -> Net {
        let (engine, shutdown) = EngineBuilder::new(Default::default())
            .build()
            .await
            .expect("an engine");
        shutdown.detach();
        Net { engine }
    }
}

/// What replaces a node's face by a face over it.
type Wrap = Box<dyn FnOnce(Arc<dyn Connection>) -> Arc<dyn Connection>>;

/// How a device is started: everything a case varies, with the defaults of a lone device
/// of a person on a forwarder that delivers nothing.
pub(crate) struct Setup<'a> {
    person: &'a Person,
    device: Name,
    keys: Option<Arc<SecurityManager>>,
    refuses: Vec<Name>,
    hold: Option<(Arc<Notify>, Arc<Semaphore>)>,
    clock: Option<Clock>,
    calls: Arc<Calls>,
    policy: IntroPolicy,
    store: Arc<dyn DataStore>,
    transport: Option<(ndn_app::Node, Arc<dyn Connection>)>,
    config: Option<Config>,
    invite: InviteConfig,
    wrap: Option<Wrap>,
}

impl<'a> Setup<'a> {
    /// `device` (e.g. `/alice/laptop`) of `person`.
    pub(crate) fn new(person: &'a Person, device: &str) -> Self {
        Setup {
            person,
            device: n(device),
            keys: None,
            refuses: Vec::new(),
            hold: None,
            clock: None,
            calls: Arc::new(Calls::default()),
            policy: IntroPolicy::new(),
            store: Arc::new(MemoryStore::new()),
            transport: None,
            config: None,
            invite: InviteConfig::new(),
            wrap: None,
        }
    }

    /// The key store that already holds the device's key (a restart, or a key that is
    /// its namespace's anchor).
    pub(crate) fn keys(mut self, keys: Arc<SecurityManager>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Namespaces the host does not adopt.
    pub(crate) fn refusing(mut self, namespaces: &[&str]) -> Self {
        self.refuses = namespaces.iter().map(|s| n(s)).collect();
        self
    }

    /// Hold the host's adoptions: told through `started` as one begins, let go one per
    /// permit of `gate`.
    pub(crate) fn holding(mut self, started: Arc<Notify>, gate: Arc<Semaphore>) -> Self {
        self.hold = Some((started, gate));
        self
    }

    /// The device's clock.
    pub(crate) fn clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// The `calls` the host records into.
    pub(crate) fn calls(mut self, calls: Arc<Calls>) -> Self {
        self.calls = calls;
        self
    }

    /// The device's introduction policy.
    pub(crate) fn policy(mut self, policy: IntroPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The durable store: a device started again over the same store and keys is a
    /// restart.
    pub(crate) fn store(mut self, store: Arc<dyn DataStore>) -> Self {
        self.store = store;
        self
    }

    /// Faces on `net`'s forwarder, ended by `cancel`: the device reaches the other
    /// devices of the net, and they reach it.
    pub(crate) fn on(mut self, net: &Net, cancel: &CancellationToken) -> Self {
        ndn_namespace::sync_group::carry(&net.engine, &self.namespace());
        self.transport = Some((
            net.engine.app_node(cancel.child_token()),
            net.engine.app_face(cancel.child_token()),
        ));
        self
    }

    /// The heap layer's tuning (default: [`Config::new`] with a 50 ms first look and
    /// settle); its clock, when [`clock`](Self::clock) is given, replaces `config`'s.
    pub(crate) fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Replace the node's face by `wrap` of it, after `on` chose it: a case wraps
    /// it to record, filter or tamper with what crosses (the sync face is untouched).
    pub(crate) fn wrapping(
        mut self,
        wrap: impl FnOnce(Arc<dyn Connection>) -> Arc<dyn Connection> + 'static,
    ) -> Self {
        self.wrap = Some(Box::new(wrap));
        self
    }

    fn namespace(&self) -> Name {
        self.person.ctx.namespace().clone()
    }

    /// Start the device.
    pub(crate) async fn start(self) -> Device {
        let person = self.person;
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
        let keys = match self.keys {
            Some(k) => k,
            None => {
                let keys = Arc::new(SecurityManager::new());
                let k = keys.generate_ed25519(key(&self.device)).unwrap();
                let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
                let cert = person.certify(&k, &public).await;
                keys.cert_cache().insert(cert.clone());
                validator.cert_cache().insert(cert);
                keys
            }
        };
        let host = Arc::new(TestHost {
            anchor: person.signed.clone(),
            validator: Arc::clone(&validator),
            refuses: self.refuses,
            hold: self.hold,
            calls: Arc::clone(&self.calls),
        });
        let mut config = self.config.unwrap_or_else(|| {
            let mut c = Config::new();
            c.first_look = Duration::from_millis(50);
            c.settle = Duration::from_millis(50);
            c
        });
        if let Some(clock) = self.clock {
            config.clock = clock;
        }
        let (node_face, sync_face) = self.transport.unwrap_or_else(|| {
            (
                ndn_app::Node::from_connection(Arc::new(Unconnected)),
                Arc::new(Unconnected) as Arc<dyn Connection>,
            )
        });
        let node_face = match self.wrap {
            Some(wrap) => ndn_app::Node::from_connection(wrap(node_face.connection())),
            None => node_face,
        };
        let node = Node::start(
            Transport {
                node: node_face,
                sync: sync_face,
            },
            self.device.clone(),
            Arc::clone(&keys),
            Arc::clone(&validator),
            Arc::clone(&self.store),
            config,
        )
        .await
        .expect("the node starts");
        let invites = Invites::start(&node, host, self.policy.clone(), self.invite)
            .expect("the introductions start");
        Arc::new(Rig {
            name: self.device,
            node,
            invites,
            keys,
            store: self.store,
            validator,
        })
    }
}

/// A device: its node and its introductions, and what a case needs to look into them.
pub(crate) struct Rig {
    pub(crate) name: Name,
    pub(crate) node: Node,
    pub(crate) invites: Invites,
    pub(crate) keys: Arc<SecurityManager>,
    pub(crate) store: Arc<dyn DataStore>,
    pub(crate) validator: Arc<Validator>,
}

/// A device shared between tasks.
pub(crate) type Device = Arc<Rig>;

/// `device` of `person`, alone, with the defaults.
pub(crate) async fn start(person: &Person, device: &str) -> Device {
    Setup::new(person, device).start().await
}

/// A device clock a case can move forward: the system's, plus a skew in milliseconds.
pub(crate) fn skewed() -> (Clock, Arc<AtomicU64>) {
    let skew = Arc::new(AtomicU64::new(0));
    let by = Arc::clone(&skew);
    let clock: Clock = Arc::new(move || {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Timestamp(now + by.load(Ordering::SeqCst))
    });
    (clock, skew)
}

/// The space Alice offers.
pub(crate) fn notebook() -> Name {
    n("/alice/32=data/notebook")
}

/// What an offer of Alice's notebook is made of: her device, her, the code and its secret.
pub(crate) struct Offered {
    pub(crate) laptop: Device,
    pub(crate) alice: Person,
    pub(crate) code: Code,
    pub(crate) secret: [u8; SECRET_LEN],
}

impl Offered {
    /// The offer's name.
    pub(crate) fn offer(&self) -> Name {
        self.code.offer.clone()
    }
}

/// Alice's laptop's notebook, shared with herself alone, and an offer of it as `role` that
/// expires in an hour of the laptop's clock, with 3 tries.
pub(crate) async fn alice_offers(laptop: Device, alice: Person, role: Role) -> Offered {
    let space = notebook();
    laptop
        .node
        .create(
            &space,
            Share {
                readers: Readers::Persons(vec![n("/alice")]),
                writers: vec![n("/alice")],
            },
        )
        .await
        .unwrap();
    let code = laptop
        .invites
        .offer(
            &space,
            Offer {
                role,
                until: Timestamp(laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    let secret = intro.secret;
    Offered {
        laptop,
        alice,
        code,
        secret,
    }
}

/// Alice's laptop and an offer of her notebook as a writer.
pub(crate) async fn alice() -> Offered {
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop").await;
    alice_offers(laptop, alice, Role::Writer).await
}

/// The heap of `space` on `device`, which has it open.
pub(crate) fn heap(device: &Rig, space: &Name) -> Heap {
    device.node.space(space).expect("the space is open")
}

/// The ask `joiner` sends `inviter` for `offer`, as `join` builds it, its credentials
/// followed by `extra` certificates: its name and its parameters.
pub(crate) fn ask(
    joiner: &Rig,
    inviter: &Rig,
    offer: &Name,
    secret: &[u8; SECRET_LEN],
    extra: &[Certificate],
) -> (Name, Bytes) {
    let j = joiner.invites.inner();
    let me = joiner.node.writer().clone();
    let digest = j.own_key_digest();
    let pk = proof_key(secret, offer);
    let nonce = j.nonce();
    let mut cred = credentials::credentials(&j.node, &*j.host).unwrap();
    cred.extend(extra.iter().map(|c| c.data_wire().unwrap()));
    let mut body = AskBody {
        offer: offer.clone(),
        nonce,
        proof: ask_proof(&pk, offer, &me, &digest, &nonce),
        credentials: cred,
        asker: Bytes::new(),
    };
    body.asker = j.ask_proof(&body.binding(&inviter.name)).unwrap();
    let (_, id) = parse_offer_name(offer).expect("an offer's name");
    let seal_key = inviter.invites.inner().state.lock().offers[&id]
        .body
        .seal_key;
    let aad = intro_prefix(&inviter.name).encode_to_tlv();
    let sealed = AskKey::to(&seal_key, &aad)
        .unwrap()
        .seal(&body.encode(), &aad);
    let params = IntroAsk {
        ephemeral: sealed.ephemeral,
        key: sealed.key,
        sealed: sealed.sealed,
    }
    .encode();
    (intro_name(&inviter.name, &params), params)
}

/// What `inviter` answers the ask: `None` for no answer.
pub(crate) async fn answer(inviter: &Rig, (name, params): (Name, Bytes)) -> Option<Outcome> {
    let reply = inviter
        .invites
        .inner()
        .answer_intro(&name, Some(params))
        .await?;
    let data = Data::decode(reply).unwrap();
    Some(
        AnswerBody::decode(data.content().unwrap().clone())
            .unwrap()
            .outcome,
    )
}

/// Whether the outcome is an acceptance.
pub(crate) fn accepted(o: &Option<Outcome>) -> bool {
    matches!(o, Some(Outcome::Accepted { .. }))
}
