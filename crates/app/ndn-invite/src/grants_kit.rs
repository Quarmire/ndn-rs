//! What the grants' tests add to the kit (`test_kit.rs`): an inviter whose laptop
//! restarts over its store and keys, a joiner on a forwarder with it, a store whose flush
//! can be frozen, notes changed in the store, and the wait a case makes for what a
//! change of the members brings about (the grants follow `Change::Members`, never a
//! poll: nothing here advances a clock).
//!
//! Owner: InviteGrants.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::{Clock, Config, MembersChange, Share, Timestamp};
use ndn_sync::{DataStore, MemoryStore};
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

use crate::host::{Offer, Role};
use crate::policy::IntroPolicy;
use crate::proofs::SECRET_LEN;
use crate::store;
use crate::test_kit::{
    Calls, Device, Net, Person, Setup, accepted, answer, ask, heap, key, n, notebook, skewed, start,
};
use crate::wire::{Outcome, parse_offer_name};

/// The heap layer's tuning of these cases: a short first look and settle, and Interest
/// lifetimes a missing entry is waited out in half a second.
pub(crate) fn config() -> Config {
    let mut c = Config::new();
    c.first_look = Duration::from_millis(50);
    c.settle = Duration::from_millis(50);
    c.lifetime = Duration::from_millis(500);
    c
}

/// Wait until `what` holds, for at most twenty seconds: a change of the members is
/// carried to the devices that judge it by the network and the watchers of the data
/// layer, and the case waits for the effect, never for a time.
pub(crate) async fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    for _ in 0..2000 {
        if holds() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}: it did not come about in twenty seconds");
}

/// Wait a moment for what must **not** happen, then say it did not: judged again by hand
/// first, so that a judgement that would have told the host has been made.
pub(crate) async fn settle(device: &Device) {
    device.invites.inner().grants.judge().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    device.invites.inner().grants.judge().await;
}

/// The secret of a code.
pub(crate) fn secret_of(code: &crate::host::Code) -> [u8; SECRET_LEN] {
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    intro.secret
}

/// The key digest a device's introductions know it by.
pub(crate) fn key_of(device: &Device) -> [u8; 32] {
    device.invites.inner().own_key_digest()
}

/// A space `device` owns, shared with its person alone, unless it holds it already.
pub(crate) async fn ensure_space(device: &Device, person: &str, space: &Name) {
    if device.node.space(space).is_none() {
        device
            .node
            .create(
                space,
                Share {
                    readers: ndn_heap::Readers::Persons(vec![n(person)]),
                    writers: vec![n(person)],
                },
            )
            .await
            .unwrap();
    }
}

/// A change of the members of `space` on `device`: persons to admit as writers, as
/// readers, and to remove.
pub(crate) async fn change(
    device: &Device,
    space: &Name,
    writers: &[&str],
    readers: &[&str],
    remove: &[&str],
) -> ndn_heap::EntryId {
    heap(device, space)
        .change(MembersChange {
            add_writers: writers.iter().map(|w| n(w)).collect(),
            add_readers: readers.iter().map(|r| n(r)).collect(),
            remove: remove.iter().map(|r| n(r)).collect(),
        })
        .await
        .expect("the members change")
}

/// The log name of the entry `id`.
pub(crate) fn entry_name(id: &ndn_heap::EntryId, space: &Name) -> Name {
    ndn_heap::wire::log_name(&id.device, space, id.seq)
}

/// The log name of the Members entry the space's members on `device` say removed
/// `person` (`Heap::removed_by`).
pub(crate) fn removal_of(device: &Device, space: &Name, person: &str) -> Name {
    let id = heap(device, space)
        .removed_by(&n(person))
        .expect("an entry removed the person");
    entry_name(&id, space)
}

/// A person's phone, alone, its host recording what it is told.
pub(crate) async fn phone_of(ns: &str) -> Device {
    let person = Person::new(ns);
    start(&person, &format!("{ns}/phone")).await
}

/// Alice's laptop on a store and keys that outlive it, its host recording in `calls`,
/// and her notebook offered as `role`. Alone on a forwarder that delivers nothing, or
/// (`on_a_net`) on one where her other devices reach it.
pub(crate) struct Inviter {
    /// `None` only while the laptop restarts.
    rig: Option<Device>,
    pub(crate) alice: Person,
    pub(crate) store: Arc<dyn DataStore>,
    pub(crate) calls: Arc<Calls>,
    pub(crate) clock: Clock,
    pub(crate) skew: Arc<AtomicU64>,
    policy: IntroPolicy,
    /// The forwarder the laptop and its peers share, and what ends their faces.
    pub(crate) net: Option<(Net, CancellationToken)>,
    /// Whether the data layer's sync interval is an hour: nothing a poll does can be
    /// mistaken for what a change of the members does.
    slow: bool,
    pub(crate) offer: Name,
    pub(crate) secret: [u8; SECRET_LEN],
}

impl Inviter {
    /// A laptop whose grants are bounded by `grant_for`.
    pub(crate) async fn new(role: Role, grant_for: Option<Duration>) -> Inviter {
        let policy = IntroPolicy {
            grant_for,
            ..IntroPolicy::new()
        };
        Self::over(role, policy, Arc::new(MemoryStore::new()), &[]).await
    }

    /// A laptop of policy `policy` over `store`, its host refusing `refuses`.
    pub(crate) async fn over(
        role: Role,
        policy: IntroPolicy,
        store: Arc<dyn DataStore>,
        refuses: &[&str],
    ) -> Inviter {
        Self::build(role, policy, store, refuses, false, false).await
    }

    /// A laptop on a forwarder where Alice's other devices reach it.
    pub(crate) async fn on_a_net(role: Role) -> Inviter {
        Self::build(
            role,
            IntroPolicy::new(),
            Arc::new(MemoryStore::new()),
            &[],
            true,
            false,
        )
        .await
    }

    /// A laptop whose data layer syncs once an hour: the grants can only follow the
    /// members by what the watch delivers.
    pub(crate) async fn slow(role: Role) -> Inviter {
        Self::build(
            role,
            IntroPolicy::new(),
            Arc::new(MemoryStore::new()),
            &[],
            false,
            true,
        )
        .await
    }

    async fn build(
        role: Role,
        policy: IntroPolicy,
        store: Arc<dyn DataStore>,
        refuses: &[&str],
        on_a_net: bool,
        slow: bool,
    ) -> Inviter {
        let (clock, skew) = skewed();
        let alice = Person::new("/alice");
        let calls = Arc::new(Calls::default());
        let net = if on_a_net {
            Some((Net::new().await, CancellationToken::new()))
        } else {
            None
        };
        let mut setup = Setup::new(&alice, "/alice/laptop")
            .config(Self::config_of(slow))
            .clock(Arc::clone(&clock))
            .policy(policy.clone())
            .store(Arc::clone(&store))
            .calls(Arc::clone(&calls))
            .refusing(refuses);
        if let Some((net, cancel)) = &net {
            setup = setup.on(net, cancel);
        }
        let laptop = setup.start().await;
        ensure_space(&laptop, "/alice", &notebook()).await;
        let (offer, secret) = offer_of(&laptop, &notebook(), role, &clock).await;
        Inviter {
            rig: Some(laptop),
            alice,
            store,
            calls,
            clock,
            skew,
            policy,
            net,
            slow,
            offer,
            secret,
        }
    }

    fn config_of(slow: bool) -> Config {
        let mut c = config();
        if slow {
            c.svs.sync_interval = Duration::from_secs(3600);
        }
        c
    }

    /// The laptop.
    pub(crate) fn laptop(&self) -> &Device {
        self.rig.as_ref().expect("the laptop runs")
    }

    /// Alice's phone, another owner device, on the laptop's forwarder: it holds the
    /// notebook once its members are heard.
    pub(crate) async fn phone(&self) -> Device {
        let (net, cancel) = self.net.as_ref().expect("the laptop is on a net");
        let phone = Setup::new(&self.alice, "/alice/phone")
            .config(config())
            .on(net, cancel)
            .start()
            .await;
        // Her devices each hold the other's certificate, as devices of one person that
        // have met do: the entries of the one verify at the other.
        for (from, to) in [(self.laptop(), &phone), (&phone, self.laptop())] {
            let k = key(&from.name);
            let public = from.keys.get_signer_sync(&k).unwrap().public_key().unwrap();
            to.validator
                .cert_cache()
                .insert(self.alice.certify(&k, &public).await);
        }
        phone
            .node
            .open(&notebook())
            .await
            .expect("Alice's phone opens her notebook");
        phone
    }

    /// Alice's laptop stopped and started again over its store and keys, its host a new
    /// one recording in the calls returned.
    pub(crate) async fn restart(&mut self) -> Arc<Calls> {
        let old = self.rig.take().expect("the laptop runs");
        let keys = Arc::clone(&old.keys);
        drop(old);
        let calls = Arc::new(Calls::default());
        let mut setup = Setup::new(&self.alice, "/alice/laptop")
            .config(Self::config_of(self.slow))
            .keys(keys)
            .clock(Arc::clone(&self.clock))
            .policy(self.policy.clone())
            .store(Arc::clone(&self.store))
            .calls(Arc::clone(&calls));
        if let Some((net, cancel)) = &self.net {
            setup = setup.on(net, cancel);
        }
        self.rig = Some(setup.start().await);
        calls
    }

    /// What the laptop answers `joiner`'s ask for the first offer.
    pub(crate) async fn answers(&self, joiner: &Device) -> Option<Outcome> {
        answer(
            self.laptop(),
            ask(joiner, self.laptop(), &self.offer, &self.secret, &[]),
        )
        .await
    }

    /// Another offer of `space` as a writer: its name and secret.
    pub(crate) async fn another_offer(&self, space: &Name) -> (Name, [u8; SECRET_LEN]) {
        offer_of(self.laptop(), space, Role::Writer, &self.clock).await
    }

    /// `who` admitted to `space` (shared with Alice alone when it is new) as `role`.
    pub(crate) async fn invites(&self, space: &Name, role: Role, who: &Device) -> Name {
        ensure_space(self.laptop(), "/alice", space).await;
        let (offer, secret) = offer_of(self.laptop(), space, role, &self.clock).await;
        let got = answer(self.laptop(), ask(who, self.laptop(), &offer, &secret, &[])).await;
        assert!(accepted(&got), "{} was answered {got:?}", who.name);
        offer
    }

    /// The change of the notebook's members on the laptop.
    pub(crate) async fn changes(
        &self,
        space: &Name,
        writers: &[&str],
        readers: &[&str],
        remove: &[&str],
    ) -> ndn_heap::EntryId {
        change(self.laptop(), space, writers, readers, remove).await
    }
}

/// An offer of `space` as `role`, expiring in an hour of `clock`, with 3 tries: its name
/// and secret.
async fn offer_of(
    laptop: &Device,
    space: &Name,
    role: Role,
    clock: &Clock,
) -> (Name, [u8; SECRET_LEN]) {
    let code = laptop
        .invites
        .offer(
            space,
            Offer {
                role,
                until: Timestamp(clock().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let secret = secret_of(&code);
    (code.offer, secret)
}

/// Alice's laptop and Bob's phone on one forwarder, Bob joined to her notebook by a real
/// join of an offer as `role`.
pub(crate) struct Joiner {
    pub(crate) net: Net,
    pub(crate) cancel: CancellationToken,
    pub(crate) bob: Person,
    pub(crate) laptop: Device,
    /// `None` only while the phone restarts.
    rig: Option<Device>,
    pub(crate) calls: Arc<Calls>,
    pub(crate) store: Arc<dyn DataStore>,
    pub(crate) space: Name,
    /// The digest of the key that signed Alice's answer: the mirror's key.
    pub(crate) inviter: [u8; 32],
    ns: String,
}

impl Joiner {
    /// Bob (`ns`, e.g. `/bob`) joined to the notebook as `role`.
    pub(crate) async fn joined(ns: &str, role: Role) -> Joiner {
        Self::joined_over(ns, role, Arc::new(MemoryStore::new())).await
    }

    /// [`joined`](Self::joined), Bob's phone over `store`.
    pub(crate) async fn joined_over(ns: &str, role: Role, store: Arc<dyn DataStore>) -> Joiner {
        let j = Self::unjoined_over(ns, store).await;
        j.join(&notebook(), role).await;
        j
    }

    /// Alice's laptop and Bob's phone, Bob not joined to anything yet.
    pub(crate) async fn unjoined(ns: &str) -> Joiner {
        Self::unjoined_over(ns, Arc::new(MemoryStore::new())).await
    }

    /// [`unjoined`](Self::unjoined), Bob's phone over `store`.
    pub(crate) async fn unjoined_over(ns: &str, store: Arc<dyn DataStore>) -> Joiner {
        Self::unjoined_gated(ns, store, None).await
    }

    /// [`unjoined_over`](Self::unjoined_over), Bob's phone's node face behind `gate`.
    pub(crate) async fn unjoined_gated(
        ns: &str,
        store: Arc<dyn DataStore>,
        gate: Option<Arc<crate::join_kit::Gate>>,
    ) -> Joiner {
        let net = Net::new().await;
        let cancel = CancellationToken::new();
        let alice = Person::new("/alice");
        let laptop = Setup::new(&alice, "/alice/laptop")
            .config(config())
            .on(&net, &cancel)
            .start()
            .await;
        ensure_space(&laptop, "/alice", &notebook()).await;
        let bob = Person::new(ns);
        let calls = Arc::new(Calls::default());
        let mut setup = Setup::new(&bob, &format!("{ns}/phone"))
            .config(config())
            .store(Arc::clone(&store))
            .calls(Arc::clone(&calls))
            .on(&net, &cancel);
        if let Some(gate) = gate {
            setup = setup.wrapping(move |face| gate.wrap(face));
        }
        let phone = setup.start().await;
        Joiner {
            net,
            cancel,
            inviter: key_of(&laptop),
            bob,
            laptop,
            rig: Some(phone),
            calls,
            store,
            space: notebook(),
            ns: ns.to_string(),
        }
    }

    /// Alice removes Bob from `space`, and Bob's host, told by Alice's link layer which
    /// entry lets him go, has his phone take it (`Surface::take_departure`): the way a
    /// removed person's own space learns it is removed.
    pub(crate) async fn let_go(&self, space: &Name) {
        self.alice_changes(space, &[], &[], &[&self.ns]).await;
        let record = removal_of(&self.laptop, space, &self.ns);
        let surface = self.phone().invites.surface();
        for _ in 0..20 {
            match surface
                .take_departure(&self.laptop.name, space, &record)
                .await
            {
                Ok(()) => return,
                Err(e) if e.retry() => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("Bob's phone refused the departure entry: {e}"),
            }
        }
        panic!("Bob's phone could not take the entry that lets him go of {space}");
    }

    /// Bob's phone stops (it is dropped, and so its node and its invitations).
    pub(crate) fn stop_phone(&mut self) {
        self.rig = None;
    }

    /// Bob's phone.
    pub(crate) fn phone(&self) -> &Device {
        self.rig.as_ref().expect("the phone runs")
    }

    /// Alice offers `space` (made when it is new) as `role` and Bob's phone joins it.
    pub(crate) async fn join(&self, space: &Name, role: Role) {
        ensure_space(&self.laptop, "/alice", space).await;
        let code = self
            .laptop
            .invites
            .offer(
                space,
                Offer {
                    role,
                    until: Timestamp(self.laptop.node.now().0 + 3_600_000),
                    tries: 3,
                },
            )
            .await
            .unwrap();
        let joined = self
            .phone()
            .invites
            .join(&code.link)
            .await
            .expect("the join returns once Bob may write");
        assert_eq!(&joined.space, space);
    }

    /// Bob's phone stopped and started again over its store and keys on the same
    /// forwarder, its host a new one recording in the calls returned.
    pub(crate) async fn restart(&mut self) -> Arc<Calls> {
        let old = self.rig.take().expect("the phone runs");
        let keys = Arc::clone(&old.keys);
        drop(old);
        let calls = Arc::new(Calls::default());
        self.rig = Some(
            Setup::new(&self.bob, &format!("{}/phone", self.ns))
                .config(config())
                .keys(keys)
                .store(Arc::clone(&self.store))
                .calls(Arc::clone(&calls))
                .on(&self.net, &self.cancel)
                .start()
                .await,
        );
        calls
    }

    /// Alice's change of the members of `space`.
    pub(crate) async fn alice_changes(
        &self,
        space: &Name,
        writers: &[&str],
        readers: &[&str],
        remove: &[&str],
    ) -> ndn_heap::EntryId {
        change(&self.laptop, space, writers, readers, remove).await
    }

    /// What Bob's host is told for the mirror: Alice's key, her namespace, the space,
    /// her role, no date.
    pub(crate) fn mirror_grant(&self, space: &Name, role: Role) -> crate::host::Grant {
        crate::host::Grant {
            key: self.inviter,
            namespaces: vec![n("/alice")],
            folder: space.clone(),
            role,
            until: None,
        }
    }

    /// Bob now holds the trust context of `ns` (a person of its own).
    pub(crate) fn hold(&self, ns: &str) {
        self.phone()
            .validator
            .adopt_context(Person::new(ns).ctx)
            .unwrap();
    }

    /// The writers of the notebook Bob's joined list routes.
    pub(crate) fn writers(&self) -> Vec<Name> {
        let joined = self.phone().invites.joined_folders();
        assert_eq!(joined.len(), 1, "{joined:?}");
        joined[0].writers.clone()
    }
}

impl Drop for Joiner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The mirror notes kept under `/localhost/ndn-invite/mirror/`.
pub(crate) fn mirror_notes(store: &dyn DataStore) -> Vec<(Name, Bytes)> {
    store::list(store, &store::root().append("mirror"))
}

/// The grant notes kept under `/localhost/ndn-invite/grant/`.
pub(crate) fn grant_notes(store: &dyn DataStore) -> Vec<(Name, Bytes)> {
    store::list(store, &store::grant_listing())
}

/// The only grant note an inviter's store keeps, changed in place by `edit` as a party
/// that can write the store would.
pub(crate) fn tamper(store: &dyn DataStore, edit: impl FnOnce(&mut Vec<u8>)) {
    let mut notes = grant_notes(store);
    assert_eq!(notes.len(), 1, "one admission, one grant note");
    let (name, value) = notes.pop().unwrap();
    let mut bytes = value.to_vec();
    edit(&mut bytes);
    store.insert(name, Bytes::from(bytes));
}

/// The octet of a grant note that holds its flags (version, flags, role, ...), and the
/// octets of its date.
pub(crate) const NOTE_FLAGS: usize = 1;
pub(crate) const NOTE_UNTIL: std::ops::Range<usize> = 3..11;

/// The key digest of an offer's id: whose use mark and grant note an offer name keys.
pub(crate) fn id_of(offer: &Name) -> crate::wire::OfferId {
    parse_offer_name(offer).expect("an offer's name").1
}

/// A store whose flush does not finish while it is frozen: a disk that has stopped
/// answering.
pub(crate) struct Frozen {
    inner: MemoryStore,
    frozen: AtomicBool,
}

impl Frozen {
    pub(crate) fn new() -> Arc<Frozen> {
        Arc::new(Frozen {
            inner: MemoryStore::new(),
            frozen: AtomicBool::new(false),
        })
    }

    pub(crate) fn freeze(&self, on: bool) {
        self.frozen.store(on, Ordering::SeqCst);
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
        while self.frozen.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}

/// Unfreezes a [`Frozen`] when dropped: a failing assertion must not leave the disk
/// frozen, the runtime would wait for it.
pub(crate) struct Thaw(pub(crate) Arc<Frozen>);

impl Drop for Thaw {
    fn drop(&mut self) {
        self.0.freeze(false);
    }
}

impl Drop for Inviter {
    fn drop(&mut self) {
        if let Some((_, cancel)) = &self.net {
            cancel.cancel();
        }
    }
}
