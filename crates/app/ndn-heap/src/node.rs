//! The node: one device's layer (spec §10).
//!
//! [`Node::start`] makes a device's heap layer: its identity checks, the
//! flusher, the judge, the network half ([`Net`]), and every space the store
//! holds, restored. [`NodeInner`] is what the network half asks questions of
//! (`take`, `missing`, `served`, …) and what a [`Heap`] reaches its device through; each space is a
//! [`SpaceInner`] (one log behind one lock, its publisher, its watchers).
//!
//! **Start**, in this order, so nothing the store holds is published before
//! it is durable and nothing is judged by an older rule than the contexts
//! held now: the identity checks; every held space (`space/<S>`) opened
//! ([`Log::open`]); the judge told what each lists and restored; the held
//! entries of persons whose context revokes something judged again by the
//! durable rule (a key revoked while the device was off); one flush for all
//! spaces; then the serving registration and the sync groups, each joined at
//! its head, with the recovery of own entries a crash may have left with
//! peers.
//!
//! **Close.** [`Node::close`] refuses new puts, drains each publisher,
//! flushes, writes `reserve/<S> = (head, clean)` for every space, flushes, and
//! stops. [`Node::shutdown`], which `Drop` calls, stops at once and leaves
//! the reservation above the head: the next start is unclean and says so in
//! a signed gap statement.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, ServeGuard};
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::confidentiality::RecipientKey;
use ndn_security::{SecurityManager, Signer, Validator};
use ndn_sync::{DataStore, StoreOp, SvsConfig};
use parking_lot::{Mutex, RwLock};

use crate::error::{HeapError, Refusal, Timestamp};
use crate::fold::Readers;
use crate::log::{Alert, Blob, Change, Log, Outcome, Params, Want};
use crate::reserve::{Flusher, Publisher};
use crate::revocation::{self, CutBound, CutProposal, Suspicion};
use crate::rt;
use crate::seal::{self, GrantRefusal, Keys};
use crate::serve;
use crate::space::{Follower, Heap, Share, SpaceInner, check_audience};
use crate::store::Kind;
use crate::sync::{HostRef, Net, Taken};
use crate::trust::{Adopter, Adoption, Judge, Judged};
use crate::wire::{
    EpochId, device_of, is_device_name, is_namespace, log_name, parse_log_name,
    parse_seal_key_name, parse_space_name,
};

#[cfg(test)]
#[path = "node_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "mesh_tests.rs"]
mod mesh_tests;

// -- What a host gives -------------------------------------------------------------

/// The device's wall clock, for the times it writes.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The two faces a node runs on: one for Interest and Data, one for the sync
/// group's Sync Interests.
pub struct Transport {
    /// The connection fetches and serving use.
    pub node: ndn_app::Node,
    /// The connection the sync groups use.
    pub sync: Arc<dyn Connection>,
}

/// What tunes a node.
#[derive(Clone)]
pub struct Config {
    /// State Vector Sync settings for every group the node joins.
    pub svs: SvsConfig,
    /// The device's wall clock.
    pub clock: Clock,
    /// Interest lifetime of every fetch.
    pub lifetime: Duration,
    /// How long a removal looks for entries of the removed person's devices
    /// that were heard of and are not held yet, so that its cut binds them.
    pub first_look: Duration,
    /// How many asks one device's walk has in flight at once.
    pub window: usize,
    /// How many asks the whole node has in flight at once; at least
    /// [`Self::window`].
    pub in_flight: usize,
    /// How long a restarting device waits for the first group vector before
    /// it fetches its own entries from its peers.
    pub settle: Duration,
    /// How many seqs one durable reservation covers.
    pub reserve_block: u64,
    /// How many changes a watcher may leave unread before it is told it
    /// lagged; at least 1.
    pub watch_queue: usize,
    /// What the host does so that persons a space lists can be judged
    /// (adopting their trust contexts for the data layer alone).
    pub adopter: Option<Arc<dyn Adopter>>,
}

impl Config {
    /// Defaults: SVS's reference timing, the system clock, 2 s Interests, a
    /// 4 s first look, 32 asks in flight per walk and 256 per node, a 1 s
    /// settle, reservations of 1,024 seqs, 4,096 changes a watcher may leave
    /// unread, no adopter.
    pub fn new() -> Config {
        Config {
            svs: SvsConfig::default(),
            clock: Arc::new(|| {
                let since = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default();
                Timestamp(since.as_millis() as u64)
            }),
            lifetime: Duration::from_secs(2),
            first_look: Duration::from_secs(4),
            window: 32,
            in_flight: 256,
            settle: Duration::from_secs(1),
            reserve_block: 1024,
            watch_queue: 4096,
            adopter: None,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

// -- The node ----------------------------------------------------------------------

/// A device's heap layer.
pub struct Node {
    pub(crate) inner: Arc<NodeInner>,
}

/// What a node is made of; shared by its handles, its tasks and its network
/// half.
pub(crate) struct NodeInner {
    me: Weak<NodeInner>,
    pub(crate) device: Name,
    pub(crate) ns: Name,
    pub(crate) signer: Arc<dyn Signer>,
    recipient: RecipientKey,
    pub(crate) judge: Arc<Judge>,
    pub(crate) store: Arc<dyn DataStore>,
    /// The keys marked suspected, for every space's log.
    pub(crate) suspicion: Arc<Suspicion>,
    pub(crate) flusher: Arc<Flusher>,
    pub(crate) config: Config,
    /// The network half; `None` once stopped (the cycle through its host
    /// ends there).
    net: RwLock<Option<Arc<Net>>>,
    spaces: RwLock<BTreeMap<Name, Arc<SpaceInner>>>,
    /// Creating, opening, following and leaving one at a time.
    opening: tokio::sync::Mutex<()>,
    seal_packet: Bytes,
    pub(crate) signatures: AtomicU64,
    /// The certificate fetches signal run headers wait for (spec §11).
    pub(crate) signal_gate: crate::signal::SignalGate,
    stopped: AtomicBool,
    serving: Mutex<Option<ServeGuard>>,
}

/// What the store says of a space opened before: a member (1) or a carrier
/// (2).
const MEMBER: u8 = 1;
const CARRIER: u8 = 2;

impl Node {
    /// Start the heap layer of `device` (e.g. `/alice/laptop`): sign with the
    /// key `keys` holds for it, keep its X25519 recipient secret with `keys`
    /// too (made on the first start), verify with `validator`, keep what it
    /// holds in `store` and pick up what an earlier run stored there, serve
    /// `device`'s prefix, and rejoin every space it held. Its namespace is that
    /// of the trust context governing its name in `validator`'s keyring; a
    /// device no held context covers does not start.
    pub async fn start(
        transport: Transport,
        device: Name,
        keys: Arc<SecurityManager>,
        validator: Arc<Validator>,
        store: Arc<dyn DataStore>,
        config: Config,
    ) -> Result<Node, HeapError> {
        let identity = keys
            .signing_identity_for(&device)
            .map_err(|e| HeapError::local(format!("no key to sign as {device}: {e}")))?;
        if device_of(&identity.key).as_ref() != Some(&device) {
            return Err(HeapError::local(format!(
                "the key that signs for {device} is {}, which is not {device}'s own key; give \
                 the device a key named {device}/KEY/<id>",
                identity.key
            )));
        }
        if !is_device_name(&device) {
            return Err(HeapError::local(format!(
                "{device} has a keyword or digest component; a device name is plain components \
                 (<namespace>/<role>/<device>), so the layer's names after it (32=log, 32=seal) \
                 say where it ends"
            )));
        }
        let ns = validator.keyring().context_for(&device).namespace().clone();
        if ns.is_empty() {
            return Err(HeapError::local(format!(
                "no trust context covers {device}: the validator holds none whose namespace is \
                 a prefix of it, so nothing says which namespace the device writes for; adopt \
                 its namespace's trust context (enroll the device) and start it again"
            )));
        }
        if !is_namespace(&ns) {
            return Err(HeapError::local(format!(
                "{device} lies in the trust context of {ns}, whose namespace has a keyword, \
                 digest or sequence-number component, which a space name \
                 <namespace>/32=data/<name> cannot carry; enroll the device in a namespace of \
                 plain components"
            )));
        }
        let recipient = seal::recipient_key(&keys, &device).map_err(HeapError::local)?;
        let seal_packet = seal::seal_key_packet(&device, &recipient.public(), &*identity.signer)
            .map_err(HeapError::local)?;

        let flusher = Flusher::spawn(Arc::clone(&store));
        let (judge, adoptions) = Judge::new(
            Arc::clone(&validator),
            Arc::clone(&store),
            config.adopter.clone(),
        );
        let inner = Arc::new_cyclic(|me| NodeInner {
            me: me.clone(),
            device: device.clone(),
            ns,
            signer: identity.signer,
            recipient,
            judge,
            suspicion: Suspicion::open(Arc::clone(&store)),
            store,
            flusher,
            config,
            net: RwLock::new(None),
            spaces: RwLock::new(BTreeMap::new()),
            opening: tokio::sync::Mutex::new(()),
            seal_packet,
            signatures: AtomicU64::new(0),
            signal_gate: crate::signal::SignalGate::default(),
            stopped: AtomicBool::new(false),
            serving: Mutex::new(None),
        });
        let node = Node {
            inner: Arc::clone(&inner),
        };
        let net = Net::start(
            Arc::clone(&inner) as HostRef,
            inner.config.clone(),
            transport.node.connection(),
            transport.sync,
        );
        *inner.net.write() = Some(net);
        // From here a failure drops `node`, which stops what was started.
        let held = inner.restore().await?;
        rt::spawn(NodeInner::adoption_task(Arc::downgrade(&inner), adoptions));
        rt::spawn(NodeInner::failure_task(
            Arc::downgrade(&inner),
            Arc::clone(&inner.flusher),
        ));
        let serving = Arc::downgrade(&inner);
        let guard = transport
            .node
            .serve(device.clone(), move |interest, responder| {
                let net = serving.upgrade().and_then(|inner| inner.net());
                async move {
                    if let Some(net) = net {
                        serve::answer(net, interest, responder).await;
                    }
                }
            })
            .await
            .map_err(|e| HeapError::local(format!("cannot serve {device}: {e}")))?;
        *inner.serving.lock() = Some(guard);
        for joined in futures::future::join_all(
            held.into_iter()
                .map(|(log, follower)| inner.join(log, follower)),
        )
        .await
        {
            joined?;
        }
        Ok(node)
    }

    /// Make the space `space` (`<O>/32=data/…`, `O` this device's namespace):
    /// sign its creation, the initial additions and, unless the space is
    /// public, its first epoch. Returns after the flush that covers them.
    /// Another namespace's device is [`HeapError::NotOwner`], next step
    /// `UseOwnerDevice`.
    pub async fn create(&self, space: &Name, share: Share) -> Result<Heap, HeapError> {
        let inner = &self.inner;
        let _opening = inner.opening.lock().await;
        if parse_space_name(space).is_some_and(|parsed| parsed.owner != inner.ns) {
            return Err(HeapError::NotOwner {
                space: space.clone(),
            });
        }
        if inner.spaces.read().contains_key(space) {
            return Err(HeapError::BadRequest {
                why: format!("{space} is open here already: create makes a space once"),
            });
        }
        if let Readers::Persons(readers) = &share.readers {
            let listed: std::collections::BTreeSet<&Name> =
                readers.iter().chain(std::iter::once(&inner.ns)).collect();
            check_audience(listed.len())?;
        }
        let attached = inner.hold(space, false).await?;
        let heap = Heap::new(Arc::clone(&attached), Arc::clone(inner));
        match attached.sign_creation(inner, &share).await {
            Ok(()) => Ok(heap),
            Err(e) => {
                inner.leave_locked(space).await;
                Err(e)
            }
        }
    }

    /// Join a space made elsewhere. Idempotent; a node's start opens every
    /// space it held.
    pub async fn open(&self, space: &Name) -> Result<Heap, HeapError> {
        let inner = &self.inner;
        let _opening = inner.opening.lock().await;
        Ok(Heap::new(
            inner.hold(space, false).await?,
            Arc::clone(inner),
        ))
    }

    /// The space `space`, if this node has it open as a member.
    pub fn space(&self, space: &Name) -> Option<Heap> {
        let held = self.inner.spaces.read().get(space).cloned()?;
        (!held.follower).then(|| Heap::new(held, Arc::clone(&self.inner)))
    }

    /// The spaces this node has open as a member, by name.
    pub fn spaces(&self) -> Vec<Name> {
        let spaces = self.inner.sorted();
        let members = spaces.iter().filter(|s| !s.follower);
        members.map(|s| s.name.clone()).collect()
    }

    /// Carry `space`: join it, verify and store what it holds and serve it,
    /// publishing no vector entry and needing no read key.
    pub async fn follow(&self, space: &Name) -> Result<Follower, HeapError> {
        let inner = &self.inner;
        let _opening = inner.opening.lock().await;
        Ok(Follower {
            space: inner.hold(space, true).await?,
            node: Arc::clone(inner),
        })
    }

    /// Wait for a flush covering everything written so far; the store's
    /// failure once it failed.
    pub async fn flush(&self) -> Result<(), HeapError> {
        Ok(self.inner.flusher.flush().await?)
    }

    /// Stop cleanly: refuse new puts, drain the publishers, flush, record
    /// each space's head as a clean close, flush, stop. The next start has no
    /// hole and says nothing.
    pub async fn close(self) {
        let inner = Arc::clone(&self.inner);
        let spaces: Vec<Arc<SpaceInner>> = inner.spaces.read().values().cloned().collect();
        for space in &spaces {
            space.closing.store(true, Ordering::Relaxed);
        }
        futures::future::join_all(spaces.iter().map(|s| s.publisher.drain())).await;
        if let Err(e) = inner.flusher.flush().await {
            tracing::warn!("the store did not make everything durable before close: {e}");
        }
        // A space that started unclean and has signed nothing since still has
        // seqs above its head an earlier run may have shown: its reservation
        // stays above them (the next start is unclean again), or a clean
        // record would let the next entry reuse one.
        let closing = spaces.iter().filter_map(|space| {
            let log = space.log.lock();
            let head = log.head();
            (log.next_seq() == head + 1).then(|| {
                let reservation = Arc::clone(&log.reservation);
                async move { reservation.close_clean(head).await }
            })
        });
        for result in futures::future::join_all(closing).await {
            if let Err(e) = result {
                tracing::warn!("a space was not closed cleanly: {e}");
            }
        }
        inner.shutdown();
    }

    /// Stop at once. Whatever the flusher had not made durable is not; the
    /// reservation stays above the head, so the next start is unclean (a
    /// hole and a gap statement).
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// The device's name.
    pub fn name(&self) -> &Name {
        &self.inner.device
    }

    /// The device's namespace: that of the trust context governing its name,
    /// whose spaces it owns and whose sync groups it joins.
    pub fn namespace(&self) -> &Name {
        &self.inner.ns
    }

    /// The key this device signs with.
    pub fn writer(&self) -> &Name {
        self.inner.signer.key_name()
    }

    /// Signatures this node has made (entries and grants).
    pub fn signatures(&self) -> u64 {
        self.inner.signatures.load(Ordering::Relaxed)
    }

    /// Entries this node holds, copies of others' and its own, in every
    /// space.
    pub fn held(&self) -> u64 {
        self.inner
            .with_logs(|logs| logs.iter().map(|log| log.held_count()).sum())
    }

    /// The cut this node can vouch for if `key` is revoked now (spec §9),
    /// over every space it holds.
    pub fn revocation_cut(&self, key: &Name, bound: &CutBound) -> Result<CutProposal, HeapError> {
        self.inner.with_logs(|logs| {
            revocation::revocation_cut(logs, &self.inner.judge, &self.inner.suspicion, key, bound)
        })
    }

    /// Mark `key` suspected since `since`: no new entry of it is taken.
    pub fn suspect(&self, key: &Name, since: Timestamp) -> Result<(), HeapError> {
        self.inner.suspicion.mark(key, since)
    }

    /// Lift the mark of `key`. Whether there was one.
    pub fn unsuspect(&self, key: &Name) -> bool {
        self.inner.suspicion.lift(key)
    }

    /// Since when `key` is marked suspected here.
    pub fn suspected(&self, key: &Name) -> Option<Timestamp> {
        self.inner.suspicion.since(key)
    }

    /// The entries `key` signed that this node holds refused because its
    /// revocation does not accept them, each by its full name.
    pub fn refused_by_revocation(&self, key: &Name) -> Vec<Name> {
        self.inner
            .with_logs(|logs| revocation::refused_by_revocation(logs, key))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

// -- Inside ------------------------------------------------------------------------

impl NodeInner {
    fn arc(&self) -> Arc<NodeInner> {
        self.me
            .upgrade()
            .expect("the node is alive while it is used")
    }

    pub(crate) fn device(&self) -> &Name {
        &self.device
    }

    pub(crate) fn now(&self) -> u64 {
        (self.config.clock)().0
    }

    fn net(&self) -> Option<Arc<Net>> {
        self.net.read().clone()
    }

    pub(crate) fn nudge(&self, space: &Name) {
        if let Some(net) = self.net() {
            net.nudge(space);
        }
    }

    pub(crate) fn space_of(&self, space: &Name) -> Option<Arc<SpaceInner>> {
        self.spaces.read().get(space).cloned()
    }

    /// Every open space, by name: the order logs are locked in together.
    fn sorted(&self) -> Vec<Arc<SpaceInner>> {
        self.spaces.read().values().cloned().collect()
    }

    fn with_logs<R>(&self, f: impl FnOnce(&[&Log]) -> R) -> R {
        let spaces = self.sorted();
        let guards: Vec<_> = spaces.iter().map(|s| s.log.lock()).collect();
        let logs: Vec<&Log> = guards.iter().map(|g| &**g).collect();
        f(&logs)
    }

    /// The person of a device: the namespace of the context that governs it.
    pub(crate) fn person_of(&self, device: &Name) -> Name {
        let keyring = self.judge.validator.keyring();
        keyring
            .unheld_personal_namespace(device)
            .unwrap_or_else(|| keyring.context_for(device).namespace().clone())
    }

    fn shutdown(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.flusher.stop();
        if let Some(net) = self.net.write().take() {
            net.shutdown();
        }
        self.serving.lock().take();
        let spaces: Vec<_> = std::mem::take(&mut *self.spaces.write())
            .into_values()
            .collect();
        for space in spaces {
            // An admission under way ends before the node is stopped.
            drop(space.log.lock());
            space.close_watchers();
        }
    }

    // -- Opening ----------------------------------------------------------------

    /// The log of `space` from the store, with the judge told what it lists.
    fn open_log(&self, space: &Name) -> Result<Log, HeapError> {
        let log = Log::open(
            Params {
                space: space.clone(),
                device: self.device.clone(),
                person: self.ns.clone(),
                suspicion: Arc::clone(&self.suspicion),
                signer: Arc::clone(&self.signer),
                keys: Keys::new(self.recipient.clone()),
                block: self.config.reserve_block,
            },
            Arc::clone(&self.store),
            Arc::clone(&self.flusher),
        )?;
        self.judge.note(space, &SpaceInner::listing(&log));
        Ok(log)
    }

    /// `space` as a member or a carrier, with `opening` held: the one held
    /// already, or one opened, recorded in the store (a restart restores it)
    /// and joined.
    async fn hold(
        self: &Arc<Self>,
        space: &Name,
        follower: bool,
    ) -> Result<Arc<SpaceInner>, HeapError> {
        if let Some(held) = self.space_of(space) {
            let why = if held.follower == follower {
                return Ok(held);
            } else if follower {
                format!("{space} is open here as a member: a member carries it already")
            } else {
                format!(
                    "{space} is followed here as a carrier, which reads and writes nothing; \
                     close the follower before opening the space"
                )
            };
            return Err(HeapError::BadRequest { why });
        }
        if self.stopped.load(Ordering::Relaxed) {
            return Err(HeapError::local("the node is stopped"));
        }
        let log = self.open_log(space)?;
        self.store.insert(
            Kind::SPACE.of(space),
            Bytes::copy_from_slice(&[if follower { CARRIER } else { MEMBER }]),
        );
        self.flusher.note_write();
        self.join(log, follower).await
    }

    /// Join the group of an opened space at its head and take it into the
    /// node; with peers known, wait for them to show what they hold of this
    /// device before anything is signed.
    async fn join(
        self: &Arc<Self>,
        log: Log,
        follower: bool,
    ) -> Result<Arc<SpaceInner>, HeapError> {
        let unclean = log.unclean();
        let net = self
            .net()
            .ok_or_else(|| HeapError::local("the node is stopped"))?;
        let space = log.space.clone();
        let counter = if follower { 0 } else { log.head() };
        let group = net.join(&space, counter).await?;
        let publisher = Publisher::spawn(Arc::clone(&self.flusher), group.sink());
        let inner = Arc::new(SpaceInner::new(
            log,
            publisher,
            Arc::clone(&group),
            follower,
        ));
        self.spaces.write().insert(space, Arc::clone(&inner));
        if !follower {
            // Peers known (an admitted entry of another device is held): wait
            // for their vector, and for the entries it shows of this device,
            // before the first publication. Clean or not: an old image closed
            // cleanly looks complete, and the peers hold what it signed since.
            // The wait ends on the first vector and on the own entries
            // fetched (or asked for in vain); `settle` is only the longest it
            // waits for a vector, liveness and not a rule. Otherwise nothing
            // is waited for; what peers heard later hold of this device's is
            // still fetched and handed to the log.
            let peers = inner.log.lock().has_peers();
            if peers {
                // The fetching goes on in the group when the wait ends: a
                // start never waits for a network without bound.
                let bound = self.config.settle + self.config.lifetime * 3;
                let _ = rt::timeout(bound, group.recover(self.config.settle)).await;
            } else if unclean {
                let group = Arc::clone(&group);
                let settle = self.config.settle;
                rt::spawn(async move {
                    group.recover(settle).await;
                });
            }
        }
        inner.seed_owed(self);
        inner.settle(self);
        Ok(inner)
    }

    /// Every space the store holds: opened, judged, flushed. Joined by the
    /// caller once the node serves.
    async fn restore(self: &Arc<Self>) -> Result<Vec<(Log, bool)>, HeapError> {
        let mut held = Vec::new();
        for (space, mode) in Kind::SPACE.named(&*self.store) {
            if parse_space_name(&space).is_none() {
                tracing::warn!(%space, "a record of a space that is no space name is ignored");
                continue;
            }
            held.push((self.open_log(&space)?, mode.first() == Some(&CARRIER)));
        }
        self.judge.restore().await;
        // A key revoked while the device was off: what it signed is judged
        // again by the contexts held now.
        let revoking: Vec<Name> = self
            .judge
            .validator
            .keyring()
            .contexts()
            .iter()
            .filter(|ctx| !ctx.revocations().is_empty())
            .map(|ctx| ctx.namespace().clone())
            .collect();
        for (log, _) in &mut held {
            let names: Vec<Name> = revoking
                .iter()
                .flat_map(|person| log.held_names(person))
                .collect();
            for (device, seq, why) in self.refusals(&log.space, names).await {
                let fx = log.withdraw(&device, seq, why);
                if fx.membership {
                    self.judge.note(&log.space, &SpaceInner::listing(log));
                }
            }
        }
        // What the store holds may be only in the operating system's
        // buffers: it is durable before any of it is published.
        self.flusher.flush().await.map_err(|e| {
            HeapError::local(format!(
                "the store did not make what it holds durable ({e}); {} publishes only what is \
                 on disk, so it does not start: check the disk or filesystem the store is on, \
                 and start it again",
                self.device
            ))
        })?;
        Ok(held)
    }

    /// Stop carrying or holding `space`: left, forgotten, and not restored.
    pub(crate) async fn leave(&self, space: &Name) {
        let _opening = self.opening.lock().await;
        self.leave_locked(space).await;
    }

    async fn leave_locked(&self, space: &Name) {
        let held = self.spaces.write().remove(space);
        if let Some(net) = self.net() {
            net.leave(space).await;
        }
        self.store.remove(&Kind::SPACE.of(space));
        self.flusher.note_write();
        if let Some(held) = held {
            held.closing.store(true, Ordering::Relaxed);
            held.close_watchers();
        }
    }

    // -- What the judge says later ----------------------------------------------

    /// The entries named that the judge now refuses, by the durable rule:
    /// device, seq, why. Entries it cannot decide yet, and a lapse (this
    /// node's clock alone says it), are left as they are.
    async fn refusals(&self, space: &Name, names: Vec<Name>) -> Vec<(Name, u64, Refusal)> {
        let mut out = Vec::new();
        for name in names {
            let Some(log_name) = parse_log_name(&name) else {
                continue;
            };
            let Some(wire) = self.store.get(&name) else {
                continue;
            };
            let Ok(data) = Data::decode(wire) else {
                continue;
            };
            if let Judged::Refused(why) = self.judge.validate(&data, space).await
                && !matches!(why, Refusal::Lapsed { .. })
            {
                out.push((log_name.device, log_name.seq, why));
            }
        }
        out
    }

    /// Judge the held entries of `persons` again in `spaces`, and withdraw
    /// what is refused now.
    async fn rejudge(self: &Arc<Self>, spaces: Vec<Name>, persons: &[Name]) {
        for space in spaces {
            let Some(held) = self.space_of(&space) else {
                continue;
            };
            let names: Vec<Name> = {
                let log = held.log.lock();
                persons.iter().flat_map(|p| log.held_names(p)).collect()
            };
            for (device, seq, why) in self.refusals(&space, names).await {
                let routed = {
                    let mut log = held.log.lock();
                    let fx = log.withdraw(&device, seq, why);
                    held.route(self, &log, fx, true)
                };
                held.finish(self, routed);
            }
            held.settle(self);
        }
    }

    async fn on_adoption(self: &Arc<Self>, event: Adoption) {
        match event {
            Adoption::Context(ctx) => {
                self.suspicion
                    .lift_revoked(revocation::revoked_by(&self.judge));
                let spaces = self.spaces.read().keys().cloned().collect();
                self.rejudge(spaces, std::slice::from_ref(ctx.namespace()))
                    .await;
            }
            Adoption::Person {
                person,
                spaces,
                refuses,
            } => {
                let persons = if refuses {
                    std::slice::from_ref(&person)
                } else {
                    &[]
                };
                self.rejudge(spaces, persons).await;
            }
        }
    }

    async fn adoption_task(
        node: Weak<NodeInner>,
        mut events: tokio::sync::mpsc::UnboundedReceiver<Adoption>,
    ) {
        while let Some(event) = events.recv().await {
            let Some(inner) = node.upgrade() else { break };
            if inner.stopped.load(Ordering::Relaxed) {
                break;
            }
            inner.on_adoption(event).await;
        }
    }

    async fn failure_task(node: Weak<NodeInner>, flusher: Arc<Flusher>) {
        let Some(why) = flusher.failed().await else {
            return;
        };
        let Some(inner) = node.upgrade() else { return };
        for space in inner.sorted() {
            space.tell(Change::Alert(Alert::StoreFailed {
                why: why.to_string(),
            }));
        }
    }

    // -- What the network half asks -------------------------------------------------

    pub(crate) async fn take(&self, space: &Name, wire: Bytes, probe: bool) -> Taken {
        let refused = |why| Taken::Decided {
            outcome: Outcome::Refused(why),
            blobs: Vec::new(),
        };
        let Some(held) = self.space_of(space) else {
            return refused(Refusal::NotMember);
        };
        let Ok(data) = Data::decode(wire.clone()) else {
            return refused(Refusal::BadSignature);
        };
        let mut tries = 0;
        let verified = loop {
            let generation = self.judge.generation();
            match self.judge.validate(&data, space).await {
                Judged::Valid(_) if self.judge.generation() != generation && tries < 3 => {
                    tries += 1;
                }
                Judged::Valid(v) => break v,
                Judged::Refused(why) => {
                    held.alert_refused_packet(&data, &why);
                    return refused(why);
                }
                Judged::Pending(waiting) => return Taken::Pending(waiting),
            }
        };
        tracing::trace!(target: crate::sync::TIMELINE, "judged");
        let (outcome, blobs, routed) = {
            let mut log = held.log.lock();
            // Judging is async: the node may have stopped meanwhile, and what
            // a stopped node writes is unknown to the log that opens the
            // store next (a restart over the same store).
            if self.stopped.load(Ordering::SeqCst) {
                return Taken::Pending(crate::trust::Waiting::Chain);
            }
            let (outcome, fx) = log.admit(&wire, &data, &verified, self.now(), probe);
            let wrote = !matches!(outcome, Outcome::Duplicate);
            let blobs = fx.blobs.clone();
            (outcome, blobs, held.route(self, &log, fx, wrote))
        };
        tracing::trace!(target: crate::sync::TIMELINE, "admitted");
        held.finish(&self.arc(), routed);
        tracing::trace!(target: crate::sync::TIMELINE, "routed");
        if let Outcome::Refused(why) = &outcome {
            held.alert_refused_packet(&data, why);
        }
        if matches!(
            outcome,
            Outcome::Applied | Outcome::Closed | Outcome::Waiting
        ) {
            // A device an admitted entry vouches for is told its counter.
            self.nudge(space);
        }
        Taken::Decided { outcome, blobs }
    }

    pub(crate) fn missing(&self, space: &Name) -> Vec<Want> {
        self.space_of(space)
            .map_or_else(Vec::new, |s| s.log.lock().missing())
    }

    pub(crate) fn high(&self, space: &Name, device: &Name) -> u64 {
        self.space_of(space)
            .map_or(0, |s| s.log.lock().high(device))
    }

    pub(crate) fn head(&self, space: &Name) -> u64 {
        self.space_of(space).map_or(0, |s| s.log.lock().head())
    }

    pub(crate) fn note_own_counter(&self, space: &Name, seen: u64) {
        let Some(held) = self.space_of(space) else {
            return;
        };
        let routed = {
            let mut log = held.log.lock();
            let fx = log.note_own_counter(seen);
            held.route(self, &log, fx, false)
        };
        held.finish(&self.arc(), routed);
    }

    pub(crate) fn vouched(&self, space: &Name, device: &Name) -> bool {
        self.space_of(space)
            .is_some_and(|s| s.log.lock().vouches(device))
    }

    pub(crate) fn standing(&self, space: &Name, device: &Name) -> Option<bool> {
        let held = self.space_of(space)?;
        let log = held.log.lock();
        log.vouches(device).then(|| log.held_prefix(device) > 0)
    }

    pub(crate) fn served(&self, space: &Name, device: &Name, seq: u64) -> Option<Bytes> {
        let held = self.space_of(space)?;
        // Whether an own entry may be served is decided under the log's lock:
        // a Members or Epoch entry is recorded as held back by the signing
        // call that stores it, still under that lock, so no Interest can find
        // it stored and not yet held back.
        let log = held.log.lock();
        if *device == self.device && !held.publisher.servable(seq) {
            return None;
        }
        log.served(device, seq)
    }

    pub(crate) fn served_piece(
        &self,
        space: &Name,
        device: &Name,
        seq: u64,
        piece: &Name,
    ) -> Option<Bytes> {
        if !piece.has_prefix(&log_name(device, space, seq)) {
            return None;
        }
        self.served(space, device, seq)?;
        self.store.get(piece)
    }

    pub(crate) fn seal_key_packet(&self, name: &Name) -> Option<Bytes> {
        let (device, public) = parse_seal_key_name(name)?;
        (device == self.device && public == self.recipient.public())
            .then(|| self.seal_packet.clone())
    }

    pub(crate) fn blobs(&self, space: &Name) -> Vec<Blob> {
        self.space_of(space)
            .map_or_else(Vec::new, |s| s.unassembled())
    }

    pub(crate) fn held_piece(&self, space: &Name, name: &Name) -> Option<Bytes> {
        self.space_of(space)?;
        self.store.get(name)
    }

    pub(crate) fn keep_pieces(&self, space: &Name, ops: Vec<StoreOp>) {
        if self.space_of(space).is_some() {
            self.store.apply(ops);
            self.flusher.note_write();
        }
    }

    pub(crate) fn assembled(&self, space: &Name, blob: &Blob) {
        if let Some(held) = self.space_of(space) {
            held.assembled(&self.arc(), blob);
        }
    }

    pub(crate) fn owed_keys(&self, space: &Name) -> Vec<EpochId> {
        let Some(held) = self.space_of(space).filter(|s| !s.follower) else {
            return Vec::new();
        };
        let log = held.log.lock();
        if !log.sealed() {
            return Vec::new();
        }
        let fold = &log.fold;
        let in_force = fold.in_force();
        fold.epochs()
            .into_iter()
            .filter(|e| fold.audience(e).contains(&log.person))
            .filter(|e| log.keys.key(space, e).is_none())
            .filter(|e| log.has_closed() || in_force.as_ref() == Some(e))
            .collect()
    }

    pub(crate) fn seal_public(&self) -> [u8; 32] {
        self.recipient.public()
    }

    pub(crate) async fn validate_device_packet(
        &self,
        space: &Name,
        data: &Data,
        device: &Name,
    ) -> Judged {
        self.judge.validate_device_packet(data, device, space).await
    }

    pub(crate) fn key_arrived(
        &self,
        space: &Name,
        epoch: &EpochId,
        name: &Name,
        content: Bytes,
    ) -> bool {
        let Some(held) = self.space_of(space) else {
            return false;
        };
        let (taken, routed) = {
            let mut log = held.log.lock();
            let Some(key) = seal::unwrap_key(&log.keys.recipient, name, content) else {
                return false;
            };
            let (taken, fx) = log.key_arrived(epoch.clone(), key);
            (taken, held.route(self, &log, fx, taken))
        };
        held.finish(&self.arc(), routed);
        taken
    }

    pub(crate) fn generation(&self) -> u64 {
        self.judge.generation()
    }

    pub(crate) fn may_grant(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        asker_key: Option<&Name>,
    ) -> Result<(), GrantRefusal> {
        let held = self.space_of(space).ok_or(GrantRefusal::EpochNotNamed)?;
        let person = self.person_of(asker);
        let log = held.log.lock();
        let revoked = asker_key.is_some_and(|k| self.judge.key_revoked(k, space));
        seal::may_grant(&log.fold, &log.keys, space, epoch, &person, revoked)?;
        // Under the lock: the entry is held back there, in the same stretch
        // that stores it, so no grant can slip in between.
        if epoch.creator == self.device && !held.publisher.servable(epoch.seq) {
            return Err(GrantRefusal::EpochNotNamed);
        }
        Ok(())
    }

    pub(crate) fn grant_packet(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        asker_key: &Name,
        to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes> {
        self.may_grant(space, epoch, asker, Some(asker_key)).ok()?;
        let held = self.space_of(space)?;
        let key = held.log.lock().keys.key(space, epoch)?.clone();
        let packet = seal::grant_packet(to, &key, name, &*self.signer).ok()?;
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Some(packet)
    }
}
