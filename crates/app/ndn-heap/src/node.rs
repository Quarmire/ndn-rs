//! The node: one device's layer (spec §10).
//!
//! [`Node::start`] makes a device's heap layer: its identity checks, the
//! flusher, the judge, the network half ([`Net`]), and every space the store
//! holds, restored. [`NodeInner`] is what the network half asks questions of
//! ([`Host`]) and what a [`Heap`] reaches its device through; each space is a
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
use ndn_security::{SecurityManager, Signer, Validator};
use ndn_sync::{DataStore, StoreOp, SvsConfig};
use parking_lot::{Mutex, RwLock};

use crate::error::{HeapError, Refusal, Timestamp};
use crate::fold::Readers;
use crate::log::{Alert, Blob, Change, Log, Outcome, Params, Want};
use crate::reserve::{Flusher, Publisher};
use crate::revocation::{self, CutBound, CutProposal};
use crate::rt;
use crate::seal::{self, GrantRefusal, Granter, Keys};
use crate::serve;
use crate::space::{Follower, Heap, Share, SpaceInner, check_audience, new_id};
use crate::store::{self, Stage};
use crate::sync::{Host, Net, NetConfig, Taken};
use crate::trust::{Adopter, Adoption, Judge, Judged};
use crate::wire::{
    EpochId, MembersBody, Op, Role, device_of, is_device_name, is_namespace, log_name,
    parse_log_name, parse_seal_key_name, parse_space_name,
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

/// Who signs: a device's key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Writer(Name);

impl Writer {
    /// The writer whose key is named `key`.
    pub fn new(key: Name) -> Writer {
        Writer(key)
    }

    /// The key name.
    pub fn key(&self) -> &Name {
        &self.0
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
    ns: Name,
    pub(crate) writer: Writer,
    pub(crate) signer: Arc<dyn Signer>,
    keys: Arc<SecurityManager>,
    pub(crate) judge: Arc<Judge>,
    raw: Arc<dyn DataStore>,
    pub(crate) stage: Arc<Stage>,
    pub(crate) flusher: Arc<Flusher>,
    pub(crate) config: Config,
    /// The network half; `None` once stopped (the cycle through its `Host`
    /// ends there).
    net: RwLock<Option<Arc<Net>>>,
    spaces: RwLock<BTreeMap<Name, Arc<SpaceInner>>>,
    /// Creating, opening, following and leaving one at a time.
    opening: tokio::sync::Mutex<()>,
    seal_public: [u8; 32],
    seal_packet: Bytes,
    pub(crate) signatures: AtomicU64,
    /// The certificate fetches signal run headers wait for (spec §11).
    pub(crate) signal_gate: crate::signal::SignalGate,
    stopped: AtomicBool,
    failed: Mutex<Option<String>>,
    serving: Mutex<Option<ServeGuard>>,
    /// Spaces opened at start, until they are joined.
    restored: Mutex<Vec<Held>>,
}

fn local(reason: impl Into<String>) -> HeapError {
    HeapError::Local {
        reason: reason.into(),
    }
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
            .map_err(|e| local(format!("no key to sign as {device}: {e}")))?;
        if device_of(&identity.key).as_ref() != Some(&device) {
            return Err(local(format!(
                "the key that signs for {device} is {}, which is not {device}'s own key; give \
                 the device a key named {device}/KEY/<id>",
                identity.key
            )));
        }
        if !is_device_name(&device) {
            return Err(local(format!(
                "{device} has a keyword or digest component; a device name is plain components \
                 (<namespace>/<role>/<device>), so the layer's names after it (32=log, 32=seal) \
                 say where it ends"
            )));
        }
        let ns = validator.keyring().context_for(&device).namespace().clone();
        if ns.is_empty() {
            return Err(local(format!(
                "no trust context covers {device}: the validator holds none whose namespace is \
                 a prefix of it, so nothing says which namespace the device writes for; adopt \
                 its namespace's trust context (enroll the device) and start it again"
            )));
        }
        if !is_namespace(&ns) {
            return Err(local(format!(
                "{device} lies in the trust context of {ns}, whose namespace has a keyword, \
                 digest or sequence-number component, which a space name \
                 <namespace>/32=data/<name> cannot carry; enroll the device in a namespace of \
                 plain components"
            )));
        }
        let recipient = seal::recipient_key(&keys, &device).map_err(|e| local(e.to_string()))?;
        let seal_public = recipient.public();
        let seal_packet = seal::seal_key_packet(&device, &seal_public, &*identity.signer)
            .map_err(|e| local(e.to_string()))?;
        drop(recipient);

        let stage = Stage::new(Arc::clone(&store));
        let flusher = Flusher::spawn(Arc::clone(&store));
        let judge = Judge::new(
            Arc::clone(&validator),
            Arc::clone(&store),
            config.adopter.clone(),
        );
        let adoptions = judge.adoptions();
        let net_config = NetConfig {
            svs: config.svs.clone(),
            lifetime: config.lifetime,
            window: config.window,
            in_flight: config.in_flight.max(config.window).max(1),
            reserve_block: config.reserve_block,
        };
        let inner = Arc::new_cyclic(|me| NodeInner {
            me: me.clone(),
            writer: Writer::new(identity.key.clone()),
            device: device.clone(),
            ns,
            signer: identity.signer,
            keys,
            judge,
            raw: store,
            stage,
            flusher,
            config,
            net: RwLock::new(None),
            spaces: RwLock::new(BTreeMap::new()),
            opening: tokio::sync::Mutex::new(()),
            seal_public,
            seal_packet,
            signatures: AtomicU64::new(0),
            signal_gate: crate::signal::SignalGate::default(),
            stopped: AtomicBool::new(false),
            failed: Mutex::new(None),
            serving: Mutex::new(None),
            restored: Mutex::new(Vec::new()),
        });
        let node = Node {
            inner: Arc::clone(&inner),
        };
        let net = Net::start(
            Arc::clone(&inner) as Arc<dyn Host>,
            net_config,
            transport.node.connection(),
            transport.sync,
        );
        *inner.net.write() = Some(net);
        // From here a failure drops `node`, which stops what was started.
        inner.restore().await?;
        if let Some(rx) = adoptions {
            rt::spawn(NodeInner::adoption_task(Arc::downgrade(&inner), rx));
        }
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
            .map_err(|e| local(format!("cannot serve {device}: {e}")))?;
        *inner.serving.lock() = Some(guard);
        inner.join_restored().await?;
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
        let parsed = parse_space_name(space).ok_or_else(|| HeapError::BadName {
            name: space.clone(),
            why: "a space is `<owner>/32=data/<name>`".into(),
        })?;
        if parsed.owner != inner.ns {
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
        let attached = inner.attach(space, false).await?;
        let heap = Heap::new(Arc::clone(&attached), Arc::clone(inner));
        match inner.sign_creation(&attached, &share).await {
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
        parse_space_name(space).ok_or_else(|| HeapError::BadName {
            name: space.clone(),
            why: "a space is `<owner>/32=data/<name>`".into(),
        })?;
        let held = inner.spaces.read().get(space).cloned();
        let attached = match held {
            Some(s) if s.follower => {
                return Err(HeapError::BadRequest {
                    why: format!(
                        "{space} is followed here as a carrier, which reads and writes nothing; \
                         close the follower before opening the space"
                    ),
                });
            }
            Some(s) => s,
            None => inner.attach(space, false).await?,
        };
        Ok(Heap::new(attached, Arc::clone(inner)))
    }

    /// The space `space`, if this node has it open as a member.
    pub fn space(&self, space: &Name) -> Option<Heap> {
        let held = self.inner.spaces.read().get(space).cloned()?;
        (!held.follower).then(|| Heap::new(held, Arc::clone(&self.inner)))
    }

    /// The spaces this node has open as a member, by name.
    pub fn spaces(&self) -> Vec<Name> {
        self.inner
            .spaces
            .read()
            .iter()
            .filter(|(_, s)| !s.follower)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Carry `space`: join it, verify and store what it holds and serve it,
    /// publishing no vector entry and needing no read key.
    pub async fn follow(&self, space: &Name) -> Result<Follower, HeapError> {
        let inner = &self.inner;
        let _opening = inner.opening.lock().await;
        parse_space_name(space).ok_or_else(|| HeapError::BadName {
            name: space.clone(),
            why: "a space is `<owner>/32=data/<name>`".into(),
        })?;
        let held = inner.spaces.read().get(space).cloned();
        let attached = match held {
            Some(s) if !s.follower => {
                return Err(HeapError::BadRequest {
                    why: format!("{space} is open here as a member: a member carries it already"),
                });
            }
            Some(s) => s,
            None => inner.attach(space, true).await?,
        };
        Ok(Follower {
            node: Arc::clone(inner),
            space: attached,
        })
    }

    /// Wait for a flush covering everything written so far; the store's
    /// failure once it failed.
    pub async fn flush(&self) -> Result<(), HeapError> {
        self.inner
            .flusher
            .flush()
            .await
            .map_err(|e| local(e.to_string()))
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
                let reservation = Arc::clone(log.reservation());
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

    /// The writer this device signs as: its key.
    pub fn writer(&self) -> &Writer {
        &self.inner.writer
    }

    /// Signatures this node has made (entries and grants).
    pub fn signatures(&self) -> u64 {
        self.inner.signatures.load(Ordering::Relaxed)
    }

    /// Entries this node holds, copies of others' and its own, in every
    /// space.
    pub fn held(&self) -> u64 {
        self.inner.held_in(&Name::root())
    }

    /// The cut this node can vouch for if `key` is revoked now (spec §9),
    /// over every space it holds.
    pub fn revocation_cut(&self, key: &Name, bound: &CutBound) -> Result<CutProposal, HeapError> {
        self.inner
            .with_logs(|logs| revocation::revocation_cut(logs, &self.inner.judge, key, bound))
    }

    /// Mark `key` suspected since `since`: no new entry of it is taken.
    pub fn suspect(&self, key: &Name, since: Timestamp) -> Result<(), HeapError> {
        self.inner
            .with_logs_mut(|logs| revocation::suspect(logs, key, since))
    }

    /// Lift the mark of `key`. Whether there was one.
    pub fn unsuspect(&self, key: &Name) -> bool {
        self.inner
            .with_logs_mut(|logs| revocation::unsuspect(logs, key))
    }

    /// Since when `key` is marked suspected here.
    pub fn suspected(&self, key: &Name) -> Option<Timestamp> {
        self.inner
            .with_logs(|logs| revocation::suspected(logs, key))
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

/// A space the store holds, opened but not yet joined.
struct Held {
    log: Log,
    follower: bool,
    unclean: bool,
}

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

    pub(crate) fn failure(&self) -> Option<String> {
        self.failed.lock().clone()
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

    fn with_logs_mut<R>(&self, f: impl FnOnce(&mut [&mut Log]) -> R) -> R {
        let spaces = self.sorted();
        let mut guards: Vec<_> = spaces.iter().map(|s| s.log.lock()).collect();
        let mut logs: Vec<&mut Log> = guards.iter_mut().map(|g| &mut **g).collect();
        f(&mut logs)
    }

    /// Mark a key a space's log suspected in every space, from the earliest
    /// time any of them marked it.
    pub(crate) fn suspect_everywhere(&self, key: &Name) {
        let now = Timestamp(self.now());
        self.with_logs_mut(|logs| {
            let since = logs
                .iter()
                .filter_map(|log| log.suspected(key))
                .min()
                .unwrap_or(now);
            let _ = revocation::suspect(logs, key, since);
        });
    }

    /// The person of a device: the namespace of the context that governs it.
    pub(crate) fn person_of(&self, device: &Name) -> Name {
        let keyring = self.judge.validator().keyring();
        keyring
            .unheld_personal_namespace(device)
            .unwrap_or_else(|| keyring.context_for(device).namespace().clone())
    }

    /// Entries held in `space` (every space when it is the root name):
    /// copies, counted from the markers.
    pub(crate) fn held_in(&self, space: &Name) -> u64 {
        let prefix = store::verified_key(&Name::root());
        self.raw
            .scan_under(&prefix, 0)
            .into_iter()
            .filter(|(key, _)| {
                let entry = Name::from_components(key.components()[prefix.len()..].iter().cloned());
                parse_log_name(&entry).is_some_and(|l| space.is_empty() || l.space == *space)
            })
            .count() as u64
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
            space.close_watchers();
        }
    }

    // -- Opening ----------------------------------------------------------------

    /// The log of `space` from the store, and whether the last run left it
    /// without a clean close.
    fn open_log(&self, space: &Name) -> Result<(Log, bool), HeapError> {
        let adopted = store::own_head_from_names(&*self.stage, &self.device, space);
        let reserve = store::read_reserve(&*self.raw, space).map_err(|e| local(e.to_string()))?;
        let head = store::read_head(&*self.raw, space).map_err(|e| local(e.to_string()))?;
        let head_seq = head.map_or(0, |h| h.seq);
        let clean = reserve.is_some_and(|r| r.clean && r.r == head_seq)
            && adopted.as_ref().map_or(0, |h| h.seq) == head_seq;
        let recipient =
            seal::recipient_key(&self.keys, &self.device).map_err(|e| local(e.to_string()))?;
        let log = Log::open(
            Params {
                space: space.clone(),
                device: self.device.clone(),
                person: self.ns.clone(),
                signer: Arc::clone(&self.signer),
                keys: Keys::new(recipient),
                block: self.config.reserve_block,
            },
            Arc::clone(&self.raw),
            Arc::clone(&self.stage),
            Arc::clone(&self.flusher),
        )?;
        Ok((log, !clean))
    }

    /// Hold `space` from now on, and join it.
    async fn attach(
        self: &Arc<Self>,
        space: &Name,
        follower: bool,
    ) -> Result<Arc<SpaceInner>, HeapError> {
        if self.stopped.load(Ordering::Relaxed) {
            return Err(local("the node is stopped"));
        }
        self.stage.insert(
            store::space_key(space),
            Bytes::copy_from_slice(&[if follower { CARRIER } else { MEMBER }]),
        );
        let (log, unclean) = self.open_log(space)?;
        self.judge.note(space, &SpaceInner::listing(&log));
        self.flusher.note_write();
        self.join(Held {
            log,
            follower,
            unclean,
        })
        .await
    }

    /// Join the group of an opened space at its head and take it into the
    /// node; recover own entries from peers after an unclean start.
    async fn join(self: &Arc<Self>, held: Held) -> Result<Arc<SpaceInner>, HeapError> {
        let Held {
            log,
            follower,
            unclean,
        } = held;
        let net = self.net().ok_or_else(|| local("the node is stopped"))?;
        let space = log.space().clone();
        let counter = if follower { 0 } else { log.next_seq() - 1 };
        let group = net.join(&space, counter).await?;
        let publisher = Publisher::spawn(Arc::clone(&self.flusher), group.sink());
        let inner = Arc::new(SpaceInner::new(
            space.clone(),
            log,
            publisher,
            Arc::clone(&group),
            follower,
        ));
        self.spaces.write().insert(space, Arc::clone(&inner));
        if unclean && !follower {
            // Peers known (an entry of another device is held): wait for
            // them before the first publication. Otherwise nothing is waited
            // for; what peers heard later hold of this device's is still
            // fetched and handed to the log.
            let peers = {
                let log = inner.log.lock();
                log.fold().persons().iter().any(|person| {
                    log.held_names(person)
                        .iter()
                        .any(|n| parse_log_name(n).is_some_and(|l| l.device != self.device))
                })
            };
            if peers {
                // The fetching goes on in the group when the wait ends: a
                // start never waits for a network without bound.
                let bound = self.config.settle + self.config.lifetime * 3;
                let _ = rt::timeout(bound, group.recover(self.config.settle)).await;
            } else {
                let group = Arc::clone(&group);
                let settle = self.config.settle;
                rt::spawn(async move {
                    group.recover(settle).await;
                });
            }
        }
        let blobs = inner.unassembled(self);
        if !blobs.is_empty() {
            self.nudge(&inner.name);
        }
        Ok(inner)
    }

    /// Every space the store holds: opened, judged, flushed, joined.
    async fn restore(self: &Arc<Self>) -> Result<(), HeapError> {
        let prefix = store::space_key(&Name::root());
        let mut held = Vec::new();
        for (key, mode) in self.raw.scan_under(&prefix, 0) {
            let space = Name::from_components(key.components()[prefix.len()..].iter().cloned());
            if parse_space_name(&space).is_none() {
                tracing::warn!(%key, "a record of a space that is no space name is ignored");
                continue;
            }
            let (log, unclean) = self.open_log(&space)?;
            held.push(Held {
                log,
                follower: mode.first() == Some(&CARRIER),
                unclean,
            });
        }
        for h in &held {
            self.judge.note(h.log.space(), &SpaceInner::listing(&h.log));
        }
        self.judge.restore().await;
        // A key revoked while the device was off: what it signed is judged
        // again by the contexts held now.
        let revoking: Vec<Name> = self
            .judge
            .validator()
            .keyring()
            .contexts()
            .iter()
            .filter(|ctx| !ctx.revocations().is_empty())
            .map(|ctx| ctx.namespace().clone())
            .collect();
        for h in &mut held {
            let names: Vec<Name> = revoking
                .iter()
                .flat_map(|person| h.log.held_names(person))
                .collect();
            for (device, seq, why) in self.refusals(h.log.space(), names).await {
                let fx = h.log.withdraw(&device, seq, why);
                if fx.membership {
                    self.judge.note(h.log.space(), &SpaceInner::listing(&h.log));
                }
            }
        }
        // What the store holds may be only in the operating system's
        // buffers: it is durable before any of it is published.
        self.flusher.flush().await.map_err(|e| {
            local(format!(
                "the store did not make what it holds durable ({e}); {} publishes only what is \
                 on disk, so it does not start: check the disk or filesystem the store is on, \
                 and start it again",
                self.device
            ))
        })?;
        *self.restored.lock() = held;
        Ok(())
    }

    async fn join_restored(self: &Arc<Self>) -> Result<(), HeapError> {
        let held = std::mem::take(&mut *self.restored.lock());
        let joins = held.into_iter().map(|h| self.join(h));
        for joined in futures::future::join_all(joins).await {
            joined?;
        }
        Ok(())
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
        self.stage.remove(&store::space_key(space));
        self.flusher.note_write();
        if let Some(held) = held {
            held.closing.store(true, Ordering::Relaxed);
            held.close_watchers();
        }
    }

    /// Sign the creation of a new space: its Members entries, then its first
    /// epoch when it is private. Returns after the covering flush.
    async fn sign_creation(
        self: &Arc<Self>,
        space: &Arc<SpaceInner>,
        share: &Share,
    ) -> Result<(), HeapError> {
        let owner = self.ns.clone();
        let mut ops = Vec::new();
        let mut added = std::collections::BTreeSet::new();
        let readers: &[Name] = match &share.readers {
            Readers::Anyone => &[],
            Readers::Persons(persons) => persons,
        };
        for (who, role) in share
            .writers
            .iter()
            .map(|w| (w, Role::Writer))
            .chain(readers.iter().map(|r| (r, Role::Reader)))
        {
            if *who != owner && added.insert((who.clone(), role as u8)) {
                ops.push(Op::Add {
                    id: new_id(),
                    who: who.clone(),
                    role,
                    epoch: None,
                });
            }
        }
        let anyone = matches!(share.readers, Readers::Anyone);
        let mut chunks: Vec<Vec<Op>> = ops
            .chunks(crate::wire::OPS_MAX)
            .map(<[Op]>::to_vec)
            .collect();
        if chunks.is_empty() {
            chunks.push(Vec::new());
        }
        let mut last = None;
        for (i, ops) in chunks.into_iter().enumerate() {
            let create = (i == 0).then_some(anyone);
            let now = self.now();
            last = Some(
                space
                    .sign_with(self, |log| {
                        log.sign_members(
                            MembersBody {
                                create,
                                ops: ops.clone(),
                            },
                            now,
                        )
                    })
                    .await?,
            );
        }
        if let Some(epoch) = space.repair_epoch(self).await? {
            last = Some(epoch);
        }
        if let Some((_, ticket)) = last {
            self.flusher
                .wait_durable(ticket)
                .await
                .map_err(|e| local(e.to_string()))?;
        }
        Ok(())
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
            let Some(wire) = self.stage.get(&name) else {
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
            self.nudge(&space);
        }
    }

    async fn on_adoption(self: &Arc<Self>, event: Adoption) {
        match event {
            Adoption::Context(ctx) => {
                self.with_logs_mut(|logs| {
                    revocation::lift_revoked(logs, revocation::revoked_by(&self.judge))
                });
                let spaces = self.spaces.read().keys().cloned().collect();
                self.rejudge(spaces, std::slice::from_ref(ctx.namespace()))
                    .await;
            }
            Adoption::Person {
                person,
                spaces,
                refuses,
            } => {
                if refuses {
                    self.rejudge(spaces, std::slice::from_ref(&person)).await;
                } else {
                    for space in spaces {
                        self.nudge(&space);
                    }
                }
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
        let why = why.to_string();
        *inner.failed.lock() = Some(why.clone());
        for space in inner.sorted() {
            space.tell(Change::Alert(Alert::StoreFailed { why: why.clone() }));
        }
    }
}

// -- What the network half asks ----------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Host for NodeInner {
    fn device(&self) -> &Name {
        &self.device
    }

    async fn take(&self, space: &Name, wire: Bytes) -> Taken {
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
        let verified = {
            let mut tries = 0;
            loop {
                let generation = self.judge.generation();
                match self.judge.validate(&data, space).await {
                    Judged::Valid(v) if self.judge.generation() != generation && tries < 3 => {
                        tries += 1;
                        let _ = v;
                    }
                    Judged::Valid(v) => break v,
                    Judged::Refused(why) => {
                        held.alert_refused_packet(&data, &why);
                        return refused(why);
                    }
                    Judged::Pending(waiting) => return Taken::Pending(waiting),
                }
            }
        };
        tracing::trace!(target: crate::sync::TIMELINE, "judged");
        let (outcome, blobs, routed) = {
            let mut log = held.log.lock();
            let admitted = log.admit(&wire, &data, &verified, self.now());
            let wrote = !matches!(admitted.outcome, Outcome::Duplicate);
            let blobs = admitted.effects.blobs.clone();
            let routed = held.route(self, &log, admitted.effects, wrote);
            (admitted.outcome, blobs, routed)
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

    fn missing(&self, space: &Name) -> Vec<Want> {
        self.space_of(space)
            .map_or_else(Vec::new, |s| s.log.lock().missing())
    }

    fn high(&self, space: &Name, device: &Name) -> u64 {
        self.space_of(space)
            .map_or(0, |s| s.log.lock().high(device))
    }

    fn head(&self, space: &Name) -> u64 {
        self.space_of(space).map_or(0, |s| s.log.lock().head())
    }

    fn note_counter(&self, space: &Name, device: &Name, seen: u64) {
        let Some(held) = self.space_of(space) else {
            return;
        };
        let routed = {
            let mut log = held.log.lock();
            let fx = log.note_counter(device, seen);
            held.route(self, &log, fx, false)
        };
        held.finish(&self.arc(), routed);
    }

    fn vouched(&self, space: &Name, device: &Name) -> bool {
        self.space_of(space)
            .is_some_and(|s| s.log.lock().vouches(device))
    }

    fn standing(&self, space: &Name, device: &Name) -> Option<bool> {
        let held = self.space_of(space)?;
        let log = held.log.lock();
        log.vouches(device).then(|| log.held_prefix(device) > 0)
    }

    fn served(&self, space: &Name, device: &Name, seq: u64) -> Option<Bytes> {
        let held = self.space_of(space)?;
        if *device == self.device && !held.servable(self, seq) {
            return None;
        }
        held.log.lock().served(device, seq)
    }

    fn served_piece(&self, space: &Name, device: &Name, seq: u64, piece: &Name) -> Option<Bytes> {
        if !piece.has_prefix(&log_name(device, space, seq)) {
            return None;
        }
        self.served(space, device, seq)?;
        self.stage.get(piece)
    }

    fn seal_key_packet(&self, name: &Name) -> Option<Bytes> {
        let (device, public) = parse_seal_key_name(name)?;
        (device == self.device && public == self.seal_public).then(|| self.seal_packet.clone())
    }

    fn blobs(&self, space: &Name) -> Vec<Blob> {
        self.space_of(space)
            .map_or_else(Vec::new, |s| s.unassembled(self))
    }

    fn assembled(&self, space: &Name, blob: &Blob, ops: Vec<StoreOp>, payload: Vec<u8>) {
        if let Some(held) = self.space_of(space) {
            held.assembled(&self.arc(), blob, ops, payload);
        }
    }

    fn owed_keys(&self, space: &Name) -> Vec<EpochId> {
        let Some(held) = self.space_of(space) else {
            return Vec::new();
        };
        if held.follower {
            return Vec::new();
        }
        let log = held.log.lock();
        if !log.sealed() {
            return Vec::new();
        }
        let fold = log.fold();
        let in_force = fold.in_force();
        fold.epochs()
            .into_iter()
            .filter(|e| fold.audience(e).contains(log.person()))
            .filter(|e| log.keys().key(space, e).is_none())
            .filter(|e| log.has_closed() || in_force.as_ref() == Some(e))
            .collect()
    }

    fn seal_public(&self) -> [u8; 32] {
        self.seal_public
    }

    async fn validate_device_packet(&self, space: &Name, data: &Data, device: &Name) -> Judged {
        self.judge.validate_device_packet(data, device, space).await
    }

    fn key_arrived(&self, space: &Name, epoch: &EpochId, name: &Name, content: Bytes) -> bool {
        let Some(held) = self.space_of(space) else {
            return false;
        };
        let (taken, routed) = {
            let mut log = held.log.lock();
            let Some(key) = seal::unwrap_key(log.keys().recipient(), name, content) else {
                return false;
            };
            let (taken, fx) = log.key_arrived(epoch.clone(), key);
            (taken, held.route(self, &log, fx, taken))
        };
        held.finish(&self.arc(), routed);
        taken
    }

    fn may_grant(&self, space: &Name, epoch: &EpochId, asker: &Name) -> Result<(), GrantRefusal> {
        let held = self.space_of(space).ok_or(GrantRefusal::EpochNotNamed)?;
        let person = self.person_of(asker);
        {
            let log = held.log.lock();
            seal::may_grant(
                &Granter {
                    fold: log.fold(),
                    keys: log.keys(),
                    space,
                },
                epoch,
                &person,
            )?;
        }
        if epoch.creator == self.device && !held.servable(self, epoch.seq) {
            return Err(GrantRefusal::EpochNotNamed);
        }
        Ok(())
    }

    fn grant_packet(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes> {
        self.may_grant(space, epoch, asker).ok()?;
        let held = self.space_of(space)?;
        let key = held.log.lock().keys().key(space, epoch)?.clone();
        let packet = seal::grant_packet(to, &key, name, &*self.signer).ok()?;
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Some(packet)
    }
}
