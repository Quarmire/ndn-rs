//! [`Device`]: one device's data layer, the reference implementation of
//! [`DataLayer`] over NDN (`docs/specs/data-layer.md`).
//!
//! A device signs with its own key and publishes only under its own name. It
//! keeps one log (its key's sequence of entries: versions, members records,
//! snapshots) and, per namespace it writes into, a nested summary of that log
//! (`docs/specs/data-layer.md` §7). It learns what others wrote from their summaries: State
//! Vector Sync in the namespace's group (`<namespace>/32=sync`) only says
//! that a writer moved; the reader then fetches the writer's signed root,
//! descends by digest into the branches it follows that changed, and fetches
//! the log entries those name. A descent always finishes against the root it
//! started from (the writer serves every node any root it signed listed), so
//! a writer that keeps putting never makes a reader start over. Every entry
//! is verified by the device's validator, admitted against the collection's
//! members record, and applied by the collection's merge rule once its
//! parents are applied.
//!
//! What a device follows: every collection or folder it has put into, read or
//! watched. Nothing about correctness depends on a clock or on timing: a
//! timeout only delays an answer, and an answer from older data says how old
//! it may be.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use futures::future::BoxFuture;
#[cfg(target_arch = "wasm32")]
use futures::future::LocalBoxFuture as BoxFuture;
use futures::stream::{self, StreamExt};
use ndn_app::{Connection, Consumer, Node, Responder, ServeGuard};
use ndn_foundation_types::Hash;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_security::safe_data::TrustPath;
use ndn_security::{SecurityManager, Signer, ValidationResult, Validator};
use ndn_sync::{DataStore, MultiSvs, SvsConfig, SyncUpdate, spawn_multi_svs};
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::collection::{Child, Members, Rule, Summary};
use crate::error::{DataError, Refusal};
use crate::layer::{Age, Answer, Change, Changes, DataLayer, Got, Hold, PutOptions, State};
use crate::merge::{MergeRule, MergeRules, MergeState};
use crate::rt::{self, Instant};
use crate::statement::{Custody, Snapshot};
use crate::tree::{Entry, Tree};
use crate::version::{
    Content, Frontier, Payload, Seal, Seq, Timestamp, Version, VersionId, Writer,
};
use crate::wire::{
    self, Branches, MembersBody, NodeBody, Record, VersionBody, device_of, group_name,
    is_collection_name, log_name, namespace_of, node_name, page_name, parse_log_name,
    parse_state_name, parse_summary_name, seqs_of, state_name, summary_prefix,
};

/// A wall clock: the date a device's clock shows. Display and retention
/// only; no decision of the layer reads it.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// A signed summary root is never fresh in a cache: discovery (`MustBeFresh`)
/// always reaches its writer, so a notice that the writer moved is never
/// answered by the root it moved from.
const ROOT_FRESHNESS: Duration = Duration::ZERO;

/// A device's settings. Everything here is performance; none of it changes
/// what a verb answers once the network has delivered.
#[derive(Clone)]
pub struct Config {
    /// State Vector Sync settings for every group the device joins.
    pub svs: SvsConfig,
    /// The merge functions the device can run.
    pub rules: MergeRules,
    /// The device's wall clock, for the dates it writes.
    pub clock: Clock,
    /// Interest lifetime of every fetch.
    pub lifetime: Duration,
    /// How long `get`, `put` and `watch` wait for a first look at a
    /// collection the device has not seen before.
    pub first_look: Duration,
    /// Fetches in flight at once.
    pub window: usize,
}

impl Config {
    /// Defaults: SVS's reference timing, the standard merge rules, the
    /// system clock, 2 s Interests, a 4 s first look, 32 fetches in flight.
    pub fn new() -> Self {
        Self {
            svs: SvsConfig::default(),
            rules: MergeRules::standard(),
            clock: Arc::new(|| {
                let since = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default();
                Timestamp(since.as_millis() as u64)
            }),
            lifetime: Duration::from_secs(2),
            first_look: Duration::from_secs(4),
            window: 32,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("svs", &self.svs)
            .field("rules", &self.rules)
            .field("lifetime", &self.lifetime)
            .field("first_look", &self.first_look)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

/// How a device reaches its forwarder: a [`Node`] for fetching and serving,
/// and a second, raw connection that carries State Vector Sync.
pub struct Transport {
    /// Fetches and the device's own prefix.
    pub node: Node,
    /// Sync Interests of every group the device joins.
    pub sync: Arc<dyn Connection>,
}

/// One device's data layer. Cheap to clone; every clone is the same device.
#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
}

struct HeldVersion {
    version: Version,
    op: Bytes,
    wire: Bytes,
}

/// One collection as this device knows it.
#[derive(Default)]
struct Coll {
    /// The newest members record accepted.
    members: Option<Members>,
    /// The merge state, once the rule is known and this device runs it.
    state: Option<Box<dyn MergeState>>,
    /// Every admitted version held, applied or waiting for its parents.
    versions: BTreeMap<VersionId, Arc<HeldVersion>>,
    /// Per writer, the highest seq applied (a prefix of its entries).
    applied: BTreeMap<Writer, u64>,
    /// Per writer, every version seq this device knows it wrote here.
    entries: HashMap<Writer, BTreeSet<u64>>,
    /// Admitted, not yet applied.
    pending: BTreeSet<VersionId>,
    /// Held while no members record is known (or the rule is not one this
    /// device runs).
    waiting: Vec<Arc<HeldVersion>>,
    /// Held but refused: their keys are not writers of the newest members
    /// record. A later revision that admits their keys admits them.
    outsiders: Vec<Arc<HeldVersion>>,
}

impl Coll {
    fn at(&self) -> Frontier {
        self.applied
            .iter()
            .map(|(w, s)| VersionId {
                writer: w.clone(),
                seq: Seq(*s),
            })
            .collect()
    }
}

/// What a held log entry is.
enum Held {
    Version(VersionId),
    Members,
    Snapshot(Snapshot),
}

/// What this device knows of another device's summary of one namespace.
#[derive(Default)]
struct Peer {
    /// The highest head verified (summaries never go back).
    head: u64,
    /// The head of the root kept in the store, so the rollback check
    /// survives a restart.
    kept: u64,
    /// The root last processed in full.
    root: Option<[u8; 32]>,
    /// Nodes and pages processed in full, by subject and page path.
    nodes: HashMap<(Name, Option<Bytes>), [u8; 32]>,
}

struct Group {
    /// The group's publish channel, once joined.
    tx: Option<mpsc::Sender<(Name, Option<Bytes>)>>,
    /// Publications made before the join completed.
    owed: u64,
    /// Devices heard in the group.
    members: BTreeSet<Name>,
    /// Devices being refreshed, and whether to refresh again after.
    busy: HashMap<Name, bool>,
    /// When the device last knew nothing newer was outstanding.
    confirmed: Option<Instant>,
}

struct Watcher {
    target: Name,
    since: Frontier,
    tx: mpsc::UnboundedSender<Result<Change, DataError>>,
}

struct SignedRoot {
    content: Bytes,
    wire: Bytes,
}

/// Mutable state, under one lock never held across an await.
struct St {
    head: u64,
    trees: HashMap<Name, Tree>,
    roots: HashMap<Name, SignedRoot>,
    colls: HashMap<Name, Coll>,
    held: HashMap<Name, Held>,
    peers: HashMap<(Name, Name), Peer>,
    groups: HashMap<Name, Group>,
    follows: BTreeSet<Name>,
    watchers: Vec<Watcher>,
    refused: HashMap<Name, Refusal>,
    /// Where applied versions of other writers are kept.
    store: Arc<dyn DataStore>,
}

struct Inner {
    device: Name,
    ns: Name,
    writer: Writer,
    signer: Arc<dyn Signer>,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    node: Node,
    sync: Arc<dyn Connection>,
    store: Arc<dyn DataStore>,
    config: Config,
    svs: MultiSvs,
    st: Mutex<St>,
    progress: Notify,
    slots: Semaphore,
    signatures: AtomicU64,
    started: Instant,
    serving: Mutex<Option<ServeGuard>>,
}

/// Why a summary root was not taken.
#[derive(Debug)]
enum RootRefusal {
    /// Its signature does not verify to a trust anchor.
    NotVerified,
    /// Its name, subject, writer or head do not match each other.
    NotItsName,
    /// Its head is lower than one this device verified or holds before.
    Rollback { head: u64, seen: u64 },
}

fn local(reason: impl Into<String>) -> DataError {
    DataError::Local {
        reason: reason.into(),
    }
}

fn frontier_of(writer: &Writer, head: u64) -> Frontier {
    if head == 0 {
        return Frontier::new();
    }
    [VersionId {
        writer: writer.clone(),
        seq: Seq(head),
    }]
    .into_iter()
    .collect()
}

/// Whether a version is ready to apply: its writer's earlier entries here
/// and its parents are applied.
fn ready(
    entries: &HashMap<Writer, BTreeSet<u64>>,
    applied: &BTreeMap<Writer, u64>,
    v: &Version,
) -> bool {
    let w = &v.id.writer;
    let prev = entries
        .get(w)
        .and_then(|e| e.range(..v.id.seq.0).next_back().copied());
    prev == applied.get(w).copied()
        && v.parents
            .iter()
            .all(|(y, t)| applied.get(y).is_some_and(|a| *a >= t.0))
}

impl St {
    fn inside(&self, subject: &Name) -> bool {
        (1..=subject.len()).any(|n| {
            self.follows.contains(&Name::from_components(
                subject.components()[..n].iter().cloned(),
            ))
        })
    }

    fn toward(&self, subject: &Name) -> bool {
        self.follows
            .range(subject.clone()..)
            .next()
            .is_some_and(|t| t.has_prefix(subject))
    }

    fn page_relevant(&self, subject: &Name, path: &[u8]) -> bool {
        if self.inside(subject) {
            return true;
        }
        self.follows
            .range(subject.clone()..)
            .take_while(|t| t.has_prefix(subject))
            .filter_map(|t| t.components().get(subject.len()))
            .any(|c| {
                path.iter()
                    .enumerate()
                    .all(|(depth, b)| wire::bucket_of(c, depth) == *b)
            })
    }

    fn emit(&mut self, about: &Name, change: &Change, writer: &Writer, seq: u64) {
        self.watchers.retain(|w| !w.tx.is_closed());
        for w in &self.watchers {
            if about.has_prefix(&w.target) && w.since.get(writer).is_none_or(|s| s.0 < seq) {
                let _ = w.tx.send(Ok(change.clone()));
            }
        }
    }

    /// Accept `body`, signed by `signer`, if it is the newest record of its
    /// collection from the collection's owner namespace.
    fn accept_members(
        &mut self,
        body: MembersBody,
        signer: &Writer,
        rules: &MergeRules,
        me: &Writer,
    ) {
        let owner_ns = device_of(signer.key()).and_then(|d| namespace_of(&d));
        if owner_ns.is_none() || owner_ns != namespace_of(&body.collection) {
            tracing::debug!(collection = %body.collection, signer = ?signer, "members record not from the collection's owner; ignored");
            return;
        }
        let c = body.collection.clone();
        let coll = self.colls.entry(c.clone()).or_default();
        let newer = coll
            .members
            .as_ref()
            .is_none_or(|m| (body.revision, signer) > (m.revision.0, &m.owner));
        if !newer {
            return;
        }
        if coll.state.is_none()
            && let Rule::Merge { function } = &body.rule
            && let Some(rule) = rules.get(function)
        {
            coll.state = Some(rule.start(me));
        }
        coll.members = Some(Members {
            collection: c.clone(),
            owner: signer.clone(),
            revision: Seq(body.revision),
            rule: body.rule,
            writers: body.writers,
            readers: body.readers,
            cuts: Vec::new(),
            readmitted: Vec::new(),
        });
        let waiting = std::mem::take(&mut coll.waiting);
        let outsiders = std::mem::take(&mut coll.outsiders);
        for v in waiting.into_iter().chain(outsiders) {
            self.refused.remove(&v.version.name);
            self.admit(v);
        }
    }

    /// Admit a verified version of another writer: hold it until the
    /// members record is known, refuse it if its key is not a member, else
    /// queue it and apply what became ready.
    fn admit(&mut self, hv: Arc<HeldVersion>) {
        let c = hv.version.collection.clone();
        let coll = self.colls.entry(c.clone()).or_default();
        let Some(members) = &coll.members else {
            coll.waiting.push(hv);
            return;
        };
        let key = hv.version.id.writer.key();
        if !members.writers.iter().any(|p| key.has_prefix(p)) {
            tracing::debug!(id = ?hv.version.id, "refused: not a writer of {c}");
            self.refused
                .insert(hv.version.name.clone(), Refusal::NotMember);
            coll.outsiders.push(hv);
            return;
        }
        let Some(state) = &coll.state else {
            // The rule is not one this device runs; the version stays held
            // and `get` says why.
            coll.waiting.push(hv);
            return;
        };
        if let Err(e) = state.check(&hv.version.id.writer, &hv.op) {
            tracing::debug!(id = ?hv.version.id, "refused: {e}");
            self.refused
                .insert(hv.version.name.clone(), Refusal::BadSignature);
            return;
        }
        coll.entries
            .entry(hv.version.id.writer.clone())
            .or_default()
            .insert(hv.version.id.seq.0);
        coll.pending.insert(hv.version.id.clone());
        coll.versions.insert(hv.version.id.clone(), hv);
        self.apply_ready(&c);
    }

    fn apply_ready(&mut self, c: &Name) {
        let St {
            colls,
            watchers,
            refused,
            store,
            ..
        } = self;
        let Some(coll) = colls.get_mut(c) else {
            return;
        };
        let mut applied_now = Vec::new();
        loop {
            let next = coll.pending.iter().find(|id| {
                coll.versions
                    .get(id)
                    .is_some_and(|hv| ready(&coll.entries, &coll.applied, &hv.version))
            });
            let Some(id) = next.cloned() else { break };
            coll.pending.remove(&id);
            let hv = Arc::clone(&coll.versions[&id]);
            let state = coll.state.as_mut().expect("admitted versions have a state");
            match state.apply(&id.writer, &hv.op) {
                Ok(()) => {
                    coll.applied.insert(id.writer.clone(), id.seq.0);
                    applied_now.push(hv);
                }
                Err(e) => {
                    tracing::warn!(?id, "refused: {e}");
                    coll.versions.remove(&id);
                    refused.insert(hv.version.name.clone(), Refusal::BadSignature);
                }
            }
        }
        watchers.retain(|w| !w.tx.is_closed());
        for hv in applied_now {
            store.insert(hv.version.name.clone(), hv.wire.clone());
            let v = &hv.version;
            for w in watchers.iter() {
                if v.collection.has_prefix(&w.target) && !w.since.contains(&v.id) {
                    let _ = w.tx.send(Ok(Change::Version(v.clone())));
                }
            }
        }
    }

    /// The merged value of `c` at exactly `at`, from held versions; `None`
    /// while some version inside `at` is not held.
    fn value_at(
        &self,
        c: &Name,
        at: &Frontier,
        rules: &MergeRules,
        me: &Writer,
    ) -> Option<Content> {
        let coll = self.colls.get(c)?;
        if *at == coll.at() {
            return coll.state.as_ref().map(|s| s.value());
        }
        let Some(Rule::Merge { function }) = coll.members.as_ref().map(|m| &m.rule) else {
            return None;
        };
        let mut state = rules.get(function)?.start(me);
        let mut entries: HashMap<Writer, BTreeSet<u64>> = HashMap::new();
        for (w, t) in at.iter() {
            let known: BTreeSet<u64> = coll.entries.get(w)?.range(..=t.0).copied().collect();
            if !known.contains(&t.0)
                || known.iter().any(|s| {
                    !coll.versions.contains_key(&VersionId {
                        writer: w.clone(),
                        seq: Seq(*s),
                    })
                })
            {
                return None;
            }
            entries.insert(w.clone(), known);
        }
        let mut applied = BTreeMap::new();
        let mut left: Vec<&HeldVersion> = coll
            .versions
            .values()
            .filter(|hv| at.contains(&hv.version.id))
            .map(Arc::as_ref)
            .collect();
        while !left.is_empty() {
            let i = left
                .iter()
                .position(|hv| ready(&entries, &applied, &hv.version))?;
            let hv = left.swap_remove(i);
            state.apply(&hv.version.id.writer, &hv.op).ok()?;
            applied.insert(hv.version.id.writer.clone(), hv.version.id.seq.0);
        }
        Some(state.value())
    }
}

impl Device {
    /// Start the data layer of the device `device` (e.g. `/alice/laptop`):
    /// sign with the key `keys` holds for it, verify with `validator`, keep
    /// what it holds in `store` (and pick up what an earlier run stored there),
    /// serve `device`'s prefix, and join its own namespace's sync group.
    pub async fn start(
        transport: Transport,
        device: Name,
        keys: Arc<SecurityManager>,
        validator: Arc<Validator>,
        store: Arc<dyn DataStore>,
        config: Config,
    ) -> Result<Device, DataError> {
        let identity = keys
            .signing_identity_for(&device)
            .map_err(|e| local(format!("no key to sign as {device}: {e}")))?;
        if device_of(&identity.key).as_ref() != Some(&device) {
            return Err(local(format!(
                "the key that signs for {device} is {}, which is not {device}'s own key; \
                 give the device a key named {device}/KEY/<id>",
                identity.key
            )));
        }
        let ns = namespace_of(&device).ok_or_else(|| local("a device has a name"))?;
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = spawn_multi_svs(device.clone(), out_tx, in_rx);
        let window = config.window.max(1);
        let inner = Arc::new(Inner {
            writer: Writer::new(identity.key.clone()),
            signer: identity.signer,
            device: device.clone(),
            ns: ns.clone(),
            keys,
            validator,
            node: transport.node,
            sync: transport.sync,
            store: Arc::clone(&store),
            config,
            svs,
            st: Mutex::new(St {
                head: 0,
                trees: HashMap::new(),
                roots: HashMap::new(),
                colls: HashMap::new(),
                held: HashMap::new(),
                peers: HashMap::new(),
                groups: HashMap::new(),
                follows: BTreeSet::new(),
                watchers: Vec::new(),
                refused: HashMap::new(),
                store,
            }),
            progress: Notify::new(),
            slots: Semaphore::new(window),
            signatures: AtomicU64::new(0),
            started: Instant::now(),
            serving: Mutex::new(None),
        });
        inner.restore();

        let sync = Arc::clone(&inner.sync);
        rt::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                if sync.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        let sync = Arc::clone(&inner.sync);
        let weak = Arc::downgrade(&inner);
        rt::spawn(async move {
            while let Some(pkt) = sync.recv().await {
                let Some(interest) = bare_interest(pkt) else {
                    continue;
                };
                if let Some(inner) = weak.upgrade() {
                    inner.heard(&interest);
                }
                if in_tx.send(interest.raw().clone()).await.is_err() {
                    break;
                }
            }
        });

        let serving = Arc::downgrade(&inner);
        let guard = inner
            .node
            .serve(device.clone(), move |interest, responder| {
                let inner = serving.upgrade();
                async move {
                    if let Some(inner) = inner {
                        inner.answer(interest, responder).await;
                    }
                }
            })
            .await
            .map_err(|e| local(format!("cannot serve {device}: {e}")))?;
        *inner.serving.lock() = Some(guard);
        inner.join(&ns).await?;
        Ok(Device { inner })
    }

    /// The writer this device signs as: its key.
    pub fn writer(&self) -> &Writer {
        &self.inner.writer
    }

    /// The device's name.
    pub fn name(&self) -> &Name {
        &self.inner.device
    }

    /// Signatures this device has made.
    pub fn signatures(&self) -> u64 {
        self.inner.signatures.load(Ordering::Relaxed)
    }

    /// Versions this device holds: its own and others'.
    pub fn held(&self) -> u64 {
        let st = self.inner.st.lock();
        st.held
            .values()
            .filter(|h| matches!(h, Held::Version(_)))
            .count() as u64
    }

    /// Stop serving and syncing. Watch streams end.
    pub fn shutdown(&self) {
        self.inner.serving.lock().take();
        self.inner.svs.shutdown();
        let mut st = self.inner.st.lock();
        st.watchers.clear();
        st.groups.clear();
    }
}

/// A summary root the store keeps under its discovery name `key`
/// (`<D>/32=summary/<O>`): the highest one verified of `D` for `O`, as
/// `(D, O, head)`.
fn kept_root(key: &Name, wire: &Bytes) -> Option<(Name, Name, u64)> {
    let k = parse_summary_name(key)?;
    if k.head.is_some() || k.page.is_some() {
        return None;
    }
    let data = Data::decode(wire.clone()).ok()?;
    let s = parse_summary_name(&data.name)?;
    if s.device != k.device || s.subject != k.subject || s.page.is_some() {
        return None;
    }
    Some((s.device, s.subject, s.head?))
}

fn bare_interest(pkt: Bytes) -> Option<Interest> {
    let pkt = if pkt.first() == Some(&0x64) {
        ndn_packet::lp::LpPacket::decode(pkt).ok()?.fragment?
    } else {
        pkt
    };
    Interest::decode(pkt).ok()
}

impl Inner {
    fn me(&self) -> &Writer {
        &self.writer
    }

    // ---- boot ---------------------------------------------------------------------------------

    /// Rebuild what the store holds: the own log, others' members records,
    /// snapshots and applied versions (each verified when it was stored),
    /// and the highest summary root verified of each other device per
    /// namespace, so a rolled-back root is still refused. Others' versions
    /// are stored only once applied, so what comes back is a causally
    /// complete prefix of each writer; members records go first.
    fn restore(&self) {
        let mut entries: Vec<(Name, Bytes, Record, Writer, u64, bool)> = Vec::new();
        let mut roots = Vec::new();
        for (name, wire) in self.store.scan_under(&Name::root(), 0) {
            let Some(parsed) = parse_log_name(&name) else {
                roots.extend(kept_root(&name, &wire));
                continue;
            };
            let Ok(data) = Data::decode(wire.clone()) else {
                continue;
            };
            let Some(key) = data.sig_info().and_then(|s| s.key_locator_name()) else {
                continue;
            };
            let Some(record) = data
                .content()
                .and_then(|c| wire::decode_record(c.clone()).ok())
            else {
                continue;
            };
            let mine = parsed.device == self.device;
            entries.push((
                name,
                wire,
                record,
                Writer::new((*key).clone()),
                parsed.seq,
                mine,
            ));
        }
        entries
            .sort_by_key(|(_, _, record, _, seq, _)| (!matches!(record, Record::Members(_)), *seq));
        let mut st = self.st.lock();
        for (name, wire, record, writer, seq, mine) in entries {
            if mine {
                st.head = st.head.max(seq);
            }
            self.take(&mut st, name, wire, writer, record, mine);
        }
        for (device, ns, head) in roots {
            if device != self.device {
                let peer = st.peers.entry((device, ns)).or_default();
                peer.head = peer.head.max(head);
                peer.kept = peer.kept.max(head);
            }
        }
    }

    // ---- sync groups --------------------------------------------------------------------------

    /// Join namespace `ns`'s sync group, once.
    async fn join(self: &Arc<Self>, ns: &Name) -> Result<(), DataError> {
        let local_seq = {
            let mut st = self.st.lock();
            if st.groups.contains_key(ns) {
                return Ok(());
            }
            st.groups.insert(
                ns.clone(),
                Group {
                    tx: None,
                    owed: 0,
                    members: BTreeSet::new(),
                    busy: HashMap::new(),
                    confirmed: None,
                },
            );
            st.head
        };
        let group = group_name(ns);
        self.sync
            .register_prefix(&group)
            .await
            .map_err(|e| local(format!("cannot receive {group}: {e}")))?;
        let cfg = SvsConfig {
            // The group's counter only says "moved"; starting at the log head
            // keeps it above anything an earlier run announced.
            local_seq,
            ..self.config.svs.clone()
        };
        let Some(mut handle) = self.svs.join(group.clone(), cfg).await else {
            return Err(local(format!("the sync driver did not join {group}")));
        };
        let tx = handle.tx.clone();
        let owed = {
            let mut st = self.st.lock();
            let g = st.groups.get_mut(ns).expect("inserted above");
            g.tx = Some(tx.clone());
            std::mem::take(&mut g.owed)
        };
        for _ in 0..owed {
            let _ = tx.send((group.clone(), None)).await;
        }
        let weak = Arc::downgrade(self);
        let ns = ns.clone();
        rt::spawn(async move {
            while let Some(update) = handle.recv().await {
                let Some(inner) = weak.upgrade() else { break };
                inner.on_update(&ns, update);
            }
        });
        Ok(())
    }

    fn heard(&self, interest: &Interest) {
        let mut st = self.st.lock();
        let now = Instant::now();
        for (ns, g) in st.groups.iter_mut() {
            if interest.name.has_prefix(&group_name(ns)) && g.busy.is_empty() {
                g.confirmed = Some(now);
            }
        }
    }

    fn on_update(self: &Arc<Self>, ns: &Name, update: SyncUpdate) {
        let device = update.name;
        tracing::trace!(me = %self.device, %ns, %device, high = update.high_seq, "sync update");
        if device == self.device {
            return;
        }
        if let Some(g) = self.st.lock().groups.get_mut(ns) {
            g.members.insert(device.clone());
        }
        self.schedule(ns.clone(), device);
    }

    /// Refresh `device`'s summary of `ns` in the background, coalescing
    /// requests that arrive while one runs.
    fn schedule(self: &Arc<Self>, ns: Name, device: Name) {
        {
            let mut st = self.st.lock();
            let Some(g) = st.groups.get_mut(&ns) else {
                return;
            };
            if let Some(again) = g.busy.get_mut(&device) {
                *again = true;
                return;
            }
            g.busy.insert(device.clone(), false);
        }
        let inner = Arc::clone(self);
        rt::spawn(async move {
            loop {
                let ok = inner.refresh(&ns, &device).await;
                let mut st = inner.st.lock();
                let Some(g) = st.groups.get_mut(&ns) else {
                    break;
                };
                match g.busy.get_mut(&device) {
                    Some(again) if *again => *again = false,
                    _ => {
                        g.busy.remove(&device);
                        if ok && g.busy.is_empty() {
                            g.confirmed = Some(Instant::now());
                        }
                        break;
                    }
                }
            }
            inner.progress.notify_waiters();
        });
    }

    /// Publish one change into `ns`'s group.
    async fn publish(&self, ns: &Name) {
        let tx = {
            let mut st = self.st.lock();
            let Some(g) = st.groups.get_mut(ns) else {
                return;
            };
            match &g.tx {
                Some(tx) => tx.clone(),
                None => {
                    g.owed += 1;
                    return;
                }
            }
        };
        let _ = tx.send((group_name(ns), None)).await;
    }

    /// Start following `target`: join its namespace's group, and forget
    /// which summaries on the way to it were processed (they were processed
    /// without it). Returns whether it is new.
    async fn follow(self: &Arc<Self>, target: &Name) -> Result<bool, DataError> {
        let ns = namespace_of(target).ok_or_else(|| DataError::NotFound {
            name: target.clone(),
        })?;
        let new = {
            let mut st = self.st.lock();
            let new = st.follows.insert(target.clone());
            if new {
                for ((_, pns), peer) in st.peers.iter_mut() {
                    if *pns == ns {
                        peer.root = None;
                        peer.nodes.retain(|(s, _), _| !target.has_prefix(s));
                    }
                }
            }
            new
        };
        self.join(&ns).await?;
        Ok(new)
    }

    /// Follow `target` and, the first time, look at what every device known
    /// in its group holds of it, for at most the first-look time.
    async fn look(self: &Arc<Self>, target: &Name) -> Result<(), DataError> {
        if !self.follow(target).await? {
            return Ok(());
        }
        let ns = namespace_of(target).expect("followed names have a namespace");
        let devices: Vec<Name> = {
            let st = self.st.lock();
            st.groups
                .get(&ns)
                .map(|g| g.members.iter().cloned().collect())
                .unwrap_or_default()
        };
        let all = futures::future::join_all(devices.iter().map(|d| self.refresh(&ns, d)));
        let _ = rt::timeout(self.config.first_look, all).await;
        Ok(())
    }

    /// Wait until `done` holds or the first-look time passes.
    async fn wait_for(&self, mut done: impl FnMut(&St) -> bool) -> bool {
        let deadline = Instant::now() + self.config.first_look;
        loop {
            let notified = self.progress.notified();
            if done(&self.st.lock()) {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let _ = rt::timeout(left, notified).await;
        }
    }

    /// Refresh in the background every device known in `ns`'s group.
    fn refresh_group(self: &Arc<Self>, ns: &Name) {
        let devices: Vec<Name> = {
            let st = self.st.lock();
            st.groups
                .get(ns)
                .map(|g| g.members.iter().cloned().collect())
                .unwrap_or_default()
        };
        for d in devices {
            self.schedule(ns.clone(), d);
        }
    }

    // ---- fetching -----------------------------------------------------------------------------

    /// Fetch `name`; `None` if nothing answered in time or the network said
    /// no.
    async fn fetch(&self, name: Name, discover: bool) -> Option<Data> {
        let _slot = self.slots.acquire().await.ok()?;
        let mut b = InterestBuilder::new(name).lifetime(self.config.lifetime);
        if discover {
            b = b.can_be_prefix().must_be_fresh();
        }
        match Consumer::new(self.node.connection()).fetch_with(b).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::trace!(me = %self.device, "fetch missed: {e}");
                None
            }
        }
    }

    /// Verify a key-signed packet with the device's validator, walking its
    /// certificate chain to a trust anchor (fetching missing certificates
    /// through the validator's fetcher, if it has one); returns its signer.
    /// A packet that does not verify is not kept as refused: the same name
    /// may verify when fetched from another holder, or once a certificate
    /// arrives.
    async fn verify(&self, data: &Data) -> Result<Writer, Refusal> {
        let key = data
            .sig_info()
            .and_then(|s| s.key_locator_name())
            .ok_or(Refusal::BadSignature)?;
        match self.validator.validate_chain(data).await {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) =>
            {
                Ok(Writer::new((*key).clone()))
            }
            other => {
                tracing::debug!(name = %data.name, "not verified: {other:?}");
                Err(Refusal::BadSignature)
            }
        }
    }

    /// Take `data` as `device`'s signed summary root of `ns`: verify it,
    /// check it against its name, and refuse it if its head is lower than
    /// one verified (or an entry held) of that writer before — kept in the
    /// store, so a restart does not forget it.
    async fn accept_root(
        &self,
        device: &Name,
        ns: &Name,
        data: &Data,
    ) -> Result<(Writer, NodeBody), RootRefusal> {
        let writer = self
            .verify(data)
            .await
            .map_err(|_| RootRefusal::NotVerified)?;
        let body = data
            .content()
            .and_then(|c| wire::decode_node(c.clone()).ok())
            .ok_or(RootRefusal::NotItsName)?;
        let named = parse_summary_name(&data.name);
        if device_of(writer.key()).as_ref() != Some(device)
            || body.subject != *ns
            || body.writer != *writer.key()
            || body.page.is_some()
            || named.as_ref().map(|n| (&n.device, &n.subject, n.head))
                != Some((device, ns, Some(body.head)))
        {
            return Err(RootRefusal::NotItsName);
        }
        let mut st = self.st.lock();
        let peer = st.peers.entry((device.clone(), ns.clone())).or_default();
        if body.head < peer.head {
            return Err(RootRefusal::Rollback {
                head: body.head,
                seen: peer.head,
            });
        }
        peer.head = body.head;
        if body.head > peer.kept {
            peer.kept = body.head;
            self.store
                .insert(summary_prefix(device, ns), data.raw().clone());
        }
        Ok((writer, body))
    }

    /// Refresh `device`'s summary of `ns`: fetch its signed root and descend
    /// it, to the end, into what this device follows. A writer that moved
    /// meanwhile is refreshed again from its newer root, which skips every
    /// branch processed in full here. Returns whether it completed.
    async fn refresh(self: &Arc<Self>, ns: &Name, device: &Name) -> bool {
        if !self.st.lock().toward(ns) {
            return true;
        }
        tracing::trace!(me = %self.device, %ns, %device, "refresh");
        let Some(data) = self.fetch(summary_prefix(device, ns), true).await else {
            return false;
        };
        let (writer, body) = match self.accept_root(device, ns, &data).await {
            Ok(taken) => taken,
            Err(RootRefusal::Rollback { head, seen }) => {
                tracing::warn!(%device, %ns, head, seen, "refused: a summary root older than one verified before (rollback); the writer must serve its newest root");
                return false;
            }
            Err(why) => {
                tracing::debug!(name = %data.name, ?why, "refused: summary root");
                return false;
            }
        };
        let digest = wire::implicit_digest(data.raw());
        let key = (device.clone(), ns.clone());
        if self.st.lock().peers.get(&key).and_then(|p| p.root) == Some(digest) {
            return true;
        }
        if !self.descend(device, &writer, body).await {
            return false;
        }
        self.st.lock().peers.entry(key).or_default().root = Some(digest);
        true
    }

    /// Process a verified node (or page) of `writer`'s summary, published by
    /// `device`: its entries if followed, then its changed, relevant branches.
    /// Returns whether all of it was processed; what was is kept, so the next
    /// descent, from this root or a newer one, does not fetch it again.
    fn descend<'a>(
        self: &'a Arc<Self>,
        device: &'a Name,
        writer: &'a Writer,
        body: NodeBody,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let subject = body.subject.clone();
            let path = body.page.clone().unwrap_or_default();
            // Entries, for a followed collection.
            let mut wanted = Vec::new();
            let (children, pages) = {
                let mut st = self.st.lock();
                let inside = st.inside(&subject);
                if body.page.is_none() && inside {
                    let coll = st.colls.entry(subject.clone()).or_default();
                    coll.entries
                        .entry(writer.clone())
                        .or_default()
                        .extend(seqs_of(&body.entries));
                    for seq in seqs_of(&body.members).chain(seqs_of(&body.entries)) {
                        let name = log_name(device, Some(&subject), seq);
                        if !st.held.contains_key(&name) && !st.refused.contains_key(&name) {
                            wanted.push(name);
                        }
                    }
                    // Learned entries may make held versions ready.
                    st.apply_ready(&subject);
                    let summary = Summary {
                        collection: subject.clone(),
                        signer: writer.clone(),
                        frontier: frontier_of(writer, body.head),
                        children: match &body.branches {
                            Branches::Children(c) => c
                                .iter()
                                .map(|c| Child {
                                    name: subject.clone().append_component(c.component.clone()),
                                    digest: Hash::from_bytes(c.digest),
                                })
                                .collect(),
                            Branches::Pages(_) => Vec::new(),
                        },
                    };
                    st.emit(&subject, &Change::Summary(summary), writer, body.head);
                }
                let ns = namespace_of(&subject).unwrap_or_else(Name::root);
                let seen = |st: &St, key: &(Name, Option<Bytes>), digest: &[u8; 32]| {
                    st.peers
                        .get(&(device.clone(), ns.clone()))
                        .and_then(|p| p.nodes.get(key))
                        == Some(digest)
                };
                match &body.branches {
                    Branches::Children(list) => {
                        let picked: Vec<_> = list
                            .iter()
                            .filter(|c| {
                                let sub = subject.clone().append_component(c.component.clone());
                                (st.inside(&sub) || st.toward(&sub))
                                    && !seen(&st, &(sub, None), &c.digest)
                            })
                            .cloned()
                            .collect();
                        (picked, Vec::new())
                    }
                    Branches::Pages(list) => {
                        let picked: Vec<_> = list
                            .iter()
                            .filter(|p| {
                                let mut sub = path.to_vec();
                                sub.push(p.bucket);
                                st.page_relevant(&subject, &sub)
                                    && !seen(
                                        &st,
                                        &(subject.clone(), Some(Bytes::from(sub))),
                                        &p.digest,
                                    )
                            })
                            .cloned()
                            .collect();
                        (Vec::new(), picked)
                    }
                }
            };

            let fetched = stream::iter(wanted)
                .map(|name| async move { self.take_fetched(name).await })
                .buffer_unordered(self.config.window)
                .collect::<Vec<_>>()
                .await;
            let entries_taken = fetched.iter().all(|ok| *ok);

            let ns = namespace_of(&subject).unwrap_or_else(Name::root);
            let branch_results = stream::iter(
                children
                    .into_iter()
                    .map(|c| {
                        let sub = subject.clone().append_component(c.component.clone());
                        (
                            node_name(device, &sub, c.head),
                            (sub, None),
                            c.digest,
                            c.head,
                        )
                    })
                    .chain(pages.into_iter().map(|p| {
                        let mut sub = path.to_vec();
                        sub.push(p.bucket);
                        let sub = Bytes::from(sub);
                        (
                            page_name(device, &subject, &sub, p.head),
                            (subject.clone(), Some(sub)),
                            p.digest,
                            p.head,
                        )
                    })),
            )
            .map(|(name, key, digest, head)| {
                let ns = ns.clone();
                async move {
                    // The writer serves every node any root it signed lists
                    // (§7): a miss is the network's, and what was processed
                    // is kept for the next descent.
                    let data = self.fetch(name.clone(), false).await?;
                    if wire::implicit_digest(data.raw()) != digest {
                        tracing::debug!(%name, "not the packet its parent lists; ignored");
                        return None;
                    }
                    let child = data
                        .content()
                        .and_then(|c| wire::decode_node(c.clone()).ok())?;
                    if child.subject != key.0
                        || child.writer != *writer.key()
                        || child.head != head
                        || child.page != key.1
                    {
                        tracing::debug!(%name, "a summary node that does not match its name; ignored");
                        return None;
                    }
                    if !self.descend(device, writer, child).await {
                        return None;
                    }
                    self.st
                        .lock()
                        .peers
                        .entry((device.clone(), ns))
                        .or_default()
                        .nodes
                        .insert(key, digest);
                    Some(())
                }
            })
            .buffer_unordered(self.config.window)
            .collect::<Vec<_>>()
            .await;
            entries_taken && branch_results.iter().all(Option::is_some)
        })
    }

    /// Fetch, verify and take one log entry; whether it is now held or refused.
    async fn take_fetched(self: &Arc<Self>, name: Name) -> bool {
        let Some(data) = self.fetch(name.clone(), false).await else {
            return false;
        };
        self.take_data(&name, data).await.is_ok()
    }

    /// Verify and take a fetched log entry named `name`.
    async fn take_data(self: &Arc<Self>, name: &Name, data: Data) -> Result<(), Refusal> {
        let refuse = |st: &mut St, why: Refusal| {
            st.refused.insert(name.clone(), why.clone());
            Err(why)
        };
        let parsed = parse_log_name(name).ok_or(Refusal::BadSignature)?;
        if *data.name != *name {
            return Err(Refusal::BadSignature);
        }
        let writer = match self.verify(&data).await {
            Ok(w) => w,
            Err(why) => return Err(why),
        };
        let record = data
            .content()
            .and_then(|c| wire::decode_record(c.clone()).ok());
        let mut st = self.st.lock();
        let Some(record) = record else {
            return refuse(&mut st, Refusal::BadSignature);
        };
        let subject_ok = match &record {
            Record::Version(b) => parsed.subject.as_ref() == Some(&b.collection),
            Record::Members(b) => parsed.subject.as_ref() == Some(&b.collection),
            Record::Snapshot(_) => parsed.subject.is_none(),
        };
        if device_of(writer.key()).as_ref() != Some(&parsed.device) || !subject_ok {
            return refuse(&mut st, Refusal::BadSignature);
        }
        self.take(
            &mut st,
            name.clone(),
            data.raw().clone(),
            writer,
            record,
            false,
        );
        Ok(())
    }

    /// Hold a verified log entry and let its collection take it. Members
    /// records, snapshots and own entries are stored now; others' versions
    /// once applied.
    fn take(
        &self,
        st: &mut St,
        name: Name,
        wire: Bytes,
        writer: Writer,
        record: Record,
        mine: bool,
    ) {
        if let Some(Held::Version(id)) = st.held.get(&name) {
            if let Record::Version(body) = &record
                && let Some(first) = st
                    .colls
                    .get(&body.collection)
                    .and_then(|c| c.versions.get(id))
                && first.wire != wire
            {
                let change = Change::Equivocation {
                    first: Box::new(first.version.clone()),
                    second: Box::new(version_of(&name, &writer, id.seq.0, body.clone())),
                };
                let seq = id.seq.0;
                st.emit(&body.collection, &change, &writer, seq.saturating_sub(1));
            }
            return;
        }
        if st.held.contains_key(&name) {
            return;
        }
        let Some(parsed) = parse_log_name(&name) else {
            return;
        };
        if mine || !matches!(record, Record::Version(_)) {
            self.store.insert(name.clone(), wire.clone());
        }
        match record {
            Record::Members(body) => {
                st.held.insert(name.clone(), Held::Members);
                let c = body.collection.clone();
                if mine {
                    st.trees
                        .entry(namespace_of(&c).expect("a collection has a namespace"))
                        .or_insert_with(|| Tree::new(namespace_of(&c).expect("namespace")))
                        .add(&c, parsed.seq, Entry::Members);
                } else {
                    self.note_peer_head(st, &parsed.device, &c, parsed.seq);
                }
                st.accept_members(body, &writer, &self.config.rules, self.me());
            }
            Record::Version(body) => {
                let c = body.collection.clone();
                let op = body.op.clone();
                let version = version_of(&name, &writer, parsed.seq, body);
                st.held
                    .insert(name.clone(), Held::Version(version.id.clone()));
                if mine {
                    st.trees
                        .entry(namespace_of(&c).expect("a collection has a namespace"))
                        .or_insert_with(|| Tree::new(namespace_of(&c).expect("namespace")))
                        .add(&c, parsed.seq, Entry::Version);
                } else {
                    self.note_peer_head(st, &parsed.device, &c, parsed.seq);
                }
                st.admit(Arc::new(HeldVersion { version, op, wire }));
            }
            Record::Snapshot(pins) => {
                let snapshot = Snapshot {
                    id: VersionId {
                        writer,
                        seq: Seq(parsed.seq),
                    },
                    name: name.clone(),
                    pins,
                };
                st.held.insert(name, Held::Snapshot(snapshot));
            }
        }
    }

    /// A held entry bounds the head of its writer's summary from below.
    fn note_peer_head(&self, st: &mut St, device: &Name, collection: &Name, seq: u64) {
        if let Some(ns) = namespace_of(collection) {
            let peer = st.peers.entry((device.clone(), ns)).or_default();
            peer.head = peer.head.max(seq);
        }
    }

    // ---- own writes ---------------------------------------------------------------------------

    /// Sign a packet with the device key.
    fn sign(&self, builder: DataBuilder) -> Result<Bytes, DataError> {
        let key = self.writer.key().clone();
        let mut failed = None;
        let wire = builder.sign_sync(self.signer.sig_type(), Some(&key), |region| {
            match self.signer.sign_sync(region) {
                Ok(sig) => sig,
                Err(e) => {
                    failed = Some(e);
                    Bytes::new()
                }
            }
        });
        if let Some(e) = failed {
            return Err(local(format!(
                "the device key {key} did not sign ({e}); the data layer needs a key that signs \
                 synchronously"
            )));
        }
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Ok(wire)
    }

    /// Append an entry about `subject` to the own log: sign, store, take.
    fn append(
        &self,
        st: &mut St,
        subject: Option<&Name>,
        content: Bytes,
    ) -> Result<(Name, u64), DataError> {
        let record = wire::decode_record(content.clone()).map_err(|e| local(e.to_string()))?;
        let seq = st.head + 1;
        let name = log_name(&self.device, subject, seq);
        let wire = self.sign(DataBuilder::new(name.clone(), &content))?;
        st.head = seq;
        self.take(st, name.clone(), wire, self.writer.clone(), record, true);
        Ok((name, seq))
    }

    /// The host default for a collection of this device's own namespace that
    /// nobody shared: merge with `/merge/yrs`, written and read by the owner.
    fn default_members(&self, c: &Name) -> MembersBody {
        MembersBody {
            collection: c.clone(),
            revision: 1,
            rule: Rule::Merge {
                function: crate::merge::Yrs::new().function().clone(),
            },
            writers: vec![self.ns.clone()],
            readers: vec![crate::Audience::Person(self.ns.clone())],
        }
    }

    // ---- serving ------------------------------------------------------------------------------

    async fn answer(self: Arc<Self>, interest: Interest, responder: Responder) {
        let name = (*interest.name).clone();
        let reply = self.packet_for(&name, interest.selectors().can_be_prefix);
        tracing::trace!(me = %self.device, %name, answered = reply.is_some(), "interest");
        let sent = match reply {
            Some(wire) => responder.respond_bytes(wire).await,
            None => responder.nack(NackReason::NoRoute).await,
        };
        if let Err(e) = sent {
            tracing::debug!(me = %self.device, %name, "reply not sent: {e}");
        }
    }

    fn packet_for(&self, name: &Name, can_be_prefix: bool) -> Option<Bytes> {
        if let Some(parsed) = parse_log_name(name)
            && parsed.device == self.device
        {
            return self.store.get(name);
        }
        if let Some(s) = parse_summary_name(name)
            && s.device == self.device
        {
            let mut st = self.st.lock();
            let ns = namespace_of(&s.subject)?;
            if s.subject == ns && s.page.is_none() {
                if s.head.is_none() && !can_be_prefix {
                    return None;
                }
                let root = self.root(&mut st, &ns)?;
                let head = st.trees.get(&ns).map_or(0, Tree::head);
                return s.head.is_none_or(|h| h == head).then_some(root);
            }
            let head = s.head?;
            let tree = st.trees.get_mut(&ns)?;
            return tree.packet(
                &self.device,
                self.writer.key(),
                &s.subject,
                s.page.as_ref(),
                head,
                name,
            );
        }
        let keys = self.device.clone().append("KEY");
        if name.has_prefix(&keys) {
            return self
                .keys
                .cert_cache()
                .get_valid(name)
                .and_then(|c| c.data_wire());
        }
        None
    }

    /// The signed root of the own summary of `ns`, signing a new one only
    /// when it changed since the last.
    fn root(&self, st: &mut St, ns: &Name) -> Option<Bytes> {
        let tree = st
            .trees
            .entry(ns.clone())
            .or_insert_with(|| Tree::new(ns.clone()));
        let content = tree.build(&self.device, self.writer.key());
        let head = tree.head();
        if let Some(r) = st.roots.get(ns)
            && r.content == content
        {
            return Some(r.wire.clone());
        }
        let builder =
            DataBuilder::new(node_name(&self.device, ns, head), &content).freshness(ROOT_FRESHNESS);
        let wire = self.sign(builder).ok()?;
        st.roots.insert(
            ns.clone(),
            SignedRoot {
                content,
                wire: wire.clone(),
            },
        );
        Some(wire)
    }

    // ---- answers ------------------------------------------------------------------------------

    fn age(&self, st: &St, c: &Name) -> Age {
        let confirmed = namespace_of(c)
            .and_then(|ns| st.groups.get(&ns))
            .and_then(|g| g.confirmed)
            .unwrap_or(self.started);
        Age::Newest {
            unconfirmed_for: Instant::now().saturating_duration_since(confirmed),
        }
    }

    /// The state of merge collection `c` now, or why there is none.
    fn state_now(&self, st: &St, c: &Name) -> Result<State, DataError> {
        let Some(coll) = st.colls.get(c) else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        let Some(members) = &coll.members else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        let Rule::Merge { function } = &members.rule else {
            return Err(local(format!(
                "{c} uses the {:?} rule; this device implements the merge rule only (the log \
                 rule is data-layer slice 2, one key slice 4)",
                members.rule
            )));
        };
        let Some(state) = &coll.state else {
            return Err(local(format!(
                "{c} merges with {function}, which this device does not run"
            )));
        };
        let at = coll.at();
        Ok(State {
            name: state_name(c, &at),
            collection: c.clone(),
            at,
            value: state.value(),
        })
    }

    async fn get_log_entry(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let answer = |st: &St| -> Option<Result<Answer, DataError>> {
            if let Some(why) = st.refused.get(name) {
                return Some(Err(refused(name, why.clone())));
            }
            Some(match st.held.get(name)? {
                Held::Snapshot(s) => Ok(Answer {
                    got: Got::Snapshot(s.clone()),
                    age: Age::Exact,
                }),
                Held::Version(id) => {
                    let parsed = parse_log_name(name)?;
                    let c = parsed.subject?;
                    let v = st.colls.get(&c)?.versions.get(id)?;
                    Ok(Answer {
                        got: Got::Version(v.version.clone()),
                        age: Age::Exact,
                    })
                }
                Held::Members => Err(DataError::NotFound { name: name.clone() }),
            })
        };
        if let Some(a) = answer(&self.st.lock()) {
            return a;
        }
        let parsed =
            parse_log_name(name).ok_or_else(|| DataError::NotFound { name: name.clone() })?;
        if let Some(c) = &parsed.subject {
            self.look(c).await?;
        }
        if let Some(a) = answer(&self.st.lock()) {
            return a;
        }
        let data = self
            .fetch(name.clone(), false)
            .await
            .ok_or_else(|| DataError::Unavailable { name: name.clone() })?;
        self.take_data(name, data)
            .await
            .map_err(|why| refused(name, why))?;
        if let Some(c) = &parsed.subject {
            let c = c.clone();
            self.wait_for(|st| st.colls.get(&c).is_some_and(|coll| coll.members.is_some()))
                .await;
        }
        answer(&self.st.lock())
            .unwrap_or_else(|| Err(DataError::Unavailable { name: name.clone() }))
    }
}

fn refused(name: &Name, why: Refusal) -> DataError {
    let id = parse_log_name(name)
        .map(|p| VersionId {
            writer: Writer::new(p.device),
            seq: Seq(p.seq),
        })
        .unwrap_or(VersionId {
            writer: Writer::new(name.clone()),
            seq: Seq(0),
        });
    DataError::Refused { id, why }
}

fn version_of(name: &Name, writer: &Writer, seq: u64, body: VersionBody) -> Version {
    Version {
        id: VersionId {
            writer: writer.clone(),
            seq: Seq(seq),
        },
        name: name.clone(),
        collection: body.collection,
        parents: body.parents,
        type_id: body.type_id,
        seal: body.seal,
        keep: body.keep,
        dated: body.dated,
        payload: Payload::Entry(body.fields),
    }
}

fn check_collection(c: &Name) -> Result<(), DataError> {
    if is_collection_name(c) {
        Ok(())
    } else {
        Err(DataError::NotFound { name: c.clone() })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl DataLayer for Device {
    async fn get(&self, name: &Name) -> Result<Answer, DataError> {
        let inner = &self.inner;
        if let Some((c, at)) = parse_state_name(name) {
            inner.look(&c).await?;
            let rules = inner.config.rules.clone();
            let me = inner.writer.clone();
            let value = |st: &St| st.value_at(&c, &at, &rules, &me);
            if !inner.wait_for(|st| value(st).is_some()).await {
                return Err(DataError::Unavailable { name: name.clone() });
            }
            let st = inner.st.lock();
            let value = value(&st).ok_or_else(|| DataError::Unavailable { name: name.clone() })?;
            return Ok(Answer {
                got: Got::State(State {
                    name: name.clone(),
                    collection: c,
                    at,
                    value,
                }),
                age: Age::Exact,
            });
        }
        if parse_log_name(name).is_some() {
            return inner.get_log_entry(name).await;
        }
        check_collection(name)?;
        inner.look(name).await?;
        let st = inner.st.lock();
        let state = inner.state_now(&st, name)?;
        Ok(Answer {
            age: inner.age(&st, name),
            got: Got::State(state),
        })
    }

    async fn put(
        &self,
        collection: &Name,
        content: Content,
        options: PutOptions,
    ) -> Result<VersionId, DataError> {
        let inner = &self.inner;
        check_collection(collection)?;
        if options.batch.is_some() {
            return Err(local(
                "batching entries into signed blocks is data-layer slice 4; this device signs \
                 each version alone (put with batch: None)",
            ));
        }
        let ns = namespace_of(collection).expect("checked above");
        inner.look(collection).await?;
        if ns != inner.ns {
            let c = collection.clone();
            inner
                .wait_for(|st| st.colls.get(&c).is_some_and(|coll| coll.members.is_some()))
                .await;
        }
        let id = {
            let mut st = inner.st.lock();
            if st.colls.get(collection).is_none_or(|c| c.members.is_none()) {
                if ns != inner.ns {
                    let heard = st.groups.get(&ns).is_some_and(|g| !g.members.is_empty());
                    return Err(if heard {
                        DataError::NotAllowed {
                            collection: collection.clone(),
                            writer: inner.writer.clone(),
                        }
                    } else {
                        DataError::Unavailable {
                            name: collection.clone(),
                        }
                    });
                }
                let body = inner.default_members(collection);
                inner.append(&mut st, Some(collection), wire::encode_members(&body))?;
            }
            let coll = st.colls.get_mut(collection).expect("members known");
            let members = coll.members.as_ref().expect("members known");
            if !members
                .writers
                .iter()
                .any(|p| inner.writer.key().has_prefix(p))
            {
                return Err(DataError::NotAllowed {
                    collection: collection.clone(),
                    writer: inner.writer.clone(),
                });
            }
            let seal = Seal {
                any_of: members.readers.clone(),
            };
            let parents = coll.at();
            let Some(state) = coll.state.as_mut() else {
                drop(st);
                let st = inner.st.lock();
                return Err(inner.state_now(&st, collection).err().unwrap_or_else(|| {
                    local(format!("{collection} has no merge state on this device"))
                }));
            };
            let op = state.edit(&content).map_err(|e| local(e.to_string()))?;
            let body = VersionBody {
                collection: collection.clone(),
                parents,
                type_id: options.type_id,
                seal,
                keep: options.keep,
                dated: (inner.config.clock)(),
                fields: content,
                op: op.clone(),
            };
            let seq = st.head + 1;
            let name = log_name(&inner.device, Some(collection), seq);
            let wire = inner.sign(DataBuilder::new(name.clone(), &wire::encode_version(&body)))?;
            st.head = seq;
            let version = version_of(&name, &inner.writer, seq, body);
            let id = version.id.clone();
            inner.store.insert(name.clone(), wire.clone());
            st.held.insert(name, Held::Version(id.clone()));
            st.trees
                .entry(ns.clone())
                .or_insert_with(|| Tree::new(ns.clone()))
                .add(collection, seq, Entry::Version);
            let coll = st.colls.get_mut(collection).expect("members known");
            coll.entries
                .entry(id.writer.clone())
                .or_default()
                .insert(seq);
            coll.applied.insert(id.writer.clone(), seq);
            coll.versions.insert(
                id.clone(),
                Arc::new(HeldVersion {
                    version: version.clone(),
                    op,
                    wire,
                }),
            );
            st.emit(collection, &Change::Version(version), &id.writer, seq);
            id
        };
        inner.publish(&ns).await;
        Ok(id)
    }

    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError> {
        let inner = &self.inner;
        check_collection(collection)?;
        inner.follow(collection).await?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        {
            let mut st = inner.st.lock();
            let mut held: Vec<&Version> = st
                .colls
                .iter()
                .filter(|(c, _)| c.has_prefix(collection))
                .flat_map(|(_, coll)| coll.versions.values().map(|hv| &hv.version))
                .filter(|v| !since.contains(&v.id))
                .collect();
            held.sort_by(|a, b| (&a.collection, &a.id).cmp(&(&b.collection, &b.id)));
            for v in held {
                let _ = tx.send(Ok(Change::Version(v.clone())));
            }
            st.watchers.push(Watcher {
                target: collection.clone(),
                since: since.clone(),
                tx,
            });
        }
        let ns = namespace_of(collection).expect("checked above");
        inner.refresh_group(&ns);
        Ok(Box::pin(stream::poll_fn(move |cx| rx.poll_recv(cx))))
    }

    async fn snapshot(&self, of: &[Name]) -> Result<Snapshot, DataError> {
        let mut pins = Vec::with_capacity(of.len());
        for name in of {
            let pin = match self.get(name).await?.got {
                Got::State(s) => s.name,
                Got::Version(v) => v.name,
                Got::Snapshot(s) => s.name,
            };
            pins.push(pin);
        }
        let inner = &self.inner;
        let mut st = inner.st.lock();
        let (name, seq) = inner.append(&mut st, None, wire::encode_snapshot(&pins))?;
        Ok(Snapshot {
            id: VersionId {
                writer: inner.writer.clone(),
                seq: Seq(seq),
            },
            name,
            pins,
        })
    }

    async fn hold(&self, prefix: &Name, _want: Hold) -> Result<Custody, DataError> {
        Err(local(format!(
            "custody leases are data-layer slice 3; this device cannot ask holders to keep {prefix} yet"
        )))
    }

    async fn prune(&self, prefix: &Name, _upto: &Frontier) -> Result<(), DataError> {
        Err(local(format!(
            "prune is data-layer slice 3; this device cannot drop its writes under {prefix} yet"
        )))
    }

    async fn share(
        &self,
        collection: &Name,
        members: crate::layer::Share,
    ) -> Result<(), DataError> {
        let inner = &self.inner;
        check_collection(collection)?;
        let ns = namespace_of(collection).expect("checked above");
        if ns != inner.ns {
            return Err(DataError::NotOwner {
                collection: collection.clone(),
            });
        }
        if !members.readmit.is_empty() {
            return Err(local(
                "re-admitting versions outside a cut is data-layer slice 5; share without readmit",
            ));
        }
        inner.follow(collection).await?;
        {
            let mut st = inner.st.lock();
            let current = st.colls.get(collection).and_then(|c| c.members.clone());
            if let Some(cur) = &current {
                if cur.rule != members.rule {
                    return Err(local(format!(
                        "{collection} keeps the rule it was first shared with ({:?}); a rule \
                         change would make its readers merge differently",
                        cur.rule
                    )));
                }
                if let Some(gone) = cur.writers.iter().find(|p| !members.writers.contains(p)) {
                    return Err(local(format!(
                        "removing writer {gone} needs a cut at what this device saw of it \
                         (data-layer slice 2); share keeps every current writer"
                    )));
                }
            }
            let body = MembersBody {
                collection: collection.clone(),
                revision: current.map_or(1, |m| m.revision.0 + 1),
                rule: members.rule,
                writers: members.writers,
                readers: members.readers,
            };
            inner.append(&mut st, Some(collection), wire::encode_members(&body))?;
        }
        inner.publish(&ns).await;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ndn_app::AppError;
    use ndn_security::TrustSchema;
    use ndn_sync::MemoryStore;

    const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

    /// A forwarder that never delivers anything: the test hands the device
    /// the packets it would have fetched.
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

    /// A device key under `authority`'s namespace key `issuer`: its key
    /// store, its key, and its certificate.
    async fn device_key(
        authority: &SecurityManager,
        issuer: &Name,
        device: &Name,
    ) -> (Arc<SecurityManager>, Name, ndn_security::Certificate) {
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
        (keys, key, cert)
    }

    /// `device`'s signed summary root of `ns` at `head`.
    fn root(keys: &SecurityManager, key: &Name, device: &Name, ns: &Name, head: u64) -> Data {
        let body = NodeBody {
            subject: ns.clone(),
            writer: key.clone(),
            head,
            page: None,
            entries: Vec::new(),
            members: Vec::new(),
            branches: Branches::Children(Vec::new()),
        };
        let signer = keys.get_signer_sync(key).unwrap();
        let wire = DataBuilder::new(node_name(device, ns, head), &wire::encode_node(&body))
            .sign_sync(signer.sig_type(), Some(key), |region| {
                signer.sign_sync(region).unwrap()
            });
        Data::decode(wire).unwrap()
    }

    #[tokio::test]
    async fn a_restarted_device_still_refuses_a_rolled_back_summary_root() {
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
        let (writer, reader) = (n("/wendy/laptop"), n("/rita/phone"));
        let (writer_keys, writer_key, writer_cert) = device_key(&authority, &issuer, &writer).await;
        let reader_keys = Arc::new(SecurityManager::new());
        reader_keys
            .generate_ed25519(reader.clone().append("KEY").append("1"))
            .unwrap();
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        validator.cert_cache().insert(writer_cert);

        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let start = || {
            let conn: Arc<dyn Connection> = Arc::new(Unconnected);
            Device::start(
                Transport {
                    node: Node::from_connection(Arc::clone(&conn)),
                    sync: conn,
                },
                reader.clone(),
                Arc::clone(&reader_keys),
                Arc::clone(&validator),
                Arc::clone(&store),
                Config::new(),
            )
        };
        let at = |head| root(&writer_keys, &writer_key, &writer, &ns, head);

        let first = start().await.unwrap();
        first
            .inner
            .accept_root(&writer, &ns, &at(5))
            .await
            .expect("a first root is taken");
        first.shutdown();
        drop(first);

        let again = start().await.unwrap();
        let refused = again.inner.accept_root(&writer, &ns, &at(3)).await;
        assert!(
            matches!(refused, Err(RootRefusal::Rollback { head: 3, seen: 5 })),
            "a root below the head verified before the restart is refused: {refused:?}"
        );
        again
            .inner
            .accept_root(&writer, &ns, &at(5))
            .await
            .expect("the same head is taken");
        again
            .inner
            .accept_root(&writer, &ns, &at(8))
            .await
            .expect("a newer head is taken");
    }
}
