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
//! newest members record (its writers and the cuts of removed ones), and
//! applied by the collection's rule once its parents are applied. A members
//! record that arrives later re-checks everything held of its collection:
//! what it refuses is withdrawn and reported.
//!
//! Sealed collections (spec §9) carry their payloads encrypted under an
//! epoch key; the device asks for the keys it may hold (`seal`), and serves
//! them, wrapped, to the readers the newest members record admits.
//!
//! Groups: a device publishes each change about a collection into the sync
//! group of the collection's namespace and of every namespace its members
//! record names, so the notice reaches every member's devices through their
//! own namespace's group; a notice from a device makes the reader refresh
//! that device's summary of every followed namespace the device writes into
//! by the members records held.
//!
//! What a device follows: every collection or folder it has put into, read or
//! watched. Nothing about correctness depends on a clock or on timing: a
//! timeout only delays an answer, and an answer from older data says how old
//! it may be.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
use ndn_security::{Keyring, SecurityManager, Signer, ValidationResult, Validator, sync_group};
use ndn_sync::{DataStore, MultiSvs, SvsConfig, SyncUpdate, spawn_multi_svs};
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::collection::{Accepted, Child, Cut, Epoch, Members, Resolve, Rule, Summary};
use crate::error::{DataError, Refusal};
use crate::layer::{Age, Answer, Change, Changes, DataLayer, Got, Hold, PutOptions, State};
use crate::merge::{MergeRule, MergeRules, MergeState};
use crate::pieces::{self, Shape};
use crate::rt::{self, Instant};
use crate::seal::{self, Keys};
use crate::statement::{Audit, Breach, Custody, Lease, Prune, Snapshot};
use crate::tree::{Entry, Tree};
use crate::version::{
    Audience, Content, Frontier, Keep, Payload, Seal, Seq, Timestamp, Version, VersionId, Writer,
};
use crate::wire::{
    self, AuditAnswer, AuditAsk, Branches, ChunksBody, CutBody, GrantAsk, HoldBody, LeaseBody,
    MembersBody, NodeBody, PieceKind, PruneBody, Record, SealedBody, VersionBody, audit_ask_name,
    device_of, grant_name, hold_ask_name, log_name, namespace_of, node_name, page_name,
    parse_audit_ask_name, parse_grant_name, parse_held_name, parse_hold_ask_name, parse_log_name,
    parse_piece_name, parse_seal_key_name, parse_state_name, parse_summary_name, piece_name,
    root_name, root_prefix, seal_key_name, seqs_of, state_name, subject_namespace,
};
use ndn_security::confidentiality::{ContentKey, RecipientKey, Sealed, wrap_ck_to};

/// A wall clock: the date a device's clock shows. Display and retention
/// only; no decision of the layer reads it.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// A source of random octets: fills the slice with unpredictable bytes. The
/// device draws an audit's pieces and nonces from it (spec §13).
pub type Entropy = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// A signed summary root is never fresh in a cache: discovery (`MustBeFresh`)
/// always reaches its writer, so a notice that the writer moved is never
/// answered by the root it moved from.
const ROOT_FRESHNESS: Duration = Duration::ZERO;

/// A device's settings. Everything here is performance, or the host's policy
/// of what this device does for others (`hold_for`); none of it changes
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
    /// The namespaces whose collections this device keeps for their owners
    /// under custody leases (spec §13): it answers their owners' hold asks
    /// and audits. Empty: the device is not a holder.
    pub hold_for: Vec<Name>,
    /// How many random pieces an audit asks each holder for.
    pub audit_pieces: usize,
    /// Where audits draw their randomness.
    pub entropy: Entropy,
}

impl Config {
    /// Defaults: SVS's reference timing, the standard merge rules, the
    /// system clock, 2 s Interests, a 4 s first look, 32 fetches in flight,
    /// not a holder, 16 pieces an audit, the operating system's randomness.
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
            hold_for: Vec::new(),
            audit_pieces: 16,
            entropy: Arc::new(|buf| {
                getrandom::getrandom(buf).expect("the operating system provides randomness")
            }),
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
            .field("hold_for", &self.hold_for)
            .field("audit_pieces", &self.audit_pieces)
            .finish_non_exhaustive()
    }
}

/// What a [`Device::release`] dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Released {
    /// Large versions whose pieces were dropped.
    pub versions: u32,
    /// Pieces dropped.
    pub pieces: u32,
    /// Their octets.
    pub bytes: u64,
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
    /// Whether its payload came sealed.
    sealed: bool,
    /// The epoch its payload is sealed in.
    epoch: Option<Epoch>,
    /// Its payload in pieces, when it travels so (spec §4.1).
    chunks: Option<ChunksBody>,
}

/// A lease of a collection this device knows, the newest of its holder.
struct LeaseHeld {
    seq: u64,
    name: Name,
    body: LeaseBody,
    audit: Audit,
}

/// What the records held say of one epoch of a collection (spec §9).
struct Named {
    /// The key check of the record that starts the epoch (or, until that
    /// record is held, of a record keeping it).
    check: [u8; 32],
    /// Whether `check` is the starting record's own.
    from_start: bool,
    /// Every reader listed by a held record naming the epoch.
    readers: Vec<Audience>,
}

/// One collection as this device knows it.
#[derive(Default)]
struct Coll {
    /// The record in force: the merge of `records` (spec §6).
    members: Option<Members>,
    /// The owner-signed records of the highest revision held, one per
    /// signer (its latest), with each record's seq in its signer's log.
    records: BTreeMap<Writer, (u64, Members)>,
    /// Every record of `records`' revision taken and every merge of them
    /// computed, by digest: the parents records of the next revision name.
    level: HashMap<[u8; 32], Members>,
    /// The same at the revision below `records`': the parents they may
    /// name, which their merge is made against (spec §6).
    parents: HashMap<[u8; 32], Members>,
    /// What `members`, a merge of concurrent records, leaves to resolve:
    /// a device of the audience resolves it with a new record.
    resolve: Resolve,
    /// Every epoch a held owner-signed record of the collection names.
    epochs: BTreeMap<Epoch, Named>,
    /// The merge state, once the rule is known and this device runs it.
    state: Option<Box<dyn MergeState>>,
    /// Every admitted version held, applied or waiting for its parents.
    versions: BTreeMap<VersionId, Arc<HeldVersion>>,
    /// Per writer, the highest seq applied (a prefix of its entries).
    applied: BTreeMap<Writer, u64>,
    /// Per writer, every version seq this device knows it wrote here.
    entries: HashMap<Writer, BTreeSet<u64>>,
    /// Per writer, the entries held and refused for what they carry (not
    /// sealed, or an operation the rule refuses): later versions do not wait
    /// for them.
    skipped: HashMap<Writer, BTreeSet<u64>>,
    /// Admitted, not yet applied.
    pending: BTreeSet<VersionId>,
    /// Held while no members record is known (or the rule is not one this
    /// device runs).
    waiting: Vec<Arc<HeldVersion>>,
    /// Held but refused by the newest members record: their keys are not
    /// writers, they lie outside a cut, or they are not sealed in a sealed
    /// collection. A later revision that admits them admits them.
    outsiders: Vec<Arc<HeldVersion>>,
    /// Verified, sealed in an epoch whose key this device does not hold
    /// (yet, or ever: it is not of the audience).
    locked: Vec<Locked>,
    /// The hold records of the owner's devices, the newest of each: its
    /// seq, its name, what it asks.
    holds: BTreeMap<Writer, (u64, Name, HoldBody)>,
    /// The leases on the collection, by holder key.
    leases: BTreeMap<Writer, LeaseHeld>,
    /// The prune records known (spec §14).
    prunes: Vec<Prune>,
    /// The keep and epoch of each version dropped as pruned, so the leases
    /// that held it can still be checked against it, and its epoch's key
    /// destroyed once the epoch is all pruned.
    pruned_keeps: HashMap<VersionId, (Keep, Option<Epoch>)>,
    /// Epochs whose key this device destroyed: every version sealed in them
    /// is pruned (spec §14).
    erased: BTreeSet<Epoch>,
}

/// A verified version whose payload is sealed and not opened.
struct Locked {
    name: Name,
    wire: Bytes,
    writer: Writer,
    seq: u64,
    body: VersionBody,
}

impl Locked {
    fn epoch(&self) -> &Epoch {
        &self
            .body
            .sealed
            .as_ref()
            .expect("a locked version is sealed")
            .epoch
    }
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

    /// Whether later versions of `id`'s writer need not wait for `id`
    /// ([`skipped_by`]).
    fn skips(&self, id: &VersionId) -> bool {
        skipped_by(self.members.as_ref(), &self.skipped, id)
    }

    /// The prune record that covers `id`, if one is known.
    fn pruned(&self, id: &VersionId) -> Option<&Prune> {
        self.prunes.iter().find(|p| covers(p, id))
    }

    /// Mark every known entry a prune covers as one later versions need
    /// not wait for: it never applies.
    fn mark_pruned(&mut self) {
        for p in &self.prunes {
            let w = &p.id.writer;
            let Some(known) = self.entries.get(w) else {
                continue;
            };
            let covered: Vec<u64> = known
                .iter()
                .copied()
                .filter(|s| {
                    covers(
                        p,
                        &VersionId {
                            writer: w.clone(),
                            seq: Seq(*s),
                        },
                    )
                })
                .collect();
            self.skipped.entry(w.clone()).or_default().extend(covered);
        }
    }
}

/// Whether prune `p` covers version `id`: its signer's own version, at or
/// below what `upto` lists for that key, and the one version `p.prefix`
/// names when it names one (spec §14).
fn covers(p: &Prune, id: &VersionId) -> bool {
    if id.writer != p.id.writer || p.upto.get(&id.writer).is_none_or(|u| id.seq > u) {
        return false;
    }
    parse_log_name(&p.prefix).is_none_or(|l| l.seq == id.seq.0)
}

/// The latest date the versions inside `holds` are kept to, when every one
/// of them is kept until a date (spec §13): the most a lease holding them
/// may promise. `None` when one is kept without a date, or none is inside
/// (no cap). `Err(())` while a version inside it is not held here (nor
/// known pruned), so the cap is not known. Versions that never apply (a
/// cut, a refusal) do not count.
fn keep_cap(coll: &Coll, holds: &Frontier) -> Result<Option<Timestamp>, ()> {
    let mut cap: Option<Timestamp> = None;
    for (w, upto) in holds.iter() {
        let Some(seqs) = coll.entries.get(w) else {
            continue;
        };
        for s in seqs.range(..=upto.0) {
            let id = VersionId {
                writer: w.clone(),
                seq: Seq(*s),
            };
            let keep = match coll.versions.get(&id) {
                Some(hv) => hv.version.keep,
                None => match coll.pruned_keeps.get(&id) {
                    Some((k, _)) => *k,
                    None => match coll.locked.iter().find(|l| l.writer == *w && l.seq == *s) {
                        Some(l) => l.body.keep,
                        None if coll.skips(&id) => continue,
                        None => return Err(()),
                    },
                },
            };
            match keep {
                Keep::Until(t) => cap = Some(cap.map_or(t, |c| c.max(t))),
                Keep::Forever | Keep::LastN(_) => return Ok(None),
            }
        }
    }
    Ok(cap)
}

/// A map that keeps its `cap` newest entries.
struct Kept<V> {
    map: HashMap<Name, V>,
    order: VecDeque<Name>,
    cap: usize,
}

impl<V> Kept<V> {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    fn get(&self, k: &Name) -> Option<&V> {
        self.map.get(k)
    }

    fn insert(&mut self, k: Name, v: V) {
        if self.map.insert(k.clone(), v).is_none() {
            self.order.push_back(k);
            if self.order.len() > self.cap
                && let Some(old) = self.order.pop_front()
            {
                self.map.remove(&old);
            }
        }
    }
}

/// Grants a device keeps signed, so asking again gets the same packet.
const GRANTS_KEPT: usize = 4096;
/// Askers' seal keys a device keeps verified.
const SEAL_KEYS_KEPT: usize = 1024;

/// Why this device owes a collection a new members record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owed {
    /// Its record merges concurrent ones and leaves a reader to add to its
    /// epoch or a removal to carry out in a new one (spec §6).
    Merge,
    /// A group its record names as a reader dropped a reader (spec §6).
    Group,
}

/// What a held log entry is.
enum Held {
    Version(VersionId),
    /// A version whose payload is sealed and not opened here.
    Locked,
    /// A members, hold or lease record, or a prune record.
    Record,
    Snapshot(Snapshot),
    /// A version its writer pruned: dropped here, never served.
    Pruned(Prune),
}

/// A collection this device keeps for its owner under a lease (spec §13).
struct Holding {
    /// The owner's hold record answered.
    hold: Name,
    /// Until when the owner asked.
    until: Timestamp,
    /// The newest lease signed: what it holds and until when.
    lease: Option<(Frontier, Timestamp)>,
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
    /// This device's namespace.
    ns: Name,
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
    /// The seal keys held.
    keys: Keys,
    /// Epoch keys being asked for.
    asking: BTreeSet<(Name, Epoch)>,
    /// Grants made, by name: one name, one packet while it is kept.
    grants: Kept<Bytes>,
    /// Askers' seal keys verified, by name.
    seal_keys: Kept<[u8; 32]>,
    /// The device's seal key packet, once signed.
    seal_key: Option<Bytes>,
    /// Collections of this namespace this device owes a new members record.
    owed: BTreeMap<Name, Owed>,
    /// Groups a record held names that this device is to follow.
    to_follow: BTreeSet<Name>,
    /// Per group, the collections whose record in force names it a reader.
    sealed_to: HashMap<Name, BTreeSet<Name>>,
    /// The collections this device holds for their owners.
    holding: BTreeMap<Name, Holding>,
    /// Large versions whose pieces are being fetched.
    fetching: BTreeSet<Name>,
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

/// Whether the members record named `entry` (`<D>/32=log/<C>/seq=<n>`, its
/// signature verified) is signed by a device of `C`'s namespace `ns`, so its
/// owner (spec §3): the trust context governing the record's name — the one
/// the validator verified it under, the held context whose namespace is the
/// longest prefix of it — is `ns`'s own. The device `D` then lies under
/// `ns`; a device under `ns` that a longer held namespace governs (a
/// `/home/bob` device, for `/home`) is that namespace's device, not `ns`'s.
fn owner_signed(keyring: &Keyring, entry: &Name, ns: &Name) -> bool {
    entry.has_prefix(ns) && keyring.context_for(entry).namespace() == ns
}

/// Whether later versions of `id`'s writer, and versions naming `id` as a
/// parent, need not wait for it: `members` refuses it by its key (a cut
/// that does not list it, a key no writer), or it is held and refused for
/// what it carries (`skipped`).
fn skipped_by(
    members: Option<&Members>,
    skipped: &HashMap<Writer, BTreeSet<u64>>,
    id: &VersionId,
) -> bool {
    members.is_some_and(|m| m.refusal(id).is_some())
        || skipped
            .get(&id.writer)
            .is_some_and(|s| s.contains(&id.seq.0))
}

/// The seq of `y` that a version naming `(y, t)` among its parents needs
/// applied: `t`; or, when `(y, t)` never applies (a cut does not list it,
/// or it was refused for what it carries), the highest version of `y` at or
/// below `t` that does.
fn needed(
    members: Option<&Members>,
    entries: &HashMap<Writer, BTreeSet<u64>>,
    skipped: &HashMap<Writer, BTreeSet<u64>>,
    y: &Writer,
    t: u64,
) -> u64 {
    let id = |s: u64| VersionId {
        writer: y.clone(),
        seq: Seq(s),
    };
    if let Some(Refusal::OutsideCut(cut)) = members.and_then(|m| m.refusal(&id(t))) {
        return cut.accept.highest_at_most(y, t).unwrap_or(0);
    }
    if !skipped_by(members, skipped, &id(t)) {
        return t;
    }
    entries
        .get(y)
        .and_then(|e| {
            e.range(..t)
                .rev()
                .find(|s| !skipped_by(members, skipped, &id(**s)))
                .copied()
        })
        .unwrap_or(0)
}

/// Whether a version is ready to apply: its writer's earlier entries here
/// that apply at all, and its parents (as far as they apply), are applied.
fn ready(
    entries: &HashMap<Writer, BTreeSet<u64>>,
    skipped: &HashMap<Writer, BTreeSet<u64>>,
    applied: &BTreeMap<Writer, u64>,
    members: Option<&Members>,
    v: &Version,
) -> bool {
    let w = &v.id.writer;
    let prev = entries.get(w).and_then(|e| {
        e.range(..v.id.seq.0)
            .rev()
            .find(|s| {
                !skipped_by(
                    members,
                    skipped,
                    &VersionId {
                        writer: w.clone(),
                        seq: Seq(**s),
                    },
                )
            })
            .copied()
    });
    prev == applied.get(w).copied()
        && v.parents.iter().all(|(y, t)| {
            let need = needed(members, entries, skipped, y, t.0);
            need == 0 || applied.get(y).is_some_and(|a| *a >= need)
        })
}

impl St {
    fn inside(&self, subject: &Name) -> bool {
        (1..=subject.len()).any(|n| {
            self.follows.contains(&Name::from_components(
                subject.components()[..n].iter().cloned(),
            ))
        })
    }

    /// Whether something followed lies under `subject`. Under a root (a
    /// namespace) only its own data names count: `/home/bob/32=data/x` is
    /// under `/home/bob`'s root, not `/home`'s.
    fn toward(&self, subject: &Name) -> bool {
        let under = |s: &Name| {
            self.follows
                .range(s.clone()..)
                .next()
                .is_some_and(|t| t.has_prefix(s))
        };
        if wire::is_namespace(subject) {
            under(&wire::data_folder(subject))
        } else {
            under(subject)
        }
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

    /// Tell every watcher of collection `c`, whatever its frontier.
    fn tell(&mut self, c: &Name, change: &Change) {
        self.watchers.retain(|w| !w.tx.is_closed());
        for w in &self.watchers {
            if c.has_prefix(&w.target) {
                let _ = w.tx.send(Ok(change.clone()));
            }
        }
    }

    /// Take `body`, the members record at seq `seq` of its signer's log,
    /// signed by `signer` (a device of the collection's namespace,
    /// [`owner_signed`]): note the epoch it names, and, if it is of the
    /// highest revision held, merge it with the other signers' records of
    /// that revision against the parent they name, if held (spec §6), and
    /// read the collection again under the merge; a record of the revision
    /// below is held as a parent they may name. Owes a new record of this
    /// namespace's collections where the merge leaves a reader to add or a
    /// removal undone, or where a group they are sealed to dropped a reader.
    fn accept_members(
        &mut self,
        seq: u64,
        body: MembersBody,
        signer: &Writer,
        rules: &MergeRules,
        me: &Writer,
    ) {
        let c = body.collection.clone();
        let record = Members {
            collection: c.clone(),
            owner: signer.clone(),
            revision: Seq(body.revision),
            rule: body.rule,
            writers: body.writers,
            readers: body.readers,
            cuts: body
                .cuts
                .into_iter()
                .map(|b| Cut {
                    of: b.of,
                    accept: b.accept,
                    signer: signer.clone(),
                })
                .collect(),
            epoch: body.epoch,
            key_check: body.key_check,
            since: body.since,
            parent: body.parent,
            readmitted: Vec::new(),
        };
        let coll = self.colls.entry(c.clone()).or_default();
        if let (Some(e), Some(check)) = (&record.epoch, record.key_check) {
            let starts = seq == e.seq.0 && device_of(signer.key()).as_ref() == Some(&e.creator);
            let named = coll.epochs.entry(e.clone()).or_insert_with(|| Named {
                check,
                from_start: starts,
                readers: Vec::new(),
            });
            if starts && !named.from_start {
                named.check = check;
                named.from_start = true;
            } else if named.check != check {
                tracing::debug!(collection = %c, epoch = ?e, signer = ?signer, "a record names an epoch with another key check than the one held; the starting record's counts");
            }
            for r in &record.readers {
                if !named.readers.contains(r) {
                    named.readers.push(r.clone());
                }
            }
        }
        let digest = record.as_parent().digest;
        match coll.records.values().next().map(|(_, m)| m.revision) {
            // A late record of the revision below: a parent the held ones
            // may name.
            Some(r) if record.revision < r => {
                if record.revision.0 + 1 != r.0 || coll.parents.contains_key(&digest) {
                    return;
                }
                coll.parents.insert(digest, record);
            }
            Some(r) if record.revision > r => {
                let level = std::mem::take(&mut coll.level);
                coll.parents = if record.revision.0 == r.0 + 1 {
                    level
                } else {
                    HashMap::new()
                };
                coll.records.clear();
                coll.level.insert(digest, record.clone());
                coll.records.insert(signer.clone(), (seq, record));
            }
            _ => {
                if coll.records.get(signer).is_some_and(|(s, _)| *s >= seq) {
                    return;
                }
                coll.level.insert(digest, record.clone());
                coll.records.insert(signer.clone(), (seq, record));
            }
        }
        let records: Vec<Members> = coll.records.values().map(|(_, m)| m.clone()).collect();
        let parents = &coll.parents;
        let (merged, resolve) =
            Members::merge(&records, |p| parents.get(&p.digest)).expect("a record is held");
        coll.resolve = resolve;
        if records.len() > 1 {
            coll.level.insert(merged.as_parent().digest, merged.clone());
        }
        if coll.members.as_ref() == Some(&merged) {
            return;
        }
        let dropped = coll
            .members
            .as_ref()
            .is_some_and(|old| old.readers.iter().any(|r| !merged.readers.contains(r)));
        let groups = |m: &Members| -> Vec<Name> {
            m.readers
                .iter()
                .filter_map(|a| match a {
                    Audience::Group(g) => Some(g.clone()),
                    _ => None,
                })
                .collect()
        };
        let (before, after) = (coll.members.as_ref().map(groups), groups(&merged));
        coll.members = Some(merged);
        for g in before.into_iter().flatten() {
            if let Some(xs) = self.sealed_to.get_mut(&g) {
                xs.remove(&c);
            }
        }
        // A group's readers decide who reads here: follow it, so that its
        // record is held and its removals heard (spec §6).
        for g in after {
            if !self.follows.contains(&g) {
                self.to_follow.insert(g.clone());
            }
            self.sealed_to.entry(g).or_default().insert(c.clone());
        }
        if resolve != Resolve::Nothing && namespace_of(&c).as_ref() == Some(&self.ns) {
            self.owed.entry(c.clone()).or_insert(Owed::Merge);
        }
        if dropped {
            // This namespace's collections sealed to `c` as a group move to
            // a new epoch with it.
            let own: Vec<Name> = self
                .sealed_to
                .get(&c)
                .into_iter()
                .flatten()
                .filter(|x| namespace_of(x).as_ref() == Some(&self.ns))
                .cloned()
                .collect();
            for x in own {
                self.owed.insert(x, Owed::Group);
            }
        }
        self.reread(&c, rules, me);
    }

    /// Read collection `c` again under its newest members record (spec
    /// §8): every version held is admitted or refused anew and the state is
    /// rebuilt from the admitted ones. A version applied before that the
    /// record now refuses is withdrawn and reported to the watchers; one
    /// applied before and still admitted is not delivered again.
    fn reread(&mut self, c: &Name, rules: &MergeRules, me: &Writer) {
        let Some(coll) = self.colls.get_mut(c) else {
            return;
        };
        let Some(members) = coll.members.clone() else {
            return;
        };
        let before = coll.at();
        let mut all: Vec<Arc<HeldVersion>> = std::mem::take(&mut coll.versions)
            .into_values()
            .chain(std::mem::take(&mut coll.waiting))
            .chain(std::mem::take(&mut coll.outsiders))
            .collect();
        all.sort_by(|a, b| a.version.id.cmp(&b.version.id));
        coll.pending.clear();
        coll.applied.clear();
        coll.skipped.clear();
        coll.mark_pruned();
        coll.state = match &members.rule {
            Rule::Merge { function } => rules.get(function).map(|r| r.start(me)),
            _ => None,
        };
        let delivered: BTreeSet<VersionId> = all
            .iter()
            .map(|hv| hv.version.id.clone())
            .filter(|id| before.contains(id))
            .collect();
        let mut withdrawn = Vec::new();
        for hv in all {
            let id = hv.version.id.clone();
            self.refused.remove(&hv.version.name);
            self.admit_one(hv);
            if delivered.contains(&id)
                && let Some(Refusal::OutsideCut(cut)) = members.refusal(&id)
            {
                withdrawn.push((id, cut));
            }
        }
        self.apply_ready(c, &delivered);
        for (id, cut) in withdrawn {
            tracing::info!(?id, collection = %c, "withdrawn: a cut that arrived later refuses it");
            self.tell(c, &Change::Withdrawn { id, cut });
        }
    }

    /// Admit a verified, opened version, or hold it: until the members
    /// record is known (and its rule is one this device runs), or as
    /// refused by it. Returns whether it was queued to apply.
    fn admit_one(&mut self, hv: Arc<HeldVersion>) -> bool {
        let c = hv.version.collection.clone();
        let coll = self.colls.entry(c.clone()).or_default();
        let Some(members) = &coll.members else {
            coll.waiting.push(hv);
            return false;
        };
        let history = members
            .since
            .as_ref()
            .is_some_and(|s| s.contains(&hv.version.id));
        let why = members.refusal(&hv.version.id).or_else(|| {
            (members.epoch.is_some() && !hv.sealed && !history).then_some(Refusal::Unsealed)
        });
        if let Some(why) = why {
            tracing::debug!(id = ?hv.version.id, %why, "refused in {c}");
            if why == Refusal::Unsealed {
                coll.skipped
                    .entry(hv.version.id.writer.clone())
                    .or_default()
                    .insert(hv.version.id.seq.0);
            }
            self.refused.insert(hv.version.name.clone(), why);
            coll.outsiders.push(hv);
            return false;
        }
        match &members.rule {
            Rule::Merge { .. } => {
                if hv.chunks.is_some() {
                    tracing::debug!(id = ?hv.version.id, "refused: its payload is in pieces, in a merge collection");
                    coll.skipped
                        .entry(hv.version.id.writer.clone())
                        .or_default()
                        .insert(hv.version.id.seq.0);
                    self.refused
                        .insert(hv.version.name.clone(), Refusal::NotInline);
                    return false;
                }
                let Some(state) = &coll.state else {
                    // The rule is not one this device runs; the version stays
                    // held and `get` says why.
                    coll.waiting.push(hv);
                    return false;
                };
                if !history && let Err(e) = state.check(&hv.version.id.writer, &hv.op) {
                    tracing::debug!(id = ?hv.version.id, "refused: {e}");
                    coll.skipped
                        .entry(hv.version.id.writer.clone())
                        .or_default()
                        .insert(hv.version.id.seq.0);
                    self.refused
                        .insert(hv.version.name.clone(), Refusal::BadSignature);
                    return false;
                }
            }
            Rule::Log => {}
            Rule::OneKey => {
                coll.waiting.push(hv);
                return false;
            }
        }
        coll.entries
            .entry(hv.version.id.writer.clone())
            .or_default()
            .insert(hv.version.id.seq.0);
        coll.pending.insert(hv.version.id.clone());
        coll.versions.insert(hv.version.id.clone(), hv);
        true
    }

    /// Admit a verified, opened version and apply what became ready.
    fn admit(&mut self, hv: Arc<HeldVersion>) {
        let c = hv.version.collection.clone();
        if self.admit_one(hv) {
            self.apply_ready(&c, &BTreeSet::new());
        }
    }

    /// Apply every pending version of `c` that is ready, and deliver each
    /// to the watchers unless `quiet` lists it (delivered before).
    fn apply_ready(&mut self, c: &Name, quiet: &BTreeSet<VersionId>) {
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
        let Coll {
            members,
            state,
            versions,
            applied,
            entries,
            skipped,
            pending,
            ..
        } = coll;
        let since = members.as_ref().and_then(|m| m.since.as_ref());
        let mut applied_now = Vec::new();
        loop {
            let next = pending.iter().find(|id| {
                versions.get(id).is_some_and(|hv| {
                    ready(entries, skipped, applied, members.as_ref(), &hv.version)
                })
            });
            let Some(id) = next.cloned() else { break };
            pending.remove(&id);
            let hv = Arc::clone(&versions[&id]);
            let history = since.is_some_and(|s| s.contains(&id));
            let done = match state.as_mut() {
                Some(state) if !history => state.apply(&id.writer, &hv.op),
                _ => Ok(()),
            };
            match done {
                Ok(()) => {
                    applied.insert(id.writer.clone(), id.seq.0);
                    if !quiet.contains(&id) {
                        applied_now.push(hv);
                    }
                }
                Err(e) => {
                    tracing::warn!(?id, "refused: {e}");
                    versions.remove(&id);
                    skipped
                        .entry(id.writer.clone())
                        .or_default()
                        .insert(id.seq.0);
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

    /// Hold `key` as the key of epoch `e` of `c` if it matches the key
    /// check of the held record naming that epoch (spec §9), and open what
    /// it unlocks. Whether it matched.
    fn take_key(&mut self, c: &Name, e: &Epoch, key: ContentKey) -> bool {
        let Some(coll) = self.colls.get(c) else {
            return false;
        };
        let Some(named) = coll.epochs.get(e) else {
            return false;
        };
        if coll.erased.contains(e) || seal::key_check(&key, c, e) != named.check {
            return false;
        }
        self.keys.hold(c.clone(), e.clone(), key);
        self.unlock(c);
        true
    }

    /// Open the locked versions of `c` whose epoch key is now held, and
    /// admit them.
    fn unlock(&mut self, c: &Name) {
        let Some(coll) = self.colls.get_mut(c) else {
            return;
        };
        let locked = std::mem::take(&mut coll.locked);
        let mut opened = Vec::new();
        for l in locked {
            match self.keys.key(c, l.epoch()) {
                Some(key) => opened.push((key, l)),
                None => self.colls.get_mut(c).expect("held").locked.push(l),
            }
        }
        for (key, l) in opened {
            let Locked {
                name,
                wire,
                writer,
                seq,
                mut body,
            } = l;
            let Some(sealed) = body.sealed.clone() else {
                continue;
            };
            let epoch = Some(sealed.epoch.clone());
            // A payload in pieces opens when it is read (`get`); the
            // record alone is admitted now.
            if body.chunks.is_none() {
                let Some((fields, op)) = seal::open_payload(&key, &name, &sealed.ciphertext) else {
                    tracing::debug!(%name, "refused: its payload does not open under its epoch's key");
                    self.held.remove(&name);
                    self.refused.insert(name, Refusal::BadSignature);
                    continue;
                };
                body.fields = fields;
                body.op = op;
            }
            let op = body.op.clone();
            let chunks = body.chunks;
            let version = version_of(&name, &writer, seq, body);
            self.held.insert(name, Held::Version(version.id.clone()));
            self.admit(Arc::new(HeldVersion {
                version,
                op,
                wire,
                sealed: true,
                epoch,
                chunks,
            }));
        }
    }

    /// Drop every version of log collection `c` that a known prune covers
    /// (spec §14): out of what the collection holds, its record and pieces
    /// out of the store, its name answered `Pruned` from now on; its keep and
    /// epoch remembered for the leases that held it. Watchers of a version
    /// that was delivered are told. Later versions no longer wait for it.
    /// Returns the names dropped.
    fn drop_pruned(&mut self, c: &Name) -> Vec<Name> {
        let St {
            colls,
            held,
            refused,
            store,
            watchers,
            ..
        } = self;
        let Some(coll) = colls.get_mut(c) else {
            return Vec::new();
        };
        if coll.prunes.is_empty() || coll.members.as_ref().is_none_or(|m| m.rule != Rule::Log) {
            return Vec::new();
        }
        coll.mark_pruned();
        let at = coll.at();
        // (id, name, keep, epoch)
        let mut dropped: Vec<(VersionId, Name, Keep, Option<Epoch>)> = Vec::new();
        let gone: Vec<VersionId> = coll
            .versions
            .keys()
            .filter(|id| coll.pruned(id).is_some())
            .cloned()
            .collect();
        for id in gone {
            let hv = coll.versions.remove(&id).expect("listed above");
            coll.pending.remove(&id);
            dropped.push((
                id,
                hv.version.name.clone(),
                hv.version.keep,
                hv.epoch.clone(),
            ));
        }
        let prunes = &coll.prunes;
        let covered = |id: &VersionId| prunes.iter().any(|p| covers(p, id));
        for list in [&mut coll.waiting, &mut coll.outsiders] {
            list.retain(|hv| {
                if !covered(&hv.version.id) {
                    return true;
                }
                dropped.push((
                    hv.version.id.clone(),
                    hv.version.name.clone(),
                    hv.version.keep,
                    hv.epoch.clone(),
                ));
                false
            });
        }
        coll.locked.retain(|l| {
            let id = VersionId {
                writer: l.writer.clone(),
                seq: Seq(l.seq),
            };
            if !covered(&id) {
                return true;
            }
            dropped.push((id, l.name.clone(), l.body.keep, Some(l.epoch().clone())));
            false
        });
        watchers.retain(|w| !w.tx.is_closed());
        let mut names = Vec::with_capacity(dropped.len());
        for (id, name, keep, epoch) in dropped {
            let by = coll.pruned(&id).expect("covered").clone();
            coll.pruned_keeps.insert(id.clone(), (keep, epoch));
            refused.remove(&name);
            for (n, _) in store.scan_under(&name, 0) {
                store.remove(&n);
            }
            if at.contains(&id) {
                for w in watchers.iter() {
                    if c.has_prefix(&w.target) {
                        let _ = w.tx.send(Ok(Change::Pruned {
                            id: id.clone(),
                            by: by.clone(),
                        }));
                    }
                }
            }
            tracing::debug!(%name, "dropped: its writer pruned it");
            held.insert(name.clone(), Held::Pruned(by));
            names.push(name);
        }
        names
    }

    /// The merged value of `c` at exactly `at`, from held versions; `None`
    /// while some version inside `at` is not held, or `c` has no merge rule.
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
        let members = coll.members.as_ref()?;
        let Rule::Merge { function } = &members.rule else {
            return None;
        };
        let mut state = rules.get(function)?.start(me);
        let mut entries: HashMap<Writer, BTreeSet<u64>> = HashMap::new();
        for (w, t) in at.iter() {
            let known: BTreeSet<u64> = coll
                .entries
                .get(w)?
                .range(..=t.0)
                .copied()
                .filter(|s| {
                    !coll.skips(&VersionId {
                        writer: w.clone(),
                        seq: Seq(*s),
                    })
                })
                .collect();
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
            let i = left.iter().position(|hv| {
                ready(
                    &entries,
                    &coll.skipped,
                    &applied,
                    Some(members),
                    &hv.version,
                )
            })?;
            let hv = left.swap_remove(i);
            let history = members
                .since
                .as_ref()
                .is_some_and(|s| s.contains(&hv.version.id));
            if !history {
                state.apply(&hv.version.id.writer, &hv.op).ok()?;
            }
            applied.insert(hv.version.id.writer.clone(), hv.version.id.seq.0);
        }
        Some(state.value())
    }
}

impl Device {
    /// Start the data layer of the device `device` (e.g.
    /// `/home/bob/member/laptop`): sign with the key `keys` holds for it,
    /// keep its X25519 recipient secret with `keys` too
    /// ([`SecurityManager::put_secret`], made on the first start), verify
    /// with `validator`, keep what it holds in `store` (and pick up what an
    /// earlier run stored there), serve `device`'s prefix, and join its own
    /// namespace's sync group. Its namespace is that of the trust context
    /// governing its name in `validator`'s keyring (spec §3); a device no
    /// held context covers does not start.
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
        if !wire::is_device_name(&device) {
            return Err(local(format!(
                "{device} has a keyword or digest component; a device name is plain components \
                 (<namespace>/<role>/<device>), so the layer's names after it (32=log, \
                 32=summary) say where it ends"
            )));
        }
        let ns = validator.keyring().context_for(&device).namespace().clone();
        if ns.is_empty() {
            return Err(local(format!(
                "no trust context covers {device}: the validator holds none whose namespace is a \
                 prefix of it, so nothing says which namespace the device writes for (its sync \
                 group, the collections it owns); adopt its namespace's trust context (enroll \
                 the device) and start it again"
            )));
        }
        if !wire::is_namespace(&ns) {
            return Err(local(format!(
                "{device} lies in the trust context of {ns}, whose namespace has a keyword, \
                 digest or sequence-number component, which a collection name \
                 <namespace>/32=data/<path> cannot carry; enroll the device in a namespace of \
                 plain components"
            )));
        }
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = spawn_multi_svs(device.clone(), out_tx, in_rx);
        let window = config.window.max(1);
        let recipient = recipient_key(&keys, &device)?;
        let seal_keys = Keys::new(recipient);
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
                ns: ns.clone(),
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
                keys: seal_keys,
                asking: BTreeSet::new(),
                grants: Kept::new(GRANTS_KEPT),
                seal_keys: Kept::new(SEAL_KEYS_KEPT),
                seal_key: None,
                owed: BTreeMap::new(),
                to_follow: BTreeSet::new(),
                sealed_to: HashMap::new(),
                holding: BTreeMap::new(),
                fetching: BTreeSet::new(),
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
        // What the restored records owe: resolving merges, following groups.
        inner.settle().await;
        // A holder makes itself heard in the groups of the namespaces it
        // holds for, so their owners' devices know to ask it (spec §13),
        // and takes up again what its leases promise.
        for hns in inner.config.hold_for.clone() {
            inner.join(&hns).await?;
            inner.publish(&hns).await;
        }
        let held: Vec<Name> = inner.st.lock().holding.keys().cloned().collect();
        for c in held {
            let inner = Arc::clone(&inner);
            rt::spawn(async move {
                if let Err(e) = inner.look(&c).await {
                    tracing::debug!(collection = %c, "cannot follow a held collection: {e}");
                    return;
                }
                inner.repair_held(&c).await;
                inner.renew().await;
            });
        }
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

    /// The device's namespace: that of the trust context governing its name
    /// (spec §3), whose collections it owns and whose sync group it joins.
    pub fn namespace(&self) -> &Name {
        &self.inner.ns
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

    /// Drop this device's own copies of the chunks of the large versions
    /// under `name` (a version's name, or a collection) that a live lease
    /// this device audited as kept holds: the host's storage policy (the
    /// phone keeps only recent originals). The version records and their
    /// manifests stay; a later `get` reads the chunks from the holders.
    /// [`DataError::NotHeld`] when no such lease holds what `name` names.
    pub async fn release(&self, name: &Name) -> Result<Released, DataError> {
        let inner = &self.inner;
        let (c, only) = match parse_log_name(name) {
            Some(l) => match l.subject {
                Some(c) => (c, Some(name.clone())),
                None => return Err(DataError::NotFound { name: name.clone() }),
            },
            None => {
                check_collection(name)?;
                (name.clone(), None)
            }
        };
        let st = inner.st.lock();
        let Some(coll) = st.colls.get(&c) else {
            return Err(DataError::Unavailable { name: name.clone() });
        };
        let kept: Vec<&LeaseHeld> = inner
            .live_leases(&st, &c)
            .iter()
            .filter_map(|h| coll.leases.get(h))
            .filter(|l| l.audit.kept())
            .collect();
        let mut out = Released::default();
        let mut unheld = false;
        for hv in coll.versions.values() {
            let Some(chunks) = hv.chunks else { continue };
            if only.as_ref().is_some_and(|n| *n != hv.version.name) {
                continue;
            }
            if !kept.iter().any(|l| l.body.holds.contains(&hv.version.id)) {
                unheld = true;
                continue;
            }
            out.versions += 1;
            for i in 0..Shape::of(chunks.size).chunks {
                let p = piece_name(&hv.version.name, PieceKind::Chunk(i));
                if let Some(w) = inner.store.get(&p) {
                    inner.store.remove(&p);
                    out.pieces += 1;
                    out.bytes += w.len() as u64;
                }
            }
        }
        if out.versions == 0 && unheld {
            return Err(DataError::NotHeld { name: name.clone() });
        }
        Ok(out)
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

/// The name the key store keeps this device's recipient secret under.
fn secret_name(device: &Name) -> Name {
    let base: Name = "/localhost/ndn-data/seal".parse().expect("a valid name");
    Name::from_components(base.components().iter().chain(device.components()).cloned())
}

/// This device's recipient key: the one its key store keeps, else a new
/// one, kept there (spec §9).
fn recipient_key(keys: &SecurityManager, device: &Name) -> Result<RecipientKey, DataError> {
    let name = secret_name(device);
    if let Some(b) = keys.secret(&name) {
        return <[u8; 32]>::try_from(b.as_slice())
            .map(RecipientKey::from_bytes)
            .map_err(|_| {
                local(format!(
                    "the key store keeps {name} as {} octets; a recipient secret is 32",
                    b.len()
                ))
            });
    }
    let key = RecipientKey::generate();
    keys.put_secret(name.clone(), key.expose())
        .map_err(|e| local(format!("the key store cannot keep {name}: {e}")))?;
    Ok(key)
}

/// Where the store keeps the epoch keys this device made: a local name
/// (`/localhost/ndn-data/epoch/<device>`), under no prefix any device
/// serves.
fn made_keys_prefix(device: &Name) -> Name {
    let base: Name = "/localhost/ndn-data/epoch".parse().expect("a valid name");
    Name::from_components(base.components().iter().chain(device.components()).cloned())
}

/// The store name of the key of epoch `e` of `c` this device made.
fn made_key_name(device: &Name, c: &Name, e: &Epoch) -> Name {
    made_keys_prefix(device).append_component(ndn_packet::NameComponent::generic(
        wire::encode_epoch_of(c, e),
    ))
}

/// The collection and epoch a [`made_key_name`] of `device` names.
fn parse_made_key_name(device: &Name, name: &Name) -> Option<(Name, Epoch)> {
    let prefix = made_keys_prefix(device);
    if !name.has_prefix(&prefix) || name.len() != prefix.len() + 1 {
        return None;
    }
    wire::decode_epoch_of(name.components()[prefix.len()].value.clone())
}

/// Where the store keeps a tombstone for each own version this device
/// pruned (`/localhost/ndn-data/pruned/<log entry name>`): the version is
/// gone, and its summary keeps listing it, as the log never changes.
fn tomb_prefix() -> Name {
    "/localhost/ndn-data/pruned".parse().expect("a valid name")
}

fn tomb_name(entry: &Name) -> Name {
    Name::from_components(
        tomb_prefix()
            .components()
            .iter()
            .chain(entry.components())
            .cloned(),
    )
}

fn untomb(name: &Name) -> Option<Name> {
    let prefix = tomb_prefix();
    name.has_prefix(&prefix)
        .then(|| Name::from_components(name.components()[prefix.len()..].iter().cloned()))
}

/// The key a grant's Content (or a made key's stored value) carries,
/// opened with `recipient` under `name`; `None` if it is not wrapped to it
/// under that name.
fn open_grant(recipient: &RecipientKey, name: &Name, content: Bytes) -> Option<ContentKey> {
    let (ephemeral, wrapped) = wire::decode_grant(content).ok()?;
    let sealed = Sealed::from_bytes(&wrapped).ok()?;
    recipient
        .unwrap_ck(&ephemeral, &sealed, &name.encode_to_tlv())
        .ok()
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
    /// the epoch keys made or granted here (each checked again against the
    /// record naming its epoch), and the highest summary root verified of
    /// each other device per namespace, so a rolled-back root is still
    /// refused. Others' versions are stored once applied (a holder: once
    /// taken); members records go first, by revision (so each revision's
    /// merge is made against the records in force below it), then the keys,
    /// then the other records, then versions. The own versions this device
    /// pruned come back as the tombstones it kept, so its summary lists
    /// them as before.
    fn restore(&self) {
        let mut entries: Vec<(Name, Bytes, Record, Writer, u64, bool)> = Vec::new();
        let mut roots = Vec::new();
        let mut keys = Vec::new();
        let mut tombs = Vec::new();
        for (name, wire) in self.store.scan_under(&Name::root(), 0) {
            if let Some((_, ask)) = parse_grant_name(&name) {
                if parse_seal_key_name(&ask.seal_key).is_some_and(|(d, _)| d == self.device)
                    && let Ok(data) = Data::decode(wire)
                    && let Some(content) = data.content()
                {
                    keys.push((name, ask.collection, ask.epoch, content.clone()));
                }
                continue;
            }
            if let Some((c, e)) = parse_made_key_name(&self.device, &name) {
                keys.push((name, c, e, wire));
                continue;
            }
            if let Some(entry) = untomb(&name) {
                if let Some(l) = parse_log_name(&entry)
                    && l.device == self.device
                    && let Some(c) = l.subject
                {
                    tombs.push((c, l.seq));
                }
                continue;
            }
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
        // Members records first, by revision; then the other records
        // (holds, leases, prunes), so that what they say is known as the
        // versions come back; then versions and snapshots.
        entries.sort_by_key(|(_, _, record, _, seq, _)| match record {
            Record::Members(b) => (0, b.revision, *seq),
            Record::Hold(_) | Record::Lease(_) | Record::Prune(_) => (1, 0, *seq),
            Record::Version(_) | Record::Snapshot(_) => (2, 0, *seq),
        });
        let rest = entries.split_off(
            entries.partition_point(|(_, _, record, ..)| matches!(record, Record::Members(_))),
        );
        let mut st = self.st.lock();
        let take_all = |st: &mut St, list: Vec<(Name, Bytes, Record, Writer, u64, bool)>| {
            for (name, wire, record, writer, seq, mine) in list {
                if mine {
                    st.head = st.head.max(seq);
                }
                let _ = self.take(st, name, wire, writer, record, mine);
            }
        };
        take_all(&mut st, entries);
        // Keys next, so that sealed entries open as they are taken.
        let recipient = st.keys.recipient.clone();
        for (name, c, e, content) in keys {
            let taken =
                open_grant(&recipient, &name, content).is_some_and(|k| st.take_key(&c, &e, k));
            if !taken {
                tracing::debug!(%name, "a stored key that does not open, or does not match its epoch's key check; dropped");
            }
        }
        take_all(&mut st, rest);
        for (c, seq) in tombs {
            st.head = st.head.max(seq);
            let ns = namespace_of(&c).expect("a log entry's collection has a namespace");
            st.trees
                .entry(ns.clone())
                .or_insert_with(|| Tree::new(ns))
                .add(&c, seq, Entry::Version);
            let coll = st.colls.entry(c).or_default();
            coll.entries
                .entry(self.writer.clone())
                .or_default()
                .insert(seq);
            coll.mark_pruned();
        }
        for (device, ns, head) in roots {
            if device != self.device {
                let peer = st.peers.entry((device, ns)).or_default();
                peer.head = peer.head.max(head);
                peer.kept = peer.kept.max(head);
            }
        }
        // A group's reader dropped in the log re-read is history: the
        // records that moved its collections on are held too.
        st.owed.retain(|_, why| *why == Owed::Merge);
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
        let group = sync_group(ns);
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
            if interest.name.has_prefix(&sync_group(ns)) && g.busy.is_empty() {
                g.confirmed = Some(now);
            }
        }
    }

    /// A notice in `ns`'s group that `update.name` moved: refresh that
    /// device's summary of `ns`, and of every other namespace this device
    /// follows that the device writes into by the members records held
    /// (spec §12): a member of another namespace notices through its own
    /// namespace's group.
    fn on_update(self: &Arc<Self>, ns: &Name, update: SyncUpdate) {
        let device = update.name;
        tracing::trace!(me = %self.device, %ns, %device, high = update.high_seq, "sync update");
        if device == self.device {
            return;
        }
        let targets = {
            let mut st = self.st.lock();
            if let Some(g) = st.groups.get_mut(ns) {
                g.members.insert(device.clone());
            }
            let mut targets = self.written_by(&st, &device);
            targets.insert(ns.clone());
            targets
        };
        for t in targets {
            self.schedule(t, device.clone());
        }
    }

    /// The namespace of the trust context governing `name` here (empty when
    /// none is held).
    fn namespace_of_name(&self, name: &Name) -> Name {
        self.validator
            .keyring()
            .context_for(name)
            .namespace()
            .clone()
    }

    /// The namespaces this device follows (has joined the group of) that
    /// `device` may write into: its own, and those of whose collections a
    /// members record held lists a writer of `device`'s namespace.
    fn written_by(&self, st: &St, device: &Name) -> BTreeSet<Name> {
        let dns = self.namespace_of_name(device);
        let mut out = BTreeSet::new();
        if dns.is_empty() {
            return out;
        }
        if st.groups.contains_key(&dns) {
            out.insert(dns.clone());
        }
        for (c, coll) in &st.colls {
            if st.groups.keys().all(|g| out.contains(g)) {
                break;
            }
            let Some(m) = &coll.members else { continue };
            let Some(ns) = namespace_of(c) else { continue };
            if out.contains(&ns) || !st.groups.contains_key(&ns) {
                continue;
            }
            if m.writers.iter().any(|w| self.namespace_of_name(w) == dns) {
                out.insert(ns);
            }
        }
        out
    }

    /// The devices heard that may write into namespace `ns`: those heard in
    /// its group, and those heard in any group whose namespace writes into
    /// `ns` by the members records held.
    fn known_for(&self, st: &St, ns: &Name) -> Vec<Name> {
        let mut out: BTreeSet<Name> = st
            .groups
            .get(ns)
            .map(|g| g.members.iter().cloned().collect())
            .unwrap_or_default();
        for g in st.groups.values() {
            for d in &g.members {
                if !out.contains(d) && self.written_by(st, d).contains(ns) {
                    out.insert(d.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// The namespaces whose groups a change about `c` is published into:
    /// `c`'s own, and every namespace held here that its members record
    /// names among the writers or readers (a group reader by the namespace
    /// of its collection).
    fn groups_of(&self, st: &St, c: &Name) -> Vec<Name> {
        let own = namespace_of(c).expect("a collection has a namespace");
        let mut out = vec![own];
        let Some(m) = st.colls.get(c).and_then(|coll| coll.members.as_ref()) else {
            return out;
        };
        let named = m
            .writers
            .iter()
            .cloned()
            .chain(m.readers.iter().map(|a| match a {
                Audience::Person(n) | Audience::Device(n) => n.clone(),
                Audience::Group(g) => namespace_of(g).unwrap_or_else(|| g.clone()),
            }));
        for n in named {
            let ns = self.namespace_of_name(&n);
            if !ns.is_empty() && wire::is_namespace(&ns) && !out.contains(&ns) {
                out.push(ns);
            }
        }
        out
    }

    /// Publish a change about `c` into each of its groups ([`Self::groups_of`])
    /// and into `also` (the groups of members a new record removed, so the
    /// removed hear the cut that ends them).
    async fn publish_about(self: &Arc<Self>, c: &Name, also: &[Name]) -> Result<(), DataError> {
        let mut groups = self.groups_of(&self.st.lock(), c);
        for ns in also {
            if !groups.contains(ns) {
                groups.push(ns.clone());
            }
        }
        for ns in groups {
            self.join(&ns).await?;
            self.publish(&ns).await;
        }
        Ok(())
    }

    /// Do what the records taken owe (spec §6): sign the record this device
    /// owes a collection of its namespace — one resolving a merge, in the
    /// epoch it keeps when it only adds readers to that epoch and in a new
    /// one when it left a removal undone, or one moving a collection sealed
    /// to a group that dropped a reader to a new epoch — when it is of the
    /// collection's audience, and publish it; follow the groups this
    /// namespace's records name, so their readers can be checked and their
    /// removals heard.
    async fn settle(self: &Arc<Self>) {
        let mut signed = Vec::new();
        let follow = {
            let mut st = self.st.lock();
            // Signing takes records, which may owe more; a few rounds settle
            // any chain of groups.
            for _ in 0..8 {
                let owed = std::mem::take(&mut st.owed);
                if owed.is_empty() {
                    break;
                }
                for (c, why) in owed {
                    let Some(coll) = st.colls.get(&c) else {
                        continue;
                    };
                    let Some(current) = coll.members.clone() else {
                        continue;
                    };
                    let new_epoch = match (why, coll.resolve) {
                        (Owed::Merge, Resolve::Nothing) => continue,
                        (Owed::Merge, Resolve::Readers) => false,
                        (Owed::Merge, Resolve::Epoch) | (Owed::Group, _) => true,
                    };
                    if namespace_of(&c).as_ref() != Some(&self.ns) || !self.reads(&st, &c) {
                        tracing::debug!(collection = %c, ?why, "a new record is owed, by a device of its audience; not this one");
                        continue;
                    }
                    let record = self.next_members(
                        &st,
                        &c,
                        Some(&current),
                        current.rule.clone(),
                        current.writers.clone(),
                        current.readers.clone(),
                        new_epoch,
                    );
                    match self.append_members(&mut st, &c, record) {
                        Ok(()) => {
                            tracing::debug!(collection = %c, ?why, new_epoch, "signed the record owed");
                            signed.push(c);
                        }
                        Err(e) => {
                            tracing::warn!(collection = %c, "the record owed was not signed: {e}")
                        }
                    }
                }
            }
            std::mem::take(&mut st.to_follow)
        };
        for g in follow {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                if let Err(e) = inner.look(&g).await {
                    tracing::debug!(group = %g, "cannot follow the group: {e}");
                }
            });
        }
        for c in signed {
            if let Err(e) = self.publish_about(&c, &[]).await {
                tracing::debug!(collection = %c, "the record owed is not announced: {e}");
            }
        }
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
            if !inner.st.lock().holding.is_empty() {
                inner.renew().await;
            }
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
        let _ = tx.send((sync_group(ns), None)).await;
    }

    /// Start following `target`: join its namespace's group, and forget
    /// which summaries on the way to it were processed (they were processed
    /// without it). Returns whether it is new.
    async fn follow(self: &Arc<Self>, target: &Name) -> Result<bool, DataError> {
        wire::data_marker(target).map_err(|why| bad_name(target, why))?;
        let ns = namespace_of(target).expect("a data name has a namespace");
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
    /// to write into its namespace holds of it, for at most the first-look
    /// time.
    async fn look(self: &Arc<Self>, target: &Name) -> Result<(), DataError> {
        if !self.follow(target).await? {
            return Ok(());
        }
        let ns = namespace_of(target).expect("followed names have a namespace");
        let devices = self.known_for(&self.st.lock(), &ns);
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

    /// Refresh in the background every device known to write into `ns`.
    fn refresh_group(self: &Arc<Self>, ns: &Name) {
        let devices = self.known_for(&self.st.lock(), ns);
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
                .insert(root_prefix(device, ns), data.raw().clone());
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
        let Some(data) = self.fetch(root_prefix(device, ns), true).await else {
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
        if !self.descend(device, ns, &writer, body).await {
            return false;
        }
        self.st.lock().peers.entry(key).or_default().root = Some(digest);
        true
    }

    /// Process a verified node (or page) of `writer`'s summary of `ns`,
    /// published by `device`: its entries if followed, then its changed,
    /// relevant branches. Returns whether all of it was processed; what was
    /// is kept, so the next descent, from this root or a newer one, does not
    /// fetch it again.
    fn descend<'a>(
        self: &'a Arc<Self>,
        device: &'a Name,
        ns: &'a Name,
        writer: &'a Writer,
        body: NodeBody,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let subject = body.subject.clone();
            let path = body.page.clone().unwrap_or_default();
            // Entries, for a followed collection: its records first (a prune
            // among them spares fetching what it covers), then its versions.
            let mut records = Vec::new();
            let mut versions = Vec::new();
            let (children, pages) = {
                let mut st = self.st.lock();
                let inside = st.inside(&subject);
                if body.page.is_none() && inside {
                    let coll = st.colls.entry(subject.clone()).or_default();
                    coll.entries
                        .entry(writer.clone())
                        .or_default()
                        .extend(seqs_of(&body.entries));
                    coll.mark_pruned();
                    for seq in seqs_of(&body.members) {
                        let name = log_name(device, Some(&subject), seq);
                        if !st.held.contains_key(&name) && !st.refused.contains_key(&name) {
                            records.push(name);
                        }
                    }
                    for seq in seqs_of(&body.entries) {
                        versions.push(seq);
                    }
                    // Learned entries may make held versions ready.
                    st.apply_ready(&subject, &BTreeSet::new());
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
                                // The tree of `ns` runs through its `32=data`:
                                // any other child names no data of `ns`.
                                wire::data_marker(&sub) == Ok(ns.len())
                                    && (st.inside(&sub) || st.toward(&sub))
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

            let fetched = stream::iter(records)
                .map(|name| async move { self.take_fetched(name).await })
                .buffer_unordered(self.config.window)
                .collect::<Vec<_>>()
                .await;
            let versions: Vec<Name> = {
                let st = self.st.lock();
                let coll = st.colls.get(&subject);
                versions
                    .into_iter()
                    .filter(|seq| {
                        let id = VersionId {
                            writer: writer.clone(),
                            seq: Seq(*seq),
                        };
                        coll.is_none_or(|c| c.pruned(&id).is_none())
                    })
                    .map(|seq| log_name(device, Some(&subject), seq))
                    .filter(|name| !st.held.contains_key(name) && !st.refused.contains_key(name))
                    .collect()
            };
            let fetched_versions = stream::iter(versions)
                .map(|name| async move { self.take_fetched(name).await })
                .buffer_unordered(self.config.window)
                .collect::<Vec<_>>()
                .await;
            let entries_taken = fetched.iter().chain(&fetched_versions).all(|ok| *ok);

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
            .map(|(name, key, digest, head)| async move {
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
                if !self.descend(device, ns, writer, child).await {
                    return None;
                }
                self.st
                    .lock()
                    .peers
                    .entry((device.clone(), ns.clone()))
                    .or_default()
                    .nodes
                    .insert(key, digest);
                Some(())
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
        let (chase, fetch) = {
            let mut st = self.st.lock();
            let Some(record) = record else {
                return refuse(&mut st, Refusal::BadSignature);
            };
            let subject_ok = record.subject() == parsed.subject;
            if device_of(writer.key()).as_ref() != Some(&parsed.device) || !subject_ok {
                return refuse(&mut st, Refusal::BadSignature);
            }
            let members = matches!(record, Record::Members(_));
            let fetch = self.take(
                &mut st,
                name.clone(),
                data.raw().clone(),
                writer,
                record,
                false,
            );
            // A group's record decides who reads the collections sealed to
            // it: their keys may be asked for now.
            let mut chase = Vec::new();
            if let Some(c) = parsed.subject {
                if members && let Some(xs) = st.sealed_to.get(&c) {
                    chase.extend(xs.iter().cloned());
                }
                chase.push(c);
            }
            (chase, fetch)
        };
        for c in chase {
            self.chase_keys(&c);
        }
        if let Some((v, chunks)) = fetch {
            self.spawn_pieces(v, chunks);
        }
        self.settle().await;
        Ok(())
    }

    /// Ask, in the background, for every epoch key that a locked version of
    /// `c` needs, that is not held or being asked for, and that this device
    /// may hold ([`Self::may_hold`]).
    fn chase_keys(self: &Arc<Self>, c: &Name) {
        let epochs: BTreeSet<Epoch> = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else { return };
            if coll.locked.is_empty() {
                return;
            }
            coll.locked
                .iter()
                .map(|l| l.epoch().clone())
                .filter(|e| {
                    st.keys.key(c, e).is_none()
                        && !st.asking.contains(&(c.clone(), e.clone()))
                        && self.may_hold(&st, c, e, &self.device, &self.ns)
                })
                .collect()
        };
        for e in epochs {
            let (inner, c) = (Arc::clone(self), c.clone());
            rt::spawn(async move {
                inner.obtain(&c, &e).await;
            });
        }
    }

    /// Hold a verified log entry and let its collection take it. Records
    /// that are not versions, snapshots and own entries are stored now;
    /// others' versions once applied — or now, when this device holds their
    /// collection for its owner (spec §13). A version a known prune covers
    /// is dropped unseen. Returns a large version whose pieces this device,
    /// holding its collection, is to fetch.
    fn take(
        &self,
        st: &mut St,
        name: Name,
        wire: Bytes,
        writer: Writer,
        record: Record,
        mine: bool,
    ) -> Option<(Name, ChunksBody)> {
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
            return None;
        }
        if st.held.contains_key(&name) {
            return None;
        }
        let parsed = parse_log_name(&name)?;
        if record.subject() != parsed.subject {
            return None;
        }
        let id = VersionId {
            writer: writer.clone(),
            seq: Seq(parsed.seq),
        };
        if let (Record::Version(_), Some(c)) = (&record, &parsed.subject)
            && let Some(p) = st.colls.get(c).and_then(|x| x.pruned(&id)).cloned()
        {
            tracing::debug!(%name, "not taken: its writer pruned it");
            st.held.insert(name, Held::Pruned(p));
            return None;
        }
        let holding = parsed
            .subject
            .as_ref()
            .is_some_and(|c| st.holding.contains_key(c));
        let admitted = parsed
            .subject
            .as_ref()
            .and_then(|c| st.colls.get(c))
            .and_then(|x| x.members.as_ref())
            .is_none_or(|m| m.refusal(&id).is_none());
        if mine || !matches!(record, Record::Version(_)) || (holding && admitted) {
            self.store.insert(name.clone(), wire.clone());
        }
        if let Some(c) = &parsed.subject {
            if mine {
                let ns = namespace_of(c).expect("a log entry's collection has a namespace");
                let entry = match record {
                    Record::Version(_) => Entry::Version,
                    _ => Entry::Record,
                };
                st.trees
                    .entry(ns.clone())
                    .or_insert_with(|| Tree::new(ns))
                    .add(c, parsed.seq, entry);
            } else {
                self.note_peer_head(st, &parsed.device, c, parsed.seq);
            }
        }
        match record {
            Record::Members(body) => {
                st.held.insert(name.clone(), Held::Record);
                let c = body.collection.clone();
                let ns = namespace_of(&c).expect("a log entry's collection has a namespace");
                if owner_signed(self.validator.keyring(), &name, &ns) {
                    st.accept_members(parsed.seq, body, &writer, &self.config.rules, self.me());
                    // The rule may now be the log rule, which prune applies to.
                    let dropped = st.drop_pruned(&c);
                    self.entomb(&dropped);
                    self.erase(st, &c);
                } else {
                    tracing::debug!(collection = %c, signer = ?writer, "members record not signed by a device of the collection's namespace; ignored");
                }
                None
            }
            Record::Version(mut body) => {
                let c = body.collection.clone();
                let seq = parsed.seq;
                let sealed = body.sealed.is_some();
                let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
                let fetch = (holding && admitted)
                    .then(|| body.chunks.map(|ch| (name.clone(), ch)))
                    .flatten();
                if let Some(s) = body.sealed.clone() {
                    let Some(key) = st.keys.key(&c, &s.epoch) else {
                        st.held.insert(name.clone(), Held::Locked);
                        st.colls.entry(c).or_default().locked.push(Locked {
                            name,
                            wire,
                            writer,
                            seq,
                            body,
                        });
                        return fetch;
                    };
                    // A payload in pieces opens when it is read.
                    if body.chunks.is_none() {
                        let Some((fields, op)) = seal::open_payload(&key, &name, &s.ciphertext)
                        else {
                            tracing::debug!(%name, "refused: its payload does not open under its epoch's key");
                            st.refused.insert(name, Refusal::BadSignature);
                            return None;
                        };
                        body.fields = fields;
                        body.op = op;
                    }
                }
                let op = body.op.clone();
                let chunks = body.chunks;
                let version = version_of(&name, &writer, seq, body);
                st.held
                    .insert(name.clone(), Held::Version(version.id.clone()));
                st.admit(Arc::new(HeldVersion {
                    version,
                    op,
                    wire,
                    sealed,
                    epoch,
                    chunks,
                }));
                fetch
            }
            Record::Snapshot(pins) => {
                let snapshot = Snapshot {
                    id,
                    name: name.clone(),
                    pins,
                };
                st.held.insert(name, Held::Snapshot(snapshot));
                None
            }
            Record::Hold(body) => {
                st.held.insert(name.clone(), Held::Record);
                let c = body.collection.clone();
                let ns = namespace_of(&c).expect("a log entry's collection has a namespace");
                if !owner_signed(self.validator.keyring(), &name, &ns) {
                    tracing::debug!(collection = %c, signer = ?writer, "hold record not signed by a device of the collection's namespace; ignored");
                    return None;
                }
                let coll = st.colls.entry(c).or_default();
                if coll
                    .holds
                    .get(&writer)
                    .is_none_or(|(s, _, _)| *s < parsed.seq)
                {
                    coll.holds.insert(writer, (parsed.seq, name, body));
                }
                None
            }
            Record::Lease(body) => {
                st.held.insert(name.clone(), Held::Record);
                let c = body.collection.clone();
                if mine {
                    let h = st.holding.entry(c.clone()).or_insert_with(|| Holding {
                        hold: body.hold.clone(),
                        until: body.until,
                        lease: None,
                    });
                    h.hold = body.hold.clone();
                    h.lease = Some((body.holds.clone(), body.until));
                }
                let coll = st.colls.entry(c).or_default();
                if coll.leases.get(&writer).is_none_or(|l| l.seq < parsed.seq) {
                    coll.leases.insert(
                        writer,
                        LeaseHeld {
                            seq: parsed.seq,
                            name,
                            body,
                            audit: Audit::NotAudited,
                        },
                    );
                }
                None
            }
            Record::Prune(body) => {
                st.held.insert(name.clone(), Held::Record);
                let c = parsed.subject.clone()?;
                // Prune reaches only its signer's own writes (spec §14).
                let own_key = body.upto.iter().all(|(w, _)| *w == writer);
                let own_entry = parse_log_name(&body.prefix)
                    .is_none_or(|l| l.device == parsed.device && l.subject.as_ref() == Some(&c));
                if !own_key || !own_entry {
                    tracing::debug!(%name, "a prune record that names another key's writes; ignored");
                    return None;
                }
                let prune = Prune {
                    id,
                    name,
                    prefix: body.prefix,
                    upto: body.upto,
                };
                st.colls.entry(c.clone()).or_default().prunes.push(prune);
                let dropped = st.drop_pruned(&c);
                self.entomb(&dropped);
                self.erase(st, &c);
                None
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

    /// Sign `record` (a members record of `c` [`Self::next_members`] or
    /// [`Self::default_members`] made) into the own log; keep the key of the
    /// epoch it starts, if it starts one.
    fn append_members(
        &self,
        st: &mut St,
        c: &Name,
        (body, key): (MembersBody, Option<ContentKey>),
    ) -> Result<(), DataError> {
        let epoch = body.epoch.clone();
        self.append(st, Some(c), wire::encode_members(&body))?;
        if let (Some(e), Some(key)) = (epoch, key) {
            self.keep_made_key(st, c, e, key);
        }
        Ok(())
    }

    /// Hold `key`, which this device made as the key of epoch `e` of `c`,
    /// and keep it with what it holds: wrapped to its own recipient key,
    /// under a local name ([`made_key_name`]).
    fn keep_made_key(&self, st: &mut St, c: &Name, e: Epoch, key: ContentKey) {
        let name = made_key_name(&self.device, c, &e);
        match wrap_ck_to(&st.keys.recipient.public(), &key, &name.encode_to_tlv()) {
            Ok((ephemeral, wrapped)) => self
                .store
                .insert(name, wire::encode_grant(&ephemeral, &wrapped.to_bytes())),
            Err(why) => {
                tracing::warn!(collection = %c, epoch = ?e, "an epoch key made here is not kept for a restart: {why}");
            }
        }
        st.keys.hold(c.clone(), e, key);
    }

    /// A new epoch of `c` that the members record at this device's log seq
    /// `seq` starts: its key (32 random octets) and the key's check.
    fn new_epoch(&self, c: &Name, seq: u64) -> (Epoch, [u8; 32], ContentKey) {
        let epoch = Epoch {
            creator: self.device.clone(),
            seq: Seq(seq),
        };
        let key = ContentKey::generate();
        let check = seal::key_check(&key, c, &epoch);
        (epoch, check, key)
    }

    /// The host default for a collection of this device's own namespace that
    /// nobody shared: merge with `/merge/yrs`, written and read by the
    /// owner's namespace, sealed in an epoch this record (the own log's entry
    /// `seq`) starts; with the epoch's key.
    fn default_members(&self, c: &Name, seq: u64) -> (MembersBody, Option<ContentKey>) {
        let (epoch, check, key) = self.new_epoch(c, seq);
        let body = MembersBody {
            collection: c.clone(),
            revision: 1,
            rule: Rule::Merge {
                function: crate::merge::Yrs::new().function().clone(),
            },
            writers: vec![self.ns.clone()],
            readers: vec![Audience::Person(self.ns.clone())],
            cuts: Vec::new(),
            epoch: Some(epoch),
            key_check: Some(check),
            since: None,
            parent: None,
        };
        (body, Some(key))
    }

    /// The next members record of `c`, owned here, after `current` (spec
    /// §6, §8, §9), and the key of the epoch it starts, if it starts one: a
    /// writer prefix removed gets a cut accepting exactly the versions of
    /// its keys in `c` this device holds verified; a prefix written again
    /// drops its cut. A reader removed — or `new_epoch` — starts a new epoch
    /// at this record, with a new random key; no readers, no seal. A rule
    /// changed, or a seal on a collection that had none, sets `since` to
    /// what this device applied. The record names `current` as its parent.
    #[allow(clippy::too_many_arguments)]
    fn next_members(
        &self,
        st: &St,
        c: &Name,
        current: Option<&Members>,
        rule: Rule,
        writers: Vec<Name>,
        readers: Vec<Audience>,
        new_epoch: bool,
    ) -> (MembersBody, Option<ContentKey>) {
        let seq = st.head + 1;
        let coll = st.colls.get(c);
        let covered = |of: &Name| writers.iter().any(|p| of.has_prefix(p));
        let mut cuts: Vec<CutBody> = current
            .map(|m| {
                m.cuts
                    .iter()
                    .filter(|k| !covered(&k.of))
                    .map(|k| CutBody {
                        of: k.of.clone(),
                        accept: k.accept.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        for p in current
            .map(|m| m.writers.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|p| !covered(p))
        {
            // Exactly the versions held verified — never what a summary
            // only listed — that the record in force admits.
            let mut accept = Accepted::new();
            if let Some(coll) = coll {
                let held = coll
                    .versions
                    .keys()
                    .cloned()
                    .chain(coll.waiting.iter().map(|hv| hv.version.id.clone()))
                    .chain(coll.locked.iter().map(|l| VersionId {
                        writer: l.writer.clone(),
                        seq: Seq(l.seq),
                    }));
                for id in held {
                    if id.writer.key().has_prefix(p)
                        && current.is_none_or(|m| m.refusal(&id).is_none())
                    {
                        accept.insert(&id);
                    }
                }
            }
            cuts.retain(|k| k.of != *p);
            cuts.push(CutBody {
                of: p.clone(),
                accept,
            });
        }
        cuts.sort_by(|a, b| a.of.cmp(&b.of));
        let kept = current.and_then(|m| {
            let narrowed = m.readers.iter().any(|r| !readers.contains(r));
            (!new_epoch && !narrowed)
                .then(|| m.epoch.clone().zip(m.key_check))
                .flatten()
        });
        let (epoch, key_check, key) = match (readers.is_empty(), kept) {
            (true, _) => (None, None, None),
            (false, Some((e, check))) => (Some(e), Some(check), None),
            (false, None) => {
                let (e, check, key) = self.new_epoch(c, seq);
                (Some(e), Some(check), Some(key))
            }
        };
        let restarts = |m: &Members| m.rule != rule || (m.epoch.is_none() && epoch.is_some());
        let since = match current {
            Some(m) if restarts(m) => {
                let mut f = coll.map(Coll::at).unwrap_or_default();
                for (w, s) in m.since.iter().flat_map(Frontier::iter) {
                    f.include(&VersionId {
                        writer: w.clone(),
                        seq: s,
                    });
                }
                Some(f)
            }
            Some(m) => m.since.clone(),
            None => None,
        };
        let body = MembersBody {
            collection: c.clone(),
            revision: current.map_or(1, |m| m.revision.0 + 1),
            rule,
            writers,
            readers,
            cuts,
            epoch,
            key_check,
            since,
            parent: current.map(Members::as_parent),
        };
        (body, key)
    }

    // ---- serving ------------------------------------------------------------------------------

    async fn answer(self: Arc<Self>, interest: Interest, responder: Responder) {
        let name = (*interest.name).clone();
        if let Some((granter, ask)) = parse_grant_name(&name)
            && granter == self.device
        {
            // A grant fetches the asker's seal key first: its own task, so
            // the serving future stays free of fetches (wasm32 timers are
            // not `Send`).
            rt::spawn(async move {
                let reply = self.grant(&name, ask).await;
                self.reply(&name, responder, reply).await;
            });
            return;
        }
        if let Some((holder, record)) = parse_hold_ask_name(&name)
            && holder == self.device
        {
            // Taking a hold fetches the owner's record and the collection:
            // its own task.
            rt::spawn(async move {
                let reply = self.accept_hold(&name, &record).await;
                self.reply(&name, responder, reply).await;
            });
            return;
        }
        if let Some((holder, piece)) = parse_held_name(&name)
            && holder == self.device
        {
            let reply = self
                .packet_for(&piece, false)
                .map(|w| DataBuilder::new(name.clone(), &w).sign_digest_sha256());
            self.reply(&name, responder, reply).await;
            return;
        }
        if let Some((holder, ask)) = parse_audit_ask_name(&name)
            && holder == self.device
        {
            let reply = self.audit_answer(&name, &ask);
            self.reply(&name, responder, reply).await;
            return;
        }
        let reply = self.packet_for(&name, interest.selectors().can_be_prefix);
        self.reply(&name, responder, reply).await;
    }

    async fn reply(&self, name: &Name, responder: Responder, reply: Option<Bytes>) {
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
        // Own log entries and pieces of own versions; and, of a collection
        // this device holds for its owner, every entry and piece it keeps
        // (readers ask it for them under its own name, `32=held`).
        let log = parse_log_name(name).or_else(|| parse_piece_name(name).map(|p| p.log));
        if let Some(parsed) = log {
            if parsed.device == self.device {
                return self.store.get(name);
            }
            let st = self.st.lock();
            let held = parsed
                .subject
                .as_ref()
                .is_some_and(|c| st.holding.contains_key(c));
            if held && !matches!(st.held.get(&strip_piece(name)), Some(Held::Pruned(_))) {
                return self.store.get(name);
            }
            return None;
        }
        if let Some(s) = parse_summary_name(name)
            && s.device == self.device
        {
            let mut st = self.st.lock();
            let ns = subject_namespace(&s.subject)?;
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
        if let Some((device, public)) = parse_seal_key_name(name)
            && device == self.device
        {
            let mut st = self.st.lock();
            return (public == st.keys.recipient.public())
                .then(|| self.seal_key_packet(&mut st))
                .flatten();
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
            DataBuilder::new(root_name(&self.device, ns, head), &content).freshness(ROOT_FRESHNESS);
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

    // ---- seals --------------------------------------------------------------------------------

    /// This device's seal key packet `<D>/32=seal/<public key>`, signed
    /// once, when first asked for.
    fn seal_key_packet(&self, st: &mut St) -> Option<Bytes> {
        if let Some(p) = &st.seal_key {
            return Some(p.clone());
        }
        let public = st.keys.recipient.public();
        let name = seal_key_name(&self.device, &public);
        let wire = self
            .sign(DataBuilder::new(name, &wire::encode_seal_key(&public)))
            .ok()?;
        st.seal_key = Some(wire.clone());
        Some(wire)
    }

    /// Whether `device`, of namespace `dns`, is of the audience `readers`
    /// lists, in an epoch `creator` started (spec §9): the creator itself,
    /// or one a reader names — its person, itself, or a group (a
    /// collection) whose own newest record names either.
    fn admits(
        &self,
        st: &St,
        readers: &[Audience],
        creator: Option<&Name>,
        device: &Name,
        dns: &Name,
    ) -> bool {
        let direct = |a: &Audience| match a {
            Audience::Person(p) => p == dns,
            Audience::Device(d) => d == device,
            Audience::Group(_) => false,
        };
        creator == Some(device)
            || readers.iter().any(|a| match a {
                Audience::Group(g) => st
                    .colls
                    .get(g)
                    .and_then(|x| x.members.as_ref())
                    .is_some_and(|gm| gm.readers.iter().any(direct)),
                other => direct(other),
            })
    }

    /// Whether `device`, of namespace `dns`, is of `c`'s audience by the
    /// record in force: the readers it lists and the device that started
    /// its epoch.
    fn admits_reader(&self, st: &St, c: &Name, device: &Name, dns: &Name) -> bool {
        let Some(m) = st.colls.get(c).and_then(|x| x.members.as_ref()) else {
            return false;
        };
        let creator = m.epoch.as_ref().map(|e| &e.creator);
        self.admits(st, &m.readers, creator, device, dns)
    }

    /// Whether `device`, of namespace `dns`, may hold the key of epoch `e`
    /// of `c` (spec §9): a held owner-signed record of `c` names `e`, the
    /// readers those records list (or `e`'s creator) admit it, and so does
    /// the record in force when it seals `c`.
    fn may_hold(&self, st: &St, c: &Name, e: &Epoch, device: &Name, dns: &Name) -> bool {
        let Some(coll) = st.colls.get(c) else {
            return false;
        };
        let Some(named) = coll.epochs.get(e) else {
            return false;
        };
        self.admits(st, &named.readers, Some(&e.creator), device, dns)
            && coll
                .members
                .as_ref()
                .is_some_and(|m| m.epoch.is_none() || self.admits_reader(st, c, device, dns))
    }

    /// Whether this device reads `c`.
    fn reads(&self, st: &St, c: &Name) -> bool {
        self.admits_reader(st, c, &self.device, &self.ns)
    }

    /// Whether `c` is sealed and this device is not of its audience.
    fn sealed_off(&self, st: &St, c: &Name) -> bool {
        st.colls
            .get(c)
            .and_then(|x| x.members.as_ref())
            .is_some_and(|m| m.epoch.is_some())
            && !self.reads(st, c)
    }

    /// The key of epoch `e` of `c` to grant `asker`, of namespace
    /// `asker_ns`: held here, and the asker may hold it
    /// ([`Self::may_hold`]).
    fn grant_key(
        &self,
        st: &St,
        c: &Name,
        e: &Epoch,
        asker: &Name,
        asker_ns: &Name,
    ) -> Option<ContentKey> {
        if !self.may_hold(st, c, e, asker, asker_ns) {
            return None;
        }
        st.keys.key(c, e)
    }

    /// Answer a grant asked of this device (spec §9): check that the asker
    /// may hold the key of the epoch asked for and that it is held here
    /// ([`Self::grant_key`]), verify the asker's seal key, and wrap the key
    /// to it. One name, one packet while it is kept. `None` (a Nack)
    /// otherwise.
    async fn grant(self: &Arc<Self>, name: &Name, ask: GrantAsk) -> Option<Bytes> {
        let (asker, public) = parse_seal_key_name(&ask.seal_key)?;
        let asker_ns = self.namespace_of_name(&asker);
        let (c, e) = (&ask.collection, &ask.epoch);
        let verified = {
            let st = self.st.lock();
            if self.grant_key(&st, c, e, &asker, &asker_ns).is_none() {
                tracing::debug!(%asker, collection = %c, epoch = ?e, "grant refused: no record held names the epoch, the asker is not of its audience, or its key is not held here");
                return None;
            }
            if let Some(p) = st.grants.get(name) {
                return Some(p.clone());
            }
            st.seal_keys.get(&ask.seal_key).copied()
        };
        if verified.is_none() {
            let data = self.fetch(ask.seal_key.clone(), false).await?;
            let signer = self.verify(&data).await.ok()?;
            if *data.name != ask.seal_key
                || device_of(signer.key()).as_ref() != Some(&asker)
                || wire::decode_seal_key(data.content()?.clone()).ok()? != public
            {
                tracing::debug!(%asker, "grant refused: its seal key does not verify as its own");
                return None;
            }
        }
        let mut st = self.st.lock();
        st.seal_keys.insert(ask.seal_key.clone(), public);
        // Checked again: the records may have moved during the fetch.
        let key = self.grant_key(&st, c, e, &asker, &asker_ns)?;
        let (ephemeral, wrapped) = wrap_ck_to(&public, &key, &name.encode_to_tlv()).ok()?;
        let wire = self
            .sign(DataBuilder::new(
                name.clone(),
                &wire::encode_grant(&ephemeral, &wrapped.to_bytes()),
            ))
            .ok()?;
        st.grants.insert(name.clone(), wire.clone());
        Some(wire)
    }

    /// Get the key of epoch `e` of `c` (spec §9): from the epoch's creator,
    /// then from every other device known to write into `c`'s namespace. A
    /// granted key is taken only if it matches the key check of the held
    /// record naming the epoch. Opens what it unlocks. Whether the key is
    /// held now.
    async fn obtain(self: &Arc<Self>, c: &Name, e: &Epoch) -> bool {
        let Some(ns) = namespace_of(c) else {
            return false;
        };
        let seal_key = {
            let mut st = self.st.lock();
            if st.keys.key(c, e).is_some() {
                return true;
            }
            if !st.colls.get(c).is_some_and(|x| x.epochs.contains_key(e)) {
                // Nothing to check a key against: no record held names it.
                return false;
            }
            if !st.asking.insert((c.clone(), e.clone())) {
                return false;
            }
            seal_key_name(&self.device, &st.keys.recipient.public())
        };
        let ask = GrantAsk {
            seal_key,
            collection: c.clone(),
            epoch: e.clone(),
        };
        let mut granters = vec![e.creator.clone()];
        let others = self.known_for(&self.st.lock(), &ns);
        granters.extend(others.into_iter().filter(|d| *d != e.creator));
        let mut got = false;
        for granter in granters {
            if granter == self.device {
                continue;
            }
            let name = grant_name(&granter, &ask);
            let Some(data) = self.fetch(name.clone(), false).await else {
                continue;
            };
            let Ok(signer) = self.verify(&data).await else {
                continue;
            };
            if *data.name != name || device_of(signer.key()).as_ref() != Some(&granter) {
                continue;
            }
            let Some(content) = data.content().cloned() else {
                continue;
            };
            let mut st = self.st.lock();
            let Some(key) = open_grant(&st.keys.recipient, &name, content) else {
                continue;
            };
            if !st.take_key(c, e, key) {
                tracing::debug!(%granter, collection = %c, epoch = ?e, "refused: a granted key that does not match its epoch's key check");
                continue;
            }
            self.store.insert(name, data.raw().clone());
            got = true;
            break;
        }
        self.st.lock().asking.remove(&(c.clone(), e.clone()));
        if !got {
            tracing::debug!(collection = %c, epoch = ?e, "no device granted the epoch's key");
        }
        self.progress.notify_waiters();
        got
    }

    /// The key of `c`'s current epoch, for writing: obtained if this device
    /// reads `c` and lacks it. `Ok(None)` when `c` is not sealed.
    async fn write_key(
        self: &Arc<Self>,
        c: &Name,
    ) -> Result<Option<(Epoch, ContentKey)>, DataError> {
        let epoch = {
            let st = self.st.lock();
            let Some(e) = st
                .colls
                .get(c)
                .and_then(|x| x.members.as_ref())
                .and_then(|m| m.epoch.clone())
            else {
                return Ok(None);
            };
            if !self.reads(&st, c) {
                return Err(DataError::Sealed { name: c.clone() });
            }
            if let Some(k) = st.keys.key(c, &e) {
                return Ok(Some((e, k)));
            }
            e
        };
        if !self.obtain(c, &epoch).await {
            let (c2, e2) = (c.clone(), epoch.clone());
            self.wait_for(|st| st.keys.key(&c2, &e2).is_some()).await;
        }
        let st = self.st.lock();
        match st.keys.key(c, &epoch) {
            Some(k) => Ok(Some((epoch, k))),
            None => Err(DataError::Unavailable { name: c.clone() }),
        }
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

    /// The newest of `c` by its rule now, or why there is none: a merge
    /// collection's state; a log collection's newest version — of the
    /// versions applied that no other applied version names as a parent,
    /// the greatest by writer key and seq (spec §5).
    fn newest(&self, st: &St, c: &Name) -> Result<Got, DataError> {
        let Some(coll) = st.colls.get(c) else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        let Some(members) = &coll.members else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        if self.sealed_off(st, c) {
            return Err(DataError::Sealed { name: c.clone() });
        }
        let at = coll.at();
        match &members.rule {
            Rule::Merge { function } => {
                let Some(state) = &coll.state else {
                    return Err(local(format!(
                        "{c} merges with {function}, which this device does not run"
                    )));
                };
                Ok(Got::State(State {
                    name: state_name(c, &at),
                    collection: c.clone(),
                    at,
                    value: state.value(),
                }))
            }
            Rule::Log => {
                let since = members.since.as_ref();
                let applied: Vec<&Version> = coll
                    .versions
                    .values()
                    .map(|hv| &hv.version)
                    .filter(|v| at.contains(&v.id) && !since.is_some_and(|s| s.contains(&v.id)))
                    .collect();
                applied
                    .iter()
                    .filter(|v| {
                        !applied
                            .iter()
                            .any(|w| w.id != v.id && w.parents.contains(&v.id))
                    })
                    .max_by(|a, b| a.id.cmp(&b.id))
                    .map(|v| Got::Version((*v).clone()))
                    .ok_or_else(|| DataError::Unavailable { name: c.clone() })
            }
            Rule::OneKey => Err(local(format!(
                "{c} uses the one-key rule, which is data-layer slice 4; this device reads the \
                 merge and log rules"
            ))),
        }
    }

    async fn get_log_entry(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let answer = |st: &St| -> Option<Result<Answer, DataError>> {
            if let Some(why) = st.refused.get(name) {
                return Some(Err(refused(name, why.clone())));
            }
            let Some(held) = st.held.get(name) else {
                // Not held: a prune known here may cover it all the same.
                return pruned_name(st, name).map(|by| {
                    Err(DataError::Pruned {
                        name: name.clone(),
                        by,
                    })
                });
            };
            Some(match held {
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
                Held::Locked => {
                    let c = parse_log_name(name)?.subject?;
                    if self.reads(st, &c) {
                        return None;
                    }
                    Err(DataError::Sealed { name: name.clone() })
                }
                Held::Record => Err(DataError::NotFound { name: name.clone() }),
                Held::Pruned(by) => Err(DataError::Pruned {
                    name: name.clone(),
                    by: by.clone(),
                }),
            })
        };
        let found = answer(&self.st.lock());
        if let Some(a) = found {
            return self.whole(a).await;
        }
        let parsed =
            parse_log_name(name).ok_or_else(|| DataError::NotFound { name: name.clone() })?;
        if let Some(c) = &parsed.subject {
            self.look(c).await?;
        }
        let found = answer(&self.st.lock());
        if let Some(a) = found {
            return self.whole(a).await;
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
            self.wait_for(|st| {
                st.colls.get(&c).is_some_and(|coll| coll.members.is_some())
                    && !matches!(st.held.get(name), Some(Held::Locked))
            })
            .await;
        }
        let found = answer(&self.st.lock())
            .unwrap_or_else(|| Err(DataError::Unavailable { name: name.clone() }));
        self.whole(found).await
    }

    /// An answer with its version read whole: a large payload fetched in
    /// pieces ([`Self::materialize`]).
    async fn whole(self: &Arc<Self>, a: Result<Answer, DataError>) -> Result<Answer, DataError> {
        match a? {
            Answer {
                got: Got::Version(v),
                age,
            } => Ok(Answer {
                got: Got::Version(self.materialize(v).await?),
                age,
            }),
            other => Ok(other),
        }
    }
}

/// How an audit checks one piece: the digest the holder's answer must have.
struct Ask {
    piece: Name,
    digest: [u8; 32],
}

impl Inner {
    // ---- large payloads -----------------------------------------------------------------------

    /// The devices whose live leases this device knows hold `c`, by name,
    /// this device excluded: where pieces are fetched from by forwarding
    /// hint when their writer no longer serves them.
    fn holders_of(&self, st: &St, c: &Name) -> Vec<Name> {
        let now = (self.config.clock)();
        let Some(coll) = st.colls.get(c) else {
            return Vec::new();
        };
        let mut out: Vec<Name> = coll
            .leases
            .iter()
            .filter(|(_, l)| lease_refusal(coll, &l.body).is_none() && l.body.until > now)
            .filter_map(|(h, _)| device_of(h.key()))
            .filter(|d| *d != self.device)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Fetch `name`, another device's packet, from `holder`, which keeps
    /// it for that device's collection: asked under the holder's own name
    /// ([`wire::held_name`]), answered with the packet inside.
    async fn fetch_held(&self, name: &Name, holder: &Name) -> Option<Data> {
        let reply = self.fetch(wire::held_name(holder, name), false).await?;
        let inner = Data::decode(reply.content()?.clone()).ok()?;
        (*inner.name == *name).then_some(inner)
    }

    /// Piece `name` of a large version of `c`, checked against `digest`:
    /// from the store, else from its writer by name, else from each holder
    /// of `c` ([`Self::fetch_held`]); stored once found.
    async fn get_piece(
        self: &Arc<Self>,
        c: &Name,
        name: &Name,
        digest: &[u8; 32],
    ) -> Option<Bytes> {
        self.get_piece_from(c, name, digest, None)
            .await
            .map(|(w, _)| w)
    }

    /// [`Self::get_piece`], trying `first` before the others, and saying
    /// which source answered (`None`: its writer by name; `Some(h)`: holder
    /// `h`). The store answers first whatever `first` says.
    async fn get_piece_from(
        self: &Arc<Self>,
        c: &Name,
        name: &Name,
        digest: &[u8; 32],
        first: Option<&Option<Name>>,
    ) -> Option<(Bytes, Option<Name>)> {
        if let Some(w) = self.store.get(name)
            && wire::implicit_digest(&w) == *digest
        {
            return Some((w, None));
        }
        let holders = self.holders_of(&self.st.lock(), c);
        // An Interest for this device's own name goes nowhere useful: its
        // own pieces it released are asked of the holders only.
        let own = parse_piece_name(name).is_some_and(|p| p.log.device == self.device);
        let mut sources: Vec<Option<Name>> = if own { Vec::new() } else { vec![None] };
        sources.extend(holders.into_iter().map(Some));
        if let Some(f) = first
            && let Some(i) = sources.iter().position(|s| s == f)
        {
            let f = sources.remove(i);
            sources.insert(0, f);
        }
        for source in sources {
            let data = match &source {
                None => self.fetch(name.clone(), false).await,
                Some(h) => self.fetch_held(name, h).await,
            };
            let Some(data) = data else { continue };
            if *data.name != *name || wire::implicit_digest(data.raw()) != *digest {
                tracing::debug!(%name, "not the piece its manifest lists; fetched elsewhere");
                continue;
            }
            let w = data.raw().clone();
            self.store.insert(name.clone(), w.clone());
            return Some((w, source));
        }
        None
    }

    /// Walk the pieces of the large version `v` of `c`: every manifest node
    /// and chunk, each checked against the digest its parent lists, the
    /// root against the record's. With `assemble`, the payload; without,
    /// an empty one once every piece is held. `None` when a piece is not to
    /// be had.
    async fn walk_pieces(
        self: &Arc<Self>,
        v: &Name,
        c: &Name,
        chunks: ChunksBody,
        assemble: bool,
    ) -> Option<Vec<u8>> {
        let shape = Shape::of(chunks.size);
        let mut digests: HashMap<PieceKind, [u8; 32]> = HashMap::new();
        digests.insert(PieceKind::Manifest(0), chunks.root);
        for k in shape.manifests() {
            let kind = PieceKind::Manifest(k);
            let expected = *digests.get(&kind)?;
            let w = self.get_piece(c, &piece_name(v, kind), &expected).await?;
            let listed = pieces::open_node(&shape, k, &w, &expected)?;
            for (kid, d) in shape.children(k)?.into_iter().zip(listed) {
                digests.insert(kid, d);
            }
        }
        // The source is chosen per version, from what answered: the first
        // chunk is asked alone (the writer first, then each holder), and
        // every other chunk goes first to whoever answered it — a writer that
        // released its chunks costs one miss, not one per chunk.
        let first_digest = *digests.get(&PieceKind::Chunk(0))?;
        let (first_wire, source) = self
            .get_piece_from(c, &piece_name(v, PieceKind::Chunk(0)), &first_digest, None)
            .await?;
        let first_chunk = if assemble {
            pieces::open_chunk(&shape, 0, &first_wire, &first_digest)?
        } else {
            Bytes::new()
        };
        let digests = &digests;
        let source = &source;
        let rest: Vec<Option<Bytes>> = stream::iter(1..shape.chunks)
            .map(|i| async move {
                let kind = PieceKind::Chunk(i);
                let d = *digests.get(&kind)?;
                let (w, _) = self
                    .get_piece_from(c, &piece_name(v, kind), &d, Some(source))
                    .await?;
                if assemble {
                    pieces::open_chunk(&shape, i, &w, &d)
                } else {
                    Some(Bytes::new())
                }
            })
            .buffered(self.config.window)
            .collect()
            .await;
        let mut out = Vec::with_capacity(if assemble { chunks.size as usize } else { 0 });
        out.extend_from_slice(&first_chunk);
        for g in rest {
            out.extend_from_slice(&g?);
        }
        Some(out)
    }

    /// Whether every piece of the large version `v` is in the store.
    fn pieces_held(&self, v: &Name, chunks: &ChunksBody) -> bool {
        let shape = Shape::of(chunks.size);
        shape
            .manifests()
            .map(PieceKind::Manifest)
            .chain((0..shape.chunks).map(PieceKind::Chunk))
            .all(|k| self.store.get(&piece_name(v, k)).is_some())
    }

    /// Read version `v` whole: a large payload is fetched piece by piece
    /// and opened (spec §4.1); any other is returned as it is.
    async fn materialize(self: &Arc<Self>, v: Version) -> Result<Version, DataError> {
        if !matches!(v.payload, Payload::Large { .. }) {
            return Ok(v);
        }
        let unavailable = || DataError::Unavailable {
            name: v.name.clone(),
        };
        let (chunks, epoch) = {
            let st = self.st.lock();
            let hv = st
                .colls
                .get(&v.collection)
                .and_then(|x| x.versions.get(&v.id))
                .ok_or_else(unavailable)?;
            (hv.chunks.ok_or_else(unavailable)?, hv.epoch.clone())
        };
        let payload = self
            .walk_pieces(&v.name, &v.collection, chunks, true)
            .await
            .ok_or_else(unavailable)?;
        let bad = || refused(&v.name, Refusal::BadSignature);
        let (fields, _) = match epoch {
            Some(e) => {
                let key = self.st.lock().keys.key(&v.collection, &e).ok_or_else(|| {
                    DataError::Sealed {
                        name: v.name.clone(),
                    }
                })?;
                seal::open_payload(&key, &v.name, &payload).ok_or_else(bad)?
            }
            None => wire::decode_payload(Bytes::from(payload)).map_err(|_| bad())?,
        };
        Ok(Version {
            payload: Payload::Entry(fields),
            ..v
        })
    }

    /// Fetch, as a holder of its collection, every piece of the large
    /// version `v` it keeps, in the background; then renew its leases.
    fn spawn_pieces(self: &Arc<Self>, v: Name, chunks: ChunksBody) {
        if !self.st.lock().fetching.insert(v.clone()) {
            return;
        }
        let inner = Arc::clone(self);
        rt::spawn(async move {
            if let Some(c) = parse_log_name(&v).and_then(|l| l.subject)
                && inner.walk_pieces(&v, &c, chunks, false).await.is_none()
            {
                tracing::debug!(name = %v, "not every piece of a held version is to be had yet");
            }
            inner.st.lock().fetching.remove(&v);
            inner.progress.notify_waiters();
            inner.renew().await;
        });
    }

    // ---- prune and erasure --------------------------------------------------------------------

    /// Keep a tombstone for each own version among `names` that was just
    /// pruned: its summary goes on listing it after a restart.
    fn entomb(&self, names: &[Name]) {
        for n in names {
            if parse_log_name(n).is_some_and(|l| l.device == self.device) {
                self.store.insert(tomb_name(n), Bytes::new());
            }
        }
    }

    /// Destroy the key of every epoch of `c` whose versions are all pruned
    /// (spec §14): not the epoch of the record in force, at least one of
    /// its versions pruned, and every version of `c` this device knows of
    /// held (so its epoch is known) and either pruned or of another epoch.
    /// The held key, the key this device made and every grant it keeps of
    /// that epoch go; a key granted again is refused.
    fn erase(&self, st: &mut St, c: &Name) {
        let Some(coll) = st.colls.get(c) else {
            return;
        };
        let current = coll.members.as_ref().and_then(|m| m.epoch.clone());
        let epoch_of = |id: &VersionId| -> Option<Option<Epoch>> {
            if let Some(hv) = coll.versions.get(id) {
                return Some(hv.epoch.clone());
            }
            if let Some(l) = coll
                .locked
                .iter()
                .find(|l| l.writer == id.writer && l.seq == id.seq.0)
            {
                return Some(Some(l.epoch().clone()));
            }
            coll.waiting
                .iter()
                .chain(&coll.outsiders)
                .find(|hv| hv.version.id == *id)
                .map(|hv| hv.epoch.clone())
        };
        let mut gone = Vec::new();
        'epochs: for e in coll.epochs.keys() {
            if Some(e) == current.as_ref() || coll.erased.contains(e) || st.keys.key(c, e).is_none()
            {
                continue;
            }
            if !coll
                .pruned_keeps
                .values()
                .any(|(_, ep)| ep.as_ref() == Some(e))
            {
                continue;
            }
            for (w, seqs) in &coll.entries {
                for s in seqs {
                    let id = VersionId {
                        writer: w.clone(),
                        seq: Seq(*s),
                    };
                    if coll.pruned_keeps.contains_key(&id) {
                        continue;
                    }
                    match epoch_of(&id) {
                        Some(Some(x)) if x == *e => continue 'epochs,
                        Some(_) => {}
                        None if coll.skips(&id) => {}
                        None => continue 'epochs,
                    }
                }
            }
            gone.push(e.clone());
        }
        if gone.is_empty() {
            return;
        }
        let coll = st.colls.get_mut(c).expect("held above");
        for e in &gone {
            coll.erased.insert(e.clone());
        }
        for e in gone {
            st.keys.forget(c, &e);
            self.store.remove(&made_key_name(&self.device, c, &e));
            for (n, _) in self.store.scan_under(&Name::root(), 0) {
                if let Some((_, ask)) = parse_grant_name(&n)
                    && ask.collection == *c
                    && ask.epoch == e
                {
                    self.store.remove(&n);
                }
            }
            tracing::info!(collection = %c, epoch = ?e, "erased: every version of the epoch is pruned; its key is destroyed");
        }
    }

    // ---- holding ------------------------------------------------------------------------------

    /// Whether the store keeps version `id` of `c` whole: its record and,
    /// in pieces, every piece.
    fn keeps(&self, coll: &Coll, id: &VersionId) -> bool {
        let found = coll
            .versions
            .get(id)
            .map(|hv| (hv.version.name.clone(), hv.chunks))
            .or_else(|| {
                coll.locked
                    .iter()
                    .find(|l| l.writer == id.writer && l.seq == id.seq.0)
                    .map(|l| (l.name.clone(), l.body.chunks))
            });
        let Some((name, chunks)) = found else {
            return false;
        };
        self.store.get(&name).is_some() && chunks.is_none_or(|ch| self.pieces_held(&name, &ch))
    }

    /// What this device keeps of `c`, by its store (spec §13): per writer,
    /// the highest seq up to which every version is kept whole here or
    /// never applies.
    fn held_frontier(&self, st: &St, c: &Name) -> Frontier {
        let Some(coll) = st.colls.get(c) else {
            return Frontier::new();
        };
        let mut writers: Vec<&Writer> = coll.entries.keys().collect();
        writers.sort();
        let mut out = Frontier::new();
        for w in writers {
            let mut top = 0;
            for s in &coll.entries[w] {
                let id = VersionId {
                    writer: w.clone(),
                    seq: Seq(*s),
                };
                if !coll.skips(&id) && !self.keeps(coll, &id) {
                    break;
                }
                top = *s;
            }
            if top > 0 {
                out.include(&VersionId {
                    writer: w.clone(),
                    seq: Seq(top),
                });
            }
        }
        out
    }

    /// Sign a lease of `c`, held here, for what the store keeps of it, until
    /// the owner's date or the latest keep of what it holds, whichever is
    /// first; the newest lease again when nothing changed. `None` when it
    /// would promise nothing past now. The lease's wire, and whether it is
    /// new.
    fn sign_lease(&self, st: &mut St, c: &Name) -> Option<(Bytes, bool)> {
        let holds = self.held_frontier(st, c);
        let h = st.holding.get(c)?;
        let coll = st.colls.get(c)?;
        let cap = keep_cap(coll, &holds).ok()?;
        let until = cap.map_or(h.until, |t| t.min(h.until));
        if until <= (self.config.clock)() {
            tracing::debug!(collection = %c, "no lease: what it would hold is past its keep");
            return None;
        }
        let hold = h.hold.clone();
        if h.lease.as_ref() == Some(&(holds.clone(), until))
            && let Some(l) = coll.leases.get(&self.writer)
            && l.body.hold == hold
            && let Some(w) = self.store.get(&l.name)
        {
            return Some((w, false));
        }
        let body = LeaseBody {
            collection: c.clone(),
            hold,
            until,
            holds,
        };
        let (name, _) = self
            .append(st, Some(c), wire::encode_lease(&body))
            .map_err(|e| tracing::warn!(collection = %c, "the lease was not signed: {e}"))
            .ok()?;
        Some((self.store.get(&name)?, true))
    }

    /// Sign a new lease of every collection held whose kept frontier grew
    /// past its newest lease, and announce it.
    async fn renew(self: &Arc<Self>) {
        let signed: Vec<Name> = {
            let mut st = self.st.lock();
            let held: Vec<Name> = st.holding.keys().cloned().collect();
            let mut out = Vec::new();
            for c in held {
                let now = self.held_frontier(&st, &c);
                let grew = match st.holding.get(&c).and_then(|h| h.lease.as_ref()) {
                    Some((before, _)) => now != *before && now.covers(before),
                    None => !now.is_empty(),
                };
                if grew && self.sign_lease(&mut st, &c).is_some_and(|(_, new)| new) {
                    out.push(c);
                }
            }
            out
        };
        for c in signed {
            if let Err(e) = self.publish_about(&c, &[]).await {
                tracing::debug!(collection = %c, "a renewed lease is not announced: {e}");
            }
        }
    }

    /// Fetch back what this holder lost of `c`: records from what it holds
    /// in memory, pieces from their writer or other holders.
    async fn repair_held(self: &Arc<Self>, c: &Name) {
        let large: Vec<(Name, ChunksBody)> = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else {
                return;
            };
            let mut large = Vec::new();
            for hv in coll.versions.values() {
                if self.store.get(&hv.version.name).is_none() {
                    self.store.insert(hv.version.name.clone(), hv.wire.clone());
                }
                if let Some(ch) = hv.chunks {
                    large.push((hv.version.name.clone(), ch));
                }
            }
            for l in &coll.locked {
                if self.store.get(&l.name).is_none() {
                    self.store.insert(l.name.clone(), l.wire.clone());
                }
                if let Some(ch) = l.body.chunks {
                    large.push((l.name.clone(), ch));
                }
            }
            large
        };
        let todo: Vec<_> = large
            .into_iter()
            .filter(|(v, ch)| !self.pieces_held(v, ch))
            .collect();
        stream::iter(todo)
            .map(|(v, ch)| async move {
                let _ = self.walk_pieces(&v, c, ch, false).await;
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
    }

    /// Answer an owner's hold ask (spec §13): verify its hold record (an
    /// owner device's, of a namespace this device holds for, asking past
    /// now), hold the collection, take it and every piece of it inside the
    /// record's frontier (fetching back what was lost), and answer with the
    /// lease, signed. `None` (a Nack) otherwise.
    async fn accept_hold(self: &Arc<Self>, ask: &Name, record: &Name) -> Option<Bytes> {
        let parsed = parse_log_name(record)?;
        let c = parsed.subject.clone()?;
        let ns = namespace_of(&c)?;
        if !self.config.hold_for.contains(&ns) {
            tracing::debug!(collection = %c, "hold refused: this device holds for none of its namespace");
            return None;
        }
        if !self.st.lock().held.contains_key(record) {
            let data = self.fetch(record.clone(), false).await?;
            self.take_data(record, data).await.ok()?;
        }
        let body = {
            let st = self.st.lock();
            st.colls
                .get(&c)?
                .holds
                .values()
                .find(|(_, n, _)| n == record)
                .map(|(_, _, b)| b.clone())
        };
        let Some(body) = body else {
            tracing::debug!(%record, "hold refused: not an owner device's hold record");
            return None;
        };
        if body.until <= (self.config.clock)() {
            tracing::debug!(%record, "hold refused: it asks for nothing past now");
            return None;
        }
        {
            let mut st = self.st.lock();
            let h = st.holding.entry(c.clone()).or_insert_with(|| Holding {
                hold: record.clone(),
                until: body.until,
                lease: None,
            });
            h.hold = record.clone();
            h.until = body.until;
        }
        self.look(&c).await.ok()?;
        // The asker moved since a first look: see what it has now.
        self.refresh(&ns, &parsed.device).await;
        self.repair_held(&c).await;
        let at = body.at.clone();
        self.wait_for(|st| {
            st.colls
                .get(&c)
                .is_some_and(|coll| reaches(coll, &self.held_frontier(st, &c), &at))
        })
        .await;
        let (lease, new) = {
            let mut st = self.st.lock();
            self.sign_lease(&mut st, &c)?
        };
        if new && let Err(e) = self.publish_about(&c, &[]).await {
            tracing::debug!(collection = %c, "the lease is not announced: {e}");
        }
        Some(DataBuilder::new(ask.clone(), &lease).sign_digest_sha256())
    }

    /// Answer an audit ask of a collection this device holds (spec §13):
    /// the piece asked for, from the store, or that it is missing; signed
    /// by the device key, under the ask's own name, so no cache answers it
    /// and nothing answers it but this device. `None` (a Nack) for a
    /// collection it does not hold.
    fn audit_answer(&self, name: &Name, ask: &AuditAsk) -> Option<Bytes> {
        let log =
            parse_log_name(&ask.piece).or_else(|| parse_piece_name(&ask.piece).map(|p| p.log))?;
        let c = log.subject?;
        let pruned = {
            let st = self.st.lock();
            if !st.holding.contains_key(&c) {
                return None;
            }
            matches!(st.held.get(&strip_piece(&ask.piece)), Some(Held::Pruned(_)))
        };
        let answer = match self.store.get(&ask.piece) {
            Some(w) if !pruned => AuditAnswer::Piece(w),
            _ => AuditAnswer::Missing,
        };
        self.sign(
            DataBuilder::new(name.clone(), &wire::encode_audit_answer(&answer))
                .freshness(Duration::ZERO),
        )
        .ok()
    }

    // ---- custody, the owner's side ----------------------------------------------------------

    /// Uniform random index below `n`, from the device's entropy.
    fn draw(&self, n: usize) -> usize {
        let n = n as u64;
        let zone = u64::MAX - u64::MAX % n;
        loop {
            let mut b = [0u8; 8];
            (self.config.entropy)(&mut b);
            let v = u64::from_be_bytes(b);
            if v < zone {
                return (v % n) as usize;
            }
        }
    }

    /// Every piece the lease of `holder` on `c` promises (spec §13): of
    /// each version inside it that applies and whose keep has not passed,
    /// its log entry and, in pieces, every manifest node and chunk — each
    /// with the digest the holder's answer must have. Manifest nodes not in
    /// the store are fetched (checked against the record) to learn the
    /// chunks' digests.
    async fn promised(self: &Arc<Self>, c: &Name, holder: &Writer) -> Vec<Ask> {
        let now = (self.config.clock)();
        let versions: Vec<(Name, [u8; 32], Option<ChunksBody>)> = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else {
                return Vec::new();
            };
            let Some(lease) = coll.leases.get(holder) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            for (w, upto) in lease.body.holds.iter() {
                let Some(seqs) = coll.entries.get(w) else {
                    continue;
                };
                for s in seqs.range(..=upto.0) {
                    let id = VersionId {
                        writer: w.clone(),
                        seq: Seq(*s),
                    };
                    if coll.skips(&id) {
                        continue;
                    }
                    let found = coll
                        .versions
                        .get(&id)
                        .map(|hv| {
                            (
                                hv.version.name.clone(),
                                hv.wire.clone(),
                                hv.chunks,
                                hv.version.keep,
                            )
                        })
                        .or_else(|| {
                            coll.locked
                                .iter()
                                .find(|l| l.writer == *w && l.seq == *s)
                                .map(|l| {
                                    (l.name.clone(), l.wire.clone(), l.body.chunks, l.body.keep)
                                })
                        });
                    let Some((name, w, chunks, keep)) = found else {
                        continue;
                    };
                    if matches!(keep, Keep::Until(t) if t <= now) {
                        continue;
                    }
                    out.push((name, wire::implicit_digest(&w), chunks));
                }
            }
            out
        };
        let mut asks = Vec::new();
        for (name, digest, chunks) in versions {
            asks.push(Ask {
                piece: name.clone(),
                digest,
            });
            let Some(chunks) = chunks else { continue };
            let shape = Shape::of(chunks.size);
            let mut digests: HashMap<PieceKind, [u8; 32]> = HashMap::new();
            digests.insert(PieceKind::Manifest(0), chunks.root);
            let mut whole = true;
            for k in shape.manifests() {
                let kind = PieceKind::Manifest(k);
                let Some(expected) = digests.get(&kind).copied() else {
                    whole = false;
                    break;
                };
                let listed = match self.get_piece(c, &piece_name(&name, kind), &expected).await {
                    Some(w) => pieces::open_node(&shape, k, &w, &expected),
                    None => None,
                };
                let Some(listed) = listed else {
                    whole = false;
                    break;
                };
                for (kid, d) in shape
                    .children(k)
                    .unwrap_or_default()
                    .into_iter()
                    .zip(listed)
                {
                    digests.insert(kid, d);
                }
            }
            if !whole {
                tracing::debug!(%name, "its manifest is not to be had; its pieces are not audited");
                continue;
            }
            let mut pieces: Vec<(PieceKind, [u8; 32])> = digests.into_iter().collect();
            pieces.sort();
            asks.extend(pieces.into_iter().map(|(k, d)| Ask {
                piece: piece_name(&name, k),
                digest: d,
            }));
        }
        asks
    }

    /// Audit the lease of `holder` on `c` (spec §13): ask for random pieces
    /// of what it promises, each under a fresh nonce, and check every
    /// answer: signed by the holder, and the piece. The verdict is kept
    /// with the lease.
    async fn audit(self: &Arc<Self>, c: &Name, holder: &Writer) -> Audit {
        let Some(device) = device_of(holder.key()) else {
            return Audit::NotAudited;
        };
        let mut all = self.promised(c, holder).await;
        let k = self.config.audit_pieces.min(all.len());
        let mut picked = Vec::with_capacity(k);
        for _ in 0..k {
            let i = self.draw(all.len());
            picked.push(all.swap_remove(i));
        }
        let asked = picked.len() as u32;
        let device = &device;
        let answers: Vec<Option<Result<(), (Name, Breach)>>> = stream::iter(picked)
            .map(|a| async move {
                let mut nonce = [0u8; wire::NONCE_LEN];
                (self.config.entropy)(&mut nonce);
                let name = audit_ask_name(
                    device,
                    &AuditAsk {
                        nonce,
                        piece: a.piece.clone(),
                    },
                );
                let data = self.fetch(name.clone(), false).await?;
                if *data.name != name {
                    return None;
                }
                let signer = self.verify(&data).await.ok()?;
                if device_of(signer.key()).as_ref() != Some(device) {
                    return None;
                }
                let answer = data
                    .content()
                    .and_then(|b| wire::decode_audit_answer(b.clone()).ok());
                Some(match answer {
                    Some(AuditAnswer::Piece(w)) if wire::implicit_digest(&w) == a.digest => Ok(()),
                    Some(AuditAnswer::Missing) => Err((a.piece, Breach::Missing)),
                    _ => Err((a.piece, Breach::Wrong)),
                })
            })
            .buffer_unordered(self.config.window)
            .collect()
            .await;
        let answered = answers.iter().filter(|a| matches!(a, Some(Ok(())))).count() as u32;
        let breach = answers
            .into_iter()
            .flatten()
            .filter_map(Result::err)
            .min_by(|a, b| a.0.cmp(&b.0));
        let audit = match breach {
            Some((piece, breach)) => Audit::Broken { piece, breach },
            None if answered == asked => Audit::Kept { pieces: asked },
            None => Audit::Unanswered { asked, answered },
        };
        if let Some(l) = self
            .st
            .lock()
            .colls
            .get_mut(c)
            .and_then(|x| x.leases.get_mut(holder))
        {
            l.audit = audit.clone();
        }
        tracing::debug!(collection = %c, holder = %device, ?audit, "audited");
        audit
    }

    /// Ask `holder` to hold `c` under the hold record `record`; whether it
    /// answered with a lease, which is then taken.
    async fn ask_hold(self: &Arc<Self>, holder: &Name, record: &Name) -> bool {
        let name = hold_ask_name(holder, record);
        // The holder answers once it took what the record asks, which may
        // take it a first look and a fetch of every piece.
        let b = InterestBuilder::new(name.clone())
            .lifetime(self.config.first_look * 3 + self.config.lifetime);
        let reply = {
            let Ok(_slot) = self.slots.acquire().await else {
                return false;
            };
            Consumer::new(self.node.connection()).fetch_with(b).await
        };
        let Ok(reply) = reply else {
            tracing::debug!(%holder, "no lease: the device did not answer the hold ask");
            return false;
        };
        let Some(lease) = reply.content().and_then(|w| Data::decode(w.clone()).ok()) else {
            return false;
        };
        let lease_name = (*lease.name).clone();
        if parse_log_name(&lease_name).is_none_or(|l| l.device != *holder) {
            return false;
        }
        self.take_data(&lease_name, lease).await.is_ok()
    }

    /// The leases of `c` this device counts (spec §13): not its own, not
    /// refused, live by its clock.
    fn live_leases(&self, st: &St, c: &Name) -> Vec<Writer> {
        let now = (self.config.clock)();
        let Some(coll) = st.colls.get(c) else {
            return Vec::new();
        };
        coll.leases
            .iter()
            .filter(|(h, l)| {
                **h != self.writer && l.body.until > now && {
                    let why = lease_refusal(coll, &l.body);
                    if let Some(why) = why {
                        tracing::debug!(lease = %l.name, "lease not counted: {why}");
                    }
                    why.is_none()
                }
            })
            .map(|(h, _)| h.clone())
            .collect()
    }

    fn lease_of(&self, st: &St, c: &Name, holder: &Writer) -> Option<Lease> {
        let l = st.colls.get(c)?.leases.get(holder)?;
        Some(Lease {
            holder: holder.clone(),
            name: l.name.clone(),
            prefix: c.clone(),
            holds: l.body.holds.clone(),
            until: l.body.until,
            audit: l.audit.clone(),
        })
    }
}

/// Why a reader does not count a lease (spec §13), if it does not: the
/// owner's hold record it answers is not held, it promises past that
/// record's date, or past the latest keep of the versions it holds (or that
/// keep is not known yet).
fn lease_refusal(coll: &Coll, l: &LeaseBody) -> Option<&'static str> {
    let Some((_, _, hold)) = coll.holds.values().find(|(_, n, _)| *n == l.hold) else {
        return Some("the owner's hold record it answers is not held here");
    };
    if l.until > hold.until {
        return Some("it promises past the date the owner asked for");
    }
    match keep_cap(coll, &l.holds) {
        Err(()) => Some("a version it holds is not held here, so its keep is not known"),
        Ok(Some(cap)) if l.until > cap => Some("it promises past the keep of everything it holds"),
        Ok(_) => None,
    }
}

/// Whether `holds` reaches `at` in `coll`: every version inside `at` is
/// inside `holds`, or never applies.
fn reaches(coll: &Coll, holds: &Frontier, at: &Frontier) -> bool {
    at.iter().all(|(w, s)| {
        let h = holds.get(w).map_or(0, |h| h.0);
        h >= s.0
            || coll.entries.get(w).is_none_or(|seqs| {
                seqs.range(h + 1..=s.0).all(|x| {
                    coll.skips(&VersionId {
                        writer: w.clone(),
                        seq: Seq(*x),
                    })
                })
            })
    })
}

/// The prune record known here that covers the version named `name` (a log
/// entry), held or not: its writer's key, whose device the name starts
/// with, pruned it.
fn pruned_name(st: &St, name: &Name) -> Option<Prune> {
    let l = parse_log_name(name)?;
    let coll = st.colls.get(l.subject.as_ref()?)?;
    coll.prunes
        .iter()
        .find(|p| {
            device_of(p.id.writer.key()).as_ref() == Some(&l.device)
                && covers(
                    p,
                    &VersionId {
                        writer: p.id.writer.clone(),
                        seq: Seq(l.seq),
                    },
                )
        })
        .cloned()
}

/// The version a piece name belongs to; any other name as it is.
fn strip_piece(name: &Name) -> Name {
    parse_piece_name(name).map_or_else(|| name.clone(), |p| p.version)
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
        payload: match body.chunks {
            Some(c) => Payload::Large { size: c.size },
            None => Payload::Entry(body.fields),
        },
    }
}

fn bad_name(name: &Name, why: wire::NotDataName) -> DataError {
    DataError::BadName {
        name: name.clone(),
        why: why.to_string(),
    }
}

fn check_collection(c: &Name) -> Result<(), DataError> {
    wire::check_collection_name(c).map_err(|why| bad_name(c, why))
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
            if inner.sealed_off(&inner.st.lock(), &c) {
                return Err(DataError::Sealed { name: name.clone() });
            }
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
        // A reader holding sealed versions waits (at most the first-look
        // time) for the keys it asks for.
        let locked = {
            let st = inner.st.lock();
            st.colls.get(name).is_some_and(|x| !x.locked.is_empty()) && inner.reads(&st, name)
        };
        if locked {
            inner.chase_keys(name);
            inner
                .wait_for(|st| st.colls.get(name).is_none_or(|x| x.locked.is_empty()))
                .await;
        }
        let (got, age) = {
            let st = inner.st.lock();
            (inner.newest(&st, name)?, inner.age(&st, name))
        };
        inner.whole(Ok(Answer { got, age })).await
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
        {
            let mut st = inner.st.lock();
            if st.colls.get(collection).is_none_or(|c| c.members.is_none()) {
                if ns != inner.ns {
                    let heard = !inner.known_for(&st, &ns).is_empty();
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
                let record = inner.default_members(collection, st.head + 1);
                inner.append_members(&mut st, collection, record)?;
            }
        }
        let key = inner.write_key(collection).await?;
        let id = {
            let mut st = inner.st.lock();
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
            if key.as_ref().map(|(e, _)| e) != members.epoch.as_ref() {
                // The record moved to another epoch while the key was asked
                // for: ask again.
                return Err(DataError::Unavailable {
                    name: collection.clone(),
                });
            }
            let seal = Seal {
                any_of: members.readers.clone(),
            };
            let parents = coll.at();
            // A merge collection carries every operation inline (spec §4.1):
            // refused before the edit touches the state.
            if matches!(members.rule, Rule::Merge { .. }) {
                let size = wire::encode_payload(&content, &[]).len();
                if size > wire::INLINE_MAX {
                    return Err(DataError::TooLarge {
                        collection: collection.clone(),
                        size: size as u64,
                        limit: wire::INLINE_MAX as u64,
                    });
                }
            }
            let log = members.rule == Rule::Log;
            let op = match &members.rule {
                Rule::Merge { function } => {
                    let function = function.clone();
                    let Some(state) = coll.state.as_mut() else {
                        return Err(local(format!(
                            "{collection} merges with {function}, which this device does not run"
                        )));
                    };
                    state.edit(&content).map_err(|e| local(e.to_string()))?
                }
                Rule::Log => Bytes::new(),
                Rule::OneKey => {
                    return Err(local(format!(
                        "{collection} uses the one-key rule, which is data-layer slice 4; this \
                         device writes merge and log collections"
                    )));
                }
            };
            let seq = st.head + 1;
            let name = log_name(&inner.device, Some(collection), seq);
            let payload = match (&key, log) {
                (Some((_, k)), _) => seal::seal_payload(k, &name, &content, &op),
                (None, true) => wire::encode_payload(&content, &op),
                // Unsealed and inline whatever its size: no payload to build.
                (None, false) => Bytes::new(),
            };
            // A log collection's large payload travels in pieces (spec
            // §4.1); the record carries its size and manifest root.
            let (chunks, pieces) = if log && payload.len() > wire::INLINE_MAX {
                let (pieces, chunks) = pieces::split(&name, &payload);
                (Some(chunks), pieces)
            } else {
                (None, Vec::new())
            };
            let sealed = key.as_ref().map(|(epoch, _)| SealedBody {
                epoch: epoch.clone(),
                ciphertext: if chunks.is_some() {
                    Bytes::new()
                } else {
                    payload.clone()
                },
            });
            let (fields, op) = match chunks {
                Some(_) => (Content::new(), Bytes::new()),
                None => (content, op),
            };
            let body = VersionBody {
                collection: collection.clone(),
                parents,
                type_id: options.type_id,
                seal,
                keep: options.keep,
                dated: (inner.config.clock)(),
                fields,
                op: op.clone(),
                sealed,
                chunks,
            };
            let wire = inner.sign(DataBuilder::new(name.clone(), &wire::encode_version(&body)))?;
            st.head = seq;
            for p in pieces {
                inner.store.insert(p.name, p.wire);
            }
            let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
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
                    sealed: key.is_some(),
                    epoch,
                    chunks,
                }),
            );
            st.emit(collection, &Change::Version(version), &id.writer, seq);
            id
        };
        inner.publish_about(collection, &[]).await?;
        Ok(id)
    }

    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError> {
        let inner = &self.inner;
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
        let ns = namespace_of(collection).expect("followed, so a data name");
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

    async fn hold(&self, prefix: &Name, want: Hold) -> Result<Custody, DataError> {
        let inner = &self.inner;
        check_collection(prefix)?;
        let ns = namespace_of(prefix).expect("checked above");
        if ns != inner.ns {
            return Err(DataError::NotOwner {
                collection: prefix.clone(),
            });
        }
        inner.look(prefix).await?;
        // The custody policy, in data: the hold record this device signs,
        // again only when what it asks changed (spec §13).
        let (record, at, signed) = {
            let mut st = inner.st.lock();
            let coll = st.colls.entry(prefix.clone()).or_default();
            let at = coll.at();
            match coll.holds.get(&inner.writer) {
                Some((_, n, b))
                    if b.copies == want.copies && b.until == want.until && b.at == at =>
                {
                    (n.clone(), at, false)
                }
                _ => {
                    let body = HoldBody {
                        collection: prefix.clone(),
                        copies: want.copies,
                        until: want.until,
                        at: at.clone(),
                    };
                    let (n, _) = inner.append(&mut st, Some(prefix), wire::encode_hold(&body))?;
                    (n, at, true)
                }
            }
        };
        if signed {
            inner.publish_about(prefix, &[]).await?;
        }
        // Audit every live lease.
        let live = inner.live_leases(&inner.st.lock(), prefix);
        let mut broken = Vec::new();
        for h in &live {
            if !inner.audit(prefix, h).await.kept()
                && let Some(l) = inner.lease_of(&inner.st.lock(), prefix, h)
            {
                broken.push(l);
            }
        }
        // Repair: ask the holders that failed again (they fetch back what
        // they lost), then the other devices of the namespace, in name
        // order, until `copies` leases hold what was asked and are kept.
        let holding = |st: &St, h: &Writer| -> bool {
            st.colls.get(prefix).is_some_and(|coll| {
                coll.leases
                    .get(h)
                    .is_some_and(|l| l.audit.kept() && reaches(coll, &l.body.holds, &at))
            })
        };
        let mut candidates: Vec<Name> = broken
            .iter()
            .filter_map(|l| device_of(l.holder.key()))
            .collect();
        // A first look: no device of the namespace heard yet, so none to
        // ask. Wait, at most the first-look time, to hear one.
        if broken.is_empty() {
            inner
                .wait_for(|st| inner.known_for(st, &ns).iter().any(|d| *d != inner.device))
                .await;
        }
        let others: Vec<Name> = {
            let st = inner.st.lock();
            let counted: Vec<Name> = inner
                .live_leases(&st, prefix)
                .into_iter()
                .filter(|h| holding(&st, h))
                .filter_map(|h| device_of(h.key()))
                .collect();
            inner
                .known_for(&st, &ns)
                .into_iter()
                .filter(|d| *d != inner.device && !counted.contains(d))
                .collect()
        };
        for d in others {
            if !candidates.contains(&d) {
                candidates.push(d);
            }
        }
        for d in candidates {
            let kept = {
                let st = inner.st.lock();
                inner
                    .live_leases(&st, prefix)
                    .iter()
                    .filter(|h| holding(&st, h))
                    .count()
            };
            if kept >= want.copies as usize {
                break;
            }
            if !inner.ask_hold(&d, &record).await {
                continue;
            }
            let lease = {
                let st = inner.st.lock();
                inner
                    .live_leases(&st, prefix)
                    .into_iter()
                    .find(|h| device_of(h.key()).as_ref() == Some(&d))
            };
            if let Some(h) = lease {
                inner.audit(prefix, &h).await;
            }
        }
        let st = inner.st.lock();
        let live = inner.live_leases(&st, prefix);
        let leases = live
            .iter()
            .filter_map(|h| inner.lease_of(&st, prefix, h))
            .collect();
        // What was asked that nothing confirms is kept: not held whole here,
        // and inside no lease audited kept.
        let mut unkept = Vec::new();
        if let Some(coll) = st.colls.get(prefix) {
            let kept: Vec<&LeaseHeld> = live
                .iter()
                .filter_map(|h| coll.leases.get(h))
                .filter(|l| l.audit.kept())
                .collect();
            for hv in coll.versions.values() {
                if at.contains(&hv.version.id)
                    && !inner.keeps(coll, &hv.version.id)
                    && !kept.iter().any(|l| l.body.holds.contains(&hv.version.id))
                {
                    unkept.push(hv.version.name.clone());
                }
            }
            unkept.sort();
        }
        Ok(Custody {
            prefix: prefix.clone(),
            copies: want.copies,
            until: want.until,
            leases,
            broken,
            unkept,
        })
    }

    async fn prune(&self, prefix: &Name, upto: &Frontier) -> Result<(), DataError> {
        let inner = &self.inner;
        // Prune reaches only the pruner's own writes (model change M9): a
        // version another key signed is removed by an edit instead.
        let entry = parse_log_name(prefix);
        let others_entry = entry.as_ref().is_some_and(|p| p.device != inner.device);
        let others_key = upto.iter().any(|(w, _)| *w != inner.writer);
        if others_entry || others_key {
            return Err(DataError::NotOwnWrites {
                prefix: prefix.clone(),
            });
        }
        let c = match entry {
            Some(l) => l.subject.ok_or_else(|| DataError::BadName {
                name: prefix.clone(),
                why: "a snapshot is no version of a collection; prune takes a collection or a \
                      version's name"
                    .into(),
            })?,
            None => {
                check_collection(prefix)?;
                prefix.clone()
            }
        };
        inner.look(&c).await?;
        {
            let mut st = inner.st.lock();
            let rule = st
                .colls
                .get(&c)
                .and_then(|x| x.members.as_ref())
                .map(|m| m.rule.clone());
            match rule {
                None => return Err(DataError::Unavailable { name: c }),
                Some(Rule::Merge { .. }) => {
                    return Err(DataError::NotPrunable {
                        name: prefix.clone(),
                        why: format!(
                            "{c} merges its versions into one state, computed from every \
                             version, so none can be dropped; remove what it set with an edit"
                        ),
                    });
                }
                Some(Rule::OneKey) => {
                    return Err(local(format!(
                        "{c} uses the one-key rule, which is data-layer slice 4"
                    )));
                }
                Some(Rule::Log) => {}
            }
            if upto.get(&inner.writer).is_none() {
                // Up to nothing of this key: nothing to drop.
                return Ok(());
            }
            let body = PruneBody {
                prefix: prefix.clone(),
                upto: upto.clone(),
            };
            inner.append(&mut st, Some(&c), wire::encode_prune(&body))?;
        }
        inner.publish_about(&c, &[]).await
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
        if members.rule == Rule::OneKey {
            return Err(local(
                "the one-key rule is data-layer slice 4; share a collection with the merge or the \
                 log rule",
            ));
        }
        inner.follow(collection).await?;
        let before = inner.groups_of(&inner.st.lock(), collection);
        {
            let mut st = inner.st.lock();
            let current = st.colls.get(collection).and_then(|c| c.members.clone());
            let record = inner.next_members(
                &st,
                collection,
                current.as_ref(),
                members.rule,
                members.writers,
                members.readers,
                false,
            );
            inner.append_members(&mut st, collection, record)?;
        }
        inner.publish_about(collection, &before).await?;
        // A collection sealed to this one as a group moves to a new epoch
        // with it, and a merge this record left unresolved is resolved.
        inner.settle().await;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ndn_app::AppError;
    use ndn_security::{SignedTrustContext, TrustSchema};
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
        let wire = DataBuilder::new(root_name(device, ns, head), &wire::encode_node(&body))
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
        let reader_keys = keys_of(&reader);
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(writer_cert);

        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let at = |head| root(&writer_keys, &writer_key, &writer, &ns, head);

        let first = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
        first
            .inner
            .accept_root(&writer, &ns, &at(5))
            .await
            .expect("a first root is taken");
        first.shutdown();
        drop(first);

        let again = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
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

    /// A key store holding a key for `device`.
    fn keys_of(device: &Name) -> Arc<SecurityManager> {
        let keys = Arc::new(SecurityManager::new());
        keys.generate_ed25519(device.clone().append("KEY").append("1"))
            .unwrap();
        keys
    }

    /// A trust context of namespace `ns` (its anchors do not matter here).
    fn context(ns: &str) -> Arc<SignedTrustContext> {
        Arc::new(SignedTrustContext::hierarchical(n(ns)))
    }

    /// Start `device` on a forwarder that delivers nothing.
    async fn start(
        device: &Name,
        keys: &Arc<SecurityManager>,
        validator: &Arc<Validator>,
        store: &Arc<dyn DataStore>,
    ) -> Result<Device, DataError> {
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
        Device::start(
            Transport {
                node: Node::from_connection(Arc::clone(&conn)),
                sync: conn,
            },
            device.clone(),
            Arc::clone(keys),
            Arc::clone(validator),
            Arc::clone(store),
            Config::new(),
        )
        .await
    }

    #[tokio::test]
    async fn a_device_is_of_the_namespace_whose_trust_context_governs_it() {
        let device = n("/home/bob/member/laptop");
        let keys = keys_of(&device);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        match start(&device, &keys, &validator, &store).await {
            Err(e @ DataError::Local { .. }) => {
                assert!(e.to_string().contains("no trust context covers"), "{e}");
                assert_eq!(e.next(), crate::NextStep::FixLocal);
            }
            other => panic!(
                "a device no trust context covers started: {:?}",
                other.err()
            ),
        }
        assert!(validator.adopt_context(context("/home")));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        assert_eq!(dev.namespace(), &n("/home"));
        dev.shutdown();
        // The longest held namespace governs it.
        assert!(validator.adopt_context(context("/home/bob")));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        assert_eq!(dev.namespace(), &n("/home/bob"));
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_name_without_its_marker_is_refused_with_how_to_name_it() {
        let device = n("/home/bob/member/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/home/bob")));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&device, &keys_of(&device), &validator, &store)
            .await
            .unwrap();
        let unmarked = n("/home/bob/notes/trip");
        let options = || PutOptions {
            type_id: crate::TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            keep: crate::Keep::Forever,
            batch: None,
        };
        let share = crate::layer::Share {
            rule: Rule::Merge {
                function: n("/merge/yrs"),
            },
            writers: vec![n("/home/bob")],
            readers: Vec::new(),
            readmit: Vec::new(),
        };
        let refusals = [
            dev.put(&unmarked, Content::new(), options()).await.err(),
            dev.get(&unmarked).await.err(),
            dev.watch(&unmarked, &Frontier::new()).await.err(),
            dev.share(&unmarked, share.clone()).await.err(),
            dev.snapshot(std::slice::from_ref(&unmarked)).await.err(),
        ];
        for refusal in refusals {
            let Some(e @ DataError::BadName { .. }) = refusal else {
                panic!("an unmarked collection name was not refused as one: {refusal:?}");
            };
            assert_eq!((e.next(), e.retry()), (crate::NextStep::FixName, false));
            assert!(e.to_string().contains("<namespace>/32=data/<path>"), "{e}");
        }
        // The namespace's folder is watched; a collection needs a path.
        let folder = wire::data_folder(&n("/home/bob"));
        assert!(dev.watch(&folder, &Frontier::new()).await.is_ok());
        let Err(DataError::BadName { why, .. }) = dev.put(&folder, Content::new(), options()).await
        else {
            panic!("a put into the namespace's folder was not refused");
        };
        assert_eq!(why, wire::NotDataName::NoPath.to_string());
        dev.shutdown();
    }

    #[test]
    fn a_members_record_is_the_owners_by_the_longest_held_namespace() {
        let record = |device: &str, collection: &str| log_name(&n(device), Some(&n(collection)), 1);
        let (bob, home) = (n("/home/bob"), n("/home"));
        let both = Keyring::new();
        both.adopt(context("/home"));
        both.adopt(context("/home/bob"));
        // A /home/bob device lies under /home, but /home/bob governs it.
        let laptop = "/home/bob/member/laptop";
        assert!(!owner_signed(
            &both,
            &record(laptop, "/home/32=data/x"),
            &home
        ));
        assert!(owner_signed(
            &both,
            &record(laptop, "/home/bob/32=data/x"),
            &bob
        ));
        let hub = "/home/member/hub";
        assert!(owner_signed(&both, &record(hub, "/home/32=data/x"), &home));
        assert!(!owner_signed(
            &both,
            &record(hub, "/home/bob/32=data/x"),
            &bob
        ));
        // Held alone, /home governs every device under it.
        let only_home = Keyring::new();
        only_home.adopt(context("/home"));
        assert!(owner_signed(
            &only_home,
            &record(laptop, "/home/32=data/x"),
            &home
        ));
        assert!(!owner_signed(
            &only_home,
            &record(laptop, "/home/bob/32=data/x"),
            &bob
        ));
        // No context held: nobody owns anything.
        assert!(!owner_signed(
            &Keyring::new(),
            &record(hub, "/home/32=data/x"),
            &home
        ));
    }

    #[tokio::test]
    async fn a_reader_takes_members_records_only_from_the_namespaces_own_devices() {
        let reader = n("/home/member/hub");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/home")));
        assert!(validator.adopt_context(context("/home/bob")));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let take = |signer: &str, collection: &str| {
            let (device, c) = (n(signer), n(collection));
            let body = MembersBody {
                collection: c.clone(),
                revision: 1,
                rule: Rule::Merge {
                    function: n("/merge/yrs"),
                },
                writers: vec![wire::namespace_of(&c).unwrap()],
                readers: Vec::new(),
                cuts: Vec::new(),
                epoch: None,
                key_check: None,
                since: None,
                parent: None,
            };
            let name = log_name(&device, Some(&c), 1);
            let content = wire::encode_members(&body);
            let packet = DataBuilder::new(name.clone(), &content).sign_digest_sha256();
            let mut st = dev.inner.st.lock();
            dev.inner.take(
                &mut st,
                name,
                packet,
                Writer::new(device.append("KEY").append("1")),
                Record::Members(body),
                false,
            );
            st.colls
                .get(&c)
                .and_then(|coll| coll.members.as_ref())
                .map(|m| m.owner.key().clone())
        };
        assert_eq!(
            take("/home/bob/member/laptop", "/home/32=data/x"),
            None,
            "a /home/bob device does not own /home's collections"
        );
        assert_eq!(
            take("/home/member/phone", "/home/32=data/x"),
            Some(n("/home/member/phone/KEY/1"))
        );
        assert_eq!(
            take("/home/bob/member/laptop", "/home/bob/32=data/y"),
            Some(n("/home/bob/member/laptop/KEY/1"))
        );
        dev.shutdown();
    }

    // ---- seals and cuts against crafted packets (the slice-2 review) -------------------------

    /// A device of `ns` (whose trust context, and `others`', it holds), on a
    /// forwarder that delivers nothing.
    async fn device_in(device: &str, others: &[&str]) -> Device {
        let device = n(device);
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in others {
            assert!(validator.adopt_context(context(ns)));
        }
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        start(&device, &keys_of(&device), &validator, &store)
            .await
            .unwrap()
    }

    fn share_of(rule: Rule, writers: &[&str], readers: Vec<Audience>) -> crate::layer::Share {
        crate::layer::Share {
            rule,
            writers: writers.iter().map(|w| n(w)).collect(),
            readers,
            readmit: Vec::new(),
        }
    }

    fn version_body(c: &Name, sealed: Option<SealedBody>) -> VersionBody {
        VersionBody {
            collection: c.clone(),
            parents: Frontier::new(),
            type_id: crate::TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            seal: Seal { any_of: Vec::new() },
            keep: crate::Keep::Forever,
            dated: Timestamp(1),
            fields: Content::new(),
            op: Bytes::new(),
            sealed,
            chunks: None,
        }
    }

    /// Hand `dev` the log entry `seq` of `device` about `c` carrying
    /// `record`, as if fetched and verified; why it is refused, if it is.
    fn hand(dev: &Device, device: &Name, c: &Name, seq: u64, record: Record) -> Option<Refusal> {
        let name = log_name(device, Some(c), seq);
        let content = wire::encode_record(&record);
        // Its signature is never checked here; its key locator names the
        // signer, as a restart reads it back.
        let key = device.clone().append("KEY").append("1");
        let packet = DataBuilder::new(name.clone(), &content).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&key),
            |_| Bytes::from_static(&[0; 64]),
        );
        let mut st = dev.inner.st.lock();
        dev.inner.take(
            &mut st,
            name.clone(),
            packet,
            Writer::new(key),
            record,
            false,
        );
        st.refused.get(&name).cloned()
    }

    #[tokio::test]
    async fn a_grant_answers_only_an_epoch_a_held_record_names_and_only_its_audience() {
        let dev = device_in("/alice/laptop", &["/alice"]).await;
        let c = n("/alice/32=data/plan");
        let bob = (n("/bob/phone"), n("/bob"));
        let phone = (n("/alice/phone"), n("/alice"));
        dev.share(
            &c,
            share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/bob"))]),
        )
        .await
        .unwrap();
        let (first, future) = {
            let st = dev.inner.st.lock();
            let first = st.colls[&c]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap();
            let future = Epoch {
                creator: n("/alice/laptop"),
                seq: Seq(st.head + 5),
            };
            (first, future)
        };
        let may = |e: &Epoch, (d, ns): &(Name, Name)| {
            dev.inner
                .grant_key(&dev.inner.st.lock(), &c, e, d, ns)
                .is_some()
        };
        assert!(may(&first, &bob), "a reader of the epoch gets its key");
        assert!(
            !may(&future, &bob),
            "an epoch no record names has no key to give, now or later"
        );
        // The owner's own other device is no reader unless listed.
        assert!(!may(&first, &phone));
        // Asked over the network, the future epoch gets no answer, without a
        // fetch of the asker's seal key.
        let ask = GrantAsk {
            seal_key: seal_key_name(&bob.0, &[9; 32]),
            collection: c.clone(),
            epoch: future.clone(),
        };
        let name = grant_name(&n("/alice/laptop"), &ask);
        assert_eq!(dev.inner.grant(&name, ask).await, None);

        // Bob removed: the new epoch is not his, and nor is the old one any
        // longer, by the record in force.
        dev.share(
            &c,
            share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/alice"))]),
        )
        .await
        .unwrap();
        let second = dev.inner.st.lock().colls[&c]
            .members
            .as_ref()
            .unwrap()
            .epoch
            .clone()
            .unwrap();
        assert_ne!(second, first);
        assert_ne!(second, future, "the new epoch is the record's own");
        assert!(!may(&second, &bob) && !may(&first, &bob));
        assert!(may(&second, &phone));
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_granted_key_is_taken_only_if_it_matches_the_check_of_its_epoch() {
        let (owner, granter) = (n("/alice/laptop"), n("/bob/phone"));
        let c = n("/alice/32=data/plan");
        let epoch = Epoch {
            creator: owner.clone(),
            seq: Seq(1),
        };
        let right = ContentKey::generate();
        let record = MembersBody {
            collection: c.clone(),
            revision: 1,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: vec![Audience::Person(n("/carol"))],
            cuts: Vec::new(),
            epoch: Some(epoch.clone()),
            key_check: Some(seal::key_check(&right, &c, &epoch)),
            since: None,
            parent: None,
        };
        let version = |seq: u64| {
            let name = log_name(&owner, Some(&c), seq);
            let fields = Content::new().with("text", Bytes::from_static(b"budget"));
            version_body(
                &c,
                Some(SealedBody {
                    epoch: epoch.clone(),
                    ciphertext: seal::seal_payload(&right, &name, &fields, b""),
                }),
            )
        };
        let device = n("/carol/phone");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in ["/alice", "/carol"] {
            assert!(validator.adopt_context(context(ns)));
        }
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        assert_eq!(hand(&dev, &owner, &c, 1, Record::Members(record)), None);
        assert_eq!(hand(&dev, &owner, &c, 2, Record::Version(version(2))), None);

        // Another device answers the ask with a key it chose, wrapped to the
        // reader and signed: it opens, and is not the epoch's.
        let public = dev.inner.st.lock().keys.recipient.public();
        let grant = |key: &ContentKey| {
            let ask = GrantAsk {
                seal_key: seal_key_name(&device, &public),
                collection: c.clone(),
                epoch: epoch.clone(),
            };
            let name = grant_name(&granter, &ask);
            let (eph, wrapped) = wrap_ck_to(&public, key, &name.encode_to_tlv()).unwrap();
            let content = wire::encode_grant(&eph, &wrapped.to_bytes());
            let packet = DataBuilder::new(name.clone(), &content).sign_digest_sha256();
            (name, content, packet)
        };
        let chosen = ContentKey::generate();
        let (name, content, packet) = grant(&chosen);
        {
            let mut st = dev.inner.st.lock();
            let opened = open_grant(&st.keys.recipient, &name, content).unwrap();
            assert!(
                !st.take_key(&c, &epoch, opened),
                "a key chosen by another device"
            );
            assert!(st.keys.key(&c, &epoch).is_none());
            assert_eq!(st.colls[&c].locked.len(), 1, "nothing opens under it");
        }
        // A stored grant of the wrong key is checked again on restart.
        store.insert(name, packet);
        dev.shutdown();
        drop(dev);
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        assert!(again.inner.st.lock().keys.key(&c, &epoch).is_none());
        // Fetched again (a version is kept only once applied), it waits.
        assert_eq!(
            hand(&again, &owner, &c, 2, Record::Version(version(2))),
            None
        );
        // The epoch's own key, from any device, is taken and opens it.
        let (name, content, _) = grant(&right);
        {
            let mut st = again.inner.st.lock();
            let opened = open_grant(&st.keys.recipient, &name, content).unwrap();
            assert!(st.take_key(&c, &epoch, opened));
            assert!(st.colls[&c].locked.is_empty());
            assert!(matches!(
                st.held.get(&log_name(&owner, Some(&c), 2)),
                Some(Held::Version(_))
            ));
        }
        again.shutdown();
    }

    #[tokio::test]
    async fn a_removed_writer_cannot_fill_a_gap_below_what_its_cut_kept() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let (c, bob) = (n("/alice/32=data/plan"), n("/bob/laptop"));
        dev.share(&c, share_of(Rule::Log, &["/alice", "/bob"], Vec::new()))
            .await
            .unwrap();
        let version = || Record::Version(version_body(&c, None));
        assert_eq!(hand(&dev, &bob, &c, 40, version()), None);
        assert_eq!(hand(&dev, &bob, &c, 100, version()), None);
        // Bob's summary listed seq 70 too, never fetched: not kept.
        dev.inner
            .st
            .lock()
            .colls
            .get_mut(&c)
            .unwrap()
            .entries
            .entry(Writer::new(n("/bob/laptop/KEY/1")))
            .or_default()
            .insert(70);
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let id = |seq| VersionId {
            writer: Writer::new(n("/bob/laptop/KEY/1")),
            seq: Seq(seq),
        };
        {
            let st = dev.inner.st.lock();
            let cut = &st.colls[&c].members.as_ref().unwrap().cuts[0];
            assert!(!cut.refuses(&id(40)) && !cut.refuses(&id(100)));
            assert!(cut.refuses(&id(70)), "a seq only a summary listed");
        }
        // After his removal Bob signs seq 57, a seq he used elsewhere.
        assert!(matches!(
            hand(&dev, &bob, &c, 57, version()),
            Some(Refusal::OutsideCut(_))
        ));
        assert!(matches!(
            hand(&dev, &bob, &c, 101, version()),
            Some(Refusal::OutsideCut(_))
        ));
        let st = dev.inner.st.lock();
        assert_eq!(st.colls[&c].applied.get(&id(0).writer), Some(&100));
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_sealed_collection_refuses_an_unsealed_version_written_after_its_seal() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let (c, bob) = (n("/alice/32=data/chat"), n("/bob/laptop"));
        let bob_key = Writer::new(n("/bob/laptop/KEY/1"));
        dev.share(&c, share_of(Rule::Log, &["/alice", "/bob"], Vec::new()))
            .await
            .unwrap();
        assert_eq!(
            hand(&dev, &bob, &c, 1, Record::Version(version_body(&c, None))),
            None
        );
        let readers = vec![Audience::Person(n("/alice")), Audience::Person(n("/bob"))];
        dev.share(&c, share_of(Rule::Log, &["/alice", "/bob"], readers))
            .await
            .unwrap();
        // Written before the seal: inside the record's `since`, kept.
        assert_eq!(
            dev.inner
                .st
                .lock()
                .refused
                .get(&log_name(&bob, Some(&c), 1)),
            None
        );
        // Written by Bob before he heard the seal: refused, and saying why.
        assert_eq!(
            hand(&dev, &bob, &c, 2, Record::Version(version_body(&c, None))),
            Some(Refusal::Unsealed)
        );
        // His next version, sealed, does not wait for the refused one.
        let (epoch, key) = {
            let st = dev.inner.st.lock();
            let e = st.colls[&c]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap();
            let k = st.keys.key(&c, &e).unwrap();
            (e, k)
        };
        let name = log_name(&bob, Some(&c), 3);
        let sealed = SealedBody {
            epoch,
            ciphertext: seal::seal_payload(&key, &name, &Content::new(), b""),
        };
        assert_eq!(
            hand(
                &dev,
                &bob,
                &c,
                3,
                Record::Version(version_body(&c, Some(sealed)))
            ),
            None
        );
        assert_eq!(
            dev.inner.st.lock().colls[&c].applied.get(&bob_key),
            Some(&3)
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn the_recipient_secret_lives_in_the_key_store_and_made_keys_only_wrapped() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/alice")));
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/journal");
        dev.share(
            &c,
            share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/alice"))]),
        )
        .await
        .unwrap();
        let (public, epoch, key) = {
            let st = dev.inner.st.lock();
            let e = st.colls[&c]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap();
            let k = st.keys.key(&c, &e).unwrap();
            (st.keys.recipient.public(), e, k)
        };
        let secret = keys
            .secret(&secret_name(&device))
            .expect("kept with the keys");
        assert_eq!(
            RecipientKey::from_bytes(secret[..].try_into().unwrap()).public(),
            public
        );
        for (name, value) in store.scan_under(&Name::root(), 0) {
            assert!(
                !value
                    .windows(32)
                    .any(|w| w == secret.as_slice() || w == key.expose()),
                "{name} holds a secret in the clear"
            );
            assert!(
                !name.has_prefix(&device) || parse_log_name(&name).is_some(),
                "{name}: only log entries are kept under the device's own prefix"
            );
        }
        dev.shutdown();
        drop(dev);
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        let st = again.inner.st.lock();
        assert_eq!(st.keys.recipient.public(), public);
        assert_eq!(
            st.keys.key(&c, &epoch).map(|k| *k.expose()),
            Some(*key.expose()),
            "the made key comes back after a restart"
        );
        drop(st);
        again.shutdown();
    }

    #[tokio::test]
    async fn concurrent_records_of_one_parent_keep_an_addition_and_a_removal_and_resolve() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/alice")));
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/plan");
        let person = |s: &str| Audience::Person(n(s));
        dev.share(
            &c,
            share_of(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            ),
        )
        .await
        .unwrap();
        let first = dev.inner.st.lock().colls[&c].members.clone().unwrap();
        // The laptop adds Carol; the phone, from the same record, removes Bob.
        dev.share(
            &c,
            share_of(
                Rule::Log,
                &["/alice", "/bob", "/carol"],
                vec![person("/alice"), person("/bob"), person("/carol")],
            ),
        )
        .await
        .unwrap();
        let phone = n("/alice/phone");
        let removed_in = Epoch {
            creator: phone.clone(),
            seq: Seq(1),
        };
        let removes = MembersBody {
            collection: c.clone(),
            revision: 2,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: vec![person("/alice")],
            cuts: vec![CutBody {
                of: n("/bob"),
                accept: Accepted::new(),
            }],
            epoch: Some(removed_in.clone()),
            key_check: Some(seal::key_check(&ContentKey::generate(), &c, &removed_in)),
            since: None,
            parent: Some(first.as_parent()),
        };
        assert_eq!(hand(&dev, &phone, &c, 1, Record::Members(removes)), None);
        let merged = {
            let st = dev.inner.st.lock();
            let coll = &st.colls[&c];
            let m = coll.members.clone().unwrap();
            assert_eq!(m.revision, Seq(2));
            assert_eq!(m.writers, vec![n("/alice"), n("/carol")]);
            assert_eq!(m.readers, vec![person("/alice"), person("/carol")]);
            assert_eq!(
                m.cuts.iter().map(|k| &k.of).collect::<Vec<_>>(),
                [&n("/bob")]
            );
            // Until resolved, the epoch Bob is not of.
            assert_eq!(m.epoch.as_ref(), Some(&removed_in));
            assert_eq!(coll.resolve, Resolve::Epoch);
            m
        };
        // The laptop, of the merged audience, resolves it: the merged
        // record, in a new epoch of its own, signed from the merge.
        dev.inner.settle().await;
        let resolved = {
            let st = dev.inner.st.lock();
            let m = st.colls[&c].members.clone().unwrap();
            assert_eq!(m.revision, Seq(3));
            assert_eq!(m.writers, merged.writers);
            assert_eq!(m.readers, merged.readers);
            assert_eq!(m.parent, Some(merged.as_parent()));
            let e = m.epoch.clone().unwrap();
            assert_eq!(e.creator, device);
            assert!(st.keys.key(&c, &e).is_some());
            assert_eq!(st.colls[&c].resolve, Resolve::Nothing);
            m
        };
        // A restart takes the records back revision by revision and owes
        // nothing more.
        dev.shutdown();
        drop(dev);
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        let st = again.inner.st.lock();
        assert_eq!(st.colls[&c].members.as_ref(), Some(&resolved));
        assert_eq!(st.head, 3);
        drop(st);
        again.shutdown();
    }
}
