//! [`Device`]: one device's data layer, the reference implementation of
//! [`DataLayer`] over NDN (`docs/specs/data-layer.md`).
//!
//! A device signs with its own key and publishes only under its own name. It
//! keeps one log (its key's sequence of entries: versions and members
//! records) and, per namespace it writes into, a nested summary of that log
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
//! Keys over time (spec §8): an entry's validity never depends on a clock.
//! The validator checks no certificate's validity period for it; a key
//! ends only by a revocation in its namespace's trust context, whose cut
//! accepts exactly the entries the owner's device held verified before the
//! device was lost — bound to their bytes by the cut's manifest and to the
//! public key that verified them — and those the owner re-admits by name and
//! digest. An entry its cut does not accept is refused and kept refused,
//! with its full name and digest ([`Device::refused_by_revocation`]); a
//! trust context adopted later withdraws what it refuses (by a cut, or for
//! the chain above an entry's key, judging held entries again by the
//! durable rule) and admits what it re-admits. The cut a device can vouch
//! for is [`Device::revocation_cut`], bounded by when it first verified each
//! entry; a key the owner fears lost is marked suspected
//! ([`Device::suspect`]) and no new entry of it is taken until its
//! revocation.
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use ndn_security::cert_name::{is_key_name, key_name_of};
use ndn_security::safe_data::TrustPath;
use ndn_security::verifier::{VerifyOutcome, verify_by_sig_type};
use ndn_security::{
    Keyring, ManifestLookup, RevocationCut, SecurityManager, SignedTrustContext, Signer,
    TrustError, ValidationResult, Validator, cut_manifest, cut_manifest::CutManifests,
    public_key_digest, sync_group,
};
use ndn_sync::{DataStore, MultiSvs, ObservedState, SvsConfig, SyncUpdate, spawn_multi_svs};
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

use crate::collection::{self, Accepted, Child, Cut, Epoch, Members, Resolve, Rule, Summary};
use crate::error::{DataError, Refusal};
use crate::layer::{Age, Answer, Change, Changes, DataLayer, Equivocal, Got, PutOptions, State};
use crate::merge::{self, MergeState, NoOps, Op, Ops, Past};
use crate::pieces::{self, Shape};
use crate::rt::{self, Instant};
use crate::seal::{self, Keys};
use crate::tree::{Kind, Tree};
use crate::version::{
    Audience, Content, Frontier, Keep, Parents, Payload, Seal, Seq, Timestamp, TypeId, Version,
    VersionId, Writer,
};
use crate::wire::{
    self, Branches, ChunksBody, CutBody, GrantAsk, MembersBody, NodeBody, PieceKind, Record,
    SealedBody, VersionBody, cut_bytes_prefix, device_of, grant_name, log_name, namespace_of,
    node_name, page_name, parse_cut_bytes_name, parse_grant_name, parse_held_name, parse_log_name,
    parse_piece_name, parse_seal_key_name, parse_summary_name, piece_name, piece_names, root_name,
    root_prefix, seal_key_name, seqs_of, subject_namespace,
};
use ndn_security::confidentiality::{ContentKey, RecipientKey, Sealed, wrap_ck_to};

/// A wall clock: the date a device's clock shows. Display and retention
/// only; no decision of the layer reads it.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// A source of random octets: fills the slice with unpredictable bytes. The
/// device draws an introduction's secrets and nonces from it (spec §19).
pub type Entropy = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// A signed summary root is never fresh in a cache: discovery (`MustBeFresh`)
/// always reaches its writer, so a notice that the writer moved is never
/// answered by the root it moved from.
const ROOT_FRESHNESS: Duration = Duration::ZERO;

/// A device's settings. Everything here is performance, or the host's policy;
/// none of it changes what a verb answers once the network has delivered.
#[derive(Clone)]
pub struct Config {
    /// State Vector Sync settings for every group the device joins.
    pub svs: SvsConfig,
    /// The device's wall clock, for the dates it writes.
    pub clock: Clock,
    /// Interest lifetime of every fetch: one ask lasts it, and an Interest
    /// of the ask nothing answered is expressed again within it after the
    /// device's measured retransmission timeout (spec §17.1).
    pub lifetime: Duration,
    /// How long `get` and `watch` wait for a first look at a
    /// collection the device has not seen before (a `put` never waits for
    /// one: spec §15; `share_folder` creating a first record does).
    pub first_look: Duration,
    /// How many asks one walk has in flight at once: the nodes or entries
    /// of one summary node, the pieces of one large version (spec §13.1).
    pub window: usize,
    /// How many asks the whole device has in flight at once, every walk
    /// and fetch together (its slots, spec §17.1): what bounds the memory
    /// and the network the device's fetching takes. Where round trips are
    /// long, a device asks at most this many per round trip. At least
    /// [`Self::window`].
    pub in_flight: usize,
    /// How many askers' proofs this device verifies at once, whoever claims
    /// to ask — introduction asks, opened and verified (spec §19.4): what a
    /// crowd of strangers' asks costs it at once; the rest wait their turn.
    /// At least 1.
    pub asks_verifying: usize,
    /// Where introductions draw their secrets and nonces (spec §19).
    pub entropy: Entropy,
    /// What the host does for introductions (spec §19): give this device's
    /// anchor and adopt another person's. `None`: [`Device::offer`] and
    /// [`Device::join`] answer [`DataError::Local`] naming this setting.
    pub introducer: Option<Arc<dyn crate::intro::Introducer>>,
    /// What introductions allow and cost this device (spec §19.4, §19.7):
    /// the namespaces they may bring either way, the overall cap on an
    /// offer's wrong tries and its backoff, the asks held at once.
    pub intro: crate::intro::IntroPolicy,
    /// How many changes a watcher may leave unread, past what its watch
    /// listed as it began (spec §15): one more is not queued; the watcher
    /// is told [`Change::Lagged`] and the changes after it are dropped
    /// until it read what was queued. At least 1.
    pub watch_queue: usize,
    /// The most collections of one namespace's data one writer outside
    /// that namespace can make this device follow, by writing into a
    /// folder it follows (spec §15). Past it, that writer's new
    /// collections there are not followed, and the folder's watchers are
    /// told why ([`Change::Untracked`]). The namespace's own devices, and
    /// collections followed by their own name or with a members record of
    /// their own, are not counted.
    pub writer_collections: usize,
}

impl Config {
    /// Defaults: SVS's reference timing, the system clock, 2 s Interests, a
    /// 4 s first look, 32 asks in flight per
    /// walk and 256 per device, 8 asker proofs verified at once, the
    /// operating system's randomness, no introducer, the default
    /// introductions ([`crate::intro::IntroPolicy::new`]), 4096 changes a
    /// watcher may leave unread, 1024 collections one outside writer can
    /// make it follow in a namespace.
    pub fn new() -> Self {
        Self {
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
            asks_verifying: 8,
            entropy: Arc::new(|buf| {
                getrandom::getrandom(buf).expect("the operating system provides randomness")
            }),
            introducer: None,
            intro: crate::intro::IntroPolicy::new(),
            watch_queue: 4096,
            writer_collections: 1024,
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
            .field("lifetime", &self.lifetime)
            .field("first_look", &self.first_look)
            .field("window", &self.window)
            .field("in_flight", &self.in_flight)
            .field("asks_verifying", &self.asks_verifying)
            .field("introducer", &self.introducer.is_some())
            .field("intro", &self.intro)
            .field("watch_queue", &self.watch_queue)
            .field("writer_collections", &self.writer_collections)
            .finish_non_exhaustive()
    }
}

/// What bounds the revocation cut a device vouches for
/// ([`Device::revocation_cut`]): the owner's own observation, never
/// anything the revoked key signed. At least one is given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CutBound {
    /// Keep only entries this device first verified strictly before this
    /// time, by its own clock: when the device was lost (by default, when
    /// its key was marked suspected, [`Device::suspected`]).
    pub held_before: Option<Timestamp>,
    /// Keep, per collection, only entries at or below this seq; when given,
    /// a collection it does not name, and entries of no collection, keep nothing.
    pub upto: BTreeMap<Name, u64>,
}

/// A revocation cut a device vouches for ([`Device::revocation_cut`]).
#[derive(Clone, Debug)]
pub struct CutProposal {
    /// The cut, with the digest of the public key that verified its
    /// entries and the full name of its manifest's root.
    pub cut: RevocationCut,
    /// The manifest's packets, root first: self-certifying Data listing
    /// the implicit digest of every entry the cut's ranges accept, to be
    /// published beside the trust context. Empty when the cut keeps
    /// nothing.
    pub manifest: Vec<Bytes>,
    /// The entries of the key held here that the bound leaves out, each by
    /// its full name ending in its implicit digest (sorted): the owner may
    /// re-admit them one by one.
    pub left_out: Vec<Name>,
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
    /// Its operation (empty under the log rule, and when the payload is in
    /// pieces).
    op: Bytes,
    wire: Bytes,
    /// The implicit digest of `wire`: the version's content address, what a
    /// child names it by.
    digest: [u8; 32],
    /// The digest of what its key signed ([`wire::signed_digest`]): the same
    /// on every copy of the packet, the register's tie-break.
    signed: [u8; 32],
    /// Whether its payload came sealed.
    sealed: bool,
    /// The epoch its payload is sealed in.
    epoch: Option<Epoch>,
    /// Its payload in pieces, when it travels so (spec §13.1).
    chunks: Option<ChunksBody>,
    /// Whether `op` is its operation: inline, or in pieces held whole and
    /// opened ([`open_held`]). A register version applies only opened;
    /// once applied, an operation in pieces is let go ([`Self::unloaded`])
    /// and read again from the pieces when needed.
    opened: bool,
}

impl HeldVersion {
    /// A version as held: opened unless its payload is in pieces. Its
    /// digest is the version's ([`Version::digest`], of `wire`).
    fn new(
        version: Version,
        op: Bytes,
        wire: Bytes,
        sealed: bool,
        epoch: Option<Epoch>,
        chunks: Option<ChunksBody>,
    ) -> Self {
        let signed = wire::signed_digest(&wire).unwrap_or(version.digest);
        HeldVersion {
            digest: version.digest,
            signed,
            version,
            op,
            wire,
            sealed,
            epoch,
            opened: chunks.is_none(),
            chunks,
        }
    }

    /// This version without its operation in memory, when that travels in
    /// pieces and is in memory: what is applied needs no operation until
    /// the state is computed anew, which opens it again from the pieces.
    /// `None` when there is nothing to let go.
    fn unloaded(&self) -> Option<Self> {
        (self.chunks.is_some() && self.opened).then(|| HeldVersion {
            version: self.version.clone(),
            op: Bytes::new(),
            wire: self.wire.clone(),
            digest: self.digest,
            signed: self.signed,
            sealed: self.sealed,
            epoch: self.epoch.clone(),
            chunks: self.chunks,
            opened: false,
        })
    }

    /// This version opened, `op` its operation read from its pieces.
    fn with_op(&self, op: Bytes) -> Self {
        HeldVersion {
            version: self.version.clone(),
            op,
            wire: self.wire.clone(),
            digest: self.digest,
            signed: self.signed,
            sealed: self.sealed,
            epoch: self.epoch.clone(),
            chunks: self.chunks,
            opened: true,
        }
    }
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

/// One line of owner-signed members records of a name (spec §6): its
/// collection's, or its folder's. The two are separate: revisions, parents,
/// merges and epochs count records of one kind only.
#[derive(Default)]
struct Line {
    /// The subject's own record in force: what the highest revision held
    /// stands for (`merged`'s last).
    own: Option<Members>,
    /// Every owner-signed record of the line held, by revision, one per
    /// signer (its latest).
    records: BTreeMap<Seq, BTreeMap<Writer, LineRecord>>,
    /// Per revision held, the record it stands for, what that leaves to
    /// resolve and what it is as a parent ([`Line::settle_at`]): its
    /// records merged, each signed from another view first taken onto what
    /// the revision below stands for.
    merged: BTreeMap<Seq, (Members, Resolve, collection::Parent)>,
    /// Per revision, the merges of the proper subsets of its records, by
    /// what each is as a parent: the parents a record of the next revision
    /// signed from a view holding some of them names ([`Line::parent_at`]).
    /// Made when first asked; dropped whenever the revision is settled
    /// again.
    subsets: HashMap<Seq, HashMap<[u8; 32], Members>>,
    /// What `own`, a merge of concurrent records, leaves to resolve: a
    /// device of the audience resolves it with a new record.
    resolve: Resolve,
    /// Every epoch a held owner-signed record of the line names.
    epochs: BTreeMap<Epoch, Named>,
}

/// An owner-signed members record held in a [`Line`].
struct LineRecord {
    /// Its seq in its signer's log.
    seq: u64,
    record: Members,
    /// What it is as a parent ([`Members::as_parent`]).
    parent: collection::Parent,
}

/// The most signers of one revision among whose records' subsets a reader
/// looks for the merge a record of the next revision names as parent (spec
/// §6): at most 2^8 − 2 merges. Above it such a record merges without one.
const SUBSET_SIGNERS: usize = 8;

/// A folder as this device knows it (spec §6): the line of its records,
/// which govern every collection strictly under it.
#[derive(Default)]
struct Folder {
    line: Line,
    /// Its record in force: its own, narrowed by the folders above it
    /// ([`collection::effective`]).
    members: Option<Members>,
}

impl Line {
    /// Take `record`, the record at seq `seq` of `signer`'s log, of this
    /// line: note the epoch it names, hold it (one per signer and
    /// revision, its latest), and settle again what its revision stands
    /// for and what each revision above it in a row does, taken onto the
    /// one below ([`Members::settle`], spec §6): so a removal of a record
    /// of one revision still applies to a record of the next signed from a
    /// view without it, and what stands depends on the records held alone,
    /// not on their order. The own record in force is what the highest
    /// revision held stands for. The own record before, when it moved.
    fn take(&mut self, seq: u64, record: Members, signer: &Writer) -> Option<Option<Members>> {
        if let (Some(e), Some(check)) = (&record.epoch, record.key_check) {
            let starts = seq == e.seq.0 && device_of(signer.key()).as_ref() == Some(&e.creator);
            let named = self.epochs.entry(e.clone()).or_insert_with(|| Named {
                check,
                from_start: starts,
                readers: Vec::new(),
            });
            if starts && !named.from_start {
                named.check = check;
                named.from_start = true;
            } else if named.check != check {
                tracing::debug!(subject = %record.collection, epoch = ?e, signer = ?signer, "a record names an epoch with another key check than the one held; the starting record's counts");
            }
            for r in &record.readers {
                if !named.readers.contains(r) {
                    named.readers.push(r.clone());
                }
            }
        }
        let revision = record.revision;
        let held = self.records.entry(revision).or_default();
        if held.get(signer).is_some_and(|h| h.seq >= seq) {
            return None;
        }
        let parent = record.as_parent();
        held.insert(
            signer.clone(),
            LineRecord {
                seq,
                record,
                parent,
            },
        );
        // The revision above names the records of this one, or merges of
        // some of them, as parents, so it is settled again whatever this
        // one stands for; one further up when the one below it moved, or
        // when a record of it named the merge of a subset of the one below
        // (made again from what that revision now holds).
        let mut r = revision;
        loop {
            let asked = self.subsets.remove(&r).is_some();
            let (m, resolve) = self.settle_at(r, None).expect("a record is held");
            let moved = self
                .merged
                .get(&r)
                .is_none_or(|(was, why, _)| *was != m || *why != resolve);
            let parent = m.as_parent();
            self.merged.insert(r, (m, resolve, parent));
            match r.0.checked_add(1).map(Seq) {
                Some(up) if (moved || asked || r == revision) && self.records.contains_key(&up) => {
                    r = up
                }
                _ => break,
            }
        }
        let (top, resolve, _) = self.merged.values().next_back().expect("a record is held");
        // A record in force can keep an epoch that a reader it lists is not
        // of, though no record merged names a reader out of it (a record of a
        // revision taken onto the one below takes the epoch of another record
        // than the one adding the reader): it is resolved, in the epoch kept,
        // as a merge that only adds a reader is (spec §6).
        self.resolve = match undergrown(top, &self.epochs) {
            true => (*resolve).max(Resolve::Readers),
            false => *resolve,
        };
        if self.own.as_ref() == Some(top) {
            return None;
        }
        Some(self.own.replace(top.clone()))
    }

    /// What the records of revision `n` held stand for, and what that
    /// leaves to resolve ([`Members::settle`]); of those `subset` picks (by
    /// position among the revision's signers), when given. Each record not
    /// naming what the revision below stands for comes with its parent,
    /// when held there ([`Self::parent_at`]).
    fn settle_at(&mut self, n: Seq, subset: Option<u32>) -> Option<(Members, Resolve)> {
        let picked = |i: usize| subset.is_none_or(|s| s & (1 << i) != 0);
        let below = n.0.checked_sub(1).map(Seq);
        let at = below.and_then(|b| self.merged.get(&b)).map(|(_, _, p)| *p);
        let wanted: Vec<Option<collection::Parent>> = self
            .records
            .get(&n)?
            .values()
            .enumerate()
            .filter(|(i, _)| picked(*i))
            .map(|(_, h)| h.record.parent.filter(|p| at.is_some_and(|at| at != *p)))
            .collect();
        let parents: Vec<Option<Members>> = wanted
            .iter()
            .map(|p| self.parent_at(below?, &(*p)?))
            .collect();
        let records: Vec<(&Members, Option<&Members>)> = self.records[&n]
            .values()
            .enumerate()
            .filter(|(i, _)| picked(*i))
            .zip(&parents)
            .map(|((_, h), p)| (&h.record, p.as_ref()))
            .collect();
        let below = below
            .and_then(|b| self.merged.get(&b))
            .map(|(m, _, p)| (m, *p));
        Members::settle(&records, below)
    }

    /// The record of revision `n` held, or merge of some of them, that `p`
    /// names (spec §6): a record itself, what the revision stands for, or
    /// the merge of a proper subset of its records ([`Self::settle_at`]) —
    /// what a device holding only those took for the revision —, looked
    /// for among them when the revision holds records of at most
    /// [`SUBSET_SIGNERS`] signers.
    fn parent_at(&mut self, n: Seq, p: &collection::Parent) -> Option<Members> {
        let held = self.records.get(&n)?;
        if let Some(h) = held.values().find(|h| h.parent == *p) {
            return Some(h.record.clone());
        }
        if let Some((m, _, at)) = self.merged.get(&n)
            && at == p
        {
            return Some(m.clone());
        }
        let signers = held.len();
        if signers > SUBSET_SIGNERS {
            tracing::debug!(
                revision = n.0,
                signers,
                "a members record names a parent not held here, and its revision has more signers than this device looks through the merges of the subsets of: it merges without one"
            );
            return None;
        }
        if !self.subsets.contains_key(&n) {
            let mut merges = HashMap::new();
            for subset in 1..(1u32 << signers) - 1 {
                if let Some((m, _)) = self.settle_at(n, Some(subset)) {
                    merges.insert(m.as_parent().digest, m);
                }
            }
            self.subsets.insert(n, merges);
        }
        self.subsets[&n].get(&p.digest).cloned()
    }
}

/// Whether a subject whose own record is `own`, whose record in force is
/// `new` and whose records name `epochs` owes a record in a new epoch
/// (spec §6.1): it seals in its own epoch, and that epoch outgrew its
/// audience ([`outgrown`]) — a folder above dropped a reader it lists.
fn owes_epoch(
    own: Option<&Members>,
    new: Option<&Members>,
    epochs: &BTreeMap<Epoch, Named>,
) -> bool {
    let (Some(own), Some(new)) = (own, new) else {
        return false;
    };
    !own.readers.is_empty() && new.epoch == own.epoch && outgrown(new, epochs)
}

/// Whether `m`, a record in force, keeps an epoch whose key a reader it no
/// longer admits may hold: a held record naming the epoch (`epochs`) lists
/// a reader `m`'s readers do not admit (spec §6.1, §9). Nothing is sealed
/// in such an epoch.
fn outgrown(m: &Members, epochs: &BTreeMap<Epoch, Named>) -> bool {
    m.epoch
        .as_ref()
        .and_then(|e| epochs.get(e))
        .is_some_and(|named| {
            named
                .readers
                .iter()
                .any(|r| !collection::admitted(r, &m.readers))
        })
}

/// Whether `m`, a record in force, lists a reader that no held record naming
/// its epoch (`epochs`) lists: a merge of concurrent records keeps the epoch
/// of one of them while listing readers another added (spec §6, §9). The
/// epoch's key goes only to the readers those records list, so a version
/// sealed in it would stay closed to such a reader for good; nothing is
/// sealed in it, and the merge is owed a resolving record ([`Line::take`]),
/// until a record naming the epoch lists the reader or moves to a new one.
fn undergrown(m: &Members, epochs: &BTreeMap<Epoch, Named>) -> bool {
    m.epoch
        .as_ref()
        .and_then(|e| epochs.get(e))
        .is_some_and(|named| {
            m.readers
                .iter()
                .any(|r| !collection::admitted(r, &named.readers))
        })
}

/// Why `c` cannot be written now: this device is of its audience, but the
/// content key of epoch `e` is not held here yet. The grant is asked of the
/// devices of the owner's namespace and arrives once one answers: not a
/// refusal ([`DataError::NotReady`]).
fn key_not_held(st: &St, c: &Name, e: &Epoch) -> DataError {
    let subject = st.seal_subject(c, e);
    DataError::NotReady {
        name: c.clone(),
        why: format!(
            "this device is of the audience of {c}, but the epoch key of {} (its grant) is not \
             held here yet: it is asked of the devices of the owner's namespace and arrives \
             once one answers; put again, or join again with the same code if the folder was \
             joined",
            subject.name
        ),
    }
}

/// One collection as this device knows it.
#[derive(Default)]
struct Coll {
    /// The record in force: its own record (`line.own`) narrowed by the
    /// records in force of the folders above it (spec §6,
    /// [`collection::effective`]); its own alone when no folder governs it.
    members: Option<Members>,
    /// The collection's own members records.
    line: Line,
    /// The merge state, once the rule is known and this device runs it.
    state: Option<Box<dyn MergeState>>,
    /// Every admitted version held, applied or waiting for its parents (or,
    /// under a merge rule this device does not know, held and never
    /// applied).
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
    /// Held while no members record is known.
    waiting: Vec<Arc<HeldVersion>>,
    /// Held but refused: by the newest members record — their keys are not
    /// writers, they lie outside a cut, or they are not sealed in a sealed
    /// collection — or because their operation travels in pieces. A later
    /// revision that admits them admits them.
    outsiders: Vec<Arc<HeldVersion>>,
    /// Verified, sealed in an epoch whose key this device does not hold
    /// (yet, or ever: it is not of the audience).
    locked: Vec<Locked>,
    /// The revocation cuts of the revoked keys that write here, or that a
    /// version held here names as a parent, by key (spec §8): each accepts
    /// that key's runs for this collection's log. An entry of such a key
    /// that its cut does not accept, and that no exact re-admission brought
    /// in, never applies: nothing waits for it.
    revoked: HashMap<Writer, Cut>,
    /// Pending versions in pieces found not whole: not looked for again
    /// until their pieces arrive ([`St::pieces_arrived`]) or the state is
    /// rebuilt, so an arrival costs no scan of every waiting version's
    /// pieces.
    unwhole: BTreeSet<VersionId>,
    /// Per version, the other packets of its name this device has seen
    /// beside the one it holds, and whether each signed the same thing (a
    /// copy in another signature value: ECDSA's `S` and `n - S`) or another
    /// ([`Wire`]): what a child naming the version by a packet this device
    /// does not hold is judged by.
    wires: HashMap<VersionId, Vec<Wire>>,
    /// The packets pending versions name as parents that this device holds
    /// another packet of (parent, implicit digest of the packet named): asked
    /// for by full name ([`St::wanted_wires`]) until one verifies.
    wants: BTreeSet<(VersionId, [u8; 32])>,
}

/// Another packet seen at the name of a version held: its implicit digest,
/// and whether it signed what the held one did.
struct Wire {
    digest: [u8; 32],
    same: bool,
}

/// What an own version carries, before it is signed.
enum Draft {
    /// One entry.
    Entry(Content),
    /// The operation the app built, for a merge collection's rule.
    Op(Bytes),
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
    /// What its versions wait for ([`Waits`]); `c` is its name.
    fn waits<'a>(&'a self, c: &'a Name) -> Waits<'a> {
        Waits {
            collection: c,
            members: self.members.as_ref(),
            entries: &self.entries,
            skipped: &self.skipped,
            locked: &self.locked,
            revoked: &self.revoked,
            admitted: &self.versions,
            wires: &self.wires,
        }
    }

    fn at(&self) -> Frontier {
        self.applied
            .iter()
            .map(|(w, s)| VersionId {
                writer: w.clone(),
                seq: Seq(*s),
            })
            .collect()
    }

    /// Its state's frontier as an own version's parents (spec §4): each
    /// tip with the implicit digest of its packet held here. In a merge
    /// collection every tip is held (applied once each of its parents was
    /// held as the packet it names).
    fn parents(&self) -> Parents {
        self.applied
            .iter()
            .map(|(w, s)| {
                let id = VersionId {
                    writer: w.clone(),
                    seq: Seq(*s),
                };
                let digest = self.versions.get(&id).map(|hv| hv.digest).or_else(|| {
                    self.locked
                        .iter()
                        .find(|l| l.writer == *w && l.seq == *s)
                        .map(|l| wire::implicit_digest(&l.wire))
                });
                (id, digest)
            })
            .collect()
    }
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

    /// Drop every entry whose key `keep` refuses.
    fn retain(&mut self, mut keep: impl FnMut(&Name) -> bool) {
        self.map.retain(|k, _| keep(k));
        let map = &self.map;
        self.order.retain(|k| map.contains_key(k));
    }
}

/// Grants a device keeps signed, so asking again gets the same packet.
const GRANTS_KEPT: usize = 4096;
/// Askers' seal keys a device keeps verified.
const SEAL_KEYS_KEPT: usize = 1024;
/// Answers to introduction asks a device keeps signed, by the ask's name:
/// the same ask asked again (a replay) costs no work and no signature.
const ANSWERS_KEPT: usize = 1024;
/// Grant asks of one asker device a granter works on at once — each fetches
/// the asker's seal key back, holding one of the device's
/// [`Config::in_flight`] fetch slots while it waits (spec §9, §17.1). An
/// honest asker has an ask in progress for each epoch it lacks, and each is
/// expressed up to `1 + REEXPRESS_MAX` = 4 times at the granter while the
/// seal key is slow to come: 32 is eight such asks at once, and the first
/// one answered keeps the seal key, so the rest of a burst is answered
/// from it by the asker's next round. An eighth of the default 256 slots,
/// so no one asker's flood holds more.
const GRANTS_PER_ASKER: usize = 32;
/// Background runs that ask again for an asker's seal key at once
/// ([`Inner::learn_seal_key`]): each holds one fetch slot at a time, so no
/// more than a quarter of the default 256 slots is ever spent on keys no
/// answer waits for. An asker beyond it is refused the run and asks its
/// grant again, which starts the run when one ends.
const SEAL_LEARNING_MAX: usize = 64;
/// Of them, the runs one asker device may have: it has one seal key, and a
/// second covers the key it had before a restart that an ask still names.
const SEAL_LEARNING_PER_ASKER: usize = 2;
/// The most entries one look at the held revocation cuts asks for (spec
/// §8): a bound on what a cut's runs make a device fetch at once; the next
/// adoption or new follow asks for the rest.
const CUT_FETCHES: usize = 1 << 16;
/// How many times, at most, an entry a trust context re-admits exactly is
/// asked for again after a pause when it is not to be had (its holders may
/// not have adopted the context yet); group refreshes ask again too.
const READMIT_TRIES: u32 = 8;
/// The first pause before a re-admitted entry is asked for again; each
/// next pause doubles it.
const READMIT_PAUSE: Duration = Duration::from_millis(500);
/// How many other packets of one version's name are remembered
/// ([`Coll::wires`]): its signature value has two malleable forms, and a
/// signer that randomizes makes a new one each time it signs.
const WIRES_MAX: usize = 8;
/// How far beyond the last seq this device wrote an entry under its own
/// name, signed by a copy of its key, is still taken — as every other
/// reader takes it, evidence of the copy, never this device's own; one
/// further ahead is refused ([`Refusal::BeyondOwnLog`]). The device numbers
/// its log itself and records every entry it writes as it signs it, so
/// none of its own lies above its head: the margin only keeps a thief's
/// next entries visible here as they are elsewhere, while one at a seq
/// such as `u64::MAX` is not held at all.
const OWN_AHEAD: u64 = 64;
/// The most cut manifest packets one look for an entry's listed digest
/// fetches (spec §8): a manifest is a tree of a few levels.
const MANIFEST_LOOKS: usize = 16;
/// Removal cuts' manifest packets held in memory ([`St::cut_bytes`]); the
/// store keeps every one taken, and one let go is read back from it.
const CUT_BYTES_HELD: usize = 4096;
/// The most versions the cuts of one members record keep (spec §8): each
/// is listed with its digest in the record's cut manifest, about 45
/// octets, so a record binds at most some 12 MB of manifest.
const CUT_KEPT_MAX: usize = 262_144;

/// The first pause before something a fetch missed is asked for again
/// (spec §17.1): a device's summary not reached or not processed in full
/// ([`Inner::schedule`]), an epoch key no device granted
/// ([`Inner::obtain`]), a removal cut's manifest packet a version
/// waits for ([`Inner::fetch_wanted_bytes`]). Doubled after each further
/// miss in a row up to [`REFRESH_PAUSE_MAX`] ([`retry_pause`]). Liveness
/// only: what counts is decided by the versions held.
const REFRESH_PAUSE: Duration = Duration::from_millis(250);

/// The longest pause between two asks while they keep missing, for the
/// first [`REFRESH_TRIES`] misses in a row: short, so a packet lost at
/// 10–20 % loss costs an Interest lifetime and a few seconds, not a minute.
const REFRESH_PAUSE_MAX: Duration = Duration::from_secs(4);

/// How many asks in a row may miss before the pause becomes
/// [`REFRESH_IDLE`] for what durable state still owes, and before a device
/// nothing verified says it owes more is no longer asked (spec §17.1).
const REFRESH_TRIES: u32 = 16;

/// The pause between two asks for what is still owed once
/// [`REFRESH_TRIES`] asks in a row missed: a source away for long costs one
/// ask a minute, until what is owed comes or is no longer owed.
const REFRESH_IDLE: Duration = Duration::from_secs(64);

/// The pause before asking again for something after `misses` asks for it
/// missed in a row (spec §17.1): [`REFRESH_PAUSE`] · 2^`misses`, at most
/// [`REFRESH_PAUSE_MAX`]; [`REFRESH_IDLE`] from [`REFRESH_TRIES`] misses on.
fn retry_pause(misses: u32) -> Duration {
    if misses >= REFRESH_TRIES {
        return REFRESH_IDLE;
    }
    REFRESH_PAUSE
        .saturating_mul(1 << misses.min(8))
        .min(REFRESH_PAUSE_MAX)
}

/// The most asks one fetch of a packet a summary being walked lists makes
/// ([`Inner::fetch_owed`], spec §17.1), each of at most 1 +
/// [`REEXPRESS_MAX`] Interests: a miss asking again may mend is asked again
/// in place, so one lost packet does not cost the whole walk.
const FETCH_TRIES: u32 = 3;

/// The most walks of one device's summary of one namespace one pass of its
/// refresh loop has under way at once ([`Inner::refresh_pass`], spec
/// §17.1): the walk it began with, and walks of newer roots begun beside
/// it.
const WALKS_AT_ONCE: usize = 3;

/// One walk of a writer's summary root ([`Inner::refresh`]), as
/// [`Inner::descend`] carries it down the tree.
struct Walk {
    /// [`Peer::resets`] when it began: what it processed is recorded only
    /// if nothing was forgotten since.
    since: u64,
    /// The pass of the refresh loop it is one of ([`Inner::refresh_pass`]).
    reach: Option<Reach>,
}

/// One pass of a refresh loop ([`Inner::refresh_pass`]), as its walks tell
/// it how far they came.
struct Pass {
    /// One more than the place of the latest-begun walk of the pass that is
    /// past the way to its versions ([`Reach::past`]).
    past: AtomicUsize,
    /// The highest head of the roots its walks took.
    head: AtomicU64,
    /// When the writer's own root came to each walk, by its place: what a pass that
    /// reached the writer's state confirms is as of then, never later — what its walk
    /// went on to fetch after the root says nothing of whether the writer still holds it.
    rooted: Mutex<BTreeMap<usize, Instant>>,
    /// Wakes the pass.
    wake: Arc<Notify>,
}

/// A walk of a refresh loop's pass ([`Inner::refresh_pass`]).
struct Reach {
    /// Its place among the pass's walks, in the order they began.
    index: usize,
    pass: Arc<Pass>,
    /// [`Busy::heard`] as it began, if a notice then was not answered yet
    /// ([`Busy::answered`]): the walk answers the notices up to it.
    answers: Option<u64>,
}

impl Reach {
    /// The walk is past the way to its versions — it took a version its
    /// root lists, so its root and the nodes on the way came; or a round
    /// of asks for a node on the way missed, so its root is a slow way to
    /// what was written since: the pass is woken, unless a walk begun after
    /// it got past first.
    fn past(&self) {
        if self.pass.past.fetch_max(self.index + 1, Ordering::Relaxed) <= self.index {
            self.pass.wake.notify_one();
        }
    }
}

/// A walk's ask under way ([`Inner::asking`]), telling whether it took what
/// it asked for.
type WalkAsk = futures::future::Shared<futures::channel::oneshot::Receiver<bool>>;

/// One packet a summary being walked lists (spec §17.1, inside a walk):
/// `round` — [`FETCH_TRIES`] asks of its writer's device in the first
/// round, and in each later one, at the same time, of the writer and of
/// the devices answering for it ([`first_some`]) — asked again in place
/// after [`retry_pause`] while it misses, up to [`FETCH_TRIES`] rounds,
/// each told its number from 0. A walk takes its branches side by side and
/// ends only once the last of them did, so a packet left to the next walk
/// waits for every other branch of this one first: under a long walk (a
/// first catch-up, a writer that never pauses) that is far longer than a
/// round. Only when every round missed is the walk asked again from the
/// root.
async fn in_rounds<T, F: Future<Output = Option<T>>>(mut round: impl FnMut(u32) -> F) -> Option<T> {
    for tries in 0..FETCH_TRIES {
        if tries > 0 {
            rt::sleep(retry_pause(tries - 1)).await;
        }
        if let Some(got) = round(tries).await {
            return Some(got);
        }
    }
    None
}

/// What the first of `a` and `b` to come with something came with, or
/// `None` once both came with nothing: a writer asked again at the same
/// time as the devices answering for it, so neither waits on the other
/// (spec §13.5, §17.1).
async fn first_some<T>(
    a: impl Future<Output = Option<T>>,
    b: impl Future<Output = Option<T>>,
) -> Option<T> {
    let (a, b) = (std::pin::pin!(a), std::pin::pin!(b));
    match futures::future::select(a, b).await {
        futures::future::Either::Left((Some(got), _))
        | futures::future::Either::Right((Some(got), _)) => Some(got),
        futures::future::Either::Left((None, other)) => other.await,
        futures::future::Either::Right((None, other)) => other.await,
    }
}

/// The most times one ask expresses its Interest again within its lifetime
/// (spec §17.1): an ask sends at most 1 + this Interests.
const REEXPRESS_MAX: u32 = 3;

/// The shortest wait before an unanswered Interest is expressed again
/// (spec §17.1): the longest a forwarder's retransmission suppression
/// holds back a fresh-nonce Interest from the same face (NFD
/// `RetxSuppressionExponential` caps its window at 250 ms), so a
/// re-expression always goes on upstream. Also the least of the lifetime
/// that must be left for one.
const RTO_MIN: Duration = Duration::from_millis(250);

/// The device's round-trip estimate, from which it times re-expressing an
/// unanswered Interest (spec §17.1, RFC 6298): the smoothed round trip and
/// its variation over the asks answered by their first Interest, and how
/// many asks since the last such answer needed a re-expression or missed.
/// An ask answered after a re-expression gives no sample (Karn: which
/// Interest was answered is not known). Before any sample nothing is
/// re-expressed: the timeout is the lifetime.
#[derive(Debug, Default)]
struct Rtt {
    srtt: Option<Duration>,
    rttvar: Duration,
    backoff: u32,
}

impl Rtt {
    /// Take the round trip of an ask answered by its first Interest.
    fn sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                self.rttvar = (self.rttvar * 3 + srtt.abs_diff(r)) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
        self.backoff = 0;
    }

    /// An ask needed a re-expression, or nothing answered it: the next
    /// waits twice as long, until an ask gives a sample again.
    fn missed(&mut self) {
        self.backoff = (self.backoff + 1).min(16);
    }

    /// The wait before expressing an unanswered Interest again:
    /// srtt + 4·rttvar (the lifetime before any sample), doubled per
    /// [`Self::missed`] since the last sample, at least [`RTO_MIN`] and at
    /// most `lifetime`.
    fn rto(&self, lifetime: Duration) -> Duration {
        self.srtt
            .map_or(lifetime, |srtt| srtt + self.rttvar * 4)
            .saturating_mul(1 << self.backoff)
            .clamp(RTO_MIN, lifetime.max(RTO_MIN))
    }
}

/// How long the committer waits before it asks the store again for a flush
/// that failed ([`Inner::commit_rounds`]); doubled each time up to
/// [`COMMIT_RETRY_MAX`]. Nothing written since the last flush is published
/// meanwhile.
const COMMIT_RETRY: Duration = Duration::from_millis(100);

/// The longest pause between two flushes asked of a store that failed.
const COMMIT_RETRY_MAX: Duration = Duration::from_secs(30);

/// The `tracing` target of the timeline events (level `trace`): the few seams
/// a put crosses on its way to another device's watch, each one named by its
/// message so a recorder can lay one put's journey out in time — `flush_begin`
/// / `flush_end` (the store's durability barrier of a commit round),
/// `announce` (the announcement handed to the sync group), `sync_update` (a
/// notice of another device heard), `fetch_out` / `fetch_in` / `fetch_miss`
/// (one ask of the network: its name, and how many Interests it expressed),
/// `verify_begin` / `verify_end` (one signature chain judged) and `watch_send`
/// (a change handed to a watcher). Disabled, each costs the callsite check
/// and nothing else; none changes what the device does. The benchmark
/// `ndn-link/examples/ladder.rs` records them.
const TIMELINE: &str = "ndn_data::timeline";

/// Why this device owes a collection (or folder) a new members record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owed {
    /// Its record merges concurrent ones and leaves a reader to add to its
    /// epoch or a removal to carry out in a new one (spec §6).
    Merge,
    /// A group its record names as a reader dropped a reader (spec §6).
    Group,
    /// A folder above it dropped a reader its own record lists: its record
    /// moves to a new epoch without that reader (spec §6).
    Folder,
}

/// Whose members records: a collection's, or a folder's (spec §6). A name
/// may be both, as two separate lines.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Subject {
    name: Name,
    folder: bool,
}

/// What a held log entry is.
enum Held {
    Version(VersionId),
    /// A version whose payload is sealed and not opened here.
    Locked,
    /// A members or introduction record: the key that
    /// signed it, its implicit digest and the digest of its signed region
    /// ([`wire::signed_digest`]), which says whether another packet at its name is another
    /// thing the key signed.
    Record {
        writer: Writer,
        digest: [u8; 32],
        signed: [u8; 32],
    },
}

/// A log entry refused by the trust context governing its name, kept
/// against its name with its implicit digest (spec §8): its key is revoked
/// and that key's cut does not accept it, so a host can hand its full name
/// to the namespace owner, who may re-admit exactly it; or a key above its
/// signer is refused ([`Refusal::Untrusted`]), which no cut excuses, and it
/// is taken back only if its chain verifies again.
struct OutOfCut {
    /// The key that signed it, as its packet names it.
    writer: Writer,
    /// Its implicit digest.
    digest: [u8; 32],
    /// The packet, when it was refused as it arrived (never taken), or
    /// withdrawn for its chain: a re-admission or a new judgement takes it
    /// from here.
    wire: Option<Bytes>,
    /// Why: [`Refusal::OutsideCut`] with the cut that refuses it, or
    /// [`Refusal::Untrusted`].
    why: Refusal,
}

impl OutOfCut {
    /// Whether a cut refuses it (and an exact re-admission may let it in).
    fn by_cut(&self) -> bool {
        matches!(self.why, Refusal::OutsideCut(_))
    }
}

/// When this device first verified a held log entry, by its own clock,
/// and which public key verified it (spec §8): what a revocation cut it
/// vouches for is bounded by ([`Device::revocation_cut`]). Kept in the
/// store beside the entry ([`verified_name`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Verified {
    /// `None` for an own entry kept before times were recorded.
    at: Option<Timestamp>,
    /// SHA-256 of the public key, as its certificate stores it, that
    /// verified the entry; `None` when not known.
    key: Option<[u8; 32]>,
    /// This device wrote it ([`written_name`]).
    own: bool,
}

/// An entry a newer trust context lets in (spec §8): refused here by a
/// revocation before, or re-admitted exactly and not held.
struct Readmit {
    name: Name,
    /// Its implicit digest, when exactly those bytes are to be fetched.
    digest: Option<[u8; 32]>,
    /// Its packet, when held.
    wire: Option<Bytes>,
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
    /// The head of the root last processed in full, in this run or an
    /// earlier one (kept in the store, [`walked_name`]).
    walked: u64,
    /// What this device followed in the namespace when it
    /// walked that root: the walk took the folder records above these
    /// only, and the versions under them.
    toward: BTreeSet<Name>,
    /// What this device followed in the namespace when it walked that root
    /// in full, in this run: the walks took the versions under these. Empty
    /// after a restart, so a name followed then is walked toward anew.
    followed: BTreeSet<Name>,
    /// Nodes and pages processed in full, by subject and page path.
    nodes: HashMap<(Name, Option<Bytes>), [u8; 32]>,
    /// How many times what was processed was forgotten ([`Peer::forget`]):
    /// a walk under way since before records nothing as processed, for it
    /// went toward less than is followed now.
    resets: u64,
    /// Its roots lie in a person's namespace no trust context held here
    /// judges ([`Inner::unjudged`]): refused whoever serves them, so not
    /// asked for, and no try of a walk is spent on them (spec §17.1).
    unjudged: Option<Unjudged>,
    /// Its walks spent their tries with no root of it verified:
    /// [`REFRESH_TRIES`] walks in one refresh loop ended so, every round of
    /// their root missed or not checking ([`Inner::refresh_loop`]); or its
    /// roots are judged by no context held here and no record held lists
    /// its person (not asked). While nothing held vouches for it
    /// ([`Inner::vouched`]), it then no longer holds back what waits for
    /// the devices not walked ([`Inner::not_walked`]): a name a Sync
    /// Interest carried holds nothing back for longer than those tries, and
    /// a real device that a faulty path kept from one walk still does.
    unreached: bool,
}

/// Where another device's roots stand that no trust context held here
/// judged when last asked for ([`Peer::unjudged`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unjudged {
    /// No trust context held judges them: asking learns nothing until one
    /// is adopted.
    Unheld,
    /// A context adopted since judges them — the node's own adoption, or
    /// one for a folder's scope (spec §6.3): the walk is owed until a root
    /// of them verifies ([`St::owes_walk`]).
    Adopted,
}

impl Peer {
    /// Forget that walks took `subject` in full — what is followed
    /// under it changed, or a version of it was let go: the root,
    /// and the nodes and pages on the way to it and under it, are walked
    /// again, and no walk under way since before records any as processed.
    fn forget(&mut self, subject: &Name) {
        self.root = None;
        self.nodes
            .retain(|(s, _), _| !subject.has_prefix(s) && !s.has_prefix(subject));
        self.resets += 1;
    }
}

/// A namespace's sync group as this device takes part in it.
struct SyncGroup {
    /// The group's publish channel, once joined.
    tx: Option<mpsc::Sender<(Name, Option<Bytes>)>>,
    /// An announcement is wanted: the next commit round makes it, once
    /// what it announces is durable ([`Inner::commit_rounds`]).
    pending: bool,
    /// Devices heard in the group, at most [`heard::HEARD_MAX`]
    /// ([`heard::Heard::hear`]).
    members: heard::Heard,
    /// Devices being refreshed ([`Inner::refresh_loop`]).
    busy: HashMap<Name, Busy>,
    /// When the device last knew nothing newer was outstanding.
    confirmed: Option<Instant>,
    /// The group counter of this device's latest announcement in the group
    /// (from the join on): kept in the store before each announcement goes
    /// out ([`announced_name`]), so a restart starts above it.
    announced: u64,
    /// The group is asked again for its members' state while this device
    /// has heard no device that writes into the namespace ([`Inner::hail`]).
    hailing: bool,
    /// This device's newest announcement goes out again while no member is
    /// heard to have taken it ([`Inner::herald`]).
    heralding: bool,
    /// A run of [`Inner::herald`] ended with every announcement out and no
    /// member heard to take any: [`St::root_asks`] then. While it has not
    /// moved — no member walked any root of this device since — no change
    /// is announced again in this group: its members take changes, if at
    /// all, without walking this device, so nothing would ever stop a run.
    unheard: Option<u64>,
    /// The highest counter of each device the group's Sync Interests heard
    /// here carried, this device's own among them ([`Inner::herald`]).
    observed: Option<Arc<ObservedState>>,
    /// The highest `(boot, counter)` of each device a notice of the group
    /// brought here ([`Inner::on_update`]), kept for the devices the
    /// group's state vector tracks and dropped when the device's refresh
    /// loop ends short of its state ([`Inner::refresh_loop`]): a Sync
    /// Interest carrying none above them brings nothing newer than is held
    /// ([`Inner::heard`]).
    noticed: HashMap<Name, (u64, u64)>,
}

/// A device whose refresh loop runs ([`Inner::refresh_loop`]).
struct Busy {
    /// A notice of it arrived since the loop's newest walk began: its
    /// newest root is walked again.
    again: bool,
    /// Sync notices of it heard since the loop began.
    heard: u64,
    /// How many of [`Busy::heard`] a walk answered: one begun after them
    /// that took a root the device itself gave ([`Inner::refresh`], spec
    /// §17.1). Until then a root a device answering for it gave, behind
    /// what it announced perhaps, does not end the loop.
    answered: u64,
    /// Something held here, not a notice, asked for a walk since the
    /// loop's newest pass began (a name followed, a namespace adopted): the
    /// pass it asks for begins at once, not after the pause notices that
    /// bring nothing new earn ([`Inner::refresh_loop`]).
    asked: bool,
    /// Wakes the loop's pass ([`Inner::refresh_pass`]) when a notice
    /// arrives.
    wake: Arc<Notify>,
}

struct Watcher {
    target: Name,
    since: Frontier,
    /// Bounded: what the watch listed when it began, then
    /// [`Config::watch_queue`] changes, then one slot for
    /// [`Change::Lagged`] ([`Self::send`]).
    tx: mpsc::Sender<Result<Change, DataError>>,
    /// Told [`Change::Lagged`], and not read empty since: every change is
    /// dropped until it is.
    lagged: bool,
}

impl Watcher {
    /// Deliver `change` (spec §15). A watcher too slow to read what it was
    /// sent is not queued for without bound: the last slot of its queue
    /// takes [`Change::Lagged`], and from there every change is dropped
    /// until it read the queue empty, then delivery goes on. It learns of
    /// the gap in order, after every change it was sent, and reads again
    /// from the frontier it holds.
    fn send(&mut self, change: Change) {
        if self.lagged {
            if self.tx.capacity() < self.tx.max_capacity() {
                return;
            }
            self.lagged = false;
        }
        if self.tx.capacity() <= 1 {
            self.lagged = true;
            let _ = self.tx.try_send(Ok(Change::Lagged {
                collection: self.target.clone(),
            }));
            return;
        }
        tracing::trace!(target: TIMELINE, "watch_send");
        let _ = self.tx.try_send(Ok(change));
    }
}

struct SignedRoot {
    content: Bytes,
    wire: Bytes,
}

/// Mutable state, under one lock never held across an await.
struct St {
    /// This device's namespace.
    ns: Name,
    /// The own log's head: the seq of the newest entry this device signed.
    head: u64,
    /// The own log's durable head: every own entry up to it is behind the
    /// store's barrier ([`DataStore::sync`] returned after it was stored).
    /// Only those are published — served, listed in a summary or head,
    /// announced (spec §4.2): what a power loss can take is above it, and
    /// nobody saw it.
    durable: u64,
    /// Commit rounds begun, and the newest whose flush returned
    /// ([`Inner::commit_rounds`]).
    round: u64,
    round_done: u64,
    /// A flush is wanted though no own entry or announcement waits for one
    /// ([`Inner::barrier`]).
    flush_wanted: bool,
    trees: HashMap<Name, Tree>,
    roots: HashMap<Name, SignedRoot>,
    colls: BTreeMap<Name, Coll>,
    /// The folders whose records are held (spec §6).
    folders: HashMap<Name, Folder>,
    held: HashMap<Name, Held>,
    peers: HashMap<(Name, Name), Peer>,
    /// By name, so what is done group by group (announcements, their
    /// re-announcements) goes out in the same order in every run (§18.1).
    groups: BTreeMap<Name, SyncGroup>,
    /// Asks this device answered for its own newest root of any namespace
    /// (`<device>/32=summary/<O>/32=root`): a member walking one after an
    /// announcement took a change this device announced ([`Inner::herald`]).
    /// Members walk it in every namespace they follow that it writes into,
    /// whatever group they heard the announcement in.
    root_asks: u64,
    follows: BTreeSet<Name>,
    watchers: Vec<Watcher>,
    /// While the records in force are made again from those held
    /// ([`Inner::rebuild_members`]): what is in force passes through
    /// records that were in force before, so nothing is told until it is
    /// made, and then only what changed (spec §15).
    quiet_members: bool,
    refused: HashMap<Name, Refusal>,
    /// The log entries refused by a revocation, by name: each also in
    /// `refused`, as [`Refusal::OutsideCut`].
    cut_out: HashMap<Name, OutOfCut>,
    /// Entries a revocation cut lists, or re-admits, being fetched.
    cut_fetching: BTreeSet<Name>,
    /// Asks in a row of what revocation cuts accept that left some of it
    /// not to be had ([`Inner::fetch_cut_runs`]): each asks again after a
    /// growing pause, up to [`READMIT_TRIES`].
    cut_misses: u32,
    /// Entries a trust context re-admits exactly that were not to be had
    /// when asked for: their digest, and how many times they were asked.
    readmitting: BTreeMap<Name, ([u8; 32], u32)>,
    /// The packets of removal cuts' manifests held (spec §8), by full
    /// name: a cache over the store, where every one taken is kept
    /// ([`load_cut_bytes`] reads it back).
    cut_bytes: CutManifests,
    /// Packets of removal cuts' manifests not held that versions wait for,
    /// with the collections those versions are in: fetched, then the
    /// collections read again ([`Inner::fetch_wanted_bytes`]).
    bytes_wanted: BTreeMap<Name, BTreeSet<Name>>,
    /// Of those, how many fetches of each missed in a row ([`retry_pause`]).
    bytes_misses: HashMap<Name, u32>,
    /// Packets of removal cuts' manifests, and log entries such cuts keep,
    /// being fetched.
    bytes_fetching: BTreeSet<Name>,
    /// Log entries a removal cut keeps bound to bytes whose other bytes
    /// were refused here, with that cut and how many times the kept bytes
    /// were asked for in vain: nothing of them is held, and the bytes the
    /// cut keeps are still taken when they come, asked for by their full
    /// name (spec §8, [`Inner::fetch_kept`]).
    other_bytes: HashMap<Name, (Cut, u32)>,
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
    /// Askers' seal keys a grant's ask in place did not get, asked again in
    /// the background ([`Inner::learn_seal_key`]): one run per key, at most
    /// [`SEAL_LEARNING_MAX`] (and [`SEAL_LEARNING_PER_ASKER`] of one asker);
    /// each run removes its key when it ends.
    seal_learning: BTreeSet<Name>,
    /// The walks started in the background of a put or a join that are
    /// under way, by (namespace, device): one at a time for each
    /// ([`Inner::walk_in_background`]).
    walking: BTreeSet<(Name, Name)>,
    /// The device's seal key packet, once signed.
    seal_key: Option<Bytes>,
    /// Collections and folders of this namespace this device owes a new
    /// members record.
    owed: BTreeMap<Subject, Owed>,
    /// Groups a record held names that this device is to follow.
    to_follow: BTreeSet<Name>,
    /// Per group, the collections and folders whose own record in force
    /// names it a reader.
    sealed_to: HashMap<Name, BTreeSet<Subject>>,
    /// Large versions whose pieces are being fetched.
    fetching: BTreeSet<Name>,
    /// Register versions in pieces a fetch found whole: not fetched again
    /// while they wait to open (for their epoch's key, or to apply).
    walked: BTreeSet<Name>,
    /// Register versions in pieces a fetch did not find whole (yet): not
    /// fetched again until [`Inner::retry_pieces`] asks.
    unfound: BTreeSet<Name>,
    /// Of those, how many fetches of each missed in a row: it is asked again
    /// after [`retry_pause`] of that, while it is still wanted (spec §17.1).
    piece_misses: HashMap<Name, u32>,
    /// The packets of parents pending versions name that are being asked for
    /// by full name, or waiting to be asked for again ([`St::wanted_wires`]):
    /// (the parent's log entry name, the packet's implicit digest).
    wiring: BTreeSet<(Name, [u8; 32])>,
    /// Of those, how many asks of each missed in a row ([`retry_pause`]).
    wire_misses: HashMap<(Name, [u8; 32]), u32>,
    /// The first log entry taken here at each seq of each key, of any
    /// collection and any kind: a key's log is one sequence (spec §4).
    seqs: HashMap<(Writer, u64), Name>,
    /// Every seq at which a key signed more than one entry, with the names
    /// of those entries: equivocation, its evidence kept (spec §4).
    equivocal: HashMap<Writer, BTreeMap<u64, Vec<Name>>>,
    /// Each collection of others' data this device follows only through a
    /// folder above it, by the writer whose version or summary made it
    /// follow it ([`Self::track`]): rebuilt from the versions held at
    /// start, so a writer's count lasts across a restart.
    brought: HashMap<Name, Writer>,
    /// How many collections of each namespace each writer outside it made
    /// this device follow ([`Self::brought`]), against
    /// [`Config::writer_collections`].
    bringing: HashMap<(Writer, Name), usize>,
    /// The second packet held of each log entry name a writer signed two
    /// different packets under (spec §4): kept in the store
    /// ([`equivocal_name`]) and read back at start, so the evidence lasts.
    twins: HashMap<Name, Bytes>,
    /// Per asker device, its introduction and grant asks this device is
    /// working on.
    asks: HashMap<Name, usize>,
    /// Answers to introduction asks signed, by the ask's name.
    answers: Kept<Bytes>,
    /// When each held log entry was first verified here, and by which
    /// public key ([`Verified`]).
    verified: HashMap<Name, Verified>,
    /// Keys marked suspected here, and since when ([`Device::suspect`]):
    /// no new entry of one is taken while no trust context revokes it.
    suspected: BTreeMap<Name, Timestamp>,
    /// The trust context last taken of each namespace, so an adoption that
    /// refuses more than it did re-judges what is held ([`Inner::adopted`]).
    contexts: HashMap<Name, Arc<SignedTrustContext>>,
    /// Introductions: offers, use marks and answers (spec §19).
    intro: intro::Intros,
    /// Whether the store is being read back at start ([`Inner::restore`]).
    restoring: bool,
    /// The persons' namespaces the records in force list as writers, and
    /// what is adopted of them for those records' subjects (spec §6.3).
    scopes: scoped::Scopes,
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
    /// `store`, as the stage that keeps a put's writes together
    /// ([`stage::Stage::batch`]).
    stage: Arc<stage::Stage>,
    config: Config,
    svs: MultiSvs,
    st: Mutex<St>,
    progress: Notify,
    /// Wakes the committer ([`Inner::commit_rounds`]): something was written that
    /// waits for the barrier, or an announcement is wanted.
    commit_wake: Arc<Notify>,
    /// Told after each commit round that moved [`St::durable`].
    committed: Notify,
    /// The signal sequence counter and time hint ([`Device::signal_sequences`],
    /// [`Device::note_signal_time`]).
    signal_clock: Mutex<signal::SignalClock>,
    slots: Semaphore,
    /// The round-trip estimate re-expressions are timed from (spec §17.1).
    rtt: Mutex<Rtt>,
    /// What walks ask for now ([`Inner::asked_once`]): a members record or
    /// version by its name, a summary node by its exact name with the
    /// [`Peer::resets`] its walk began at. A second walk listing the same
    /// waits for the first's ask, and its outcome, rather than asking again.
    asking: Mutex<HashMap<(Name, Option<u64>), WalkAsk>>,
    /// Asker proofs being verified ([`Config::asks_verifying`]).
    verifying: Semaphore,
    signatures: AtomicU64,
    /// Epoch keys asked for ([`Device::grants_asked`]).
    grants_asked: AtomicU64,
    /// Grants signed for askers ([`Device::grants_answered`]).
    grants_answered: AtomicU64,
    started: Instant,
    serving: Mutex<Option<ServeGuard>>,
    /// Set by [`Device::shutdown`]: trust contexts adopted from then on are
    /// not taken (a restart judges what is held again).
    stopped: AtomicBool,
    /// The digest of the device key's public key, as its certificate
    /// stores it ([`Verified::key`] of its own entries).
    own_key: Option<[u8; 32]>,
    /// What the signal gate keeps between questions (spec §20).
    signals: signal::SignalGate,
}

/// What [`Inner::rejudge`] judges again.
enum Rejudge {
    /// Every entry held (a restart).
    All,
    /// Every entry held under the trust context of this namespace (one
    /// adopted that may refuse more), and those withdrawn for their chain.
    Namespace(Name),
    /// The entries withdrawn for their chain: of this key, or every one.
    Withdrawn(Option<Name>),
    /// These entries (what waited for a certificate or manifest packet).
    Names(Vec<Name>),
}

/// What the durable rule, run again, means for a held entry.
enum Verdict {
    Accepted,
    /// Its key's revocation cut does not accept it.
    Cut(Cut),
    /// Its chain is refused, for this reason.
    Chain(String),
    /// It waits for this certificate or cut manifest packet.
    Pending(Name),
    /// Nothing signed decides it either way now.
    Undecided,
}

/// The key that signed the held log entry `name`, if held as an entry.
fn held_signer<'a>(st: &'a St, name: &Name, held: &'a Held) -> Option<&'a Writer> {
    match held {
        Held::Version(id) => Some(&id.writer),
        Held::Record { writer, .. } => Some(writer),
        Held::Locked => parse_log_name(name)
            .and_then(|l| st.colls.get(&l.subject?))
            .and_then(|coll| coll.locked.iter().find(|l| l.name == *name))
            .map(|l| &l.writer),
    }
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

/// A summary root checked against its writer's signature and its name
/// ([`Inner::check_root`]), not yet taken: the packet, its signer and its
/// body.
struct Rooted {
    data: Data,
    writer: Writer,
    body: NodeBody,
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
/// signature by `writer`, a key of `D`, verified) about collection `c` is
/// signed by a device of `c`'s namespace, so its owner (spec §3): `D` lies
/// under the namespace ([`crate::wire::owns`], the test a merge rule asks
/// too), and the trust context governing the record's name — the one the
/// validator verified it under, the held context whose namespace is the
/// longest prefix of it — is the namespace's own. A device under the
/// namespace that a longer held namespace governs (a `/home/bob` device,
/// for `/home`) is that namespace's device, not an owner.
fn owner_signed(keyring: &Keyring, entry: &Name, c: &Name, writer: &Writer) -> bool {
    crate::wire::owns(c, writer)
        && namespace_of(c).is_some_and(|ns| *keyring.context_for(entry).namespace() == ns)
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

/// What a collection's versions wait for (spec §5): the entries known
/// here, and which of them never apply.
#[derive(Clone, Copy)]
struct Waits<'a> {
    /// The collection: cuts accept versions per collection.
    collection: &'a Name,
    members: Option<&'a Members>,
    entries: &'a HashMap<Writer, BTreeSet<u64>>,
    skipped: &'a HashMap<Writer, BTreeSet<u64>>,
    locked: &'a [Locked],
    /// The revocation cuts of keys writing here ([`Coll::revoked`]).
    revoked: &'a HashMap<Writer, Cut>,
    /// The versions admitted here.
    admitted: &'a BTreeMap<VersionId, Arc<HeldVersion>>,
    /// The other packets seen at the names of versions held ([`Coll::wires`]).
    wires: &'a HashMap<VersionId, Vec<Wire>>,
}

impl Waits<'_> {
    /// Whether later versions of `id`'s writer, and versions naming `id` as
    /// a parent, need not wait for it: [`skipped_by`]; or its key is revoked
    /// and its cut does not accept it ([`Self::outside_cut`]).
    fn never(&self, id: &VersionId) -> bool {
        skipped_by(self.members, self.skipped, id) || self.outside_cut(id)
    }

    /// Whether `id`'s key is revoked, its cut does not accept `id`, and no
    /// exact re-admission brought it in (it is not admitted here).
    fn outside_cut(&self, id: &VersionId) -> bool {
        self.revoked
            .get(&id.writer)
            .is_some_and(|cut| !cut.accept.contains(self.collection, id))
            && !self.admitted.contains_key(id)
    }

    /// Whether the packet `digest` (the implicit digest a child names its
    /// parent `id` by) is what is held here at `id`: admitted, or held
    /// sealed and locked.
    fn names(&self, id: &VersionId, digest: &[u8; 32]) -> Packet {
        let held = self.admitted.get(id).map(|hv| hv.digest).or_else(|| {
            self.locked
                .iter()
                .find(|l| l.writer == id.writer && l.seq == id.seq.0)
                .map(|l| wire::implicit_digest(&l.wire))
        });
        let Some(held) = held else {
            return Packet::NotHeld;
        };
        if held == *digest {
            return Packet::Held;
        }
        match self
            .wires
            .get(id)
            .and_then(|w| w.iter().find(|w| w.digest == *digest))
        {
            Some(w) if w.same => Packet::Held,
            Some(_) => Packet::Another,
            None => Packet::Unknown,
        }
    }
}

/// Whether the packet a child names its parent by is the one held there
/// ([`Waits::names`]).
enum Packet {
    /// No packet is held at the parent's name yet.
    NotHeld,
    /// The packet held, or another copy of it in another signature value:
    /// the same signed version.
    Held,
    /// A packet that signed another thing at the parent's name, held as
    /// evidence ([`Wire::same`]): its key signed two entries there.
    Another,
    /// Not seen here: another packet is held, and this one may be a copy of
    /// it (asked for by its full name, [`St::wanted_wires`]) or nothing.
    Unknown,
}

/// The seq of `y` that a version naming `(y, t)` among its parents needs
/// applied: `t`; or, when `(y, t)` never applies (a cut does not list it,
/// or it was refused for what it carries), the highest version of `y` at or
/// below `t` that does: for a cut, the highest it accepts (or, of a revoked
/// key, an exact re-admission admitted here).
fn needed(w: &Waits, y: &Writer, t: u64) -> u64 {
    let id = |s: u64| VersionId {
        writer: y.clone(),
        seq: Seq(s),
    };
    if let Some(Refusal::OutsideCut(cut)) = w.members.and_then(|m| m.refusal(&id(t))) {
        return cut.accept.highest_at_most(w.collection, y, t).unwrap_or(0);
    }
    if let Some(cut) = w.revoked.get(y)
        && w.outside_cut(&id(t))
    {
        let readmitted = w
            .admitted
            .range(id(0)..=id(t))
            .next_back()
            .map(|(v, _)| v.seq.0);
        return cut
            .accept
            .highest_at_most(w.collection, y, t)
            .max(readmitted)
            .unwrap_or(0);
    }
    if !w.never(&id(t)) {
        return t;
    }
    w.entries
        .get(y)
        .and_then(|e| e.range(..t).rev().find(|s| !w.never(&id(**s))).copied())
        .unwrap_or(0)
}

/// Whether a version is ready to apply: its writer's earlier entries here
/// that apply at all, and its parents (as far as they apply), are applied.
fn ready(w: &Waits, applied: &BTreeMap<Writer, u64>, v: &Version) -> bool {
    let writer = &v.id.writer;
    let prev = w.entries.get(writer).and_then(|e| {
        e.range(..v.id.seq.0)
            .rev()
            .find(|s| {
                !w.never(&VersionId {
                    writer: writer.clone(),
                    seq: Seq(**s),
                })
            })
            .copied()
    });
    prev == applied.get(writer).copied()
        && v.parents.iter().all(|(y, t)| {
            let need = needed(w, y, t.0);
            need == 0 || applied.get(y).is_some_and(|a| *a >= need)
        })
}

/// P of version `v` (spec §5): its parents joined with (its writer,
/// seq − 1). down(P) is what it was made over.
fn past_frontier(v: &Version) -> Frontier {
    let mut within = v.parents.frontier().clone();
    if let Some(before) = v.id.seq.0.checked_sub(1).filter(|s| *s > 0) {
        within.include(&VersionId {
            writer: v.id.writer.clone(),
            seq: Seq(before),
        });
    }
    within
}

/// The past of a version as its rule sees it (spec §5): down
/// ([`past_frontier`]) — the versions inside it not refused by their key.
/// A version refused by its key — a cut that does not list it, a key no
/// writer, a revocation, an issuer no longer trusted — is in no past,
/// whether this device holds it or not (a late reader never fetches it), so
/// every reader answers alike.
struct PastOf<'a> {
    within: Frontier,
    waits: Waits<'a>,
}

impl<'a> PastOf<'a> {
    fn new(v: &Version, waits: Waits<'a>) -> Self {
        PastOf {
            within: past_frontier(v),
            waits,
        }
    }

    /// Whether `id` is refused by its key: by the record in force, or a
    /// revocation whose cut does not accept it.
    fn key_refused(&self, id: &VersionId) -> bool {
        self.waits.members.is_some_and(|m| m.refusal(id).is_some()) || self.waits.outside_cut(id)
    }
}

impl Past for PastOf<'_> {
    fn contains(&self, id: &VersionId) -> bool {
        self.within.contains(id) && !self.key_refused(id)
    }
}

/// What an own version is written under: its collection's record in force
/// (or the one about to be signed for it), and the state's frontier.
struct Under {
    /// The record's readers: the version's declared seal.
    readers: Vec<Audience>,
    /// The merge rule's name; `None` under the log rule.
    function: Option<Name>,
    /// The version's parents: the state's frontier, each tip with its
    /// packet's digest.
    parents: Parents,
}

/// An own log entry signed and not yet kept ([`Inner::sign_entry`]).
struct LogEntry {
    name: Name,
    seq: u64,
    wire: Bytes,
    record: Record,
}

/// An own members record signed and not yet kept
/// ([`Inner::sign_members`]): the entry, the epoch it starts with its key,
/// and the packets of its cuts' manifest, root first.
type SignedMembers = (LogEntry, Option<(Epoch, ContentKey)>, Vec<Bytes>);

/// An own version signed and not yet kept ([`Inner::sign_version`]).
struct Signed {
    c: Name,
    seq: u64,
    held: HeldVersion,
    pieces: Vec<pieces::Piece>,
    function: Option<Name>,
}

/// Apply `held`, an own version, to `state` over `past`: the register's
/// write. `ops` reads the operations of the versions applied before it.
fn apply_own(
    state: &mut (dyn MergeState + 'static),
    held: &HeldVersion,
    past: &PastOf<'_>,
    ops: &dyn Ops,
) {
    state.apply(&Op {
        id: &held.version.id,
        signed: &held.signed,
        past,
        bytes: &held.op,
        ops,
    });
}

/// The operations of the versions held in a collection, for the register
/// to read the head that wins once the winner is superseded: an operation
/// in memory, or one in pieces read from `store`.
struct OpsOf<'a> {
    versions: &'a BTreeMap<VersionId, Arc<HeldVersion>>,
    store: &'a dyn DataStore,
    keys: &'a Keys,
}

impl Ops for OpsOf<'_> {
    fn op_of(&self, id: &VersionId) -> Option<Bytes> {
        let hv = self.versions.get(id)?;
        if hv.opened {
            return Some(hv.op.clone());
        }
        match open_held(self.store, self.keys, hv) {
            Opening::Opened(op) => Some(op),
            _ => None,
        }
    }
}

/// What opening a version in pieces found.
enum Opening {
    /// Whole and opened: its operation.
    Opened(Bytes),
    /// The key of its epoch is not held (yet).
    NoKey,
    /// A piece is not held yet.
    Missing,
    /// Whole, and its payload does not open: its writer signed what does
    /// not decode.
    Bad,
}

/// Open `hv`, a version whose payload travels in pieces, from the pieces
/// `store` holds (spec §13.1): assembled, each piece checked against its
/// manifest, and unsealed under its epoch's key from `keys` (looked for
/// first: it costs no read of the pieces).
fn open_held(store: &dyn DataStore, keys: &Keys, hv: &HeldVersion) -> Opening {
    let key = match &hv.epoch {
        Some(e) => match keys.key(&hv.version.collection, e) {
            Some(key) => Some(key),
            None => return Opening::NoKey,
        },
        None => None,
    };
    open_with(store, key.as_ref(), hv)
}

/// [`open_held`] with the key of its epoch in hand (`None`: it is not
/// sealed).
fn open_with(store: &dyn DataStore, key: Option<&ContentKey>, hv: &HeldVersion) -> Opening {
    let Some(chunks) = hv.chunks else {
        return Opening::Missing;
    };
    let name = &hv.version.name;
    if !piece_names(name, &chunks).all(|p| store.contains(&p)) {
        return Opening::Missing;
    }
    let Some(payload) = pieces::assemble(name, &chunks, |p| store.get(p)) else {
        return Opening::Missing;
    };
    let op = match key {
        Some(key) => match seal::open_payload(key, name, &payload) {
            Some((_, op)) => op,
            None => return Opening::Bad,
        },
        None => match wire::decode_payload(Bytes::from(payload)) {
            Ok((_, op)) => op,
            Err(_) => return Opening::Bad,
        },
    };
    Opening::Opened(op)
}

/// A pending register version in pieces to open without holding the device's
/// lock ([`St::open_jobs`]): reading and unsealing a payload of up to
/// [`wire::PAYLOAD_MAX`] octets is work no other reader of the device waits
/// behind.
struct OpenJob {
    collection: Name,
    held: Arc<HeldVersion>,
    /// The key of its epoch; `None` when it is not sealed.
    key: Option<ContentKey>,
}

/// What each job opens to, outside the lock: the version's id, the digest of
/// the packet that was opened (it is installed only over that packet), and
/// the operation.
fn open_jobs(store: &dyn DataStore, jobs: &[OpenJob]) -> Vec<(Name, VersionId, [u8; 32], Bytes)> {
    jobs.iter()
        .filter_map(|job| match open_with(store, job.key.as_ref(), &job.held) {
            Opening::Opened(op) => Some((
                job.collection.clone(),
                job.held.version.id.clone(),
                job.held.digest,
                op,
            )),
            _ => None,
        })
        .collect()
}

/// The folder a collection is in: its name but the last component.
fn folder_of(c: &Name) -> Name {
    Name::from_components(c.components()[..c.len().saturating_sub(1)].iter().cloned())
}

/// What a [`Run`] did with one version, in order.
enum Ran {
    /// Applied: by the rule; or, under the log rule or inside the record's
    /// `since`, taken without one.
    Applied(VersionId),
    /// Refused for good — by the rule — and taken out of the admitted
    /// versions.
    Refused(Arc<HeldVersion>, Refusal),
}

/// One collection's pending versions run through its rule (spec §5):
/// each applied once its writer's earlier versions and its parents are; a
/// merge version only if it carries its operation in its record, only if it
/// was made for the rule in force, and only over the very packets its
/// parents name. Under the log rule (`state` `None`) versions apply without
/// a rule. The live state and [`St::value_at`] run the same procedure.
struct Run<'a> {
    members: &'a Members,
    entries: &'a HashMap<Writer, BTreeSet<u64>>,
    locked: &'a [Locked],
    revoked: &'a HashMap<Writer, Cut>,
    store: &'a dyn DataStore,
    keys: &'a Keys,
    state: Option<&'a mut (dyn MergeState + 'static)>,
    versions: &'a mut BTreeMap<VersionId, Arc<HeldVersion>>,
    skipped: &'a mut HashMap<Writer, BTreeSet<u64>>,
    applied: &'a mut BTreeMap<Writer, u64>,
    pending: &'a mut BTreeSet<VersionId>,
    /// The versions held and refused: those refused in this run join them.
    outsiders: &'a mut Vec<Arc<HeldVersion>>,
    /// Pending versions in pieces found not whole ([`Coll::unwhole`]): not
    /// looked for again until their pieces arrive.
    unwhole: &'a mut BTreeSet<VersionId>,
    /// The other packets seen at the names of versions held ([`Coll::wires`]).
    wires: &'a HashMap<VersionId, Vec<Wire>>,
    /// The packets pending versions name as parents that are not held
    /// ([`Coll::wants`]).
    wants: &'a mut BTreeSet<(VersionId, [u8; 32])>,
    out: Vec<Ran>,
}

/// What [`Run::parents_hold`] found of a version's parents.
enum Hold {
    /// Every parent that applies is held as the packet the version names.
    Yes,
    /// A parent that applies is not held yet.
    Waits,
    /// A parent is held as another packet than the one named: that packet
    /// (parent, implicit digest) is asked for by its full name.
    Wire(VersionId, [u8; 32]),
}

impl Run<'_> {
    fn waits(&self) -> Waits<'_> {
        Waits {
            collection: &self.members.collection,
            members: Some(self.members),
            entries: self.entries,
            skipped: self.skipped,
            locked: self.locked,
            revoked: self.revoked,
            admitted: self.versions,
            wires: self.wires,
        }
    }

    fn history(&self, id: &VersionId) -> bool {
        self.members.since.as_ref().is_some_and(|s| s.contains(id))
    }

    fn is_ready(&self, id: &VersionId) -> bool {
        self.pending.contains(id)
            && !self.unwhole.contains(id)
            && self
                .versions
                .get(id)
                .is_some_and(|hv| ready(&self.waits(), self.applied, &hv.version))
    }

    /// Apply everything that is ready; what was done, in order.
    fn run(mut self) -> Vec<Ran> {
        if self.state.is_some() {
            self.other_rule();
        }
        loop {
            let ready_now: Vec<VersionId> = self
                .pending
                .iter()
                .filter(|id| self.is_ready(id))
                .cloned()
                .collect();
            let mut moved = false;
            for id in ready_now {
                if !self.is_ready(&id) {
                    continue;
                }
                moved |= self.take(&id);
            }
            if !moved {
                break;
            }
        }
        // Only a packet a pending version still names is wanted.
        let (versions, pending) = (&*self.versions, &*self.pending);
        self.wants.retain(|(parent, digest)| {
            pending.iter().filter_map(|p| versions.get(p)).any(|hv| {
                hv.version
                    .parents
                    .tips()
                    .any(|(y, t, d)| *y == parent.writer && t == parent.seq && d == Some(digest))
            })
        });
        self.out
    }

    /// Every pending version made for another rule than the one in force
    /// is refused (spec §5): what it carries is read only under its own.
    /// Versions inside the record's `since` are its history, taken without
    /// a rule.
    fn other_rule(&mut self) {
        let Rule::Merge { function } = &self.members.rule else {
            return;
        };
        let other: Vec<(VersionId, Refusal)> = self
            .pending
            .iter()
            .filter(|id| !self.history(id))
            .filter_map(|id| {
                let made_for = &self.versions.get(id)?.version.rule;
                (made_for.as_ref() != Some(function)).then(|| {
                    let why = Refusal::OtherRule {
                        made_for: made_for.clone(),
                        in_force: function.clone(),
                    };
                    (id.clone(), why)
                })
            })
            .collect();
        for (id, why) in other {
            tracing::debug!(?id, %why, "refused");
            self.refuse(&id, why);
        }
    }

    /// Whether each parent of `id` is held here as the very packet it names
    /// (spec §5): [`Hold::Waits`] while a parent that applies is not held
    /// yet. A parent that never applies is no tip (it waits for what applies
    /// below it). Refused for good when a parent carries no digest, or when
    /// the packet it names is known to have signed another thing than the
    /// one held at its writer and seq (the key signed two entries there: an
    /// equivocation), whatever order the packets arrived in. A child naming
    /// a packet that is not the one held is not refused for that alone: an
    /// ECDSA signature value is malleable, so a relay may hand this reader
    /// another copy of a parent than the one its writer signed. The packet
    /// the child names is asked for by its full name ([`Hold::Wire`]); a
    /// copy that signed the same thing is the same version, and one that
    /// signed another is the evidence. No clock decides it.
    fn parents_hold(&self, id: &VersionId) -> Result<Hold, Refusal> {
        let Some(hv) = self.versions.get(id) else {
            return Ok(Hold::Waits);
        };
        let w = self.waits();
        let mut asks = None;
        for (y, t, digest) in hv.version.parents.tips() {
            let parent = VersionId {
                writer: y.clone(),
                seq: t,
            };
            let Some(digest) = digest else {
                return Err(Refusal::Parent {
                    parent,
                    why: "it carries no digest of that packet, and a merge version binds each \
                          parent to the packet it was made over"
                        .into(),
                });
            };
            if needed(&w, y, t.0) != t.0 {
                continue;
            }
            match w.names(&parent, digest) {
                Packet::NotHeld => return Ok(Hold::Waits),
                Packet::Held => {}
                Packet::Another => {
                    return Err(Refusal::Parent {
                        parent,
                        why: "the packet it names is not the one held there: that key signed two \
                              different entries at one seq"
                            .into(),
                    });
                }
                Packet::Unknown => asks = asks.or(Some((parent, *digest))),
            }
        }
        Ok(match asks {
            Some((parent, digest)) => Hold::Wire(parent, digest),
            None => Hold::Yes,
        })
    }

    fn refuse(&mut self, id: &VersionId, why: Refusal) {
        self.pending.remove(id);
        self.skipped
            .entry(id.writer.clone())
            .or_default()
            .insert(id.seq.0);
        if let Some(hv) = self.versions.remove(id) {
            self.outsiders.push(Arc::clone(&hv));
            self.out.push(Ran::Refused(hv, why));
        }
    }

    /// Open `id` if its payload is in pieces held whole. Whether it is
    /// opened (`None`: not yet); refused when it does not open. A version
    /// opened outside the lock ([`Inner::open_pieces`]) is open already; this
    /// reads the pieces itself only where no such step ran (a state read
    /// anew, a start).
    fn whole(&mut self, id: &VersionId) -> Option<bool> {
        let hv = self.versions.get(id)?;
        if hv.opened {
            return Some(true);
        }
        match open_held(self.store, self.keys, hv) {
            Opening::Opened(op) => {
                let opened = hv.with_op(op);
                self.versions.insert(id.clone(), Arc::new(opened));
                Some(true)
            }
            Opening::Missing => {
                self.unwhole.insert(id.clone());
                None
            }
            Opening::NoKey => None,
            Opening::Bad => {
                tracing::debug!(?id, "refused: its payload in pieces does not open");
                self.refuse(id, Refusal::BadSignature);
                Some(false)
            }
        }
    }

    /// Apply `id`, which is ready. Whether anything moved: not while a
    /// parent that applies is not held here yet.
    fn take(&mut self, id: &VersionId) -> bool {
        if self.state.is_none() || self.history(id) {
            self.pending.remove(id);
            self.applied.insert(id.writer.clone(), id.seq.0);
            self.out.push(Ran::Applied(id.clone()));
            return true;
        }
        // A version in pieces applies once they are held whole and open.
        match self.whole(id) {
            None => return false,
            Some(false) => return true,
            Some(true) => {}
        }
        let hv = Arc::clone(&self.versions[id]);
        match self.parents_hold(id) {
            Ok(Hold::Yes) => {}
            Ok(Hold::Waits) => return false,
            Ok(Hold::Wire(parent, digest)) => {
                self.wants.insert((parent, digest));
                return false;
            }
            Err(why) => {
                tracing::debug!(?id, %why, "refused");
                self.refuse(id, why);
                return true;
            }
        }
        {
            // Its past, from the fields, while the state is borrowed.
            let waits = Waits {
                collection: &self.members.collection,
                members: Some(self.members),
                entries: self.entries,
                skipped: self.skipped,
                locked: self.locked,
                revoked: self.revoked,
                admitted: self.versions,
                wires: self.wires,
            };
            let past = PastOf::new(&hv.version, waits);
            let ops = OpsOf {
                versions: self.versions,
                store: self.store,
                keys: self.keys,
            };
            self.state.as_deref_mut().expect("a merge run").apply(&Op {
                id,
                signed: &hv.signed,
                past: &past,
                bytes: &hv.op,
                ops: &ops,
            });
        }
        self.pending.remove(id);
        // Applied, an operation in pieces is not kept in memory.
        if let Some(unloaded) = hv.unloaded() {
            self.versions.insert(id.clone(), Arc::new(unloaded));
        }
        let a = self.applied.entry(id.writer.clone()).or_insert(0);
        *a = (*a).max(id.seq.0);
        self.out.push(Ran::Applied(id.clone()));
        true
    }
}

impl St {
    fn inside(&self, subject: &Name) -> bool {
        (1..=subject.len()).any(|n| {
            self.follows.contains(&Name::from_components(
                subject.components()[..n].iter().cloned(),
            ))
        })
    }

    /// Whether something followed lies under `subject`. Under
    /// a root (a namespace) only its own data names count:
    /// `/home/bob/32=data/x` is under `/home/bob`'s root, not `/home`'s.
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

    /// What a walk of a summary of namespace `ns` goes toward: what is
    /// followed in `ns` now.
    fn toward_in(&self, ns: &Name) -> BTreeSet<Name> {
        self.follows
            .iter()
            .filter(|t| namespace_of(t).as_ref() == Some(ns))
            .cloned()
            .collect()
    }

    /// Whether a walk of `device`'s summary of `ns` is owed (spec §17.1):
    /// something is followed in `ns`, and a root of `device`
    /// verified here is above the head walked in full ([`Peer::walked`],
    /// both kept across restarts), or a name followed in `ns` lies under
    /// none a walk of that device's root in full went toward with it
    /// followed ([`Peer::followed`]). Every version such a root lists that the
    /// device follows and holds not — not cut or
    /// refused — is in a branch no walk took in full, so the walk stays
    /// owed until one takes it or it is no longer wanted, whatever ended
    /// the walk before. So is a walk of a device whose roots no trust
    /// context held judged when last asked for, once one adopted since
    /// judges them ([`Unjudged::Adopted`]), until a root of it verifies:
    /// the refusals before say nothing of what it lists.
    fn owes_walk(&self, device: &Name, ns: &Name) -> bool {
        let Some(peer) = self.peers.get(&(device.clone(), ns.clone())) else {
            return false;
        };
        let toward = self.toward_in(ns);
        !toward.is_empty()
            && (peer.unjudged == Some(Unjudged::Adopted)
                || peer.head > peer.walked
                || (peer.head > 0
                    && toward
                        .iter()
                        .any(|t| !peer.followed.iter().any(|w| t.has_prefix(w)))))
    }

    /// Whether `device`'s roots of `ns` lie in a person's namespace no
    /// trust context held here judged when last asked for
    /// ([`Unjudged::Unheld`]): asking again learns nothing until one is
    /// adopted, which owes the walk ([`Inner::owe_unjudged_roots`]).
    fn unheld_roots(&self, device: &Name, ns: &Name) -> bool {
        self.peers
            .get(&(device.clone(), ns.clone()))
            .is_some_and(|p| p.unjudged == Some(Unjudged::Unheld))
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
        for w in &mut self.watchers {
            if about.has_prefix(&w.target) && w.since.get(writer).is_none_or(|s| s.0 < seq) {
                w.send(change.clone());
            }
        }
    }

    /// Forget everything held of the log entry `name` and its refusal, so
    /// that it is taken anew (a re-admission, spec §8).
    fn forget(&mut self, name: &Name) {
        let writer = self.cut_out.remove(name).map(|o| o.writer);
        self.refused.remove(name);
        self.held.remove(name);
        let Some(l) = parse_log_name(name) else {
            return;
        };
        let Some(coll) = l.subject.and_then(|c| self.colls.get_mut(&c)) else {
            return;
        };
        coll.waiting.retain(|hv| hv.version.name != *name);
        coll.outsiders.retain(|hv| hv.version.name != *name);
        coll.locked.retain(|lk| lk.name != *name);
        let ids: Vec<VersionId> = coll
            .versions
            .iter()
            .filter(|(_, hv)| hv.version.name == *name)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            coll.versions.remove(&id);
            coll.pending.remove(&id);
        }
        if let Some(w) = writer
            && let Some(s) = coll.skipped.get_mut(&w)
        {
            s.remove(&l.seq);
        }
    }

    /// The bytes a removal cut of the record in force over the log entry
    /// `name`'s collection binds at `name`, when it keeps it (spec §8):
    /// `Ok(Some(digest))`, listed by its manifest; `Ok(None)`, no cut keeps
    /// it with bytes listed; `Err(full)`, a manifest packet on its path is
    /// not held.
    fn kept_digest(&self, name: &Name) -> Result<Option<[u8; 32]>, Name> {
        let Some(l) = parse_log_name(name) else {
            return Ok(None);
        };
        let Some(c) = l.subject else {
            return Ok(None);
        };
        let Some(m) = self.colls.get(&c).and_then(|x| x.members.as_ref()) else {
            return Ok(None);
        };
        let keys = m
            .cuts
            .iter()
            .flat_map(|k| k.accept.iter())
            .filter(|(x, w, _)| **x == c && device_of(w.key()).as_ref() == Some(&l.device))
            .map(|(_, w, _)| w);
        for w in keys {
            let id = VersionId {
                writer: w.clone(),
                seq: Seq(l.seq),
            };
            let Some(cut) = m.kept_by(&c, &id) else {
                continue;
            };
            for root in cut.accept.manifests(&c, w) {
                match listed_bytes(&self.cut_bytes, &*self.store, root, name) {
                    ManifestLookup::Listed(d) => return Ok(Some(d)),
                    ManifestLookup::Missing(full) => return Err(full),
                    ManifestLookup::NotListed => {}
                }
            }
        }
        Ok(None)
    }

    /// Deliver `v` again to every watcher of its collection it was
    /// delivered to before (its frontier holds it): it was withdrawn, and
    /// is taken back. The others had it delivered as it applied.
    fn tell_again(&mut self, v: &Version) {
        self.watchers.retain(|w| !w.tx.is_closed());
        for w in &mut self.watchers {
            if v.collection.has_prefix(&w.target) && w.since.contains(&v.id) {
                w.send(Change::Version(v.clone()));
            }
        }
    }

    /// Tell every watcher of collection `c`, whatever its frontier.
    fn tell(&mut self, c: &Name, change: &Change) {
        self.watchers.retain(|w| !w.tx.is_closed());
        for w in &mut self.watchers {
            if c.has_prefix(&w.target) {
                w.send(change.clone());
            }
        }
    }

    /// Take `body`, the members record at seq `seq` of its signer's log,
    /// signed by `signer` (a device of the subject's namespace,
    /// [`owner_signed`]), into its line — the collection's, or the folder's
    /// ([`Line::take`]) — and, if the subject's own record in force moved,
    /// read again every collection it governs under its record in force
    /// ([`Self::refold`]): the collection, or every collection under the
    /// folder. Owes a new record of this namespace's collections and
    /// folders where the merge leaves a reader to add or a removal undone,
    /// or where a group they are sealed to dropped a reader.
    fn accept_members(&mut self, seq: u64, body: MembersBody, signer: &Writer) {
        let c = body.collection.clone();
        if body.folder && wire::check_collection_name(&c).is_err() {
            // A folder has a component after `32=data` (spec §6).
            tracing::debug!(folder = %c, "a folder record of a name with no path; ignored");
            return;
        }
        let subject = Subject {
            name: c.clone(),
            folder: body.folder,
        };
        let record = Members {
            collection: c.clone(),
            folder: body.folder,
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
        };
        let line = match subject.folder {
            true => &mut self.folders.entry(c.clone()).or_default().line,
            false => &mut self.colls.entry(c.clone()).or_default().line,
        };
        let Some(before) = line.take(seq, record, signer) else {
            return;
        };
        let resolve = line.resolve;
        // The persons' namespaces it lists are adopted for it (spec §6.3),
        // within the caps; what is left out is told.
        let excess = self.scopes.note(&subject, line.own.as_ref());
        // A seal key kept on the strength of a record that listed a writer is
        // dropped with it, whichever record listed it last: the key's device
        // is asked for nothing more until it is vouched for again.
        let scopes = &self.scopes;
        self.seal_keys.retain(|name| !scopes.vouches_no_more(name));
        let groups = |m: &Members| -> Vec<Name> {
            m.readers
                .iter()
                .filter_map(|a| match a {
                    Audience::Group(g) => Some(g.clone()),
                    _ => None,
                })
                .collect()
        };
        let after = line.own.as_ref().map(groups).unwrap_or_default();
        for x in excess {
            tracing::warn!(subject = %x.subject.name, folder = x.subject.folder, left_out = x.namespaces.len(), "{}", x.why);
            self.tell(
                &x.subject.name,
                &Change::NotAdopted {
                    collection: x.subject.name.clone(),
                    namespaces: x.namespaces,
                    why: x.why,
                },
            );
        }
        for g in before.as_ref().map(groups).into_iter().flatten() {
            if let Some(xs) = self.sealed_to.get_mut(&g) {
                xs.remove(&subject);
            }
        }
        // A group's readers decide who reads here: follow it, so that its
        // record is held and its removals heard (spec §6).
        for g in after {
            if !self.follows.contains(&g) {
                self.to_follow.insert(g.clone());
            }
            self.sealed_to.entry(g).or_default().insert(subject.clone());
        }
        if resolve != Resolve::Nothing && namespace_of(&c).as_ref() == Some(&self.ns) {
            self.owed.entry(subject.clone()).or_insert(Owed::Merge);
        }
        match subject.folder {
            true => self.refold_under(&c),
            false => self.refold(&c),
        }
    }

    /// The lines of records of the folders above `name` (its proper
    /// prefixes), nearest first.
    fn folder_lines_above(&self, name: &Name) -> Vec<&Line> {
        let mut above: Vec<(&Name, &Line)> = self
            .folders
            .iter()
            .filter(|(f, _)| f.len() < name.len() && name.has_prefix(f))
            .map(|(f, x)| (f, &x.line))
            .collect();
        above.sort_by_key(|(f, _)| std::cmp::Reverse(f.len()));
        above.into_iter().map(|(_, line)| line).collect()
    }

    /// The records in force of the folders above `name`, nearest first.
    fn folders_above(&self, name: &Name) -> Vec<&Members> {
        self.folder_lines_above(name)
            .into_iter()
            .filter_map(|line| line.own.as_ref())
            .collect()
    }

    /// The record in force of collection `c`: its own narrowed by the
    /// folders above it ([`collection::effective`]).
    fn effective(&self, c: &Name) -> Option<Members> {
        let own = self.colls.get(c).and_then(|x| x.line.own.as_ref());
        collection::effective(c, own, &self.folders_above(c))
    }

    /// What [`DataLayer::members`] answers for `name` (spec §15): the
    /// record in force over it ([`Self::record_in_force`]).
    fn members_in_force(&self, name: &Name) -> Option<crate::layer::Share> {
        self.record_in_force(name)
            .map(|m| crate::layer::Share::of(&m))
    }

    /// The record in force over `name`: of the folder `name` when one is
    /// held, else that of collection `name` — its own narrowed by the
    /// folders above it, or the nearest folder's when it has none.
    fn record_in_force(&self, name: &Name) -> Option<std::borrow::Cow<'_, Members>> {
        if let Some(m) = self.folders.get(name).and_then(|f| f.members.as_ref()) {
            return Some(std::borrow::Cow::Borrowed(m));
        }
        match self.colls.get(name).and_then(|c| c.members.as_ref()) {
            Some(m) => Some(std::borrow::Cow::Borrowed(m)),
            None => self.effective(name).map(std::borrow::Cow::Owned),
        }
    }

    /// The [`Change::Members`] a watch of `target` lists first (spec §15):
    /// the record in force over `target`, then over each folder strictly
    /// under it and each collection under it with a record of its own, by
    /// name; what is held here.
    fn members_listing(&self, target: &Name) -> Vec<Change> {
        let told = |name: &Name, m: &Members| Change::Members {
            collection: name.clone(),
            share: crate::layer::Share::of(m),
        };
        let mut out: Vec<Change> = self
            .members_in_force(target)
            .map(|share| Change::Members {
                collection: target.clone(),
                share,
            })
            .into_iter()
            .collect();
        let mut under: Vec<Change> = self
            .folders
            .iter()
            .filter(|(f, _)| f.has_prefix(target) && *f != target)
            .filter_map(|(f, x)| x.members.as_ref().map(|m| told(f, m)))
            .chain(
                self.colls
                    .iter()
                    .filter(|(c, x)| c.has_prefix(target) && *c != target && x.line.own.is_some())
                    .filter_map(|(c, x)| x.members.as_ref().map(|m| told(c, m))),
            )
            .collect();
        under.sort_by(|a, b| a.collection().cmp(b.collection()));
        out.extend(under);
        out
    }

    /// Tell `watchers` that the members record in force over `name` (a
    /// folder's, or a collection's) moved from `old` to `new`, when what
    /// [`DataLayer::members`] answers changed ([`Change::Members`]): a
    /// watch of `name` itself and, when `own` — a folder, or a collection
    /// with a record of its own — a watch of a folder above it. Borrows
    /// the watchers alone, so the records stay where they are held.
    fn tell_members(
        watchers: &mut Vec<Watcher>,
        name: &Name,
        own: bool,
        old: Option<&Members>,
        new: Option<&Members>,
    ) {
        let Some(new) = new else {
            return;
        };
        if old.is_some_and(|o| {
            o.rule == new.rule && o.writers == new.writers && o.readers == new.readers
        }) {
            return;
        }
        watchers.retain(|w| !w.tx.is_closed());
        let mut change = None;
        for w in watchers.iter_mut() {
            if w.target == *name || (own && name.has_prefix(&w.target)) {
                let change = change.get_or_insert_with(|| Change::Members {
                    collection: name.clone(),
                    share: crate::layer::Share::of(new),
                });
                w.send(change.clone());
            }
        }
    }

    /// Owe, from the records held alone, what namespace `ns`'s collections
    /// and folders need signed (spec §6.1): a new epoch of one sealed in
    /// its own epoch that outgrew its audience.
    fn owe_from_held(&mut self, ns: &Name) {
        let mine = |n: &Name| namespace_of(n).as_ref() == Some(ns);
        let mut owed: Vec<(Subject, Owed)> = self
            .colls
            .iter()
            .filter(|(c, x)| {
                mine(c) && owes_epoch(x.line.own.as_ref(), x.members.as_ref(), &x.line.epochs)
            })
            .map(|(c, _)| {
                let s = Subject {
                    name: c.clone(),
                    folder: false,
                };
                (s, Owed::Folder)
            })
            .collect();
        for (f, x) in self.folders.iter() {
            if !mine(f) || !owes_epoch(x.line.own.as_ref(), x.members.as_ref(), &x.line.epochs) {
                continue;
            }
            let s = Subject {
                name: f.clone(),
                folder: true,
            };
            owed.push((s, Owed::Folder));
        }
        for (s, why) in owed {
            self.owed.entry(s).or_insert(why);
        }
    }

    /// The writer prefixes that the record in force over subject `c` — its
    /// own record `current` narrowed by the folders above, or theirs alone
    /// — admits and that a record of `c` listing `writers` would not cover
    /// (listing none, it takes the folders' writers): each is removed by
    /// that record, with a cut (spec §6.1, §8).
    fn removing(&self, c: &Name, current: Option<&Members>, writers: &[Name]) -> Vec<Name> {
        let above = self.folders_above(c);
        let inherited = match writers.is_empty() {
            true => collection::effective(c, None, &above)
                .map(|m| m.writers)
                .unwrap_or_default(),
            false => Vec::new(),
        };
        collection::effective(c, current, &above)
            .map(|m| m.writers)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| !writers.iter().chain(&inherited).any(|w| p.has_prefix(w)))
            .collect()
    }

    /// Keep `public` as the verified seal key packet `name` of its device;
    /// `unheld`: this device holds no context of the device's namespace
    /// ([`Inner::namespace_unheld`]). The seal key of a device of such a
    /// namespace is kept only while a record in force lists the writer
    /// ([`Scopes::writes`], spec §6.3): `false`, and nothing kept, when none
    /// does — the listing the packet verified by went with the record that
    /// dropped it, whenever the packet arrived.
    fn keep_seal_key(&mut self, name: &Name, public: [u8; 32], unheld: bool) -> bool {
        if unheld && !self.scopes.writes(name) {
            return false;
        }
        self.seal_keys.insert(name.clone(), public);
        true
    }

    /// Whose record names epoch `e` that a version of `c`, or an ask
    /// naming `c`, is sealed in: `c`'s collection records, else those of the
    /// nearest folder at or above `c` (spec §6: a collection that inherits
    /// its folder's readers reads in the folder's epoch, its key check bound
    /// to the folder). `c`'s collection when none does.
    fn seal_subject(&self, c: &Name, e: &Epoch) -> Subject {
        let nearest = match self
            .colls
            .get(c)
            .is_some_and(|x| x.line.epochs.contains_key(e))
        {
            true => None,
            false => self
                .folders
                .iter()
                .filter(|(f, x)| c.has_prefix(f) && x.line.epochs.contains_key(e))
                .map(|(f, _)| f)
                .max_by_key(|f| f.len()),
        };
        match nearest {
            Some(f) => Subject {
                name: f.clone(),
                folder: true,
            },
            None => Subject {
                name: c.clone(),
                folder: false,
            },
        }
    }

    /// The epochs subject `s`'s records name, and its record in force.
    fn line_of(&self, s: &Subject) -> Option<(&BTreeMap<Epoch, Named>, Option<&Members>)> {
        match s.folder {
            true => self
                .folders
                .get(&s.name)
                .map(|f| (&f.line.epochs, f.members.as_ref())),
            false => self
                .colls
                .get(&s.name)
                .map(|x| (&x.line.epochs, x.members.as_ref())),
        }
    }

    /// Know collection `c` under the record in force over it: a collection
    /// with no record of its own that a folder governs takes the folder's
    /// (spec §6), so that what arrives for it is read, and what is put in
    /// it written, under that. Known from now on, a folder record taken
    /// later sets it too ([`Self::refold_under`]).
    fn ensure(&mut self, c: &Name) {
        let coll = self.colls.entry(c.clone()).or_default();
        if coll.members.is_none() && !self.folders_above(c).is_empty() {
            self.refold(c);
        }
    }

    /// Set collection `c`'s record in force anew ([`Self::effective`]) and,
    /// if it moved, read `c` again under it ([`Self::reread`]); with none
    /// left, its versions wait for one. Owes a new record of this
    /// namespace's collections sealed to `c` as a group when `c` dropped a
    /// reader, and of `c` itself when a folder above dropped a reader its
    /// own record lists (spec §6).
    fn refold(&mut self, c: &Name) {
        let new = self.effective(c);
        if self.colls.get(c).is_some_and(|x| x.members == new) {
            return;
        }
        let coll = self.colls.entry(c.clone()).or_default();
        if coll.members == new {
            return;
        }
        let old = std::mem::replace(&mut coll.members, new.clone());
        let owes = owes_epoch(coll.line.own.as_ref(), new.as_ref(), &coll.line.epochs);
        let dropped = old.as_ref().is_some_and(|o| {
            o.readers
                .iter()
                .any(|r| new.as_ref().is_none_or(|n| !n.readers.contains(r)))
        });
        if new.is_none() {
            tracing::info!(collection = %c, "no members record of the collection stands: its versions wait for one");
            coll.state = None;
            coll.applied.clear();
            coll.pending.clear();
            let versions = std::mem::take(&mut coll.versions);
            coll.waiting.extend(versions.into_values());
        }
        let mine = namespace_of(c).as_ref() == Some(&self.ns);
        if owes && mine {
            self.owed.insert(
                Subject {
                    name: c.clone(),
                    folder: false,
                },
                Owed::Folder,
            );
        }
        if dropped {
            // This namespace's collections and folders sealed to `c` as a
            // group move to a new epoch with it.
            let own: Vec<Subject> = self
                .sealed_to
                .get(c)
                .into_iter()
                .flatten()
                .filter(|x| namespace_of(&x.name).as_ref() == Some(&self.ns))
                .cloned()
                .collect();
            for x in own {
                self.owed.insert(x, Owed::Group);
            }
        }
        // Its watchers learn the record in force before what it refuses.
        let own = self.colls.get(c).is_some_and(|x| x.line.own.is_some());
        if !self.quiet_members {
            Self::tell_members(&mut self.watchers, c, own, old.as_ref(), new.as_ref());
        }
        if new.is_some() {
            self.reread(c);
        }
    }

    /// After folder `f`'s own record moved: set the record in force of
    /// every folder at or under `f`, and of every collection under it known
    /// here or looked at ([`Self::refold`]). Owes a new record of a folder
    /// under `f` of this namespace whose own readers lost one to `f`.
    fn refold_under(&mut self, f: &Name) {
        let folders: Vec<Name> = self
            .folders
            .keys()
            .filter(|n| n.has_prefix(f))
            .cloned()
            .collect();
        for n in folders {
            let own = self.folders.get(&n).and_then(|x| x.line.own.as_ref());
            let new = collection::effective(&n, own, &self.folders_above(&n));
            let folder = self.folders.get_mut(&n).expect("listed above");
            let old = std::mem::replace(&mut folder.members, new);
            if !self.quiet_members {
                Self::tell_members(
                    &mut self.watchers,
                    &n,
                    true,
                    old.as_ref(),
                    folder.members.as_ref(),
                );
            }
            if owes_epoch(
                folder.line.own.as_ref(),
                folder.members.as_ref(),
                &folder.line.epochs,
            ) && namespace_of(&n).as_ref() == Some(&self.ns)
            {
                self.owed.insert(
                    Subject {
                        name: n,
                        folder: true,
                    },
                    Owed::Folder,
                );
            }
        }
        let under = |n: &Name| n.has_prefix(f) && n != f;
        let colls: BTreeSet<Name> = self.colls.keys().filter(|n| under(n)).cloned().collect();
        for c in colls {
            self.refold(&c);
        }
    }

    /// Read collection `c` again under its newest members record (spec
    /// §8): every version held is admitted or refused anew and the state is
    /// rebuilt from the admitted ones. A version applied before that is now
    /// refused outside a cut — the record's, or a revocation's
    /// ([`St::cut_out`]) — for its chain ([`Refusal::Untrusted`]) is
    /// withdrawn and reported to the watchers; one applied before and still
    /// admitted is not delivered again.
    fn reread(&mut self, c: &Name) {
        // Entries refused by a revocation as they arrived, never taken:
        // later versions do not wait for them.
        let cut_out: Vec<(Writer, u64)> = self
            .cut_out
            .iter()
            .filter(|(_, o)| o.wire.is_some())
            .filter_map(|(n, o)| {
                let l = parse_log_name(n)?;
                (l.subject.as_ref() == Some(c)).then(|| (o.writer.clone(), l.seq))
            })
            .collect();
        let Some(coll) = self.colls.get_mut(c) else {
            return;
        };
        let Some(members) = coll.members.clone() else {
            return;
        };
        // What was delivered: applied or covered (under a rule this device
        // does not know, held), and not refused since.
        let delivered: BTreeSet<VersionId> = coll
            .versions
            .iter()
            .filter(|(id, hv)| {
                !coll.pending.contains(*id) && !self.refused.contains_key(&hv.version.name)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut all: Vec<Arc<HeldVersion>> = std::mem::take(&mut coll.versions)
            .into_values()
            .chain(std::mem::take(&mut coll.waiting))
            .chain(std::mem::take(&mut coll.outsiders))
            .collect();
        all.sort_by(|a, b| a.version.id.cmp(&b.version.id));
        coll.pending.clear();
        coll.applied.clear();
        coll.skipped.clear();
        for (w, seq) in cut_out {
            coll.skipped.entry(w).or_default().insert(seq);
        }
        coll.state = match &members.rule {
            Rule::Merge { function } => merge::rule(function).map(|r| r.start()),
            _ => None,
        };
        coll.unwhole.clear();
        let names: Vec<(VersionId, Name)> = all
            .iter()
            .filter(|hv| delivered.contains(&hv.version.id))
            .map(|hv| (hv.version.id.clone(), hv.version.name.clone()))
            .collect();
        for hv in all {
            self.refused.remove(&hv.version.name);
            self.admit_one(hv);
        }
        self.apply_ready(c, &delivered);
        let withdrawn: Vec<(VersionId, Refusal)> = names
            .into_iter()
            .filter_map(|(id, name)| match self.refused.get(&name) {
                Some(why @ (Refusal::OutsideCut(_) | Refusal::Untrusted { .. })) => {
                    Some((id, why.clone()))
                }
                // Other bytes than a removal cut keeps at its name, let go:
                // the bytes it keeps may still come.
                None => self
                    .other_bytes
                    .get(&name)
                    .map(|(cut, _)| (id, Refusal::OutsideCut(cut.clone()))),
                _ => None,
            })
            .collect();
        for (id, why) in withdrawn {
            tracing::info!(?id, collection = %c, %why, "withdrawn");
            self.tell(
                c,
                &Change::Withdrawn {
                    collection: c.clone(),
                    id,
                    why,
                },
            );
        }
    }

    /// Admit a verified version (opened, or in pieces), or hold it: until
    /// the members record is known, or as refused by it, or by the trust
    /// context ([`St::cut_out`]) whatever the record says. A merge
    /// collection's rule judges it when it applies ([`Run`]). Returns
    /// whether it was queued to apply.
    fn admit_one(&mut self, hv: Arc<HeldVersion>) -> bool {
        let c = hv.version.collection.clone();
        let coll = self.colls.entry(c.clone()).or_default();
        if let Some(out) = self.cut_out.get(&hv.version.name) {
            tracing::debug!(id = ?hv.version.id, why = %out.why, "refused in {c} by the trust context");
            coll.skipped
                .entry(hv.version.id.writer.clone())
                .or_default()
                .insert(hv.version.id.seq.0);
            self.refused
                .insert(hv.version.name.clone(), out.why.clone());
            coll.outsiders.push(hv);
            return false;
        }
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
        // A version a removal cut keeps is inside it only with the bytes
        // the cut's manifests list (spec §8).
        if let Some(cut) = members.kept_by(&c, &hv.version.id) {
            let name = &hv.version.name;
            match bound_bytes(
                &self.cut_bytes,
                &*self.store,
                cut,
                &c,
                &hv.version.id,
                name,
                &hv.digest,
            ) {
                Bound::Listed => {}
                Bound::Missing(full) => {
                    tracing::debug!(id = ?hv.version.id, %full, "waits in {c} for the manifest of the removal cut keeping it");
                    self.bytes_wanted.entry(full).or_default().insert(c.clone());
                    coll.waiting.push(hv);
                    return false;
                }
                Bound::Unbound => {
                    // A cut signed before cuts bound bytes accepts nothing,
                    // but what it keeps is history the owner held: refused,
                    // and kept with its bytes, so the owner's next record
                    // binds it from them and it is taken back ([`Inner::bind_cuts`]).
                    tracing::info!(id = ?hv.version.id, collection = %c, "refused: a removal cut signed before cuts bound bytes keeps it; kept for the owner's next record to bind");
                    self.other_bytes.remove(name);
                    self.refused
                        .insert(name.clone(), Refusal::OutsideCut(cut.clone()));
                    coll.outsiders.push(hv);
                    return false;
                }
                Bound::Other => {
                    // Other bytes than the cut keeps at that name: refused,
                    // and let go so the bytes it keeps are taken when they
                    // come, asked for by their full name ([`Inner::fetch_kept`]);
                    // the writer's summary is walked again for them.
                    tracing::info!(id = ?hv.version.id, collection = %c, "refused: other bytes than the removal cut keeps at its name; let go for the bytes it keeps");
                    if self
                        .store
                        .get(name)
                        .is_some_and(|w| wire::implicit_digest(&w) == hv.digest)
                    {
                        self.store.remove(name);
                    }
                    self.held.remove(name);
                    self.other_bytes.insert(name.clone(), (cut.clone(), 0));
                    if let (Some(l), Some(ns)) = (parse_log_name(name), namespace_of(&c))
                        && let Some(peer) = self.peers.get_mut(&(l.device, ns))
                    {
                        peer.forget(&c);
                    }
                    return false;
                }
            }
        }
        // Other bytes refused at its name before: these are the ones kept.
        self.other_bytes.remove(&hv.version.name);
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

    /// The version the store holds at log entry `name` (`wire`), as held:
    /// opened (or in pieces), or sealed in an epoch whose key is not held
    /// here (`Err`). `None` when `wire` is no version.
    fn reload(&self, name: &Name, wire: Bytes) -> Option<Result<HeldVersion, Locked>> {
        let data = Data::decode(wire.clone()).ok()?;
        let writer = Writer::new((*data.sig_info()?.key_locator_name()?).clone());
        let Record::Version(mut body) = wire::decode_record(data.content()?.clone()).ok()? else {
            return None;
        };
        let seq = parse_log_name(name)?.seq;
        let sealed = body.sealed.is_some();
        let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
        if let Some(s) = body.sealed.clone() {
            let Some(key) = self.keys.key(&body.collection, &s.epoch) else {
                return Some(Err(Locked {
                    name: name.clone(),
                    wire,
                    writer,
                    seq,
                    body,
                }));
            };
            if body.chunks.is_none() {
                open_into(&mut body, seal::open_payload(&key, name, &s.ciphertext)?);
            }
        }
        let op = body.op.clone();
        let chunks = body.chunks;
        let version = version_of(name, &writer, seq, body, wire::implicit_digest(&wire), true);
        Some(Ok(HeldVersion::new(
            version, op, wire, sealed, epoch, chunks,
        )))
    }

    /// Apply every pending version of `c` that is ready ([`Run`]), store it,
    /// and deliver it to the watchers unless `quiet` lists it (delivered
    /// before). Under a merge rule this device does not know, every pending
    /// version is stored and delivered and none applied: no state is read
    /// under another rule.
    fn apply_ready(&mut self, c: &Name, quiet: &BTreeSet<VersionId>) {
        let St {
            colls,
            watchers,
            refused,
            store,
            keys,
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
            locked,
            pending,
            revoked,
            outsiders,
            unwhole,
            wires,
            wants,
            ..
        } = coll;
        let Some(members) = members.as_ref() else {
            return;
        };
        // Each change, and the version whose delivery it follows.
        let mut changes: Vec<(Change, VersionId)> = Vec::new();
        let deliver = |hv: &HeldVersion, changes: &mut Vec<(Change, VersionId)>| {
            // What was delivered before is stored already.
            if !quiet.contains(&hv.version.id) {
                store.insert(hv.version.name.clone(), hv.wire.clone());
            }
            if !quiet.contains(&hv.version.id) {
                changes.push((Change::Version(hv.version.clone()), hv.version.id.clone()));
            }
        };
        if matches!(members.rule, Rule::Merge { .. }) && state.is_none() {
            for id in std::mem::take(pending) {
                if let Some(hv) = versions.get(&id) {
                    deliver(hv, &mut changes);
                }
            }
        } else {
            let ran = Run {
                members,
                entries,
                locked,
                revoked,
                store: &**store,
                keys,
                state: state.as_deref_mut(),
                versions,
                skipped,
                applied,
                pending,
                outsiders,
                unwhole,
                wires,
                wants,
                out: Vec::new(),
            }
            .run();
            // Only what still waits is remembered not whole.
            unwhole.retain(|id| pending.contains(id));
            for r in ran {
                match r {
                    Ran::Applied(id) => deliver(&versions[&id], &mut changes),
                    Ran::Refused(hv, why) => {
                        tracing::debug!(id = ?hv.version.id, collection = %c, %why, "refused");
                        refused.insert(hv.version.name.clone(), why);
                    }
                }
            }
        }
        watchers.retain(|w| !w.tx.is_closed());
        for (change, of) in changes {
            for w in watchers.iter_mut() {
                let to = c.has_prefix(&w.target) && !w.since.contains(&of);
                if to {
                    w.send(change.clone());
                }
            }
        }
    }

    /// Note the log entry `name`, signed by `writer` at `seq`: a key's log
    /// is one sequence across its collections and entry kinds (spec §4),
    /// so a second entry at a seq it already used, under another name, is
    /// equivocation. Both are kept, and it is reported to the watchers of
    /// both collections where both are versions. Whether it is such a
    /// second entry. `wire`: its packet.
    fn note_seq(
        &mut self,
        name: &Name,
        writer: &Writer,
        seq: u64,
        record: &Record,
        wire: &[u8],
    ) -> bool {
        let key = (writer.clone(), seq);
        let first = match self.seqs.get(&key) {
            None => {
                self.seqs.insert(key, name.clone());
                return false;
            }
            Some(first) if first == name => return false,
            Some(first) => first.clone(),
        };
        let names = self
            .equivocal
            .entry(writer.clone())
            .or_default()
            .entry(seq)
            .or_insert_with(|| vec![first.clone()]);
        if names.contains(name) {
            return false;
        }
        names.push(name.clone());
        tracing::warn!(%first, second = %name, "two log entries of one key at one seq: equivocation");
        if let Record::Version(body) = record
            && let Some(first) = self.held_version(&first)
        {
            let open = body.sealed.is_none();
            let digest = wire::implicit_digest(wire);
            let second = version_of(name, writer, seq, body.clone(), digest, open);
            let mut told = vec![body.collection.clone()];
            if first.collection != body.collection {
                told.push(first.collection.clone());
            }
            // Each collection's watchers see its own version whole and the
            // other collection's by name and id only.
            for c in told {
                let change = Change::Equivocation {
                    collection: c.clone(),
                    first: Equivocal::of(&first, &c),
                    second: Equivocal::of(&second, &c),
                };
                self.tell(&c, &change);
            }
        }
        true
    }

    /// The equivocation evidence held of collections under `target`
    /// ([`Self::note_seq`]): each later version at a writer's seq beside
    /// the first, told for each of their collections under `target`, the
    /// version of another collection by name and id only; and each second
    /// packet at a name beside the version held there ([`St::twins`]).
    fn equivocations_under(&self, target: &Name) -> Vec<Change> {
        let mut writers: Vec<&Writer> = self.equivocal.keys().collect();
        writers.sort();
        let mut out = Vec::new();
        for names in writers.into_iter().flat_map(|w| self.equivocal[w].values()) {
            let Some((first, rest)) = names.split_first() else {
                continue;
            };
            let Some(first) = self.held_version(first) else {
                continue;
            };
            for second in rest.iter().filter_map(|n| self.held_version(n)) {
                let mut told = vec![first.collection.clone()];
                if second.collection != first.collection {
                    told.push(second.collection.clone());
                }
                for c in told.into_iter().filter(|c| c.has_prefix(target)) {
                    out.push(Change::Equivocation {
                        first: Equivocal::of(&first, &c),
                        second: Equivocal::of(&second, &c),
                        collection: c,
                    });
                }
            }
        }
        // Two packets at one name: one collection, both whole.
        let mut names: Vec<&Name> = self.twins.keys().collect();
        names.sort();
        for name in names {
            let Some(first) = self.held_version(name) else {
                continue;
            };
            if !first.collection.has_prefix(target) {
                continue;
            }
            let second = match self.reload(name, self.twins[name].clone()) {
                Some(Ok(hv)) => hv.version,
                Some(Err(lk)) => lk.version(),
                None => continue,
            };
            out.push(Change::Equivocation {
                collection: first.collection.clone(),
                first: Equivocal::Here(Box::new(first)),
                second: Equivocal::Here(Box::new(second)),
            });
        }
        out
    }

    /// Whether a version or summary node of `writer` may make this device
    /// follow collection `c` (spec §15, [`Config::writer_collections`]).
    /// Yes when it follows `c` already — by its own name, under a members
    /// record of its own, held for its owner, or brought by a writer
    /// before — or follows nothing above it, or `writer` is a device of
    /// `c`'s namespace; else when `writer` made it follow fewer than
    /// `limit` collections of that namespace, and `c` then counts as one
    /// more. Read back at start, what the store held counts and is never
    /// refused. A refusal is told to the folder's watchers, naming the
    /// writer and what to do.
    fn track(&mut self, c: &Name, writer: &Writer, limit: usize) -> bool {
        let Some(ns) = namespace_of(c) else {
            return true;
        };
        if writer.key().has_prefix(&ns) {
            // The namespace's own device: never counted, and a collection
            // it writes into is its namespace's, not an outside writer's.
            if let Some(before) = self.brought.insert(c.clone(), writer.clone())
                && !before.key().has_prefix(&ns)
                && let Some(n) = self.bringing.get_mut(&(before, ns))
            {
                *n = n.saturating_sub(1);
            }
            return true;
        }
        if self.brought.contains_key(c)
            || self.follows.contains(c)
            || self.colls.get(c).is_some_and(|x| x.members.is_some())
            || !(self.restoring || self.inside(c))
        {
            return true;
        }
        let n = self
            .bringing
            .entry((writer.clone(), ns.clone()))
            .or_default();
        if self.restoring || *n < limit {
            *n += 1;
            self.brought.insert(c.clone(), writer.clone());
            return true;
        }
        let w = writer.key();
        let why = format!(
            "{w} already made this device follow {limit} collections of {ns}, the most \
             Config::writer_collections lets one writer outside {ns} add by writing into a \
             folder, so {c} is not followed: follow {c} by its name to read it, or have {ns} \
             remove {w} from the folder's writers"
        );
        tracing::warn!(collection = %c, writer = %w, "{why}");
        self.tell(
            c,
            &Change::Untracked {
                collection: c.clone(),
                writer: writer.clone(),
                why,
            },
        );
        false
    }

    /// Note another packet of the version held at `name`, with implicit
    /// digest `digest`: it signed what the held one did (`same`: a copy in
    /// another signature value) or another thing. A pending version that
    /// names the version by it is judged again ([`Run::parents_hold`]).
    fn note_wire(&mut self, name: &Name, digest: [u8; 32], same: bool) {
        let Some(c) = parse_log_name(name).and_then(|l| l.subject) else {
            return;
        };
        let held = self.held.get(name);
        let Some(coll) = self.colls.get_mut(&c) else {
            return;
        };
        let found = match held {
            Some(Held::Version(id)) => coll.versions.get(id).map(|hv| (id.clone(), hv.digest)),
            Some(Held::Locked) => coll.locked.iter().find(|l| l.name == *name).map(|l| {
                let id = VersionId {
                    writer: l.writer.clone(),
                    seq: Seq(l.seq),
                };
                (id, wire::implicit_digest(&l.wire))
            }),
            _ => None,
        };
        let Some((id, held)) = found else {
            return;
        };
        let wires = coll.wires.entry(id.clone()).or_default();
        if held == digest || wires.iter().any(|w| w.digest == digest) || wires.len() >= WIRES_MAX {
            return;
        }
        wires.push(Wire { digest, same });
        if coll.wants.contains(&(id, digest)) {
            self.apply_ready(&c, &BTreeSet::new());
        }
    }

    /// The packets pending versions of `c` name as parents that this device
    /// holds another packet of, not asked for already: (the parent's log
    /// entry name, the implicit digest of the packet named). Each is asked
    /// for by its full name ([`Inner::spawn_wires`]): if it signed what the
    /// one held did, it is the same version; if another thing, the child is
    /// refused.
    fn wanted_wires(&mut self, only: Option<&Name>) -> Vec<(Name, [u8; 32])> {
        let mut asks = Vec::new();
        for (c, coll) in &self.colls {
            if only.is_some_and(|only| only != c) {
                continue;
            }
            for (parent, digest) in &coll.wants {
                let Some(device) = device_of(parent.writer.key()) else {
                    continue;
                };
                let ask = (log_name(&device, Some(c), parent.seq.0), *digest);
                if !self.wiring.contains(&ask) {
                    asks.push(ask);
                }
            }
        }
        self.wiring.extend(asks.iter().cloned());
        asks
    }

    /// Whether a pending version still names the packet `digest` as its
    /// parent at the log entry `name`, which is not the one held
    /// ([`Coll::wants`]).
    fn wants_wire(&self, name: &Name, digest: &[u8; 32]) -> bool {
        let Some(log) = parse_log_name(name) else {
            return false;
        };
        log.subject
            .and_then(|c| self.colls.get(&c))
            .is_some_and(|coll| {
                coll.wants.iter().any(|(parent, d)| {
                    d == digest
                        && parent.seq.0 == log.seq
                        && device_of(parent.writer.key()).as_ref() == Some(&log.device)
                })
            })
    }

    /// The pending register versions in pieces, under `under` (a collection,
    /// or a folder's), to open now: only `version` if given; each with the key
    /// of its epoch, `granted` (an epoch's key about to be held) or held
    /// already. A version whose key is not held is left out. The caller
    /// reads the pieces and unseals them without the lock ([`open_jobs`]),
    /// then installs what opened ([`Self::install_opened`]).
    fn open_jobs(
        &self,
        under: &Name,
        version: Option<&Name>,
        granted: Option<(&Epoch, &ContentKey)>,
    ) -> Vec<OpenJob> {
        let mut jobs = Vec::new();
        for (c, coll) in self.colls.iter().filter(|(c, _)| c.has_prefix(under)) {
            if coll.state.is_none() {
                continue;
            }
            for hv in coll.pending.iter().filter_map(|id| coll.versions.get(id)) {
                if hv.opened
                    || hv.chunks.is_none()
                    || version.is_some_and(|v| hv.version.name != *v)
                {
                    continue;
                }
                let key = match &hv.epoch {
                    None => None,
                    Some(e) => match granted {
                        Some((ge, key)) if ge == e => Some(key.clone()),
                        _ => match self.keys.key(c, e) {
                            Some(key) => Some(key),
                            None => continue,
                        },
                    },
                };
                jobs.push(OpenJob {
                    collection: c.clone(),
                    held: Arc::clone(hv),
                    key,
                });
            }
        }
        jobs
    }

    /// Install the operation `op` read outside the lock from the pieces of
    /// the packet `digest` of version `id` of `c`, if that packet is still
    /// the pending one.
    fn install_opened(&mut self, c: &Name, id: &VersionId, digest: [u8; 32], op: Bytes) {
        let Some(coll) = self.colls.get_mut(c) else {
            return;
        };
        if !coll.pending.contains(id) {
            return;
        }
        if let Some(hv) = coll
            .versions
            .get(id)
            .filter(|hv| !hv.opened && hv.digest == digest)
        {
            let opened = hv.with_op(op);
            coll.versions.insert(id.clone(), Arc::new(opened));
        }
    }

    /// The digest of what the key signed in the entry held at `name` ([`wire::signed_digest`]),
    /// as far as this device holds it: of a members or introduction record
    /// that it does not store too, which it noted when it took it.
    fn held_signed(&self, name: &Name) -> Option<[u8; 32]> {
        match self.held.get(name)? {
            Held::Version(_) | Held::Locked => {
                held_wire(self, name).and_then(|w| wire::signed_digest(&w))
            }
            Held::Record { signed, .. } => Some(*signed),
        }
    }

    /// The version held here under `name`, opened or sealed.
    fn held_version(&self, name: &Name) -> Option<Version> {
        let l = parse_log_name(name)?;
        let coll = self.colls.get(l.subject.as_ref()?)?;
        coll.versions
            .values()
            .chain(&coll.waiting)
            .chain(&coll.outsiders)
            .find(|hv| hv.version.name == *name)
            .map(|hv| hv.version.clone())
            .or_else(|| {
                coll.locked
                    .iter()
                    .find(|lk| lk.name == *name)
                    .map(|lk| lk.version())
            })
    }

    /// Hold `key` as the key of epoch `e` of `c` if it matches the key
    /// check of the held record naming that epoch (spec §9), and open what
    /// it unlocks. Whether it matched. An epoch of folder `c`'s records is
    /// one key for every collection under it that reads in it (spec §6):
    /// it opens what each holds locked.
    fn take_key(&mut self, c: &Name, e: &Epoch, key: ContentKey) -> bool {
        if let Some(named) = self.folders.get(c).and_then(|f| f.line.epochs.get(e)) {
            if seal::key_check(&key, c, e) != named.check {
                return false;
            }
            let under: Vec<Name> = self
                .colls
                .keys()
                .filter(|x| x.has_prefix(c) && *x != c)
                .cloned()
                .collect();
            self.keys.hold(c.clone(), e.clone(), key);
            for x in under {
                self.unlock(&x);
                self.apply_ready(&x, &BTreeSet::new());
            }
            return true;
        }
        let Some(named) = self.colls.get(c).and_then(|x| x.line.epochs.get(e)) else {
            return false;
        };
        if seal::key_check(&key, c, e) != named.check {
            return false;
        }
        self.keys.hold(c.clone(), e.clone(), key);
        self.unlock(c);
        // A merge version in pieces sealed in the epoch opens now.
        self.apply_ready(c, &BTreeSet::new());
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
            // A payload in pieces opens when it is read (`get`), or, of a
            // merge version, once whole, before it applies; the record
            // alone is admitted now.
            if body.chunks.is_none() {
                let Some(opened) = seal::open_payload(&key, &name, &sealed.ciphertext) else {
                    // Its writer signed what does not open: later versions
                    // do not wait for it.
                    tracing::debug!(%name, "refused: its payload does not open under its epoch's key");
                    self.held.remove(&name);
                    self.refused.insert(name, Refusal::BadSignature);
                    self.colls
                        .get_mut(c)
                        .expect("held")
                        .skipped
                        .entry(writer)
                        .or_default()
                        .insert(seq);
                    continue;
                };
                open_into(&mut body, opened);
            }
            let op = body.op.clone();
            let chunks = body.chunks;
            let version = version_of(
                &name,
                &writer,
                seq,
                body,
                wire::implicit_digest(&wire),
                true,
            );
            self.held.insert(name, Held::Version(version.id.clone()));
            self.admit(Arc::new(HeldVersion::new(
                version, op, wire, true, epoch, chunks,
            )));
        }
    }

    /// The versions of register collection `c` in pieces this device is to
    /// fetch (spec §13.1): pending — admitted and not applied yet — not
    /// opened, and neither being fetched nor found whole already. Under a
    /// rule this device does not know, none: it applies nothing.
    fn wanted_pieces(&self, c: &Name) -> Vec<(Name, ChunksBody)> {
        let Some(coll) = self.colls.get(c) else {
            return Vec::new();
        };
        if coll.state.is_none() {
            return Vec::new();
        }
        coll.pending
            .iter()
            .filter_map(|id| coll.versions.get(id))
            .filter(|hv| {
                !hv.opened
                    && !self.fetching.contains(&hv.version.name)
                    && !self.walked.contains(&hv.version.name)
                    && !self.unfound.contains(&hv.version.name)
            })
            .filter_map(|hv| Some((hv.version.name.clone(), hv.chunks?)))
            .collect()
    }

    /// Every piece of version `v` of `c` was found: a register version
    /// waiting for them opens and applies once ready.
    fn pieces_arrived(&mut self, c: &Name, v: &Name) {
        let merge = self.colls.get(c).is_some_and(|x| x.state.is_some());
        if !merge {
            return;
        }
        self.walked.insert(v.clone());
        if let Some(coll) = self.colls.get_mut(c) {
            coll.unwhole
                .retain(|id| coll.versions.get(id).is_none_or(|hv| hv.version.name != *v));
        }
        self.apply_ready(c, &BTreeSet::new());
        // Remembered only while it waits unopened.
        let waits = self.colls.get(c).is_some_and(|x| {
            x.versions
                .values()
                .any(|hv| hv.version.name == *v && !hv.opened && x.pending.contains(&hv.version.id))
        });
        if !waits {
            self.walked.remove(v);
        }
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
        let in_flight = config.in_flight.max(config.window).max(1);
        let asks_verifying = config.asks_verifying.max(1);
        let recipient = recipient_key(&keys, &device)?;
        let seal_keys = Keys::new(recipient);
        let contexts = contexts_by_namespace(validator.keyring());
        let own_key = identity
            .signer
            .public_key()
            .map(|pk| public_key_digest(&pk));
        // The host's store behind a stage: the writes of one put reach it as
        // one batch ([`stage::Stage`]); everything else goes through as made.
        let stage = stage::Stage::new(store);
        let store: Arc<dyn DataStore> = stage.clone();
        // The signal sequence counter and time hint, as the last run left them.
        let signal_clock = signal::SignalClock::load(store.as_ref());
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
            stage,
            config,
            svs,
            st: Mutex::new(St {
                ns: ns.clone(),
                head: 0,
                durable: 0,
                round: 0,
                round_done: 0,
                flush_wanted: false,
                trees: HashMap::new(),
                roots: HashMap::new(),
                colls: BTreeMap::new(),
                folders: HashMap::new(),
                held: HashMap::new(),
                peers: HashMap::new(),
                groups: BTreeMap::new(),
                root_asks: 0,
                follows: BTreeSet::new(),
                watchers: Vec::new(),
                quiet_members: false,
                refused: HashMap::new(),
                cut_out: HashMap::new(),
                cut_fetching: BTreeSet::new(),
                cut_misses: 0,
                readmitting: BTreeMap::new(),
                cut_bytes: CutManifests::new(CUT_BYTES_HELD),
                bytes_wanted: BTreeMap::new(),
                bytes_misses: HashMap::new(),
                bytes_fetching: BTreeSet::new(),
                other_bytes: HashMap::new(),
                store,
                keys: seal_keys,
                asking: BTreeSet::new(),
                grants: Kept::new(GRANTS_KEPT),
                seal_keys: Kept::new(SEAL_KEYS_KEPT),
                seal_learning: BTreeSet::new(),
                walking: BTreeSet::new(),
                seal_key: None,
                owed: BTreeMap::new(),
                to_follow: BTreeSet::new(),
                sealed_to: HashMap::new(),
                fetching: BTreeSet::new(),
                walked: BTreeSet::new(),
                unfound: BTreeSet::new(),
                piece_misses: HashMap::new(),
                wiring: BTreeSet::new(),
                wire_misses: HashMap::new(),
                seqs: HashMap::new(),
                equivocal: HashMap::new(),
                brought: HashMap::new(),
                bringing: HashMap::new(),
                twins: HashMap::new(),
                asks: HashMap::new(),
                answers: Kept::new(ANSWERS_KEPT),
                verified: HashMap::new(),
                suspected: BTreeMap::new(),
                contexts,
                intro: intro::Intros::new(),
                restoring: false,
                scopes: scoped::Scopes::default(),
            }),
            progress: Notify::new(),
            signal_clock: Mutex::new(signal_clock),
            commit_wake: Arc::new(Notify::new()),
            committed: Notify::new(),
            slots: Semaphore::new(in_flight),
            rtt: Mutex::new(Rtt::default()),
            asking: Mutex::new(HashMap::new()),
            verifying: Semaphore::new(asks_verifying),
            signatures: AtomicU64::new(0),
            grants_asked: AtomicU64::new(0),
            grants_answered: AtomicU64::new(0),
            started: Instant::now(),
            serving: Mutex::new(None),
            stopped: AtomicBool::new(false),
            own_key,
            signals: signal::SignalGate::default(),
        });
        // A trust context adopted later may revoke keys whose entries are
        // held here, or re-admit entries refused here (spec §8): the
        // listener only queues it (it runs on the adopting thread), and one
        // task takes the contexts in order. Registered before the restore,
        // so no adoption from now on is missed.
        let (adopted_tx, mut adopted_rx) = mpsc::unbounded_channel::<Arc<SignedTrustContext>>();
        inner.validator.keyring().on_adoption(move |ctx| {
            let _ = adopted_tx.send(Arc::clone(ctx));
        });
        inner.restore();
        inner.restore_hints();
        // Every entry held is judged again by the durable rule against the
        // trust contexts held now (spec §8): a key above its signer may
        // have been revoked while the device was off.
        inner.rejudge(Rejudge::All).await;
        // Versions kept by a removal cut whose manifest the store lacks wait
        // for it: asked for now.
        inner.fetch_wanted_bytes();
        // What the store holds may be only in the operating system's
        // buffers (an earlier run was killed before its flush): it is made
        // durable before any of it is published, or a power loss now could
        // take entries peers are about to see (spec §4.2).
        if let Err(e) = inner.flush().await {
            return Err(local(format!(
                "the store did not make what it holds durable ({e}); {device} publishes only \
                 what is on disk, so it does not start: check the disk or filesystem the store \
                 is on, and start it again"
            )));
        }
        {
            let mut st = inner.st.lock();
            st.durable = st.head;
        }
        inner.spawn_committer();
        let weak = Arc::downgrade(&inner);
        rt::spawn(async move {
            while let Some(ctx) = adopted_rx.recv().await {
                let Some(inner) = weak.upgrade() else { break };
                if inner.stopped.load(Ordering::Relaxed) {
                    break;
                }
                inner.adopted(&ctx).await;
            }
        });

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
        // A face that carries a joined group coming up announces it (spec
        // §12): when the forwarder's connection can tell its routes.
        if let Some(routes) = inner.sync.routes() {
            rt::spawn(Inner::run_face_up(Arc::downgrade(&inner), routes));
        }

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
        // The persons' namespaces adopted for folders before, held again at
        // the version kept, before anything asks for them (spec §6.3).
        inner.restore_scoped().await;
        // What the restored records owe: resolving merges, following groups.
        inner.settle().await;
        // Back in every group a change about what this device wrote or
        // owns is published into ([`Inner::groups_of`]): a peer hears it
        // only where it listens (a reader of this namespace's collection,
        // in its own namespace's group), and one that missed what this
        // device announced before the restart catches up from the counter
        // announced now, without waiting for a new write.
        for g in inner.restored_groups() {
            inner.join(&g).await?;
            inner.publish(&g);
        }
        // Register versions in pieces held from before wait for them.
        inner.fetch_wanted(true);
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

    /// Epoch keys this device has asked other devices to grant it: one per
    /// epoch of one collection or folder asked for (spec §9), whatever the
    /// number of devices asked and of collections that read in the epoch.
    pub fn grants_asked(&self) -> u64 {
        self.inner.grants_asked.load(Ordering::Relaxed)
    }

    /// Grants of an epoch key this device has signed for askers (spec §9).
    pub fn grants_answered(&self) -> u64 {
        self.inner.grants_answered.load(Ordering::Relaxed)
    }

    /// Versions this device holds: its own and others'.
    pub fn held(&self) -> u64 {
        let st = self.inner.st.lock();
        st.held
            .values()
            .filter(|h| matches!(h, Held::Version(_)))
            .count() as u64
    }

    /// The cut this device can vouch for if `key` (a key name
    /// `<id>/KEY/<k>`, or one of its certificate names) is revoked now (spec
    /// §8), bounded by this device's own observation, never by anything
    /// the key signed: every log entry `key` signed that this device holds
    /// verified and has neither refused nor withdrawn — versions (opened or
    /// still sealed) and members records, as runs of
    /// seqs per collection log `<D>/32=log/<C>`, and of no collection, under
    /// `<D>/32=log` — that it first verified strictly before
    /// `bound.held_before` (when set) and whose seq is at most
    /// `bound.upto` of its collection (when `upto` is given; a collection
    /// it does not name, and entries of no collection, are then left out). An entry whose
    /// first verification time or verifying public key is not known here
    /// (held before this was recorded) is left out. Every entry left out is
    /// listed in [`CutProposal::left_out`] by its full name, for the owner
    /// to re-admit one by one.
    ///
    /// The cut carries the digest of the public key that verified its
    /// entries (`CutKeyDigest`) and the full name of its manifest's root
    /// (`CutManifest`), the self-certifying packets of which, listing the
    /// implicit digest of every entry in the cut, are
    /// [`CutProposal::manifest`]: the namespace owner signs the cut into the
    /// trust context with the revocation (its TLV:
    /// [`RevocationCut::encode`]) and publishes the manifest.
    ///
    /// Refused ([`DataError::BadRequest`]) when neither bound is given (say
    /// when the device was lost: [`Self::suspected`] is when its key was
    /// marked suspected), when the entries it would keep were verified by
    /// two different public keys under the key's name, and when no public
    /// key of the key can be named.
    pub fn revocation_cut(&self, key: &Name, bound: &CutBound) -> Result<CutProposal, DataError> {
        let key = key_name_of(key);
        let inner = &self.inner;
        if bound.held_before.is_none() && bound.upto.is_empty() {
            let since = inner.st.lock().suspected.get(&key).copied();
            return Err(DataError::BadRequest {
                name: key,
                why: format!(
                    "a revocation cut keeps what this device held of the key before it was \
                     lost, so say when that was: give held_before (the time the device was \
                     lost{}) or upto (the last seq to keep per collection); every entry first \
                     verified here later, or above upto, is left out and listed, for the owner \
                     to re-admit one by one",
                    match since {
                        Some(t) => format!("; its key is marked suspected here since {}", t.0),
                        None => String::new(),
                    }
                ),
            });
        }
        let ctx = inner.validator.keyring().context_for(&key);
        if ctx.namespace().is_empty() {
            return Err(DataError::BadRequest {
                name: key,
                why: "no trust context held here governs the key, so it cannot be revoked in \
                      one; adopt its namespace's trust context first"
                    .to_string(),
            });
        }
        let mut entries: Vec<(Name, u64, [u8; 32])> = Vec::new();
        let mut left_out = Vec::new();
        let mut public: BTreeSet<[u8; 32]> = BTreeSet::new();
        {
            let st = inner.st.lock();
            for (name, held) in st.held.iter() {
                if st.refused.contains_key(name) {
                    continue;
                }
                if held_signer(&st, name, held).is_none_or(|w| key_name_of(w.key()) != key) {
                    continue;
                }
                let Some(l) = parse_log_name(name) else {
                    continue;
                };
                let digest = match held {
                    Held::Record { digest, .. } => Some(*digest),
                    _ => held_wire(&st, name)
                        .or_else(|| inner.store.get(name))
                        .map(|w| wire::implicit_digest(&w)),
                };
                let Some(digest) = digest else {
                    tracing::warn!(%name, "held without its packet: left out of the cut");
                    continue;
                };
                let seen = st.verified.get(name);
                let in_time = bound
                    .held_before
                    .is_none_or(|t| seen.and_then(|v| v.at).is_some_and(|at| at < t));
                let in_seq = bound.upto.is_empty()
                    || l.subject
                        .as_ref()
                        .and_then(|c| bound.upto.get(c))
                        .is_some_and(|upto| l.seq <= *upto);
                match seen.and_then(|v| v.key) {
                    Some(pk) if in_time && in_seq => {
                        public.insert(pk);
                        entries.push((log_prefix(name), l.seq, digest));
                    }
                    _ => left_out.push(name.clone().append_implicit_digest(digest)),
                }
            }
        }
        if public.len() > 1 {
            return Err(DataError::BadRequest {
                name: key,
                why: "the entries this device would keep of the key were verified by two \
                      different public keys certified under the key's name, so a cut cannot \
                      say which one wrote the honest work; revoke the key without a cut, and \
                      have the CA's operator find which certificate is genuine"
                    .to_string(),
            });
        }
        let key_digest = match public.into_iter().next() {
            Some(d) => d,
            None => {
                let mut held: BTreeSet<[u8; 32]> = inner
                    .validator
                    .cert_cache()
                    .all(&key)
                    .iter()
                    .map(|c| public_key_digest(&c.public_key))
                    .collect();
                held.extend(
                    ctx.anchor_for(&key)
                        .map(|a| public_key_digest(&a.public_key)),
                );
                match (held.len(), held.into_iter().next()) {
                    (1, Some(d)) => d,
                    _ => {
                        return Err(DataError::BadRequest {
                            name: key,
                            why: "no entry of the key that this device would keep names the \
                                  public key that verified it, and the certificates held of the \
                                  key do not name exactly one; revoke the key without a cut"
                                .to_string(),
                        });
                    }
                }
            }
        };
        let mut cut = RevocationCut::new(key.clone());
        for (prefix, seq, _) in &entries {
            cut.add_seq(prefix, *seq);
        }
        cut.set_key_digest(key_digest);
        let manifest = if entries.is_empty() {
            Vec::new()
        } else {
            let built = cut_manifest::build(ctx.namespace(), &key, &entries)
                .map_err(|e| local(format!("the cut's manifest of {key} is not made: {e}")))?;
            cut.set_manifest(built.root)
                .map_err(|e| local(format!("the cut's manifest of {key} is not named: {e}")))?;
            // This device judges its own held entries by it once the cut is
            // adopted, without fetching what it made.
            for p in &built.packets {
                if let Ok(d) = Data::decode(p.clone()) {
                    let _ = inner.validator.cut_manifests().insert(&d);
                }
            }
            built.packets
        };
        left_out.sort();
        Ok(CutProposal {
            cut,
            manifest,
            left_out,
        })
    }

    /// Mark `key` (a key name `<id>/KEY/<k>`, or one of its certificate
    /// names) suspected since `since`, by this device's clock, as the owner
    /// says when the device was lost (spec §8): from now on this device
    /// takes no new log entry of the key — none is fetched, applied or
    /// stored, and a `get` of one answers [`Refusal::Suspected`] — while
    /// the entries it held before stay. Kept across restarts. The mark ends
    /// with [`Self::unsuspect`], or once a trust context this device adopts
    /// revokes the key (its cut decides from then on). `since` is the
    /// default bound of the key's cut ([`CutBound::held_before`]).
    pub fn suspect(&self, key: &Name, since: Timestamp) -> Result<(), DataError> {
        let key = key_name_of(key);
        if !is_key_name(&key) {
            return Err(DataError::BadRequest {
                name: key,
                why: "this is no key name: a key is named <id>/KEY/<k> (or by one of its \
                      certificates); give the lost device's key"
                    .to_string(),
            });
        }
        self.inner.store.insert(
            suspected_name(&key),
            Bytes::copy_from_slice(&since.0.to_be_bytes()),
        );
        self.inner.st.lock().suspected.insert(key, since);
        Ok(())
    }

    /// Lift the suspected mark of `key` ([`Self::suspect`]): new entries of
    /// it are taken again. Whether it was marked.
    pub fn unsuspect(&self, key: &Name) -> bool {
        let key = key_name_of(key);
        self.inner.store.remove(&suspected_name(&key));
        self.inner.st.lock().suspected.remove(&key).is_some()
    }

    /// Since when `key` (a key or certificate name) is marked suspected
    /// here ([`Self::suspect`]), if it is.
    pub fn suspected(&self, key: &Name) -> Option<Timestamp> {
        self.inner
            .st
            .lock()
            .suspected
            .get(&key_name_of(key))
            .copied()
    }

    /// The log entries this device holds refused because `key` (a key or
    /// certificate name) is revoked and its cut does not accept them —
    /// refused as they arrived, or withdrawn when the revocation came later
    /// — each by its full name ending in its implicit digest, as the
    /// namespace owner re-admits it (`ndn-fwd readmit`). Once this device
    /// adopts a trust context that re-admits one, it is taken and delivered
    /// like a new version, and no longer listed.
    pub fn refused_by_revocation(&self, key: &Name) -> Vec<Name> {
        let key = key_name_of(key);
        let st = self.inner.st.lock();
        let mut out: Vec<Name> = st
            .cut_out
            .iter()
            .filter(|(_, o)| o.by_cut() && key_name_of(o.writer.key()) == key)
            .map(|(n, o)| n.clone().append_implicit_digest(o.digest))
            .collect();
        out.sort();
        out
    }

    /// Stop serving and syncing. Watch streams end, and trust contexts
    /// adopted from now on are not taken (a restart judges what is held
    /// against them).
    pub fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Relaxed);
        self.inner.serving.lock().take();
        self.inner.svs.shutdown();
        {
            let mut st = self.inner.st.lock();
            st.watchers.clear();
            st.groups.clear();
        }
        // The committer stops, and whatever waits for the barrier is let go.
        self.inner.commit_wake.notify_one();
        self.inner.committed.notify_waiters();
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

/// Where the store keeps, per device `D` and namespace `O`, how far this
/// device walked `D`'s summary of `O` in full
/// (`/localhost/ndn-data/walked/<D>/32=summary/<O>`; [`encode_walked`]),
/// so a restart knows how far each device was walked, and toward what
/// (spec §5).
fn walked_prefix() -> Name {
    "/localhost/ndn-data/walked".parse().expect("a valid name")
}

fn walked_name(device: &Name, ns: &Name) -> Name {
    under(&walked_prefix(), &root_prefix(device, ns))
}

/// Where the store keeps the newest packet of each node and page of another
/// device's summary that this device verified in a descent, so that it can
/// answer for them while that device is away (spec §13.5): under the node's
/// name without its head, so that a newer one of the same node replaces it.
fn relayed_name(node: &Name) -> Name {
    let prefix: Name = "/localhost/ndn-data/relayed".parse().expect("a valid name");
    let comps = node.components();
    let headless = &comps[..comps.len().saturating_sub(1)];
    Name::from_components(prefix.components().iter().chain(headless).cloned())
}

/// A walked marker's value: the head walked (8 octets, big-endian), then
/// the `Name` TLV of each name it was walked toward — what this device
/// followed in the namespace then, whose folder records above
/// the walk took (spec §7).
fn encode_walked(head: u64, toward: &BTreeSet<Name>) -> Bytes {
    let mut out = head.to_be_bytes().to_vec();
    for t in toward {
        out.extend_from_slice(&t.encode_to_tlv());
    }
    Bytes::from(out)
}

/// `(D, O, head, toward)` of a walked marker ([`walked_name`],
/// [`encode_walked`]).
fn parse_walked(name: &Name, value: &Bytes) -> Option<(Name, Name, u64, BTreeSet<Name>)> {
    let k = parse_summary_name(&over(&walked_prefix(), name)?)?;
    let head = u64::from_be_bytes(value.get(..8)?.try_into().ok()?);
    let mut r = ndn_tlv::TlvReader::new(value.slice(8..));
    let mut toward = BTreeSet::new();
    while !r.is_empty() {
        let (_, inner) = r.read_tlv().ok()?;
        toward.insert(Name::decode(inner).ok()?);
    }
    Some((k.device, k.subject, head, toward))
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

/// Where the store keeps the second packet a writer signed under a log
/// entry name it already signed another packet under
/// (`/localhost/ndn-data/equivocal/<log entry name>`, its value that
/// packet): evidence against its key (spec §4), the first held under the
/// name itself, read back at start ([`St::twins`]). One per name: one is
/// proof enough.
fn equivocal_prefix() -> Name {
    "/localhost/ndn-data/equivocal"
        .parse()
        .expect("a valid name")
}

fn equivocal_name(entry: &Name) -> Name {
    under(&equivocal_prefix(), entry)
}

/// Where the store keeps when this device first verified each log entry it
/// holds, by its clock, and the digest of the public key that verified it
/// (`/localhost/ndn-data/verified/<log entry name>`, its value the time as
/// 8 octets big-endian, then the 32-octet digest when known): what bounds
/// a cut it vouches for (spec §8). An entry stored without one was held
/// before this was recorded: its time is not known.
fn verified_prefix() -> Name {
    "/localhost/ndn-data/verified"
        .parse()
        .expect("a valid name")
}

fn verified_name(entry: &Name) -> Name {
    under(&verified_prefix(), entry)
}

/// A [`verified_name`] record of the entry first verified `at` by the
/// public key whose digest is `key`.
fn encode_verified(at: Timestamp, key: Option<&[u8; 32]>) -> Bytes {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&at.0.to_be_bytes());
    if let Some(k) = key {
        out.extend_from_slice(k);
    }
    Bytes::from(out)
}

/// A [`verified_name`] record: its time and key digest.
fn decode_verified(value: &[u8]) -> Option<(Timestamp, Option<[u8; 32]>)> {
    let at = Timestamp(u64::from_be_bytes(value.get(..8)?.try_into().ok()?));
    match value.len() {
        8 => Some((at, None)),
        40 => Some((at, Some(value[8..].try_into().ok()?))),
        _ => None,
    }
}

/// Where the store keeps, for each log entry this device signed, the
/// implicit digest of what it signed (`/localhost/ndn-data/written/<log
/// entry name>`): only an entry stored under its name with exactly that
/// digest is restored as its own and moves its log head; what a copy of
/// its key signed under its name is restored as another writer's.
fn written_prefix() -> Name {
    "/localhost/ndn-data/written".parse().expect("a valid name")
}

fn written_name(entry: &Name) -> Name {
    under(&written_prefix(), entry)
}

/// Where the store keeps the keys marked suspected here
/// (`/localhost/ndn-data/suspected/<key name>`, its value since when, 8
/// octets big-endian; [`Device::suspect`]).
fn suspected_prefix() -> Name {
    "/localhost/ndn-data/suspected"
        .parse()
        .expect("a valid name")
}

fn suspected_name(key: &Name) -> Name {
    under(&suspected_prefix(), key)
}

/// Where the store keeps the group counter of this device's latest
/// announcement in each namespace's sync group
/// (`/localhost/ndn-data/announced/<namespace>`, 8 octets big-endian): a
/// peer takes a counter only above the highest it heard, and a run may
/// announce more often than it appends to its log, so a restart starts at
/// the higher of this and its log head ([`Inner::join`]).
fn announced_name(ns: &Name) -> Name {
    let prefix: Name = "/localhost/ndn-data/announced"
        .parse()
        .expect("a valid name");
    under(&prefix, ns)
}

/// Where the store keeps a marker for each log entry withdrawn because the
/// trust context refuses its chain (`/localhost/ndn-data/untrusted/<log
/// entry name>`, its value the verdict in UTF-8; [`Refusal::Untrusted`]):
/// it stays withdrawn across a restart until its chain verifies again.
fn untrusted_prefix() -> Name {
    "/localhost/ndn-data/untrusted"
        .parse()
        .expect("a valid name")
}

fn untrusted_name(entry: &Name) -> Name {
    under(&untrusted_prefix(), entry)
}

/// The trust contexts `keyring` holds, by namespace.
fn contexts_by_namespace(keyring: &Keyring) -> HashMap<Name, Arc<SignedTrustContext>> {
    keyring
        .contexts()
        .into_iter()
        .map(|c| (c.namespace().clone(), c))
        .collect()
}

/// Whether a trust context `new` taken after `old` (of the same namespace)
/// may refuse an entry `old` accepted (spec §8): it revokes a name `old`
/// did not, has a revocation cut accept less than `old`'s did (dropped,
/// shrunk, or bound to another manifest or key), lists a role whose Data
/// requires a cut that `old` did not, or drops a trust anchor. `None` (no
/// context before): it may.
fn refuses_more(old: Option<&SignedTrustContext>, new: &SignedTrustContext) -> bool {
    let Some(old) = old else {
        return true;
    };
    let revokes = new
        .revocations()
        .iter()
        .any(|r| !old.revocations().contains(r));
    let shrinks = old.revocation_cuts().iter().any(|was| {
        new.revocation_cut(was.key())
            .is_none_or(|now| !now.covers(was))
    });
    let lapses = new
        .data_requires_cut()
        .iter()
        .any(|role| !old.data_requires_cut().contains(role));
    let anchors = old
        .anchors()
        .iter()
        .any(|a| !new.anchors().contains_key(a.key()));
    revokes || shrinks || lapses || anchors
}

/// `name` under the local `prefix`.
fn under(prefix: &Name, name: &Name) -> Name {
    Name::from_components(prefix.components().iter().chain(name.components()).cloned())
}

/// The name a local name under `prefix` keeps.
fn over(prefix: &Name, name: &Name) -> Option<Name> {
    name.has_prefix(prefix)
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

/// Whether a device may hold the key of an epoch, as far as what this device holds tells
/// ([`Inner::epoch_standing`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpochStanding {
    /// It may.
    In,
    /// It may not.
    Out,
    /// The records that tell are not all held here (yet): neither.
    NotHeld,
}

impl Inner {
    // ---- boot ---------------------------------------------------------------------------------

    /// Rebuild what the store holds: the own log, others' members records,
    /// and applied versions (each verified when it was stored),
    /// the epoch keys made or granted here (each checked again against the
    /// record naming its epoch), and the highest summary root verified of
    /// each other device per namespace, so a rolled-back root is still
    /// refused. Others' versions are stored once applied; members records
    /// go first, by revision (so each revision's merge is made against the
    /// records in force below it), then the keys, then the other records,
    /// then versions.
    ///
    /// Only an entry this device signed — stored under its name with the
    /// digest it recorded as it signed ([`written_name`]) — is its own and
    /// moves its log head; an entry under its name that a copy of its key
    /// signed comes back as another writer's. Each entry keeps the time it
    /// was first verified here ([`verified_name`]); the keys marked
    /// suspected stay marked, and entries withdrawn for their chain stay
    /// withdrawn until judged again ([`Self::rejudge`]).
    fn restore(&self) {
        let mut entries: Vec<(Name, Bytes, Record, Writer, u64, bool)> = Vec::new();
        let mut roots = Vec::new();
        let mut walked = Vec::new();
        let mut keys = Vec::new();
        let mut seen: HashMap<Name, (Timestamp, Option<[u8; 32]>)> = HashMap::new();
        let mut written: HashMap<Name, Bytes> = HashMap::new();
        let mut suspected = BTreeMap::new();
        let mut untrusted: HashMap<Name, String> = HashMap::new();
        let mut writers: HashMap<Name, Writer> = HashMap::new();
        let mut twins = Vec::new();
        let mut scoped_newest = Vec::new();
        // Entries under this device's name that this build cannot read (an
        // old family's records): not restored, yet seqs of its log.
        let mut unread: Vec<(Name, Bytes, u64)> = Vec::new();
        for (name, wire) in self.store.scan_under(&Name::root(), 0) {
            if notes::is_stored(&name) {
                continue;
            }
            if let Some(entry) = over(&verified_prefix(), &name) {
                match decode_verified(&wire) {
                    Some(v) => {
                        seen.insert(entry, v);
                    }
                    None => self.store.remove(&name),
                }
                continue;
            }
            if let Some(entry) = over(&equivocal_prefix(), &name) {
                twins.push((entry, wire));
                continue;
            }
            if let Some(entry) = over(&written_prefix(), &name) {
                written.insert(entry, wire);
                continue;
            }
            if let Some(key) = over(&suspected_prefix(), &name) {
                if let Some(since) = wire.get(..8).and_then(|b| b.try_into().ok()) {
                    suspected.insert(key, Timestamp(u64::from_be_bytes(since)));
                }
                continue;
            }
            if let Some(ns) = over(&scoped::scoped_prefix(), &name) {
                scoped_newest.push((ns, wire));
                continue;
            }
            if let Some(entry) = over(&untrusted_prefix(), &name) {
                untrusted.insert(entry, String::from_utf8_lossy(&wire).into_owned());
                continue;
            }
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
            if let Some(w) = parse_walked(&name, &wire) {
                walked.push(w);
                continue;
            }
            // A removal cut's manifest packet: read back when judged by.
            if parse_cut_bytes_name(&name).is_some() {
                continue;
            }
            let Some(parsed) = parse_log_name(&name) else {
                roots.extend(kept_root(&name, &wire));
                continue;
            };
            let decoded = Data::decode(wire.clone()).ok().and_then(|data| {
                let key = data.sig_info().and_then(|s| s.key_locator_name())?;
                let record = data
                    .content()
                    .and_then(|c| wire::decode_record(c.clone()).ok())?;
                Some((key, record))
            });
            let Some((key, record)) = decoded else {
                if parsed.device == self.device {
                    unread.push((name, wire, parsed.seq));
                }
                continue;
            };
            // One writer per key, shared by its entries (a name read from
            // one packet, not one per entry).
            let key: &Name = &key;
            let writer = match writers.get(key) {
                Some(w) => w.clone(),
                None => {
                    let w = Writer::new(key.clone());
                    writers.insert(key.clone(), w.clone());
                    w
                }
            };
            // Own by name for now; by what it wrote once all is read.
            let mine = parsed.device == self.device;
            entries.push((name, wire, record, writer, parsed.seq, mine));
        }
        // A store kept before this device recorded what it writes: its
        // entries under its name are taken as its own, as they were, and
        // recorded so from now on.
        let legacy = written.is_empty();
        for (name, wire, _, _, _, mine) in entries.iter_mut() {
            if !*mine {
                continue;
            }
            let digest = wire::implicit_digest(wire);
            if legacy {
                self.store
                    .insert(written_name(name), Bytes::copy_from_slice(&digest));
            } else if written.get(name).map(|d| d.as_ref()) != Some(digest.as_slice()) {
                tracing::warn!(%name, "an entry under this device's name that it did not write (a copy of its key signed it): restored as another writer's");
                *mine = false;
            }
        }
        // What this device wrote and no longer reads (a hold, a prune, a group:
        // kinds of an earlier release) is not restored but is still a seq it
        // signed: its log head covers it before and whatever it decodes as, or
        // the next write signs it again (self-equivocation) and the peers that
        // took it refuse the next root as a rollback. Judged by the marker
        // written with it, as the entries restored are.
        let mut unread_head = 0;
        for (name, wire, seq) in unread {
            let digest = wire::implicit_digest(&wire);
            if legacy {
                self.store
                    .insert(written_name(&name), Bytes::copy_from_slice(&digest));
            } else if written.get(&name).map(|d| d.as_ref()) != Some(digest.as_slice()) {
                tracing::warn!(%name, "an entry under this device's name that it did not write and this build cannot read: not counted in its log head");
                continue;
            }
            unread_head = unread_head.max(seq);
        }
        // Members records first, by revision; then the other records, so
        // that what they say is known as the versions come back; then
        // versions.
        entries.sort_by_key(|(_, _, record, _, seq, _)| match record {
            Record::Members(b) => (0, b.revision, *seq),
            Record::Intro(_) => (1, 0, *seq),
            Record::Version(_) => (2, 0, *seq),
        });
        let rest = entries.split_off(
            entries.partition_point(|(_, _, record, ..)| matches!(record, Record::Members(_))),
        );
        let mut st = self.st.lock();
        // The store is read back from here until everything is read: what is
        // taken is stored already.
        st.restoring = true;
        st.head = st.head.max(unread_head);
        // What the trust context refused for its chain stays withdrawn
        // until judged again ([`Self::rejudge`]); what a held trust context
        // revokes outside its cut stays refused across a restart (spec §8):
        // records are not taken, versions held as refused.
        for (name, wire, _, writer, _, _) in entries.iter().chain(&rest) {
            let why = match untrusted.remove(name) {
                Some(why) => Some(Refusal::Untrusted { why }),
                None => self
                    .cut_refusing(name, writer, wire)
                    .map(|(_, cut)| Refusal::OutsideCut(cut)),
            };
            if let Some(why) = why {
                st.refused.insert(name.clone(), why.clone());
                st.cut_out.insert(
                    name.clone(),
                    OutOfCut {
                        writer: writer.clone(),
                        digest: wire::implicit_digest(wire),
                        wire: None,
                        why,
                    },
                );
            }
        }
        // Markers of entries no longer stored.
        for name in untrusted.keys() {
            self.store.remove(&untrusted_name(name));
        }
        for (name, _, _, _, _, mine) in entries.iter().chain(&rest) {
            // An own entry kept before times were recorded has none.
            let (at, key) = match seen.remove(name) {
                Some((at, key)) => (Some(at), key),
                None if *mine => (None, None),
                None => continue,
            };
            st.verified.insert(
                name.clone(),
                Verified {
                    at,
                    key,
                    own: *mine,
                },
            );
        }
        // Times of entries no longer stored: taken again, they are verified
        // again, later.
        for name in seen.keys() {
            self.store.remove(&verified_name(name));
        }
        st.suspected = suspected;
        st.scopes.restore_newest(scoped_newest);
        // An own entry moves the log head, refused or not: this device
        // signed that seq. (In a store kept before own entries were
        // recorded, a refused one does not: it may be a copy's.)
        let take_all = |st: &mut St, list: Vec<(Name, Bytes, Record, Writer, u64, bool)>| {
            for (name, wire, record, writer, seq, mine) in list {
                if mine && !(legacy && st.cut_out.contains_key(&name)) {
                    st.head = st.head.max(seq);
                }
                self.take(st, name, wire, writer, record, mine);
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
        // The second packets held at a name: evidence beside the version
        // read back under it.
        st.twins.extend(twins);
        for (device, ns, head) in roots {
            if device != self.device {
                let peer = st.peers.entry((device, ns)).or_default();
                peer.head = peer.head.max(head);
                peer.kept = peer.kept.max(head);
            }
        }
        for (device, ns, head, toward) in walked {
            if device != self.device {
                let peer = st.peers.entry((device, ns)).or_default();
                if head >= peer.walked {
                    peer.walked = head;
                    peer.toward = toward;
                }
            }
        }
        st.restoring = false;
        // A group's reader dropped in the log re-read is history: the
        // records that moved its collections on are held too.
        // What the held records owe now is owed again, whatever
        // was owed when the device stopped (spec §6.1).
        st.owed.retain(|_, why| *why == Owed::Merge);
        st.owe_from_held(&self.ns);
        self.note_revoked(&mut st);
    }

    // ---- sync groups --------------------------------------------------------------------------

    /// Join namespace `ns`'s sync group, once.
    async fn join(self: &Arc<Self>, ns: &Name) -> Result<(), DataError> {
        let local_seq = {
            let mut st = self.st.lock();
            if st.groups.contains_key(ns) {
                return Ok(());
            }
            // Above anything an earlier run announced: a peer takes a counter
            // only above the highest it heard of this device. Of the log,
            // only its durable head: the counter is published at once.
            let announced = self
                .store
                .get(&announced_name(ns))
                .and_then(|w| w.get(..8).and_then(|b| b.try_into().ok()))
                .map_or(0, u64::from_be_bytes);
            let local_seq = st.durable.max(announced);
            st.groups.insert(
                ns.clone(),
                SyncGroup {
                    tx: None,
                    pending: false,
                    members: heard::Heard::default(),
                    busy: HashMap::new(),
                    confirmed: None,
                    announced: local_seq,
                    hailing: false,
                    heralding: false,
                    unheard: None,
                    observed: None,
                    noticed: HashMap::new(),
                },
            );
            local_seq
        };
        let group = sync_group(ns);
        self.sync
            .register_prefix(&group)
            .await
            .map_err(|e| local(format!("cannot receive {group}: {e}")))?;
        // The group's state vector keeps the devices heard (spec §12): at
        // most [`heard::HEARD_MAX`] besides this one, a device signed data
        // held here vouches for never displaced by a name a Sync Interest
        // carried — so such names grow neither the vector nor every Sync
        // Interest this device sends, which carries it.
        let vouch = {
            let weak = Arc::downgrade(self);
            let ns = ns.clone();
            ndn_sync::ProducerVouch(Arc::new(move |d: &Name| {
                weak.upgrade()
                    .is_some_and(|inner| inner.vouched_heard(&inner.st.lock(), d, &ns))
            }))
        };
        let cfg = SvsConfig {
            // The group's counter only says "moved": it starts above every
            // announcement an earlier run made ([`announced_name`]) and
            // every durable entry of the log.
            local_seq,
            max_producers: heard::HEARD_MAX,
            vouch: Some(vouch),
            ..self.config.svs.clone()
        };
        let Some(mut handle) = self.svs.join(group.clone(), cfg).await else {
            return Err(local(format!("the sync driver did not join {group}")));
        };
        let pending = {
            let mut st = self.st.lock();
            let g = st.groups.get_mut(ns).expect("inserted above");
            g.tx = Some(handle.tx.clone());
            g.observed = handle.observed_shared();
            g.pending
        };
        // What was published before the join completed is announced now.
        if pending {
            self.commit_wake.notify_one();
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

    /// Ask `ns`'s group again for its members' state, when a first look
    /// finds no device heard that writes into `ns` (spec §17.1, a group
    /// heard from no one): the join announcement, or every answer to it,
    /// may have been lost, and the group's period is half a minute. The
    /// device's state vector goes out again after [`retry_pause`] of the
    /// announcements made so far, up to [`REFRESH_TRIES`] times, until a
    /// device writing into `ns` is heard ([`Self::known_for`]); the notice
    /// that brings it starts its walk. One such run per group at a time.
    fn hail(self: &Arc<Self>, ns: &Name) {
        {
            let mut st = self.st.lock();
            match st.groups.get_mut(ns) {
                Some(g) if !g.hailing => g.hailing = true,
                _ => return,
            }
        }
        let weak = Arc::downgrade(self);
        let ns = ns.clone();
        rt::spawn(async move {
            for asked in 0..REFRESH_TRIES {
                rt::sleep(retry_pause(asked)).await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.stopped.load(Ordering::Relaxed)
                    || !inner.known_for(&inner.st.lock(), &ns).is_empty()
                {
                    break;
                }
                tracing::debug!(me = %inner.device, %ns, asked, "no device writing into the namespace heard: its group asked again");
                inner.svs.announce(sync_group(&ns)).await;
            }
            if let Some(inner) = weak.upgrade()
                && let Some(g) = inner.st.lock().groups.get_mut(&ns)
            {
                g.hailing = false;
            }
        });
    }

    /// Announce this device's newest change in `ns`'s group again while no
    /// member is heard to have taken it (spec §17.1, a change announced):
    /// the announcement, or every answer to it, may have been lost, and the
    /// group's period is half a minute. A member took it once one of the
    /// group's Sync Interests carries this device's counter at that
    /// announcement, or once this device answered an ask for any of its
    /// roots since ([`St::root_asks`]: a member walking it takes what was
    /// announced, in every namespace it follows that this device writes
    /// into). At most [`REFRESH_TRIES`] times per run, after [`retry_pause`]
    /// of the announcements made so far, a newer announcement heralded in
    /// the same run; only in a group in which some member was heard, and
    /// not in a group whose last run ended unheard while no root of this
    /// device was asked for since ([`SyncGroup::unheard`]). One such run per
    /// group at a time.
    fn herald(self: &Arc<Self>, ns: &Name) {
        // The announcement heralded, and the root asks answered before it.
        let mut from = {
            let mut st = self.st.lock();
            let asks = st.root_asks;
            match st.groups.get_mut(ns) {
                Some(g) if !g.heralding && !g.members.is_empty() => {
                    if g.unheard == Some(asks) {
                        return;
                    }
                    g.unheard = None;
                    g.heralding = true;
                    (g.announced, asks)
                }
                _ => return,
            }
        };
        let began = from.1;
        let weak = Arc::downgrade(self);
        let ns = ns.clone();
        rt::spawn(async move {
            let mut asked = 0;
            while asked < REFRESH_TRIES {
                rt::sleep(retry_pause(asked)).await;
                let Some(inner) = weak.upgrade() else { return };
                if inner.stopped.load(Ordering::Relaxed) {
                    break;
                }
                let again = {
                    let st = inner.st.lock();
                    let Some(g) = st.groups.get(&ns) else { break };
                    if g.announced != from.0 {
                        // A newer announcement went out: heralded in this
                        // run, which goes on at its pace.
                        from = (g.announced, st.root_asks);
                    }
                    let carried = g
                        .observed
                        .as_ref()
                        .and_then(|o| o.seq_for(&inner.device))
                        .is_some_and(|s| s >= from.0);
                    if carried || st.root_asks != from.1 {
                        break;
                    }
                    true
                };
                if again {
                    tracing::debug!(me = %inner.device, %ns, asked, "no member heard to have taken this device's newest announcement: announced again");
                    inner.svs.announce(sync_group(&ns)).await;
                    asked += 1;
                }
            }
            if let Some(inner) = weak.upgrade() {
                let mut st = inner.st.lock();
                let asks = st.root_asks;
                if let Some(g) = st.groups.get_mut(&ns) {
                    g.heralding = false;
                    if asked >= REFRESH_TRIES && asks == began {
                        tracing::debug!(me = %inner.device, %ns, "no member walked this device during a whole run: its changes are not announced again in this group until one does");
                        g.unheard = Some(asks);
                    }
                }
            }
        });
    }

    /// A Sync Interest of a group joined, heard before the group's driver
    /// merges it ([`ndn_sync::svs_sync::sync_interest_state`]): it confirms
    /// that nothing newer is outstanding in the group (spec §15, `get`)
    /// when the group's validator admits it, no refresh is pending, and its
    /// state vector carries no device's counter above the highest a notice
    /// of the group brought here that no refresh ended short of
    /// ([`SyncGroup::noticed`]) — this device's own aside, which no notice
    /// brings. A counter above them is news: the merge turns it into a
    /// notice, whose refresh confirms once it ends having taken it. What
    /// the notice of a device not kept among those heard brought counts as
    /// held: such a device is not walked, so nothing of it is outstanding.
    /// Any other Interest under the group's prefix — a signal (spec §20),
    /// whoever pushed it, this device among them — carries no state of the
    /// group and confirms nothing.
    fn heard(&self, interest: &Interest) {
        let Some(ns) = self
            .st
            .lock()
            .groups
            .keys()
            .find(|ns| interest.name.has_prefix(&sync_group(ns)))
            .cloned()
        else {
            return;
        };
        let svs = &self.config.svs;
        let Some(vector) =
            ndn_sync::svs_sync::sync_interest_state(&sync_group(&ns), interest, svs.dialect)
        else {
            return;
        };
        if svs.validator.validate(interest.raw()).is_err() {
            return;
        }
        let mut st = self.st.lock();
        let Some(g) = st.groups.get_mut(&ns) else {
            return;
        };
        let newer = vector.iter().any(|e| {
            e.name != self.device
                && e.seq > 0
                && g.noticed
                    .get(&e.name)
                    .is_none_or(|held| (e.boot, e.seq) > *held)
        });
        if !newer && g.busy.is_empty() {
            g.confirmed = Some(Instant::now());
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
        tracing::trace!(target: TIMELINE, %device, high = update.high_seq, "sync_update");
        if device == self.device {
            return;
        }
        let targets = {
            let mut st = self.st.lock();
            // What the notice brought, whether or not the device is walked
            // ([`SyncGroup::noticed`]): of the boot the group's driver
            // noted of it, which it noted before handing the notice on.
            if let Some(g) = st.groups.get_mut(ns) {
                let boot = g
                    .observed
                    .as_ref()
                    .and_then(|o| o.get(&device))
                    .map_or(0, |(boot, _)| boot);
                let held = g.noticed.entry(device.clone()).or_default();
                *held = (*held).max((boot, update.high_seq));
                if g.noticed.len() > heard::HEARD_MAX
                    && let Some(observed) = &g.observed
                {
                    g.noticed.retain(|d, _| observed.get(d).is_some());
                }
            }
            // Heard: kept among the devices heard unless every other one
            // is vouched for by signed data held here and it is not
            // (spec §12, §13.5); a name dropped is not walked.
            if !self.hear(&mut st, ns, &device) {
                tracing::debug!(me = %self.device, %ns, %device, "not walked: as many devices are heard in the group already, each vouched for by signed data held here, and nothing held vouches for this one");
                return;
            }
            let mut targets = self.written_by(&st, &device);
            targets.insert(ns.clone());
            targets
        };
        for t in targets {
            self.noticed(t, device.clone());
        }
        // A device moved: what was re-admitted and not to be had may be now.
        self.retry_readmissions();
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

    /// The namespace whose sync group `name`'s device notices in (spec
    /// §12): that of the context governing it here, or — for a person's
    /// self-certifying name no held context covers — the person's
    /// namespace once it is adopted here for a folder (§6.3), never by the
    /// name's shape alone: a record listing writers nobody adopted joins no
    /// group of theirs. Empty when neither is.
    fn group_namespace_of(&self, st: &St, name: &Name) -> Name {
        let ns = self.namespace_of_name(name);
        if !ns.is_empty() {
            return ns;
        }
        match ndn_security::self_certifying::personal_namespace_of(name) {
            Some(person) if st.scopes.adopted(&person) => person,
            _ => ns,
        }
    }

    /// The namespaces this device follows (has joined the group of) that
    /// `device` may write into: its own, and those of whose collections or
    /// folders a members record held lists a writer of `device`'s namespace.
    fn written_by(&self, st: &St, device: &Name) -> BTreeSet<Name> {
        let dns = self.group_namespace_of(st, device);
        let mut out = BTreeSet::new();
        if dns.is_empty() {
            return out;
        }
        if st.groups.contains_key(&dns) {
            out.insert(dns.clone());
        }
        let records = st
            .colls
            .iter()
            .map(|(c, x)| (c, &x.members))
            .chain(st.folders.iter().map(|(f, x)| (f, &x.members)));
        for (c, m) in records {
            if st.groups.keys().all(|g| out.contains(g)) {
                break;
            }
            let Some(m) = m else { continue };
            let Some(ns) = namespace_of(c) else { continue };
            if out.contains(&ns) || !st.groups.contains_key(&ns) {
                continue;
            }
            if m.writers
                .iter()
                .any(|w| self.group_namespace_of(st, w) == dns)
            {
                out.insert(ns);
            }
        }
        out
    }

    /// The devices heard that may write into namespace `ns`: those heard in
    /// its group, and those heard in any group whose namespace writes into
    /// `ns` by the members records held — each group's at most
    /// [`heard::HEARD_MAX`] ([`heard::Heard::hear`]).
    fn known_for(&self, st: &St, ns: &Name) -> Vec<Name> {
        let mut out: BTreeSet<Name> = st
            .groups
            .get(ns)
            .map(|g| g.members.iter().cloned().collect())
            .unwrap_or_default();
        for g in st.groups.values() {
            for d in g.members.iter() {
                if !out.contains(d) && self.written_by(st, d).contains(ns) {
                    out.insert(d.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// The groups changes about what this device holds of its own are
    /// published into ([`Self::groups_of`]): of every collection and folder
    /// of its namespace with a record held, and of every collection it
    /// wrote into. Its own namespace's group first.
    fn restored_groups(&self) -> Vec<Name> {
        let st = self.st.lock();
        let mine = |c: &Name| namespace_of(c).as_ref() == Some(&self.ns);
        let subjects = st
            .colls
            .iter()
            .filter(|(c, x)| {
                (mine(c) && x.members.is_some()) || x.entries.contains_key(&self.writer)
            })
            .map(|(c, _)| c)
            .chain(
                st.folders
                    .iter()
                    .filter(|(f, x)| mine(f) && x.members.is_some())
                    .map(|(f, _)| f),
            );
        let mut out = vec![self.ns.clone()];
        for c in subjects {
            for g in self.groups_of(&st, c) {
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
        out
    }

    /// The namespaces whose groups a change about `c` is published into:
    /// `c`'s own, and the namespace of every writer or reader its members
    /// record — its collection's or its folder's (spec §6) — names, as
    /// [`Self::group_namespace_of`] says (a group reader by the namespace
    /// of its collection): a person's namespace neither held nor adopted
    /// here is none.
    fn groups_of(&self, st: &St, c: &Name) -> Vec<Name> {
        let own = namespace_of(c).expect("a collection has a namespace");
        let mut out = vec![own];
        let records = [
            st.colls.get(c).and_then(|coll| coll.members.as_ref()),
            st.folders.get(c).and_then(|f| f.members.as_ref()),
        ];
        for m in records.into_iter().flatten() {
            self.groups_named(st, m, &mut out);
        }
        out
    }

    /// Add to `out` the namespace of every writer or reader record `m`
    /// names, as [`Self::groups_of`] counts them, each once.
    fn groups_named(&self, st: &St, m: &Members, out: &mut Vec<Name>) {
        let named = m
            .writers
            .iter()
            .cloned()
            .chain(m.readers.iter().map(|a| match a {
                Audience::Person(n) | Audience::Device(n) => n.clone(),
                Audience::Group(g) => namespace_of(g).unwrap_or_else(|| g.clone()),
            }));
        for n in named {
            let ns = self.group_namespace_of(st, &n);
            if !ns.is_empty() && wire::is_namespace(&ns) && !out.contains(&ns) {
                out.push(ns);
            }
        }
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
            self.publish(&ns);
        }
        Ok(())
    }

    /// Do what the records taken owe (spec §6): sign the record this device
    /// owes a collection or folder of its namespace — one resolving a merge,
    /// in the epoch it keeps when it only adds readers to that epoch and in
    /// a new one when it left a removal undone; one moving a subject sealed
    /// to a group that dropped a reader to a new epoch; or one moving a
    /// subject sealed in its own epoch to a new one without a reader a
    /// folder above dropped — when it is of the subject's audience, and
    /// publish it; follow the groups this namespace's records name, so
    /// their readers can be checked and their removals heard.
    async fn settle(self: &Arc<Self>) {
        let mut signed = Vec::new();
        let follow = {
            let mut st = self.st.lock();
            // What could not be signed stays owed, for the next settle.
            let mut failed = Vec::new();
            // Signing takes records, which may owe more; a few rounds settle
            // any chain of groups.
            for _ in 0..8 {
                let owed = std::mem::take(&mut st.owed);
                if owed.is_empty() {
                    break;
                }
                for (s, why) in owed {
                    let (line, in_force) = match s.folder {
                        true => match st.folders.get(&s.name) {
                            Some(f) => (&f.line, f.members.as_ref()),
                            None => continue,
                        },
                        false => match st.colls.get(&s.name) {
                            Some(x) => (&x.line, x.members.as_ref()),
                            None => continue,
                        },
                    };
                    let Some(current) = line.own.clone() else {
                        continue;
                    };
                    let new_epoch = match (why, line.resolve) {
                        (Owed::Merge, Resolve::Nothing) => continue,
                        (Owed::Merge, Resolve::Readers) => false,
                        (Owed::Merge, Resolve::Epoch) | (Owed::Group | Owed::Folder, _) => true,
                    };
                    let c = &s.name;
                    let reads = in_force
                        .is_some_and(|m| self.admits_record(&st, m, &self.device, &self.ns));
                    if namespace_of(c).as_ref() != Some(&self.ns) || !reads {
                        tracing::debug!(subject = %c, folder = s.folder, ?why, "a new record is owed, by a device of its audience; not this one");
                        continue;
                    }
                    // Its readers, less any a folder above no longer admits.
                    let readers = match in_force {
                        Some(m) if m.epoch == current.epoch => current
                            .readers
                            .iter()
                            .filter(|r| m.readers.contains(r))
                            .cloned()
                            .collect(),
                        _ => current.readers.clone(),
                    };
                    let record = self.next_members(
                        &st,
                        &s,
                        Some(&current),
                        current.rule.clone(),
                        current.writers.clone(),
                        readers,
                        new_epoch,
                    );
                    match self.append_members(&mut st, c, record) {
                        Ok(()) => {
                            tracing::debug!(subject = %c, folder = s.folder, ?why, new_epoch, "signed the record owed");
                            signed.push(c.clone());
                        }
                        Err(e) => {
                            tracing::warn!(subject = %c, "the record owed was not signed, and stays owed: {e}");
                            failed.push((s, why));
                        }
                    }
                }
            }
            for (s, why) in failed {
                st.owed.entry(s).or_insert(why);
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
        // The writers the records in force list from persons' namespaces
        // this node does not hold are adopted for those records (§6.3).
        self.scope_writers();
        // What was adopted, or a record listing a person for a subject, may
        // judge roots refused unasked before: their walks are owed.
        self.owe_unjudged_roots();
        for c in signed {
            if let Err(e) = self.publish_about(&c, &[]).await {
                tracing::debug!(collection = %c, "the record owed is not announced: {e}");
            }
        }
        // A person a record held leaves out has no grant to link any more, and one whose
        // role it changes has the grant re-told, whoever signed it (spec §19.8).
        self.judge_grants().await;
    }

    /// Refresh `device`'s summary of `ns` in the background, coalescing
    /// requests that arrive while one runs.
    fn schedule(self: &Arc<Self>, ns: Name, device: Name) {
        self.refresh_loop(ns, device, 0, false);
    }

    /// [`Self::schedule`] for a sync notice of `device`: it moved, so its
    /// loop walks until a root `device` itself gives answers the notice
    /// ([`Busy::heard`], spec §17.1).
    fn noticed(self: &Arc<Self>, ns: Name, device: Name) {
        self.refresh_loop(ns, device, 0, true);
    }

    /// Hand a walk of `device`'s summary of `ns` that `missed` passes in a
    /// row did not take in full (a first look's, [`Self::walk`]) to that
    /// device's refresh loop: one starts, asking first after the pause
    /// those misses earn, and counting them toward [`REFRESH_TRIES`] (spec
    /// §17.1); a loop under way already asks again while the walk is owed,
    /// so it is left as it is.
    fn walk_again(self: &Arc<Self>, ns: Name, device: Name, missed: u32) {
        self.refresh_loop(ns, device, missed.max(1), false);
    }

    /// The one refresh loop of (`device`, `ns`) ([`Self::schedule`]),
    /// started after `missed` passes in a row missed (0: on a notice, or
    /// something held here that the walk may answer); a notice arriving
    /// while it runs marks it to walk again and wakes its pass
    /// ([`Self::refresh_pass`]), a walk that missed does not (the loop asks
    /// again while owed). `notice`: a sync notice of `device` started it,
    /// counted in [`Busy::heard`]. A pass a notice asks for begins at once
    /// after one that took a newer root of `device`, or that did not reach
    /// its state (a loss: its own rounds pace it); after one that reached
    /// it and took nothing newer, after the pause such passes in a row earn
    /// (spec §17.1): notices that bring nothing new cost root asks at the
    /// pace of a miss, never back to back. One something held here asked
    /// for ([`Busy::asked`]) begins at
    /// once. A name dropped from the devices heard that nothing held
    /// vouches for and nothing verified owes begins no pass
    /// ([`Self::walks_on`]).
    fn refresh_loop(self: &Arc<Self>, ns: Name, device: Name, missed: u32, notice: bool) {
        let wake = {
            let mut st = self.st.lock();
            let Some(g) = st.groups.get_mut(&ns) else {
                return;
            };
            if let Some(busy) = g.busy.get_mut(&device) {
                if missed == 0 {
                    busy.again = true;
                    busy.heard += u64::from(notice);
                    busy.asked |= !notice;
                    busy.wake.notify_one();
                }
                return;
            }
            let wake = Arc::new(Notify::new());
            g.busy.insert(
                device.clone(),
                Busy {
                    again: false,
                    heard: u64::from(notice),
                    answered: 0,
                    asked: false,
                    wake: Arc::clone(&wake),
                },
            );
            wake
        };
        let inner = Arc::clone(self);
        rt::spawn(async move {
            // Passes in a row that left the walk owed or missed.
            let mut misses = missed;
            // Passes in a row a notice asked for that took no newer root.
            let mut idle = 0;
            // Walks of it that ended with nothing held vouching for it — no
            // root of it verified — whatever asked for them, those of the
            // first look it was handed from included: at
            // [`REFRESH_TRIES`] it is unreached ([`Peer::unreached`]).
            let mut unverified = missed;
            if missed > 0 {
                rt::sleep(retry_pause(missed - 1)).await;
            }
            let key = (device.clone(), ns.clone());
            loop {
                let from = {
                    let mut st = inner.st.lock();
                    if !inner.walks_on(&st, &ns, &device) {
                        if let Some(g) = st.groups.get_mut(&ns) {
                            g.busy.remove(&device);
                        }
                        tracing::debug!(me = %inner.device, %ns, %device, "not walked: no longer heard, and nothing held vouches for it or owes its walk");
                        break;
                    }
                    st.peers.get(&key).map_or(0, |p| p.head)
                };
                let (ok, reached) = inner
                    .refresh_pass(&ns, &device, &wake, &mut unverified)
                    .await;
                let moved = {
                    let st = inner.st.lock();
                    st.peers.get(&key).is_some_and(|p| p.head > from)
                };
                // Whether something held here asked for the pass to come.
                let mut asked = false;
                // Again now; again later; or done.
                let next: Option<bool> = {
                    let mut st = inner.st.lock();
                    // A device whose announced change was not taken in full
                    // (not reached now: offline, restarted with its routes
                    // not yet back, a holder away, a packet lost) is asked
                    // again, later: its group counter will not move again
                    // for what it already announced, so nothing else would
                    // ask (spec §12). While the walk is owed by
                    // durable state ([`St::owes_walk`]: a root of it
                    // verified here lists what is wanted and no walk took),
                    // it is asked again after the pause until it is taken or
                    // no longer wanted — whatever ended the pass, and also
                    // after a pass taken in full that a name followed
                    // meanwhile or a newer root left owing; otherwise only
                    // the notice says it moved, and it is asked at most
                    // [`REFRESH_TRIES`] times in a row (spec §17.1). Roots
                    // no trust context held here judges are not asked for
                    // and spend no try: the adoption that judges them owes
                    // the walk ([`Self::owe_unjudged_roots`]).
                    let owed = st.owes_walk(&device, &ns);
                    let waits =
                        owed || (!ok && misses < REFRESH_TRIES && !st.unheld_roots(&device, &ns));
                    match st.groups.get_mut(&ns) {
                        None => None,
                        Some(g) => match g.busy.get_mut(&device) {
                            Some(busy) if busy.again => {
                                busy.again = false;
                                asked = std::mem::take(&mut busy.asked);
                                Some(false)
                            }
                            Some(_) if waits => Some(true),
                            _ => {
                                g.busy.remove(&device);
                                if ok && g.busy.is_empty() {
                                    // As of when the writer's root came to the walk that
                                    // reached its state, not of when that walk ended: its
                                    // descent may fetch for long what the root lists,
                                    // after the writer left.
                                    let at = reached.unwrap_or_else(Instant::now);
                                    g.confirmed = Some(g.confirmed.map_or(at, |c| c.max(at)));
                                }
                                // Its loop ended short of the writer's
                                // state: what the notices brought is not
                                // held, so a Sync Interest carrying it
                                // confirms nothing ([`Inner::heard`]).
                                if !ok {
                                    g.noticed.remove(&device);
                                }
                                None
                            }
                        },
                    }
                };
                match next {
                    None => break,
                    Some(false) if moved || asked => idle = 0,
                    // A pass that did not reach the writer's state (a loss,
                    // a relay behind it) took nothing a notice could be
                    // spent on: the notice is walked again at once, as the
                    // pass's own rounds pace its asks.
                    Some(false) if !ok => {}
                    Some(false) => {
                        rt::sleep(retry_pause(idle)).await;
                        idle = idle.saturating_add(1);
                    }
                    Some(true) => {
                        rt::sleep(retry_pause(misses)).await;
                        misses = misses.saturating_add(1);
                    }
                }
            }
            inner.progress.notify_waiters();
        });
    }

    /// Publish a change into `ns`'s group: the next commit round announces
    /// it, once what it announces is durable ([`Self::commit_rounds`]).
    fn publish(&self, ns: &Name) {
        let mut st = self.st.lock();
        let Some(g) = st.groups.get_mut(ns) else {
            return;
        };
        g.pending = true;
        if g.tx.is_some() {
            self.commit_wake.notify_one();
        }
    }

    // ---- the durability barrier ---------------------------------------------------------------

    /// Start the committer: one task making what this device wrote durable
    /// in rounds, then publishing it ([`Self::commit_rounds`]).
    fn spawn_committer(self: &Arc<Self>) {
        let wake = Arc::clone(&self.commit_wake);
        let weak = Arc::downgrade(self);
        rt::spawn(async move {
            loop {
                wake.notified().await;
                let Some(inner) = weak.upgrade() else { break };
                if inner.stopped.load(Ordering::Relaxed) {
                    break;
                }
                inner.commit_rounds().await;
            }
        });
    }

    /// Commit rounds until nothing waits (spec §4.2). A round writes the
    /// counters of the announcements wanted, makes everything stored so
    /// far durable in one flush of the store ([`DataStore::sync`]) —
    /// however many puts came since the last round: a group commit — and
    /// only then publishes: the durable head moves to the log head as the
    /// round began (its entries are served, listed in summaries and heads)
    /// and the announcements go out. Puts made during a flush wait for the
    /// next round, so an entry is published at most two flushes after its
    /// put. A flush that fails publishes nothing and is tried again, later,
    /// until it succeeds or the device stops.
    async fn commit_rounds(self: &Arc<Self>) {
        let mut pause = COMMIT_RETRY;
        loop {
            let (target, round, announce) = {
                let mut st = self.st.lock();
                let mut announce = Vec::new();
                // The counters of the announcements wanted, one batch.
                let _batch = self.stage.batch();
                for (ns, g) in st.groups.iter_mut() {
                    let Some(tx) = g.tx.clone().filter(|_| g.pending) else {
                        continue;
                    };
                    g.pending = false;
                    g.announced += 1;
                    self.store.insert(
                        announced_name(ns),
                        Bytes::copy_from_slice(&g.announced.to_be_bytes()),
                    );
                    announce.push((ns.clone(), tx));
                }
                if announce.is_empty() && st.durable >= st.head && !st.flush_wanted {
                    return;
                }
                st.flush_wanted = false;
                st.round += 1;
                (st.head, st.round, announce)
            };
            tracing::trace!(target: TIMELINE, "flush_begin");
            let flushed = self.flush().await;
            tracing::trace!(target: TIMELINE, ok = flushed.is_ok(), "flush_end");
            match flushed {
                Ok(()) => {
                    {
                        let mut st = self.st.lock();
                        st.durable = st.durable.max(target);
                        st.round_done = st.round_done.max(round);
                    }
                    self.committed.notify_waiters();
                    self.progress.notify_waiters();
                    for (ns, tx) in announce {
                        tracing::trace!(target: TIMELINE, %ns, "announce");
                        let _ = tx.send((sync_group(&ns), None)).await;
                        self.herald(&ns);
                    }
                    pause = COMMIT_RETRY;
                }
                Err(e) => {
                    tracing::warn!(
                        device = %self.device,
                        "the store did not make this device's writes durable ({e}): nothing \
                         written since its last flush is published until it does; check the disk \
                         or filesystem the store is on"
                    );
                    {
                        let mut st = self.st.lock();
                        st.flush_wanted = true;
                        for (ns, _) in &announce {
                            if let Some(g) = st.groups.get_mut(ns) {
                                g.pending = true;
                            }
                        }
                    }
                    if self.stopped.load(Ordering::Relaxed) {
                        return;
                    }
                    rt::sleep(pause).await;
                    pause = (pause * 2).min(COMMIT_RETRY_MAX);
                }
            }
        }
    }

    /// The store's barrier ([`DataStore::sync`]), on a blocking thread: a
    /// flush takes as long as the disk does. A store whose flush returns at
    /// once ([`DataStore::sync_is_immediate`]) is flushed inline.
    #[cfg(not(target_arch = "wasm32"))]
    async fn flush(&self) -> std::io::Result<()> {
        if self.store.sync_is_immediate() {
            return self.store.sync();
        }
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.sync())
            .await
            .unwrap_or_else(|e| {
                Err(std::io::Error::other(format!(
                    "the flush did not finish ({e})"
                )))
            })
    }

    /// The store's barrier ([`DataStore::sync`]). A browser store commits
    /// each write durably (an IndexedDB transaction is durable when it
    /// completes), so this returns at once there.
    #[cfg(target_arch = "wasm32")]
    async fn flush(&self) -> std::io::Result<()> {
        self.store.sync()
    }

    /// Wait until the own entry at `seq` is durable, and so published;
    /// `false` if the device stopped first.
    async fn published(&self, seq: u64) -> bool {
        loop {
            let notified = self.committed.notified();
            if self.st.lock().durable >= seq {
                return true;
            }
            if self.stopped.load(Ordering::Relaxed) {
                return false;
            }
            self.commit_wake.notify_one();
            notified.await;
        }
    }

    /// Wait until everything stored so far is durable: a commit round
    /// begun after now has flushed. `false` if the device stopped first.
    async fn barrier(&self) -> bool {
        let need = {
            let mut st = self.st.lock();
            st.flush_wanted = true;
            st.round + 1
        };
        loop {
            let notified = self.committed.notified();
            if self.st.lock().round_done >= need {
                return true;
            }
            if self.stopped.load(Ordering::Relaxed) {
                return false;
            }
            self.commit_wake.notify_one();
            notified.await;
        }
    }

    /// Wait until everything written so far is durable and every
    /// announcement wanted so far went out.
    #[cfg(test)]
    async fn flushed(&self) {
        let head = self.st.lock().head;
        loop {
            let notified = self.committed.notified();
            {
                let st = self.st.lock();
                let pending = st.groups.values().any(|g| g.pending && g.tx.is_some());
                if st.durable >= head && !pending {
                    return;
                }
            }
            self.commit_wake.notify_one();
            notified.await;
        }
    }

    /// Start following `target`: join its namespace's group, and forget
    /// which summaries on the way to it were processed (they were processed
    /// without it). Returns whether it is new. A collection held here inside
    /// a name followed already is not: the walks toward that name took it
    /// (spec §15). One a writer outside its namespace was refused making
    /// this device follow ([`St::track`]) is not held, so following it by
    /// its name walks again.
    async fn follow(self: &Arc<Self>, target: &Name) -> Result<bool, DataError> {
        wire::data_marker(target).map_err(|why| bad_name(target, why))?;
        let ns = namespace_of(target).expect("a data name has a namespace");
        let new = {
            let mut st = self.st.lock();
            let taken = st.inside(target) && st.colls.contains_key(target);
            let new = st.follows.insert(target.clone()) && !taken;
            if new {
                for ((_, pns), peer) in st.peers.iter_mut() {
                    if *pns == ns {
                        peer.forget(target);
                    }
                }
            }
            new
        };
        self.join(&ns).await?;
        // A revoked key's summaries are refused: what its cut accepts here
        // is fetched by name (spec §8).
        if new {
            self.fetch_cut_runs();
        }
        Ok(new)
    }

    /// Follow `target` and, the first time, look at what every device known
    /// to write into its namespace holds of it, waiting at most the
    /// first-look time ([`Self::walk`]: a walk the wait outlasts goes on).
    /// With no such device heard, its group is asked again ([`Self::hail`]).
    async fn look(self: &Arc<Self>, target: &Name) -> Result<(), DataError> {
        if !self.follow(target).await? {
            return Ok(());
        }
        let ns = namespace_of(target).expect("followed names have a namespace");
        let devices = self.known_for(&self.st.lock(), &ns);
        if devices.is_empty() {
            self.hail(&ns);
        }
        let all = futures::future::join_all(devices.iter().map(|d| self.walk(&ns, d)));
        let _ = rt::timeout(self.config.first_look, all).await;
        Ok(())
    }

    /// [`Self::look`] for a verb that must not wait on other devices (a
    /// put, spec §15): follow `target` and, the first time, start the walk
    /// of every device known to write into its namespace in the background
    /// ([`Self::walk_in_background`]); never wait for them. With no such
    /// device heard, its group is asked again ([`Self::hail`]).
    async fn look_behind(self: &Arc<Self>, target: &Name) -> Result<(), DataError> {
        if !self.follow(target).await? {
            return Ok(());
        }
        let ns = namespace_of(target).expect("followed names have a namespace");
        let devices = self.known_for(&self.st.lock(), &ns);
        if devices.is_empty() {
            self.hail(&ns);
        }
        self.walk_in_background(&ns, devices);
        Ok(())
    }

    /// Walk `device`'s summary of `ns` now ([`Self::refresh`]), in a task of
    /// its own: a caller that stops waiting for it — a first look's time
    /// passing — never cuts it short. A walk not taken in full is walked
    /// again in place after the pause, up to [`FETCH_TRIES`] walks in all,
    /// then handed to the device's refresh loop ([`Self::walk_again`]),
    /// which asks again after the pause for as long as the walk is owed
    /// ([`St::owes_walk`], spec §17.1). Roots no trust context held here
    /// judges end it at once: the adoption that judges them owes the walk
    /// ([`Self::owe_unjudged_roots`]). Whether it was taken in full.
    async fn walk(self: &Arc<Self>, ns: &Name, device: &Name) -> bool {
        let (tx, rx) = futures::channel::oneshot::channel();
        let inner = Arc::clone(self);
        let (ns, device) = (ns.clone(), device.clone());
        rt::spawn(async move {
            let mut misses = 0;
            let whole = loop {
                if inner.refresh(&ns, &device, None).await {
                    break true;
                }
                if inner.st.lock().unheld_roots(&device, &ns) {
                    break false;
                }
                misses += 1;
                if misses >= FETCH_TRIES {
                    inner.walk_again(ns, device, misses);
                    break false;
                }
                rt::sleep(retry_pause(misses - 1)).await;
            };
            let _ = tx.send(whole);
        });
        rx.await.unwrap_or(false)
    }

    /// Walk in the background the summary of each of `devices` of `ns`,
    /// each in a task of its own that nothing waits for ([`Self::walk`]),
    /// one walk at a time for each (namespace, device): a verb that must not
    /// wait on other devices — a put, a join looking for its record — starts
    /// them and answers what it holds.
    fn walk_in_background(self: &Arc<Self>, ns: &Name, devices: Vec<Name>) {
        for device in devices {
            let key = (ns.clone(), device.clone());
            if !self.st.lock().walking.insert(key.clone()) {
                continue;
            }
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.walk(&key.0, &key.1).await;
                inner.st.lock().walking.remove(&key);
            });
        }
    }

    /// The devices known to write into namespace `ns` that `relevant`
    /// picks — heard in a group this run, or whose summary root this
    /// device verified before, also in an earlier run ([`Peer::kept`]) —
    /// whose summary of `ns` this device has not walked for what is asked:
    /// neither in full since it last followed something new in `ns`
    /// ([`Self::follow`]), nor in full up to the newest head it knows of
    /// that device, in this run or an earlier one ([`Peer::walked`]), while
    /// following a name `covers` accepts ([`Peer::toward`]: a walk takes
    /// the folder records above what it goes toward only). A device merely
    /// offline since such a walk does not hold anything back, nor does one
    /// ended here — a key of it suspected, or revoked by the trust context
    /// governing it ([`Self::ended`]): what it holds is not taken anyway —,
    /// nor one nothing held vouches for ([`Self::vouched`]) once its walks
    /// spent their tries with no root of it verified ([`Peer::unreached`]):
    /// a name a Sync Interest carried, or a device never reached, that
    /// signed data held here gives no reason to wait for.
    /// Empty: what each of them lists of what is asked — a folder record
    /// above a collection, a version under a folder — is held here, or
    /// refused (spec §6.1).
    fn not_walked(
        &self,
        st: &St,
        ns: &Name,
        relevant: impl Fn(&Name) -> bool,
        covers: impl Fn(&Name) -> bool,
    ) -> Vec<Name> {
        let mut known: BTreeSet<Name> = self.known_for(st, ns).into_iter().collect();
        known.extend(
            st.peers
                .iter()
                .filter(|((_, n), p)| n == ns && p.kept > 0)
                .map(|((d, _), _)| d.clone()),
        );
        let walked = |p: &Peer| {
            p.root.is_some() || (p.walked > 0 && p.walked >= p.head && p.toward.iter().any(&covers))
        };
        known
            .into_iter()
            .filter(|d| *d != self.device && relevant(d) && !self.ended(st, d))
            .filter(|d| {
                st.peers
                    .get(&(d.clone(), ns.clone()))
                    .is_none_or(|p| !walked(p) && (!p.unreached || self.vouched(st, d, ns)))
            })
            .collect()
    }

    /// [`Self::not_walked`], after refreshing each device it names once
    /// more, for at most the first-look time.
    async fn unsynced(
        self: &Arc<Self>,
        ns: &Name,
        relevant: impl Fn(&Name) -> bool,
        covers: impl Fn(&Name) -> bool,
    ) -> Vec<Name> {
        let missing = self.not_walked(&self.st.lock(), ns, &relevant, &covers);
        if missing.is_empty() {
            return missing;
        }
        let all = futures::future::join_all(missing.iter().map(|d| self.walk(ns, d)));
        let _ = rt::timeout(self.config.first_look, all).await;
        self.not_walked(&self.st.lock(), ns, &relevant, &covers)
    }

    /// Wait until `done` holds or the first-look time passes.
    async fn wait_for(&self, done: impl FnMut(&St) -> bool) -> bool {
        self.wait_within(self.config.first_look, done).await
    }

    /// Wait until `done` holds or `within` passes.
    async fn wait_within(&self, within: Duration, mut done: impl FnMut(&St) -> bool) -> bool {
        let deadline = Instant::now() + within;
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

    /// Refresh in the background every device known to write into `ns`;
    /// ask again for what a trust context re-admits, or a revocation cut
    /// accepts, that was not to be had before (spec §8), and for the epoch
    /// keys versions of `ns` held here wait for (spec §17.1: owed by what is
    /// held, after a restart too).
    fn refresh_group(self: &Arc<Self>, ns: &Name) {
        let (devices, locked) = {
            let st = self.st.lock();
            let locked: Vec<Name> = st
                .colls
                .iter()
                .filter(|(c, x)| !x.locked.is_empty() && namespace_of(c).as_ref() == Some(ns))
                .map(|(c, _)| c.clone())
                .collect();
            (self.known_for(&st, ns), locked)
        };
        for d in devices {
            self.schedule(ns.clone(), d);
        }
        for c in locked {
            self.chase_keys(&c);
        }
        self.retry_readmissions();
        self.fetch_cut_runs();
        self.fetch_kept(true);
    }

    /// Whether no trust context held here judges `name`: it lies in a
    /// person's namespace (`/user/<0xA1: …>`) that the validator judging it
    /// ([`Self::judge`]: the node's, or a view adopted for a folder's scope,
    /// spec §6.3) does not hold, so every signed packet of it is refused,
    /// whoever serves it (trust-context.md §4.5.6).
    fn unjudged(&self, name: &Name) -> bool {
        self.judge(name)
            .keyring()
            .unheld_personal_namespace(name)
            .is_some()
    }

    /// Owe the walk of every device whose roots no trust context held here
    /// judged when last asked for ([`Unjudged::Unheld`]) that one held now
    /// judges — a namespace adopted by the node or for a folder's scope, a
    /// record listing it for a subject — and walk it: asked again after the
    /// pause while owed ([`St::owes_walk`], spec §17.1), whatever the
    /// refusals before it.
    fn owe_unjudged_roots(self: &Arc<Self>) {
        let unheld: Vec<(Name, Name)> = self
            .st
            .lock()
            .peers
            .iter()
            .filter(|(_, p)| p.unjudged == Some(Unjudged::Unheld))
            .map(|(key, _)| key.clone())
            .collect();
        let judged: Vec<(Name, Name)> = unheld
            .into_iter()
            .filter(|(d, ns)| !self.unjudged(&root_prefix(d, ns)))
            .collect();
        if judged.is_empty() {
            return;
        }
        {
            let mut st = self.st.lock();
            for key in &judged {
                if let Some(p) = st.peers.get_mut(key)
                    && p.unjudged == Some(Unjudged::Unheld)
                {
                    p.unjudged = Some(Unjudged::Adopted);
                    p.unreached = false;
                }
            }
        }
        for (device, ns) in judged {
            tracing::debug!(%device, %ns, "its roots are judged here now: its walk is owed");
            self.schedule(ns, device);
        }
    }

    // ---- fetching -----------------------------------------------------------------------------

    /// Fetch `name`; `None` if nothing answered in time or the network said
    /// no.
    async fn fetch(&self, name: Name, discover: bool) -> Option<Data> {
        self.fetch_once(name, discover).await.ok()
    }

    /// [`Self::fetch`], saying of a miss whether asking again may get the
    /// packet: nothing answered in time, the forwarder refused it for now
    /// (a certificate on its chain not to be had yet), or it refused a
    /// reply that does not verify (`bad-signature`: forged or altered on
    /// the way, spec §17.1), or a Nack with reason Congestion that asking
    /// again soon did not mend, or no fetch slot to be had within an
    /// Interest lifetime ([`Self::slot`]). Any other Nack, any other final
    /// refusal or a closed connection is an answer. Re-expressed up to
    /// [`REEXPRESS_MAX`] times ([`Self::fetch_expressed`]).
    async fn fetch_once(&self, name: Name, discover: bool) -> Result<Data, bool> {
        self.fetch_expressed(name, discover, REEXPRESS_MAX).await
    }

    /// One of the device's [`Config::in_flight`] fetch slots, waiting for one
    /// at most `within` — the lifetime of the Interest it is for (spec
    /// §17.1), so a queue of fetches that others made never holds one
    /// longer than the Interest it waits to send would have lived. `Err(true)`:
    /// every slot stayed taken that long, so the device is busy, not the packet
    /// absent — asking again after the pause may get a slot; `Err(false)`: the
    /// device stopped.
    async fn slot(&self, within: Duration) -> Result<tokio::sync::SemaphorePermit<'_>, bool> {
        match rt::timeout(within, self.slots.acquire()).await {
            Ok(Ok(slot)) => Ok(slot),
            Ok(Err(_)) => Err(false),
            Err(_) => {
                tracing::debug!(
                    me = %self.device,
                    slots = self.config.in_flight,
                    "fetch not sent: every one of the device's fetch slots stayed taken for an Interest lifetime ({within:?}); it is asked again after its pause, or raise Config::in_flight"
                );
                Err(true)
            }
        }
    }

    /// One ask, within one Interest lifetime: an Interest nothing answered
    /// within the device's retransmission timeout ([`Rtt::rto`]) is
    /// expressed again under a fresh nonce, the timeout doubling each time,
    /// at most `most` times, while at least [`RTO_MIN`] of the lifetime is
    /// left (spec §17.1). A lost packet then costs about one round-trip
    /// timeout, not the lifetime. An ask its caller asks again under a
    /// fresh name of its own (an introduction's ask) is expressed once
    /// (`most` 0). A Nack with reason Congestion — the Interest was dropped
    /// for rate — is asked again by the consumer after a short jittered
    /// pause, a bounded number of times within the lifetime
    /// ([`ndn_app::Consumer::fetch_reexpressing`]), which costs the ask no
    /// sample of the round trip. The wait for a slot is at most one lifetime
    /// ([`Self::slot`]). The miss is told as in [`Self::fetch_once`].
    async fn fetch_expressed(&self, name: Name, discover: bool, most: u32) -> Result<Data, bool> {
        let lifetime = self.config.lifetime;
        let _slot = match self.slot(lifetime).await {
            Ok(slot) => slot,
            Err(busy) => {
                tracing::trace!(me = %self.device, %name, "fetch not sent: no slot");
                return Err(busy);
            }
        };
        let rto = self.rtt.lock().rto(lifetime);
        let interest = || {
            let b = InterestBuilder::new(name.clone());
            if discover {
                b.can_be_prefix().must_be_fresh()
            } else {
                b
            }
        };
        tracing::trace!(target: TIMELINE, %name, "fetch_out");
        let asked = Instant::now();
        let fetched = Consumer::new(self.node.connection())
            .fetch_reexpressing(
                interest,
                lifetime,
                RTO_MIN,
                (0..most).map(|k| rto.saturating_mul(1 << k)),
            )
            .await;
        match fetched {
            Ok((d, expressed)) => {
                tracing::trace!(target: TIMELINE, %name, expressed, "fetch_in");
                let mut rtt = self.rtt.lock();
                if expressed == 1 {
                    rtt.sample(asked.elapsed());
                } else {
                    rtt.missed();
                }
                Ok(d)
            }
            Err(e) => {
                tracing::trace!(target: TIMELINE, %name, "fetch_miss");
                tracing::trace!(me = %self.device, %name, "fetch missed: {e}");
                Err(match e {
                    ndn_app::AppError::Timeout => {
                        self.rtt.lock().missed();
                        true
                    }
                    // A reply that does not verify was forged or altered on
                    // the way: the verdict is final for that packet, not for
                    // the name, whose genuine packet asking again may get.
                    ndn_app::AppError::Refused { reason } => {
                        reason == ndn_packet::Refusal::BadSignature || !reason.is_final()
                    }
                    // The Interest was dropped for rate, and asking again soon
                    // already failed [`ndn_app::consumer::CONGESTION_RETRIES`]
                    // times: not an answer, so the owed ask asks again after its
                    // pause ([`Self::fetch_owed`]), never "not there". The other
                    // reasons (no route, not yet, duplicate, none) are answers.
                    ndn_app::AppError::Nacked {
                        reason: Some(NackReason::Congestion),
                    } => true,
                    _ => false,
                })
            }
        }
    }

    /// Fetch a packet a summary being walked lists (a node, a members
    /// record, a version): a miss that asking again may mend is asked
    /// again in place, after [`retry_pause`], up to [`FETCH_TRIES`] asks
    /// in all (spec §17.1). A lost packet then costs its walk about one
    /// round-trip timeout ([`Self::fetch_once`]), not the walk: the walk is
    /// asked again from the writer's root only when every ask missed.
    async fn fetch_owed(&self, name: Name, discover: bool) -> Option<Data> {
        for tries in 0..FETCH_TRIES {
            if tries > 0 {
                rt::sleep(retry_pause(tries - 1)).await;
            }
            match self.fetch_once(name.clone(), discover).await {
                Ok(d) => return Some(d),
                Err(true) => {}
                Err(false) => return None,
            }
        }
        None
    }

    /// Verify a key-signed packet with the device's validator, walking its
    /// certificate chain to a trust anchor (fetching missing certificates
    /// through the validator's fetcher, if it has one) by the durable rule:
    /// no certificate's validity period is checked against a clock, and a
    /// revoked signing key is excused for exactly what its cut accepts
    /// (spec §8). Returns its signer. A packet that does not verify is not
    /// kept as refused: the same name may verify when fetched from another
    /// holder, or once a certificate arrives. One its own key signed whose
    /// key the trust context governing its name revokes, and whose cut does
    /// not accept it, is [`Refusal::OutsideCut`] by that cut, refused by
    /// signed data. When the context holds a cut for the key, the validator
    /// verified the signature and chain first, so the packet is authentic
    /// and a caller may keep the decision ([`Self::refuse_outside_cut`]); a
    /// key revoked without a cut is refused unverified. A key of a role the
    /// context lists in `DataRequiresCut` whose certificates are none valid
    /// by this clock is [`Refusal::Lapsed`]: kept by no decision, since only
    /// the clock refuses it.
    async fn verify(&self, data: &Data) -> Result<Writer, Refusal> {
        let key = data
            .sig_info()
            .and_then(|s| s.key_locator_name())
            .ok_or(Refusal::BadSignature)?;
        // A person's namespace adopted for a folder judges its packets
        // about that folder alone (spec §6.3), and the seal key and the
        // asker's proof of a device of a writer the folder's record lists
        // no others; the device's own validator every other packet.
        let device_packet = self.judge_device_packet(&data.name);
        let judge = match &device_packet {
            Some(d) => Arc::clone(&d.judge),
            None => self.judge(&data.name),
        };
        tracing::trace!(target: TIMELINE, "verify_begin");
        let verdict = judge.validate_durable(data).await;
        tracing::trace!(
            target: TIMELINE,
            valid = matches!(verdict, ValidationResult::Valid(_)),
            "verify_end"
        );
        match verdict {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) =>
            {
                if let Some(d) = &device_packet
                    && device_of(&key).as_ref() != Some(&d.device)
                {
                    tracing::debug!(name = %data.name, key = %key, "not verified: it is signed by a key of another device than the one its name is under");
                    return Err(Refusal::BadSignature);
                }
                Ok(Writer::new((*key).clone()))
            }
            // The signing key itself (not an issuer above it) is revoked.
            ValidationResult::Invalid(TrustError::Revoked { name, .. })
                if name
                    .parse::<Name>()
                    .is_ok_and(|n| key_name_of(&n) == key_name_of(&key)) =>
            {
                let writer = Writer::new((*key).clone());
                let ctx = judge.keyring().context_for(&data.name);
                tracing::debug!(name = %data.name, key = %key, "refused: its key is revoked and the cut does not accept it");
                Err(Refusal::OutsideCut(revocation_cut_for(
                    &ctx,
                    &writer,
                    &log_prefix(&data.name),
                )))
            }
            // The signing key's role needs a cut and no certificate of it is
            // valid by this clock: only the clock refuses (a signer's own
            // key alone is judged so).
            ValidationResult::Invalid(TrustError::Lapsed { not_after, now, .. }) => {
                tracing::debug!(name = %data.name, key = %key, "refused: its key's certificate lapsed by this device's clock");
                Err(Refusal::Lapsed {
                    not_after: Timestamp(not_after),
                    now: Timestamp(now),
                })
            }
            other => {
                tracing::debug!(name = %data.name, "not verified: {other:?}");
                Err(Refusal::BadSignature)
            }
        }
    }

    /// [`Self::verify`], with the digest of the public key that verified
    /// the packet ([`Self::verifying_key`]).
    async fn verify_keyed(&self, data: &Data) -> Result<(Writer, Option<[u8; 32]>), Refusal> {
        let writer = self.verify(data).await?;
        let public = self.verifying_key(data, writer.key()).await;
        Ok((writer, public))
    }

    /// The digest of the public key, as its certificate stores it, that
    /// verifies `data`'s signature: of the certificates of `key` (its
    /// KeyLocator) the validator holds, or of the anchor `key` names. A
    /// cut binds the public key that verified the entries it keeps
    /// (`CutKeyDigest`), so it is checked, not assumed. `None` when none
    /// held verifies it.
    async fn verifying_key(&self, data: &Data, key: &Name) -> Option<[u8; 32]> {
        let sig_type = data.sig_info()?.sig_type;
        let mut keys: Vec<Bytes> = Vec::new();
        let anchor = self
            .judge(&data.name)
            .keyring()
            .context_for(&data.name)
            .anchor_for(key);
        for pk in self
            .validator
            .cert_cache()
            .all(key)
            .into_iter()
            .map(|c| c.public_key)
            .chain(anchor.map(|a| a.public_key))
        {
            if !keys.contains(&pk) {
                keys.push(pk);
            }
        }
        for pk in &keys {
            if let Ok(VerifyOutcome::Valid) =
                verify_by_sig_type(sig_type, data.signed_region(), data.sig_value(), pk).await
            {
                return Some(public_key_digest(pk));
            }
        }
        None
    }

    /// Take `data` as `device`'s signed summary root of `ns`: check it
    /// ([`Self::check_root`]) and take it ([`Self::take_root`]).
    #[cfg(test)]
    async fn accept_root(
        &self,
        device: &Name,
        ns: &Name,
        data: &Data,
    ) -> Result<(Writer, NodeBody), RootRefusal> {
        let data = Data::decode(data.raw().clone()).map_err(|_| RootRefusal::NotItsName)?;
        let r = self.check_root(device, ns, data).await?;
        self.take_root(device, ns, &r)?;
        Ok((r.writer, r.body))
    }

    /// Check `data` as `device`'s signed summary root of `ns`: verify it
    /// and check it against its name. Nothing is kept: a reply checked
    /// while others wait to be ([`Self::ask_relays_root`]) changes nothing
    /// here until it is taken ([`Self::take_root`]).
    async fn check_root(
        &self,
        device: &Name,
        ns: &Name,
        data: Data,
    ) -> Result<Rooted, RootRefusal> {
        let writer = self
            .verify(&data)
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
        Ok(Rooted { data, writer, body })
    }

    /// Take `r`, a root of `device` for `ns` checked ([`Self::check_root`]):
    /// refused if its head is lower than one verified (or an entry held) of
    /// that writer before — kept in the store, so a restart does not forget
    /// it.
    fn take_root(&self, device: &Name, ns: &Name, r: &Rooted) -> Result<(), RootRefusal> {
        let head = r.body.head;
        let mut st = self.st.lock();
        let peer = st.peers.entry((device.clone(), ns.clone())).or_default();
        if head < peer.head {
            return Err(RootRefusal::Rollback {
                head,
                seen: peer.head,
            });
        }
        peer.head = head;
        peer.unjudged = None;
        if head > peer.kept {
            peer.kept = head;
            self.store
                .insert(root_prefix(device, ns), r.data.raw().clone());
        }
        Ok(())
    }

    /// Refresh `device`'s summary of `ns`: fetch its signed root and descend
    /// it, to the end, into what this device follows. A writer that moved
    /// meanwhile is refreshed again from its newer root, which skips every
    /// branch processed in full here. Returns whether it completed and
    /// reached the writer's state: not when only a relay answered, with a
    /// root no newer than the head walked in full, or in a walk answering a
    /// sync notice of the writer ([`Reach::answers`]) whatever its head
    /// (spec §13.5, §17.1). A walk of a refresh loop's pass tells the pass
    /// how far it came (`reach`, [`Self::refresh_pass`]).
    async fn refresh(self: &Arc<Self>, ns: &Name, device: &Name, reach: Option<Reach>) -> bool {
        if !self.st.lock().toward(ns) {
            return true;
        }
        tracing::trace!(me = %self.device, %ns, %device, "refresh");
        // A root in a person's namespace no trust context held here judges
        // is refused whoever serves it: not asked for, and no try is spent
        // on it; the adoption that judges it owes the walk
        // ([`Self::owe_unjudged_roots`], spec §17.1). Marked before the
        // second look, so an adoption in between is seen by one of them.
        let root = root_prefix(device, ns);
        if self.unjudged(&root) {
            let key = (device.clone(), ns.clone());
            {
                // Unreached, unless a record listing its person awaits the
                // adoption that judges it ([`Self::awaits_adoption`]).
                let mut st = self.st.lock();
                st.peers.entry(key.clone()).or_default().unjudged = Some(Unjudged::Unheld);
                if !self.awaits_adoption(&st, device) {
                    self.mark_unreached(&mut st, device, ns);
                }
            }
            if self.unjudged(&root) {
                tracing::debug!(%device, %ns, "not asked: its roots lie in a person's namespace no trust context held here judges; adopt the namespace, and its walk is owed");
                return false;
            }
            // Adopted between the looks: owed like any adoption.
            if let Some(p) = self.st.lock().peers.get_mut(&key) {
                p.unjudged = Some(Unjudged::Adopted);
                p.unreached = false;
            }
        }
        // A writer that does not answer is answered for by the devices that
        // hold its newest root (spec §13.5). A walk begun beside others of
        // its pass is for what the writer did since their roots: a relay's
        // root no newer than those says nothing of that. A walk answering a
        // notice is for what the writer did since the roots verified here:
        // a relay's root no newer than those is not taken, and the writer's
        // own is asked again in the root's next rounds — an old copy of it,
        // a duplicate the network delayed, may answer a later ask (spec
        // §17.1).
        let key = (device.clone(), ns.clone());
        let answers = reach.as_ref().and_then(|r| r.answers);
        let floor = answers.and_then(|_| {
            self.st
                .lock()
                .peers
                .get(&key)
                .filter(|p| p.head > 0 || p.root.is_some())
                .map(|p| p.head)
        });
        let above = reach
            .as_ref()
            .filter(|r| r.index > 0)
            .map(|r| r.pass.head.load(Ordering::Relaxed))
            .max(floor);
        let Some((rooted, relayed)) = self.fetch_root(root, ns, device, above, floor).await else {
            return false;
        };
        if let Some(r) = &reach {
            r.pass.rooted.lock().insert(r.index, Instant::now());
        }
        if let Err(why) = self.take_root(device, ns, &rooted) {
            if let RootRefusal::Rollback { head, seen } = why {
                tracing::warn!(%device, %ns, head, seen, "refused: a summary root older than one verified before (rollback); the writer must serve its newest root");
            }
            return false;
        }
        let Rooted { data, writer, body } = rooted;
        if let Some(r) = &reach {
            r.pass.head.fetch_max(body.head, Ordering::Relaxed);
        }
        let digest = wire::implicit_digest(data.raw());
        // The writer's own root answers the notices the walk began after. A
        // relay holds the newest root it verified, which may be older than
        // the writer's: one answering a notice may be behind what the writer
        // announced, and one no newer than the head walked in full says
        // nothing of what the writer did since; either way the writer is not
        // reached (asked again as §17.1 says), whatever the walk of it takes.
        if let Some(upto) = answers
            && !relayed
            && let Some(b) = self
                .st
                .lock()
                .groups
                .get_mut(ns)
                .and_then(|g| g.busy.get_mut(device))
        {
            b.answered = b.answered.max(upto);
        }
        let unreached = relayed
            && (answers.is_some()
                || self
                    .st
                    .lock()
                    .peers
                    .get(&key)
                    .is_some_and(|p| body.head <= p.walked));
        // The root walked in full last time, and nothing it lists is owed
        // still (a name followed since is walked toward anew).
        {
            let st = self.st.lock();
            if st.peers.get(&key).and_then(|p| p.root) == Some(digest) && !st.owes_walk(device, ns)
            {
                return !unreached;
            }
        }
        let head = body.head;
        // What the descent goes toward: what is followed in
        // `ns` as it starts, and of that what is followed (its versions
        // taken); and how often what was processed
        // had been forgotten then ([`Peer::forget`]).
        let (toward, followed, since) = {
            let st = self.st.lock();
            let toward = st.toward_in(ns);
            let followed: Vec<Name> = toward
                .iter()
                .filter(|t| st.follows.contains(*t))
                .cloned()
                .collect();
            let since = st.peers.get(&key).map_or(0, |p| p.resets);
            (toward, followed, since)
        };
        let walk = Walk { since, reach };
        let whole = self.descend(device, ns, &writer, body, &walk).await;
        // The pieces of register versions it brought are fetched once it
        // took everything it lists.
        self.fetch_wanted(true);
        if !whole {
            return false;
        }
        let mut st = self.st.lock();
        let peer = st.peers.entry(key).or_default();
        // Processed in full for what is followed now, unless
        // that changed meanwhile.
        if peer.resets == since {
            peer.root = Some(digest);
        }
        // What it was walked toward with versions taken, at this head.
        if head > peer.walked {
            peer.followed.clear();
        }
        if head >= peer.walked {
            peer.followed.extend(followed);
        }
        // What it was walked toward, at this head: more of the same head
        // adds to it.
        let wider = !toward.is_subset(&peer.toward);
        if head > peer.walked || (head == peer.walked && wider) {
            if head > peer.walked {
                peer.toward.clear();
            }
            peer.walked = head;
            peer.toward.extend(toward);
            self.store
                .insert(walked_name(device, ns), encode_walked(head, &peer.toward));
        }
        !unreached
    }

    /// One pass of `device`'s refresh loop of `ns` ([`Self::refresh_loop`],
    /// spec §17.1): a walk of its newest root ([`Self::refresh`]) and,
    /// beside it, walks of the newer roots notices tell of. Once the walk
    /// begun last is past the way to its versions ([`Reach::past`]: it took
    /// one, or a round of asks for a node on the way missed) or ended, a
    /// notice arrived since it began ([`Busy`]) begins a walk of the newest
    /// root, while fewer than [`WALKS_AT_ONCE`] of the pass's walks are
    /// under way; one ending makes room. A walk takes its root's branches
    /// side by side and ends once the slowest did: a writer that never
    /// pauses would otherwise have each version wait for the walk under way
    /// as it was written, long tail and all, then for the next. What walks
    /// under way at once both list is asked once ([`Self::asked_once`]); a
    /// walk begun beside takes no root a device answering for the writer
    /// gives that is no newer than one a walk of the pass took
    /// ([`Self::fetch_root`]). A walk that reached the writer's state with
    /// no root newer than the one verified as it began begins none beside
    /// it: the notice is left to the loop, which walks again after the pause
    /// ([`Self::refresh_loop`]). The pass ends once every walk of it
    /// ended: whether the one begun last was taken in full and reached the
    /// writer's state. Each walk that ended without it, while nothing held
    /// vouches for `device`, spends a try of `unverified` — as it ends, not
    /// when the pass does: notices arriving while a walk runs begin the
    /// next, so a pass may last as long as they keep coming — and at
    /// [`REFRESH_TRIES`] the device is unreached ([`Self::mark_unreached`]).
    /// Returns that, and when the writer's own root came to that walk: what
    /// the pass confirms is as of then.
    async fn refresh_pass(
        self: &Arc<Self>,
        ns: &Name,
        device: &Name,
        wake: &Arc<Notify>,
        unverified: &mut u32,
    ) -> (bool, Option<Instant>) {
        let pass = Arc::new(Pass {
            past: AtomicUsize::new(0),
            head: AtomicU64::new(0),
            rooted: Mutex::new(BTreeMap::new()),
            wake: Arc::clone(wake),
        });
        let walk = |index: usize| {
            // Whether it answers a notice not answered yet, read as it begins.
            let answers = self
                .st
                .lock()
                .groups
                .get(ns)
                .and_then(|g| g.busy.get(device))
                .and_then(|b| (b.heard > b.answered).then_some(b.heard));
            let reach = Reach {
                index,
                pass: Arc::clone(&pass),
                answers,
            };
            async move { (index, self.refresh(ns, device, Some(reach)).await) }
        };
        let head = || {
            self.st
                .lock()
                .peers
                .get(&(device.clone(), ns.clone()))
                .map_or(0, |p| p.head)
        };
        let mut walks = stream::FuturesUnordered::new();
        // The walk begun now answers the notices before it.
        let _ = self.noticed_again(ns, device);
        walks.push(walk(0));
        // The walk begun last, the head verified as it began, and whether
        // it was taken in full once ended.
        let (mut newest, mut from, mut outcome) = (0, head(), None);
        loop {
            let ended = {
                let woken = std::pin::pin!(wake.notified());
                match futures::future::select(walks.next(), woken).await {
                    futures::future::Either::Left((ended, _)) => ended,
                    futures::future::Either::Right(_) => None,
                }
            };
            if let Some((index, whole)) = ended {
                if !whole {
                    let mut st = self.st.lock();
                    if !self.vouched(&st, device, ns) {
                        *unverified = unverified.saturating_add(1);
                        if *unverified >= REFRESH_TRIES {
                            self.mark_unreached(&mut st, device, ns);
                        }
                    }
                }
                if index == newest {
                    outcome = Some(whole);
                }
            }
            // A walk that reached the writer with nothing newer begins none
            // beside it; one that did not reach (a loss) begins one as before.
            let ready = match outcome {
                Some(whole) => !whole || head() > from,
                None => pass.past.load(Ordering::Relaxed) > newest,
            };
            if ready && walks.len() < WALKS_AT_ONCE && self.noticed_again(ns, device) {
                newest += 1;
                from = head();
                outcome = None;
                walks.push(walk(newest));
            }
            if walks.is_empty() {
                break;
            }
        }
        let whole = outcome.unwrap_or(false);
        // As of the newest walk's root, never of the end of its descent.
        let reached = whole
            .then(|| pass.rooted.lock().get(&newest).copied())
            .flatten();
        (whole, reached)
    }

    /// Whether a notice of `device` in `ns`'s group arrived since its
    /// refresh loop's newest walk began ([`Busy::again`]), taken: the walk
    /// about to begin answers it.
    fn noticed_again(&self, ns: &Name, device: &Name) -> bool {
        self.st
            .lock()
            .groups
            .get_mut(ns)
            .and_then(|g| g.busy.get_mut(device))
            .is_some_and(|b| std::mem::take(&mut b.again))
    }

    /// Process a verified node (or page) of `writer`'s summary of `ns`,
    /// published by `device`: its entries if followed, then its changed,
    /// relevant branches. Returns whether all of it was processed; what was
    /// is kept, so the next descent, from this root or a newer one, does not
    /// fetch it again — unless what was processed was forgotten since the
    /// walk began (`since`, [`Peer::forget`]): a node processed for less
    /// than is followed now is not recorded as processed.
    fn descend<'a>(
        self: &'a Arc<Self>,
        device: &'a Name,
        ns: &'a Name,
        writer: &'a Writer,
        body: NodeBody,
        walk: &'a Walk,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let since = walk.since;
            let subject = body.subject.clone();
            let path = body.page.clone().unwrap_or_default();
            // Entries, for a followed collection: its records first, then
            // its versions.
            let mut records = Vec::new();
            let mut versions = Vec::new();
            let (children, pages) = {
                let mut st = self.st.lock();
                let inside = st.inside(&subject);
                // A collection this outside writer may not make the device
                // follow ([`St::track`]): nothing of it is taken from this
                // writer's summary.
                if inside
                    && body.page.is_none()
                    && !body.entries.is_empty()
                    && !st.track(&subject, writer, self.config.writer_collections)
                {
                    return true;
                }
                if body.page.is_none() && inside {
                    let coll = st.colls.entry(subject.clone()).or_default();
                    coll.entries
                        .entry(writer.clone())
                        .or_default()
                        .extend(seqs_of(&body.entries));
                    for seq in seqs_of(&body.members) {
                        let name = log_name(device, Some(&subject), seq);
                        if !st.held.contains_key(&name) && !st.refused.contains_key(&name) {
                            records.push(name);
                        }
                    }
                    versions.extend(seqs_of(&body.entries));
                    // Learned entries may make held versions ready.
                    st.apply_ready(&subject, &BTreeSet::new());
                } else if body.page.is_none()
                    && st.toward(&subject)
                    && wire::check_collection_name(&subject).is_ok()
                {
                    // A name above what is followed: its
                    // members entries only, for a folder record there
                    // governs what lies under it (spec §6).
                    for seq in seqs_of(&body.members) {
                        let name = log_name(device, Some(&subject), seq);
                        if !st.held.contains_key(&name) && !st.refused.contains_key(&name) {
                            records.push(name);
                        }
                    }
                }
                if body.page.is_none() && inside {
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
                                    && !self.left_out(&st, &sub)
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
                .map(|name| async move { self.take_listed(name).await })
                .buffer_unordered(self.config.window)
                .collect::<Vec<_>>()
                .await;
            let versions: Vec<Name> = {
                let st = self.st.lock();
                versions
                    .into_iter()
                    .map(|seq| log_name(device, Some(&subject), seq))
                    .filter(|name| !st.held.contains_key(name) && !st.refused.contains_key(name))
                    .collect()
            };
            let fetched_versions = stream::iter(versions)
                .map(|name| async move { self.take_listed(name).await })
                .buffer_unordered(self.config.window)
                .collect::<Vec<_>>()
                .await;
            let entries_taken = fetched.iter().chain(&fetched_versions).all(|ok| *ok);
            // The walk reached the versions its root lists: its pass may
            // begin a walk of a newer root beside it.
            if let Some(reach) = &walk.reach
                && fetched_versions.iter().any(|ok| *ok)
            {
                reach.past();
            }

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
                // (§7): a miss is the network's, asked again in place in
                // rounds ([`in_rounds`]), and what was processed is kept for
                // the next descent. Asked for by the digest its parent
                // lists: no cache answers with another packet of the name (a
                // writer whose store came back with entries it had lost
                // signs a node of the same head anew). A writer that does
                // not answer is answered for by the devices that hold its
                // node (spec §13.5), checked by the same digest. A walk of
                // another root listing the same node meanwhile, begun for
                // the same names followed, waits for this one's outcome
                // ([`Self::asked_once`]).
                let exact = name.clone().append_implicit_digest(digest);
                let branch = async {
                    let (asked, node) = (&exact, &name);
                    let data = in_rounds(|round| async move {
                        let own = self.fetch_owed(asked.clone(), false);
                        if round == 0 {
                            return own.await;
                        }
                        // A round on the way missed: a newer root may be the
                        // quicker way to what was written since.
                        if let Some(reach) = &walk.reach {
                            reach.past();
                        }
                        first_some(own, self.ask_relays(node, ns, device, Some(digest))).await
                    })
                    .await;
                    let data = data?;
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
                    // Kept, the newest of its node, to answer for the writer.
                    self.store.insert(relayed_name(&name), data.raw().clone());
                    if !self.descend(device, ns, writer, child, walk).await {
                        return None;
                    }
                    let mut st = self.st.lock();
                    let peer = st.peers.entry((device.clone(), ns.clone())).or_default();
                    if peer.resets == since {
                        peer.nodes.insert(key, digest);
                    }
                    Some(())
                };
                self.asked_once((exact.clone(), Some(since)), async { branch.await.is_some() })
                    .await
                    .then_some(())
            })
            .buffer_unordered(self.config.window)
            .collect::<Vec<_>>()
            .await;
            entries_taken && branch_results.iter().all(Option::is_some)
        })
    }

    /// `ask`, a walk's ask for `key` ([`Inner::asking`]), unless another
    /// walk asks for the same now: then that one's outcome, waited for, so
    /// walks of two roots of one writer under way at once ask once for
    /// what both list. Whether what it asks for was taken (an ask whose
    /// walk stopped tells its waiters it was not).
    async fn asked_once(&self, key: (Name, Option<u64>), ask: impl Future<Output = bool>) -> bool {
        /// Takes the ask out of [`Inner::asking`] however it ends.
        struct Ending<'a>(
            &'a Mutex<HashMap<(Name, Option<u64>), WalkAsk>>,
            (Name, Option<u64>),
        );
        impl Drop for Ending<'_> {
            fn drop(&mut self) {
                self.0.lock().remove(&self.1);
            }
        }
        let tx = {
            let mut asking = self.asking.lock();
            match asking.get(&key) {
                Some(under_way) => Err(under_way.clone()),
                None => {
                    let (tx, rx) = futures::channel::oneshot::channel();
                    asking.insert(key.clone(), futures::FutureExt::shared(rx));
                    Ok(tx)
                }
            }
        };
        match tx {
            Err(under_way) => under_way.await.unwrap_or(false),
            Ok(tx) => {
                let ending = Ending(&self.asking, key);
                let got = ask.await;
                drop(ending);
                let _ = tx.send(got);
                got
            }
        }
    }

    /// [`Self::take_fetched`] for a members record or version a summary
    /// being walked lists: asked again in place in rounds while it misses
    /// ([`in_rounds`], spec §17.1), so it costs its walk a round of asks,
    /// not a walk begun anew once every other branch ended. A refusal
    /// decided against the name, or a device whose key is suspected here,
    /// ends it. One another walk asks for now is waited for, not asked
    /// again ([`Self::asked_once`]). Whether it is now held or refused.
    async fn take_listed(self: &Arc<Self>, name: Name) -> bool {
        let decided = |st: &St| st.held.contains_key(&name) || st.refused.contains_key(&name);
        if decided(&self.st.lock()) {
            return true;
        }
        let listed = &name;
        let rounds = in_rounds(|round| async move {
            if self.take_fetched(listed.clone(), Some(round)).await {
                return Some(true);
            }
            let st = self.st.lock();
            let ended = st.refused.contains_key(listed)
                || parse_log_name(listed).is_some_and(|l| self.suspects_device(&st, &l.device));
            ended.then_some(false)
        });
        self.asked_once((name.clone(), None), async {
            rounds.await.unwrap_or(false)
        })
        .await
    }

    /// Fetch, verify and take one log entry — by its name, else from each
    /// device that answers for it ([`Self::fetch_entry`]), or,
    /// as round `round` of a walk's asks, as [`Self::fetch_listed`] asks —;
    /// whether it is now held or refused. One a removal cut keeps bound to
    /// bytes is asked for by its full name, so only those bytes answer
    /// ([`Self::kept_bytes`]). The log of a device whose key is suspected
    /// here is not fetched ([`Device::suspect`]).
    async fn take_fetched(self: &Arc<Self>, name: Name, round: Option<u32>) -> bool {
        if parse_log_name(&name).is_some_and(|l| self.suspects_device(&self.st.lock(), &l.device)) {
            tracing::debug!(%name, "not fetched: its device's key is suspected here");
            return false;
        }
        let digest = self.kept_bytes(&name).await;
        let fetched = match round {
            None => self.fetch_entry(&name, digest).await,
            Some(round) => self.fetch_listed(&name, digest, round).await,
        };
        let Some(data) = fetched else {
            return false;
        };
        match self.take_data(&name, data).await {
            Ok(()) => true,
            Err(Refusal::OutsideCut(_)) => self.st.lock().cut_out.contains_key(&name),
            Err(_) => false,
        }
    }

    /// Since when `key` (a key or certificate name) is suspected here, if
    /// it is and no trust context held revokes it (its cut decides then).
    fn suspected_key(&self, st: &St, key: &Name) -> Option<Timestamp> {
        let since = st.suspected.get(&key_name_of(key)).copied()?;
        (!self.validator.keyring().context_for(key).is_revoked(key)).then_some(since)
    }

    /// Whether a key of `device` is suspected here ([`Self::suspected_key`]).
    fn suspects_device(&self, st: &St, device: &Name) -> bool {
        st.suspected
            .keys()
            .any(|k| device_of(k).as_ref() == Some(device) && self.suspected_key(st, k).is_some())
    }

    /// Verify and take a fetched log entry named `name`. A packet that is
    /// not its name's writer's — a signature that fails, a signer of
    /// another device (checked before the chain walk), a record about
    /// another collection — is refused as a packet
    /// and nothing is kept against the name: whoever answers an Interest can
    /// make such a packet, and the genuine copy may still come from another
    /// source. A record that does not decode is the writer's own once the
    /// signature verifies, and is recorded against its name as refused for
    /// what it carries ([`Self::refuse_unread`]). Only what the genuine writer signed is decided against the
    /// name ([`Self::take`]); so is a packet its key signed that a
    /// revocation refuses ([`Self::refuse_outside_cut`]). A new entry of a
    /// key suspected here is not taken ([`Refusal::Suspected`]), nor one
    /// under this device's own name far beyond its log head
    /// ([`Refusal::BeyondOwnLog`]). The time an entry is first verified
    /// here is kept with it ([`Self::note_verified`]); an entry that
    /// verifies makes the entries of its key withdrawn for their chain be
    /// judged again ([`Self::rejudge`]).
    async fn take_data(self: &Arc<Self>, name: &Name, data: Data) -> Result<(), Refusal> {
        self.take_entry(name, data, true).await
    }

    /// The entry `name`, verified as its writer's, does not decode as a
    /// record this build reads (a kind of an earlier or a later release). It
    /// is recorded against its name as refused for what it carries
    /// ([`Refusal::Unread`]) and its seq is skipped, as any such entry is
    /// ([`Coll::skipped`]): a walk that lists it completes, and the writer's
    /// later versions do not wait for it for good. An entry about no
    /// collection, or of a collection this device does not follow, is
    /// dropped as a packet, as before.
    fn refuse_unread(
        &self,
        name: &Name,
        parsed: &wire::LogName,
        writer: &Writer,
    ) -> Result<(), Refusal> {
        let Some(c) = &parsed.subject else {
            return Err(Refusal::BadSignature);
        };
        let mut st = self.st.lock();
        if st.held.contains_key(name) || st.refused.contains_key(name) {
            return Ok(());
        }
        if !st.track(c, writer, self.config.writer_collections) {
            return Err(Refusal::BadSignature);
        }
        st.ensure(c);
        tracing::debug!(%name, "a verified entry of a kind this build does not read: skipped");
        st.refused.insert(name.clone(), Refusal::Unread);
        if let Some(coll) = st.colls.get_mut(c) {
            coll.skipped
                .entry(writer.clone())
                .or_default()
                .insert(parsed.seq);
        }
        st.apply_ready(c, &BTreeSet::new());
        Ok(())
    }

    /// [`Self::take_data`]; `wake`: judge again what is withdrawn of its
    /// key for its chain (not when taking back such an entry, which the
    /// judgement under way does).
    async fn take_entry(
        self: &Arc<Self>,
        name: &Name,
        data: Data,
        wake: bool,
    ) -> Result<(), Refusal> {
        let parsed = parse_log_name(name).ok_or(Refusal::BadSignature)?;
        if *data.name != *name {
            return Err(Refusal::BadSignature);
        }
        let named = data
            .sig_info()
            .and_then(|s| s.key_locator_name())
            .ok_or(Refusal::BadSignature)?;
        if device_of(&named).as_ref() != Some(&parsed.device) {
            return Err(Refusal::BadSignature);
        }
        {
            let st = self.st.lock();
            if !st.held.contains_key(name)
                && let Some(since) = self.suspected_key(&st, &named)
            {
                return Err(Refusal::Suspected {
                    key: key_name_of(&named),
                    since,
                });
            }
            if parsed.device == self.device && parsed.seq > st.head.saturating_add(OWN_AHEAD) {
                tracing::warn!(%name, head = st.head, "refused: under this device's name, far beyond the last seq it wrote; a copy of its key signed it");
                return Err(Refusal::BeyondOwnLog { head: st.head });
            }
        }
        let (writer, public) = match self.verify_keyed(&data).await {
            Ok(w) => w,
            Err(Refusal::OutsideCut(cut)) => {
                self.refuse_outside_cut(name, &data, cut.clone());
                return Err(Refusal::OutsideCut(cut));
            }
            Err(why) => return Err(why),
        };
        if device_of(writer.key()).as_ref() != Some(&parsed.device) {
            return Err(Refusal::BadSignature);
        }
        let record = match data
            .content()
            .and_then(|c| wire::decode_record(c.clone()).ok())
        {
            Some(record) if record.subject() == parsed.subject => record,
            Some(_) => return Err(Refusal::BadSignature),
            // Its writer's key signed it (the signature is verified): a kind
            // of record this build does not read, not a packet someone made
            // up to answer an Interest.
            None => return self.refuse_unread(name, &parsed, &writer),
        };
        // A version a removal cut keeps is taken only with the bytes the
        // cut's manifests list (spec §8): other bytes at its name are refused
        // as a packet, before anything is held of them, and the ones it keeps
        // may still come. While a manifest packet is not to be had, it is
        // taken and waits ([`St::admit_one`]).
        if let (Record::Version(_), Some(c)) = (&record, &parsed.subject) {
            let id = VersionId {
                writer: writer.clone(),
                seq: Seq(parsed.seq),
            };
            let digest = wire::implicit_digest(data.raw());
            for _ in 0..MANIFEST_LOOKS {
                let verdict = {
                    let st = self.st.lock();
                    st.colls
                        .get(c)
                        .and_then(|x| x.members.as_ref())
                        .and_then(|m| m.kept_by(c, &id))
                        .map(|cut| {
                            let bound =
                                bound_bytes(&st.cut_bytes, &*st.store, cut, c, &id, name, &digest);
                            (bound, cut.clone())
                        })
                };
                match verdict {
                    None | Some((Bound::Listed, _)) => break,
                    Some((Bound::Other, cut)) => {
                        tracing::debug!(%name, "refused as a packet: other bytes than the removal cut keeps at this name");
                        {
                            let mut st = self.st.lock();
                            if !st.held.contains_key(name) {
                                st.other_bytes
                                    .entry(name.clone())
                                    .or_insert_with(|| (cut.clone(), 0));
                            }
                        }
                        self.fetch_kept(false);
                        return Err(Refusal::OutsideCut(cut));
                    }
                    Some((Bound::Unbound, cut)) => {
                        // Bytes taken now at a seq a cut signed before cuts
                        // bound bytes keeps need not be the ones its owner
                        // held: none is taken. The owner's next record binds
                        // the bytes it holds, asked for then by full name.
                        tracing::debug!(%name, "refused as a packet: a removal cut signed before cuts bound bytes keeps this seq; the owner's next record binds its bytes");
                        let mut st = self.st.lock();
                        if !st.held.contains_key(name) {
                            st.other_bytes
                                .entry(name.clone())
                                .or_insert_with(|| (cut.clone(), 0));
                        }
                        return Err(Refusal::OutsideCut(cut));
                    }
                    Some((Bound::Missing(full), _)) => {
                        if !self.fetch_cut_bytes(&full).await {
                            break;
                        }
                    }
                }
            }
        }
        // The manifests a members record's cuts bind their versions by: held
        // here once it is, so this device judges by them and serves them.
        let bound_by: Vec<Name> = match &record {
            Record::Members(b) => b
                .cuts
                .iter()
                .flat_map(|k| k.accept.all_manifests())
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        // They are fetched before the record is taken, when an owner device
        // signed it (spec §8): its cuts judge every version of the collection the
        // moment it is, and a version a cut keeps that this device applied
        // under the record before stays applied across the switch, instead
        // of waiting for a packet this record names. Asked again after
        // [`retry_pause`], up to [`FETCH_TRIES`] rounds (spec §17.1); one
        // still not to be had then is taken without, and what its cuts keep
        // waits for it as any version does.
        if !bound_by.is_empty()
            && !self.st.lock().held.contains_key(name)
            && let Record::Members(b) = &record
            && owner_signed(self.validator.keyring(), name, &b.collection, &writer)
        {
            for tries in 0..FETCH_TRIES {
                if tries > 0 {
                    rt::sleep(retry_pause(tries - 1)).await;
                }
                let mut whole = true;
                for root in &bound_by {
                    whole &= self.hold_cut_tree(root).await;
                }
                if whole {
                    break;
                }
                tracing::debug!(record = %name, "a removal cut's manifest not held whole before its record is taken; asked again");
            }
        }
        let (chase, wanted, wires, withdrawn) = {
            let mut st = self.st.lock();
            let members = matches!(record, Record::Members(_));
            let key = key_name_of(writer.key());
            self.take(
                &mut st,
                name.clone(),
                data.raw().clone(),
                writer,
                record,
                false,
            );
            if st.held.contains_key(name) {
                self.note_verified(&mut st, name, public);
            }
            let withdrawn = st
                .cut_out
                .values()
                .any(|o| !o.by_cut() && key_name_of(o.writer.key()) == key);
            // A register version in pieces waits for them: fetched now.
            let wanted = match &parsed.subject {
                Some(c) => st.wanted_pieces(c),
                None => Vec::new(),
            };
            // A version naming its parent by a packet other than the one held
            // waits for that packet: asked for by its full name.
            let wires = st.wanted_wires(parsed.subject.as_ref());
            // A group's record decides who reads the collections sealed to
            // it: their keys may be asked for now.
            let mut chase = Vec::new();
            if let Some(c) = parsed.subject {
                // A folder's record decides who reads the collections under
                // it.
                let under = |st: &St, n: &Name, folder: bool| -> Vec<Name> {
                    match folder {
                        true => st
                            .colls
                            .keys()
                            .filter(|x| x.has_prefix(n))
                            .cloned()
                            .collect(),
                        false => vec![n.clone()],
                    }
                };
                if members {
                    for s in st.sealed_to.get(&c).into_iter().flatten() {
                        chase.extend(under(&st, &s.name, s.folder));
                    }
                    if st.folders.contains_key(&c) {
                        chase.extend(under(&st, &c, true));
                    }
                }
                chase.push(c);
            }
            chase.sort();
            chase.dedup();
            (chase, wanted, wires, (wake && withdrawn).then_some(key))
        };
        for c in chase {
            self.chase_keys(&c);
        }
        for (v, chunks) in wanted {
            self.spawn_pieces(v, chunks);
        }
        self.spawn_wires(wires);
        // Its key verifies again: what was withdrawn of it for its chain
        // may verify too (a new certificate of the key).
        if let Some(key) = withdrawn {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.rejudge(Rejudge::Withdrawn(Some(key))).await;
            });
        }
        if !bound_by.is_empty() && self.st.lock().held.contains_key(name) {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                for root in &bound_by {
                    if !inner.hold_cut_tree(root).await {
                        tracing::debug!(%root, "a removal cut's manifest not held whole yet; its versions wait for what they need");
                    }
                }
            });
        }
        self.fetch_wanted_bytes();
        self.fetch_kept(false);
        self.settle().await;
        Ok(())
    }

    /// Ask, in the background, for every epoch key that a locked version of
    /// `c` needs, or that the record in force over `c` is in, that is not
    /// held or being asked for, and that this device may hold
    /// ([`Self::may_hold`]).
    fn chase_keys(self: &Arc<Self>, c: &Name) {
        let asks: BTreeSet<(Name, Epoch)> = {
            let st = self.st.lock();
            // The epochs of its locked versions, and of the record in force
            // over it (its own, or its folder's: a folder's own record when
            // `c` is a folder), whose key is owed for what comes next and for
            // writing (spec §17.1): asked as soon as the record is held, not
            // once the first version sealed in it waits.
            let coll = st.colls.get(c);
            let mut epochs: BTreeSet<Epoch> = coll
                .into_iter()
                .flat_map(|x| x.locked.iter().map(|l| l.epoch().clone()))
                .collect();
            epochs.extend(
                coll.and_then(|x| x.members.as_ref())
                    .into_iter()
                    .chain(st.folders.get(c).and_then(|f| f.members.as_ref()))
                    .filter_map(|m| m.epoch.clone()),
            );
            epochs
                .into_iter()
                .filter(|e| st.keys.key(c, e).is_none())
                // Of the collection, or of the folder whose epoch it is.
                .map(|e| (st.seal_subject(c, &e).name, e))
                .filter(|(s, e)| {
                    !st.asking.contains(&(s.clone(), e.clone()))
                        && self.may_hold(&st, s, e, &self.device, &self.ns)
                })
                .collect()
        };
        for (s, e) in asks {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.obtain(&s, &e).await;
            });
        }
    }

    /// Hold a verified log entry and let its collection take it. Own entries
    /// are stored now; members records once accepted
    /// (owner-signed); others' versions once applied.
    fn take(
        &self,
        st: &mut St,
        name: Name,
        wire: Bytes,
        writer: Writer,
        record: Record,
        mine: bool,
    ) {
        // Another packet of a version held: a copy in another signature value
        // of what its key signed (the same version), or the other thing the
        // key signed there. A version naming its parent by it is judged anew.
        if matches!(record, Record::Version(_))
            && matches!(st.held.get(&name), Some(Held::Version(_) | Held::Locked))
            && let Some(signed) = wire::signed_digest(&wire)
        {
            let same = st.held_signed(&name) == Some(signed);
            st.note_wire(&name, wire::implicit_digest(&wire), same);
        }
        if let Some(Held::Version(id)) = st.held.get(&name) {
            let seq = id.seq.0;
            if let Record::Version(body) = &record
                && st
                    .held_signed(&name)
                    .is_some_and(|first| Some(first) != wire::signed_digest(&wire))
                && let Some(first) = st.held_version(&name)
            {
                // Kept first, then reported, so the evidence outlives a
                // restart: one second packet per name. Another signature value over what
                // the key signed is no second thing (it is not kept: `wire::signed_digest`).
                if !st.twins.contains_key(&name) {
                    self.store.insert(equivocal_name(&name), wire.clone());
                    st.twins.insert(name.clone(), wire.clone());
                }
                let change = Change::Equivocation {
                    collection: body.collection.clone(),
                    first: Equivocal::Here(Box::new(first)),
                    second: Equivocal::Here(Box::new(version_of(
                        &name,
                        &writer,
                        seq,
                        body.clone(),
                        wire::implicit_digest(&wire),
                        body.sealed.is_none(),
                    ))),
                };
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
        if record.subject() != parsed.subject {
            return;
        }
        // A version of a collection its outside writer may not make this
        // device follow is not taken ([`St::track`]).
        if let (Record::Version(_), Some(c), false) = (&record, &parsed.subject, mine)
            && !st.track(c, &writer, self.config.writer_collections)
        {
            return;
        }
        // A key's log is one sequence across its collections and entry
        // kinds (spec §4): another entry at a seq it used is equivocation.
        // An entry the trust context refuses is a thief's (spec §8.1).
        if !st.cut_out.contains_key(&name) {
            st.note_seq(&name, &writer, parsed.seq, &record, &wire);
        }
        if let Some(c) = &parsed.subject {
            if mine {
                let ns = namespace_of(c).expect("a log entry's collection has a namespace");
                let kind = match record {
                    Record::Version(_) => Kind::Version,
                    _ => Kind::Record,
                };
                st.trees
                    .entry(ns.clone())
                    .or_insert_with(|| Tree::new(ns))
                    .add(c, parsed.seq, kind);
            } else {
                self.note_peer_head(st, &parsed.device, c, parsed.seq);
            }
        }
        // Read back from the store at start, it is stored already.
        if !st.restoring && mine {
            self.store.insert(name.clone(), wire.clone());
        }
        // A record a revocation refuses is held as refused and not taken
        // (a version is admitted as refused, [`St::admit_one`]).
        let digest = wire::implicit_digest(&wire);
        let Some(signed) = wire::signed_digest(&wire) else {
            return;
        };
        if st.cut_out.contains_key(&name) && !matches!(record, Record::Version(_)) {
            st.held.insert(
                name,
                Held::Record {
                    writer,
                    digest,
                    signed,
                },
            );
            return;
        }
        match record {
            Record::Members(body) => {
                st.held.insert(
                    name.clone(),
                    Held::Record {
                        writer: writer.clone(),
                        digest,
                        signed,
                    },
                );
                let c = body.collection.clone();
                if owner_signed(self.validator.keyring(), &name, &c, &writer) {
                    // The record and what accepting it writes reach the store as one batch.
                    let _batch = self.stage.batch();
                    self.store.insert(name.clone(), wire);
                    st.accept_members(parsed.seq, body, &writer);
                } else {
                    tracing::debug!(collection = %c, signer = ?writer, "members record not signed by a device of the collection's namespace; ignored");
                }
            }
            Record::Version(mut body) => {
                let c = body.collection.clone();
                // Under a folder in force with no record of its own, it is
                // read under the folder's (spec §6).
                st.ensure(&c);
                let seq = parsed.seq;
                let sealed = body.sealed.is_some();
                let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
                // Of a revoked key, its entries outside its cut never apply:
                // this version's and its parents' (spec §5, §8).
                let writers: Vec<Writer> = std::iter::once(writer.clone())
                    .chain(body.parents.iter().map(|(y, _)| y.clone()))
                    .collect();
                self.note_revoked_in(st, &c, writers);
                if let Some(s) = body.sealed.clone() {
                    let Some(key) = st.keys.key(&c, &s.epoch) else {
                        st.held.insert(name.clone(), Held::Locked);
                        let coll = st.colls.entry(c.clone()).or_default();
                        coll.locked.push(Locked {
                            name,
                            wire,
                            writer,
                            seq,
                            body,
                        });
                        return;
                    };
                    // A payload in pieces opens when it is read, or, of a
                    // merge version, once whole, before it applies.
                    if body.chunks.is_none() {
                        let Some(opened) = seal::open_payload(&key, &name, &s.ciphertext) else {
                            // Its writer signed what does not open: later
                            // versions do not wait for it.
                            tracing::debug!(%name, "refused: its payload does not open under its epoch's key");
                            st.refused.insert(name, Refusal::BadSignature);
                            st.colls
                                .entry(c.clone())
                                .or_default()
                                .skipped
                                .entry(writer)
                                .or_default()
                                .insert(seq);
                            return;
                        };
                        open_into(&mut body, opened);
                    }
                }
                let op = body.op.clone();
                let chunks = body.chunks;
                let version = version_of(&name, &writer, seq, body, digest, true);
                st.held
                    .insert(name.clone(), Held::Version(version.id.clone()));
                st.admit(Arc::new(HeldVersion::new(
                    version, op, wire, sealed, epoch, chunks,
                )));
            }
            Record::Intro(body) => {
                self.take_intro(st, name, &parsed, wire, writer, body, (digest, signed));
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

    // ---- revocation (spec §8) -----------------------------------------------------------------

    /// Whether the trust context governing `name` revokes `writer`'s key
    /// and that key's cut does not accept the entry `name` with the implicit
    /// digest `digest` gives (asked only of a revoked key): its digest and
    /// the cut that refuses it ([`Self::cut_verdict`]; not refused while
    /// undecided).
    fn refusing(
        &self,
        name: &Name,
        writer: &Writer,
        digest: impl FnOnce() -> Option<[u8; 32]>,
    ) -> Option<([u8; 32], Cut)> {
        let ctx = self.validator.keyring().context_for(name);
        if !ctx.is_revoked(writer.key()) {
            return None;
        }
        let digest = digest()?;
        (self.cut_verdict(&ctx, name, writer, &digest) == Some(true))
            .then(|| (digest, revocation_cut_for(&ctx, writer, &log_prefix(name))))
    }

    /// Whether `ctx` refuses the entry `name` with implicit digest `digest`
    /// signed by `writer` for its key's revocation: no revocation, or its
    /// cut accepts it — `Some(false)`; revoked without a cut, or its cut
    /// does not accept it — `Some(true)`. An entry in a range of a cut bound
    /// to a manifest is accepted only with the digest the manifest lists for
    /// it; while the manifest is not held here the verdict is `None`
    /// (undecided: it stays as it is, and is judged again once the manifest
    /// is fetched, [`Self::rejudge`]).
    fn cut_verdict(
        &self,
        ctx: &SignedTrustContext,
        name: &Name,
        writer: &Writer,
        digest: &[u8; 32],
    ) -> Option<bool> {
        if !ctx.is_revoked(writer.key()) {
            return Some(false);
        }
        Some(match ctx.revocation_cut(&key_name_of(writer.key())) {
            None => true,
            Some(cut) if cut.accepts(name, digest) => false,
            Some(cut) => match (cut.manifest(), cut.range_seq(name)) {
                (Some(root), Some((range, seq))) => {
                    match self
                        .validator
                        .cut_manifests()
                        .lookup(root, &range.prefix, seq)
                    {
                        ManifestLookup::Listed(listed) => listed != *digest,
                        ManifestLookup::NotListed => true,
                        ManifestLookup::Missing(_) => return None,
                    }
                }
                _ => true,
            },
        })
    }

    /// [`Self::refusing`] for the entry whose packet is `packet`.
    fn cut_refusing(&self, name: &Name, writer: &Writer, packet: &[u8]) -> Option<([u8; 32], Cut)> {
        self.refusing(name, writer, || Some(wire::implicit_digest(packet)))
    }

    /// What the manifest of the revocation cut binding the log entry `name`
    /// of `writer` lists for it, when the trust context governing it
    /// revokes the key with a cut bound to a manifest whose ranges take
    /// `name`; `None` when no such cut binds it (an old cut binds names
    /// only).
    fn listed_digest(&self, name: &Name, writer: &Writer) -> Option<ManifestLookup> {
        let ctx = self.validator.keyring().context_for(name);
        let cut = ctx.revocation_cut(&key_name_of(writer.key()))?;
        let (Some(root), Some((range, seq))) = (cut.manifest(), cut.range_seq(name)) else {
            return None;
        };
        Some(
            self.validator
                .cut_manifests()
                .lookup(root, &range.prefix, seq),
        )
    }

    /// Fetch the cut manifest packet `full` (a full name ending in its
    /// implicit digest) and hold it with the validator's manifests; whether
    /// it is held now.
    async fn fetch_manifest(&self, full: &Name) -> bool {
        if self.validator.cut_manifests().contains(full) {
            return true;
        }
        let Some(data) = self.fetch(full.clone(), false).await else {
            tracing::debug!(%full, "a cut manifest packet not to be had now");
            return false;
        };
        match self.validator.cut_manifests().insert(&data) {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(%full, "a cut manifest packet refused: {e}");
                false
            }
        }
    }

    /// The digest to fetch the log entry `name` of `writer` by, which a
    /// revocation cut accepts: `Some(Some(d))` exactly the bytes its cut's
    /// manifest lists (its manifest packets fetched as needed);
    /// `Some(None)` by name, the cut binding no bytes; `None` when it is
    /// not to be fetched (the manifest lists nothing there, or cannot be
    /// had now).
    async fn cut_digest(&self, name: &Name, writer: &Writer) -> Option<Option<[u8; 32]>> {
        // A manifest is a tree a few levels deep; each look fetches one.
        for _ in 0..MANIFEST_LOOKS {
            match self.listed_digest(name, writer) {
                None => return Some(None),
                Some(ManifestLookup::Listed(d)) => return Some(Some(d)),
                Some(ManifestLookup::NotListed) => return None,
                Some(ManifestLookup::Missing(full)) => {
                    if !self.fetch_manifest(&full).await {
                        return None;
                    }
                }
            }
        }
        None
    }

    /// Hold the removal cut manifest packet `full` (a full name ending in
    /// its implicit digest): from the store, else fetched by its full name
    /// from whoever answers — it is trusted by that digest alone — and kept
    /// in the store, so this device serves it too (spec §8). Whether it is
    /// held now.
    async fn fetch_cut_bytes(&self, full: &Name) -> bool {
        {
            let st = self.st.lock();
            if load_cut_bytes(&st.cut_bytes, &*st.store, full) {
                return true;
            }
        }
        let Some(data) = self.fetch(full.clone(), false).await else {
            tracing::debug!(%full, "a removal cut's manifest packet not to be had now");
            return false;
        };
        let taken = data
            .name
            .as_ref()
            .clone()
            .append_implicit_digest(data.implicit_digest());
        if taken != *full {
            tracing::debug!(%full, "not the removal cut's manifest packet asked for; ignored");
            return false;
        }
        let st = self.st.lock();
        st.store.insert((*data.name).clone(), data.raw().clone());
        if let Err(e) = st.cut_bytes.insert(&data) {
            tracing::debug!(%full, "a removal cut's manifest packet that lists nothing: {e}");
        }
        true
    }

    /// Hold every packet of the removal cut manifest rooted at `root`
    /// (fetched as [`Self::fetch_cut_bytes`] says), so this device judges
    /// by it and serves it; whether all are held.
    async fn hold_cut_tree(&self, root: &Name) -> bool {
        // One round per level of the tree, at most.
        for _ in 0..MANIFEST_LOOKS {
            let missing: Vec<Name> = {
                let st = self.st.lock();
                st.cut_bytes
                    .missing(root)
                    .into_iter()
                    .filter(|full| !load_cut_bytes(&st.cut_bytes, &*st.store, full))
                    .collect()
            };
            if missing.is_empty() {
                // What the store gave may have named more.
                if self.st.lock().cut_bytes.missing(root).is_empty() {
                    return true;
                }
                continue;
            }
            for full in missing {
                if !self.fetch_cut_bytes(&full).await {
                    return false;
                }
            }
        }
        false
    }

    /// The digest to fetch the log entry `name` by, when a removal cut of
    /// the record in force over its collection keeps it bound to bytes:
    /// exactly those its manifest lists (its packets fetched as needed),
    /// so other bytes at that name are never asked for (spec §8). `None`:
    /// by name.
    async fn kept_bytes(&self, name: &Name) -> Option<[u8; 32]> {
        // A manifest is a tree a few levels deep; each look fetches one.
        for _ in 0..MANIFEST_LOOKS {
            let looked = self.st.lock().kept_digest(name);
            match looked {
                Ok(digest) => return digest,
                Err(full) => {
                    if !self.fetch_cut_bytes(&full).await {
                        return None;
                    }
                }
            }
        }
        None
    }

    /// Fetch, in the background, the removal cut manifest packets versions
    /// wait for ([`St::bytes_wanted`]), then read their collections again,
    /// so the waiting versions are judged by them. Called wherever a version
    /// may have come to wait for one — an entry taken, and every path that
    /// admits versions anew (a key obtained, a descent ended, a start). A
    /// packet not to be had stays
    /// wanted, asked for again then and after [`retry_pause`] of the misses
    /// in a row for it (spec §17.1).
    fn fetch_wanted_bytes(self: &Arc<Self>) {
        let wanted: Vec<(Name, BTreeSet<Name>)> = {
            let mut st = self.st.lock();
            let all = std::mem::take(&mut st.bytes_wanted);
            let (busy, free): (BTreeMap<_, _>, BTreeMap<_, _>) = all
                .into_iter()
                .partition(|(full, _)| st.bytes_fetching.contains(full));
            st.bytes_wanted = busy;
            st.bytes_fetching.extend(free.keys().cloned());
            free.into_iter().collect()
        };
        for (full, colls) in wanted {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                let held = inner.fetch_cut_bytes(&full).await;
                let fetch: Vec<(Name, ChunksBody)> = {
                    let mut st = inner.st.lock();
                    st.bytes_fetching.remove(&full);
                    if !held {
                        let misses = st.bytes_misses.entry(full.clone()).or_insert(0);
                        let pause = retry_pause(*misses);
                        *misses = misses.saturating_add(1);
                        st.bytes_wanted.entry(full).or_default().extend(colls);
                        drop(st);
                        let weak = Arc::downgrade(&inner);
                        rt::spawn(async move {
                            rt::sleep(pause).await;
                            if let Some(inner) = weak.upgrade() {
                                inner.fetch_wanted_bytes();
                            }
                        });
                        return;
                    }
                    st.bytes_misses.remove(&full);
                    let mut fetch = Vec::new();
                    for c in &colls {
                        st.reread(c);
                        fetch.extend(st.wanted_pieces(c));
                    }
                    fetch
                };
                for (v, chunks) in fetch {
                    inner.spawn_pieces(v, chunks);
                }
                inner.fetch_wanted_bytes();
                inner.fetch_kept(false);
                inner.settle().await;
            });
        }
    }

    /// Ask, in the background, for the bytes a removal cut keeps at each
    /// name whose other bytes were refused here ([`St::other_bytes`]), by
    /// their full name (spec §8): only those bytes can answer, whoever
    /// serves them. One not to be had now is asked for again after a
    /// growing pause, up to [`READMIT_TRIES`] times, and at each refresh of
    /// a group meanwhile. `all`: every such name; else those not asked for
    /// yet.
    fn fetch_kept(self: &Arc<Self>, all: bool) {
        let names: Vec<Name> = {
            let mut st = self.st.lock();
            let names: Vec<Name> = st
                .other_bytes
                .iter()
                .filter(|(n, (_, tries))| {
                    (all || *tries == 0)
                        && !st.held.contains_key(*n)
                        && !st.bytes_fetching.contains(*n)
                })
                .map(|(n, _)| n.clone())
                .collect();
            st.bytes_fetching.extend(names.iter().cloned());
            names
        };
        for name in names {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.fetch_kept_one(name).await;
            });
        }
    }

    /// [`Self::fetch_kept`] of one name.
    async fn fetch_kept_one(self: &Arc<Self>, name: Name) {
        let taken = self.take_fetched(name.clone(), None).await;
        let retry = {
            let mut st = self.st.lock();
            st.bytes_fetching.remove(&name);
            let held = taken && st.held.contains_key(&name);
            match st.other_bytes.get_mut(&name) {
                Some((_, tries)) if !held => {
                    *tries = tries.saturating_add(1);
                    (*tries <= READMIT_TRIES).then(|| READMIT_PAUSE * 2u32.pow(*tries - 1))
                }
                _ => None,
            }
        };
        tracing::debug!(%name, ?retry, "the bytes a removal cut keeps, asked for by their full name");
        if let Some(pause) = retry {
            let weak = Arc::downgrade(self);
            rt::spawn(async move {
                rt::sleep(pause).await;
                if let Some(inner) = weak.upgrade() {
                    inner.fetch_kept(true);
                }
            });
        }
    }

    /// Keep the refusal of `data`, the log entry `name`, by `cut`: its key
    /// is revoked and the cut does not accept it ([`Self::verify`]). The
    /// packet is kept with it, so a re-admission of exactly it needs no
    /// fetch, and later entries do not wait for it. Kept only when the
    /// context holds a cut for the key: only then did the validator verify
    /// the packet's signature and chain before refusing it, so it is
    /// authentic; a key revoked without a cut is refused before any
    /// signature check, and such a packet is refused as a packet only (it
    /// may be a forgery, and nothing of it can be re-admitted). Not kept
    /// either when the context re-admits other bytes at that name, or its
    /// cut's manifest binds the name to bytes (other bytes than these: the
    /// listed ones may still come from another source), nor when an
    /// accepted entry holds the name.
    fn refuse_outside_cut(&self, name: &Name, data: &Data, cut: Cut) {
        let Some(key) = data.sig_info().and_then(|s| s.key_locator_name()) else {
            return;
        };
        let Some(parsed) = parse_log_name(name) else {
            return;
        };
        let ctx = self.validator.keyring().context_for(name);
        let Some(held_cut) = ctx.revocation_cut(&cut.of) else {
            tracing::debug!(%name, "refused as a packet: its key is revoked without a cut, so every packet it signs is refused unverified");
            return;
        };
        let other_bytes = held_cut
            .exact()
            .iter()
            .any(|e| e.len() == name.len() + 1 && e.has_prefix(name))
            || (held_cut.manifest().is_some() && held_cut.range_seq(name).is_some());
        if other_bytes {
            tracing::debug!(%name, "refused as a packet: other bytes at this name are accepted");
            return;
        }
        let writer = Writer::new((*key).clone());
        let mut st = self.st.lock();
        if st.held.contains_key(name) {
            return;
        }
        st.refused
            .insert(name.clone(), Refusal::OutsideCut(cut.clone()));
        st.cut_out.insert(
            name.clone(),
            OutOfCut {
                writer: writer.clone(),
                digest: wire::implicit_digest(data.raw()),
                wire: Some(data.raw().clone()),
                why: Refusal::OutsideCut(cut.clone()),
            },
        );
        if let Some(c) = parsed.subject {
            let coll = st.colls.entry(c.clone()).or_default();
            coll.skipped
                .entry(writer.clone())
                .or_default()
                .insert(parsed.seq);
            coll.revoked.insert(writer, cut);
            // Versions that waited for it apply.
            st.apply_ready(&c, &BTreeSet::new());
        }
        drop(st);
        self.progress.notify_waiters();
    }

    /// Note in collection `c` the revocation cut of each of `writers` whose
    /// key the trust context governing its log there revokes
    /// ([`Coll::revoked`]).
    fn note_revoked_in(&self, st: &mut St, c: &Name, writers: impl IntoIterator<Item = Writer>) {
        let keyring = self.validator.keyring();
        let coll = st.colls.entry(c.clone()).or_default();
        for w in writers {
            if coll.revoked.contains_key(&w) {
                continue;
            }
            let Some(device) = device_of(w.key()) else {
                continue;
            };
            let prefix = log_prefix(&log_name(&device, Some(c), 0));
            let ctx = keyring.context_for(&prefix);
            if ctx.is_revoked(w.key()) {
                let cut = revocation_cut_for(&ctx, &w, &prefix);
                coll.revoked.insert(w, cut);
            }
        }
    }

    /// Note anew, in every collection, the revocation cuts of the keys
    /// that write there or that a version held names as a parent, by the
    /// trust contexts held now.
    fn note_revoked(&self, st: &mut St) {
        let writers: Vec<(Name, BTreeSet<Writer>)> = st
            .colls
            .iter_mut()
            .map(|(c, coll)| {
                coll.revoked.clear();
                let mut ws: BTreeSet<Writer> = coll.entries.keys().cloned().collect();
                for hv in coll
                    .versions
                    .values()
                    .chain(&coll.waiting)
                    .chain(&coll.outsiders)
                {
                    ws.insert(hv.version.id.writer.clone());
                    ws.extend(hv.version.parents.iter().map(|(y, _)| y.clone()));
                }
                ws.extend(coll.locked.iter().map(|l| l.writer.clone()));
                (c.clone(), ws)
            })
            .collect();
        for (c, ws) in writers {
            self.note_revoked_in(st, &c, ws);
        }
    }

    /// Take a trust context this device's keyring adopted (spec §8): a key
    /// it revokes is no longer only suspected here (its cut decides); every
    /// held log entry that a revocation now refuses outside its key's cut
    /// is withdrawn ([`Self::withdraw_revoked`]); every entry refused here
    /// that the contexts no longer refuse, or that a cut re-admits exactly,
    /// is taken — fetched by its full name if not held — and delivered like
    /// a newly arrived one; what is held is judged again by the durable rule
    /// — every entry of its namespace when the context may refuse more than
    /// the one before it ([`refuses_more`]), else those withdrawn for their
    /// chain ([`Self::rejudge`]); then what the cuts accept of the
    /// collections this device follows is fetched.
    async fn adopted(self: &Arc<Self>, ctx: &Arc<SignedTrustContext>) {
        let ns = ctx.namespace().clone();
        let (readmit, more) = {
            let mut st = self.st.lock();
            // The markers of what it refuses reach the store as one batch.
            let _batch = self.stage.batch();
            let more = refuses_more(st.contexts.get(&ns).map(|c| &**c), ctx);
            st.contexts.insert(ns.clone(), Arc::clone(ctx));
            let keyring = self.validator.keyring();
            let revoked: Vec<Name> = st
                .suspected
                .keys()
                .filter(|k| keyring.context_for(k).is_revoked(k))
                .cloned()
                .collect();
            for key in revoked {
                tracing::info!(%key, "no longer suspected: a trust context revokes it");
                st.suspected.remove(&key);
                self.store.remove(&suspected_name(&key));
            }
            self.note_revoked(&mut st);
            self.withdraw_revoked(&mut st);
            let readmit = self.readmissions(&mut st, ctx);
            // What waited for an entry a cut now leaves out applies.
            let colls: Vec<Name> = st.colls.keys().cloned().collect();
            for c in colls {
                st.apply_ready(&c, &BTreeSet::new());
            }
            (readmit, more)
        };
        futures::future::join_all(readmit.into_iter().map(|r| self.readmit(r))).await;
        self.rejudge(match more {
            true => Rejudge::Namespace(ns),
            false => Rejudge::Withdrawn(None),
        })
        .await;
        self.fetch_cut_runs();
        self.settle().await;
        self.progress.notify_waiters();
    }

    /// Withdraw every held log entry whose key the trust context governing
    /// it revokes and whose cut does not accept it ([`Self::withdraw`]).
    fn withdraw_revoked(&self, st: &mut St) {
        let mut found: Vec<(Name, Writer, [u8; 32], Refusal)> = Vec::new();
        for coll in st.colls.values() {
            let versions = coll
                .versions
                .values()
                .chain(&coll.waiting)
                .chain(&coll.outsiders)
                .map(|hv| (&hv.version.name, &hv.version.id.writer, &hv.wire))
                .chain(coll.locked.iter().map(|l| (&l.name, &l.writer, &l.wire)));
            for (name, writer, packet) in versions {
                if !st.cut_out.contains_key(name)
                    && let Some((digest, cut)) = self.cut_refusing(name, writer, packet)
                {
                    found.push((
                        name.clone(),
                        writer.clone(),
                        digest,
                        Refusal::OutsideCut(cut),
                    ));
                }
            }
        }
        for (name, held) in st.held.iter() {
            if st.cut_out.contains_key(name) {
                continue;
            }
            let refused = match held {
                Held::Record { writer, digest, .. } => self
                    .refusing(name, writer, || Some(*digest))
                    .map(|r| (writer, r)),
                _ => None,
            };
            if let Some((writer, (digest, cut))) = refused {
                found.push((
                    name.clone(),
                    writer.clone(),
                    digest,
                    Refusal::OutsideCut(cut),
                ));
            }
        }
        self.withdraw(st, found);
    }

    /// Withdraw each held log entry `found` lists — its name, the key that
    /// signed it, its implicit digest, and why the trust context refuses it
    /// now ([`Refusal::OutsideCut`] by its key's cut, or
    /// [`Refusal::Untrusted`] for its chain) — as a members record that
    /// arrived later withdraws what its cut refuses: it is kept as refused
    /// ([`St::cut_out`]); a version leaves the state, which is rebuilt, and
    /// one delivered before is reported to every watcher of its collection
    /// whatever its frontier ([`Change::Withdrawn`]); a members record
    /// stops counting and the record in force is made again from the
    /// others. This device's own entries too. Its
    /// packet stays in the store; one refused for its chain is marked so
    /// there ([`untrusted_name`]), for a restart.
    fn withdraw(&self, st: &mut St, found: Vec<(Name, Writer, [u8; 32], Refusal)>) {
        // The markers reach the store as one batch.
        let _batch = self.stage.batch();
        let mut reread = BTreeSet::new();
        let mut rebuild = BTreeMap::new();
        for (name, writer, digest, why) in found {
            tracing::info!(%name, %why, "withdrawn: a trust context adopted later refuses it");
            let record = matches!(st.held.get(&name), Some(Held::Record { .. }));
            // A version admitted is refused as its collection is read again
            // ([`St::admit_one`]), which reports it if it was delivered.
            if !matches!(st.held.get(&name), Some(Held::Version(_))) {
                st.refused.insert(name.clone(), why.clone());
            }
            if let Refusal::Untrusted { why } = &why {
                self.store.insert(
                    untrusted_name(&name),
                    Bytes::copy_from_slice(why.as_bytes()),
                );
            }
            st.cut_out.insert(
                name.clone(),
                OutOfCut {
                    writer,
                    digest,
                    wire: None,
                    why: why.clone(),
                },
            );
            let Some(c) = parse_log_name(&name).and_then(|l| l.subject) else {
                continue;
            };
            if record {
                let members = self
                    .store
                    .get(&name)
                    .and_then(|w| Data::decode(w).ok())
                    .and_then(|d| wire::decode_record(d.content()?.clone()).ok())
                    .is_some_and(|r| matches!(r, Record::Members(_)));
                if members {
                    rebuild.entry(c.clone()).or_insert(why);
                }
            }
            reread.insert(c);
        }
        for (c, why) in rebuild {
            self.rebuild_members(st, &c, &why);
        }
        for c in reread {
            st.reread(&c);
        }
        // A version of a collection no record is known of yet: refused too.
        let waiting: Vec<(Name, Refusal)> = st
            .cut_out
            .iter()
            .filter(|(n, _)| !st.refused.contains_key(*n))
            .map(|(n, o)| (n.clone(), o.why.clone()))
            .collect();
        for (name, why) in waiting {
            st.refused.insert(name, why);
        }
    }

    /// Judge held log entries again by the durable rule, on their packets,
    /// against the trust contexts and certificates held now (spec §8): the
    /// same rule a fresh fetch gets (`validate_durable_cached`), so a key
    /// above an entry's signer that a context revokes, a cut bound to other
    /// bytes or another public key, or a lapse a cut must end, refuses it
    /// as it would refuse it fetched. What [`Rejudge`] names is judged:
    ///
    /// - accepted: it stays; one withdrawn for its chain before is taken
    ///   back and delivered again;
    /// - refused by its key's own revocation: withdrawn by the cut
    ///   ([`Refusal::OutsideCut`], re-admitted only exactly);
    /// - refused for its chain: withdrawn ([`Refusal::Untrusted`]), its
    ///   packet kept, taken back once the chain verifies (a new certificate
    ///   of its key from an issuer still trusted);
    /// - pending (a certificate or cut manifest packet not held): it stays
    ///   as it is; the missing piece is fetched, once for every entry
    ///   waiting for it, and those entries are judged again.
    ///
    /// A verdict no signed data decides (a signature that no longer checks
    /// against what is cached) leaves the entry as it is. This device's own
    /// entries are not judged: it signed them.
    fn rejudge<'a>(self: &'a Arc<Self>, which: Rejudge) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let list = self.to_rejudge(&which);
            if list.is_empty() {
                return;
            }
            let mut found = Vec::new();
            let mut back = Vec::new();
            let mut waiting: BTreeMap<Name, Vec<(Name, Data)>> = BTreeMap::new();
            for (name, writer, wire, withdrawn) in list {
                let Ok(data) = Data::decode(wire.clone()) else {
                    continue;
                };
                let (result, missing) = self.judge(&name).validate_durable_cached(&data).await;
                match self.verdict(&name, &writer, result, missing) {
                    Verdict::Accepted if withdrawn => back.push((name, data)),
                    Verdict::Cut(cut) if !withdrawn => found.push((
                        name,
                        writer,
                        wire::implicit_digest(&wire),
                        Refusal::OutsideCut(cut),
                    )),
                    Verdict::Chain(why) if !withdrawn => found.push((
                        name,
                        writer,
                        wire::implicit_digest(&wire),
                        Refusal::Untrusted { why },
                    )),
                    Verdict::Pending(missing) => {
                        waiting.entry(missing).or_default().push((name, data));
                    }
                    _ => {}
                }
            }
            if !found.is_empty() {
                let mut st = self.st.lock();
                self.withdraw(&mut st, found);
                let colls: Vec<Name> = st.colls.keys().cloned().collect();
                for c in colls {
                    st.apply_ready(&c, &BTreeSet::new());
                }
            }
            // Taken back below newer entries applied meanwhile: their
            // collections are read again, in order.
            let mut taken = Vec::new();
            for (name, data) in back {
                if self.take_back(&name, data).await {
                    taken.push(name);
                }
            }
            if !taken.is_empty() {
                let mut st = self.st.lock();
                let colls: BTreeSet<Name> = taken
                    .iter()
                    .filter_map(|n| parse_log_name(n)?.subject)
                    .collect();
                for c in &colls {
                    st.reread(c);
                }
                for name in &taken {
                    let again = parse_log_name(name).and_then(|l| l.subject).and_then(|c| {
                        let coll = st.colls.get(&c)?;
                        let hv = coll.versions.values().find(|hv| hv.version.name == *name)?;
                        let id = &hv.version.id;
                        coll.applied
                            .get(&id.writer)
                            .is_some_and(|a| *a >= id.seq.0)
                            .then(|| hv.version.clone())
                    });
                    if let Some(v) = again {
                        st.tell_again(&v);
                    }
                }
            }
            for (missing, entries) in waiting {
                let inner = Arc::clone(self);
                rt::spawn(async move {
                    if inner.resolve(&missing, &entries[0].1).await {
                        let names = entries.into_iter().map(|(n, _)| n).collect();
                        inner.rejudge(Rejudge::Names(names)).await;
                    }
                });
            }
            self.progress.notify_waiters();
        })
    }

    /// The held log entries [`Rejudge`] names, not this device's own:
    /// each with its signer, its packet, and whether it is withdrawn for
    /// its chain now.
    fn to_rejudge(&self, which: &Rejudge) -> Vec<(Name, Writer, Bytes, bool)> {
        let st = self.st.lock();
        let keyring = self.validator.keyring();
        let packet = |name: &Name, o: Option<&OutOfCut>| {
            o.and_then(|o| o.wire.clone())
                .or_else(|| held_wire(&st, name))
                .or_else(|| self.store.get(name))
        };
        let mut out = Vec::new();
        for (name, held) in st.held.iter() {
            if st.verified.get(name).is_some_and(|v| v.own) {
                continue;
            }
            let out_of = st.cut_out.get(name);
            let withdrawn = out_of.is_some_and(|o| !o.by_cut());
            if out_of.is_some_and(|o| o.by_cut()) {
                continue;
            }
            let wanted = match which {
                Rejudge::All => true,
                // A person's namespace adopted for a folder is no context
                // the keyring holds: its entries are found by their name.
                Rejudge::Namespace(ns) => {
                    withdrawn
                        || keyring.context_for(name).namespace() == ns
                        || ndn_security::self_certifying::personal_namespace_of(name).as_ref()
                            == Some(ns)
                }
                Rejudge::Withdrawn(None) => withdrawn,
                Rejudge::Withdrawn(Some(key)) => {
                    withdrawn && out_of.is_some_and(|o| key_name_of(o.writer.key()) == *key)
                }
                Rejudge::Names(names) => names.contains(name),
            };
            if !wanted {
                continue;
            }
            let Some(writer) = held_signer(&st, name, held) else {
                continue;
            };
            if let Some(wire) = packet(name, out_of) {
                out.push((name.clone(), writer.clone(), wire, withdrawn));
            }
        }
        out
    }

    /// What the durable rule's `result` (with the certificate or manifest
    /// packet `missing` it waits for) on the held log entry `name` of
    /// `writer` means for it ([`Self::rejudge`]).
    fn verdict(
        &self,
        name: &Name,
        writer: &Writer,
        result: ValidationResult,
        missing: Option<Arc<Name>>,
    ) -> Verdict {
        let e = match result {
            ValidationResult::Valid(_) => return Verdict::Accepted,
            ValidationResult::Pending => {
                return match missing {
                    Some(m) => Verdict::Pending((*m).clone()),
                    None => Verdict::Undecided,
                };
            }
            ValidationResult::Invalid(e) => e,
        };
        match &e {
            // The signing key itself: its revocation's cut decides.
            TrustError::Revoked { name: refused, .. }
                if refused
                    .parse::<Name>()
                    .is_ok_and(|n| key_name_of(&n) == key_name_of(writer.key())) =>
            {
                let ctx = self.judge(name).keyring().context_for(name);
                if ctx.is_revoked(writer.key()) {
                    Verdict::Cut(revocation_cut_for(&ctx, writer, &log_prefix(name)))
                } else {
                    // Only a certificate of its key is revoked, not the key.
                    Verdict::Chain(e.to_string())
                }
            }
            // Its key lapsed where Data of its role needs a cut: withdrawn
            // with the lapse as its reason, taken back with a renewal.
            TrustError::Revoked { .. }
            | TrustError::Lapsed { .. }
            | TrustError::CertNotAuthorized { .. }
            | TrustError::SchemaMismatch
            | TrustError::UntrustedSelfSigned { .. }
            | TrustError::NoTrustAnchors { .. } => Verdict::Chain(e.to_string()),
            _ => {
                tracing::debug!(%name, "judged again, undecided: {e}");
                Verdict::Undecided
            }
        }
    }

    /// Fetch `missing`, the certificate or cut manifest packet a durable
    /// judgement of `data` waits for; whether it may decide now.
    async fn resolve(&self, missing: &Name, data: &Data) -> bool {
        if ndn_security::is_full_name(missing) {
            return self.fetch_manifest(missing).await;
        }
        // The validator's fetcher brings the certificate in.
        !matches!(
            self.judge(&data.name).validate_durable(data).await,
            ValidationResult::Pending
        )
    }

    /// Take back the log entry `name`, withdrawn for its chain, whose
    /// packet `data` the durable rule accepts again: it is taken like a
    /// newly arrived entry. Whether it was taken.
    async fn take_back(self: &Arc<Self>, name: &Name, data: Data) -> bool {
        {
            let mut st = self.st.lock();
            st.forget(name);
            self.store.remove(&untrusted_name(name));
        }
        tracing::info!(%name, "taken back: its chain verifies again");
        match self.take_entry(name, data, false).await {
            Ok(()) => true,
            Err(why) => {
                tracing::debug!(%name, "judged again and accepted, yet not taken: {why}");
                false
            }
        }
    }

    /// Make the records in force at `c` again — its collection's and its
    /// folder's, each from its own line — from the owner-signed members
    /// records held that the trust context does not refuse, after it
    /// refused one for `why` (spec §6, §8), and set anew the record in
    /// force of every collection they govern. A version delivered before
    /// that the new record refuses is reported withdrawn by the refusal
    /// that refused it, or by `why` (the record that admitted it no longer
    /// counts); with no record left, every version waits for one.
    fn rebuild_members(&self, st: &mut St, c: &Name, why: &Refusal) {
        if !wire::is_data_name(c) {
            return;
        }
        let keyring = self.validator.keyring();
        let mut records: Vec<(u64, u64, MembersBody, Writer)> = st
            .held
            .iter()
            .filter(|(n, _)| !st.cut_out.contains_key(*n))
            .filter_map(|(n, h)| {
                let Held::Record { writer, .. } = h else {
                    return None;
                };
                let l = parse_log_name(n)?;
                if l.subject.as_ref() != Some(c) || !owner_signed(keyring, n, c, writer) {
                    return None;
                }
                let data = Data::decode(self.store.get(n)?).ok()?;
                let key = data.sig_info()?.key_locator_name()?;
                match wire::decode_record(data.content()?.clone()).ok()? {
                    Record::Members(body) => {
                        Some((body.revision, l.seq, body, Writer::new((*key).clone())))
                    }
                    _ => None,
                }
            })
            .collect();
        records.sort_by(|a, b| (a.0, a.1, &a.3).cmp(&(b.0, b.1, &b.3)));
        // A folder's records govern every collection under it.
        let folder = st.folders.contains_key(c) || records.iter().any(|r| r.2.folder);
        let affected: Vec<Name> = st
            .colls
            .keys()
            .filter(|x| *x == c || (folder && x.has_prefix(c)))
            .cloned()
            .collect();
        let mut delivered: Vec<(Name, VersionId, Name)> = Vec::new();
        for x in &affected {
            let coll = &st.colls[x];
            let before = coll.at();
            delivered.extend(
                coll.versions
                    .values()
                    .chain(&coll.waiting)
                    .filter(|hv| {
                        before.contains(&hv.version.id)
                            && !st.refused.contains_key(&hv.version.name)
                    })
                    .map(|hv| (x.clone(), hv.version.id.clone(), hv.version.name.clone())),
            );
        }
        // What is in force now over every name the records govern: made
        // again, a watch is told only what changed (spec §15).
        let in_force: Vec<(Name, bool, Option<Members>)> = st
            .folders
            .iter()
            .filter(|(f, _)| f.has_prefix(c))
            .map(|(f, x)| (f.clone(), true, x.members.clone()))
            .chain(
                st.colls
                    .keys()
                    .filter(|x| *x == c || (folder && x.has_prefix(c)))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|x| {
                        (
                            x.clone(),
                            false,
                            st.colls.get(x).and_then(|y| y.members.clone()),
                        )
                    }),
            )
            .collect();
        st.quiet_members = true;
        // `c` is read again whatever record comes back.
        if let Some(coll) = st.colls.get_mut(c) {
            coll.line = Line::default();
            coll.members = None;
        }
        if let Some(f) = st.folders.get_mut(c) {
            f.line = Line::default();
        }
        for (_, seq, body, writer) in records {
            st.accept_members(seq, body, &writer);
        }
        // A line left with no record moved nothing when taking: set what is
        // in force anew either way.
        if folder {
            st.refold_under(c);
        }
        if st.colls.contains_key(c) {
            st.refold(c);
        }
        st.quiet_members = false;
        for (name, folder, before) in in_force {
            let (own, now) = match folder {
                true => (true, st.folders.get(&name).and_then(|x| x.members.clone())),
                false => {
                    let x = st.colls.get(&name);
                    let own = x.is_some_and(|x| x.line.own.is_some());
                    (own, x.and_then(|x| x.members.clone()))
                }
            };
            St::tell_members(&mut st.watchers, &name, own, before.as_ref(), now.as_ref());
        }
        if let Some(coll) = st.colls.get_mut(c)
            && coll.members.is_none()
        {
            tracing::info!(collection = %c, "no members record of the collection stands: its versions wait for one");
            coll.state = None;
            coll.applied.clear();
            coll.pending.clear();
            let versions = std::mem::take(&mut coll.versions);
            coll.waiting.extend(versions.into_values());
        }
        for (x, id, name) in delivered {
            let told = matches!(
                st.refused.get(&name),
                Some(Refusal::OutsideCut(_) | Refusal::Untrusted { .. })
            );
            let admitted = st
                .colls
                .get(&x)
                .is_some_and(|coll| coll.versions.contains_key(&id));
            if !told && !admitted {
                tracing::info!(?id, collection = %x, "withdrawn: the members record that admitted it is refused");
                st.tell(
                    &x,
                    &Change::Withdrawn {
                        collection: x.clone(),
                        id,
                        why: why.clone(),
                    },
                );
            }
        }
    }

    /// What a newly adopted trust context `ctx` lets in (spec §8): every
    /// entry refused here by a revocation that the contexts held no longer
    /// refuse (the revocation lifted, or its exact bytes re-admitted); and
    /// every entry a cut of `ctx` re-admits exactly that this device holds
    /// refused with other bytes (dropped for the re-admitted ones), or does
    /// not hold though it follows its collection. What was held of each is
    /// forgotten, so each is taken anew ([`Self::readmit`]).
    fn readmissions(&self, st: &mut St, ctx: &SignedTrustContext) -> Vec<Readmit> {
        let keyring = self.validator.keyring();
        let released: Vec<(Name, Bytes)> = st
            .cut_out
            .iter()
            .filter(|(_, o)| o.by_cut())
            .filter_map(|(name, o)| {
                let packet = o
                    .wire
                    .clone()
                    .or_else(|| held_wire(st, name))
                    .or_else(|| self.store.get(name))?;
                let governing = keyring.context_for(name);
                (wire::implicit_digest(&packet) == o.digest
                    && self.cut_verdict(&governing, name, &o.writer, &o.digest) == Some(false))
                .then(|| (name.clone(), packet))
            })
            .collect();
        let mut out = Vec::new();
        for (name, packet) in released {
            st.forget(&name);
            // Taken from its packet: not fetched as well.
            st.cut_fetching.insert(name.clone());
            out.push(Readmit {
                name,
                digest: None,
                wire: Some(packet),
            });
        }
        let keyring = self.validator.keyring();
        for cut in ctx.revocation_cuts() {
            if !ctx.is_revoked(cut.key()) {
                continue;
            }
            for full in cut.exact() {
                let Some((last, bare)) = full.components().split_last() else {
                    continue;
                };
                let Ok(digest) = <[u8; 32]>::try_from(last.value.as_ref()) else {
                    continue;
                };
                let name = Name::from_components(bare.iter().cloned());
                let Some(l) = parse_log_name(&name) else {
                    continue;
                };
                if last.typ != ndn_packet::tlv_type::IMPLICIT_SHA256
                    || keyring.context_for(&name).namespace() != ctx.namespace()
                    || st.cut_fetching.contains(&name)
                {
                    continue;
                }
                match st.cut_out.get(&name) {
                    Some(o) if o.digest != digest => {
                        tracing::info!(%name, "other bytes than the re-admitted ones were refused at this name: dropped for the re-admitted ones");
                        st.forget(&name);
                    }
                    Some(_) => continue,
                    None if st.held.contains_key(&name) || st.refused.contains_key(&name) => {
                        continue;
                    }
                    None if !l.subject.as_ref().is_some_and(|c| st.inside(c)) => continue,
                    None => {}
                }
                st.cut_fetching.insert(name.clone());
                out.push(Readmit {
                    name,
                    digest: Some(digest),
                    wire: None,
                });
            }
        }
        out
    }

    /// Take an entry a trust context lets in: from its packet, or fetched
    /// by its full name, verified anew, then applied and delivered like a
    /// newly arrived entry. One not to be had now (its holders may not
    /// have adopted the context yet) is asked for again, after a growing
    /// pause, up to [`READMIT_TRIES`] times, and at each refresh of a group
    /// meanwhile ([`Self::retry_readmissions`]).
    async fn readmit(self: &Arc<Self>, r: Readmit) {
        let data = match r.wire.and_then(|w| Data::decode(w).ok()) {
            Some(d) => Some(d),
            None => self.fetch_entry(&r.name, r.digest).await,
        };
        let mut retry = None;
        match data {
            None => {
                if let Some(digest) = r.digest {
                    let mut st = self.st.lock();
                    let tries = st.readmitting.entry(r.name.clone()).or_insert((digest, 0));
                    tries.0 = digest;
                    tries.1 += 1;
                    if tries.1 <= READMIT_TRIES {
                        retry = Some(READMIT_PAUSE * 2u32.pow(tries.1 - 1));
                    }
                }
                tracing::debug!(name = %r.name, ?retry, "re-admitted, not to be had now");
            }
            Some(d) => {
                self.st.lock().readmitting.remove(&r.name);
                match self.take_data(&r.name, d).await {
                    Ok(()) => tracing::info!(name = %r.name, "re-admitted: taken"),
                    Err(why) => tracing::debug!(name = %r.name, "re-admitted, yet refused: {why}"),
                }
            }
        }
        self.st.lock().cut_fetching.remove(&r.name);
        if let Some(pause) = retry {
            let weak = Arc::downgrade(self);
            let name = r.name;
            rt::spawn(async move {
                rt::sleep(pause).await;
                if let Some(inner) = weak.upgrade() {
                    inner.readmit_again(&name).await;
                }
            });
        }
    }

    /// Ask again for the re-admitted entry `name` not to be had before,
    /// unless it is held now or being asked for.
    fn readmit_again<'a>(self: &'a Arc<Self>, name: &'a Name) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let digest = {
                let mut st = self.st.lock();
                if st.held.contains_key(name) {
                    st.readmitting.remove(name);
                    return;
                }
                let Some((digest, _)) = st.readmitting.get(name).copied() else {
                    return;
                };
                if !st.cut_fetching.insert(name.clone()) {
                    return;
                }
                digest
            };
            self.readmit(Readmit {
                name: name.clone(),
                digest: Some(digest),
                wire: None,
            })
            .await;
        })
    }

    /// Ask again, in the background, for every re-admitted entry not to be
    /// had before (a group refreshed: its holders may have it now).
    fn retry_readmissions(self: &Arc<Self>) {
        let names: Vec<Name> = self.st.lock().readmitting.keys().cloned().collect();
        for name in names {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.readmit_again(&name).await;
            });
        }
    }

    /// Fetch the log entry `name` — exactly the packet whose implicit
    /// digest is `digest`, if given — by its name, else as
    /// [`Self::fetch_entry_held`] does (spec §13.5).
    async fn fetch_entry(&self, name: &Name, digest: Option<[u8; 32]>) -> Option<Data> {
        let exact = digest.map_or_else(|| name.clone(), |d| name.clone().append_implicit_digest(d));
        if let Some(d) = self.fetch_owed(exact, false).await {
            return Some(d);
        }
        self.fetch_entry_held(name, digest).await
    }

    /// [`Self::fetch_entry`] for an entry a summary being walked lists, as
    /// round `round` of its asks ([`in_rounds`], spec §17.1): of its
    /// writer's device in the first round, and in each later one of the
    /// writer and, at the same time, of the devices answering for it
    /// ([`Self::fetch_entry_held`]). A writer that answers late is still
    /// asked while they are, and devices that do not answer cost no time
    /// beside it.
    async fn fetch_listed(
        &self,
        name: &Name,
        digest: Option<[u8; 32]>,
        round: u32,
    ) -> Option<Data> {
        let exact = digest.map_or_else(|| name.clone(), |d| name.clone().append_implicit_digest(d));
        let own = self.fetch_owed(exact, false);
        if round == 0 {
            return own.await;
        }
        first_some(own, self.fetch_entry_held(name, digest)).await
    }

    /// The log entry `name` — exactly the packet whose implicit digest is
    /// `digest`, if given — from the devices answering for its writer
    /// ([`Self::relays`]) at once (spec §13.5); each answer checked as it
    /// is chosen ([`Self::answers_for`]).
    async fn fetch_entry_held(&self, name: &Name, digest: Option<[u8; 32]>) -> Option<Data> {
        let log = parse_log_name(name)?;
        let ns = namespace_of(log.subject.as_ref()?)?;
        self.ask_relays(name, &ns, &log.device, digest).await
    }

    /// `name`, `writer`'s packet of namespace `ns` — exactly the packet
    /// whose implicit digest is `digest`, if given — from the first of its
    /// relays ([`Self::relays`]) that answers with it.
    async fn ask_relays(
        &self,
        name: &Name,
        ns: &Name,
        writer: &Name,
        digest: Option<[u8; 32]>,
    ) -> Option<Data> {
        let relays = self.relays(&self.st.lock(), ns, writer, &[]);
        self.first_held(name, &relays, digest).await
    }

    /// `name` — exactly the packet whose implicit digest is `digest`, if
    /// given — from the first of `devices` that answers with it under its
    /// own name ([`Self::fetch_held`]) and checks ([`Self::answers_for`]).
    /// All are asked at once: a device that is away costs one Interest
    /// lifetime, not one each. An answer that does not check is passed
    /// over and the next one read: a device answering first with a
    /// forgery cancels no other's answer.
    async fn first_held(
        &self,
        name: &Name,
        devices: &[Name],
        digest: Option<[u8; 32]>,
    ) -> Option<Data> {
        self.first_held_from(name, devices, digest)
            .await
            .map(|(data, _)| data)
    }

    /// [`Self::first_held`], with the device that answered.
    async fn first_held_from(
        &self,
        name: &Name,
        devices: &[Name],
        digest: Option<[u8; 32]>,
    ) -> Option<(Data, Name)> {
        let mut asks: stream::FuturesUnordered<_> = devices
            .iter()
            .map(|d| async move { (self.fetch_held(name, d).await, d) })
            .collect();
        while let Some((got, d)) = asks.next().await {
            if let Some(data) = got
                && self.answers_for(name, &data, digest).await
            {
                return Some((data, d.clone()));
            }
        }
        None
    }

    /// Whether `data`, a device's answer for `name` under its own name, is
    /// the packet asked for (spec §13.5): the one whose implicit digest is
    /// `digest`, if given; else, `name` being a log entry, one its writer
    /// signed — a signer of the name's device that verifies, or whose
    /// key's revocation cut refuses it, decided against the name all the
    /// same ([`Self::verify`]). Anything else is a forgery, passed over.
    async fn answers_for(&self, name: &Name, data: &Data, digest: Option<[u8; 32]>) -> bool {
        if let Some(x) = digest {
            return wire::implicit_digest(data.raw()) == x;
        }
        let Some(log) = parse_log_name(name) else {
            return false;
        };
        let signer = data.sig_info().and_then(|s| s.key_locator_name());
        if signer.is_none_or(|k| device_of(&k).as_ref() != Some(&log.device)) {
            return false;
        }
        // Boxed: a validation's future is large, and this one sits inside
        // every walk's asks for entries.
        match Box::pin(self.verify(data)).await {
            Ok(_) | Err(Refusal::OutsideCut(_) | Refusal::Lapsed { .. }) => true,
            Err(_) => {
                tracing::debug!(%name, "refused: a device answering for the writer gave a packet its writer did not sign; the next answer is read");
                false
            }
        }
    }

    /// `device`'s newest summary root of `ns`, `root` its prefix (spec
    /// §13.5, §17.1), checked ([`Self::check_root`]), and whether a device
    /// answering for it gave it: asked of the writer; while the writer does
    /// not answer, of the writer again and at once of the devices answering
    /// for it ([`Self::ask_relays_root`]) — the writer's root taken over
    /// theirs, which may be behind it — after the pause, up to
    /// [`FETCH_TRIES`] rounds in all. One lost packet then costs neither
    /// the writer's newest root (a holder behind it walked instead, its
    /// writes since left to a later walk) nor a pass of the refresh loop; a
    /// writer away costs the lifetime it did before its relays answer. A
    /// root that does not check — a forgery on the way — counts as none in
    /// its round. A relay's root must be above `above`, if given (a walk
    /// begun beside walks of roots up to that head, [`Self::refresh_pass`],
    /// or answering a notice): one that is not, the writer is asked again
    /// in the next round. The writer's own root must be above `floor`, if
    /// given (a walk answering a notice, the highest head verified before
    /// it): one that is not may be an old copy the network delayed, so the
    /// writer is asked again in the next round, and it is taken only once
    /// every round brought nothing newer — the notice may have announced no
    /// new root (a device announcing itself as it joins).
    async fn fetch_root(
        &self,
        root: Name,
        ns: &Name,
        device: &Name,
        above: Option<u64>,
        floor: Option<u64>,
    ) -> Option<(Rooted, bool)> {
        let newer = |r: &Rooted| floor.is_none_or(|f| r.body.head > f);
        let mut old = None;
        if let Some(r) = self.own_root(root.clone(), ns, device).await {
            if newer(&r) {
                return Some((r, false));
            }
            old = Some(r);
        }
        for tries in 1..FETCH_TRIES {
            if tries > 1 {
                rt::sleep(retry_pause(tries - 2)).await;
            }
            // The writer's own root, newer, is taken as it comes: a relay
            // that is silent costs it no lifetime. A relay's root is taken
            // only once the writer's own asks of the round came to nothing
            // newer (the writer's taken over theirs, which may be behind).
            let own = std::pin::pin!(self.own_root(root.clone(), ns, device));
            let relayed = std::pin::pin!(self.ask_relays_root(ns, device, above));
            let (own, relayed) = match futures::future::select(own, relayed).await {
                futures::future::Either::Left((own, relayed)) => {
                    if own.as_ref().is_some_and(&newer) {
                        return own.map(|r| (r, false));
                    }
                    (own, relayed.await)
                }
                futures::future::Either::Right((relayed, own)) => (own.await, relayed),
            };
            if let Some(r) = own {
                if newer(&r) {
                    return Some((r, false));
                }
                old = Some(r);
            }
            if let Some(r) = relayed {
                return Some((r, true));
            }
        }
        old.map(|r| (r, false))
    }

    /// `device`'s root of `ns` as the writer answers its prefix `root`,
    /// checked ([`Self::check_root`]); `None` when nothing answered or the
    /// answer does not check.
    async fn own_root(&self, root: Name, ns: &Name, device: &Name) -> Option<Rooted> {
        let data = self.fetch(root, true).await?;
        match self.check_root(device, ns, data).await {
            Ok(r) => Some(r),
            Err(why) => {
                tracing::debug!(%device, %ns, ?why, "refused: a summary root answered for the writer; asked again in the next round");
                None
            }
        }
    }

    /// `device`'s newest summary root of `ns` that a device answering for
    /// it holds ([`Self::held_packet`], spec §13.5), when the writer does
    /// not answer: of the replies of its relays, asked at once, those whose
    /// head is at least the highest verified here — an older one is a
    /// holder that is behind, not the writer rolling back — and above
    /// `above`, if given, are checked from the highest head down
    /// ([`Self::check_root`]: the writer's signature, the name), and the
    /// first that checks is taken. A reply that does not check is passed
    /// over, never taken in place of the others: a relay that forges a
    /// higher head cancels no other relay's root.
    async fn ask_relays_root(
        &self,
        ns: &Name,
        device: &Name,
        above: Option<u64>,
    ) -> Option<Rooted> {
        let prefix = root_prefix(device, ns);
        let (relays, seen) = {
            let st = self.st.lock();
            let seen = st
                .peers
                .get(&(device.clone(), ns.clone()))
                .map_or(0, |p| p.head);
            (self.relays(&st, ns, device, &[]), seen)
        };
        // Asked fresh: a cache must not answer with an older root.
        let replies = futures::future::join_all(
            relays
                .iter()
                .map(|r| self.fetch(wire::held_name(r, &prefix), true)),
        )
        .await;
        let mut roots: Vec<(u64, Data)> = replies
            .into_iter()
            .flatten()
            .filter_map(|reply| {
                let root = Data::decode(reply.content()?.clone()).ok()?;
                let head = parse_summary_name(&root.name)
                    .filter(|_| root.name.has_prefix(&prefix))
                    .and_then(|s| s.head)?;
                (head >= seen && above.is_none_or(|a| head > a)).then_some((head, root))
            })
            .collect();
        roots.sort_by_key(|r| std::cmp::Reverse(r.0));
        // The same root from two relays is checked once.
        roots.dedup_by(|a, b| a.1.raw() == b.1.raw());
        for (head, root) in roots {
            match self.check_root(device, ns, root).await {
                Ok(r) => return Some(r),
                Err(why) => {
                    tracing::debug!(%device, %ns, head, ?why, "refused: a summary root a device answering for the writer gave; the next one is checked");
                }
            }
        }
        None
    }

    /// Fetch, in the background, every entry of a collection this device
    /// follows that a held revocation cut accepts and that it neither holds
    /// nor refused (spec §8): the revoked key's summaries are refused, so
    /// its cut is the listing of what stays. The entries become known as
    /// the key's, so later ones wait for them in order. An entry of a cut
    /// bound to a manifest is fetched by its full name, exactly the bytes
    /// the manifest lists ([`Self::cut_digest`]): other bytes a thief signed
    /// at that name are never asked for. What was not to be had is asked for
    /// again as re-admitted entries are ([`St::cut_misses`]).
    fn fetch_cut_runs(self: &Arc<Self>) {
        let names: Vec<(Name, Writer, Option<[u8; 32]>)> = {
            let keyring = self.validator.keyring();
            let mut st = self.st.lock();
            let mut out = Vec::new();
            'all: for ctx in keyring.contexts() {
                for cut in ctx.revocation_cuts() {
                    let Some(device) = device_of(cut.key()) else {
                        continue;
                    };
                    if !ctx.is_revoked(cut.key()) {
                        continue;
                    }
                    let writer = Writer::new(cut.key().clone());
                    for range in cut.ranges() {
                        let Some(c) = parse_log_name(&range.prefix.clone().append_sequence_num(0))
                            .filter(|l| l.device == device)
                            .and_then(|l| l.subject)
                        else {
                            continue;
                        };
                        if !st.inside(&c)
                            || keyring.context_for(&range.prefix).namespace() != ctx.namespace()
                        {
                            continue;
                        }
                        let St {
                            colls,
                            held,
                            refused,
                            cut_fetching,
                            ..
                        } = &mut *st;
                        let coll = colls.entry(c.clone()).or_default();
                        coll.revoked
                            .entry(writer.clone())
                            .or_insert_with(|| revocation_cut_for(&ctx, &writer, &range.prefix));
                        for &(first, last) in &range.runs {
                            for seq in first..=last {
                                if out.len() >= CUT_FETCHES {
                                    break 'all;
                                }
                                coll.entries.entry(writer.clone()).or_default().insert(seq);
                                let name = log_name(&device, Some(&c), seq);
                                if held.contains_key(&name)
                                    || refused.contains_key(&name)
                                    || cut_fetching.contains(&name)
                                {
                                    continue;
                                }
                                cut_fetching.insert(name.clone());
                                out.push((name, writer.clone(), None));
                            }
                        }
                    }
                    // What the cut re-admits exactly, in a collection
                    // followed now (perhaps only since the adoption), is
                    // fetched by its full name.
                    for full in cut.exact() {
                        if out.len() >= CUT_FETCHES {
                            break 'all;
                        }
                        let Some((last, bare)) = full.components().split_last() else {
                            continue;
                        };
                        let Ok(digest) = <[u8; 32]>::try_from(last.value.as_ref()) else {
                            continue;
                        };
                        let name = Name::from_components(bare.iter().cloned());
                        let in_followed = parse_log_name(&name)
                            .filter(|l| l.device == device)
                            .and_then(|l| l.subject)
                            .is_some_and(|c| st.inside(&c));
                        if last.typ != ndn_packet::tlv_type::IMPLICIT_SHA256
                            || !in_followed
                            || keyring.context_for(&name).namespace() != ctx.namespace()
                            || st.held.contains_key(&name)
                            || st.refused.contains_key(&name)
                            || !st.cut_fetching.insert(name.clone())
                        {
                            continue;
                        }
                        out.push((name, writer.clone(), Some(digest)));
                    }
                }
            }
            out
        };
        if names.is_empty() {
            return;
        }
        tracing::debug!(me = %self.device, entries = names.len(), "fetching what revocation cuts accept");
        let inner = Arc::clone(self);
        rt::spawn(async move {
            let inner = &inner;
            let missed = stream::iter(names)
                .map(|(name, writer, exact)| async move {
                    // Exactly the bytes re-admitted, or those the cut's
                    // manifest lists, by full name: other bytes at the
                    // name are not asked for.
                    let digest = match exact {
                        Some(d) => Some(Some(d)),
                        None => inner.cut_digest(&name, &writer).await,
                    };
                    let got = match digest {
                        Some(digest) => inner.fetch_entry(&name, digest).await,
                        None => None,
                    };
                    let missed = got.is_none();
                    if let Some(d) = got
                        && let Err(why) = inner.take_data(&name, d).await
                    {
                        tracing::debug!(%name, "an entry its revocation cut accepts is refused: {why}");
                    }
                    inner.st.lock().cut_fetching.remove(&name);
                    missed
                })
                .buffer_unordered(inner.config.window)
                .collect::<Vec<bool>>()
                .await
                .contains(&true);
            // What was not to be had now (its writer away, every reply
            // lost) is asked for again after a growing pause, up to
            // READMIT_TRIES asks in a row, and at every group refresh
            // meanwhile (spec §8, §17.1): nothing else would ask.
            let again = {
                let mut st = inner.st.lock();
                if missed {
                    st.cut_misses = st.cut_misses.saturating_add(1);
                    (st.cut_misses <= READMIT_TRIES)
                        .then(|| READMIT_PAUSE * 2u32.pow(st.cut_misses - 1))
                } else {
                    st.cut_misses = 0;
                    None
                }
            };
            inner.progress.notify_waiters();
            if let Some(pause) = again {
                tracing::debug!(me = %inner.device, ?pause, "some of what revocation cuts accept is not to be had now; asked again");
                let weak = Arc::downgrade(inner);
                rt::spawn(async move {
                    rt::sleep(pause).await;
                    if let Some(inner) = weak.upgrade() {
                        inner.fetch_cut_runs();
                    }
                });
            }
        });
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

    /// The seq of the next entry of the own log: one past its head. Refused
    /// once the head is the last seq a log can number.
    fn next_seq(&self, st: &St) -> Result<u64, DataError> {
        st.head.checked_add(1).ok_or_else(|| {
            local(format!(
                "{} has written the last seq its log can number ({}), so it writes nothing more \
                 under this name; enroll the device again under a new name",
                self.device, st.head
            ))
        })
    }

    /// Record that this device signed `wire`, its log entry `name`, now:
    /// a restart takes it as its own ([`written_name`]), and it was first
    /// verified now, by the device's own public key ([`verified_name`]).
    fn note_written(&self, st: &mut St, name: &Name, wire: &Bytes) {
        self.store.insert(
            written_name(name),
            Bytes::copy_from_slice(&wire::implicit_digest(wire)),
        );
        let at = (self.config.clock)();
        self.store.insert(
            verified_name(name),
            encode_verified(at, self.own_key.as_ref()),
        );
        st.verified.insert(
            name.clone(),
            Verified {
                at: Some(at),
                key: self.own_key,
                own: true,
            },
        );
        // A key's log is one sequence (spec §4): what a copy of this key
        // signs at a seq this device used is equivocation here too.
        if let Some(l) = parse_log_name(name) {
            st.seqs
                .entry((self.writer.clone(), l.seq))
                .or_insert_with(|| name.clone());
        }
        // Published once durable: the next commit round, which reads the
        // log head under the lock held here, so after the entry is stored.
        self.commit_wake.notify_one();
    }

    /// Note that this device verified the log entry `name` of another
    /// writer now, by the public key whose digest is `key` — unless it was
    /// verified before: the first time is what a cut is bounded by.
    fn note_verified(&self, st: &mut St, name: &Name, key: Option<[u8; 32]>) {
        if st.verified.contains_key(name) {
            return;
        }
        let at = (self.config.clock)();
        self.store
            .insert(verified_name(name), encode_verified(at, key.as_ref()));
        st.verified.insert(
            name.clone(),
            Verified {
                at: Some(at),
                key,
                own: false,
            },
        );
    }

    /// Append an entry about `subject` to the own log: sign, store, take.
    fn append(
        &self,
        st: &mut St,
        subject: Option<&Name>,
        content: Bytes,
    ) -> Result<(Name, u64), DataError> {
        let seq = self.next_seq(st)?;
        let entry = self.sign_entry(subject, seq, content)?;
        Ok(self.keep_entry(st, entry))
    }

    /// Sign `content`, an entry about `subject`, as the own log's entry at
    /// `seq`. Nothing is kept: [`Self::keep_entry`] keeps it, or it is
    /// dropped.
    fn sign_entry(
        &self,
        subject: Option<&Name>,
        seq: u64,
        content: Bytes,
    ) -> Result<LogEntry, DataError> {
        let record = wire::decode_record(content.clone()).map_err(|e| local(e.to_string()))?;
        let name = log_name(&self.device, subject, seq);
        let wire = self.sign(DataBuilder::new(name.clone(), &content))?;
        Ok(LogEntry {
            name,
            seq,
            wire,
            record,
        })
    }

    /// Keep `entry`, an own entry signed: the log's head, stored, taken.
    fn keep_entry(&self, st: &mut St, entry: LogEntry) -> (Name, u64) {
        let _batch = self.stage.batch();
        let LogEntry {
            name,
            seq,
            wire,
            record,
        } = entry;
        st.head = seq;
        self.note_written(st, &name, &wire);
        self.take(st, name.clone(), wire, self.writer.clone(), record, true);
        (name, seq)
    }

    /// Sign `record` (a members record of `c` [`Self::next_members`] or
    /// [`Self::default_members`] made) into the own log; keep the key of the
    /// epoch it starts, if it starts one.
    fn append_members(
        &self,
        st: &mut St,
        c: &Name,
        record: (MembersBody, Option<ContentKey>),
    ) -> Result<(), DataError> {
        let seq = self.next_seq(st)?;
        let signed = self.sign_members(st, c, seq, record)?;
        self.keep_members(st, c, signed);
        Ok(())
    }

    /// Sign `record`, a members record of `c`, as the own log's entry at
    /// `seq`, with the key of the epoch it starts, its cuts bound to the
    /// bytes they keep ([`Self::bind_cuts`]); nothing is kept.
    fn sign_members(
        &self,
        st: &St,
        c: &Name,
        seq: u64,
        (mut body, key): (MembersBody, Option<ContentKey>),
    ) -> Result<SignedMembers, DataError> {
        let name = log_name(&self.device, Some(c), seq);
        let manifest = self.bind_cuts(st, &name, &mut body)?;
        let entry = self.sign_entry(Some(c), seq, wire::encode_members(&body))?;
        Ok((entry, body.epoch.zip(key), manifest))
    }

    /// Bind every version the cuts of `body` keep to its bytes (spec §8):
    /// the manifest of the record named `record` lists the implicit digest
    /// of each — the one a manifest binding it lists already (a cut carried
    /// over, or merged), else that of its packet held verified here — and
    /// every cut keeping versions names it (`CutBytes`). A kept version
    /// this device knows no bytes of is left out, as one only a summary
    /// listed is (§6): it holds no verified copy. Returns the manifest's
    /// packets, root first; none when nothing is kept. [`DataError::NotReady`]
    /// while a manifest packet of a cut carried over is not held here.
    fn bind_cuts(
        &self,
        st: &St,
        record: &Name,
        body: &mut MembersBody,
    ) -> Result<Vec<Bytes>, DataError> {
        let mut entries: Vec<(Name, u64, [u8; 32])> = Vec::new();
        let mut rebuilt: Vec<Accepted> = Vec::with_capacity(body.cuts.len());
        for cut in &body.cuts {
            let mut kept = Accepted::new();
            for (c, w, runs) in cut.accept.iter() {
                // A collection's record keeps its own versions only.
                if !body.folder && *c != body.collection {
                    continue;
                }
                let Some(device) = device_of(w.key()) else {
                    continue;
                };
                let roots: Vec<&Name> = cut.accept.manifests(c, w).collect();
                for &(lo, hi) in runs {
                    if entries.len() as u64 + (hi - lo) >= CUT_KEPT_MAX as u64 {
                        return Err(DataError::BadRequest {
                            name: body.collection.clone(),
                            why: format!(
                                "its cuts would keep more than {CUT_KEPT_MAX} versions, more \
                                 than one record binds to their bytes; write the removed \
                                 writers back in, or share the collections apart"
                            ),
                        });
                    }
                    for seq in lo..=hi {
                        let name = log_name(&device, Some(c), seq);
                        let digest = match roots.is_empty() {
                            true => held_digest(st, &name, w),
                            false => {
                                let mut listed: Option<[u8; 32]> = None;
                                let mut agree = true;
                                for root in &roots {
                                    match listed_bytes(&st.cut_bytes, &*st.store, root, &name) {
                                        ManifestLookup::Listed(d) => {
                                            agree &= listed.is_none_or(|l| l == d);
                                            listed = Some(d);
                                        }
                                        ManifestLookup::NotListed => agree = false,
                                        ManifestLookup::Missing(full) => {
                                            return Err(DataError::NotReady {
                                                name: body.collection.clone(),
                                                why: format!(
                                                    "the manifest of a removal cut it carries \
                                                     over is not held here yet ({full}); share \
                                                     again once its signer, or a device that \
                                                     took it, is reachable"
                                                ),
                                            });
                                        }
                                    }
                                }
                                listed.filter(|_| agree)
                            }
                        };
                        match digest {
                            Some(d) => {
                                kept.insert_range(c, w, seq, seq);
                                entries.push((log_prefix(&name), seq, d));
                            }
                            None => {
                                tracing::debug!(%name, "left out of the cut: no bytes of it known here");
                            }
                        }
                    }
                }
            }
            rebuilt.push(kept);
        }
        let packets = match entries.is_empty() {
            true => Vec::new(),
            false => {
                let built = cut_manifest::build_under(&cut_bytes_prefix(record), &entries)
                    .map_err(|e| {
                        local(format!("the manifest of {record}'s cuts is not made: {e}"))
                    })?;
                for kept in &mut rebuilt {
                    if !kept.is_empty() {
                        kept.bind(&built.root);
                    }
                }
                built.packets
            }
        };
        for (cut, kept) in body.cuts.iter_mut().zip(rebuilt) {
            cut.accept = kept;
        }
        Ok(packets)
    }

    /// Keep a members record of `c` [`Self::sign_members`] signed, the key
    /// of the epoch it starts, and its cuts' manifest: stored, so this
    /// device serves it, and held, so it judges by it. The key is stored
    /// first ([`Self::store_made_key`]) and held once the record is taken.
    fn keep_members(&self, st: &mut St, c: &Name, (entry, made, manifest): SignedMembers) {
        let _batch = self.stage.batch();
        if let Some((e, key)) = &made {
            self.store_made_key(st, c, e, key);
        }
        for wire in manifest {
            if let Ok(data) = Data::decode(wire.clone()) {
                st.store.insert((*data.name).clone(), wire);
                let _ = st.cut_bytes.insert(&data);
            }
        }
        self.keep_entry(st, entry);
        if let Some((e, key)) = made {
            st.keys.hold(c.clone(), e, key);
        }
    }

    /// Whether this device may write into `c` now, sealed in `epoch`: its
    /// key is a writer by the record in force, and that record's epoch is
    /// `epoch` (else it moved while the key was asked for: ask again), one
    /// that has not outgrown its audience ([`outgrown`]: a reader the
    /// record in force no longer admits may hold its key, so nothing is
    /// sealed in it until a device of the audience moves `c` to a new
    /// epoch; ask again then, spec §6.1) and has not undergrown it
    /// ([`undergrown`]: the record in force lists a reader no record naming
    /// the epoch lists, so nothing is sealed in it until the merge is
    /// resolved; ask again then, spec §6).
    fn writable(&self, st: &St, c: &Name, epoch: Option<&Epoch>) -> Result<(), DataError> {
        let Some(members) = st.colls.get(c).and_then(|x| x.members.as_ref()) else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        if !members
            .writers
            .iter()
            .any(|p| self.writer.key().has_prefix(p))
        {
            return Err(self.admitted_by_offer(
                st,
                c,
                DataError::NotAllowed {
                    collection: c.clone(),
                    writer: self.writer.clone(),
                },
            ));
        }
        if epoch != members.epoch.as_ref() {
            return Err(DataError::Unavailable { name: c.clone() });
        }
        if let Some(e) = epoch
            && st
                .line_of(&st.seal_subject(c, e))
                .is_some_and(|(epochs, _)| outgrown(members, epochs))
        {
            return Err(DataError::NotReady {
                name: c.clone(),
                why: format!(
                    "its epoch {e:?} outgrew its audience — a reader the record in force no \
                     longer admits may hold its key — so nothing is sealed in it; put again once \
                     a device of the owner's namespace that reads it has moved it to a new epoch"
                ),
            });
        }
        if let Some(e) = epoch
            && st
                .line_of(&st.seal_subject(c, e))
                .is_some_and(|(epochs, _)| undergrown(members, epochs))
        {
            return Err(DataError::NotReady {
                name: c.clone(),
                why: format!(
                    "the record in force lists a reader that no record naming its epoch {e:?} \
                     lists — a merge not resolved yet — so a version sealed in it would stay \
                     closed to that reader; put again once a device of the owner's namespace \
                     that reads it has signed the record resolving the merge; the epoch was \
                     created by {creator}, so bring that device online (or another device of \
                     the owner's namespace that reads the collection), and puts wait until one \
                     has",
                    creator = e.creator
                ),
            });
        }
        Ok(())
    }

    /// Sign `draft` into `c` as a new own version (the record in force
    /// checked by [`Self::writable`]), sealed with `key`, and hold it; a
    /// log entry larger than [`wire::INLINE_MAX`] travels in pieces. A merge
    /// collection's entry is the bytes the app built, applied by the rule to
    /// the state before anything is kept: more than [`wire::INLINE_MAX`] is
    /// [`DataError::TooLarge`], fields are [`DataError::BadRequest`], with
    /// nothing stored, published or counted in the log's head.
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        st: &mut St,
        c: &Name,
        ns: &Name,
        key: Option<&(Epoch, ContentKey)>,
        type_id: TypeId,
        keep: Keep,
        draft: Draft,
    ) -> Result<VersionId, DataError> {
        // Refused before anything touches the state.
        let seq = self.next_seq(st)?;
        let signed = self.sign_in(st, c, seq, key, type_id, keep, draft)?;
        self.apply_own_version(st, &signed)?;
        Ok(self.commit(st, ns, signed))
    }

    /// [`Self::not_walked`] for a verb that must not wait on other devices:
    /// each device it names is walked in the background
    /// ([`Self::walk_in_background`]), and what it names is answered now.
    fn not_walked_now(
        self: &Arc<Self>,
        ns: &Name,
        relevant: impl Fn(&Name) -> bool,
        covers: impl Fn(&Name) -> bool,
    ) -> Vec<Name> {
        let missing = self.not_walked(&self.st.lock(), ns, relevant, covers);
        self.walk_in_background(ns, missing.clone());
        missing
    }

    /// Refuse the host's default record of `c`, a collection of this
    /// namespace with no record in force here, while a device of the
    /// namespace known here has not been walked ([`Self::not_walked`]): a
    /// folder record above `c` that device may hold governs `c`, and a
    /// default record would narrow `c` for good (spec §6.1). Answered at
    /// once, the walks running in the background — a put never waits on
    /// other devices (spec §15).
    /// [`DataError::NotReady`]: put again once they are reached.
    fn default_allowed(self: &Arc<Self>, c: &Name) -> Result<(), DataError> {
        // A walk took the folder records above `c` only if it went toward
        // `c`'s folder: toward a name under it, or followed a folder above.
        let folder = folder_of(c);
        let missing = self.not_walked_now(
            &self.ns,
            |d| self.namespace_of_name(d) == self.ns,
            |t| t.has_prefix(&folder) || folder.has_prefix(t),
        );
        if missing.is_empty() {
            return Ok(());
        }
        let devices: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Err(DataError::NotReady {
            name: c.clone(),
            why: format!(
                "it has no members record here, and this device has not yet walked the summary \
                 of {}, which may hold a folder record governing it (the walk runs in the \
                 background); no default record is signed, since one would narrow the \
                 collection for good. Put again once that device is reached; if it is lost, mark \
                 its key suspected or revoke it (it is not waited for then)",
                devices.join(", ")
            ),
        })
    }

    /// Refuse a put into `c`, a collection of namespace `ns` with no record of
    /// its own here, that would inherit the record of a folder above it,
    /// while a device of `ns` known here has not been walked toward `c`'s
    /// folder ([`Self::not_walked`]): that device may hold a record of `c`
    /// of its own, which narrows the folder's audience or writers, and a
    /// version sealed or written under the folder's record meanwhile would
    /// reach readers the narrower record leaves out, for good (spec §6.1,
    /// §15). Answered at once, the walks running in the background — a put
    /// never waits on other devices. Once the folder was walked the list is
    /// empty and the put goes through without a look.
    /// [`DataError::NotReady`]: put again once they are reached.
    fn inherit_allowed(self: &Arc<Self>, c: &Name, ns: &Name) -> Result<(), DataError> {
        {
            let st = self.st.lock();
            let own = st.colls.get(c).is_some_and(|x| x.line.own.is_some());
            if own || st.folders_above(c).is_empty() {
                return Ok(());
            }
        }
        let missing = self.not_walked_toward(&self.st.lock(), ns, &folder_of(c));
        self.walk_in_background(ns, missing.clone());
        if missing.is_empty() {
            return Ok(());
        }
        let devices: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Err(DataError::NotReady {
            name: c.clone(),
            why: format!(
                "it has no members record of its own here, so it would inherit its folder's, \
                 and this device has not yet walked the summary of {}, which may hold a record \
                 of {c} that narrows who reads or writes it (the walk runs in the background); \
                 nothing is written under the folder's record meanwhile. Put again once that \
                 device is reached; if it is lost, mark its key suspected or revoke it (it is \
                 not waited for then)",
                devices.join(", ")
            ),
        })
    }

    /// The devices of namespace `ns` known here that were not walked toward
    /// `folder`: a record of a collection under it that one of them holds
    /// has not been taken ([`Self::inherit_allowed`], and the readiness
    /// wait of a join, [`Self::admission_missing`]).
    fn not_walked_toward(&self, st: &St, ns: &Name, folder: &Name) -> Vec<Name> {
        self.not_walked(
            st,
            ns,
            |d| self.namespace_of_name(d) == *ns,
            |t| t.has_prefix(folder) || folder.has_prefix(t),
        )
    }

    /// Whether this device was **let go** of the folder over `c`, a data name of
    /// another person's namespace: the folder's record in force here (the longest
    /// folder at or above `c` this device holds one of) is sealed and lists this
    /// key neither as a writer nor in the audience, **and** a held record of that
    /// folder's line admits it — at some revision, as a writer or in the
    /// audience: it was a member, and a record signed since leaves it out. A
    /// walk of another writer's summary then does not descend into `c`'s node:
    /// this device reads nothing new there and writes nothing, and a link layer
    /// that let the person go no longer carries the node, so waiting for it would
    /// hold every other folder of the namespace not walked (spec §19.8).
    ///
    /// A device **not yet admitted** — a joiner that holds the folder's sealed
    /// record from before the offer admitted it — is never left out: no held
    /// record of the line admits it, and the revision that does has still to be
    /// fetched from that very node. The rule reads signed, durable data held
    /// here (the line's records), no flag and no clock, so it is the same after a
    /// restart. A folder of this device's own namespace is never left out.
    ///
    /// A device **invited again** is not left out either, while the new
    /// admission is pending ([`Inner::admission_pending`]): it holds the record
    /// that once admitted it and the one that left it out (in force), and the
    /// answer to its join names a revision above that one, signed since and held
    /// nowhere here yet. That revision is listed only in the node a walk would
    /// skip, so the join would never complete. The pending admission is the
    /// joined note the answer left, read against the record in force: signed
    /// data, no clock where the answer named a revision.
    fn left_out(&self, st: &St, c: &Name) -> bool {
        if namespace_of(c).is_none_or(|ns| ns == self.ns) {
            return false;
        }
        let folder = (1..=c.len()).rev().find_map(|n| {
            let at = Name::from_components(c.components()[..n].iter().cloned());
            st.folders.get(&at).filter(|f| f.members.is_some())
        });
        let admits = |m: &Members| {
            m.writers.iter().any(|p| self.writer.key().has_prefix(p))
                || self.admits_record(st, m, &self.device, &self.ns)
        };
        folder.is_some_and(|f| {
            f.members
                .as_ref()
                .is_some_and(|m| m.epoch.is_some() && !admits(m))
                && f.line
                    .records
                    .values()
                    .flat_map(|signers| signers.values())
                    .any(|held| admits(&held.record))
        }) && !self.admission_pending(st, c)
    }

    /// Whether the members record in force over `c` here admits this
    /// device's key to write into it: lists it as a writer and, when it
    /// seals, admits this device to its audience.
    fn admitted(&self, st: &St, c: &Name) -> bool {
        st.colls
            .get(c)
            .and_then(|x| x.members.as_ref())
            .is_some_and(|m| {
                m.writers.iter().any(|p| self.writer.key().has_prefix(p))
                    && (m.epoch.is_none() || self.admits_record(st, m, &self.device, &self.ns))
            })
    }

    /// Why `c`, a collection of another person's namespace `ns`, cannot be
    /// written here while no members record held admits this key — none is
    /// held, or the one in force does not list it as a writer or, sealed,
    /// does not admit this device to its audience; `None` once one admits
    /// it ([`Self::admitted`]). Only signed data refuses the key (spec
    /// §18.1): while a device of `ns` known here was not walked toward
    /// `c`'s folder, a record it holds — the one a share or an
    /// introduction admitting this key signed — could still arrive
    /// ([`DataError::NotReady`]: put again). Once every one was walked, the
    /// records held decide: with none, nothing admits this key there
    /// ([`DataError::NotAllowed`]); with one, `None`, and the record in
    /// force refuses the write ([`Self::writable`], [`Self::write_key`]).
    /// With no device of `ns` known at all, nothing can be asked
    /// ([`DataError::Unavailable`] when no record is held).
    fn unadmitted(self: &Arc<Self>, c: &Name, ns: &Name) -> Option<DataError> {
        let recorded = |st: &St| st.colls.get(c).is_some_and(|x| x.members.is_some());
        let owner = |d: &Name| self.namespace_of_name(d) == *ns;
        {
            let st = self.st.lock();
            if self.admitted(&st, c) {
                return None;
            }
            let heard = self.known_for(&st, ns).iter().any(owner)
                || st
                    .peers
                    .iter()
                    .any(|((d, n), p)| n == ns && p.kept > 0 && owner(d));
            if !heard {
                return (!recorded(&st)).then(|| DataError::Unavailable { name: c.clone() });
            }
        }
        let folder = folder_of(c);
        let missing =
            self.not_walked_now(ns, owner, |t| t.has_prefix(&folder) || folder.has_prefix(t));
        let st = self.st.lock();
        if self.admitted(&st, c) || (missing.is_empty() && recorded(&st)) {
            return None;
        }
        if missing.is_empty() {
            return Some(self.admitted_by_offer(
                &st,
                c,
                DataError::NotAllowed {
                    collection: c.clone(),
                    writer: self.writer.clone(),
                },
            ));
        }
        let held = match recorded(&st) {
            true => "the members record in force here does not admit this key",
            false => "it has no members record here yet",
        };
        let devices: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Some(DataError::NotReady {
            name: c.clone(),
            why: format!(
                "{held}, and this device has not yet walked the summary of {}, which may hold \
                 the record admitting this key (the walk runs in the background); put again \
                 once that device is reached",
                devices.join(", ")
            ),
        })
    }

    /// Why this device may not read `name` of sealed collection `c` while
    /// no members record held admits it to `c`'s audience — none is held,
    /// or the one in force seals without admitting it; `None` once one
    /// admits it ([`Self::reads`]). Only signed data refuses a reader (spec
    /// §15, §18.1), as [`Self::unadmitted`] a writer: while a device of
    /// `c`'s namespace heard here was not walked toward `c`'s folder, the
    /// record admitting it — one a share or an introduction signed, lost
    /// on its way or not yet walked to — could still arrive
    /// ([`DataError::NotReady`]: get again). Once every one was walked, the
    /// records held decide ([`DataError::Sealed`]). With no device of the
    /// namespace known at all, nothing can be asked: `Sealed` under a
    /// record held, [`DataError::Unavailable`] with none.
    async fn unreadable(self: &Arc<Self>, name: &Name, c: &Name) -> Option<DataError> {
        let ns = namespace_of(c)?;
        let recorded = |st: &St| st.colls.get(c).is_some_and(|x| x.members.is_some());
        let owner = |d: &Name| self.namespace_of_name(d) == ns;
        {
            let st = self.st.lock();
            if self.reads(&st, c) {
                return None;
            }
            let heard = self.known_for(&st, &ns).iter().any(owner)
                || st
                    .peers
                    .iter()
                    .any(|((d, n), p)| *n == ns && p.kept > 0 && owner(d));
            if !heard {
                return Some(match recorded(&st) {
                    true => DataError::Sealed { name: name.clone() },
                    false => DataError::Unavailable { name: name.clone() },
                });
            }
        }
        let folder = folder_of(c);
        let missing = self
            .unsynced(&ns, owner, |t| {
                t.has_prefix(&folder) || folder.has_prefix(t)
            })
            .await;
        let st = self.st.lock();
        if self.reads(&st, c) {
            return None;
        }
        if missing.is_empty() {
            return Some(DataError::Sealed { name: name.clone() });
        }
        let held = match recorded(&st) {
            true => {
                "the version is sealed, and the members record in force here does not admit this \
                 device to its audience"
            }
            false => {
                "it holds sealed data of a collection whose members record it does not hold yet"
            }
        };
        let devices: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Some(DataError::NotReady {
            name: name.clone(),
            why: format!(
                "{held}, and this device has not yet walked the summary of {}, which may hold \
                 the record admitting it; get again once that device is reached",
                devices.join(", ")
            ),
        })
    }

    /// `a`, a `get`'s answer about `name` of collection `c`, with a refusal
    /// as sealed judged by signed data only ([`Self::unreadable`]):
    /// `NotReady` while a device of the namespace heard here was not walked
    /// toward `c`'s folder, then the records held. When a record admitting
    /// this device arrived meanwhile, `Unavailable`: get again, as a reader.
    async fn sealed_judged(
        self: &Arc<Self>,
        name: &Name,
        c: &Name,
        a: Result<Answer, DataError>,
    ) -> Result<Answer, DataError> {
        match a {
            Err(DataError::Sealed { .. }) => Err(self
                .unreadable(name, c)
                .await
                .unwrap_or_else(|| DataError::Unavailable { name: name.clone() })),
            a => a,
        }
    }

    /// Whether `device` is ended here: a key of it is suspected
    /// ([`Self::suspects_device`]), or the trust context governing it
    /// revokes one of its keys (spec §8.1).
    fn ended(&self, st: &St, device: &Name) -> bool {
        let ctx = self.validator.keyring().context_for(device);
        self.suspects_device(st, device)
            || ctx
                .revocations()
                .iter()
                .chain(ctx.revocation_cuts().iter().map(|c| c.key()))
                .any(|k| device_of(k).as_ref() == Some(device))
    }

    /// Whether `c` is still a fresh collection of this namespace: no record
    /// in force over it, and no version held that waits for one (written
    /// under a record this device does not hold). Otherwise
    /// [`DataError::NotReady`]: put again under the record.
    fn fresh(&self, st: &St, c: &Name) -> Result<(), DataError> {
        let why = match st.colls.get(c) {
            Some(x) if x.members.is_some() => {
                "a members record of it arrived meanwhile: put again, under that record"
            }
            Some(x)
                if !x.versions.is_empty()
                    || !x.waiting.is_empty()
                    || !x.locked.is_empty()
                    || !x.outsiders.is_empty() =>
            {
                "it holds versions that wait for a members record this device does not hold \
                 yet; no default record is signed over them: put again once that record arrives"
            }
            _ => return Ok(()),
        };
        Err(DataError::NotReady {
            name: c.clone(),
            why: why.into(),
        })
    }

    /// Sign `draft` as the own version at `seq` of `c`, a fresh collection,
    /// under `body`, the host's default record about to be signed for it
    /// ([`Self::default_members`]), sealed with the key `made` of the epoch
    /// it starts; and apply it on a state of its own that the register
    /// starts empty — the state the record starts. The version and that
    /// state; nothing is kept.
    fn sign_fresh(
        &self,
        c: &Name,
        seq: u64,
        body: &MembersBody,
        made: Option<&ContentKey>,
        draft: Draft,
        (type_id, keep): (TypeId, Keep),
    ) -> Result<(Signed, Box<dyn MergeState>), DataError> {
        // The host default is the register ([`Self::default_members`]).
        let function: Name = merge::NEWEST
            .parse()
            .expect("the register's name is an NDN name");
        let rule = merge::rule(&function).expect("the register is built in");
        let mut temp = rule.start();
        let key = body.epoch.clone().zip(made.cloned());
        let under = Under {
            readers: body.readers.clone(),
            function: Some(function),
            parents: Parents::new(),
        };
        let signed = self.sign_version(
            c,
            seq,
            under,
            Some(&*temp),
            key.as_ref(),
            (type_id, keep, (self.config.clock)()),
            draft,
        )?;
        let empty = Coll::default();
        let past = PastOf::new(&signed.held.version, empty.waits(c));
        apply_own(&mut *temp, &signed.held, &past, &NoOps);
        Ok((signed, temp))
    }

    /// After the record [`Self::sign_fresh`] signed a version under is
    /// kept: `c`'s state is `temp`, the state that record starts with the
    /// version judged on it applied (nothing else is held of `c`,
    /// [`Self::fresh`]).
    fn start_fresh(&self, st: &mut St, c: &Name, temp: Box<dyn MergeState>) {
        if let Some(coll) = st.colls.get_mut(c) {
            coll.state = Some(temp);
        }
    }

    /// Write `draft` as the first version of `c`, a fresh collection of
    /// this namespace ([`Self::fresh`]), after the host's default record
    /// ([`Self::default_members`]): the version is signed and judged first
    /// ([`Self::sign_fresh`]), then the record signed, and both kept only
    /// once both are. Refused, nothing is kept: no seq taken, no record
    /// (spec §5).
    fn put_fresh(
        &self,
        st: &mut St,
        c: &Name,
        ns: &Name,
        draft: Draft,
        options: (TypeId, Keep),
    ) -> Result<VersionId, DataError> {
        let _batch = self.stage.batch();
        self.fresh(st, c)?;
        let base = self.next_seq(st)?;
        let Some(seq) = base.checked_add(1) else {
            return Err(local(format!(
                "{} has too few seqs left in its log for a collection's record and its first \
                 version; enroll the device again under a new name",
                self.device
            )));
        };
        let (body, made) = self.default_members(c, base);
        let (signed, temp) = self.sign_fresh(c, seq, &body, made.as_ref(), draft, options)?;
        let record = self.sign_members(st, c, base, (body, made))?;
        self.keep_members(st, c, record);
        self.start_fresh(st, c, temp);
        Ok(self.commit(st, ns, signed))
    }

    /// Sign `draft` as the own version at `seq` of `c`, under its record in
    /// force and with its state ([`Self::sign_version`]); nothing is kept.
    #[allow(clippy::too_many_arguments)]
    fn sign_in(
        &self,
        st: &mut St,
        c: &Name,
        seq: u64,
        key: Option<&(Epoch, ContentKey)>,
        type_id: TypeId,
        keep: Keep,
        draft: Draft,
    ) -> Result<Signed, DataError> {
        let dated = (self.config.clock)();
        let coll = st.colls.get_mut(c).expect("members known");
        let members = coll.members.as_ref().expect("members known");
        let under = Under {
            readers: members.readers.clone(),
            function: match &members.rule {
                Rule::Merge { function } => Some(function.clone()),
                Rule::Log => None,
            },
            parents: coll.parents(),
        };
        self.sign_version(
            c,
            seq,
            under,
            coll.state.as_deref(),
            key,
            (type_id, keep, dated),
            draft,
        )
    }

    /// Sign `draft` as the own version at `seq` of `c`, written `under`
    /// a record, sealed with `key`: a merge collection's entry as the
    /// operation `state` makes of its fields (or the one the app built); a
    /// payload larger than [`wire::INLINE_MAX`] in pieces. Nothing is kept:
    /// the version is [`Self::commit`]ted once judged, or dropped.
    #[allow(clippy::too_many_arguments)]
    fn sign_version(
        &self,
        c: &Name,
        seq: u64,
        under: Under,
        state: Option<&(dyn MergeState + 'static)>,
        key: Option<&(Epoch, ContentKey)>,
        (type_id, keep, dated): (TypeId, Keep, Timestamp),
        draft: Draft,
    ) -> Result<Signed, DataError> {
        let (content, built) = match draft {
            Draft::Entry(content) => (content, None),
            Draft::Op(op) => (Content::new(), Some(op)),
        };
        let op = match &under.function {
            Some(function) => {
                if state.is_none() {
                    return Err(DataError::RuleUnknown {
                        collection: c.clone(),
                        rule: function.clone(),
                    });
                }
                match built {
                    Some(op) => op,
                    None => {
                        return Err(DataError::BadRequest {
                            name: c.clone(),
                            why: format!(
                                "{c} merges with {function}, which takes bytes, not fields: \
                                 use put_op"
                            ),
                        });
                    }
                }
            }
            None => Bytes::new(),
        };
        let name = log_name(&self.device, Some(c), seq);
        let payload = match key {
            Some((_, k)) => seal::seal_payload(k, &name, &content, &op),
            None => wire::encode_payload(&content, &op),
        };
        if payload.len() as u64 > wire::PAYLOAD_MAX {
            return Err(DataError::TooLarge {
                collection: c.clone(),
                size: payload.len() as u64,
                limit: wire::PAYLOAD_MAX,
            });
        }
        // A large entry travels in pieces, whatever the rule (spec §13.1);
        // the record carries its size and manifest root.
        let (chunks, pieces) = if payload.len() > wire::INLINE_MAX {
            let (pieces, chunks) = pieces::split(&name, &payload);
            (Some(chunks), pieces)
        } else {
            (None, Vec::new())
        };
        let sealed = key.map(|(epoch, _)| SealedBody {
            epoch: epoch.clone(),
            ciphertext: if chunks.is_some() {
                Bytes::new()
            } else {
                payload.clone()
            },
        });
        let (fields, record_op) = match chunks {
            Some(_) => (Content::new(), Bytes::new()),
            None => (content, op.clone()),
        };
        let body = VersionBody {
            collection: c.clone(),
            parents: under.parents,
            type_id,
            seal: Seal {
                any_of: under.readers,
            },
            keep,
            dated,
            rule: under.function.clone(),
            fields,
            op: record_op,
            sealed,
            chunks,
        };
        let wire = self.sign(DataBuilder::new(name.clone(), &wire::encode_version(&body)))?;
        let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
        let version = version_of(
            &name,
            &self.writer,
            seq,
            body,
            wire::implicit_digest(&wire),
            true,
        );
        let held = HeldVersion {
            opened: true,
            ..HeldVersion::new(version, op, wire, key.is_some(), epoch, chunks)
        };
        Ok(Signed {
            c: c.clone(),
            seq,
            held,
            pieces,
            function: under.function,
        })
    }

    /// Apply `signed`, an own version of a merge collection, to the
    /// collection's state over its past — here the state's frontier and this
    /// writer's earlier log, as every reader will judge it. Nothing under the
    /// log rule; [`DataError::RuleUnknown`] when this device runs no rule for
    /// the collection.
    fn apply_own_version(&self, st: &mut St, signed: &Signed) -> Result<(), DataError> {
        let Some(function) = &signed.function else {
            return Ok(());
        };
        let c = &signed.c;
        let St {
            colls, store, keys, ..
        } = st;
        let Coll {
            members,
            state,
            entries,
            skipped,
            locked,
            revoked,
            versions,
            wires,
            ..
        } = colls.get_mut(c).expect("members known");
        let Some(state) = state.as_deref_mut() else {
            return Err(DataError::RuleUnknown {
                collection: c.clone(),
                rule: function.clone(),
            });
        };
        // Its past, as every reader will see it (spec §5).
        let waits = Waits {
            collection: c,
            members: members.as_ref(),
            entries,
            skipped,
            locked,
            revoked,
            admitted: versions,
            wires,
        };
        let ops = OpsOf {
            versions,
            store: &**store,
            keys,
        };
        apply_own(
            state,
            &signed.held,
            &PastOf::new(&signed.held.version, waits),
            &ops,
        );
        Ok(())
    }

    /// Keep `signed`, an own version applied to its collection's state: its
    /// seq is the log's head, it and its pieces are stored, listed in the
    /// summary, applied, and delivered. Its id.
    fn commit(&self, st: &mut St, ns: &Name, signed: Signed) -> VersionId {
        let _batch = self.stage.batch();
        let Signed {
            c,
            seq,
            held,
            pieces,
            ..
        } = signed;
        let version = held.version.clone();
        let id = version.id.clone();
        let name = version.name.clone();
        st.head = st.head.max(seq);
        // Written together (one batch): the markers first, then the pieces,
        // the entry that makes the version visible last. On a store that
        // cannot apply a batch whole, a prefix of these writes is at worst a
        // marker or a piece of no entry, which a restart ignores, never an
        // entry a restart takes as another writer's (spec §4.2, Batching).
        self.note_written(st, &name, &held.wire);
        for p in pieces {
            self.store.insert(p.name, p.wire);
        }
        self.store.insert(name.clone(), held.wire.clone());
        st.held.insert(name, Held::Version(id.clone()));
        st.trees
            .entry(ns.clone())
            .or_insert_with(|| Tree::new(ns.clone()))
            .add(&c, seq, Kind::Version);
        let coll = st.colls.get_mut(&c).expect("members known");
        coll.entries
            .entry(id.writer.clone())
            .or_default()
            .insert(seq);
        coll.applied.insert(id.writer.clone(), seq);
        // An own operation in pieces is not kept in memory once applied.
        let held = match held.unloaded() {
            Some(unloaded) => unloaded,
            None => held,
        };
        coll.versions.insert(id.clone(), Arc::new(held));
        st.emit(&c, &Change::Version(version), &id.writer, seq);
        id
    }

    /// Keep `key`, which this device made as the key of epoch `e` of `c`,
    /// with what the store holds: wrapped to its own recipient key, under a
    /// local name ([`made_key_name`]). Stored before the members record that
    /// names the epoch ([`Self::keep_members`]), so that no prefix of what a
    /// put writes is a record whose key was never kept: a key stored without
    /// its record is no authority ([`St::take_key`] refuses it, there being
    /// no record to check it against) and costs one small entry.
    fn store_made_key(&self, st: &St, c: &Name, e: &Epoch, key: &ContentKey) {
        let name = made_key_name(&self.device, c, e);
        match wrap_ck_to(&st.keys.recipient.public(), key, &name.encode_to_tlv()) {
            Ok((ephemeral, wrapped)) => self
                .store
                .insert(name, wire::encode_grant(&ephemeral, &wrapped.to_bytes())),
            Err(why) => {
                tracing::warn!(collection = %c, epoch = ?e, "an epoch key made here is not kept for a restart: {why}");
            }
        }
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
    /// nobody shared: the register ([`merge::NEWEST`]), written and read by the
    /// owner's namespace, sealed in an epoch this record (the own log's entry
    /// `seq`) starts; with the epoch's key.
    fn default_members(&self, c: &Name, seq: u64) -> (MembersBody, Option<ContentKey>) {
        let (epoch, check, key) = self.new_epoch(c, seq);
        let body = MembersBody {
            collection: c.clone(),
            folder: false,
            revision: 1,
            rule: Rule::Merge {
                function: merge::NEWEST
                    .parse()
                    .expect("the register's name is an NDN name"),
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

    /// The next members record of subject `s` — a collection, or a folder
    /// (spec §6) — owned here, after `current`, its own record in force
    /// (spec §6, §8, §9), and the key of the epoch it starts, if it starts
    /// one. It starts from the record in force over `s` — `current`
    /// narrowed by the folders above, or theirs alone while `s` has no
    /// record of its own (spec §5, §6.1) — so a first own record under a
    /// folder carries on what the folder's governed: a writer prefix that
    /// record admits and this one does not gets a cut accepting exactly the
    /// versions of its keys this device holds verified that the record in
    /// force admits, each in its own collection — the collection, or every
    /// collection under the folder (a key's log is one sequence across its
    /// collections, so a seq accepted in one is accepted there only); a
    /// prefix written again, or that the folders above cover when the
    /// record lists no writers and so takes theirs, drops its cut; the cuts
    /// in force carry over. A reader removed from `current` — or
    /// `new_epoch` — starts a new epoch at this record, with a new random
    /// key, as does a first record listing readers (its epoch's key check
    /// is bound to `s`); no readers, no seal. A rule changed, or a seal on
    /// a subject that had none in force, sets `since` to what this device
    /// applied there; else the `since` in force carries over. The record
    /// names `current` as its parent, and is revision 1 without it.
    #[allow(clippy::too_many_arguments)]
    fn next_members(
        &self,
        st: &St,
        s: &Subject,
        current: Option<&Members>,
        rule: Rule,
        writers: Vec<Name>,
        readers: Vec<Audience>,
        new_epoch: bool,
    ) -> (MembersBody, Option<ContentKey>) {
        let c = &s.name;
        // The seq it is written at, if the log can number one
        // ([`Self::next_seq`] refuses it otherwise).
        let seq = st.head.saturating_add(1);
        // What it starts from: the record in force over `s`.
        let basis = collection::effective(c, current, &st.folders_above(c));
        let basis = basis.as_ref();
        // Where the versions it governs are held.
        let held_in: Vec<(&Name, &Coll)> = match s.folder {
            true => st
                .colls
                .iter()
                .filter(|(x, _)| x.has_prefix(c) && *x != c)
                .collect(),
            false => st.colls.get_key_value(c).into_iter().collect(),
        };
        // Listing no writers, it takes those of the folders above.
        let inherited = match writers.is_empty() {
            true => collection::effective(c, None, &st.folders_above(c))
                .map(|m| m.writers)
                .unwrap_or_default(),
            false => Vec::new(),
        };
        let covered = |of: &Name| writers.iter().chain(&inherited).any(|p| of.has_prefix(p));
        let mut cuts: Vec<CutBody> = current
            .or(basis)
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
        for p in &st.removing(c, current, &writers) {
            // Exactly the versions held verified — never what a summary
            // only listed — that the record in force admits.
            let mut accept = Accepted::new();
            for (x, coll) in &held_in {
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
                        && coll
                            .members
                            .as_ref()
                            .is_none_or(|m| m.refusal(&id).is_none())
                    {
                        accept.insert(x, &id);
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
        let since = match basis {
            Some(m) if restarts(m) => {
                let mut f = Frontier::default();
                for (_, coll) in &held_in {
                    for (w, s) in coll.at().iter() {
                        f.include(&VersionId {
                            writer: w.clone(),
                            seq: s,
                        });
                    }
                }
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
            folder: s.folder,
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
        // One look at the name's keyword picks the one ask it can be; the kind's parser
        // still judges it, and a name that is none of them, or not this device's, is a
        // packet it serves ([`Self::packet_for`]).
        match wire::served_kind(&name) {
            Some(wire::Served::Grant) => {
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
            }
            Some(wire::Served::Intro) => {
                if crate::intro::parse_intro_name(&name).is_some_and(|d| d == self.device) {
                    // Answering an ask verifies the asker, writes durably and has
                    // the host adopt the asker's anchor (spec §19.4): its own task.
                    let params = interest.app_parameters().cloned();
                    rt::spawn(async move {
                        let reply = self.answer_intro(&name, params).await;
                        self.reply(&name, responder, reply).await;
                    });
                    return;
                }
            }
            Some(wire::Served::Hint) => {
                if crate::intro::parse_hint_name(&name).is_some_and(|(d, _)| d == self.device) {
                    // The hint record of a short code (SHAPES-R10 §2), or its gone mark:
                    // made and signed on request, for a token this device holds; a
                    // token it does not is not answered.
                    let reply = self.hint_packet(&name);
                    self.reply(&name, responder, reply).await;
                    return;
                }
            }
            Some(wire::Served::Held) => {
                if let Some((holder, piece)) = parse_held_name(&name)
                    && holder == self.device
                {
                    let reply = self
                        .held_packet(&piece)
                        .map(|w| DataBuilder::new(name.clone(), &w).sign_digest_sha256());
                    self.reply(&name, responder, reply).await;
                    return;
                }
            }
            None => {}
        }
        let reply = self.packet_for(&name, interest.selectors().can_be_prefix);
        // An ask for this device's own newest root of any namespace: a
        // member walking it took what this device announced, in whichever
        // group it heard it ([`Self::herald`]).
        if reply.is_some()
            && parse_summary_name(&name)
                .is_some_and(|s| s.device == self.device && s.head.is_none())
        {
            self.st.lock().root_asks += 1;
        }
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

    /// What this device answers under its own name (`32=held`) for `name`,
    /// another device's packet (spec §13.5): every packet it serves by name,
    /// and, asked by its discovery prefix, the newest summary root of
    /// another device it verified — the writer's own signed packet.
    fn held_packet(&self, name: &Name) -> Option<Bytes> {
        if let Some(s) = parse_summary_name(name)
            && s.device != self.device
            && s.head.is_none()
            && subject_namespace(&s.subject).as_ref() == Some(&s.subject)
        {
            return self.store.get(&root_prefix(&s.device, &s.subject));
        }
        self.packet_for(name, false)
    }

    fn packet_for(&self, name: &Name, can_be_prefix: bool) -> Option<Bytes> {
        // A name ending in an implicit digest asks for exactly that packet
        // (a re-admission fetches so, spec §8): the packet of the name
        // before it, if its digest is that one.
        if let Some((last, bare)) = name.components().split_last()
            && last.typ == ndn_packet::tlv_type::IMPLICIT_SHA256
        {
            let bare = Name::from_components(bare.iter().cloned());
            return self
                .packet_for(&bare, false)
                .filter(|w| wire::implicit_digest(w).as_slice() == last.value.as_ref());
        }
        // A packet of a removal cut's manifest (spec §8): of an own record
        // once the record is durable; of another's, as taken here (it is
        // trusted by the digest naming it, whoever serves it).
        if let Some(record) = parse_cut_bytes_name(name) {
            if record.device == self.device && record.seq > self.st.lock().durable {
                return None;
            }
            return self.store.get(name);
        }
        // Own log entries and pieces of own versions; and of every other
        // device, each entry it holds verified — a version, held sealed or
        // opened, or a record — and the pieces of such a version it holds:
        // the very packets their writers signed, never re-signed (spec
        // §13.5). Readers ask it for another device's under its own name,
        // `32=held`, when the writer does not answer. Nothing refused or
        // withdrawn here (by its record, a cut, its chain, its group or its
        // rule).
        let log = parse_log_name(name).or_else(|| parse_piece_name(name).map(|p| p.log));
        if let Some(parsed) = log {
            let st = self.st.lock();
            let version = strip_piece(name);
            if parsed.device == self.device {
                // Published once durable (spec §4.2): above the durable
                // head, a power loss could take it after a peer saw it.
                if parsed.seq > st.durable {
                    return None;
                }
                return self.store.get(name);
            }
            let refused = st.refused.contains_key(&version) || st.cut_out.contains_key(&version);
            let verified = matches!(
                st.held.get(&version),
                Some(Held::Version(_) | Held::Locked | Held::Record { .. })
            );
            if refused || !verified {
                return None;
            }
            // An entry not stored yet — pending, held sealed — is
            // answered from where it is held.
            return self
                .store
                .get(name)
                .or_else(|| (version == *name).then(|| held_wire(&st, name)).flatten());
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
                let (head, root) = self.root(&mut st, &ns)?;
                return s.head.is_none_or(|h| h == head).then_some(root);
            }
            // A node or page lists the log up to its head, so one above the
            // durable head lists what is not durable yet.
            let head = s.head.filter(|h| *h <= st.durable)?;
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
        // A node or page of another device's summary, as this device kept
        // it from its newest descent (spec §13.5): checked by the asker
        // against the digest its parent lists. Another device's root only
        // under this device's own name ([`Self::held_packet`]): discovery
        // by name reaches the writer (§7).
        if let Some(s) = parse_summary_name(name)
            && s.head.is_some()
            && subject_namespace(&s.subject).is_some_and(|ns| ns != s.subject)
        {
            let w = self.store.get(&relayed_name(name))?;
            let kept = Data::decode(w.clone()).ok()?;
            return (*kept.name == *name).then_some(w);
        }
        // This device's seal key by its device name alone, as one asked for
        // by prefix: whoever seals an ask to this device (spec §19.4)
        // learns the key from the packet it signed, and verifies it so.
        if can_be_prefix && *name == wire::seal_key_prefix(&self.device) {
            return self.seal_key_packet(&mut self.st.lock());
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

    /// The signed root of the own summary of `ns` as the log up to its
    /// durable head fixes it (spec §4.2), signing a new one only when it
    /// changed since the last: its head and packet.
    fn root(&self, st: &mut St, ns: &Name) -> Option<(u64, Bytes)> {
        let durable = st.durable;
        let tree = st
            .trees
            .entry(ns.clone())
            .or_insert_with(|| Tree::new(ns.clone()));
        let (head, content) = tree.root_at(&self.device, self.writer.key(), durable);
        if let Some(r) = st.roots.get(ns)
            && r.content == content
        {
            return Some((head, r.wire.clone()));
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
        Some((head, wire))
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
        st.colls
            .get(c)
            .and_then(|x| x.members.as_ref())
            .is_some_and(|m| self.admits_record(st, m, device, dns))
    }

    /// Whether `device`, of namespace `dns`, is of the audience of record
    /// `m`: the readers it lists and the device that started its epoch.
    fn admits_record(&self, st: &St, m: &Members, device: &Name, dns: &Name) -> bool {
        let creator = m.epoch.as_ref().map(|e| &e.creator);
        self.admits(st, &m.readers, creator, device, dns)
    }

    /// Whether `device`, of namespace `dns`, may hold the key of epoch `e`
    /// of `c` (spec §9): a held owner-signed record of `c` — or of the
    /// folder whose epoch it is ([`St::seal_subject`]) — names `e`, the
    /// readers those records list (or `e`'s creator) admit it, and so does
    /// that subject's record in force when it seals. Records not held
    /// admit no one.
    fn may_hold(&self, st: &St, c: &Name, e: &Epoch, device: &Name, dns: &Name) -> bool {
        self.epoch_standing(st, c, e, device, dns) == EpochStanding::In
    }

    /// Whether `device`, of namespace `dns`, may hold the key of epoch `e` of `c`, as far as the
    /// records held here tell: a held owner-signed record of `c` — or of the folder whose
    /// epoch it is ([`St::seal_subject`]) — names `e`, the readers those records list (or `e`'s
    /// creator) admit it, and so does that subject's record in force when it seals. A record
    /// that is not held says nothing: [`EpochStanding::NotHeld`].
    fn epoch_standing(
        &self,
        st: &St,
        c: &Name,
        e: &Epoch,
        device: &Name,
        dns: &Name,
    ) -> EpochStanding {
        let Some((epochs, Some(record))) = st.line_of(&st.seal_subject(c, e)) else {
            return EpochStanding::NotHeld;
        };
        let Some(named) = epochs.get(e) else {
            return EpochStanding::NotHeld;
        };
        let admitted = self.admits(st, &named.readers, Some(&e.creator), device, dns)
            && (record.epoch.is_none() || self.admits_record(st, record, device, dns));
        match admitted {
            true => EpochStanding::In,
            false => EpochStanding::Out,
        }
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
        // An epoch this device started is granted once the record starting
        // it is durable (spec §4.2): before, a power loss could take the
        // record and its key, and the seq go to a record with another key.
        if e.creator == self.device && e.seq.0 > st.durable {
            return None;
        }
        st.keys.key(c, e)
    }

    /// Answer a grant asked of this device (spec §9): check that the asker
    /// may hold the key of the epoch asked for and that it is held here
    /// ([`Self::grant_key`]), verify the asker's seal key, and wrap the key
    /// to it. One name, one packet while it is kept. `None` (a Nack)
    /// otherwise. The seal key is asked once in place, within the asker's
    /// wait; when that ask misses, it is asked again in the background
    /// ([`Self::learn_seal_key`]), so the asker's next round is answered
    /// from the key then verified. At most [`GRANTS_PER_ASKER`] asks of one
    /// asker device are worked on at once, taken before anything is fetched
    /// ([`Self::grant_slot`]): one more is refused, and an honest asker's
    /// next round asks again.
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
        let Some(_slot) = self.grant_slot(&asker) else {
            tracing::debug!(%asker, "grant not answered: the asker has as many grant asks in progress here as it may ({GRANTS_PER_ASKER}); its next round asks again once they end");
            return None;
        };
        if verified.is_none() {
            let fetched = self.fetch(ask.seal_key.clone(), false).await;
            let ok = match &fetched {
                Some(data) => self.seal_key_of(data, &ask.seal_key, &asker, &public).await,
                None => false,
            };
            if !ok {
                tracing::debug!(%asker, "grant not answered: its seal key did not come, or did not verify as its own; asked again in the background");
                self.learn_seal_key(&ask.seal_key, &asker, &public);
                return None;
            }
        }
        let mut st = self.st.lock();
        if !st.keep_seal_key(&ask.seal_key, public, self.namespace_unheld(&ask.seal_key)) {
            tracing::debug!(%asker, "grant not answered: no record in force lists the asker's writer any more");
            return None;
        }
        // Checked again: the records may have moved during the fetch.
        let key = self.grant_key(&st, c, e, &asker, &asker_ns)?;
        // Another Interest of the same ask (a re-expression, spec §17.1)
        // was answered meanwhile: one name, one packet.
        if let Some(p) = st.grants.get(name) {
            return Some(p.clone());
        }
        let (ephemeral, wrapped) = wrap_ck_to(&public, &key, &name.encode_to_tlv()).ok()?;
        let wire = self
            .sign(DataBuilder::new(
                name.clone(),
                &wire::encode_grant(&ephemeral, &wrapped.to_bytes()),
            ))
            .ok()?;
        st.grants.insert(name.clone(), wire.clone());
        self.grants_answered.fetch_add(1, Ordering::Relaxed);
        Some(wire)
    }

    /// Whether `data` is `asker`'s seal key packet `seal_key`, naming
    /// `public`: verified, signed by the asker's device.
    async fn seal_key_of(
        &self,
        data: &Data,
        seal_key: &Name,
        asker: &Name,
        public: &[u8; 32],
    ) -> bool {
        let Ok(signer) = self.verify(data).await else {
            return false;
        };
        *data.name == *seal_key
            && device_of(signer.key()).as_ref() == Some(asker)
            && data
                .content()
                .and_then(|c| wire::decode_seal_key(c.clone()).ok())
                .is_some_and(|p| p == *public)
    }

    /// Ask again, in the background, for `asker`'s seal key `seal_key`
    /// that a grant's ask in place did not get (spec §9, §17.1): up to
    /// [`FETCH_TRIES`] asks, one run per key at a time, and, verified, it is
    /// kept, so the asker's next round of grant asks is answered at once.
    /// Only an asker the records held admit gets here ([`Self::grant_key`]):
    /// a stranger costs no asks. At most [`SEAL_LEARNING_MAX`] runs at once,
    /// [`SEAL_LEARNING_PER_ASKER`] of one asker's: an admitted reader can
    /// name any number of seal keys of its own device, and none of them
    /// is to take the device's fetch slots from its own fetches. A run
    /// beyond the cap is not started, and says why; the asker's next grant
    /// ask starts it once one ends.
    fn learn_seal_key(self: &Arc<Self>, seal_key: &Name, asker: &Name, public: &[u8; 32]) {
        {
            let mut st = self.st.lock();
            if st.seal_learning.contains(seal_key) {
                return;
            }
            let of_asker = st
                .seal_learning
                .iter()
                .filter(|k| k.has_prefix(asker))
                .count();
            if st.seal_learning.len() >= SEAL_LEARNING_MAX || of_asker >= SEAL_LEARNING_PER_ASKER {
                tracing::debug!(
                    %asker,
                    all = st.seal_learning.len(),
                    of_asker,
                    "seal key not asked again in the background: as many runs are under way as this device allows ({SEAL_LEARNING_MAX} in all, {SEAL_LEARNING_PER_ASKER} per asker device); the asker's next grant ask starts it once one ends"
                );
                return;
            }
            st.seal_learning.insert(seal_key.clone());
        }
        let (inner, seal_key, asker, public) =
            (Arc::clone(self), seal_key.clone(), asker.clone(), *public);
        rt::spawn(async move {
            let got = match inner.fetch_owed(seal_key.clone(), false).await {
                Some(data) => inner.seal_key_of(&data, &seal_key, &asker, &public).await,
                None => false,
            };
            let mut st = inner.st.lock();
            st.seal_learning.remove(&seal_key);
            if got {
                let unheld = inner.namespace_unheld(&seal_key);
                st.keep_seal_key(&seal_key, public, unheld);
            }
        });
    }

    /// Get the key of epoch `e` of `c` (spec §9) — asked of the subject
    /// whose record names it ([`St::seal_subject`]): `c`, or the folder
    /// above it whose epoch it is, so one ask serves every collection that
    /// reads in a folder's epoch — from the epoch's creator, then from
    /// every other device known to write into `c`'s namespace
    /// ([`Self::ask_grants`]). A granted key is taken only if it matches the
    /// key check of the held record naming the epoch. Opens what it unlocks.
    /// Whether the key is held now. The rounds run in one task of their
    /// own, round after round with a capped backoff ([`retry_pause`]), for
    /// as long as the key is owed here ([`Self::key_owed`], spec §17.1):
    /// never one try per granter. The caller waits for the first
    /// [`FETCH_TRIES`] of them, so a verb that needs the key is answered by
    /// them rather than by one lost packet; the rest go on in the
    /// background, and none is cut when the caller stops waiting.
    async fn obtain(self: &Arc<Self>, c: &Name, e: &Epoch) -> bool {
        if let Some(rx) = self.ask_for_key(c, e) {
            // Answered after the rounds in place, or once the loop ended
            // (its sender dropped).
            let _ = rx.await;
        }
        self.st.lock().keys.key(c, e).is_some()
    }

    /// Start the ask for the key of epoch `e` of `c` ([`Self::obtain`])
    /// and do not wait for it: a verb that must not wait on other devices —
    /// a put, a join's own wait — asks and answers what it holds. `None`:
    /// the key is held, nothing held names the epoch, or an ask for it is
    /// under way already; else the receiver that is answered after the
    /// first rounds, or once the loop ended.
    fn ask_for_key(self: &Arc<Self>, c: &Name, e: &Epoch) -> Option<oneshot::Receiver<()>> {
        let ns = namespace_of(c)?;
        let (s, seal_key) = {
            let mut st = self.st.lock();
            if st.keys.key(c, e).is_some() {
                return None;
            }
            let s = st.seal_subject(c, e);
            if !st
                .line_of(&s)
                .is_some_and(|(epochs, _)| epochs.contains_key(e))
            {
                // Nothing to check a key against: no record held names it.
                return None;
            }
            if !st.asking.insert((s.name.clone(), e.clone())) {
                return None;
            }
            (s, seal_key_name(&self.device, &st.keys.recipient.public()))
        };
        self.grants_asked.fetch_add(1, Ordering::Relaxed);
        let ask = GrantAsk {
            seal_key,
            collection: s.name.clone(),
            epoch: e.clone(),
        };
        let (tx, rx) = oneshot::channel::<()>();
        let inner = Arc::clone(self);
        // The ask stays under way while this loop runs, so nothing starts a
        // second round beside it.
        rt::spawn(async move {
            let mut waiting = Some(tx);
            let mut misses = 0;
            let owed = |inner: &Arc<Self>| inner.key_owed(&inner.st.lock(), &s, &ask.epoch);
            let got = loop {
                if inner.ask_grants(&ns, &ask).await {
                    break true;
                }
                misses += 1;
                if misses >= FETCH_TRIES
                    && let Some(tx) = waiting.take()
                {
                    let _ = tx.send(());
                }
                if !owed(&inner) {
                    break inner.st.lock().keys.key(&s.name, &ask.epoch).is_some();
                }
                rt::sleep(retry_pause(misses - 1)).await;
                if !owed(&inner) {
                    break inner.st.lock().keys.key(&s.name, &ask.epoch).is_some();
                }
            };
            inner.obtained(&ask, got).await;
        });
        Some(rx)
    }

    /// One round of asks for the key `ask` names (spec §9): of the epoch's
    /// creator, then of the devices signed data held here vouches for
    /// among those known to write into `ns`, at most [`heard::RELAYS_ASKED`]
    /// ([`Self::granters`]), one Interest each, until one grants a key that
    /// matches the epoch's key check. Whether one did; the grant is kept in
    /// the store.
    async fn ask_grants(self: &Arc<Self>, ns: &Name, ask: &GrantAsk) -> bool {
        let (c, e) = (&ask.collection, &ask.epoch);
        let granters = self.granters(&self.st.lock(), ns, &e.creator);
        for granter in granters {
            let name = grant_name(&granter, ask);
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
            let Some(key) = open_grant(&self.st.lock().keys.recipient, &name, content) else {
                continue;
            };
            // Versions in pieces sealed in this epoch that wait for its key
            // are read and unsealed here, not under the lock; a key that is
            // not the epoch's opens none.
            self.open_pieces(c, None, Some((e, &key)));
            let mut st = self.st.lock();
            if !st.take_key(c, e, key) {
                tracing::debug!(%granter, collection = %c, epoch = ?e, "refused: a granted key that does not match its epoch's key check");
                continue;
            }
            self.store.insert(name, data.raw().clone());
            return true;
        }
        tracing::debug!(collection = %c, epoch = ?e, "no device granted the epoch's key this round; asked again while it is owed");
        false
    }

    /// End the ask for the key `ask` names: no longer under way; `got`, it
    /// opens what it unlocks.
    async fn obtained(self: &Arc<Self>, ask: &GrantAsk, got: bool) {
        self.st
            .lock()
            .asking
            .remove(&(ask.collection.clone(), ask.epoch.clone()));
        if got {
            // Register versions in pieces it unlocked wait for them; a group
            // member it opened may make its folder followed.
            self.fetch_wanted(true);
            self.settle().await;
        } else {
            tracing::debug!(collection = %ask.collection, epoch = ?ask.epoch, "the epoch's key is not owed here (no version held waits for it, or this device may not hold it): not asked again until one arrives");
        }
        self.progress.notify_waiters();
    }

    /// Whether the key of epoch `e` of subject `s` is still owed here
    /// (spec §17.1): not held; a held record of `s` names `e` and this
    /// device may hold its key ([`Self::may_hold`]); and a version held
    /// here waits for it, or it is the epoch of `s`'s record in force (for
    /// writing). Cut or let-go versions, a record that no longer
    /// admits this device and a subject no longer followed end it.
    fn key_owed(&self, st: &St, s: &Subject, e: &Epoch) -> bool {
        if st.keys.key(&s.name, e).is_some() {
            return false;
        }
        let Some((epochs, record)) = st.line_of(s) else {
            return false;
        };
        if !epochs.contains_key(e) || !self.may_hold(st, &s.name, e, &self.device, &self.ns) {
            return false;
        }
        record.and_then(|m| m.epoch.as_ref()) == Some(e)
            || st.colls.iter().any(|(c, coll)| {
                coll.locked.iter().any(|l| l.epoch() == e) && st.seal_subject(c, e) == *s
            })
    }

    /// The key of `c`'s current epoch, for writing, as this device holds it
    /// now: a put never waits on other devices (spec §15). When this device
    /// reads `c` and lacks the key, the ask for the grant runs in the
    /// background ([`Self::ask_for_key`]) and the put is
    /// [`DataError::NotReady`] at once, naming the key. `Ok(None)` when `c`
    /// is not sealed.
    fn write_key(self: &Arc<Self>, c: &Name) -> Result<Option<(Epoch, ContentKey)>, DataError> {
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
        let _ = self.ask_for_key(c, &epoch);
        Err(key_not_held(&self.st.lock(), c, &epoch))
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

    /// Set the record in force of `c`, a collection under a followed
    /// folder known here only by what a walk listed of it — no version of
    /// it taken yet, so nothing set it ([`St::ensure`]) —, so it is read
    /// under that record (spec §6.1) as one a version arrived for, not
    /// answered `Unavailable` while the versions listed are on their way.
    fn known_under_folder(&self, c: &Name) {
        let mut st = self.st.lock();
        if st.inside(c) && st.colls.get(c).is_some_and(|x| x.members.is_none()) {
            st.ensure(c);
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
                // Never read under another rule.
                let Some(state) = &coll.state else {
                    return Err(DataError::RuleUnknown {
                        collection: c.clone(),
                        rule: function.clone(),
                    });
                };
                Ok(Got::State(State {
                    collection: c.clone(),
                    at,
                    value: state.value().map_err(|winner| DataError::NotReady {
                        name: c.clone(),
                        why: format!(
                            "the version that wins here ({winner:?}) carries its value in \
                             pieces this device's store no longer holds, so it cannot read the \
                             value now; get {c} again after the group next delivers that \
                             version's pieces"
                        ),
                    })?,
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
        }
    }

    /// A log entry by name, read whole (a large payload from its pieces).
    async fn get_log_entry(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let a = self.log_entry(name).await;
        self.whole(a).await
    }

    /// The log entry named `name`, verified, not read whole: held here, or
    /// fetched — by name (its writer, or a cache), else from the devices
    /// that answer for it (`32=held`). A packet that is not its
    /// writer's (a forged or spliced packet, another signer's, one that does
    /// not decode) is dropped and the next source asked
    /// ([`Self::take_data`]); a refusal kept against the name is a decision
    /// on the genuine writer's own packet. Its collection is followed first. A
    /// version sealed to an audience no record held admits this device to
    /// is judged by signed data only ([`Self::sealed_judged`]).
    async fn log_entry(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let a = self.log_entry_held(name).await;
        match parse_log_name(name).and_then(|p| p.subject) {
            Some(c) => self.sealed_judged(name, &c, a).await,
            None => a,
        }
    }

    /// [`Self::log_entry`], a sealed version this device does not read by
    /// the record in force answered [`DataError::Sealed`] as it is.
    async fn log_entry_held(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let answer = |st: &mut St| -> Option<Result<Answer, DataError>> {
            if let Some(why) = st.refused.get(name) {
                return Some(Err(refused(name, why.clone())));
            }
            let held = st.held.get(name)?;
            Some(match held {
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
                Held::Record { .. } => Err(DataError::NotFound { name: name.clone() }),
            })
        };
        if let Some(a) = answer(&mut self.st.lock()) {
            return a;
        }
        let parsed =
            parse_log_name(name).ok_or_else(|| DataError::NotFound { name: name.clone() })?;
        if let Some(c) = &parsed.subject {
            self.look(c).await?;
        }
        if let Some(a) = answer(&mut self.st.lock()) {
            return a;
        }
        let relays = match parsed.subject.as_ref().and_then(namespace_of) {
            Some(ns) => self.relays(&self.st.lock(), &ns, &parsed.device, &[]),
            None => Vec::new(),
        };
        let mut failed = DataError::Unavailable { name: name.clone() };
        let mut taken = false;
        // One a removal cut keeps bound to bytes: by its full name.
        let exact = match self.kept_bytes(name).await {
            Some(d) => name.clone().append_implicit_digest(d),
            None => name.clone(),
        };
        for source in std::iter::once(None).chain(relays.iter().map(Some)) {
            let data = match source {
                None => self.fetch_owed(exact.clone(), false).await,
                Some(h) => self.fetch_held(name, h).await,
            };
            let Some(data) = data else { continue };
            match self.take_data(name, data).await {
                Ok(()) => {
                    taken = true;
                    break;
                }
                Err(why) => {
                    // A revocation's refusal kept against the name is final.
                    if self.st.lock().cut_out.contains_key(name) {
                        return Err(refused(name, why));
                    }
                    tracing::debug!(%name, ?source, "refused ({why}); asked elsewhere");
                    failed = refused(name, why);
                }
            }
        }
        if !taken {
            // Only other bytes than a removal cut keeps came at this name:
            // that refusal says why, though the kept ones may still come.
            if matches!(failed, DataError::Unavailable { .. })
                && let Some((cut, _)) = self.st.lock().other_bytes.get(name).cloned()
            {
                return Err(refused(name, Refusal::OutsideCut(cut)));
            }
            return Err(failed);
        }
        // The entry came, but no members record of its collection is held:
        // ask its writer's own summary for the records (it answered, so a
        // path to it exists), whether or not it was heard in a group.
        if let Some(c) = &parsed.subject
            && self
                .st
                .lock()
                .colls
                .get(c)
                .is_none_or(|x| x.members.is_none())
            && let Some(ns) = namespace_of(c)
        {
            {
                let mut st = self.st.lock();
                if let Some(peer) = st.peers.get_mut(&(parsed.device.clone(), ns.clone())) {
                    peer.forget(c);
                }
            }
            let _ = rt::timeout(self.config.first_look, self.walk(&ns, &parsed.device)).await;
        }
        if let Some(c) = &parsed.subject {
            let c = c.clone();
            self.wait_for(|st| {
                st.colls.get(&c).is_some_and(|coll| coll.members.is_some())
                    && !matches!(st.held.get(name), Some(Held::Locked))
            })
            .await;
        }
        answer(&mut self.st.lock())
            .unwrap_or_else(|| Err(DataError::Unavailable { name: name.clone() }))
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

/// One ask of an asker device this device is working on ([`Inner::ask_slot`]).
struct AskSlot<'a> {
    inner: &'a Inner,
    asker: Name,
}

impl Drop for AskSlot<'_> {
    fn drop(&mut self) {
        self.inner.release_ask(&self.asker);
    }
}

impl Inner {
    // ---- large payloads -----------------------------------------------------------------------

    /// Fetch `name`, another device's packet, from `holder`, which keeps
    /// it for that device's collection: asked under the holder's own name
    /// ([`wire::held_name`]), answered with the packet inside; a miss
    /// asking again may mend is asked again in place ([`Self::fetch_owed`]).
    async fn fetch_held(&self, name: &Name, holder: &Name) -> Option<Data> {
        let reply = self
            .fetch_owed(wire::held_name(holder, name), false)
            .await?;
        let inner = Data::decode(reply.content()?.clone()).ok()?;
        (*inner.name == *name).then_some(inner)
    }

    /// Piece `name` of a large version of `c`, checked against `digest`:
    /// from the store, else from its writer by name, else from the devices
    /// that answer for it ([`Self::fetch_held`]); stored once found.
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
    /// which source answered (`None`: its writer by name; `Some(d)`: device
    /// `d` under its own name — any other device heard for `c`'s
    /// namespace, [`Self::relays`]). The store answers first whatever
    /// `first` says. In rounds, as a walk asks (spec §13.5, §17.1): the
    /// writer first; once its first ask missed (a lifetime), beside its
    /// later asks, the relays all at once — so a source that is silent
    /// costs the writer's answer nothing, and the writer's later asks wait
    /// for none of them.
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
        let writer = parse_piece_name(name).map(|p| p.log.device);
        let relays = {
            let st = self.st.lock();
            match (namespace_of(c), &writer) {
                (Some(ns), Some(w)) => self.relays(&st, &ns, w, &[]),
                _ => Vec::new(),
            }
        };
        // An Interest for this device's own name goes nowhere useful: its
        // own pieces it dropped are asked of the others only.
        let own = writer.as_ref() == Some(&self.device);
        let mut relays: Vec<Name> = relays.into_iter().filter(|d| *d != self.device).collect();
        let checks = |data: Data| {
            let fits = *data.name == *name && wire::implicit_digest(data.raw()) == *digest;
            if !fits {
                tracing::debug!(%name, "not the piece its manifest lists; fetched elsewhere");
            }
            fits.then_some(data)
        };
        // The source that answered the piece before this one, asked first.
        let preferred = match first {
            Some(Some(d)) if relays.contains(d) => {
                relays.retain(|r| r != d);
                Some(d.clone())
            }
            _ => None,
        };
        let from_relays = async {
            self.first_held_from(name, &relays, Some(*digest))
                .await
                .map(|(data, r)| (data, Some(r)))
        };
        let got = async {
            if let Some(p) = &preferred
                && let Some(data) = self.fetch_held(name, p).await.and_then(checks)
            {
                return Some((data, Some(p.clone())));
            }
            if own {
                return from_relays.await;
            }
            let by_name = async {
                self.fetch_owed(name.clone(), false)
                    .await
                    .and_then(checks)
                    .map(|data| (data, None))
            };
            let beside = async {
                rt::sleep(self.config.lifetime).await;
                from_relays.await
            };
            first_some(by_name, beside).await
        }
        .await;
        let (data, source) = got?;
        let w = data.raw().clone();
        self.store.insert(name.clone(), w.clone());
        Some((w, source))
    }

    /// Walk the pieces of the large version `v` of `c`: every manifest node
    /// and chunk, each checked against the digest its parent lists, the
    /// root against the record's. With `assemble`, the payload; without,
    /// an empty one once every piece is held. `None` when a piece is not to
    /// be had.
    ///
    /// Pieces are asked a window at once (spec §13.1, §17.1): the manifest
    /// a level at a time, then the chunks, at most [`Config::window`] of
    /// them in flight, each an owed fetch with its own bounded asks. A
    /// piece not to be had neither stops the walk nor holds back the pieces
    /// behind it: every other one this walk can name is fetched and kept,
    /// so asking again costs only what is still missing. What came is
    /// placed by its index, never by when it came.
    async fn walk_pieces(
        self: &Arc<Self>,
        v: &Name,
        c: &Name,
        chunks: ChunksBody,
        assemble: bool,
    ) -> Option<Vec<u8>> {
        let shape = Shape::of(chunks.size);
        let window = self.config.window.max(1);
        let mut digests: HashMap<PieceKind, [u8; 32]> = HashMap::new();
        digests.insert(PieceKind::Manifest(0), chunks.root);
        // A node not to be had, or not the one listed, leaves its children
        // unknown: they are not asked, and the walk ends without the payload.
        let mut level: Vec<u64> = vec![0];
        while !level.is_empty() {
            let listed: Vec<(u64, Option<Vec<[u8; 32]>>)> = {
                let (digests, shape) = (&digests, &shape);
                stream::iter(level)
                    .map(|k| async move {
                        let node = async {
                            let expected = *digests.get(&PieceKind::Manifest(k))?;
                            let w = self
                                .get_piece(c, &piece_name(v, PieceKind::Manifest(k)), &expected)
                                .await?;
                            pieces::open_node(shape, k, &w, &expected)
                        };
                        (k, node.await)
                    })
                    .buffer_unordered(window)
                    .collect()
                    .await
            };
            let mut next = Vec::new();
            for (k, listed) in listed {
                let (Some(listed), Some(kids)) = (listed, shape.children(k)) else {
                    continue;
                };
                for (kid, d) in kids.into_iter().zip(listed) {
                    if let PieceKind::Manifest(m) = kid {
                        next.push(m);
                    }
                    digests.insert(kid, d);
                }
            }
            next.sort_unstable();
            level = next;
        }
        let open = move |shape: &Shape, i: u64, w: Bytes, d: [u8; 32]| {
            if assemble {
                pieces::open_chunk(shape, i, &w, &d)
            } else {
                Some(Bytes::new())
            }
        };
        let mut got: Vec<Option<Bytes>> = vec![None; shape.chunks as usize];
        // The source is chosen per version, from what answered: the first
        // chunk is asked alone (the writer first, then the others), and
        // every other chunk goes first to whoever answered it — a writer that
        // dropped its chunks costs one miss, not one per chunk. When the
        // first is not to be had, the others go in the usual order.
        let mut first: Option<Option<Name>> = None;
        if let Some(d) = digests.get(&PieceKind::Chunk(0)).copied()
            && let Some((w, source)) = self
                .get_piece_from(c, &piece_name(v, PieceKind::Chunk(0)), &d, None)
                .await
        {
            got[0] = open(&shape, 0, w, d);
            first = Some(source);
        }
        let todo: Vec<(u64, [u8; 32])> = (1..shape.chunks)
            .filter_map(|i| Some((i, *digests.get(&PieceKind::Chunk(i))?)))
            .collect();
        let (first, shape) = (first.as_ref(), &shape);
        let rest: Vec<(u64, Option<Bytes>)> = stream::iter(todo)
            .map(|(i, d)| async move {
                let w = self
                    .get_piece_from(c, &piece_name(v, PieceKind::Chunk(i)), &d, first)
                    .await;
                (i, w.and_then(|(w, _)| open(shape, i, w, d)))
            })
            .buffer_unordered(window)
            .collect()
            .await;
        for (i, w) in rest {
            got[i as usize] = w;
        }
        let mut out = Vec::with_capacity(if assemble { chunks.size as usize } else { 0 });
        for w in got {
            out.extend_from_slice(&w?);
        }
        Some(out)
    }

    /// Read version `v` whole: a large payload is fetched piece by piece
    /// and opened (spec §13.1); any other is returned as it is.
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
        // A payload in pieces is one entry.
        let (fields, op) = match epoch {
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
        // Read whole, a merge version's operation is open.
        let op = v.rule.is_some().then_some(op);
        Ok(Version {
            payload: Payload::Entry(fields),
            op,
            ..v
        })
    }

    /// Fetch, in the background, what versions held here wait for: the
    /// removal cut manifest packets ([`Self::fetch_wanted_bytes`]) — which a
    /// version may come to wait for as it is admitted on any path, a key
    /// opening it as much as an entry taken (spec §8, §17.1) — and the
    /// pieces every register version waits for ([`St::wanted_pieces`]).
    /// `retry`: also those whose pieces a fetch did not find (asked again
    /// on what may have changed since: a descent, a key, a start).
    fn fetch_wanted(self: &Arc<Self>, retry: bool) {
        self.fetch_wanted_bytes();
        let (wanted, wires): (Vec<(Name, ChunksBody)>, _) = {
            let mut st = self.st.lock();
            if retry {
                st.unfound.clear();
            }
            let wanted = st.colls.keys().flat_map(|c| st.wanted_pieces(c)).collect();
            (wanted, st.wanted_wires(None))
        };
        for (v, chunks) in wanted {
            self.spawn_pieces(v, chunks);
        }
        self.spawn_wires(wires);
    }

    /// Ask, in the background, for the packets pending versions name as
    /// parents that this device holds another packet of ([`St::wanted_wires`]),
    /// each by its full name, from the parent's writer and the devices
    /// answering for it. One that verifies is taken, which notes it beside
    /// the one held ([`St::note_wire`]): the same version if it signed the
    /// same thing, and the evidence against the child if another. One not to
    /// be had is asked for again after [`retry_pause`] while a pending version
    /// still names it (spec §17.1).
    fn spawn_wires(self: &Arc<Self>, asks: Vec<(Name, [u8; 32])>) {
        for ask in asks {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                let (name, digest) = ask.clone();
                if let Some(data) = inner.fetch_entry(&name, Some(digest)).await
                    && let Err(why) = inner.take_data(&name, data).await
                {
                    tracing::debug!(%name, %why, "the packet a version names its parent by is refused");
                }
                let pause = {
                    let mut st = inner.st.lock();
                    if st.wants_wire(&name, &digest) {
                        let misses = st.wire_misses.entry(ask.clone()).or_insert(0);
                        let pause = retry_pause(*misses);
                        *misses = misses.saturating_add(1);
                        Some(pause)
                    } else {
                        st.wiring.remove(&ask);
                        st.wire_misses.remove(&ask);
                        None
                    }
                };
                inner.progress.notify_waiters();
                if let Some(pause) = pause {
                    rt::sleep(pause).await;
                    let asks = {
                        let mut st = inner.st.lock();
                        st.wiring.remove(&ask);
                        st.wanted_wires(None)
                    };
                    inner.spawn_wires(asks);
                }
            });
        }
    }

    /// Fetch every piece of the large version `v` in the background — as a
    /// reader of a register collection whose version waits for them — then
    /// open and apply what waited.
    fn spawn_pieces(self: &Arc<Self>, v: Name, chunks: ChunksBody) {
        if !self.st.lock().fetching.insert(v.clone()) {
            return;
        }
        tracing::trace!(me = %self.device, name = %v, "fetching the pieces of a version");
        let inner = Arc::clone(self);
        rt::spawn(async move {
            let c = parse_log_name(&v).and_then(|l| l.subject);
            let whole = match &c {
                Some(c) => inner.walk_pieces(&v, c, chunks, false).await.is_some(),
                None => false,
            };
            // Read and unsealed here, not under the lock ([`Self::open_pieces`]).
            if whole && let Some(c) = &c {
                inner.open_pieces(c, Some(&v), None);
            }
            let retry = {
                let mut st = inner.st.lock();
                st.fetching.remove(&v);
                match (&c, whole) {
                    (Some(c), true) => {
                        st.unfound.remove(&v);
                        st.piece_misses.remove(&v);
                        st.pieces_arrived(c, &v);
                        None
                    }
                    _ => {
                        tracing::debug!(me = %inner.device, name = %v, "not every piece of a held version is to be had yet; asked again while it waits for them");
                        st.unfound.insert(v.clone());
                        let misses = st.piece_misses.entry(v.clone()).or_insert(0);
                        let pause = retry_pause(*misses);
                        *misses = misses.saturating_add(1);
                        Some(pause)
                    }
                }
            };
            if let Some(pause) = retry {
                inner.retry_pieces(v, pause);
            }
            inner.progress.notify_waiters();
        });
    }

    /// Open the pending register versions in pieces under `under` that are
    /// whole in the store (only `version`, if given): the pieces are read,
    /// checked and unsealed without the device's lock, the one thing a payload
    /// of up to [`wire::PAYLOAD_MAX`] octets costs here; the lock is held only
    /// to pick them and to put each result in place. The state applies them
    /// on its next run. `granted`: the key of an epoch about to be held.
    fn open_pieces(
        &self,
        under: &Name,
        version: Option<&Name>,
        granted: Option<(&Epoch, &ContentKey)>,
    ) {
        let jobs = self.st.lock().open_jobs(under, version, granted);
        if jobs.is_empty() {
            return;
        }
        let opened = open_jobs(&*self.store, &jobs);
        drop(jobs);
        let mut st = self.st.lock();
        for (c, id, digest, op) in opened {
            st.install_opened(&c, &id, digest, op);
        }
    }

    /// Ask again, after `pause`, for the pieces of the register version `v`
    /// a fetch did not find whole (spec §17.1): if it still waits for them
    /// and nothing asked for them meanwhile.
    fn retry_pieces(self: &Arc<Self>, v: Name, pause: Duration) {
        let weak = Arc::downgrade(self);
        rt::spawn(async move {
            rt::sleep(pause).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let wanted = {
                let mut st = inner.st.lock();
                if !st.unfound.remove(&v) {
                    return;
                }
                let wanted = parse_log_name(&v)
                    .and_then(|l| l.subject)
                    .and_then(|c| st.wanted_pieces(&c).into_iter().find(|(n, _)| *n == v));
                if wanted.is_none() {
                    st.piece_misses.remove(&v);
                }
                wanted
            };
            if let Some((v, chunks)) = wanted {
                inner.spawn_pieces(v, chunks);
            }
        });
    }

    /// The device an ask's proof claims asks, by its key locator, and the
    /// proof's packet: unverified, for the checks that cost nothing.
    fn claimed_asker(proof: &Bytes) -> Option<(Data, Name)> {
        let data = Data::decode(proof.clone()).ok()?;
        let key = data.sig_info()?.key_locator_name()?;
        let asker = device_of(&key)?;
        Some((data, asker))
    }

    /// Count one more ask of `asker` in progress, if it has fewer than
    /// `limit`; the slot is given back when dropped.
    fn ask_slot(&self, asker: &Name, limit: usize) -> Option<AskSlot<'_>> {
        self.take_ask(asker, limit).then(|| AskSlot {
            inner: self,
            asker: asker.clone(),
        })
    }

    /// [`Self::ask_slot`] for a grant ask of `asker`, [`GRANTS_PER_ASKER`] at
    /// once. Counted apart from the asker's other asks, under
    /// the asker's name with the `32=grant` keyword added, so a device's grant
    /// asks neither take the slot of its other asks nor wait behind them.
    fn grant_slot(&self, asker: &Name) -> Option<AskSlot<'_>> {
        let key = Name::from_components(
            asker
                .components()
                .iter()
                .cloned()
                .chain([wire::kw(b"grant")]),
        );
        self.ask_slot(&key, GRANTS_PER_ASKER)
    }

    /// Count one more ask of `asker` in progress, if it has fewer than
    /// `limit`: whether it was counted. [`Self::release_ask`] gives it back.
    fn take_ask(&self, asker: &Name, limit: usize) -> bool {
        let mut st = self.st.lock();
        let n = st.asks.entry(asker.clone()).or_default();
        if *n >= limit {
            tracing::debug!(%asker, "ask refused: the asker has as many in progress as it may");
            return false;
        }
        *n += 1;
        true
    }

    /// Give back an ask [`Self::take_ask`] counted.
    fn release_ask(&self, asker: &Name) {
        let mut st = self.st.lock();
        if let Some(n) = st.asks.get_mut(asker) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.asks.remove(asker);
            }
        }
    }

    /// A proof of who asks for this device's own asks: `<me>/32=ask/
    /// <binding>`, signed by the device key.
    fn ask_proof(&self, binding: &[u8; 32]) -> Option<Bytes> {
        self.sign(
            DataBuilder::new(wire::ask_name(&self.device, binding), &[]).freshness(Duration::ZERO),
        )
        .ok()
    }

    /// A fresh nonce from the device's entropy.
    fn nonce(&self) -> [u8; wire::NONCE_LEN] {
        let mut nonce = [0u8; wire::NONCE_LEN];
        (self.config.entropy)(&mut nonce);
        nonce
    }
}

/// A sealed payload opened: its fields and operation, into the record's
/// body.
fn open_into(body: &mut VersionBody, (fields, op): (Content, Bytes)) {
    body.fields = fields;
    body.op = op;
}

/// The version a piece name belongs to; any other name as it is.
fn strip_piece(name: &Name) -> Name {
    parse_piece_name(name).map_or_else(|| name.clone(), |p| p.version)
}

/// The prefix a revocation cut's range names for the log entry `entry`:
/// its collection's log `<D>/32=log/<C>` (or `<D>/32=log`, of no collection),
/// the name without its seq.
fn log_prefix(entry: &Name) -> Name {
    let comps = entry.components();
    Name::from_components(comps[..comps.len().saturating_sub(1)].iter().cloned())
}

/// The key that signs for trust context `ctx`: its anchor's key, one of
/// its namespace if it has several (the first in name order).
fn anchor_key(ctx: &SignedTrustContext) -> Writer {
    let mut keys: Vec<Name> = ctx.anchors().iter().map(|a| key_name_of(a.key())).collect();
    keys.sort();
    let key = keys
        .iter()
        .find(|k| k.has_prefix(ctx.namespace()))
        .or(keys.first())
        .cloned()
        .unwrap_or_else(|| ctx.namespace().clone());
    Writer::new(key)
}

/// The data-layer cut by which `ctx` ends `writer`'s key in the log
/// `prefix` (`<D>/32=log/<C>`): of the key, accepting exactly the key's
/// runs for that log, in collection `C` (or of the log `<D>/32=log` of no
/// collection, under that prefix), signed by the context's anchor key (spec §8). Empty
/// when the revocation has no cut, or the cut no runs there.
fn revocation_cut_for(ctx: &SignedTrustContext, writer: &Writer, prefix: &Name) -> Cut {
    let key = key_name_of(writer.key());
    let mut accept = Accepted::new();
    if let Some(range) = ctx
        .revocation_cut(&key)
        .and_then(|c| c.ranges().iter().find(|r| r.prefix == *prefix))
    {
        let entry = Name::from_components(
            prefix
                .components()
                .iter()
                .cloned()
                .chain([ndn_packet::NameComponent::sequence_num(0)]),
        );
        let c = parse_log_name(&entry)
            .and_then(|l| l.subject)
            .unwrap_or_else(|| prefix.clone());
        for &(first, last) in &range.runs {
            accept.insert_range(&c, writer, first, last);
        }
    }
    Cut {
        of: key,
        accept,
        signer: anchor_key(ctx),
    }
}

/// What a removal cut's manifests say of the bytes of a version it keeps
/// (spec §8): [`bound_bytes`].
enum Bound {
    /// Every manifest binding it lists exactly these bytes.
    Listed,
    /// A manifest lists other bytes at its name, or none: outside the cut.
    Other,
    /// The cut binds what it keeps to no bytes (a record signed before
    /// cuts bound bytes): outside the cut, and kept, bytes and all, for the
    /// owner's next record to bind (spec §8).
    Unbound,
    /// A manifest packet on its path is not held: fetch it by this full
    /// name, then judge again.
    Missing(Name),
}

/// Take the removal cut manifest packet `full` (a full name) into `held`,
/// from `store` if not held; whether it is held now. Every packet taken is
/// kept in the store, under its name, as it came.
fn load_cut_bytes(held: &CutManifests, store: &dyn DataStore, full: &Name) -> bool {
    if held.contains(full) {
        return true;
    }
    let Some((last, bare)) = full.components().split_last() else {
        return false;
    };
    let Some(wire) = store.get(&Name::from_components(bare.iter().cloned())) else {
        return false;
    };
    if wire::implicit_digest(&wire).as_slice() != last.value.as_ref() {
        return false;
    }
    let Ok(data) = Data::decode(wire) else {
        return false;
    };
    // One that is no manifest node is held too: it lists nothing.
    let _ = held.insert(&data);
    true
}

/// What the removal cut manifest rooted at `root` lists for the log entry
/// `entry` (`<D>/32=log/<C>/seq=<n>`, listed under `<D>/32=log/<C>`), its
/// packets read back from `store` as needed.
fn listed_bytes(
    held: &CutManifests,
    store: &dyn DataStore,
    root: &Name,
    entry: &Name,
) -> ManifestLookup {
    let Some((last, prefix)) = entry.components().split_last() else {
        return ManifestLookup::NotListed;
    };
    let Some(seq) = last.as_sequence_num() else {
        return ManifestLookup::NotListed;
    };
    let prefix = Name::from_components(prefix.iter().cloned());
    loop {
        match held.lookup(root, &prefix, seq) {
            ManifestLookup::Missing(full) if load_cut_bytes(held, store, &full) => continue,
            other => return other,
        }
    }
}

/// Whether version `id` of `c` (the log entry `name`, of implicit digest
/// `digest`), which `cut` keeps, has the bytes the cut binds: every
/// manifest binding `id`'s key in `c` must list exactly `digest` at
/// `name`. Other bytes listed anywhere refuse it, whatever is not held.
fn bound_bytes(
    held: &CutManifests,
    store: &dyn DataStore,
    cut: &Cut,
    c: &Name,
    id: &VersionId,
    name: &Name,
    digest: &[u8; 32],
) -> Bound {
    let mut any = false;
    let mut missing = None;
    for root in cut.accept.manifests(c, &id.writer) {
        any = true;
        match listed_bytes(held, store, root, name) {
            ManifestLookup::Listed(d) if d == *digest => {}
            ManifestLookup::Missing(full) => {
                missing.get_or_insert(full);
            }
            _ => return Bound::Other,
        }
    }
    match (any, missing) {
        (false, _) => Bound::Unbound,
        (true, Some(full)) => Bound::Missing(full),
        (true, None) => Bound::Listed,
    }
}

/// The packet of the log entry `name` held here, opened or sealed. Every
/// entry a collection holds is in [`St::held`]
/// by name, so an entry never held costs one lookup, and an admitted
/// version one more by its id: no scan of the collection (spec §13.5).
fn held_wire(st: &St, name: &Name) -> Option<Bytes> {
    let held = st.held.get(name)?;
    let coll = st.colls.get(&parse_log_name(name)?.subject?)?;
    let named = |hv: &&Arc<HeldVersion>| hv.version.name == *name;
    if let Held::Version(id) = held
        && let Some(hv) = coll.versions.get(id).filter(named)
    {
        return Some(hv.wire.clone());
    }
    coll.waiting
        .iter()
        .chain(&coll.outsiders)
        .find(named)
        .map(|hv| hv.wire.clone())
        .or_else(|| {
            coll.locked
                .iter()
                .find(|l| l.name == *name)
                .map(|l| l.wire.clone())
        })
}

/// The implicit digest of the version `name` of `writer` held verified
/// here, opened or sealed: what a removal cut this device signs binds it
/// to (spec §8).
fn held_digest(st: &St, name: &Name, writer: &Writer) -> Option<[u8; 32]> {
    match st.held.get(name)? {
        Held::Version(id) if id.writer == *writer => {}
        Held::Locked => {}
        _ => return None,
    }
    held_wire(st, name).map(|w| wire::implicit_digest(&w))
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

/// The version `body` signed by `writer` at `seq` describes, its packet's
/// implicit digest `digest`. `open`: whether its payload is open here (not
/// sealed, or opened), so that its operation is the body's; a merge
/// version's operation is carried ([`Version::op`]) only then, and only
/// when it stands in the record, not in pieces.
fn version_of(
    name: &Name,
    writer: &Writer,
    seq: u64,
    body: VersionBody,
    digest: [u8; 32],
    open: bool,
) -> Version {
    let op = (open && body.rule.is_some() && body.chunks.is_none()).then_some(body.op);
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
        rule: body.rule,
        digest,
        op,
        payload: match body.chunks {
            Some(c) => Payload::Large { size: c.size },
            None => Payload::Entry(body.fields),
        },
    }
}

impl Locked {
    /// The version it is, its payload not open: no fields, no operation.
    fn version(&self) -> Version {
        let digest = wire::implicit_digest(&self.wire);
        version_of(
            &self.name,
            &self.writer,
            self.seq,
            self.body.clone(),
            digest,
            false,
        )
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

impl Device {
    /// [`DataLayer::put`] and [`DataLayer::put_op`]: sign `draft` into
    /// `collection` (its record first, for a collection of this namespace
    /// that has none).
    async fn put_draft(
        &self,
        collection: &Name,
        draft: Draft,
        options: PutOptions,
    ) -> Result<VersionId, DataError> {
        let inner = &self.inner;
        check_collection(collection)?;
        let ns = namespace_of(collection).expect("checked above");
        inner.look_behind(collection).await?;
        // Under a folder in force the collection writes under the record in
        // force over it, and no default record of its own is signed (spec
        // §6).
        inner.st.lock().ensure(collection);
        // A collection inheriting a folder's record waits for the walk toward
        // it: the device that has not been walked may hold a narrower record
        // of the collection's own (spec §15).
        inner.inherit_allowed(collection, &ns)?;
        if ns != inner.ns {
            if let Some(refused) = inner.unadmitted(collection, &ns) {
                return Err(refused);
            }
            inner.release_joined(collection);
        }
        // Another person's collection is held under its record by now.
        let fresh = {
            let mut st = inner.st.lock();
            st.ensure(collection);
            ns == inner.ns && st.colls.get(collection).is_none_or(|c| c.members.is_none())
        };
        // A collection of this namespace that no record governs gets the
        // host's default, once nothing a device of the namespace holds can
        // govern it (spec §6.1), signed with its first version and only once
        // that version is judged (spec §5).
        let draft = match fresh {
            false => draft,
            true => {
                inner.default_allowed(collection)?;
                let written = {
                    let mut st = inner.st.lock();
                    st.ensure(collection);
                    match st.colls.get(collection).is_none_or(|c| c.members.is_none()) {
                        // A record arrived meanwhile: written under it.
                        false => Err(draft),
                        true => Ok(inner.put_fresh(
                            &mut st,
                            collection,
                            &ns,
                            draft,
                            (options.type_id.clone(), options.keep),
                        )?),
                    }
                };
                match written {
                    Ok(id) => {
                        inner.publish_about(collection, &[]).await?;
                        return Ok(id);
                    }
                    Err(draft) => draft,
                }
            }
        };
        let key = inner.write_key(collection)?;
        let PutOptions { type_id, keep } = options;
        let id = {
            let mut st = inner.st.lock();
            inner.writable(&st, collection, key.as_ref().map(|(e, _)| e))?;
            let rule = st.colls[collection]
                .members
                .as_ref()
                .expect("members known")
                .rule
                .clone();
            if matches!(draft, Draft::Op(_)) && rule == Rule::Log {
                return Err(DataError::BadRequest {
                    name: collection.clone(),
                    why: format!(
                        "{collection} is a log collection: its versions carry fields, not a \
                         merge rule's operation; put the fields"
                    ),
                });
            }
            inner.write(&mut st, collection, &ns, key.as_ref(), type_id, keep, draft)?
        };
        inner.publish_about(collection, &[]).await?;
        Ok(id)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl DataLayer for Device {
    async fn get(&self, name: &Name) -> Result<Answer, DataError> {
        let inner = &self.inner;
        // Each reading below needs its own keyword in the name: one pass finds them, so a
        // plain collection name (the common read) is parsed by none of them.
        let words = wire::NameWords::of(name);
        if words.log() && parse_log_name(name).is_some() {
            return inner.get_log_entry(name).await;
        }
        check_collection(name)?;
        // A collection not read before: followed, and its members record
        // waited for (at most the first-look time), so that what the record
        // seals or governs is known before the answer is judged.
        let unread = {
            let st = inner.st.lock();
            !st.inside(name) && st.colls.get(name).is_none_or(|x| x.members.is_none())
        };
        inner.look(name).await?;
        if unread {
            inner
                .wait_for(|st| st.colls.get(name).is_some_and(|x| x.members.is_some()))
                .await;
        }
        if inner.sealed_off(&inner.st.lock(), name) {
            let sealed = Err(DataError::Sealed { name: name.clone() });
            return inner.sealed_judged(name, name, sealed).await;
        }
        inner.known_under_folder(name);
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
        let a = {
            let st = inner.st.lock();
            inner.newest(&st, name).map(|got| Answer {
                got,
                age: inner.age(&st, name),
            })
        };
        let a = inner.sealed_judged(name, name, a).await;
        inner.whole(a).await
    }

    async fn put(
        &self,
        collection: &Name,
        content: Content,
        options: PutOptions,
    ) -> Result<VersionId, DataError> {
        self.put_draft(collection, Draft::Entry(content), options)
            .await
    }

    async fn put_op(
        &self,
        collection: &Name,
        op: Bytes,
        options: PutOptions,
    ) -> Result<VersionId, DataError> {
        self.put_draft(collection, Draft::Op(op), options).await
    }

    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError> {
        let inner = &self.inner;
        inner.follow(collection).await?;
        let mut rx = {
            let mut st = inner.st.lock();
            // Each collection under the target, in order: what it holds
            // applied. A version not applied yet is delivered once it
            // applies, as it would have been had the watch begun earlier, so
            // none is delivered twice.
            let mut listed: Vec<(&Name, &VersionId, Change)> = Vec::new();
            for (c, coll) in st.colls.iter().filter(|(c, _)| c.has_prefix(collection)) {
                for hv in coll.versions.values() {
                    let v = &hv.version;
                    if since.contains(&v.id) || coll.pending.contains(&v.id) {
                        continue;
                    }
                    listed.push((c, &v.id, Change::Version(v.clone())));
                }
            }
            listed.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
            // First the records in force (spec §15): over the target, and
            // over each folder and each collection with a record of its own
            // under it.
            let mut changes = st.members_listing(collection);
            changes.extend(listed.into_iter().map(|(_, _, c)| c));
            // The equivocation evidence held of what lies under the target,
            // whatever its frontier: it is reported as long as it is held
            // (spec §4), each version of another collection by name and id.
            changes.extend(st.equivocations_under(collection));
            // The listing, then `watch_queue` changes and one slot for
            // `Lagged` ([`Watcher::send`]).
            let room = changes.len() + inner.config.watch_queue.max(1) + 1;
            let (tx, rx) = mpsc::channel(room);
            for change in changes {
                let _ = tx.try_send(Ok(change));
            }
            st.watchers.push(Watcher {
                target: collection.clone(),
                since: since.clone(),
                tx,
                lagged: false,
            });
            rx
        };
        let ns = namespace_of(collection).expect("followed, so a data name");
        inner.refresh_group(&ns);
        Ok(Box::pin(stream::poll_fn(move |cx| rx.poll_recv(cx))))
    }

    async fn share(
        &self,
        collection: &Name,
        members: crate::layer::Share,
    ) -> Result<(), DataError> {
        self.share_subject(
            Subject {
                name: collection.clone(),
                folder: false,
            },
            crate::layer::Sharing::Whole(members),
        )
        .await
    }

    async fn share_folder(
        &self,
        folder: &Name,
        members: crate::layer::Sharing,
    ) -> Result<(), DataError> {
        self.share_subject(
            Subject {
                name: folder.clone(),
                folder: true,
            },
            members,
        )
        .await
    }

    async fn members(&self, name: &Name) -> Result<crate::layer::Share, DataError> {
        check_collection(name)?;
        let st = self.inner.st.lock();
        st.members_in_force(name)
            .ok_or_else(|| DataError::NotReady {
                name: name.clone(),
                why: format!(
                    "no members record over {name} is held here: a device of its namespace \
                     shares it first (share_folder, or share); any other device follows or \
                     watches it so that the owner's record is fetched, then asks again"
                ),
            })
    }
}

impl Device {
    /// [`DataLayer::share`] and [`DataLayer::share_folder`]: sign the next
    /// members record of subject `s` — a collection, or a folder governing
    /// every collection under it (spec §6) — owned by this namespace: the
    /// whole content given, or a change to its own record in force,
    /// applied to the record held when it is signed, under the lock it is
    /// signed under (spec §15).
    async fn share_subject(
        &self,
        s: Subject,
        members: crate::layer::Sharing,
    ) -> Result<(), DataError> {
        let inner = &self.inner;
        let name = &s.name;
        check_collection(name)?;
        let ns = namespace_of(name).expect("checked above");
        if ns != inner.ns {
            return Err(DataError::NotOwner {
                collection: name.clone(),
            });
        }
        let own_record = |st: &St| match s.folder {
            true => st.folders.get(name).and_then(|f| f.line.own.clone()),
            false => st.colls.get(name).and_then(|c| c.line.own.clone()),
        };
        // What it would sign over the record held now: refused early, and
        // the writers it removes walked below. Resolved again under the
        // lock it is signed under.
        let Some(crate::layer::Share { writers, .. }) = ({
            let current = own_record(&inner.st.lock());
            inner.resolve_share(name, current.as_ref(), &members)?
        }) else {
            return Ok(());
        };
        // What lies under the subject is looked at: every device known to
        // write into the namespace, walked for at most the first-look time.
        inner.look(name).await?;
        // A record removing a writer cuts over exactly what is held here of
        // its keys (spec §8): every device of those writers known here that
        // was not walked yet is walked first, as far as it is reachable
        // within the first-look time, so what it lists under the subject is
        // held. What a device not reached holds falls outside the cut: a
        // removed writer cannot hold its own removal off by staying away.
        let removed = {
            let st = inner.st.lock();
            st.removing(name, own_record(&st).as_ref(), &writers)
        };
        if !removed.is_empty() {
            let missing = inner
                .unsynced(
                    &ns,
                    |d| removed.iter().any(|p| d.has_prefix(p) || p.has_prefix(d)),
                    |t| name.has_prefix(t),
                )
                .await;
            if !missing.is_empty() {
                tracing::warn!(subject = %name, folder = s.folder, devices = ?missing, "a record removing a writer is signed over what is held: these devices of the writers it removes were not reached, and what only they hold falls outside its cut");
            }
        }
        // The manifests of the cuts it carries over are held first: it binds
        // what they keep by the bytes they list (spec §8).
        let carried: BTreeSet<Name> = {
            let st = inner.st.lock();
            let current = own_record(&st);
            let folders = st.folders_above(name);
            current
                .iter()
                .chain(folders.iter().copied())
                .flat_map(|m| m.cuts.iter())
                .flat_map(|k| k.accept.all_manifests())
                .cloned()
                .collect()
        };
        for root in &carried {
            if !inner.hold_cut_tree(root).await {
                tracing::debug!(subject = %name, %root, "a carried cut's manifest is not held whole");
            }
        }
        let before = inner.groups_of(&inner.st.lock(), name);
        let dropped = {
            let mut st = inner.st.lock();
            // Resolved over the record held now: a change keeps what was
            // added since it was asked (an introduction's admission, a
            // record of another device of the owner).
            let current = own_record(&st);
            let Some(crate::layer::Share {
                rule,
                writers,
                readers,
            }) = inner.resolve_share(name, current.as_ref(), &members)?
            else {
                return Ok(());
            };
            if !s.folder {
                widens(&st, name, &writers, &readers)?;
            }
            let record =
                inner.next_members(&st, &s, current.as_ref(), rule, writers, readers, false);
            // The namespaces this record removes, as writers or readers.
            let dropped: Vec<Name> = current
                .iter()
                .flat_map(|m| {
                    let writers = m
                        .writers
                        .iter()
                        .filter(|w| !record.0.writers.contains(w))
                        .cloned();
                    let readers = m.readers.iter().filter_map(|r| match r {
                        Audience::Person(p) if !record.0.readers.contains(r) => Some(p.clone()),
                        _ => None,
                    });
                    writers.chain(readers).collect::<Vec<_>>()
                })
                .collect();
            inner.append_members(&mut st, name, record)?;
            dropped
        };
        inner.publish_about(name, &before).await?;
        // An introduced member removed never comes back by its code: the
        // offers it used are closed (spec §19.7).
        if s.folder {
            inner.close_used_by(name, &dropped).await;
        }
        // A collection sealed to this one as a group moves to a new epoch
        // with it, and a merge this record left unresolved is resolved; so
        // does a collection with readers of its own that a folder record
        // dropped one of.
        inner.settle().await;
        Ok(())
    }
}

impl Inner {
    /// The rule, writers and readers a record of `name` signs for
    /// `members` over `current`, its own record in force (spec §15): the
    /// whole content given, or `current` changed. `None` when a change
    /// changes nothing: nothing is signed.
    fn resolve_share(
        &self,
        name: &Name,
        current: Option<&Members>,
        members: &crate::layer::Sharing,
    ) -> Result<Option<crate::layer::Share>, DataError> {
        let bad = |why: String| DataError::BadRequest {
            name: name.clone(),
            why,
        };
        let change = match members {
            crate::layer::Sharing::Whole(share) => {
                return Ok(Some(crate::layer::Share {
                    rule: share.rule.clone(),
                    writers: share.writers.clone(),
                    readers: share.readers.clone(),
                }));
            }
            crate::layer::Sharing::Change(change) => change,
        };
        let Some(m) = current else {
            return Err(DataError::NotReady {
                name: name.clone(),
                why: "no members record of it is held here, so there is nothing to change: \
                      share it whole first, or bring online the device of its namespace that \
                      signed one and ask again"
                    .into(),
            });
        };
        let mut writers = m.writers.clone();
        for w in &change.remove_writers {
            if let Some(i) = writers.iter().position(|x| x == w) {
                writers.remove(i);
            } else if let Some(p) = writers.iter().find(|p| w.has_prefix(p)) {
                return Err(bad(format!(
                    "writer {w} is not listed, and {p}, which is listed, covers it: remove {p}, \
                     or share the record whole"
                )));
            }
        }
        for w in &change.add_writers {
            if !writers.iter().any(|p| w.has_prefix(p)) {
                writers.push(w.clone());
            }
        }
        let sealed = !m.readers.is_empty();
        let mut readers = m.readers.clone();
        for r in &change.remove_readers {
            if let Some(i) = readers.iter().position(|x| x == r) {
                readers.remove(i);
            } else if collection::admitted(r, &readers) {
                return Err(bad(format!(
                    "reader {r:?} is not listed, and a reader listed admits it: remove that \
                     reader, or share the record whole"
                )));
            }
        }
        // Not sealed, every reader reads already.
        if sealed {
            for r in &change.add_readers {
                if !collection::admitted(r, &readers) {
                    readers.push(r.clone());
                }
            }
        }
        if writers.is_empty() && !m.writers.is_empty() {
            return Err(bad(
                "the change leaves no writer, and a record listing none takes the writers of \
                 the folders above it: share the record whole to mean that"
                    .into(),
            ));
        }
        if sealed && readers.is_empty() {
            return Err(bad(
                "the change leaves no reader, which unseals it for everyone: share the record \
                 whole to mean that"
                    .into(),
            ));
        }
        if writers == m.writers && readers == m.readers {
            return Ok(None);
        }
        Ok(Some(crate::layer::Share {
            rule: m.rule.clone(),
            writers,
            readers,
        }))
    }
}

/// Refuse a record of collection `c` listing `writers` and `readers` that
/// would widen the folders in force above it (spec §6): a writer their
/// writers do not cover, or a reader their readers do not admit. Under a
/// folder a collection only narrows; what widens has no effect, so it is
/// refused rather than signed.
fn widens(st: &St, c: &Name, writers: &[Name], readers: &[Audience]) -> Result<(), DataError> {
    let folders = st.folders_above(c);
    let Some(nearest) = folders.first().map(|f| f.collection.clone()) else {
        return Ok(());
    };
    let over = collection::effective(c, None, &folders).expect("a folder is above");
    let mut wide: Vec<String> = writers
        .iter()
        .filter(|w| !over.writers.iter().any(|p| w.has_prefix(p)))
        .map(|w| format!("writer {w}, which its writers do not cover"))
        .collect();
    if over.epoch.is_some() {
        wide.extend(
            readers
                .iter()
                .filter(|r| !collection::admitted(r, &over.readers))
                .map(|r| format!("reader {r:?}, whom its readers do not admit")),
        );
    }
    if wide.is_empty() {
        return Ok(());
    }
    Err(DataError::BadRequest {
        name: c.clone(),
        why: format!(
            "{c} is under folder {nearest}, whose members record governs it: this record would \
             widen it with {}, and under a folder a collection only narrows; list only what the \
             folder admits, or share the folder {nearest} (share_folder) to widen it",
            wide.join(", ")
        ),
    })
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
        validator.adopt_context(context("/rita")).unwrap();
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

    /// Start `device` on a forwarder that delivers nothing, its wall clock
    /// reading `clock`.
    async fn start_at(
        device: &Name,
        keys: &Arc<SecurityManager>,
        validator: &Arc<Validator>,
        store: &Arc<dyn DataStore>,
        clock: &Arc<AtomicU64>,
    ) -> Result<Device, DataError> {
        start_at_on(device, keys, validator, store, clock, Arc::new(Unconnected)).await
    }

    /// [`start_at`], on the forwarder `conn`.
    async fn start_at_on(
        device: &Name,
        keys: &Arc<SecurityManager>,
        validator: &Arc<Validator>,
        store: &Arc<dyn DataStore>,
        clock: &Arc<AtomicU64>,
        conn: Arc<dyn Connection>,
    ) -> Result<Device, DataError> {
        let read = Arc::clone(clock);
        Device::start(
            Transport {
                node: Node::from_connection(Arc::clone(&conn)),
                sync: conn,
            },
            device.clone(),
            Arc::clone(keys),
            Arc::clone(validator),
            Arc::clone(store),
            Config {
                clock: Arc::new(move || Timestamp(read.load(Ordering::Relaxed))),
                ..Config::new()
            },
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
        validator.adopt_context(context("/home")).unwrap();
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        assert_eq!(dev.namespace(), &n("/home"));
        dev.shutdown();
        // The longest held namespace governs it.
        validator.adopt_context(context("/home/bob")).unwrap();
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        assert_eq!(dev.namespace(), &n("/home/bob"));
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_store_with_records_of_a_deleted_family_still_starts() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/alice")).unwrap();
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        for kind in [
            "answers",
            "answer-results",
            "answer-evidence",
            "events",
            "host",
            "expired",
            "pruned",
            "erased",
            "erased-folder",
            "batched",
        ] {
            for rest in ["x", "x/y"] {
                store.insert(
                    n(&format!("/localhost/ndn-data/{kind}/{rest}")),
                    Bytes::from_static(b"\xff\x00 not a record of anything"),
                );
            }
        }
        let dev = start(&device, &keys_of(&device), &validator, &store)
            .await
            .expect("records of a family this build no longer has are inert");
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_name_without_its_marker_is_refused_with_how_to_name_it() {
        let device = n("/home/bob/member/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/home/bob")).unwrap();
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
        };
        let share = crate::layer::Share {
            rule: Rule::Merge {
                function: n(crate::merge::NEWEST),
            },
            writers: vec![n("/home/bob")],
            readers: Vec::new(),
        };
        let refusals = [
            dev.put(&unmarked, Content::new(), options()).await.err(),
            dev.get(&unmarked).await.err(),
            dev.watch(&unmarked, &Frontier::new()).await.err(),
            dev.share(&unmarked, share.clone()).await.err(),
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
        // Whether `device` (its key `<device>/KEY/1`) signing a members
        // record about `collection` is an owner, by `keyring`.
        let signed = |keyring: &Keyring, device: &str, collection: &str| {
            let c = n(collection);
            let entry = log_name(&n(device), Some(&c), 1);
            let writer = Writer::new(n(device).append("KEY").append("1"));
            owner_signed(keyring, &entry, &c, &writer)
        };
        let both = Keyring::new();
        both.adopt(context("/home")).unwrap();
        both.adopt(context("/home/bob")).unwrap();
        // A /home/bob device lies under /home, but /home/bob governs it.
        let laptop = "/home/bob/member/laptop";
        assert!(!signed(&both, laptop, "/home/32=data/x"));
        assert!(signed(&both, laptop, "/home/bob/32=data/x"));
        let hub = "/home/member/hub";
        assert!(signed(&both, hub, "/home/32=data/x"));
        assert!(!signed(&both, hub, "/home/bob/32=data/x"));
        // A device of another namespace is no owner, whatever is held.
        assert!(!signed(&both, "/alice/laptop", "/home/32=data/x"));
        // Held alone, /home governs every device under it.
        let only_home = Keyring::new();
        only_home.adopt(context("/home")).unwrap();
        assert!(signed(&only_home, laptop, "/home/32=data/x"));
        assert!(!signed(&only_home, laptop, "/home/bob/32=data/x"));
        // No context held: nobody owns anything.
        assert!(!signed(&Keyring::new(), hub, "/home/32=data/x"));
    }

    #[tokio::test]
    async fn a_reader_takes_members_records_only_from_the_namespaces_own_devices() {
        let reader = n("/home/member/hub");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/home")).unwrap();
        validator.adopt_context(context("/home/bob")).unwrap();
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let take = |signer: &str, collection: &str| {
            let (device, c) = (n(signer), n(collection));
            let body = MembersBody {
                collection: c.clone(),
                folder: false,
                revision: 1,
                rule: Rule::Merge {
                    function: n(crate::merge::NEWEST),
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
            validator.adopt_context(context(ns)).unwrap();
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
        }
    }

    fn version_body(c: &Name, sealed: Option<SealedBody>) -> VersionBody {
        VersionBody {
            collection: c.clone(),
            parents: Parents::new(),
            type_id: crate::TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            seal: Seal { any_of: Vec::new() },
            keep: crate::Keep::Forever,
            dated: Timestamp(1),
            rule: None,
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
        // A key is granted once the record starting its epoch is durable.
        dev.inner.flushed().await;
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
        dev.inner.flushed().await;
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
            folder: false,
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
            validator.adopt_context(context(ns)).unwrap();
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
            assert!(!cut.refuses(&c, &id(40)) && !cut.refuses(&c, &id(100)));
            assert!(cut.refuses(&c, &id(70)), "a seq only a summary listed");
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
        validator.adopt_context(context("/alice")).unwrap();
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
        validator.adopt_context(context("/alice")).unwrap();
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
            folder: false,
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
            assert_eq!(coll.line.resolve, Resolve::Epoch);
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
            assert_eq!(st.colls[&c].line.resolve, Resolve::Nothing);
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

    /// A merge of concurrent records can list a reader that none of the
    /// records naming the epoch it keeps lists (the phone removes Bob, in
    /// an epoch of its own, while the laptop adds Carol): that epoch's key
    /// goes to the readers those records list, never to Carol, so a version
    /// sealed in it stays closed to her for good, though the record in
    /// force lists her. Until the record resolving the merge is held, no
    /// writer seals in it: `put` answers `NotReady` (`RetryLater`) and signs
    /// nothing; once it is held, in the new epoch, `put` writes.
    #[tokio::test]
    async fn nothing_is_sealed_in_an_epoch_a_merge_lists_a_reader_outside_of() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/alice")).unwrap();
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/plan");
        let person = |s: &str| Audience::Person(n(s));
        let put = || {
            dev.put(
                &c,
                Content::new().with("text", Bytes::from_static(b"budget")),
                PutOptions {
                    type_id: crate::TypeId {
                        name: n("/types/note"),
                        revision: 1,
                    },
                    keep: crate::Keep::Forever,
                },
            )
        };
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
        put()
            .await
            .expect("the epoch of the record in force admits its readers");
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
        put()
            .await
            .expect("a record that only adds a reader keeps the epoch and names it");
        let phone = n("/alice/phone");
        let removed_in = Epoch {
            creator: phone.clone(),
            seq: Seq(1),
        };
        let key = ContentKey::generate();
        let removes = MembersBody {
            collection: c.clone(),
            folder: false,
            revision: 2,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: vec![person("/alice")],
            cuts: vec![CutBody {
                of: n("/bob"),
                accept: Accepted::new(),
            }],
            epoch: Some(removed_in.clone()),
            key_check: Some(seal::key_check(&key, &c, &removed_in)),
            since: None,
            parent: Some(first.as_parent()),
        };
        assert_eq!(hand(&dev, &phone, &c, 1, Record::Members(removes)), None);
        {
            let mut st = dev.inner.st.lock();
            let m = st.colls[&c].members.clone().unwrap();
            assert_eq!(m.epoch.as_ref(), Some(&removed_in));
            assert_eq!(m.readers, vec![person("/alice"), person("/carol")]);
            st.keys.hold(c.clone(), removed_in.clone(), key);
        }
        // The merge lists Carol; the epoch it keeps is not hers.
        let head = dev.inner.st.lock().head;
        let refused = put().await;
        assert!(
            matches!(refused, Err(DataError::NotReady { .. })),
            "nothing is sealed in an epoch the record in force lists a reader outside of: \
             {refused:?}"
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.to_string().contains("/alice/phone")),
            "the message names the device that created the epoch it waits for, which the \
             owner brings online: {refused:?}"
        );
        assert_eq!(dev.inner.st.lock().head, head, "nothing was signed");
        // The laptop resolves the merge, in a new epoch Carol is of: it writes.
        dev.inner.settle().await;
        put()
            .await
            .expect("the resolved record's epoch lists every reader of the merge");
        dev.shutdown();
    }

    /// The round-3 review's M5: the laptop removes Carol at revision 2,
    /// with a cut; the phone, offline, admits Dave at revision 2, then Eve
    /// at revision 3 on top of its own revision 2, listing Carol and no cut.
    /// Every reader, whatever order the four records reach it in, ends with
    /// one record in force: Carol removed, her versions refused outside the
    /// cut, Dave and Eve admitted.
    #[tokio::test]
    async fn a_removal_wins_across_revisions_whatever_order_the_records_arrive_in() {
        use sha2::{Digest, Sha256};
        let c = n("/alice/32=data/plan");
        let (laptop, phone) = (n("/alice/laptop"), n("/alice/phone"));
        let record = |revision: u64, writers: &[&str], cut: bool, parent: Option<&MembersBody>| {
            MembersBody {
                collection: c.clone(),
                folder: false,
                revision,
                rule: Rule::Log,
                writers: writers.iter().map(|w| n(w)).collect(),
                readers: Vec::new(),
                cuts: match cut {
                    true => vec![CutBody {
                        of: n("/carol"),
                        accept: Accepted::new(),
                    }],
                    false => Vec::new(),
                },
                epoch: None,
                key_check: None,
                since: None,
                parent: parent.map(|p| collection::Parent {
                    revision: Seq(p.revision),
                    digest: Sha256::digest(wire::encode_members(p)).into(),
                }),
            }
        };
        let first = record(1, &["/alice", "/carol"], false, None);
        let removes = record(2, &["/alice"], true, Some(&first));
        let admits = record(2, &["/alice", "/carol", "/dave"], false, Some(&first));
        let joins = record(
            3,
            &["/alice", "/carol", "/dave", "/eve"],
            false,
            Some(&admits),
        );
        let records = [
            (&laptop, 1, first),
            (&laptop, 2, removes),
            (&phone, 1, admits),
            (&phone, 2, joins),
        ];
        every_order_removes_carol(&c, &records, &["/alice", "/dave", "/eve"]).await;
    }

    /// Hand `records` (signer device, seq, body) of `c` to a fresh reader
    /// in every order: each reader ends with one record in force, whose
    /// writers are exactly `wanted` and whose one cut is Carol's — her
    /// version refused outside it, a version of every other writer
    /// admitted.
    async fn every_order_removes_carol(
        c: &Name,
        records: &[(&Name, u64, MembersBody)],
        wanted: &[&str],
    ) {
        let wanted: BTreeSet<Name> = wanted.iter().map(|w| n(w)).collect();
        let count = records.len();
        let mut seen: Option<Members> = None;
        for k in 0..(1..=count).product::<usize>() {
            let mut left: Vec<usize> = (0..count).collect();
            let mut order = Vec::with_capacity(count);
            let mut rest = k;
            for radix in (1..=count).rev() {
                order.push(left.remove(rest % radix));
                rest /= radix;
            }
            let dev = device_in("/bob/laptop", &["/alice", "/bob"]).await;
            for &i in &order {
                let (device, seq, body) = &records[i];
                assert_eq!(
                    hand(&dev, device, c, *seq, Record::Members(body.clone())),
                    None
                );
            }
            let m = dev.inner.st.lock().colls[c].members.clone().unwrap();
            assert_eq!(
                m.writers.iter().cloned().collect::<BTreeSet<_>>(),
                wanted,
                "arrival order {order:?}"
            );
            assert_eq!(
                m.cuts.iter().map(|k| &k.of).collect::<Vec<_>>(),
                [&n("/carol")],
                "arrival order {order:?}"
            );
            let version = Record::Version(version_body(c, None));
            let carol = hand(&dev, &n("/carol/phone"), c, 1, version.clone());
            assert!(
                matches!(&carol, Some(Refusal::OutsideCut(k)) if k.of == n("/carol")),
                "arrival order {order:?}: {carol:?}"
            );
            for w in wanted.iter().filter(|w| **w != n("/alice")) {
                let device = w.clone().append("phone");
                assert_eq!(hand(&dev, &device, c, 1, version.clone()), None);
            }
            match &seen {
                Some(s) => assert_eq!(&m, s, "arrival order {order:?}: one record in force"),
                None => seen = Some(m),
            }
            dev.shutdown();
        }
    }

    /// M5 with three owner devices: the laptop removes Carol at revision 2
    /// while the phone admits Dave and the tablet Frank; the phone, holding
    /// its own record and the tablet's but not the laptop's, signs revision
    /// 3 for Eve over the merge of those two. Its parent is a merge of some
    /// of the records of revision 2, which every reader finds among the
    /// merges of their subsets: Carol stays removed, and Dave, Frank and
    /// Eve are admitted, whatever order the five records arrive in.
    #[tokio::test]
    async fn a_record_over_a_merge_of_some_records_of_a_revision_keeps_its_additions() {
        use sha2::{Digest, Sha256};
        let c = n("/alice/32=data/plan");
        let (laptop, phone, tablet) = (n("/alice/laptop"), n("/alice/phone"), n("/alice/tablet"));
        let record = |revision: u64,
                      writers: &[&str],
                      cut: bool,
                      parent: Option<collection::Parent>| MembersBody {
            collection: c.clone(),
            folder: false,
            revision,
            rule: Rule::Log,
            writers: writers.iter().map(|w| n(w)).collect(),
            readers: Vec::new(),
            cuts: match cut {
                true => vec![CutBody {
                    of: n("/carol"),
                    accept: Accepted::new(),
                }],
                false => Vec::new(),
            },
            epoch: None,
            key_check: None,
            since: None,
            parent,
        };
        let of = |p: &MembersBody| {
            Some(collection::Parent {
                revision: Seq(p.revision),
                digest: Sha256::digest(wire::encode_members(p)).into(),
            })
        };
        let first = record(1, &["/alice", "/carol"], false, None);
        let removes = record(2, &["/alice"], true, of(&first));
        let admits = record(2, &["/alice", "/carol", "/dave"], false, of(&first));
        let frank = record(2, &["/alice", "/carol", "/frank"], false, of(&first));
        // The phone's record in force when it signs revision 3: the merge of
        // its record and the tablet's.
        let over = {
            let dev = device_in("/bob/laptop", &["/alice", "/bob"]).await;
            for (device, seq, body) in [
                (&laptop, 1, &first),
                (&phone, 1, &admits),
                (&tablet, 1, &frank),
            ] {
                assert_eq!(
                    hand(&dev, device, &c, seq, Record::Members(body.clone())),
                    None
                );
            }
            let own = dev.inner.st.lock().colls[&c].line.own.clone().unwrap();
            dev.shutdown();
            own
        };
        let joins = record(
            3,
            &["/alice", "/carol", "/dave", "/frank", "/eve"],
            false,
            Some(over.as_parent()),
        );
        let records = [
            (&laptop, 1, first),
            (&laptop, 2, removes),
            (&phone, 1, admits),
            (&tablet, 1, frank),
            (&phone, 2, joins),
        ];
        every_order_removes_carol(&c, &records, &["/alice", "/dave", "/frank", "/eve"]).await;
    }

    fn upto(key: &str, seq: u64) -> Frontier {
        [VersionId {
            writer: Writer::new(n(key)),
            seq: Seq(seq),
        }]
        .into_iter()
        .collect()
    }

    /// A date no test reaches.
    const LATER: Timestamp = Timestamp(u64::MAX / 2);

    /// What [`Asks`] answers the `n`th ask (from 0) of the holder's name
    /// with: `None`, the ask or its answer is lost.
    type Answering = Box<dyn Fn(&Name, usize) -> Option<Bytes> + Send + Sync>;

    /// A forwarder that carries only the Interests under device `holder`'s
    /// name: each is recorded and answered as `answer` says; nothing else
    /// arrives.
    struct Asks {
        holder: Name,
        asked: std::sync::Mutex<Vec<Name>>,
        answer: Answering,
        tx: futures::channel::mpsc::UnboundedSender<Bytes>,
        rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
    }

    impl Asks {
        fn new(holder: &Name, answer: Answering) -> Arc<Self> {
            let (tx, rx) = futures::channel::mpsc::unbounded();
            Arc::new(Asks {
                holder: holder.clone(),
                asked: std::sync::Mutex::new(Vec::new()),
                answer,
                tx,
                rx: futures::lock::Mutex::new(rx),
            })
        }

        fn asked(&self) -> Vec<Name> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Connection for Asks {
        async fn send(&self, wire: Bytes) -> Result<(), AppError> {
            let Ok(interest) = Interest::decode(wire) else {
                return Ok(());
            };
            let name = (*interest.name).clone();
            if !name.has_prefix(&self.holder) {
                return Ok(());
            }
            let nth = {
                let mut asked = self.asked.lock().unwrap();
                asked.push(name.clone());
                asked.len() - 1
            };
            if let Some(reply) = (self.answer)(&name, nth) {
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

    /// A namespace authority for `ns`: its key store, its key and the
    /// trust anchor a validator takes.
    async fn authority(ns: &Name) -> (SecurityManager, Name, ndn_security::Certificate) {
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
        (authority, issuer, anchor)
    }

    /// A packet named `name` carrying `content`, signed by `key`; and its
    /// signature value.
    fn signed(keys: &SecurityManager, key: &Name, name: &Name, content: &Bytes) -> (Bytes, Bytes) {
        let signer = keys.get_signer_sync(key).unwrap();
        let mut sig = Bytes::new();
        let wire = DataBuilder::new(name.clone(), content).sign_sync(
            signer.sig_type(),
            Some(key),
            |region| {
                sig = signer.sign_sync(region).unwrap();
                sig.clone()
            },
        );
        (wire, sig)
    }

    /// The order of the P-256 group.
    const P256_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    /// The `(r, s)` of a DER ECDSA signature, each as 32 octets big-endian.
    fn der_scalars(der: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(der[0], 0x30, "a DER sequence");
        assert_eq!(der[1] as usize + 2, der.len(), "a short-form length");
        let mut at = 2;
        let mut out = [[0u8; 32]; 2];
        for scalar in &mut out {
            assert_eq!(der[at], 0x02, "a DER integer");
            let len = der[at + 1] as usize;
            let int = &der[at + 2..at + 2 + len];
            let int = int.strip_prefix(&[0u8][..]).unwrap_or(int);
            scalar[32 - int.len()..].copy_from_slice(int);
            at += 2 + len;
        }
        assert_eq!(at, der.len());
        (out[0], out[1])
    }

    /// `n - s`, the other `S` that verifies with the same `r`.
    fn other_s(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = P256_ORDER[i] as i16 - s[i] as i16 - borrow;
            borrow = i16::from(d < 0);
            out[i] = d.rem_euclid(256) as u8;
        }
        out
    }

    fn der_ecdsa(r: &[u8; 32], s: &[u8; 32]) -> Bytes {
        let int = |x: &[u8; 32]| {
            let start = x.iter().position(|b| *b != 0).unwrap_or(31);
            let mut v = Vec::new();
            if x[start] & 0x80 != 0 {
                v.push(0);
            }
            v.extend_from_slice(&x[start..]);
            let mut out = vec![0x02, v.len() as u8];
            out.extend(v);
            out
        };
        let mut body = int(r);
        body.extend(int(s));
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        Bytes::from(der)
    }

    #[tokio::test]
    async fn a_high_s_copy_of_a_held_ecdsa_entry_is_not_an_equivocation() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let sensor_keys = Arc::new(SecurityManager::new());
        let key = sensor_keys
            .generate_ecdsa_p256(sensor.clone().append("KEY").append("1"))
            .unwrap();
        let public = sensor_keys
            .get_signer_sync(&key)
            .unwrap()
            .public_key()
            .unwrap();
        let cert = authority
            .certify(&key, public, &issuer, VALIDITY_MS)
            .await
            .unwrap();
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        validator.adopt_context(context("/rita")).unwrap();
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let a = log_name(&sensor, Some(&c), 4);
        let content = wire::encode_version(&version_body(&c, None));

        // What this crate's own signer guarantees: it does not normalise S (the `ecdsa` crate's
        // RFC 6979 signing keeps whichever S it computes), so about half of its signatures are
        // high-S, and every verifier accepts both: malleability is in the signature value only.
        let signer = sensor_keys.get_signer_sync(&key).unwrap();
        let high_s = |sig: &[u8]| {
            let (_, s) = der_scalars(sig);
            s > other_s(&s)
        };
        let mut seen = [0usize; 2];
        for i in 0..32u8 {
            seen[usize::from(high_s(&signer.sign_sync(&[i; 16]).unwrap()))] += 1;
        }
        assert!(
            seen[0] > 0 && seen[1] > 0,
            "the signer's S is not normalised: {seen:?} (low, high)"
        );

        let (original, sig) = signed(&sensor_keys, &key, &a, &content);
        let (r, s) = der_scalars(&sig);
        let flipped = der_ecdsa(&r, &other_s(&s));
        assert_ne!(flipped, sig, "n - s is another signature value");
        let copy =
            DataBuilder::new(a.clone(), &content)
                .sign_sync(signer.sig_type(), Some(&key), |_| flipped.clone());
        let (orig_d, copy_d) = (
            Data::decode(original.clone()).unwrap(),
            Data::decode(copy.clone()).unwrap(),
        );
        assert_eq!(orig_d.signed_region(), copy_d.signed_region());
        assert_ne!(
            wire::implicit_digest(&original),
            wire::implicit_digest(&copy),
            "the copy is another packet"
        );

        dev.inner
            .take_data(&a, orig_d)
            .await
            .expect("the original is taken");
        assert!(matches!(
            dev.inner.st.lock().held.get(&a),
            Some(Held::Version(_))
        ));
        dev.inner
            .take_data(&a, copy_d)
            .await
            .expect("the copy verifies: S is malleable and the verifier accepts both");
        assert!(
            dev.inner.st.lock().twins.is_empty() && store.get(&equivocal_name(&a)).is_none(),
            "no second packet is kept as evidence"
        );

        // Another content signed at the name is equivocation, as before.
        let other = wire::encode_version(&VersionBody {
            fields: Content::new().with("t", "another"),
            ..version_body(&c, None)
        });
        let (second, _) = signed(&sensor_keys, &key, &a, &other);
        dev.inner
            .take_data(&a, Data::decode(second).unwrap())
            .await
            .expect("verified");
        assert!(
            dev.inner.st.lock().twins.contains_key(&a) && store.get(&equivocal_name(&a)).is_some(),
            "two contents signed at one name are equivocation: the second is kept as evidence"
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_packet_from_the_wrong_signer_does_not_refuse_its_name() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let (sensor_keys, key, cert) = device_key(&authority, &issuer, &sensor).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        validator.adopt_context(context("/rita")).unwrap();
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let a = log_name(&sensor, Some(&c), 4);
        let content = wire::encode_version(&version_body(&c, None));
        // A key the trust schema accepts for the name, yet not the
        // sensor's: whoever answers the Interest signs that exact name.
        let (impostor, _) = signed(&authority, &issuer, &a, &content);
        let taken = dev
            .inner
            .take_data(&a, Data::decode(impostor).unwrap())
            .await;
        assert!(taken.is_err(), "a packet its name's device did not sign");
        assert!(
            !dev.inner.st.lock().refused.contains_key(&a),
            "the packet is refused, not the name"
        );
        let (genuine, _) = signed(&sensor_keys, &key, &a, &content);
        dev.inner
            .take_data(&a, Data::decode(genuine).unwrap())
            .await
            .expect("the genuine copy, from the next source, is taken");
        let st = dev.inner.st.lock();
        assert!(st.held.contains_key(&a) && !st.refused.contains_key(&a));
        drop(st);
        dev.shutdown();
    }

    /// An entry its writer signed that this build cannot read (a kind of an
    /// earlier release) is that writer's own, verified: it is recorded against
    /// its name as refused for what it carries and skipped, so a walk that
    /// lists it completes and the writer's later versions do not wait for it
    /// for good.
    #[tokio::test]
    async fn a_verified_entry_this_build_cannot_read_is_skipped_not_waited_for() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let (sensor_keys, key, cert) = device_key(&authority, &issuer, &sensor).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        validator.adopt_context(context("/rita")).unwrap();
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let (first, second) = (
            log_name(&sensor, Some(&c), 1),
            log_name(&sensor, Some(&c), 2),
        );
        // A hold of an earlier release, signed by the sensor's key.
        let unread = Bytes::from_static(&[0xFD, 0x05, 0x25, 0x01, 0x00]);
        assert!(wire::decode_record(unread.clone()).is_err());
        let (packet, _) = signed(&sensor_keys, &key, &first, &unread);
        dev.inner
            .take_data(&first, Data::decode(packet).unwrap())
            .await
            .expect("a verified entry its writer signed is recorded, not dropped as a packet");
        let writer = Writer::new(key.clone());
        {
            let st = dev.inner.st.lock();
            assert!(
                st.refused.contains_key(&first),
                "refused for what it carries"
            );
            let waits = st.colls[&c].waits(&c);
            let id = |seq| VersionId {
                writer: writer.clone(),
                seq: Seq(seq),
            };
            assert!(waits.never(&id(1)), "nothing waits for it");
            assert!(!waits.never(&id(2)), "only it is skipped");
        }
        // The writer's next version is taken as any other.
        let content = wire::encode_version(&version_body(&c, None));
        let (next, _) = signed(&sensor_keys, &key, &second, &content);
        dev.inner
            .take_data(&second, Data::decode(next).unwrap())
            .await
            .expect("its later version is taken");
        assert!(dev.inner.st.lock().held.contains_key(&second));
        dev.shutdown();
    }

    fn reading(t: u64) -> Content {
        Content::new().with("t", Bytes::from(t.to_string()))
    }

    fn options() -> PutOptions {
        PutOptions {
            type_id: crate::TypeId {
                name: n("/types/reading"),
                revision: 1,
            },
            keep: Keep::Forever,
        }
    }

    // ---- revocation as a cut (spec §8) ---------------------------------------------------------

    /// `/sam`'s trust context at `version`, anchored at `anchor`, revoking
    /// the key of `cut` with it.
    fn sam_context(
        anchor: &ndn_security::Certificate,
        version: u64,
        cut: Option<RevocationCut>,
    ) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(n("/sam")).with_version(version);
        if let Some(cut) = cut {
            ctx = ctx
                .with_revocation(cut.key().clone())
                .with_revocation_cut(cut);
        }
        assert!(ctx.add_anchor(anchor.clone()));
        Arc::new(ctx)
    }

    /// Wait until `done` holds of `dev`'s state.
    async fn until(dev: &Device, done: impl Fn(&St) -> bool) {
        for _ in 0..500 {
            if done(&dev.inner.st.lock()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the device did not take the adopted trust context in time");
    }

    /// A reader `/rita/tab` owning the log collection `/rita/32=data/notes`,
    /// which `/sam` writes into; it holds `/sam`'s trust context, whose
    /// device `/sam/phone` writes.
    struct Revoking {
        dev: Device,
        tab_keys: Arc<SecurityManager>,
        validator: Arc<Validator>,
        store: Arc<dyn DataStore>,
        anchor: ndn_security::Certificate,
        cert: ndn_security::Certificate,
        phone: Name,
        phone_keys: Arc<SecurityManager>,
        key: Name,
        c: Name,
        /// The reader's wall clock.
        clock: Arc<AtomicU64>,
    }

    impl Revoking {
        /// The phone's certificate is valid `validity_ms` from now.
        async fn new(validity_ms: u64) -> Self {
            Self::new_on(validity_ms, Arc::new(Unconnected)).await
        }

        /// [`Self::new`], the reader on the forwarder `conn`.
        async fn new_on(validity_ms: u64, conn: Arc<dyn Connection>) -> Self {
            Self::new_for(n("/sam/phone"), validity_ms, conn).await
        }

        /// [`Self::new_on`] for a writer device named `phone`.
        async fn new_for(phone: Name, validity_ms: u64, conn: Arc<dyn Connection>) -> Self {
            let (authority, issuer, anchor) = authority(&n("/sam")).await;
            let phone_keys = Arc::new(SecurityManager::new());
            let key = phone_keys
                .generate_ed25519(phone.clone().append("KEY").append("1"))
                .unwrap();
            let public = phone_keys
                .get_signer_sync(&key)
                .unwrap()
                .public_key()
                .unwrap();
            let cert = authority
                .certify(&key, public, &issuer, validity_ms)
                .await
                .unwrap();
            let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
            validator.adopt_context(context("/rita")).unwrap();
            validator
                .adopt_context(sam_context(&anchor, 1, None))
                .unwrap();
            validator.cert_cache().insert(cert.clone());
            let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
            let tab = n("/rita/tab");
            let tab_keys = keys_of(&tab);
            let clock = Arc::new(AtomicU64::new(1_000));
            let dev = start_at_on(&tab, &tab_keys, &validator, &store, &clock, conn)
                .await
                .unwrap();
            let c = n("/rita/32=data/notes");
            dev.share(&c, share_of(Rule::Log, &["/rita", "/sam"], Vec::new()))
                .await
                .unwrap();
            Self {
                dev,
                tab_keys,
                validator,
                store,
                anchor,
                cert,
                phone,
                phone_keys,
                key,
                c,
                clock,
            }
        }

        fn writer(&self) -> Writer {
            Writer::new(self.key.clone())
        }

        fn id(&self, seq: u64) -> VersionId {
            VersionId {
                writer: self.writer(),
                seq: Seq(seq),
            }
        }

        /// The phone's version `seq` of `c`, dated `dated`: its name and
        /// packet.
        fn version_of(&self, c: &Name, seq: u64, dated: u64) -> (Name, Data) {
            let name = log_name(&self.phone, Some(c), seq);
            let body = VersionBody {
                dated: Timestamp(dated),
                ..version_body(c, None)
            };
            let (wire, _) = signed(
                &self.phone_keys,
                &self.key,
                &name,
                &wire::encode_record(&Record::Version(body)),
            );
            (name, Data::decode(wire).unwrap())
        }

        fn version(&self, seq: u64, dated: u64) -> (Name, Data) {
            self.version_of(&self.c, seq, dated)
        }

        /// The phone key's cut accepting its `first..=last` in `c`, and
        /// re-admitting exactly `exact`.
        fn cut(&self, first: u64, last: u64, exact: &[Name]) -> RevocationCut {
            let mut cut = RevocationCut::new(self.key.clone());
            cut.add_run(
                &log_prefix(&log_name(&self.phone, Some(&self.c), 0)),
                first,
                last,
            );
            for e in exact {
                cut.readmit(e.clone()).unwrap();
            }
            cut
        }

        /// Adopt `/sam`'s context at `version`, revoking the phone's key
        /// with `cut`.
        fn revoke(&self, version: u64, cut: RevocationCut) {
            self.validator
                .keyring()
                .adopt_update(sam_context(&self.anchor, version, Some(cut)))
                .unwrap();
        }

        fn applied(&self) -> Option<u64> {
            let st = self.dev.inner.st.lock();
            st.colls[&self.c].applied.get(&self.writer()).copied()
        }
    }

    fn outside_cut(got: Result<Answer, DataError>) -> bool {
        matches!(
            got,
            Err(DataError::Refused {
                why: Refusal::OutsideCut(_),
                ..
            })
        )
    }

    #[tokio::test]
    async fn a_revoked_key_is_admitted_exactly_where_its_cut_accepts_whatever_its_date() {
        let r = Revoking::new(VALIDITY_MS).await;
        r.revoke(2, r.cut(1, 2, &[]));
        let (one, d1) = r.version(1, 1_000);
        let (two, d2) = r.version(2, 2_000);
        r.dev
            .inner
            .take_data(&one, d1)
            .await
            .expect("inside the cut");
        r.dev
            .inner
            .take_data(&two, d2)
            .await
            .expect("inside the cut");
        // After the cut, the key signs seq 3 dated before both.
        let (three, d3) = r.version(3, 1);
        let digest = wire::implicit_digest(d3.raw());
        match r.dev.inner.take_data(&three, d3).await {
            Err(Refusal::OutsideCut(cut)) => {
                assert_eq!(cut.of, r.key);
                assert!(
                    cut.accept.contains(&r.c, &r.id(2)) && !cut.accept.contains(&r.c, &r.id(3))
                );
            }
            other => panic!("a version outside the cut: {other:?}"),
        }
        let refused = r.dev.get(&three).await.unwrap_err();
        assert!(outside_cut(Err(refused.clone())), "{refused}");
        assert_eq!(refused.next(), crate::NextStep::AskOwner);
        assert!(!refused.retry());
        assert_eq!(
            r.dev.refused_by_revocation(&r.key),
            vec![three.clone().append_implicit_digest(digest)]
        );
        assert_eq!(r.applied(), Some(2));
        let st = r.dev.inner.st.lock();
        assert!(!st.refused.contains_key(&one) && !st.refused.contains_key(&two));
        drop(st);
        r.dev.shutdown();
    }

    #[tokio::test]
    async fn a_revocation_adopted_later_withdraws_what_its_cut_does_not_accept() {
        let r = Revoking::new(VALIDITY_MS).await;
        let mut packets = Vec::new();
        for seq in 1..=3 {
            let (name, data) = r.version(seq, seq);
            packets.push((name.clone(), wire::implicit_digest(data.raw())));
            r.dev
                .inner
                .take_data(&name, data)
                .await
                .expect("before the revocation");
        }
        assert_eq!(r.applied(), Some(3));
        let mut changes = r
            .dev
            .watch(&r.c, &upto("/sam/phone/KEY/1", 3))
            .await
            .unwrap();
        // The listing starts with the record in force (spec §15).
        assert!(matches!(
            changes.next().await,
            Some(Ok(Change::Members { .. }))
        ));
        r.revoke(2, r.cut(1, 2, &[]));
        let three = packets[2].0.clone();
        until(&r.dev, |st| st.refused.contains_key(&three)).await;
        let change = tokio::time::timeout(Duration::from_secs(5), changes.next())
            .await
            .expect("the watcher is told")
            .expect("the stream is open")
            .unwrap();
        assert!(
            matches!(&change, Change::Withdrawn { collection, id, why: Refusal::OutsideCut(cut) } if *collection == r.c && *id == r.id(3) && cut.of == r.key),
            "{change:?}"
        );
        assert!(outside_cut(r.dev.get(&three).await));
        assert!(r.dev.get(&packets[1].0).await.is_ok(), "inside the cut");
        assert_eq!(r.applied(), Some(2));
        assert_eq!(
            r.dev.refused_by_revocation(&r.key),
            vec![three.clone().append_implicit_digest(packets[2].1)]
        );
        // A restart keeps it withdrawn.
        r.dev.shutdown();
        let again = start(&n("/rita/tab"), &r.tab_keys, &r.validator, &r.store)
            .await
            .unwrap();
        assert!(outside_cut(again.get(&three).await));
        assert_eq!(
            again.inner.st.lock().colls[&r.c].applied.get(&r.writer()),
            Some(&2)
        );
        again.shutdown();
    }

    #[tokio::test]
    async fn an_exact_re_admission_admits_exactly_that_version() {
        let r = Revoking::new(VALIDITY_MS).await;
        r.revoke(2, r.cut(1, 2, &[]));
        let mut full = Vec::new();
        for seq in 1..=4 {
            let (name, data) = r.version(seq, seq);
            full.push(
                name.clone()
                    .append_implicit_digest(wire::implicit_digest(data.raw())),
            );
            let _ = r.dev.inner.take_data(&name, data).await;
        }
        assert_eq!(r.applied(), Some(2));
        let mut changes = r
            .dev
            .watch(&r.c, &upto("/sam/phone/KEY/1", 2))
            .await
            .unwrap();
        // The listing starts with the record in force (spec §15).
        assert!(matches!(
            changes.next().await,
            Some(Ok(Change::Members { .. }))
        ));
        // The owner re-admits seq 3, exactly its bytes.
        r.revoke(3, r.cut(1, 2, &[full[2].clone()]));
        let three = log_name(&r.phone, Some(&r.c), 3);
        let four = log_name(&r.phone, Some(&r.c), 4);
        until(&r.dev, |st| {
            st.held.contains_key(&three) && !st.refused.contains_key(&three)
        })
        .await;
        let change = tokio::time::timeout(Duration::from_secs(5), changes.next())
            .await
            .expect("the watcher is told")
            .expect("the stream is open")
            .unwrap();
        assert!(
            matches!(&change, Change::Version(v) if v.id == r.id(3)),
            "{change:?}"
        );
        assert!(r.dev.get(&three).await.is_ok());
        assert!(
            outside_cut(r.dev.get(&four).await),
            "its neighbour stays out"
        );
        assert_eq!(r.applied(), Some(3));
        assert_eq!(r.dev.refused_by_revocation(&r.key), vec![full[3].clone()]);
        r.dev.shutdown();
    }

    #[tokio::test]
    async fn a_version_whose_certificate_expired_unrevoked_is_admitted() {
        let r = Revoking::new(1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (one, d1) = r.version(1, 1);
        r.dev
            .inner
            .take_data(&one, d1)
            .await
            .expect("a Data's validity never depends on a clock");
        assert_eq!(r.applied(), Some(1));
        r.dev.shutdown();
    }

    #[tokio::test]
    async fn the_cut_a_device_vouches_for_is_exactly_what_it_holds_verified() {
        let r = Revoking::new(VALIDITY_MS).await;
        let (photos, diary) = (n("/rita/32=data/photos"), n("/rita/32=data/diary"));
        r.dev
            .share(&photos, share_of(Rule::Log, &["/rita", "/sam"], Vec::new()))
            .await
            .unwrap();
        r.dev
            .share(&diary, share_of(Rule::Log, &["/rita"], Vec::new()))
            .await
            .unwrap();
        for (c, seq) in [(&r.c, 1), (&r.c, 2), (&photos, 3), (&r.c, 4), (&diary, 5)] {
            let (name, data) = r.version_of(c, seq, seq);
            r.dev.inner.take_data(&name, data).await.unwrap();
        }
        // The diary refuses it (no member); a seq only a summary listed is
        // not held.
        assert_eq!(
            r.dev
                .inner
                .st
                .lock()
                .refused
                .get(&log_name(&r.phone, Some(&diary), 5)),
            Some(&Refusal::NotMember)
        );
        r.dev
            .inner
            .st
            .lock()
            .colls
            .get_mut(&r.c)
            .unwrap()
            .entries
            .entry(r.writer())
            .or_default()
            .insert(6);
        let prefix = |c: &Name| log_prefix(&log_name(&r.phone, Some(c), 0));
        let mut expected = RevocationCut::new(r.key.clone());
        expected.add_run(&prefix(&r.c), 1, 2);
        expected.add_seq(&prefix(&r.c), 4);
        expected.add_seq(&prefix(&photos), 3);
        let bound = CutBound {
            held_before: Some(LATER),
            ..CutBound::default()
        };
        let proposal = r.dev.revocation_cut(&r.key, &bound).unwrap();
        assert_eq!(proposal.cut.ranges(), expected.ranges());
        assert!(proposal.left_out.is_empty());
        assert_eq!(
            proposal.cut.key_digest(),
            Some(&public_key_digest(&r.cert.public_key)),
            "bound to the public key that verified its entries"
        );
        assert!(proposal.cut.manifest().is_some() && !proposal.manifest.is_empty());
        assert_eq!(
            r.dev
                .revocation_cut(&r.cert.name, &bound)
                .unwrap()
                .cut
                .ranges(),
            expected.ranges(),
            "by a certificate name"
        );
        let nothing = r.dev.revocation_cut(&n("/sam/laptop/KEY/1"), &bound);
        assert!(
            matches!(nothing, Err(DataError::BadRequest { .. })),
            "no entry, no certificate held: no public key to bind"
        );
        let unbounded = r.dev.revocation_cut(&r.key, &CutBound::default());
        assert_eq!(
            unbounded.map(|_| ()).unwrap_err().next(),
            crate::NextStep::FixRequest,
            "say when the device was lost"
        );
        r.dev.shutdown();
    }

    #[tokio::test]
    async fn a_writer_serves_its_re_admitted_version_by_name_and_digest() {
        let (authority, issuer, anchor) = authority(&n("/sam")).await;
        let phone = n("/sam/phone");
        let (keys, key, cert) = device_key(&authority, &issuer, &phone).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator
            .adopt_context(sam_context(&anchor, 1, None))
            .unwrap();
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&phone, &keys, &validator, &store).await.unwrap();
        let c = n("/sam/32=data/notes");
        dev.share(&c, share_of(Rule::Log, &["/sam"], Vec::new()))
            .await
            .unwrap();
        let id = dev.put(&c, reading(1), options()).await.unwrap();
        let name = log_name(&phone, Some(&c), id.seq.0);
        // Revoked with a cut that leaves it out: withdrawn here.
        let mut cut = RevocationCut::new(key.clone());
        cut.add_run(&log_prefix(&name), 1, id.seq.0 - 1);
        validator
            .keyring()
            .adopt_update(sam_context(&anchor, 2, Some(cut.clone())))
            .unwrap();
        until(&dev, |st| st.cut_out.contains_key(&name)).await;
        let full = dev.refused_by_revocation(&key);
        assert_eq!(full.len(), 1, "its own version is listed refused");
        // The owner re-admits exactly it.
        cut.readmit(full[0].clone()).unwrap();
        validator
            .keyring()
            .adopt_update(sam_context(&anchor, 3, Some(cut)))
            .unwrap();
        until(&dev, |st| {
            matches!(st.held.get(&name), Some(Held::Version(_))) && !st.refused.contains_key(&name)
        })
        .await;
        let served = dev.inner.packet_for(&full[0], false).expect("served");
        assert_eq!(
            Some(wire::implicit_digest(&served).as_slice()),
            full[0].components().last().map(|d| d.value.as_ref())
        );
        assert_eq!(dev.inner.packet_for(&name, false), Some(served));
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_packet_of_a_key_revoked_without_a_cut_is_refused_without_refusing_its_name() {
        let r = Revoking::new(VALIDITY_MS).await;
        let ctx = SignedTrustContext::hierarchical(n("/sam"))
            .with_version(2)
            .with_revocation(r.key.clone());
        assert!(ctx.add_anchor(r.anchor.clone()));
        r.validator.keyring().adopt_update(Arc::new(ctx)).unwrap();
        // Unchecked bytes under the revoked key: whoever answers may make them.
        let (one, _) = r.version(1, 1);
        let forged = DataBuilder::new(
            one.clone(),
            &wire::encode_record(&Record::Version(version_body(&r.c, None))),
        )
        .sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&r.key),
            |_| Bytes::from_static(&[0; 64]),
        );
        let refused = r
            .dev
            .inner
            .take_data(&one, Data::decode(forged).unwrap())
            .await;
        assert!(
            matches!(refused, Err(Refusal::OutsideCut(_))),
            "{refused:?}"
        );
        let st = r.dev.inner.st.lock();
        assert!(
            !st.refused.contains_key(&one) && !st.cut_out.contains_key(&one),
            "the packet is refused, not the name"
        );
        drop(st);
        assert!(r.dev.refused_by_revocation(&r.key).is_empty());
        r.dev.shutdown();
    }

    /// Round-8 L-a: a packet of a key whose role needs a cut and whose only
    /// certificate lapsed is refused as lapsed by this device's clock, not as
    /// "revoked" or "cut": the text names the expiry, the clock, and the way
    /// out; the next step is the owner's; and the refusal is not kept (only
    /// the clock refuses), so the same name is judged again when fetched again.
    #[tokio::test]
    async fn a_lapsed_keys_packet_is_refused_as_lapsed_by_this_devices_clock() {
        // The member phone's certificate is valid for one millisecond.
        let r = Revoking::new_for(n("/sam/member/phone"), 1, Arc::new(Unconnected)).await;
        let ctx = SignedTrustContext::hierarchical(n("/sam"))
            .with_version(2)
            .with_data_requires_cut("member");
        assert!(ctx.add_anchor(r.anchor.clone()));
        r.validator.keyring().adopt_update(Arc::new(ctx)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (one, d1) = r.version(1, 1);
        let refused = r.dev.inner.take_data(&one, d1).await;
        let Err(why @ Refusal::Lapsed { not_after, now }) = refused else {
            panic!("a lapsed key's packet must be Refusal::Lapsed: {refused:?}");
        };
        assert!(now > not_after, "{now:?} is after {not_after:?}");
        let text = why.to_string();
        for want in [
            "certificate expired at",
            "by this device's clock",
            "check the clock",
            "end the key",
            "re-enrol",
        ] {
            assert!(text.contains(want), "{want:?} missing from: {text}");
        }
        assert!(
            !text.contains("lies under") && !text.contains("revoked"),
            "a lapse is not a cut or a revocation: {text}"
        );
        let error = DataError::Refused {
            id: r.id(1),
            why: why.clone(),
        };
        assert_eq!(error.next(), crate::NextStep::AskOwner);
        let st = r.dev.inner.st.lock();
        assert!(
            !st.refused.contains_key(&one) && !st.cut_out.contains_key(&one),
            "only the clock refused it: the name is not"
        );
        drop(st);
        r.dev.shutdown();
    }

    // ---- slice 5 review: keys over time ---------------------------------------------------------

    #[tokio::test]
    async fn an_exact_re_admission_is_fetched_once_its_collection_is_followed() {
        let r = Revoking::new(VALIDITY_MS).await;
        let photos = n("/rita/32=data/photos");
        let (three, d3) = r.version_of(&photos, 3, 3);
        let full = three
            .clone()
            .append_implicit_digest(wire::implicit_digest(d3.raw()));
        r.revoke(2, r.cut(1, 1, std::slice::from_ref(&full)));
        until(&r.dev, |st| st.contexts.values().any(|c| c.version() == 2)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!r.dev.inner.st.lock().cut_fetching.contains(&three));
        // Followed only after the adoption.
        r.dev.inner.st.lock().follows.insert(photos.clone());
        r.dev.inner.fetch_cut_runs();
        assert!(
            r.dev.inner.st.lock().cut_fetching.contains(&three),
            "asked for by its full name"
        );
        r.dev.shutdown();
    }

    /// An entry a revocation cut accepts that is not to be had when asked —
    /// its writer away, every reply lost — is asked again on its own, after
    /// a growing pause (spec §8, §17.1), not only at the next group refresh,
    /// follow or adoption: the reader joining after the cut otherwise waits
    /// for something unrelated to ask again (faulty seed 4, k6).
    #[tokio::test(start_paused = true)]
    async fn an_entry_a_cut_accepts_not_to_be_had_when_asked_is_asked_again() {
        let packet: Arc<std::sync::Mutex<Option<(Name, Bytes)>>> = Default::default();
        let serves = Arc::clone(&packet);
        let asks = Asks::new(
            &n("/sam/phone"),
            Box::new(move |name, _| {
                let packet = serves.lock().unwrap();
                packet
                    .as_ref()
                    .filter(|(entry, _)| name.has_prefix(entry))
                    .map(|(_, wire)| wire.clone())
            }),
        );
        let r = Revoking::new_on(VALIDITY_MS, asks.clone()).await;
        let (one, d1) = r.version(1, 1_000);
        r.revoke(2, r.cut(1, 1, &[]));
        /// Whether `done` holds of `dev`'s state within a minute.
        async fn within(dev: &Device, done: impl Fn(&St) -> bool) -> bool {
            for _ in 0..600 {
                if done(&dev.inner.st.lock()) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }
        assert!(
            within(&r.dev, |st| st.cut_fetching.contains(&one)).await,
            "the entry the cut accepts is asked for once the cut is held"
        );
        assert!(
            within(&r.dev, |st| !st.cut_fetching.contains(&one)).await,
            "the first ask ends"
        );
        assert!(
            asks.asked().iter().any(|a| a.has_prefix(&one)),
            "it was asked of its writer"
        );
        assert!(!r.dev.inner.st.lock().held.contains_key(&one));
        // The writer answers from now on; nothing refreshes, follows or
        // adopts anything meanwhile.
        *packet.lock().unwrap() = Some((one.clone(), d1.raw().clone()));
        assert!(
            within(&r.dev, |st| matches!(
                st.held.get(&one),
                Some(Held::Version(_))
            ))
            .await,
            "an entry the cut accepts that was not to be had is asked for again, and taken"
        );
        r.dev.shutdown();
    }

    /// The same packet again.
    fn copy(d: &Data) -> Data {
        Data::decode(d.raw().clone()).unwrap()
    }

    /// Whether a range of `cut` lists the log entry `name`.
    fn ranged(cut: &RevocationCut, name: &Name) -> bool {
        let seq = parse_log_name(name).unwrap().seq;
        cut.ranges().iter().any(|r| {
            r.prefix == log_prefix(name) && r.runs.iter().any(|&(a, b)| a <= seq && seq <= b)
        })
    }

    #[tokio::test]
    async fn a_thiefs_entry_first_verified_after_the_loss_is_left_out_of_the_cut_and_listed() {
        let r = Revoking::new(VALIDITY_MS).await;
        let mut names = Vec::new();
        for seq in 1..=2 {
            let (name, data) = r.version(seq, seq);
            r.dev.inner.take_data(&name, data).await.unwrap();
            names.push(name);
        }
        // The phone is lost at 2_000; what its key signs from then on is
        // first verified here at 3_000, whatever date it claims.
        r.clock.store(3_000, Ordering::Relaxed);
        let (three, d3) = r.version(3, 1);
        let full = three
            .clone()
            .append_implicit_digest(wire::implicit_digest(d3.raw()));
        r.dev.inner.take_data(&three, d3).await.unwrap();
        let lost = CutBound {
            held_before: Some(Timestamp(2_000)),
            ..CutBound::default()
        };
        let proposal = r.dev.revocation_cut(&r.key, &lost).unwrap();
        assert!(ranged(&proposal.cut, &names[0]) && ranged(&proposal.cut, &names[1]));
        assert!(
            !ranged(&proposal.cut, &three),
            "first verified after the loss"
        );
        assert_eq!(proposal.left_out, vec![full.clone()], "listed to re-admit");
        // Bounded by seq instead: the same.
        let upto = CutBound {
            upto: [(r.c.clone(), 2)].into_iter().collect(),
            ..CutBound::default()
        };
        let by_seq = r.dev.revocation_cut(&r.key, &upto).unwrap();
        assert_eq!(by_seq.cut.ranges(), proposal.cut.ranges());
        // The times are kept across a restart; an entry held without one
        // (kept before times were recorded) is left out.
        r.dev.shutdown();
        r.store.remove(&verified_name(&names[0]));
        let tab = n("/rita/tab");
        let again = start_at(&tab, &r.tab_keys, &r.validator, &r.store, &r.clock)
            .await
            .unwrap();
        let after = again.revocation_cut(&r.key, &lost).unwrap();
        assert!(ranged(&after.cut, &names[1]) && !ranged(&after.cut, &three));
        assert!(!ranged(&after.cut, &names[0]), "its time is not known");
        assert_eq!(after.left_out.len(), 2);
        again.shutdown();
    }

    #[tokio::test]
    async fn a_suspected_keys_new_entries_are_not_taken_until_its_revocation() {
        let r = Revoking::new(VALIDITY_MS).await;
        let (one, d1) = r.version(1, 1);
        r.dev.inner.take_data(&one, d1).await.unwrap();
        r.dev.suspect(&r.key, Timestamp(2_000)).unwrap();
        assert_eq!(r.dev.suspected(&r.cert.name), Some(Timestamp(2_000)));
        let (two, d2) = r.version(2, 2);
        let refused = r.dev.inner.take_data(&two, copy(&d2)).await;
        assert!(
            matches!(refused, Err(Refusal::Suspected { .. })),
            "{refused:?}"
        );
        assert!(!r.dev.inner.st.lock().held.contains_key(&two));
        assert!(r.store.get(&two).is_none(), "not stored");
        assert!(r.dev.get(&one).await.is_ok(), "what was held stays");
        // Kept across a restart.
        r.dev.shutdown();
        let tab = n("/rita/tab");
        let again = start_at(&tab, &r.tab_keys, &r.validator, &r.store, &r.clock)
            .await
            .unwrap();
        assert_eq!(again.suspected(&r.key), Some(Timestamp(2_000)));
        let refused = again.inner.take_data(&two, copy(&d2)).await;
        assert!(
            matches!(refused, Err(Refusal::Suspected { .. })),
            "{refused:?}"
        );
        // Its cut, bounded by when it was suspected, then revokes it: the
        // mark ends, and the cut decides.
        let lost = CutBound {
            held_before: again.suspected(&r.key),
            ..CutBound::default()
        };
        let proposal = again.revocation_cut(&r.key, &lost).unwrap();
        assert!(ranged(&proposal.cut, &one));
        r.revoke(2, proposal.cut);
        until(&again, |st| st.suspected.is_empty()).await;
        assert_eq!(again.suspected(&r.key), None);
        let refused = again.inner.take_data(&two, d2).await;
        assert!(
            matches!(refused, Err(Refusal::OutsideCut(_))),
            "{refused:?}"
        );
        assert!(again.get(&one).await.is_ok(), "inside the cut");
        again.shutdown();
    }

    #[tokio::test]
    async fn other_bytes_at_a_name_the_cut_lists_are_refused_once_bound_to_its_manifest() {
        let r = Revoking::new(VALIDITY_MS).await;
        let mut honest = Vec::new();
        for seq in 1..=2 {
            let (name, data) = r.version(seq, seq);
            r.dev.inner.take_data(&name, copy(&data)).await.unwrap();
            honest.push((name, data));
        }
        let lost = CutBound {
            held_before: Some(Timestamp(2_000)),
            ..CutBound::default()
        };
        let proposal = r.dev.revocation_cut(&r.key, &lost).unwrap();
        r.revoke(2, proposal.cut);
        // A reader that holds none of it, its validator holding the
        // manifest.
        let pad = n("/rita/pad");
        let pad_store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let late = start_at(&pad, &keys_of(&pad), &r.validator, &pad_store, &r.clock)
            .await
            .unwrap();
        // The thief's other bytes at seq 2, which the cut's range takes.
        let (two, forged) = r.version(2, 99);
        let refused = late.inner.take_data(&two, forged).await;
        assert!(refused.is_err(), "other bytes than the manifest lists");
        {
            let st = late.inner.st.lock();
            assert!(
                !st.held.contains_key(&two) && !st.refused.contains_key(&two),
                "the name stays open for the listed bytes"
            );
        }
        // It asks for exactly the listed bytes, by full name.
        assert_eq!(
            late.inner.cut_digest(&two, &r.writer()).await,
            Some(Some(wire::implicit_digest(honest[1].1.raw())))
        );
        late.inner
            .take_data(&two, copy(&honest[1].1))
            .await
            .expect("the bytes the manifest lists");
        late.shutdown();
        r.dev.shutdown();
    }

    /// A removal cut binds what it keeps to the bytes its manifest lists
    /// (spec §8): a kept version is inside it only with exactly those
    /// bytes, as every manifest binding its key lists them; a cut binding
    /// no bytes (signed before cuts bound bytes) keeps nothing inside; and
    /// while a manifest packet is not held — nor another packet under its
    /// name taken for it — the version waits on it, by full name.
    #[test]
    fn a_kept_version_is_inside_a_removal_cut_only_with_the_bytes_its_manifest_lists() {
        let c = n("/alice/32=data/trip/plan");
        let id = VersionId {
            writer: Writer::new(n("/bob/phone/KEY/1")),
            seq: Seq(1),
        };
        let name = log_name(&n("/bob/phone"), Some(&c), 1);
        let (honest, other) = ([1u8; 32], [2u8; 32]);
        let manifest = |seq: u64, digest: [u8; 32]| {
            let record = log_name(&n("/alice/laptop"), Some(&c), seq);
            cut_manifest::build_under(
                &wire::cut_bytes_prefix(&record),
                &[(log_prefix(&name), 1, digest)],
            )
            .unwrap()
        };
        let built = manifest(4, honest);
        let mut accept = Accepted::new();
        accept.insert(&c, &id);
        let unbound = Cut {
            of: n("/bob"),
            accept,
            signer: Writer::new(n("/alice/laptop/KEY/1")),
        };
        let mut bound = unbound.clone();
        bound.accept.bind(&built.root);
        let held = CutManifests::new(16);
        let store = MemoryStore::new();
        let judge =
            |cut: &Cut, digest: &[u8; 32]| bound_bytes(&held, &store, cut, &c, &id, &name, digest);
        assert!(
            matches!(judge(&unbound, &honest), Bound::Unbound),
            "an unbound cut"
        );
        assert!(
            matches!(judge(&bound, &honest), Bound::Missing(full) if full == built.root),
            "waits on the root, by full name"
        );
        // Other bytes under the root's name are not taken for it.
        let root_name = Name::from_components(
            built.root.components()[..built.root.len() - 1]
                .iter()
                .cloned(),
        );
        store.insert(root_name.clone(), manifest(4, other).packets[0].clone());
        assert!(
            matches!(judge(&bound, &honest), Bound::Missing(_)),
            "other bytes under the root's name"
        );
        store.insert(root_name, built.packets[0].clone());
        assert!(matches!(judge(&bound, &honest), Bound::Listed));
        assert!(
            matches!(judge(&bound, &other), Bound::Other),
            "other bytes at the kept seq"
        );
        // Two manifests binding one key: every one must list the bytes.
        let disagreeing = manifest(5, other);
        for wire in &disagreeing.packets {
            let data = Data::decode(wire.clone()).unwrap();
            held.insert(&data).unwrap();
        }
        let mut both = bound.clone();
        both.accept.bind(&disagreeing.root);
        for digest in [&honest, &other] {
            assert!(
                matches!(judge(&both, digest), Bound::Other),
                "manifests disagree"
            );
        }
    }

    /// `/sam/phone`, its key certified by `/sam`'s namespace key, writing
    /// into its log collection `/sam/32=data/notes`.
    struct OwnLog {
        dev: Device,
        keys: Arc<SecurityManager>,
        key: Name,
        validator: Arc<Validator>,
        store: Arc<dyn DataStore>,
        phone: Name,
        c: Name,
    }

    impl OwnLog {
        async fn new() -> Self {
            let (authority, issuer, anchor) = authority(&n("/sam")).await;
            let phone = n("/sam/phone");
            let (keys, key, cert) = device_key(&authority, &issuer, &phone).await;
            let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
            validator
                .adopt_context(sam_context(&anchor, 1, None))
                .unwrap();
            validator.cert_cache().insert(cert);
            let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
            let dev = start(&phone, &keys, &validator, &store).await.unwrap();
            let c = n("/sam/32=data/notes");
            dev.share(&c, share_of(Rule::Log, &["/sam"], Vec::new()))
                .await
                .unwrap();
            Self {
                dev,
                keys,
                key,
                validator,
                store,
                phone,
                c,
            }
        }

        /// A version at `seq` of the collection under the device's name,
        /// signed by a copy of its key: its name and packet.
        fn copy_writes(&self, seq: u64) -> (Name, Bytes) {
            let name = log_name(&self.phone, Some(&self.c), seq);
            let (packet, _) = signed(
                &self.keys,
                &self.key,
                &name,
                &wire::encode_record(&Record::Version(version_body(&self.c, None))),
            );
            (name, packet)
        }

        async fn restart(self) -> Device {
            self.dev.shutdown();
            drop(self.dev);
            start(&self.phone, &self.keys, &self.validator, &self.store)
                .await
                .unwrap()
        }
    }

    #[tokio::test]
    async fn a_version_a_copy_of_its_key_wrote_under_its_name_is_not_restored_as_its_own() {
        let own = OwnLog::new().await;
        for t in 1..=2 {
            own.dev.put(&own.c, reading(t), options()).await.unwrap();
        }
        let head = own.dev.inner.st.lock().head;
        let (thief, packet) = own.copy_writes(head + 1);
        let _ = own
            .dev
            .inner
            .take_data(&thief, Data::decode(packet.clone()).unwrap())
            .await;
        // Kept in the store, as an applied version of another writer is.
        own.store.insert(thief.clone(), packet);
        let c = own.c.clone();
        let again = own.restart().await;
        let st = again.inner.st.lock();
        assert_eq!(st.head, head, "the log head is what this device wrote");
        let ns = namespace_of(&c).unwrap();
        assert_eq!(
            st.trees.get(&ns).map(Tree::head),
            Some(head),
            "its summary lists only what it wrote"
        );
        drop(st);
        again.shutdown();
    }

    #[tokio::test]
    async fn a_store_kept_before_own_entries_were_recorded_keeps_its_log_head() {
        let own = OwnLog::new().await;
        for t in 1..=2 {
            own.dev.put(&own.c, reading(t), options()).await.unwrap();
        }
        let head = own.dev.inner.st.lock().head;
        // As an earlier release kept it: no record of what it wrote.
        for (n, _) in own.store.scan_under(&written_prefix(), 0) {
            own.store.remove(&n);
        }
        let c = own.c.clone();
        let again = own.restart().await;
        assert_eq!(again.inner.st.lock().head, head);
        let id = again.put(&c, reading(3), options()).await.unwrap();
        assert_eq!(id.seq.0, head + 1, "it never signs a seq it used");
        again.shutdown();
    }

    /// Entries this device signed under its own name, of kinds this build no
    /// longer decodes (an upgraded store: hold, prune and group records), are
    /// still seqs it used: the log head covers them, so it never signs one
    /// of those seqs again (self-equivocation) and peers that decoded them do
    /// not refuse its next root as a rollback.
    #[tokio::test]
    async fn an_own_entry_this_build_cannot_decode_still_moves_the_log_head() {
        let own = OwnLog::new().await;
        for t in 1..=2 {
            own.dev.put(&own.c, reading(t), options()).await.unwrap();
        }
        let head = own.dev.inner.st.lock().head;
        let kinds: [&[u8]; 3] = [
            &[0xFD, 0x05, 0x25, 0x01, 0x00], // a hold
            &[0xFD, 0x05, 0x39, 0x01, 0x00], // a prune
            &[0xFD, 0x05, 0x57, 0x01, 0x00], // a group of versions
        ];
        for (i, content) in kinds.into_iter().enumerate() {
            let seq = head + 1 + i as u64;
            let name = log_name(&own.phone, Some(&own.c), seq);
            let content = Bytes::copy_from_slice(content);
            assert!(
                wire::decode_record(content.clone()).is_err(),
                "a record this build does not decode"
            );
            let (packet, _) = signed(&own.keys, &own.key, &name, &content);
            // As this device kept it: the entry and its marker.
            own.store.insert(
                written_name(&name),
                Bytes::copy_from_slice(&wire::implicit_digest(&packet)),
            );
            own.store.insert(name, packet);
        }
        let c = own.c.clone();
        let again = own.restart().await;
        assert_eq!(
            again.inner.st.lock().head,
            head + 3,
            "this device signed those seqs"
        );
        let id = again.put(&c, reading(3), options()).await.unwrap();
        assert_eq!(id.seq.0, head + 4, "it never signs a seq it used");
        again.shutdown();
    }

    #[tokio::test]
    async fn an_entry_at_the_last_seq_under_its_name_never_makes_its_next_write_wrap() {
        let own = OwnLog::new().await;
        own.dev.put(&own.c, reading(1), options()).await.unwrap();
        let head = own.dev.inner.st.lock().head;
        let (thief, packet) = own.copy_writes(u64::MAX);
        let live = own
            .dev
            .inner
            .take_data(&thief, Data::decode(packet.clone()).unwrap())
            .await;
        assert!(
            matches!(live, Err(Refusal::BeyondOwnLog { .. })),
            "far beyond what it wrote: {live:?}"
        );
        // A store that kept it all the same (as an earlier run did).
        own.store.insert(thief.clone(), packet);
        let c = own.c.clone();
        let again = own.restart().await;
        assert_eq!(again.inner.st.lock().head, head);
        let id = again.put(&c, reading(2), options()).await.unwrap();
        assert_eq!(id.seq.0, head + 1, "the next write follows its own head");
        again.shutdown();
    }

    #[tokio::test]
    async fn entries_under_a_revoked_issuer_are_withdrawn_on_adoption_and_after_a_restart() {
        let (authority, issuer, anchor) = authority(&n("/sam")).await;
        // `/sam/admin`'s key, certified by the namespace key, certifies the
        // phone's key.
        let admin = n("/sam/admin");
        let (admin_keys, admin_key, admin_cert) = device_key(&authority, &issuer, &admin).await;
        let phone = n("/sam/admin/phone");
        let (phone_keys, phone_key, phone_cert) = device_key(&admin_keys, &admin_key, &phone).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/rita")).unwrap();
        validator
            .adopt_context(sam_context(&anchor, 1, None))
            .unwrap();
        validator.cert_cache().insert(admin_cert);
        validator.cert_cache().insert(phone_cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let tab = n("/rita/tab");
        let tab_keys = keys_of(&tab);
        let dev = start(&tab, &tab_keys, &validator, &store).await.unwrap();
        let c = n("/rita/32=data/notes");
        dev.share(&c, share_of(Rule::Log, &["/rita", "/sam"], Vec::new()))
            .await
            .unwrap();
        let writer = Writer::new(phone_key.clone());
        let mut names = Vec::new();
        for seq in 1..=2 {
            let name = log_name(&phone, Some(&c), seq);
            let (packet, _) = signed(
                &phone_keys,
                &phone_key,
                &name,
                &wire::encode_record(&Record::Version(version_body(&c, None))),
            );
            dev.inner
                .take_data(&name, Data::decode(packet).unwrap())
                .await
                .unwrap();
            names.push(name);
        }
        let applied = |dev: &Device| dev.inner.st.lock().colls[&c].applied.get(&writer).copied();
        assert_eq!(applied(&dev), Some(2));
        let mut changes = dev
            .watch(&c, &upto("/sam/admin/phone/KEY/1", 2))
            .await
            .unwrap();
        // The listing starts with the record in force (spec §15).
        assert!(matches!(
            changes.next().await,
            Some(Ok(Change::Members { .. }))
        ));
        // The issuer's key is revoked: nothing it certified signs Data.
        let ctx = SignedTrustContext::hierarchical(n("/sam"))
            .with_version(2)
            .with_revocation(admin_key.clone());
        assert!(ctx.add_anchor(anchor.clone()));
        validator.keyring().adopt_update(Arc::new(ctx)).unwrap();
        until(&dev, |st| names.iter().all(|n| st.refused.contains_key(n))).await;
        let change = tokio::time::timeout(Duration::from_secs(5), changes.next())
            .await
            .expect("the watcher is told")
            .expect("the stream is open")
            .unwrap();
        assert!(
            matches!(&change, Change::Withdrawn { id, why: Refusal::Untrusted { .. }, .. } if id.writer == writer),
            "withdrawn for its chain, by no cut: {change:?}"
        );
        assert!(matches!(
            dev.get(&names[0]).await,
            Err(DataError::Refused {
                why: Refusal::Untrusted { .. },
                ..
            })
        ));
        assert!(
            dev.refused_by_revocation(&phone_key).is_empty(),
            "nothing to re-admit by name and digest"
        );
        assert_eq!(applied(&dev), None);
        // A restart keeps them withdrawn.
        dev.shutdown();
        drop(dev);
        let again = start(&tab, &tab_keys, &validator, &store).await.unwrap();
        for name in &names {
            assert!(
                matches!(
                    again.get(name).await,
                    Err(DataError::Refused {
                        why: Refusal::Untrusted { .. },
                        ..
                    })
                ),
                "{name} after a restart"
            );
        }
        assert_eq!(applied(&again), None);
        // The namespace key certifies the phone's key anew: what it wrote
        // verifies again, and comes back as its next entry arrives.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let public = phone_keys
            .get_signer_sync(&phone_key)
            .unwrap()
            .public_key()
            .unwrap();
        let renewed = authority
            .certify(&phone_key, public, &issuer, VALIDITY_MS)
            .await
            .unwrap();
        validator.cert_cache().insert(renewed);
        let mut changes = again
            .watch(&c, &upto("/sam/admin/phone/KEY/1", 2))
            .await
            .unwrap();
        // The listing starts with the record in force (spec §15).
        assert!(matches!(
            changes.next().await,
            Some(Ok(Change::Members { .. }))
        ));
        let three = log_name(&phone, Some(&c), 3);
        let (packet, _) = signed(
            &phone_keys,
            &phone_key,
            &three,
            &wire::encode_record(&Record::Version(version_body(&c, None))),
        );
        again
            .inner
            .take_data(&three, Data::decode(packet).unwrap())
            .await
            .unwrap();
        until(&again, |st| {
            names.iter().all(|n| !st.refused.contains_key(n))
                && st.colls[&c].applied.get(&writer) == Some(&3)
        })
        .await;
        assert!(again.get(&names[0]).await.is_ok(), "taken back");
        let mut delivered = BTreeSet::new();
        while delivered.len() < 3 {
            match tokio::time::timeout(Duration::from_secs(5), changes.next()).await {
                Ok(Some(Ok(Change::Version(v)))) => {
                    delivered.insert(v.id.seq.0);
                }
                Ok(Some(Ok(_))) => {}
                other => panic!("every version is delivered again: {other:?}"),
            }
        }
        again.shutdown();
    }

    // ---- folder members records (spec §6) ------------------------------------------------------

    /// Hand `to` the log entry `seq` of `from` about `c`, as `from` signed
    /// it; why it is refused, if it is.
    fn relay(from: &Device, to: &Device, c: &Name, seq: u64) -> Option<Refusal> {
        let name = log_name(from.name(), Some(c), seq);
        let wire = from.inner.store.get(&name).expect("written and stored");
        let content = Data::decode(wire).unwrap().content().unwrap().clone();
        hand(
            to,
            from.name(),
            c,
            seq,
            wire::decode_record(content).unwrap(),
        )
    }

    fn version(c: &Name) -> Record {
        Record::Version(version_body(c, None))
    }

    #[tokio::test]
    async fn a_collection_with_no_record_of_its_own_is_written_and_read_by_its_folders() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let (f, c) = (n("/alice/32=data/docs"), n("/alice/32=data/docs/plan"));
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
        )
        .await
        .unwrap();
        dev.put(&c, reading(1), options()).await.unwrap();
        {
            let st = dev.inner.st.lock();
            let coll = &st.colls[&c];
            assert!(coll.line.own.is_none(), "no record of its own is signed");
            assert_eq!(coll.members.as_ref().map(|m| &m.rule), Some(&Rule::Log));
        }
        let bob = n("/bob/phone");
        assert_eq!(hand(&dev, &bob, &c, 1, version(&c)), None);
        assert_eq!(
            hand(&dev, &n("/carol/phone"), &c, 1, version(&c)),
            Some(Refusal::NotMember)
        );
        // A collection of the folder's name is another line of records.
        dev.share(&f, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let st = dev.inner.st.lock();
        let folder = st.folders[&f].line.own.clone().unwrap();
        let same_name = st.colls[&f].line.own.clone().unwrap();
        assert!(folder.folder && !same_name.folder);
        assert_eq!((folder.revision, same_name.revision), (Seq(1), Seq(1)));
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_collection_under_a_folder_narrows_and_never_widens() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob", "/carol"]).await;
        let (f, c) = (n("/alice/32=data/docs"), n("/alice/32=data/docs/plan"));
        let person = |p: &str| Audience::Person(n(p));
        dev.share_folder(
            &f,
            share_of(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            )
            .into(),
        )
        .await
        .unwrap();
        // Widening is refused at share, and nothing is signed.
        let head = dev.inner.st.lock().head;
        for (writers, readers) in [
            (vec!["/alice", "/carol"], Vec::new()),
            (vec!["/alice"], vec![person("/carol")]),
        ] {
            let refused = dev
                .share(&c, share_of(Rule::Log, &writers, readers))
                .await
                .unwrap_err();
            assert!(matches!(refused, DataError::BadRequest { .. }), "{refused}");
            assert_eq!(refused.next(), crate::error::NextStep::FixRequest);
        }
        assert_eq!(dev.inner.st.lock().head, head);
        // Narrowed to Alice: Bob, a writer of the folder's, is removed with
        // a cut (spec §6.1), and his new versions are refused here.
        dev.share(&c, share_of(Rule::Log, &["/alice"], vec![person("/alice")]))
            .await
            .unwrap();
        assert!(matches!(
            hand(&dev, &n("/bob/phone"), &c, 1, version(&c)),
            Some(Refusal::OutsideCut(_))
        ));
        let carol = (n("/carol/phone"), n("/carol"));
        let bob = (n("/bob/phone"), n("/bob"));
        // A record that widens anyway (signed elsewhere) has no effect.
        let st = dev.inner.st.lock();
        let own = st.colls[&c].line.own.clone().unwrap();
        drop(st);
        let wide = MembersBody {
            readers: vec![person("/alice"), person("/carol")],
            writers: vec![n("/alice"), n("/carol")],
            revision: 2,
            parent: Some(own.as_parent()),
            ..wire::MembersBody::from(&own)
        };
        assert_eq!(
            hand(&dev, &n("/alice/phone"), &c, 1, Record::Members(wide)),
            None
        );
        let st = dev.inner.st.lock();
        assert_eq!(
            st.colls[&c].line.own.as_ref().map(|m| m.revision),
            Some(Seq(2))
        );
        assert!(!dev.inner.admits_reader(&st, &c, &carol.0, &carol.1));
        assert!(!dev.inner.admits_reader(&st, &c, &bob.0, &bob.1));
        drop(st);
        assert_eq!(
            hand(&dev, &carol.0, &c, 1, version(&c)),
            Some(Refusal::NotMember)
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn one_key_of_a_folder_epoch_opens_every_collection_that_inherits_it() {
        let laptop = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let reader = device_in("/bob/phone", &["/alice", "/bob"]).await;
        let f = n("/alice/32=data/docs");
        let cs = [
            n("/alice/32=data/docs/plan"),
            n("/alice/32=data/docs/notes"),
        ];
        laptop
            .share_folder(
                &f,
                share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/bob"))]).into(),
            )
            .await
            .unwrap();
        let e = {
            let st = laptop.inner.st.lock();
            st.folders[&f]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap()
        };
        let mut ids = Vec::new();
        for c in &cs {
            ids.push(laptop.put(c, reading(1), options()).await.unwrap());
        }
        assert_eq!(relay(&laptop, &reader, &f, e.seq.0), None);
        for (c, id) in cs.iter().zip(&ids) {
            assert_eq!(relay(&laptop, &reader, c, id.seq.0), None);
            let st = reader.inner.st.lock();
            assert_eq!(st.colls[c].locked.len(), 1, "sealed, and not opened yet");
            assert_eq!(
                st.colls[c].locked[0].epoch(),
                &e,
                "sealed in the folder epoch"
            );
            // Its key is asked of the folder.
            let s = st.seal_subject(c, &e);
            assert_eq!((s.name, s.folder), (f.clone(), true));
        }
        let key = {
            let st = laptop.inner.st.lock();
            let bob = (n("/bob/phone"), n("/bob"));
            laptop.inner.grant_key(&st, &f, &e, &bob.0, &bob.1).unwrap()
        };
        let mut st = reader.inner.st.lock();
        assert!(
            !st.take_key(&cs[0], &e, key.clone()),
            "the key check is bound to the folder"
        );
        assert!(st.take_key(&f, &e, key));
        let writer = Writer::new(n("/alice/laptop/KEY/1"));
        for (c, id) in cs.iter().zip(&ids) {
            assert!(st.colls[c].locked.is_empty(), "{c} opens with the one key");
            assert_eq!(st.colls[c].applied.get(&writer), Some(&id.seq.0));
        }
        drop(st);
        laptop.shutdown();
        reader.shutdown();
    }

    #[tokio::test]
    async fn a_folder_removal_cut_refuses_the_removed_writers_later_versions_everywhere_under_it() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let f = n("/alice/32=data/docs");
        let [c1, c2, c3] = ["plan", "notes", "later"].map(|x| f.clone().append(x));
        let bob = n("/bob/phone");
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
        )
        .await
        .unwrap();
        assert_eq!(hand(&dev, &bob, &c1, 1, version(&c1)), None);
        assert_eq!(hand(&dev, &bob, &c2, 2, version(&c2)), None);
        dev.share_folder(&f, share_of(Rule::Log, &["/alice"], Vec::new()).into())
            .await
            .unwrap();
        for (c, seq) in [(&c1, 3), (&c2, 4), (&c3, 5)] {
            assert!(
                matches!(
                    hand(&dev, &bob, c, seq, version(c)),
                    Some(Refusal::OutsideCut(_))
                ),
                "seq {seq} in {c}"
            );
        }
        let st = dev.inner.st.lock();
        let writer = Writer::new(n("/bob/phone/KEY/1"));
        let kept = |c: &Name, seq: u64| {
            st.colls[c].versions.contains_key(&VersionId {
                writer: writer.clone(),
                seq: Seq(seq),
            })
        };
        assert!(kept(&c1, 1) && kept(&c2, 2), "what the cut kept stays");
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn concurrent_folder_records_merge_three_ways() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob", "/carol"]).await;
        let f = n("/alice/32=data/docs");
        let c = f.clone().append("plan");
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
        )
        .await
        .unwrap();
        let first = dev.inner.st.lock().folders[&f].line.own.clone().unwrap();
        // The laptop removes Bob; the phone, from the same record, adds Carol.
        dev.share_folder(&f, share_of(Rule::Log, &["/alice"], Vec::new()).into())
            .await
            .unwrap();
        let adds = MembersBody {
            writers: vec![n("/alice"), n("/bob"), n("/carol")],
            revision: 2,
            parent: Some(first.as_parent()),
            ..wire::MembersBody::from(&first)
        };
        assert_eq!(
            hand(&dev, &n("/alice/phone"), &f, 1, Record::Members(adds)),
            None
        );
        {
            let st = dev.inner.st.lock();
            let m = st.folders[&f].line.own.clone().unwrap();
            assert!(m.folder);
            assert_eq!(m.writers, vec![n("/alice"), n("/carol")]);
            assert!(
                m.cuts.iter().any(|k| k.of == n("/bob")),
                "the removal stands"
            );
        }
        assert_eq!(hand(&dev, &n("/carol/phone"), &c, 1, version(&c)), None);
        assert!(matches!(
            hand(&dev, &n("/bob/phone"), &c, 1, version(&c)),
            Some(Refusal::OutsideCut(_))
        ));
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_reader_a_folder_drops_moves_a_collection_with_readers_of_its_own_to_a_new_epoch() {
        let dev = device_in("/alice/laptop", &["/alice", "/bob"]).await;
        let (f, c) = (n("/alice/32=data/docs"), n("/alice/32=data/docs/plan"));
        let person = |p: &str| Audience::Person(n(p));
        dev.share_folder(
            &f,
            share_of(
                Rule::Log,
                &["/alice"],
                vec![person("/alice"), person("/bob")],
            )
            .into(),
        )
        .await
        .unwrap();
        dev.share(&c, share_of(Rule::Log, &[], vec![person("/bob")]))
            .await
            .unwrap();
        let bob = (n("/bob/phone"), n("/bob"));
        let before = {
            let st = dev.inner.st.lock();
            assert!(dev.inner.admits_reader(&st, &c, &bob.0, &bob.1));
            st.colls[&c]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap()
        };
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice"], vec![person("/alice")]).into(),
        )
        .await
        .unwrap();
        let st = dev.inner.st.lock();
        let own = st.colls[&c].line.own.clone().unwrap();
        assert!(
            !own.readers.contains(&person("/bob")),
            "a record without Bob"
        );
        let now = st.colls[&c]
            .members
            .as_ref()
            .unwrap()
            .epoch
            .clone()
            .unwrap();
        assert_ne!(now, before, "in a new epoch");
        assert!(!dev.inner.admits_reader(&st, &c, &bob.0, &bob.1));
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_restarted_device_announces_above_everything_its_earlier_run_announced() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(context("/alice")).unwrap();
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let keys = keys_of(&device);
        let ns = n("/alice");
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        // A run announces more often than it appends to its log.
        for _ in 0..5 {
            dev.inner.publish(&ns);
            dev.inner.flushed().await;
        }
        let (head, before) = {
            let st = dev.inner.st.lock();
            (st.head, st.groups[&ns].announced)
        };
        assert!(before > head);
        dev.shutdown();
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        again.inner.publish(&ns);
        again.inner.flushed().await;
        let after = again.inner.st.lock().groups[&ns].announced;
        assert!(
            after > before,
            "its first announcement after the restart is above every earlier one"
        );
        again.shutdown();
    }

    #[tokio::test]
    async fn a_restarted_device_announces_again_in_every_group_its_records_publish_into() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in ["/alice", "/bob"] {
            validator.adopt_context(context(ns)).unwrap();
        }
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let keys = keys_of(&device);
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let f = n("/alice/32=data/notebook");
        let c = f.clone().append("cover");
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/bob"))]).into(),
        )
        .await
        .unwrap();
        dev.put(&c, reading(1), options()).await.unwrap();
        dev.inner.flushed().await;
        let bob = n("/bob");
        let before = dev.inner.st.lock().groups[&bob].announced;
        dev.shutdown();
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        again.inner.flushed().await;
        let after = again.inner.st.lock().groups.get(&bob).map(|g| g.announced);
        assert!(
            after.is_some_and(|a| a > before),
            "back in the reader's group, above what it announced there before"
        );
        again.shutdown();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test_kit;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod register_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod folder_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod admission_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod durability_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod watch_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod intro_tests;

mod hint;

mod intro;
pub use intro::IntroductionSurface;

mod grants;

mod scoped;

mod signal;

mod heard;

mod face_up;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod face_up_tests;

mod stage;

mod notes;
pub use notes::{LocalNotes, NOTE_PART_MAX, NOTE_VALUE_MAX, NOTES_PER_AREA_MAX};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fetch_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod walk_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod batching_tests;
